// ─── PCAP ANALYSIS ORCHESTRATOR ──────────────────────────────────────────────
// Ties together container parsing, link/IP/transport decoding, TCP stream
// reassembly, and the DNS/TLS/HTTP/SNMP protocol parsers into one pass over
// a capture file. Resource limits are enforced here, not left to each
// sub-module, so there's one place that defines "how much of this file we're
// willing to process."

import { parsePcapFile } from './pcapFile.js';
import { decodeLinkLayer, decodeIpLayer, decodeTcp, decodeUdp, IP_PROTO } from './layers.js';
import { reassembleTcpStreams } from './tcpReassembly.js';
import { parseDns, suspiciousDnsPatterns } from './dnsParser.js';
import { parseClientHello } from './tlsParser.js';
import { parseHttpStream } from './httpParser.js';
import { parseSnmpCommunity } from './snmpParser.js';
import { scanForSecrets } from '../secrets.js';

export const PCAP_LIMITS = {
  MAX_BYTES_PROCESSED: 300 * 1024 * 1024, // first 300MB of a capture, not the whole thing if larger
  MAX_PACKETS: 300_000,
  MAX_STREAMS: 5_000,
  MAX_BYTES_PER_STREAM: 5 * 1024 * 1024,
  MAX_DNS_QUERIES_LISTED: 500,
  MAX_TLS_HELLOS_LISTED: 500,
  MAX_STREAMS_LISTED: 500,
};

const COMMON_PLAINTEXT_PORTS = { 21: 'FTP', 23: 'Telnet', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 389: 'LDAP' };

function looksLikeCleartextCreds(text) {
  // FTP/Telnet/POP3/IMAP-style line-oriented credential exchange
  return /\b(USER|PASS|LOGIN|login|password)\b[:\s]/i.test(text);
}

export async function analysePcap(arrayBuffer, filename) {
  const findings = [];
  const metadata = {};
  const externalLinks = [];

  const raw = new Uint8Array(arrayBuffer);
  const bytesToProcess = raw.length > PCAP_LIMITS.MAX_BYTES_PROCESSED ? raw.subarray(0, PCAP_LIMITS.MAX_BYTES_PROCESSED) : raw;
  const wasTruncated = raw.length > PCAP_LIMITS.MAX_BYTES_PROCESSED;

  let parsed;
  try {
    parsed = parsePcapFile(bytesToProcess, { maxPackets: PCAP_LIMITS.MAX_PACKETS, maxBytes: PCAP_LIMITS.MAX_BYTES_PROCESSED });
  } catch (e) {
    return {
      findings: [{ severity: 'medium', category: 'Parse Error', title: 'Could not parse capture file', detail: e.message }],
      metadata: {}, textContent: '', externalLinks: [], previewData: { type: 'pcap', streams: [], dns: [], tls: [] },
    };
  }

  metadata['Format'] = parsed.format;
  metadata['Packets Processed'] = parsed.packets.length.toLocaleString();
  if (wasTruncated || parsed.truncated) {
    findings.push({ severity: 'info', category: 'Format', title: 'Capture was truncated for analysis', detail: `Only the first ${wasTruncated ? (PCAP_LIMITS.MAX_BYTES_PROCESSED / 1024 / 1024) + 'MB' : parsed.packets.length + ' packets'} of this capture were processed, to keep analysis bounded in the browser.` });
  }

  // ── Decode every packet's link/IP/transport layers ──────────────────────
  const tcpPackets = [];
  const udpPackets = [];
  const hostsSeen = new Set();
  let decodeFailures = 0;

  for (const pkt of parsed.packets) {
    const link = decodeLinkLayer(pkt.data, pkt.linkType);
    if (!link) { decodeFailures++; continue; }
    const ip = decodeIpLayer(link.ethertype, link.payload);
    if (!ip) continue; // non-IP traffic (ARP, etc.) — not analysed, not an error
    hostsSeen.add(ip.srcIP); hostsSeen.add(ip.dstIP);

    if (ip.protocol === IP_PROTO.TCP) {
      const tcp = decodeTcp(ip.payload);
      if (tcp) tcpPackets.push({ ip, tcp });
    } else if (ip.protocol === IP_PROTO.UDP) {
      const udp = decodeUdp(ip.payload);
      if (udp) udpPackets.push({ ip, udp });
    }
  }
  metadata['Distinct Hosts'] = String(hostsSeen.size);

  // ── UDP: DNS + SNMP + generic secret scan on everything else ─────────────
  const dnsQueries = [];
  for (const { ip, udp } of udpPackets) {
    if (udp.srcPort === 53 || udp.dstPort === 53) {
      const dns = parseDns(udp.payload);
      if (!dns) continue;
      for (const q of dns.questions) {
        if (dnsQueries.length < PCAP_LIMITS.MAX_DNS_QUERIES_LISTED) dnsQueries.push({ name: q, response: dns.isResponse });
        for (const s of suspiciousDnsPatterns(q)) {
          findings.push({ severity: 'medium', category: 'DNS', title: s.reason, detail: `${s.detail} (queried by ${ip.srcIP})` });
        }
      }
      for (const a of dns.answers) {
        if (a.type === 'TXT' && a.data) {
          findings.push(...scanForSecrets(a.data, `DNS TXT record for ${a.name}`));
        }
      }
    } else if (udp.dstPort === 161 || udp.srcPort === 161) {
      const snmp = parseSnmpCommunity(udp.payload);
      if (snmp && snmp.community && snmp.community !== 'public') {
        findings.push({ severity: 'high', category: 'Cleartext Credentials', title: 'SNMP community string (non-default)', detail: `"${snmp.community}" from ${ip.srcIP} — SNMPv1/v2c sends this in the clear on every request.` });
      } else if (snmp) {
        findings.push({ severity: 'medium', category: 'Cleartext Credentials', title: 'SNMP community string ("public")', detail: `Default community string in use from ${ip.srcIP} — SNMPv1/v2c sends this in the clear.` });
      }
    } else {
      // Generic UDP payload — cheap secret scan catches anything protocol-specific we don't otherwise parse
      try {
        const decoded = new TextDecoder('utf-8', { fatal: true }).decode(udp.payload);
        findings.push(...scanForSecrets(decoded, `UDP ${ip.srcIP}:${udp.srcPort} -> ${ip.dstIP}:${udp.dstPort}`));
      } catch { /* binary payload, not text — skip */ }
    }
  }

  // ── TCP: reassemble streams, then sniff HTTP / TLS / cleartext creds ────
  const { streams, streamCapReached } = reassembleTcpStreams(tcpPackets, {
    maxStreams: PCAP_LIMITS.MAX_STREAMS, maxBytesPerStream: PCAP_LIMITS.MAX_BYTES_PER_STREAM,
  });
  if (streamCapReached) {
    findings.push({ severity: 'info', category: 'Format', title: `Stream limit reached (${PCAP_LIMITS.MAX_STREAMS})`, detail: 'Additional TCP conversations beyond this limit were not analysed.' });
  }

  const tlsHellos = [];
  const streamSummaries = [];
  const insecureHosts = new Set();

  for (const stream of streams) {
    const label = `${stream.clientIP}:${stream.clientPort} -> ${stream.serverIP}:${stream.serverPort}`;
    let protocol = 'TCP';

    // TLS ClientHello (works regardless of port — don't assume 443)
    const hello = parseClientHello(stream.c2s);
    if (hello) {
      protocol = 'TLS';
      if (hello.sni) {
        externalLinks.push({ url: `https://${hello.sni}`, context: 'TLS SNI' });
        if (tlsHellos.length < PCAP_LIMITS.MAX_TLS_HELLOS_LISTED) {
          tlsHellos.push({ sni: hello.sni, ja3: hello.ja3Hash, client: `${stream.clientIP}:${stream.clientPort}` });
        }
      }
    } else {
      const http = parseHttpStream(stream.c2s, stream.s2c);
      if (http) {
        protocol = 'HTTP';
        if (http.host) externalLinks.push({ url: `http://${http.host}${http.path}`, context: `${http.method} request` });
        if (stream.serverPort === 80 || !hello) insecureHosts.add(http.host || stream.serverIP);

        const headerBlob = Object.entries(http.requestHeaders).map(([k, v]) => `${k}: ${v}`).join('\n');
        findings.push(...scanForSecrets(headerBlob, `HTTP request to ${http.host || stream.serverIP}`));
        if (http.requestBody) findings.push(...scanForSecrets(http.requestBody, `HTTP request body to ${http.host || stream.serverIP}`));
        if (/api[_-]?key|token|secret|password/i.test(http.path)) {
          findings.push({ severity: 'medium', category: 'Secrets — Query Parameters', title: 'Potential secret in HTTP request path', detail: `${label} — ${http.path}` });
        }
      } else {
        // Plaintext protocol (FTP/Telnet/POP3/IMAP/etc.) or any other TCP
        // stream — always run the shared secret scanner regardless of port
        // or pattern match (a stream on an unlisted port is still worth
        // scanning; the port/pattern checks below only decide whether to
        // ALSO flag it specifically as "known insecure protocol").
        const portLabel = COMMON_PLAINTEXT_PORTS[stream.serverPort];
        try {
          const c2sText = new TextDecoder('utf-8', { fatal: true }).decode(stream.c2s);
          protocol = portLabel || (looksLikeCleartextCreds(c2sText) ? 'Cleartext' : 'TCP');
          const credFindings = scanForSecrets(c2sText, `${protocol} session ${label}`);
          findings.push(...credFindings);
          if ((portLabel || looksLikeCleartextCreds(c2sText)) && credFindings.length === 0 && looksLikeCleartextCreds(c2sText)) {
            // Plainly a credential exchange (USER/PASS/login: style) that the
            // generic patterns didn't happen to match a specific format for.
            findings.push({ severity: 'high', category: 'Cleartext Credentials', title: `Cleartext credentials over ${protocol}`, detail: `${label} — credentials transmitted unencrypted.` });
          }
          if (portLabel || looksLikeCleartextCreds(c2sText)) insecureHosts.add(stream.serverIP);
        } catch { /* binary stream — not text, nothing to scan */ }
      }
    }

    if (streamSummaries.length < PCAP_LIMITS.MAX_STREAMS_LISTED) {
      streamSummaries.push({ label, protocol, bytes: stream.c2s.length + stream.s2c.length, truncated: stream.truncated });
    }
  }

  metadata['TCP Streams'] = String(streams.length);
  metadata['UDP Packets'] = String(udpPackets.length);
  metadata['TLS ClientHellos'] = String(tlsHellos.length);
  metadata['DNS Queries'] = String(dnsQueries.length);

  if (insecureHosts.size > 0) {
    findings.push({ severity: 'medium', category: 'Transport Security', title: `Cleartext traffic to ${insecureHosts.size} host(s)`, detail: [...insecureHosts].slice(0, 10).join(', ') });
  }

  if (findings.length === 0) {
    findings.push({ severity: 'info', category: 'Format', title: 'No credentials or suspicious patterns detected', detail: `Analysed ${parsed.packets.length.toLocaleString()} packets across ${streams.length} TCP stream(s) and ${udpPackets.length} UDP packet(s).` });
  }

  return {
    findings,
    metadata,
    textContent: '',
    externalLinks,
    previewData: { type: 'pcap', streams: streamSummaries, dns: dnsQueries, tls: tlsHellos },
  };
}
