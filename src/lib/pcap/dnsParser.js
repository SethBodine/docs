// ─── DNS PARSER ───────────────────────────────────────────────────────────
// Parses DNS query/response messages from UDP port 53 payloads. Handles
// name decompression (the 0xC0 pointer scheme) since real-world DNS makes
// heavy use of it. Extracts query names and answer records — enough to spot
// suspicious patterns (long/high-entropy labels suggestive of DNS
// tunneling, TXT records, unexpected record types) without needing a full
// RFC 1035 implementation.

function readName(view, bytes, startOffset, maxJumps = 20) {
  let offset = startOffset;
  let labels = [];
  let jumps = 0;
  let endOffset = null; // where the name "actually" ends in the original stream, for the caller's position tracking

  while (offset < bytes.length) {
    const len = bytes[offset];
    if (len === 0) {
      if (endOffset === null) endOffset = offset + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (jumps++ >= maxJumps) throw new Error('DNS name compression pointer loop (too many jumps)');
      if (endOffset === null) endOffset = offset + 2;
      const pointer = ((len & 0x3f) << 8) | bytes[offset + 1];
      offset = pointer;
      continue;
    }
    if (offset + 1 + len > bytes.length) throw new Error('DNS label runs past end of message');
    labels.push(String.fromCharCode(...bytes.subarray(offset + 1, offset + 1 + len)));
    offset += 1 + len;
  }
  return { name: labels.join('.'), endOffset: endOffset ?? offset };
}

const QTYPE = { 1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 6: 'SOA' };

/**
 * @param {Uint8Array} bytes - the UDP payload (DNS message)
 * @returns {{ isResponse: boolean, questions: string[], answers: Array<{name:string, type:string, data:string}> } | null}
 */
export function parseDns(bytes) {
  if (bytes.length < 12) return null;
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const flags = view.getUint16(2, false);
    const isResponse = (flags & 0x8000) !== 0;
    const qdCount = view.getUint16(4, false);
    const anCount = view.getUint16(6, false);

    let offset = 12;
    const questions = [];
    for (let i = 0; i < Math.min(qdCount, 50) && offset < bytes.length; i++) {
      const { name, endOffset } = readName(view, bytes, offset);
      questions.push(name);
      offset = endOffset + 4; // skip QTYPE(2) + QCLASS(2)
    }

    const answers = [];
    for (let i = 0; i < Math.min(anCount, 50) && offset < bytes.length; i++) {
      const { name, endOffset } = readName(view, bytes, offset);
      offset = endOffset;
      if (offset + 10 > bytes.length) break;
      const type = view.getUint16(offset, false);
      offset += 8; // TYPE(2) + CLASS(2) + TTL(4)
      const rdLength = view.getUint16(offset, false);
      offset += 2;
      let data = '';
      if (type === 1 && rdLength === 4) { // A record
        data = `${bytes[offset]}.${bytes[offset+1]}.${bytes[offset+2]}.${bytes[offset+3]}`;
      } else if (type === 16) { // TXT record — length-prefixed string(s)
        try { data = String.fromCharCode(...bytes.subarray(offset + 1, offset + rdLength)); } catch { data = '(unreadable)'; }
      } else if (type === 5 || type === 2) { // CNAME/NS — another (possibly compressed) name
        try { data = readName(view, bytes, offset).name; } catch { data = '(unreadable)'; }
      }
      answers.push({ name, type: QTYPE[type] || `TYPE${type}`, data });
      offset += rdLength;
    }

    return { isResponse, questions, answers };
  } catch {
    return null; // malformed DNS — caller just won't get DNS-specific findings for this packet
  }
}

/**
 * Heuristic checks for DNS-tunneling-style patterns: unusually long labels,
 * high proportion of base32/base64-shaped characters, excessive subdomain
 * depth. None of these are proof of tunneling on their own — flagged as
 * signals, same convention as the binary suspicious-API findings.
 */
export function suspiciousDnsPatterns(queryName) {
  const findings = [];
  const labels = queryName.split('.');
  const longLabels = labels.filter(l => l.length > 40);
  if (longLabels.length > 0) {
    findings.push({ reason: 'Unusually long DNS label(s)', detail: longLabels.join(', ') });
  }
  const base64ish = labels.filter(l => l.length > 20 && /^[A-Za-z0-9+/=_-]+$/.test(l) && /[A-Z]/.test(l) && /[0-9]/.test(l));
  if (base64ish.length > 0) {
    findings.push({ reason: 'DNS label(s) resembling encoded data (possible tunneling)', detail: base64ish.join(', ') });
  }
  if (labels.length > 8) {
    findings.push({ reason: 'Unusually deep subdomain nesting', detail: `${labels.length} labels: ${queryName}` });
  }
  return findings;
}
