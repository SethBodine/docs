// ─── TCP STREAM REASSEMBLY ───────────────────────────────────────────────────
// Groups TCP segments into bidirectional streams keyed by the 5-tuple, then
// reassembles each direction's payload in sequence-number order. This is a
// pragmatic reassembler, not a full RFC 793 implementation: it handles the
// common real-world cases (out-of-order arrival, exact retransmission
// dedup) but doesn't model partial-overlap segment merging, PAWS, or 32-bit
// sequence-number wraparound. That covers the vast majority of real
// captures; a capture deliberately engineered to defeat this ordering would
// at worst produce a garbled reassembly for that one stream, not a crash or
// a hang, and per-stream size limits bound the damage either way.

function streamKey(srcIP, srcPort, dstIP, dstPort) {
  // Order-independent key so both directions of a conversation land in the
  // same bucket, regardless of which side we saw first.
  const a = `${srcIP}:${srcPort}`, b = `${dstIP}:${dstPort}`;
  return a < b ? `${a}|${b}` : `${b}|${a}`;
}

/**
 * @param {Array<{ip: object, tcp: object}>} tcpPackets - decoded IP+TCP layers, in capture order
 * @param {{maxStreams:number, maxBytesPerStream:number}} limits
 * @returns {Array<Stream>} where Stream = { key, clientIP, clientPort, serverIP, serverPort, c2s: Uint8Array, s2c: Uint8Array, truncated: boolean }
 */
export function reassembleTcpStreams(tcpPackets, limits) {
  const streams = new Map();
  let truncatedForStreamCap = false;

  for (const { ip, tcp } of tcpPackets) {
    const key = streamKey(ip.srcIP, tcp.srcPort, ip.dstIP, tcp.dstPort);
    let stream = streams.get(key);
    if (!stream) {
      if (streams.size >= limits.maxStreams) { truncatedForStreamCap = true; continue; }
      // First packet we see for this 5-tuple defines "client" (arbitrary but consistent)
      stream = {
        key,
        clientIP: ip.srcIP, clientPort: tcp.srcPort,
        serverIP: ip.dstIP, serverPort: tcp.dstPort,
        segments: { c2s: [], s2c: [] }, // {seq, data}
        truncated: false,
      };
      streams.set(key, stream);
    }

    if (tcp.payload.length === 0) continue;

    const isClientToServer = ip.srcIP === stream.clientIP && tcp.srcPort === stream.clientPort;
    const dir = isClientToServer ? 'c2s' : 's2c';
    const bucket = stream.segments[dir];

    const currentBytes = bucket.reduce((sum, s) => sum + s.data.length, 0);
    if (currentBytes >= limits.maxBytesPerStream) { stream.truncated = true; continue; }

    // Dedup exact retransmissions (same seq + same length already present)
    if (bucket.some(s => s.seq === tcp.seq && s.data.length === tcp.payload.length)) continue;

    bucket.push({ seq: tcp.seq, data: tcp.payload });
  }

  const result = [];
  for (const stream of streams.values()) {
    for (const dir of ['c2s', 's2c']) {
      stream.segments[dir].sort((a, b) => a.seq - b.seq); // handles out-of-order arrival
    }
    const c2s = concatSegments(stream.segments.c2s, limits.maxBytesPerStream);
    const s2c = concatSegments(stream.segments.s2c, limits.maxBytesPerStream);
    result.push({
      key: stream.key,
      clientIP: stream.clientIP, clientPort: stream.clientPort,
      serverIP: stream.serverIP, serverPort: stream.serverPort,
      c2s, s2c,
      truncated: stream.truncated,
    });
  }

  return { streams: result, streamCapReached: truncatedForStreamCap };
}

function concatSegments(sortedSegments, maxBytes) {
  let total = 0;
  const chunks = [];
  for (const seg of sortedSegments) {
    if (total + seg.data.length > maxBytes) {
      chunks.push(seg.data.subarray(0, maxBytes - total));
      total = maxBytes;
      break;
    }
    chunks.push(seg.data);
    total += seg.data.length;
  }
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) { out.set(c, pos); pos += c.length; }
  return out;
}
