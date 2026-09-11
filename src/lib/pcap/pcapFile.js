// ─── PCAP / PCAPNG CONTAINER PARSER ─────────────────────────────────────────
// Parses the two capture container formats into a flat list of raw packet
// records: { timestampMicros, linkType, data }. Everything above this layer
// (Ethernet/IP/TCP/UDP/TLS/DNS/HTTP decoding) works from that list — this
// module's only job is "get the packet bytes and the link-layer type out of
// the container correctly."
//
// Bounded by design: capture files can be enormous, so packet count and
// total bytes processed are capped (see PCAP_LIMITS in pcapAnalysis.js).
// This module itself just parses what it's given — the caller decides how
// much of the file to hand it.

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.pos = 0;
  }
  remaining() { return this.bytes.length - this.pos; }
  u16(le) { const v = this.view.getUint16(this.pos, le); this.pos += 2; return v; }
  u32(le) { const v = this.view.getUint32(this.pos, le); this.pos += 4; return v; }
  i32(le) { const v = this.view.getInt32(this.pos, le); this.pos += 4; return v; }
  bytes_(n) { const v = this.bytes.subarray(this.pos, this.pos + n); this.pos += n; return v; }
  skip(n) { this.pos += n; }
}

// Common LINKTYPE_* values we know how to strip a header for downstream.
export const LINKTYPE = {
  ETHERNET: 1,
  LINUX_SLL: 113,
  RAW_IP: 101,
  LINUX_SLL2: 276,
};

/**
 * Classic libpcap format (magic d4 c3 b2 a1 or a1 b2 c3 d4, big/little endian
 * variants, plus the microsecond/nanosecond timestamp variants).
 */
function parseClassicPcap(bytes, maxPackets, maxBytes) {
  const r = new Reader(bytes);
  const magic = r.u32(true);
  let littleEndian, nanoTimestamps;
  if (magic === 0xa1b2c3d4) { littleEndian = true; nanoTimestamps = false; }
  else if (magic === 0xd4c3b2a1) { littleEndian = false; nanoTimestamps = false; }
  else if (magic === 0xa1b23c4d) { littleEndian = true; nanoTimestamps = true; }
  else if (magic === 0x4d3cb2a1) { littleEndian = false; nanoTimestamps = true; }
  else throw new Error('Not a classic PCAP file (bad magic number).');

  r.pos = 0;
  r.u32(littleEndian); // re-read magic to advance position consistently
  r.u16(littleEndian); // version major
  r.u16(littleEndian); // version minor
  r.skip(8); // thiszone + sigfigs
  r.skip(4); // snaplen
  const linkType = r.u32(littleEndian);

  const packets = [];
  let totalBytes = 0;
  while (r.remaining() >= 16 && packets.length < maxPackets && totalBytes < maxBytes) {
    const tsSec = r.u32(littleEndian);
    const tsFrac = r.u32(littleEndian);
    const capLen = r.u32(littleEndian);
    r.u32(littleEndian); // origLen — not needed, we only look at captured bytes
    if (capLen > r.remaining() || capLen > 262144) break; // malformed/truncated — stop rather than misread
    const data = r.bytes_(capLen);
    totalBytes += capLen;
    packets.push({
      timestampMicros: tsSec * 1_000_000 + (nanoTimestamps ? Math.floor(tsFrac / 1000) : tsFrac),
      linkType,
      data,
    });
  }
  return { packets, linkType, truncated: r.remaining() >= 16 && packets.length >= maxPackets };
}

/**
 * PCAPNG format — block-based, each block is
 * [block type (4)][block total length (4)][block body][block total length (4) again].
 * We only care about Section Header Blocks (0x0A0D0D0A, sets endianness),
 * Interface Description Blocks (0x00000001, sets link type), and Enhanced
 * Packet Blocks (0x00000006, the actual packets). Everything else is
 * skipped via its self-reported length.
 */
function parsePcapNg(bytes, maxPackets, maxBytes) {
  let pos = 0;
  let littleEndian = true;
  let linkTypes = []; // indexed by interface id, set by Interface Description Blocks
  const packets = [];
  let totalBytes = 0;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  while (pos + 12 <= bytes.length && packets.length < maxPackets && totalBytes < maxBytes) {
    const blockType = view.getUint32(pos, true); // block type is always read... but endianness is only known after SHB
    let blockLen;

    if (blockType === 0x0a0d0d0a) {
      // Section Header Block — byte-order magic at offset+8 tells us endianness
      const bom = view.getUint32(pos + 8, true);
      littleEndian = bom === 0x1a2b3c4d;
      blockLen = view.getUint32(pos + 4, littleEndian);
      linkTypes = [];
    } else {
      blockLen = view.getUint32(pos + 4, littleEndian);
    }

    if (blockLen < 12 || pos + blockLen > bytes.length) break; // malformed — stop cleanly

    const realType = view.getUint32(pos, littleEndian);

    if (realType === 0x00000001) {
      // Interface Description Block: u16 linktype, u16 reserved, u32 snaplen, then options
      const linkType = view.getUint16(pos + 8, littleEndian);
      linkTypes.push(linkType);
    } else if (realType === 0x00000006) {
      // Enhanced Packet Block: u32 interfaceId, u32 tsHigh, u32 tsLow, u32 capLen, u32 origLen, then data
      const interfaceId = view.getUint32(pos + 8, littleEndian);
      const tsHigh = view.getUint32(pos + 12, littleEndian);
      const tsLow = view.getUint32(pos + 16, littleEndian);
      const capLen = view.getUint32(pos + 20, littleEndian);
      if (capLen <= blockLen - 32) {
        const data = bytes.subarray(pos + 28, pos + 28 + capLen);
        totalBytes += capLen;
        packets.push({
          timestampMicros: (tsHigh * 4294967296 + tsLow), // interface's if_tsresol default (assume microseconds — good enough for our purposes)
          linkType: linkTypes[interfaceId] ?? LINKTYPE.ETHERNET,
          data,
        });
      }
    }
    // Simple Packet Blocks (type 3) and other block types are intentionally
    // skipped — SPBs lack per-packet interface/timestamp info we'd want
    // anyway, and everything else (name resolution, stats, comments) isn't
    // packet data.

    pos += blockLen;
  }

  return { packets, linkType: linkTypes[0] ?? LINKTYPE.ETHERNET, truncated: packets.length >= maxPackets };
}

/**
 * @param {Uint8Array} bytes
 * @param {{maxPackets:number, maxBytes:number}} limits
 * @returns {{ packets: Array<{timestampMicros:number, linkType:number, data:Uint8Array}>, format: string, truncated: boolean }}
 */
export function parsePcapFile(bytes, limits) {
  if (bytes.length < 4) throw new Error('File too short to be a packet capture.');
  const magic = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);

  if (magic === 0x0a0d0d0a) {
    const result = parsePcapNg(bytes, limits.maxPackets, limits.maxBytes);
    return { ...result, format: 'PCAPNG' };
  }
  if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1 || magic === 0xa1b23c4d || magic === 0x4d3cb2a1) {
    const result = parseClassicPcap(bytes, limits.maxPackets, limits.maxBytes);
    return { ...result, format: 'PCAP' };
  }
  throw new Error('Not a recognised PCAP or PCAPNG file (bad magic number).');
}
