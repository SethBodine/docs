// ─── LINK / NETWORK / TRANSPORT LAYER DECODING ──────────────────────────────
// Strips headers layer by layer to get at the actual payload. Every function
// here returns null on anything malformed/truncated rather than throwing —
// a single corrupt packet in a capture shouldn't abort processing the rest.

import { LINKTYPE } from './pcapFile.js';

function ipToString(bytes, offset, isV6) {
  if (isV6) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(((bytes[offset + i] << 8) | bytes[offset + i + 1]).toString(16));
    return parts.join(':');
  }
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

/** Strip the link-layer header, return { ethertype, payload } or null. */
export function decodeLinkLayer(data, linkType) {
  try {
    if (linkType === LINKTYPE.ETHERNET) {
      if (data.length < 14) return null;
      const ethertype = (data[12] << 8) | data[13];
      return { ethertype, payload: data.subarray(14) };
    }
    if (linkType === LINKTYPE.LINUX_SLL) {
      // 16-byte header: packet type(2), arphrd(2), addr len(2), addr(8), protocol(2)
      if (data.length < 16) return null;
      const ethertype = (data[14] << 8) | data[15];
      return { ethertype, payload: data.subarray(16) };
    }
    if (linkType === LINKTYPE.LINUX_SLL2) {
      // 20-byte header: protocol(2) at offset 0, ... this differs from SLL — protocol is first
      if (data.length < 20) return null;
      const ethertype = (data[0] << 8) | data[1];
      return { ethertype, payload: data.subarray(20) };
    }
    if (linkType === LINKTYPE.RAW_IP) {
      if (data.length < 1) return null;
      const version = data[0] >> 4;
      return { ethertype: version === 6 ? 0x86dd : 0x0800, payload: data };
    }
  } catch { /* fall through */ }
  return null;
}

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;
export { ETHERTYPE_IPV4, ETHERTYPE_IPV6 };

/** Parse IPv4/IPv6, return { protocol, srcIP, dstIP, payload } or null. */
export function decodeIpLayer(ethertype, data) {
  try {
    if (ethertype === ETHERTYPE_IPV4) {
      if (data.length < 20) return null;
      const ihl = (data[0] & 0x0f) * 4;
      if (ihl < 20 || data.length < ihl) return null;
      const protocol = data[9];
      const totalLength = (data[2] << 8) | data[3];
      const srcIP = ipToString(data, 12, false);
      const dstIP = ipToString(data, 16, false);
      const end = totalLength > 0 && totalLength <= data.length ? totalLength : data.length;
      return { protocol, srcIP, dstIP, payload: data.subarray(ihl, end) };
    }
    if (ethertype === ETHERTYPE_IPV6) {
      if (data.length < 40) return null;
      const protocol = data[6]; // next header — doesn't handle extension headers, covers the common case
      const payloadLength = (data[4] << 8) | data[5];
      const srcIP = ipToString(data, 8, true);
      const dstIP = ipToString(data, 24, true);
      const end = payloadLength > 0 && 40 + payloadLength <= data.length ? 40 + payloadLength : data.length;
      return { protocol, srcIP, dstIP, payload: data.subarray(40, end) };
    }
  } catch { /* fall through */ }
  return null;
}

export const IP_PROTO = { TCP: 6, UDP: 17 };

/** Parse TCP header, return { srcPort, dstPort, seq, ackSeq, flags, payload } or null. */
export function decodeTcp(data) {
  try {
    if (data.length < 20) return null;
    const srcPort = (data[0] << 8) | data[1];
    const dstPort = (data[2] << 8) | data[3];
    const seq = ((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]) >>> 0;
    const dataOffset = (data[12] >> 4) * 4;
    if (dataOffset < 20 || data.length < dataOffset) return null;
    const flags = data[13];
    return {
      srcPort, dstPort, seq,
      flags: { fin: !!(flags & 0x01), syn: !!(flags & 0x02), rst: !!(flags & 0x04), psh: !!(flags & 0x08), ack: !!(flags & 0x10) },
      payload: data.subarray(dataOffset),
    };
  } catch { return null; }
}

/** Parse UDP header, return { srcPort, dstPort, payload } or null. */
export function decodeUdp(data) {
  try {
    if (data.length < 8) return null;
    const srcPort = (data[0] << 8) | data[1];
    const dstPort = (data[2] << 8) | data[3];
    const length = (data[4] << 8) | data[5];
    const end = length >= 8 && length <= data.length ? length : data.length;
    return { srcPort, dstPort, payload: data.subarray(8, end) };
  } catch { return null; }
}
