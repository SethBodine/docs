// ─── SNMP COMMUNITY STRING EXTRACTOR ─────────────────────────────────────────
// SNMPv1/v2c authenticate with a plaintext "community string" (often
// "public"/"private" left at defaults) sent in the clear on every request.
// The message structure is a fixed, shallow ASN.1 BER SEQUENCE:
//   SEQUENCE { INTEGER version, OCTET STRING community, PDU ... }
// which is simple enough to walk directly without a general ASN.1 library.

function readTLV(bytes, offset) {
  if (offset >= bytes.length) return null;
  const tag = bytes[offset];
  let lenByte = bytes[offset + 1];
  let lenOffset = offset + 2;
  let length;
  if (lenByte & 0x80) {
    const numBytes = lenByte & 0x7f;
    if (numBytes === 0 || numBytes > 4 || lenOffset + numBytes > bytes.length) return null;
    length = 0;
    for (let i = 0; i < numBytes; i++) length = (length << 8) | bytes[lenOffset + i];
    lenOffset += numBytes;
  } else {
    length = lenByte;
  }
  if (lenOffset + length > bytes.length) return null;
  return { tag, value: bytes.subarray(lenOffset, lenOffset + length), next: lenOffset + length };
}

/** @returns {{version:number, community:string} | null} */
export function parseSnmpCommunity(bytes) {
  try {
    const outer = readTLV(bytes, 0);
    if (!outer || outer.tag !== 0x30) return null; // must be a SEQUENCE
    const version = readTLV(outer.value, 0);
    if (!version || version.tag !== 0x02) return null; // INTEGER
    const community = readTLV(outer.value, version.next);
    if (!community || community.tag !== 0x04) return null; // OCTET STRING
    return {
      version: version.value.length === 1 ? version.value[0] : 0,
      community: String.fromCharCode(...community.value),
    };
  } catch {
    return null;
  }
}
