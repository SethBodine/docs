// ─── TLS CLIENTHELLO PARSER + JA3 FINGERPRINT ───────────────────────────────
// Parses just the ClientHello handshake message — the one part of a TLS
// connection that's never encrypted, in TLS 1.2 or 1.3 — to extract the SNI
// hostname and compute a JA3 fingerprint. Never attempts to decrypt
// anything past the handshake; there is no key material available to do so
// even if we wanted to.
//
// JA3 (Salesforce's fingerprint format): MD5 of
//   TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// with GREASE values (RFC 8701 — reserved values like 0x0A0A, 0x1A1A, ...
// used by some clients to test extensibility) stripped from ciphers,
// extensions, and curves before hashing. Verified against a real capture's
// known-correct JA3 (computed independently by tshark) rather than only
// against the spec document — see test-harness.mjs.

import md5 from 'blueimp-md5';

const GREASE_VALUES = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
]);

class Reader {
  constructor(bytes) { this.bytes = bytes; this.pos = 0; }
  remaining() { return this.bytes.length - this.pos; }
  u8() { return this.bytes[this.pos++]; }
  u16() { const v = (this.bytes[this.pos] << 8) | this.bytes[this.pos + 1]; this.pos += 2; return v; }
  u24() { const v = (this.bytes[this.pos] << 16) | (this.bytes[this.pos + 1] << 8) | this.bytes[this.pos + 2]; this.pos += 3; return v; }
  take(n) { if (this.pos + n > this.bytes.length) throw new Error('TLS field runs past end of buffer'); const v = this.bytes.subarray(this.pos, this.pos + n); this.pos += n; return v; }
}

/**
 * Pulls the reassembled ClientHello handshake body out of a client-to-server
 * TCP stream, which may have the handshake message split across multiple
 * TLS records (rare for ClientHello, but large ones with many extensions
 * can do it).
 */
function extractHandshakeBody(streamBytes) {
  let offset = 0;
  const handshakeChunks = [];
  let recordsSeen = 0;

  while (offset + 5 <= streamBytes.length && recordsSeen < 20) {
    const contentType = streamBytes[offset];
    const recordLength = (streamBytes[offset + 3] << 8) | streamBytes[offset + 4];
    if (contentType !== 22) break; // not a Handshake record — ClientHello must be the first record(s)
    if (offset + 5 + recordLength > streamBytes.length) break; // truncated capture
    handshakeChunks.push(streamBytes.subarray(offset + 5, offset + 5 + recordLength));
    offset += 5 + recordLength;
    recordsSeen++;
  }
  if (handshakeChunks.length === 0) return null;

  let total = 0;
  for (const c of handshakeChunks) total += c.length;
  const combined = new Uint8Array(total);
  let pos = 0;
  for (const c of handshakeChunks) { combined.set(c, pos); pos += c.length; }
  return combined;
}

/**
 * @param {Uint8Array} streamBytes - the client-to-server direction of a reassembled TCP stream
 * @returns {null | { sni: string|null, tlsVersion: number, ja3: string, ja3Hash: string }}
 */
export function parseClientHello(streamBytes) {
  const handshake = extractHandshakeBody(streamBytes);
  if (!handshake || handshake.length < 4) return null;
  if (handshake[0] !== 1) return null; // not a ClientHello (type 1)

  try {
    const r = new Reader(handshake);
    r.u8(); // handshake type
    const declaredLen = r.u24();
    if (r.remaining() < Math.min(declaredLen, r.remaining())) { /* proceed with what we have */ }

    const clientVersion = r.u16();
    r.take(32); // random
    const sessionIdLen = r.u8();
    r.take(sessionIdLen);

    const cipherSuitesLen = r.u16();
    const cipherSuites = [];
    const cipherEnd = r.pos + cipherSuitesLen;
    while (r.pos < cipherEnd) cipherSuites.push(r.u16());

    const compressionLen = r.u8();
    r.take(compressionLen);

    let sni = null;
    const extensionTypes = [];
    let ellipticCurves = [];
    let pointFormats = [];

    if (r.remaining() >= 2) {
      const extensionsLen = r.u16();
      const extEnd = Math.min(r.pos + extensionsLen, handshake.length);
      while (r.pos + 4 <= extEnd) {
        const extType = r.u16();
        const extLen = r.u16();
        if (r.pos + extLen > handshake.length) break;
        const extData = r.take(extLen);
        extensionTypes.push(extType);

        if (extType === 0) { // server_name
          try {
            const er = new Reader(extData);
            er.u16(); // server_name_list length
            const nameType = er.u8();
            const nameLen = er.u16();
            if (nameType === 0) sni = String.fromCharCode(...er.take(nameLen));
          } catch { /* malformed SNI extension — leave sni null */ }
        } else if (extType === 10) { // supported_groups
          try {
            const er = new Reader(extData);
            const listLen = er.u16();
            const end = Math.min(er.pos + listLen, extData.length);
            while (er.pos + 2 <= end) ellipticCurves.push(er.u16());
          } catch { /* leave whatever we got */ }
        } else if (extType === 11) { // ec_point_formats
          try {
            const er = new Reader(extData);
            const listLen = er.u8();
            const end = Math.min(er.pos + listLen, extData.length);
            while (er.pos < end) pointFormats.push(er.u8());
          } catch { /* leave whatever we got */ }
        }
      }
    }

    const stripGrease = (arr) => arr.filter(v => !GREASE_VALUES.has(v));
    const ja3 = [
      clientVersion,
      stripGrease(cipherSuites).join('-'),
      stripGrease(extensionTypes).join('-'),
      stripGrease(ellipticCurves).join('-'),
      pointFormats.join('-'),
    ].join(',');

    return { sni, tlsVersion: clientVersion, ja3, ja3Hash: md5(ja3) };
  } catch {
    return null; // malformed/truncated ClientHello — not fatal to the rest of the analysis
  }
}
