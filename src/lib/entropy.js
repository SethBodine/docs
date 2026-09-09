// ─── SHANNON ENTROPY ─────────────────────────────────────────────────────────
// Used to flag PE/ELF sections that are likely packed, encrypted, or otherwise
// obfuscated — packers and encrypted payloads produce near-random byte
// distributions (entropy close to 8.0 bits/byte), whereas normal code/data
// sections sit meaningfully lower.

export function shannonEntropy(bytes) {
  if (!bytes || bytes.length === 0) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
  let entropy = 0;
  const len = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function entropyLabel(entropy) {
  if (entropy >= 7.5) return { label: 'Very high (likely packed/encrypted/compressed)', severity: 'medium' };
  if (entropy >= 6.8) return { label: 'High', severity: 'low' };
  return { label: 'Normal', severity: 'info' };
}
