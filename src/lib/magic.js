// ─── MAGIC-BYTE SNIFFING ─────────────────────────────────────────────────────
// The dispatcher previously trusted the filename extension alone. Once we're
// handling archives/binaries, a mislabelled or deliberately-renamed file
// (evil.pdf that's actually a PE, whatever.txt that's actually a ZIP) needs to
// still be routed to the correct analyser and flagged as a mismatch.
//
// This only sniffs — it never executes or trusts content, and it degrades to
// "unknown" rather than guessing when signatures don't match.

function bytesStartWith(bytes, sig, offset = 0) {
  if (bytes.length < offset + sig.length) return false;
  for (let i = 0; i < sig.length; i++) {
    if (bytes[offset + i] !== sig[i]) return false;
  }
  return true;
}

function asciiAt(bytes, offset, len) {
  return String.fromCharCode(...bytes.slice(offset, offset + len));
}

/**
 * @param {Uint8Array} bytes
 * @returns {{ kind: string, label: string } | null}
 */
export function sniffMagic(bytes) {
  if (!bytes || bytes.length < 4) return null;

  // ZIP-family (also DOCX/XLSX/PPTX/JAR/APK — all ZIP containers)
  if (bytesStartWith(bytes, [0x50, 0x4b, 0x03, 0x04]) ||
      bytesStartWith(bytes, [0x50, 0x4b, 0x05, 0x06]) || // empty zip
      bytesStartWith(bytes, [0x50, 0x4b, 0x07, 0x08])) {
    return { kind: 'zip', label: 'ZIP archive (or ZIP-based container)' };
  }

  // GZIP
  if (bytesStartWith(bytes, [0x1f, 0x8b])) {
    return { kind: 'gzip', label: 'GZIP compressed data' };
  }

  // BZIP2
  if (bytesStartWith(bytes, [0x42, 0x5a, 0x68])) {
    return { kind: 'bzip2', label: 'BZIP2 compressed data' };
  }

  // XZ
  if (bytesStartWith(bytes, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) {
    return { kind: 'xz', label: 'XZ compressed data' };
  }

  // 7-Zip
  if (bytesStartWith(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) {
    return { kind: '7z', label: '7-Zip archive' };
  }

  // RAR (4.x and 5.x signatures)
  if (bytesStartWith(bytes, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]) ||
      bytesStartWith(bytes, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00])) {
    return { kind: 'rar', label: 'RAR archive' };
  }

  // TAR — no fixed magic at offset 0; "ustar" appears at byte 257 in POSIX tar
  if (bytes.length > 262) {
    const ustar = asciiAt(bytes, 257, 5);
    if (ustar === 'ustar') {
      return { kind: 'tar', label: 'TAR archive' };
    }
  }

  // Windows PE (EXE/DLL/SYS/...): "MZ" then a pointer to a PE header containing "PE\0\0"
  if (bytesStartWith(bytes, [0x4d, 0x5a])) {
    return { kind: 'pe', label: 'Windows PE executable/library' };
  }

  // ELF (Linux/Unix binaries)
  if (bytesStartWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) {
    return { kind: 'elf', label: 'ELF binary (Linux/Unix)' };
  }

  // Mach-O (macOS binaries) — flagged as "binary" only, no dedicated analyser yet
  if (bytesStartWith(bytes, [0xfe, 0xed, 0xfa, 0xce]) ||
      bytesStartWith(bytes, [0xfe, 0xed, 0xfa, 0xcf]) ||
      bytesStartWith(bytes, [0xce, 0xfa, 0xed, 0xfe]) ||
      bytesStartWith(bytes, [0xcf, 0xfa, 0xed, 0xfe])) {
    return { kind: 'macho', label: 'Mach-O binary (macOS)' };
  }

  // PCAP (classic libpcap) and PCAPNG
  if (bytesStartWith(bytes, [0xd4, 0xc3, 0xb2, 0xa1]) || bytesStartWith(bytes, [0xa1, 0xb2, 0xc3, 0xd4]) ||
      bytesStartWith(bytes, [0x4d, 0x3c, 0xb2, 0xa1]) || bytesStartWith(bytes, [0xa1, 0xb2, 0x3c, 0x4d])) {
    return { kind: 'pcap', label: 'PCAP packet capture' };
  }
  if (bytesStartWith(bytes, [0x0a, 0x0d, 0x0d, 0x0a])) {
    return { kind: 'pcapng', label: 'PCAPNG packet capture' };
  }

  // PDF
  if (bytesStartWith(bytes, [0x25, 0x50, 0x44, 0x46])) {
    return { kind: 'pdf', label: 'PDF document' };
  }

  return null; // plain text / unrecognised — extension-based dispatch takes over
}

/**
 * Extensions we'd reasonably expect for a given sniffed "kind" — used to decide
 * whether extension vs. content disagree.
 */
export const KIND_TO_EXPECTED_EXTS = {
  zip: ['zip', 'jar', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'apk', 'odt', 'ods', 'odp'],
  gzip: ['gz', 'tgz', 'tar.gz'],
  bzip2: ['bz2', 'tbz2', 'tar.bz2'],
  xz: ['xz', 'txz', 'tar.xz'],
  '7z': ['7z'],
  rar: ['rar'],
  tar: ['tar'],
  pe: ['exe', 'dll', 'sys', 'scr', 'cpl', 'ocx', 'msi'],
  elf: ['elf', 'so', 'ko', 'bin', ''],
  macho: ['dylib', 'bin', ''],
  pcap: ['pcap', 'cap'],
  pcapng: ['pcapng'],
  pdf: ['pdf'],
};
