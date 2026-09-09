// ─── ARCHIVE ENGINE ──────────────────────────────────────────────────────────
// Recursive, capped archive extraction: ZIP / TAR / GZIP / BZIP2 / XZ / 7Z / RAR
// (JAR is just a ZIP and reuses this directly).
//
// Security model (this is the part that matters — decompression bombs are the
// main new attack surface a static analyser gains by opening archives):
//   - MAX_TOTAL_EXPANDED_BYTES   — hard ceiling across the WHOLE recursive tree
//   - MAX_INDIVIDUAL_FILE_BYTES  — hard ceiling per extracted file
//   - MAX_FILES_PER_ARCHIVE      — hard ceiling on total extracted file count
//   - MAX_RECURSION_DEPTH        — archive-in-archive-in-archive nesting limit
// All limits are enforced against a single shared `budget` object threaded
// through every recursive call, so nested archives can't reset the counters.
// Nothing extracted is ever written to disk — everything stays as in-memory
// Uint8Arrays / Blobs for the lifetime of the analysis.

import JSZip from 'jszip';
import { Gunzip } from 'fflate';
import Bunzip from 'seek-bzip';
import { sniffMagic } from './magic.js';

export const ARCHIVE_LIMITS = {
  MAX_UPLOAD_BYTES: 250 * 1024 * 1024,          // 250 MB
  MAX_TOTAL_EXPANDED_BYTES: 1024 * 1024 * 1024, // 1 GB
  MAX_INDIVIDUAL_FILE_BYTES: 100 * 1024 * 1024, // 100 MB
  MAX_FILES_PER_ARCHIVE: 10_000,
  MAX_RECURSION_DEPTH: 5,
};

export function newBudget() {
  return { totalExpandedBytes: 0, totalFiles: 0, truncationNotes: [] };
}

function noteTruncation(budget, reason) {
  if (!budget.truncationNotes.includes(reason)) budget.truncationNotes.push(reason);
}

/** Returns true if OK to add `size` more bytes / 1 more file to the shared budget. */
function reserveBudget(budget, size, path) {
  if (budget.totalFiles + 1 > ARCHIVE_LIMITS.MAX_FILES_PER_ARCHIVE) {
    noteTruncation(budget, `File-count limit (${ARCHIVE_LIMITS.MAX_FILES_PER_ARCHIVE}) reached — remaining entries skipped.`);
    return false;
  }
  if (size > ARCHIVE_LIMITS.MAX_INDIVIDUAL_FILE_BYTES) {
    noteTruncation(budget, `"${path}" exceeds the per-file limit (${ARCHIVE_LIMITS.MAX_INDIVIDUAL_FILE_BYTES / 1024 / 1024}MB) and was skipped.`);
    return false;
  }
  if (budget.totalExpandedBytes + size > ARCHIVE_LIMITS.MAX_TOTAL_EXPANDED_BYTES) {
    noteTruncation(budget, `Total expansion limit (${ARCHIVE_LIMITS.MAX_TOTAL_EXPANDED_BYTES / 1024 / 1024}MB) reached — remaining entries skipped.`);
    return false;
  }
  budget.totalFiles += 1;
  budget.totalExpandedBytes += size;
  return true;
}

// ─── ZIP / JAR ───────────────────────────────────────────────────────────────
async function extractZip(bytes, budget) {
  const children = [];
  let zip;
  try {
    zip = await JSZip.loadAsync(bytes);
  } catch (e) {
    return { children, error: `Could not open ZIP: ${e.message}` };
  }

  const names = Object.keys(zip.files).sort();
  for (const name of names) {
    const entry = zip.files[name];
    if (entry.dir) continue;

    // Path traversal guard — JSZip normalizes ../ sequences internally before
    // exposing `entry.name`, so check the RAW pre-normalization name
    // (`unsafeOriginalName`) to actually detect an attempted traversal rather
    // than silently accepting an already-sanitized path with no warning.
    const rawName = entry.unsafeOriginalName ?? name;
    if (rawName.includes('..') || rawName.startsWith('/')) {
      noteTruncation(budget, `Suspicious path skipped: "${rawName}" (path traversal pattern).`);
      continue;
    }

    // JSZip exposes the pre-inflation size on the internal entry metadata —
    // use it to reject oversized entries BEFORE spending CPU/memory to inflate them.
    const declaredSize = entry._data?.uncompressedSize ?? entry.uncompressedSize;
    if (typeof declaredSize === 'number' && !reserveBudget(budget, declaredSize, name)) {
      continue;
    }

    let content;
    try {
      content = await entry.async('uint8array');
    } catch (e) {
      noteTruncation(budget, `Could not extract "${name}": ${e.message}`);
      continue;
    }

    // If we couldn't read a declared size up front, enforce the cap post-hoc.
    if (typeof declaredSize !== 'number' && !reserveBudget(budget, content.length, name)) {
      continue;
    }

    children.push({ name, bytes: content });
  }
  return { children };
}

// ─── TAR (hand-rolled — deliberately no dependency, so we control the budget
// checks block-by-block instead of allocating everything up front) ──────────
function parseTar(bytes, budget) {
  const children = [];
  const BLOCK = 512;
  let offset = 0;

  function readAscii(start, len) {
    let s = '';
    for (let i = 0; i < len; i++) {
      const b = bytes[start + i];
      if (b === 0) break;
      s += String.fromCharCode(b);
    }
    return s.trim();
  }

  function readOctal(start, len) {
    const s = readAscii(start, len).trim();
    if (!s) return 0;
    return parseInt(s, 8) || 0;
  }

  while (offset + BLOCK <= bytes.length) {
    // Two all-zero blocks in a row = end of archive
    const isZeroBlock = bytes.slice(offset, offset + BLOCK).every(b => b === 0);
    if (isZeroBlock) break;

    const name = readAscii(offset, 100);
    if (!name) break; // malformed / end
    const size = readOctal(offset + 124, 12);
    const typeflag = String.fromCharCode(bytes[offset + 156] || 0);
    const prefix = readAscii(offset + 345, 155);
    const fullName = prefix ? `${prefix}/${name}` : name;

    offset += BLOCK;

    const isRegularFile = typeflag === '0' || typeflag === '\0';
    const dataStart = offset;
    const paddedSize = Math.ceil(size / BLOCK) * BLOCK;

    if (isRegularFile && size > 0) {
      if (fullName.includes('..') || fullName.startsWith('/')) {
        noteTruncation(budget, `Suspicious path skipped in TAR: "${fullName}".`);
      } else if (reserveBudget(budget, size, fullName)) {
        children.push({ name: fullName, bytes: bytes.slice(dataStart, dataStart + size) });
      }
    }

    offset += paddedSize;
  }

  return { children };
}

// ─── GZIP (streaming, so we can abort mid-decompress on a bomb) ─────────────
async function extractGzip(bytes, budget, filename) {
  return new Promise((resolve) => {
    const outChunks = [];
    let total = 0;
    let aborted = false;

    const gz = new Gunzip((chunk, final) => {
      if (aborted) return;
      total += chunk.length;
      if (total > ARCHIVE_LIMITS.MAX_INDIVIDUAL_FILE_BYTES) {
        aborted = true;
        noteTruncation(budget, `"${filename}" exceeded the decompressed-size limit while inflating and was truncated (possible decompression bomb).`);
        resolve({ children: [], truncated: true });
        return;
      }
      outChunks.push(chunk);
    });

    try {
      // Feed in bounded slices so we get callbacks incrementally rather than
      // one giant synchronous burst.
      const CHUNK = 262144; // 256KB
      for (let i = 0; i < bytes.length && !aborted; i += CHUNK) {
        gz.push(bytes.slice(i, i + CHUNK), i + CHUNK >= bytes.length);
      }
    } catch (e) {
      if (!aborted) {
        noteTruncation(budget, `Could not decompress "${filename}": ${e.message}`);
        resolve({ children: [], error: e.message });
        return;
      }
    }

    if (aborted) return;

    const combined = new Uint8Array(total);
    let pos = 0;
    for (const c of outChunks) { combined.set(c, pos); pos += c.length; }

    const innerName = filename.replace(/\.(gz|tgz)$/i, '') || 'decompressed';
    if (!reserveBudget(budget, combined.length, innerName)) {
      resolve({ children: [] });
      return;
    }
    resolve({ children: [{ name: innerName, bytes: combined }] });
  });
}

// ─── BZIP2 (byte-by-byte bounded output stream so decode() aborts on a bomb) ─
function extractBzip2(bytes, budget, filename) {
  const cap = ARCHIVE_LIMITS.MAX_INDIVIDUAL_FILE_BYTES;
  const chunks = [];
  let total = 0;

  const boundedOutput = {
    _coerced: false,
    writeByte(b) {
      if (total >= cap) throw new Error('BZIP2_OUTPUT_LIMIT_EXCEEDED');
      chunks.push(b);
      total++;
    },
    write(buf, off, len) {
      for (let i = 0; i < len; i++) this.writeByte(buf[off + i]);
      return len;
    },
    flush() {},
  };

  try {
    Bunzip.decode(bytes, boundedOutput, false);
  } catch (e) {
    if (String(e.message).includes('BZIP2_OUTPUT_LIMIT_EXCEEDED')) {
      noteTruncation(budget, `"${filename}" exceeded the decompressed-size limit while inflating and was truncated (possible decompression bomb).`);
      return { children: [], truncated: true };
    }
    noteTruncation(budget, `Could not decompress "${filename}": ${e.message}`);
    return { children: [], error: e.message };
  }

  const combined = new Uint8Array(chunks);
  const innerName = filename.replace(/\.(bz2|tbz2)$/i, '') || 'decompressed';
  if (!reserveBudget(budget, combined.length, innerName)) return { children: [] };
  return { children: [{ name: innerName, bytes: combined }] };
}

// ─── XZ (via WASM streaming decoder, ReadableStream-based so it's abortable) ─
async function extractXz(bytes, budget, filename) {
  let XzReadableStream;
  try {
    // xz-decompress ships as a CJS/UMD bundle. Depending on the bundler/runtime's
    // interop, the named export can land on the namespace object directly OR on
    // its `.default` — handle both rather than assuming one.
    const mod = await import('xz-decompress');
    XzReadableStream = mod.XzReadableStream || mod.default?.XzReadableStream;
    if (typeof XzReadableStream !== 'function') throw new Error('XzReadableStream export not found');
  } catch (e) {
    noteTruncation(budget, `XZ support unavailable in this build: ${e.message}`);
    return { children: [], error: 'xz unavailable' };
  }

  const cap = ARCHIVE_LIMITS.MAX_INDIVIDUAL_FILE_BYTES;
  const src = new Response(bytes).body; // ReadableStream<Uint8Array>
  const stream = new XzReadableStream(src);
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > cap) {
        await reader.cancel();
        noteTruncation(budget, `"${filename}" exceeded the decompressed-size limit while inflating and was truncated (possible decompression bomb).`);
        return { children: [], truncated: true };
      }
      chunks.push(value);
    }
  } catch (e) {
    noteTruncation(budget, `Could not decompress "${filename}": ${e.message}`);
    return { children: [], error: e.message };
  }

  const combined = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) { combined.set(c, pos); pos += c.length; }

  const innerName = filename.replace(/\.(xz|txz)$/i, '') || 'decompressed';
  if (!reserveBudget(budget, combined.length, innerName)) return { children: [] };
  return { children: [{ name: innerName, bytes: combined }] };
}

/**
 * Extract one layer of an archive/compressed container. If the result of
 * decompressing a single-file format (gzip/bzip2/xz) is itself a TAR, that's
 * unwrapped too so `.tar.gz` etc. yield the real file list in one call.
 */
export async function extractOneLayer(kind, bytes, filename, budget) {
  let result;
  switch (kind) {
    case 'zip':   result = await extractZip(bytes, budget); break;
    case 'tar':   result = parseTar(bytes, budget); break;
    case 'gzip':  result = await extractGzip(bytes, budget, filename); break;
    case 'bzip2': result = extractBzip2(bytes, budget, filename); break;
    case 'xz':    result = await extractXz(bytes, budget, filename); break;
    case '7z':
      return { children: [], error: '7z support is not yet implemented in this build.' };
    case 'rar':
      return { children: [], error: 'RAR support is not yet implemented in this build.' };
    default:
      return { children: [], error: `Unsupported archive kind: ${kind}` };
  }

  // gzip/bzip2/xz produce exactly one inner file — if that file is itself a
  // TAR, unwrap it immediately so children reflect the real archive contents.
  if (['gzip', 'bzip2', 'xz'].includes(kind) && result.children?.length === 1) {
    const inner = result.children[0];
    const innerMagic = sniffMagic(inner.bytes);
    if (innerMagic?.kind === 'tar') {
      const tarResult = parseTar(inner.bytes, budget);
      return { ...result, children: tarResult.children };
    }
  }

  return result;
}

export function isArchiveKind(kind) {
  return ['zip', 'tar', 'gzip', 'bzip2', 'xz', '7z', 'rar'].includes(kind);
}
