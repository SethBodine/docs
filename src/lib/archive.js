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
    case 'rar':
      return await extract7zOrRar(bytes, filename, kind, budget);
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

// ─── 7-ZIP / RAR (via the real 7-Zip CLI compiled to WASM) ──────────────────
// This is a deliberately reviewed and tested addition — see README.md's SBOM
// section for the history of why that sentence matters here specifically.
// One dependency covers both formats — 7-Zip's own codec reads RAR natively
// (RAR4 fully, RAR5 read-only), so there's no need for a second WASM runtime.
// Lazy-loaded (dynamic import) since the WASM binary is ~1.7MB and most users
// never touch a 7z/RAR file.
//
// Hardening, verified against real hostile fixtures (not assumed):
//   - `stdin: () => null` — without this, a password-protected archive can
//     make the underlying C++ code fall through to `window.prompt()` in a
//     real browser, i.e. a hostile file popping a native dialog in the
//     user's tab. Encrypted archives are additionally detected from the
//     `-slt` listing and skipped entirely before extraction is ever
//     attempted, so this path should never actually be reached — the
//     override exists as defense in depth in case detection is wrong.
//   - Every callMain() call is wrapped in try/catch: the library's own
//     exit-code handling is caught internally for normal errors, but a
//     password-prompt failure specifically throws a raw non-Error value
//     that bypasses that internal handling.
//   - Path-traversal check on every listed entry name before extraction
//     (same as ZIP/TAR).
//   - Symlinks are NEVER followed when reading extraction output. Verified
//     against a real-world RAR symlink-traversal exploit sample (a RAR
//     archive containing a symlink named "up" pointing outside the
//     extraction root, plus a file written through it) from the `rarfile`
//     Python library's own test suite: without this check, walking the
//     extracted output with a plain recursive readdir+readFile would follow
//     the symlink and return the file it points to as if it were legitimate
//     archive content. `FS.lstat` + `FS.isLink` catches it before `readFile`
//     is ever called, and it's reported as a finding instead of silently
//     resolved. This class of bug is the RAR/symlink analogue of "Zip Slip"
//     and is *not* caught by a plain name-based `../` check, since neither
//     entry name in the exploit actually contains `..`.
//   - Extraction happens entirely inside the WASM module's own in-memory
//     virtual filesystem (Emscripten MEMFS) — there is no real disk access
//     from this code path regardless of what a hostile archive contains.

function parse7zListing(stdout) {
  const entries = [];
  let current = null;
  for (const line of stdout.split('\n')) {
    const pathMatch = line.match(/^Path = (.+)$/);
    const sizeMatch = line.match(/^Size = (\d+)$/);
    const encMatch = line.match(/^Encrypted = \+/);
    if (pathMatch) {
      if (current) entries.push(current);
      current = { path: pathMatch[1], size: 0, encrypted: false, isDir: false };
    } else if (current && sizeMatch) {
      current.size = parseInt(sizeMatch[1], 10);
    } else if (current && encMatch) {
      current.encrypted = true;
    } else if (current && /^Folder = \+/.test(line)) {
      current.isDir = true;
    }
  }
  if (current) entries.push(current);
  return entries.slice(1); // first entry is the archive file itself, not a member
}

function walkEmscriptenDir(FS, dir, prefix, budget) {
  const out = [];
  for (const name of FS.readdir(dir)) {
    if (name === '.' || name === '..') continue;
    const full = `${dir}/${name}`;
    const rel = prefix ? `${prefix}/${name}` : name;

    // lstat (not stat) so we see the symlink itself rather than what it
    // resolves to — critical, see the file-level comment above.
    const st = FS.lstat(full);
    if (FS.isLink(st.mode)) {
      let target = '(unreadable)';
      try { target = FS.readlink(full); } catch { /* ignore */ }
      noteTruncation(budget, `Symlink skipped, not followed: "${rel}" -> "${target}" (RAR/7z archives can contain symlinks that point outside the extracted contents).`);
      continue;
    }
    if (FS.isDir(st.mode)) {
      out.push(...walkEmscriptenDir(FS, full, rel, budget));
    } else {
      out.push({ name: rel, bytes: FS.readFile(full) });
    }
  }
  return out;
}

async function extract7zOrRar(bytes, filename, kind, budget) {
  let SevenZip;
  try {
    ({ default: SevenZip } = await import('7z-wasm'));
  } catch (e) {
    return { children: [], error: `${kind.toUpperCase()} support unavailable in this build: ${e.message}` };
  }

  let stdout = '', stderrBuf = '';
  let sevenZip;
  try {
    // No locateFile override: the package resolves its own .wasm sibling via
    // new URL('7zz.wasm', import.meta.url) internally, which works in both
    // Node (verified directly) and Vite's build (which statically detects
    // and rewrites that exact import.meta.url-relative pattern) — confirmed
    // by inspecting the package's own bundled resolution logic rather than
    // assuming a manual override was required.
    sevenZip = await SevenZip({
      print: (s) => { stdout += s + '\n'; },
      printErr: (s) => { stderrBuf += s + '\n'; },
      stdin: () => null, // never fall through to window.prompt() on an encrypted archive
      noExitRuntime: true,
    });
  } catch (e) {
    return { children: [], error: `Could not initialise the ${kind.toUpperCase()} decoder: ${e.message}` };
  }

  const archiveName = 'input.' + kind;
  sevenZip.FS.writeFile(archiveName, bytes);

  let listRet;
  try {
    stdout = ''; stderrBuf = '';
    listRet = sevenZip.callMain(['l', '-slt', archiveName]);
  } catch (e) {
    // A password-protected archive with encrypted headers can't even be
    // listed without a password. Because stdin is wired to return null (so
    // it can never fall through to window.prompt()), the underlying C++
    // unwinds via a raw numeric exception rather than a normal Error —
    // verified directly against real header-encrypted .7z and RAR5 fixtures
    // rather than assumed. Give an accurate message for that specific,
    // expected case instead of surfacing the raw code.
    if (typeof e === 'number' || (e && typeof e.message === 'string' && /^\d+$/.test(e.message))) {
      return { children: [], error: `This ${kind.toUpperCase()} archive uses encrypted headers — even its file listing is password-protected. No password was supplied (and none is prompted for), so nothing could be read from it.` };
    }
    return { children: [], error: `Could not read ${kind.toUpperCase()} archive (${e?.message || e}).` };
  }
  if (listRet !== 0) {
    return { children: [], error: `Could not read ${kind.toUpperCase()} archive: ${stderrBuf.trim().slice(0, 300) || 'unknown error'}` };
  }

  const entries = parse7zListing(stdout).filter(e => !e.isDir);
  const encryptedEntries = entries.filter(e => e.encrypted);
  const acceptedPaths = [];
  for (const entry of entries) {
    if (entry.encrypted) continue; // reported separately below, extraction never attempted
    if (entry.path.includes('..') || entry.path.startsWith('/')) {
      noteTruncation(budget, `Suspicious path skipped in ${kind.toUpperCase()}: "${entry.path}".`);
      continue;
    }
    if (!reserveBudget(budget, entry.size, entry.path)) continue;
    acceptedPaths.push(entry.path);
  }

  const children = [];
  if (acceptedPaths.length > 0) {
    try {
      stdout = ''; stderrBuf = '';
      const extractRet = sevenZip.callMain(['x', archiveName, ...acceptedPaths, '-oout', '-y']);
      if (extractRet === 0) {
        children.push(...walkEmscriptenDir(sevenZip.FS, 'out', '', budget));
      } else {
        noteTruncation(budget, `${kind.toUpperCase()} extraction reported errors: ${stderrBuf.trim().slice(0, 300) || 'unknown error'}`);
      }
    } catch (e) {
      noteTruncation(budget, `${kind.toUpperCase()} extraction failed: ${e?.message || e}`);
    }
  }

  if (encryptedEntries.length > 0) {
    noteTruncation(budget, `${encryptedEntries.length} encrypted entr${encryptedEntries.length === 1 ? 'y' : 'ies'} in this ${kind.toUpperCase()} archive ${encryptedEntries.length === 1 ? 'was' : 'were'} not extracted (no password was supplied, and none is prompted for): ${encryptedEntries.slice(0, 10).map(e => e.path).join(', ')}`);
  }

  return { children };
}

export function isArchiveKind(kind) {
  return ['zip', 'tar', 'gzip', 'bzip2', 'xz', '7z', 'rar'].includes(kind);
}
