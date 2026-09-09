// ─── PE (Windows PE32/PE32+) STRUCTURAL PARSER ──────────────────────────────
// Parses just enough of the PE format to be useful for static triage: COFF
// header, optional header basics, section table (+ entropy per section), and
// the import table (DLL + function names). Never executes anything.
//
// Defensive by necessity: this parses untrusted, potentially malformed or
// deliberately hostile binaries. Every read is bounds-checked, every walk is
// capped, and any failure degrades to a partial result with a note rather
// than throwing out of the whole analysis.

import { shannonEntropy } from './entropy.js';

const MAX_SECTIONS = 96;
const MAX_IMPORT_DLLS = 128;
const MAX_IMPORTS_PER_DLL = 500;

const MACHINE_TYPES = {
  0x014c: 'x86 (32-bit)',
  0x0200: 'Itanium (IA64)',
  0x8664: 'x64 (AMD64)',
  0x01c0: 'ARM',
  0xaa64: 'ARM64',
  0x01c4: 'ARMv7 (Thumb-2)',
};

const SUBSYSTEMS = {
  1: 'Native', 2: 'Windows GUI', 3: 'Windows Console',
  5: 'OS/2 Console', 7: 'POSIX Console', 9: 'Windows CE GUI',
  10: 'EFI Application', 12: 'EFI Boot Service Driver', 13: 'EFI Runtime Driver',
};

class SafeReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  u8(off) { this._check(off, 1); return this.view.getUint8(off); }
  u16(off) { this._check(off, 2); return this.view.getUint16(off, true); }
  u32(off) { this._check(off, 4); return this.view.getUint32(off, true); }
  bigU64(off) { this._check(off, 8); return this.view.getBigUint64(off, true); }
  _check(off, len) {
    if (off < 0 || off + len > this.bytes.length) throw new RangeError(`Read out of bounds at ${off}`);
  }
  cstr(off, maxLen = 256) {
    let s = '';
    for (let i = 0; i < maxLen; i++) {
      const b = this.u8(off + i);
      if (b === 0) break;
      s += String.fromCharCode(b);
    }
    return s;
  }
  slice(off, len) {
    this._check(off, len);
    return this.bytes.subarray(off, off + len);
  }
}

export function parsePe(bytes) {
  const warnings = [];
  const r = new SafeReader(bytes);

  const e_lfanew = r.u32(0x3c);
  if (r.u16(e_lfanew) !== 0x4550 && !(r.u8(e_lfanew) === 0x50 && r.u8(e_lfanew + 1) === 0x45)) {
    // "PE\0\0" as little-endian u16 pair check (0x50 'P', 0x45 'E')
  }
  if (!(r.u8(e_lfanew) === 0x50 && r.u8(e_lfanew + 1) === 0x45 && r.u8(e_lfanew + 2) === 0 && r.u8(e_lfanew + 3) === 0)) {
    throw new Error('PE signature not found at declared offset — file may be corrupt, truncated, or not a real PE.');
  }

  const coffOff = e_lfanew + 4;
  const machine = r.u16(coffOff);
  const numberOfSections = Math.min(r.u16(coffOff + 2), MAX_SECTIONS);
  const timeDateStamp = r.u32(coffOff + 4);
  const sizeOfOptionalHeader = r.u16(coffOff + 16);
  const characteristics = r.u16(coffOff + 18);
  const isDll = (characteristics & 0x2000) !== 0;

  const optOff = coffOff + 20;
  const magic = sizeOfOptionalHeader > 0 ? r.u16(optOff) : 0;
  const isPE32Plus = magic === 0x20b;

  let entryPoint = null, imageBase = null, subsystem = null, dllCharacteristics = null, sizeOfImage = null;
  let dataDirOff = null, numRvaAndSizes = 0;

  if (sizeOfOptionalHeader > 0) {
    entryPoint = r.u32(optOff + 16);
    if (isPE32Plus) {
      imageBase = r.bigU64(optOff + 24);
      sizeOfImage = r.u32(optOff + 56);
      subsystem = r.u16(optOff + 68);
      dllCharacteristics = r.u16(optOff + 70);
      numRvaAndSizes = r.u32(optOff + 108);
      dataDirOff = optOff + 112;
    } else {
      imageBase = BigInt(r.u32(optOff + 28));
      sizeOfImage = r.u32(optOff + 56);
      subsystem = r.u16(optOff + 68);
      dllCharacteristics = r.u16(optOff + 70);
      numRvaAndSizes = r.u32(optOff + 92);
      dataDirOff = optOff + 96;
    }
  }

  // ── Section table ──────────────────────────────────────────────────────
  const sectionTableOff = optOff + sizeOfOptionalHeader;
  const sections = [];
  for (let i = 0; i < numberOfSections; i++) {
    const base = sectionTableOff + i * 40;
    try {
      const nameBytes = r.slice(base, 8);
      let name = '';
      for (const b of nameBytes) { if (b === 0) break; name += String.fromCharCode(b); }
      const virtualSize = r.u32(base + 8);
      const virtualAddress = r.u32(base + 12);
      const sizeOfRawData = r.u32(base + 16);
      const pointerToRawData = r.u32(base + 20);
      const sectionCharacteristics = r.u32(base + 36);

      let entropy = null;
      if (sizeOfRawData > 0 && pointerToRawData > 0) {
        try {
          const cappedLen = Math.min(sizeOfRawData, 4 * 1024 * 1024); // cap entropy sample at 4MB/section
          entropy = shannonEntropy(r.slice(pointerToRawData, cappedLen));
        } catch { /* section data out of bounds — skip entropy for this one */ }
      }

      sections.push({
        name: name || `(unnamed #${i})`, virtualSize, virtualAddress, sizeOfRawData, pointerToRawData,
        executable: (sectionCharacteristics & 0x20000000) !== 0,
        writable: (sectionCharacteristics & 0x80000000) !== 0,
        entropy,
      });
    } catch (e) {
      warnings.push(`Section ${i} could not be fully read: ${e.message}`);
      break;
    }
  }

  function rvaToOffset(rva) {
    for (const s of sections) {
      if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.sizeOfRawData)) {
        return s.pointerToRawData + (rva - s.virtualAddress);
      }
    }
    return null;
  }

  // ── Import table (Data Directory index 1) ─────────────────────────────
  const imports = [];
  try {
    if (dataDirOff !== null && numRvaAndSizes > 1) {
      const importDirRva = r.u32(dataDirOff + 1 * 8);
      const importDirSize = r.u32(dataDirOff + 1 * 8 + 4);
      if (importDirRva && importDirSize) {
        let descOff = rvaToOffset(importDirRva);
        let dllCount = 0;
        while (descOff !== null && dllCount < MAX_IMPORT_DLLS) {
          const originalFirstThunk = r.u32(descOff);
          const nameRva = r.u32(descOff + 12);
          const firstThunk = r.u32(descOff + 16);
          if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break; // null terminator

          const nameOff = rvaToOffset(nameRva);
          const dllName = nameOff !== null ? r.cstr(nameOff, 128) : '(unresolvable)';

          const thunkRva = originalFirstThunk || firstThunk;
          const functions = [];
          let thunkOff = rvaToOffset(thunkRva);
          let fnCount = 0;
          const thunkSize = isPE32Plus ? 8 : 4;
          while (thunkOff !== null && fnCount < MAX_IMPORTS_PER_DLL) {
            const thunkVal = isPE32Plus ? r.bigU64(thunkOff) : BigInt(r.u32(thunkOff));
            if (thunkVal === 0n) break;
            const ordinalFlag = isPE32Plus ? (thunkVal & 0x8000000000000000n) !== 0n : (thunkVal & 0x80000000n) !== 0n;
            if (ordinalFlag) {
              functions.push(`Ordinal#${thunkVal & 0xffffn}`);
            } else {
              const ibnRva = Number(thunkVal & 0x7fffffffn);
              const ibnOff = rvaToOffset(ibnRva);
              if (ibnOff !== null) {
                functions.push(r.cstr(ibnOff + 2, 128)); // +2 skips the Hint field
              }
            }
            thunkOff += thunkSize;
            fnCount++;
          }

          imports.push({ dll: dllName, functions });
          descOff += 20;
          dllCount++;
        }
      }
    }
  } catch (e) {
    warnings.push(`Import table parsing stopped early: ${e.message}`);
  }

  return {
    machine: MACHINE_TYPES[machine] || `Unknown (0x${machine.toString(16)})`,
    isDll,
    isPE32Plus,
    timeDateStamp,
    compiledAt: timeDateStamp ? new Date(timeDateStamp * 1000).toISOString() : null,
    entryPoint,
    imageBase: imageBase !== null ? '0x' + imageBase.toString(16) : null,
    subsystem: SUBSYSTEMS[subsystem] || `Unknown (${subsystem})`,
    dllCharacteristics,
    aslr: dllCharacteristics !== null ? (dllCharacteristics & 0x0040) !== 0 : null,
    nxCompat: dllCharacteristics !== null ? (dllCharacteristics & 0x0100) !== 0 : null,
    sizeOfImage,
    sections,
    imports,
    warnings,
  };
}
