// ─── ELF STRUCTURAL PARSER ───────────────────────────────────────────────────
// Parses ELF headers, section headers (+ entropy), program headers (PT_INTERP,
// PT_DYNAMIC), and the dynamic section (DT_NEEDED / DT_RPATH / DT_RUNPATH) plus
// undefined dynamic symbols (i.e. imported libc/library functions). Same
// defensive posture as peParser.js — this parses untrusted binaries.

import { shannonEntropy } from './entropy.js';

const MAX_SECTIONS = 200;
const MAX_SYMBOLS = 5000;
const MAX_DYN_ENTRIES = 500;

const MACHINES = { 3: 'x86', 62: 'x86-64', 40: 'ARM', 183: 'ARM64 (AArch64)', 8: 'MIPS', 20: 'PowerPC', 21: 'PowerPC64', 243: 'RISC-V' };
const TYPES = { 1: 'Relocatable', 2: 'Executable', 3: 'Shared object (PIE/.so)', 4: 'Core dump' };

class SafeReader {
  constructor(bytes, littleEndian) {
    this.bytes = bytes;
    this.le = littleEndian;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  u8(off) { this._check(off, 1); return this.view.getUint8(off); }
  u16(off) { this._check(off, 2); return this.view.getUint16(off, this.le); }
  u32(off) { this._check(off, 4); return this.view.getUint32(off, this.le); }
  u64(off) { this._check(off, 8); return this.view.getBigUint64(off, this.le); }
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

export function parseElf(bytes) {
  const warnings = [];
  if (bytes.length < 20 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    throw new Error('ELF magic not found — file may be corrupt or truncated.');
  }

  const is64 = bytes[4] === 2;
  const littleEndian = bytes[5] === 1;
  const r = new SafeReader(bytes, littleEndian);

  const e_type = r.u16(16);
  const e_machine = r.u16(18);
  const e_entry = is64 ? r.u64(24) : BigInt(r.u32(24));
  const e_phoff = is64 ? Number(r.u64(32)) : r.u32(28);
  const e_shoff = is64 ? Number(r.u64(40)) : r.u32(32);
  const e_phentsize = is64 ? r.u16(54) : r.u16(42);
  const e_phnum = is64 ? r.u16(56) : r.u16(44);
  const e_shentsize = is64 ? r.u16(58) : r.u16(46);
  const e_shnum = Math.min(is64 ? r.u16(60) : r.u16(48), MAX_SECTIONS);
  const e_shstrndx = is64 ? r.u16(62) : r.u16(50);

  // ── Section headers ─────────────────────────────────────────────────────
  const rawSections = [];
  for (let i = 0; i < e_shnum; i++) {
    try {
      const base = e_shoff + i * e_shentsize;
      const sh_name = r.u32(base);
      const sh_type = r.u32(base + 4);
      let sh_offset, sh_size, sh_link;
      if (is64) {
        sh_offset = Number(r.u64(base + 24));
        sh_size = Number(r.u64(base + 32));
        sh_link = r.u32(base + 40);
      } else {
        sh_offset = r.u32(base + 16);
        sh_size = r.u32(base + 20);
        sh_link = r.u32(base + 24);
      }
      rawSections.push({ sh_name, sh_type, sh_offset, sh_size, sh_link });
    } catch (e) {
      warnings.push(`Section header ${i} truncated: ${e.message}`);
      break;
    }
  }

  // Resolve section names via shstrtab
  let shstrtabOff = null;
  if (rawSections[e_shstrndx]) shstrtabOff = rawSections[e_shstrndx].sh_offset;
  const sections = rawSections.map((s, i) => {
    let name = `(section #${i})`;
    if (shstrtabOff !== null) {
      try { name = r.cstr(shstrtabOff + s.sh_name, 64) || name; } catch { /* leave default */ }
    }
    let entropy = null;
    if (s.sh_type !== 8 /* SHT_NOBITS = .bss, no file content */ && s.sh_size > 0) {
      try {
        const cappedLen = Math.min(s.sh_size, 4 * 1024 * 1024);
        entropy = shannonEntropy(r.slice(s.sh_offset, cappedLen));
      } catch { /* out of bounds — skip */ }
    }
    return { ...s, name, entropy };
  });

  function findSection(name) { return sections.find(s => s.name === name); }

  // ── Program headers — PT_INTERP (3) ────────────────────────────────────
  let interpreter = null;
  const phdrTypes = [];
  for (let i = 0; i < Math.min(e_phnum, 64); i++) {
    try {
      const base = e_phoff + i * e_phentsize;
      const p_type = r.u32(base);
      phdrTypes.push(p_type);
      if (p_type === 3) { // PT_INTERP
        const p_offset = is64 ? Number(r.u64(base + 8)) : r.u32(base + 4);
        const p_filesz = is64 ? Number(r.u64(base + 32)) : r.u32(base + 16);
        interpreter = r.cstr(p_offset, Math.min(p_filesz || 256, 256));
      }
    } catch (e) {
      warnings.push(`Program header ${i} truncated: ${e.message}`);
      break;
    }
  }

  // ── .dynamic — DT_NEEDED (1), DT_RPATH (15), DT_RUNPATH (29) ───────────
  const needed = [];
  let rpath = null, runpath = null;
  const dynSec = findSection('.dynamic');
  const dynstrSec = findSection('.dynstr');
  if (dynSec && dynstrSec) {
    const entrySize = is64 ? 16 : 8;
    const count = Math.min(Math.floor(dynSec.sh_size / entrySize), MAX_DYN_ENTRIES);
    for (let i = 0; i < count; i++) {
      try {
        const base = dynSec.sh_offset + i * entrySize;
        const tag = is64 ? r.u64(base) : BigInt(r.u32(base));
        if (tag === 0n) break; // DT_NULL terminator
        const val = is64 ? Number(r.u64(base + 8)) : r.u32(base + 4);
        if (tag === 1n) needed.push(r.cstr(dynstrSec.sh_offset + val, 128));
        else if (tag === 15n) rpath = r.cstr(dynstrSec.sh_offset + val, 256);
        else if (tag === 29n) runpath = r.cstr(dynstrSec.sh_offset + val, 256);
      } catch (e) {
        warnings.push(`.dynamic entry ${i} truncated: ${e.message}`);
        break;
      }
    }
  }

  // ── .dynsym — undefined (imported) symbols ─────────────────────────────
  const importedSymbols = [];
  const dynsymSec = findSection('.dynsym');
  if (dynsymSec) {
    const strtabSec = sections[dynsymSec.sh_link];
    const entrySize = is64 ? 24 : 16;
    const count = Math.min(Math.floor(dynsymSec.sh_size / entrySize), MAX_SYMBOLS);
    for (let i = 0; i < count; i++) {
      try {
        const base = dynsymSec.sh_offset + i * entrySize;
        let st_name, st_shndx;
        if (is64) { st_name = r.u32(base); st_shndx = r.u16(base + 6); }
        else { st_name = r.u32(base); st_shndx = r.u16(base + 14); }
        if (st_shndx === 0 && st_name !== 0 && strtabSec) { // SHN_UNDEF = imported from a shared lib
          const name = r.cstr(strtabSec.sh_offset + st_name, 128);
          if (name) importedSymbols.push(name);
        }
      } catch (e) {
        warnings.push(`.dynsym entry ${i} truncated: ${e.message}`);
        break;
      }
    }
  }

  return {
    class: is64 ? '64-bit' : '32-bit',
    endianness: littleEndian ? 'Little-endian' : 'Big-endian',
    type: TYPES[e_type] || `Unknown (${e_type})`,
    machine: MACHINES[e_machine] || `Unknown (${e_machine})`,
    entryPoint: '0x' + e_entry.toString(16),
    interpreter,
    isDynamic: phdrTypes.includes(2),
    isStatic: !phdrTypes.includes(2) && !interpreter,
    neededLibraries: needed,
    rpath,
    runpath,
    sections: sections.map(s => ({ name: s.name, size: s.sh_size, entropy: s.entropy })),
    importedSymbols: [...new Set(importedSymbols)],
    warnings,
  };
}
