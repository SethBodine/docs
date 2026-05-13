import React, { useState, useCallback } from 'react';
import {
  Upload, Shield, FileText, AlertTriangle, CheckCircle,
  XCircle, Info, ChevronDown, ChevronRight, Eye, EyeOff,
  Link, User, Clock, Hash, Layers, Code
} from 'lucide-react';import DOMPurify from 'dompurify';
import * as XLSX from 'xlsx';

// ─── PDF.js (lazy loaded to avoid SSR issues) ───────────────────────────────
let pdfjsLib = null;
async function getPdfJs() {
  if (!pdfjsLib) {
    pdfjsLib = await import('pdfjs-dist');
    pdfjsLib.GlobalWorkerOptions.workerSrc = new URL(
      'pdfjs-dist/build/pdf.worker.mjs',
      import.meta.url
    ).href;
  }
  return pdfjsLib;
}

// ─── Mammoth (lazy) ──────────────────────────────────────────────────────────
let mammothLib = null;
async function getMammoth() {
  if (!mammothLib) mammothLib = await import('mammoth');
  return mammothLib;
}

// ─── Supported file types ────────────────────────────────────────────────────
const SUPPORTED_TYPES = {
  'application/pdf': { label: 'PDF', ext: 'pdf', category: 'document' },
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': { label: 'Word (DOCX)', ext: 'docx', category: 'office' },
  'application/msword': { label: 'Word (DOC)', ext: 'doc', category: 'office' },
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': { label: 'Excel (XLSX)', ext: 'xlsx', category: 'office' },
  'application/vnd.ms-excel': { label: 'Excel (XLS)', ext: 'xls', category: 'office' },
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': { label: 'PowerPoint (PPTX)', ext: 'pptx', category: 'office' },
  'application/vnd.ms-powerpoint': { label: 'PowerPoint (PPT)', ext: 'ppt', category: 'office' },
  'text/html': { label: 'HTML', ext: 'html', category: 'web' },
  'text/csv': { label: 'CSV', ext: 'csv', category: 'data' },
  'application/xml': { label: 'XML', ext: 'xml', category: 'data' },
  'text/xml': { label: 'XML', ext: 'xml', category: 'data' },
  'image/svg+xml': { label: 'SVG', ext: 'svg', category: 'web' },
  'application/rtf': { label: 'RTF', ext: 'rtf', category: 'document' },
  'text/rtf': { label: 'RTF', ext: 'rtf', category: 'document' },
};

const ACCEPT_EXTENSIONS = '.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.html,.htm,.csv,.xml,.svg,.rtf';

// ─── Risk helpers ────────────────────────────────────────────────────────────
function riskLevel(findings) {
  if (findings.some(f => f.severity === 'critical')) return 'critical';
  if (findings.some(f => f.severity === 'high')) return 'high';
  if (findings.some(f => f.severity === 'medium')) return 'medium';
  if (findings.some(f => f.severity === 'low')) return 'low';
  return 'none';
}

const RISK_CONFIG = {
  none:     { label: 'CLEAN',    color: 'var(--risk-none)',     bg: '#0d2b1a' },
  low:      { label: 'LOW',      color: 'var(--risk-low)',      bg: '#1a2b0d' },
  medium:   { label: 'MEDIUM',   color: 'var(--risk-medium)',   bg: '#2b1f0d' },
  high:     { label: 'HIGH',     color: 'var(--risk-high)',     bg: '#2b0d0d' },
  critical: { label: 'CRITICAL', color: 'var(--risk-critical)', bg: '#3b0000' },
};

// ─── ANALYSERS ───────────────────────────────────────────────────────────────

async function analysePdf(arrayBuffer) {
  const findings = [];
  const metadata = {};
  let textContent = '';
  let pageCount = 0;
  const externalLinks = [];

  try {
    const pdfjs = await getPdfJs();
    const pdf = await pdfjs.getDocument({ data: arrayBuffer }).promise;
    pageCount = pdf.numPages;

    // Metadata
    const meta = await pdf.getMetadata();
    if (meta.info) {
      const info = meta.info;
      if (info.Title)    metadata['Title']    = info.Title;
      if (info.Author)   metadata['Author']   = info.Author;
      if (info.Creator)  metadata['Creator']  = info.Creator;
      if (info.Producer) metadata['Producer'] = info.Producer;
      if (info.Subject)  metadata['Subject']  = info.Subject;
      if (info.Keywords) metadata['Keywords'] = info.Keywords;
      if (info.CreationDate) metadata['Created']  = info.CreationDate;
      if (info.ModDate)      metadata['Modified'] = info.ModDate;
      if (info.Trapped)      metadata['Trapped']  = info.Trapped;

      // Suspicious: creator != producer (converted from another format)
      if (info.Creator && info.Producer && info.Creator !== info.Producer) {
        findings.push({
          severity: 'low',
          category: 'Metadata',
          title: 'Document converted between applications',
          detail: `Created with "${info.Creator}", produced by "${info.Producer}". This is normal but worth noting.`
        });
      }
      if (info.Author && info.Author.trim()) {
        findings.push({
          severity: 'info',
          category: 'Metadata',
          title: 'Author information present',
          detail: `Author: "${info.Author}". This PII may be unintentionally included.`
        });
      }
    }

    // JavaScript check
    const jsCheck = meta.info?.IsAcroFormPresent || meta.info?.IsXFAPresent;
    if (jsCheck) {
      findings.push({
        severity: 'high',
        category: 'Active Content',
        title: 'AcroForm / XFA form detected',
        detail: 'Interactive forms can contain JavaScript. Malicious PDFs commonly abuse AcroForm JS to execute code.'
      });
    }

    // Extract text and links from each page
    for (let i = 1; i <= Math.min(pageCount, 50); i++) {
      const page = await pdf.getPage(i);
      const text = await page.getTextContent();
      textContent += text.items.map(item => item.str).join(' ') + '\n';

      // Annotations (links)
      const annots = await page.getAnnotations();
      for (const annot of annots) {
        if (annot.subtype === 'Link' && annot.url) {
          externalLinks.push({ url: annot.url, page: i });
        }
        if (annot.subtype === 'Widget' && annot.fieldType) {
          findings.push({
            severity: 'low',
            category: 'Form Fields',
            title: `Form field on page ${i}`,
            detail: `Field type: ${annot.fieldType}${annot.fieldName ? `, name: "${annot.fieldName}"` : ''}`
          });
        }
      }
    }

    // Embedded JS patterns in text
    const jsPatterns = [/\/JavaScript/gi, /\/JS\s/gi, /app\.alert/gi, /this\.submitForm/gi, /getURL/gi];
    for (const pat of jsPatterns) {
      if (pat.test(textContent)) {
        findings.push({
          severity: 'critical',
          category: 'Active Content',
          title: 'JavaScript pattern detected in content stream',
          detail: `Pattern "${pat.source}" found. This strongly indicates embedded JavaScript which is a common malware vector.`
        });
        break;
      }
    }

    // External links analysis
    for (const link of externalLinks) {
      const url = link.url;
      const isSuspicious = /\.(exe|bat|cmd|ps1|vbs|jar|sh|msi|dll)(\?|$)/i.test(url) ||
                           /data:/i.test(url) ||
                           /javascript:/i.test(url);
      findings.push({
        severity: isSuspicious ? 'high' : 'low',
        category: 'External Links',
        title: isSuspicious ? `Suspicious link on page ${link.page}` : `External link on page ${link.page}`,
        detail: url.length > 120 ? url.slice(0, 120) + '…' : url
      });
    }

    // Obfuscation check
    const suspiciousChunks = textContent.match(/[A-Za-z0-9+/]{200,}/g);
    if (suspiciousChunks && suspiciousChunks.length > 3) {
      findings.push({
        severity: 'medium',
        category: 'Obfuscation',
        title: 'Long base64-like strings detected',
        detail: `Found ${suspiciousChunks.length} long encoded strings. Could indicate obfuscated payloads.`
      });
    }

  } catch (err) {
    findings.push({
      severity: 'medium',
      category: 'Parse Error',
      title: 'Could not fully parse PDF',
      detail: err.message
    });
  }

  return { findings, metadata, textContent: textContent.slice(0, 5000), pageCount, externalLinks, previewData: { type: 'pdf', arrayBuffer } };
}

async function analyseOffice(arrayBuffer, ext) {
  const findings = [];
  const metadata = {};
  let textContent = '';
  const externalLinks = [];

  try {
    // All Office formats (docx, xlsx, pptx, xls, etc.) are ZIP-based for modern formats
    // Use SheetJS for xlsx/xls and mammoth for docx; for others use raw ZIP inspection
    const isExcel = ['xlsx', 'xls', 'xlsm', 'xlsb'].includes(ext);
    const isWord  = ['docx', 'doc'].includes(ext);
    const isPpt   = ['pptx', 'ppt'].includes(ext);
    const isMacro = ['xlsm', 'xlsb', 'docm', 'dotm', 'pptm', 'potm'].includes(ext);

    if (isMacro) {
      findings.push({
        severity: 'critical',
        category: 'Macros',
        title: 'Macro-enabled file format',
        detail: `The .${ext} extension explicitly indicates this file contains macros. Never enable macros unless you trust the source completely.`
      });
    }

    if (isExcel || isPpt) {
      const workbook = XLSX.read(arrayBuffer, {
        type: 'array',
        cellFormula: true,
        cellHTML: false,
        bookVBA: true,
        password: '',
      });

      // VBA check
      if (workbook.vbaraw || (workbook.Workbook && workbook.Workbook.WBProps && workbook.Workbook.WBProps.CodeName)) {
        findings.push({
          severity: 'critical',
          category: 'Macros / VBA',
          title: 'VBA macro code detected',
          detail: 'This file contains embedded Visual Basic for Applications (VBA) code. Macros are a primary malware delivery mechanism in Office documents.'
        });
      }

      // Metadata
      if (workbook.Props) {
        const p = workbook.Props;
        if (p.Author)       metadata['Author']       = p.Author;
        if (p.LastAuthor)   metadata['Last Author']  = p.LastAuthor;
        if (p.CreatedDate)  metadata['Created']      = new Date(p.CreatedDate).toLocaleString();
        if (p.ModifiedDate) metadata['Modified']     = new Date(p.ModifiedDate).toLocaleString();
        if (p.Company)      metadata['Company']      = p.Company;
        if (p.Application)  metadata['Application']  = p.Application;
        if (p.Title)        metadata['Title']        = p.Title;
        if (p.Subject)      metadata['Subject']      = p.Subject;

        if (p.Author)   findings.push({ severity: 'info', category: 'Metadata', title: 'Author PII present', detail: `Author: "${p.Author}"` });
        if (p.Company)  findings.push({ severity: 'info', category: 'Metadata', title: 'Company PII present', detail: `Company: "${p.Company}"` });
        if (p.LastAuthor && p.LastAuthor !== p.Author) {
          findings.push({ severity: 'info', category: 'Metadata', title: 'Edited by different user', detail: `Last modified by: "${p.LastAuthor}"` });
        }
      }

      // Sheet-level analysis for Excel
      if (isExcel) {
        metadata['Sheets'] = workbook.SheetNames.join(', ');
        for (const sheetName of workbook.SheetNames) {
          const sheet = workbook.Sheets[sheetName];
          const isHidden = workbook.Workbook?.Sheets?.find(s => s.name === sheetName)?.Hidden;
          if (isHidden) {
            findings.push({
              severity: 'medium',
              category: 'Hidden Content',
              title: `Hidden sheet: "${sheetName}"`,
              detail: 'Hidden sheets can contain data, formulas, or macro staging areas not visible to the user.'
            });
          }

          // Scan formulas
          for (const cellRef in sheet) {
            if (cellRef.startsWith('!')) continue;
            const cell = sheet[cellRef];
            if (cell.f) {
              const formula = cell.f;
              // Dangerous formula patterns
              if (/WEBSERVICE|HYPERLINK|DDE\b|DDEAUTO|CALL\s*\(/i.test(formula)) {
                findings.push({
                  severity: 'high',
                  category: 'Dangerous Formulas',
                  title: `Suspicious formula in ${sheetName}!${cellRef}`,
                  detail: `Formula: =${formula.slice(0, 100)}`
                });
              }
              if (/cmd|powershell|wscript|cscript|mshta|rundll/i.test(formula)) {
                findings.push({
                  severity: 'critical',
                  category: 'Dangerous Formulas',
                  title: `Shell command in formula at ${sheetName}!${cellRef}`,
                  detail: `Formula contains command execution string: =${formula.slice(0, 100)}`
                });
              }
              // External links in formulas
              const extRef = formula.match(/\[([^\]]+)\]/);
              if (extRef) {
                externalLinks.push({ url: extRef[1], context: `Formula at ${sheetName}!${cellRef}` });
                findings.push({
                  severity: 'medium',
                  category: 'External References',
                  title: `External workbook reference in ${sheetName}!${cellRef}`,
                  detail: `References: [${extRef[1]}]`
                });
              }
            }
            // Collect text
            if (cell.v && typeof cell.v === 'string') textContent += cell.v + ' ';
          }
        }
      }
    }

    if (isWord) {
      try {
        const mammoth = await getMammoth();
        const result = await mammoth.default.convertToHtml({ arrayBuffer });
        textContent = result.value;

        // Scan extracted HTML for suspicious patterns
        const linkMatches = [...textContent.matchAll(/href=["']([^"']+)["']/gi)];
        for (const match of linkMatches) {
          externalLinks.push({ url: match[1], context: 'Document hyperlink' });
          const isSusp = /javascript:|data:|\.exe|\.bat|\.ps1/i.test(match[1]);
          findings.push({
            severity: isSusp ? 'high' : 'low',
            category: 'Links',
            title: isSusp ? 'Suspicious hyperlink' : 'External hyperlink',
            detail: match[1].length > 120 ? match[1].slice(0, 120) + '…' : match[1]
          });
        }

        if (result.messages && result.messages.length > 0) {
          for (const msg of result.messages.slice(0, 5)) {
            if (msg.type === 'warning') {
              findings.push({ severity: 'low', category: 'Parse Warnings', title: 'Document parse warning', detail: msg.message });
            }
          }
        }
      } catch (e) {
        findings.push({ severity: 'medium', category: 'Parse Error', title: 'Could not parse Word document', detail: e.message });
      }
    }

    // Raw ZIP inspection for embedded objects and relationships (works for all OOXML)
    try {
      const { default: JSZip } = await import('https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js');
      const zip = await JSZip.loadAsync(arrayBuffer);

      // Check for OLE objects
      const oleFiles = Object.keys(zip.files).filter(f =>
        f.includes('oleObject') || f.includes('embeddings') || f.endsWith('.bin')
      );
      if (oleFiles.length > 0) {
        findings.push({
          severity: 'high',
          category: 'Embedded Objects',
          title: `${oleFiles.length} embedded OLE object(s) detected`,
          detail: oleFiles.slice(0, 5).join(', ') + (oleFiles.length > 5 ? ` + ${oleFiles.length - 5} more` : '')
        });
      }

      // Check for external relationships
      const relFiles = Object.keys(zip.files).filter(f => f.endsWith('.rels'));
      for (const relFile of relFiles) {
        const content = await zip.files[relFile].async('string');
        const extRels = [...content.matchAll(/Target="(https?:\/\/[^"]+)"/gi)];
        for (const rel of extRels) {
          externalLinks.push({ url: rel[1], context: `Relationship: ${relFile}` });
          findings.push({
            severity: 'medium',
            category: 'External Relationships',
            title: 'External URL in document relationships',
            detail: rel[1].length > 120 ? rel[1].slice(0, 120) + '…' : rel[1]
          });
        }
      }

      // Check for vbaProject
      if (zip.files['xl/vbaProject.bin'] || zip.files['word/vbaProject.bin'] || zip.files['ppt/vbaProject.bin']) {
        if (!findings.some(f => f.title.includes('VBA'))) {
          findings.push({
            severity: 'critical',
            category: 'Macros / VBA',
            title: 'VBA project binary detected',
            detail: 'vbaProject.bin found inside the document archive. This file contains compiled macro code.'
          });
        }
      }

      // Check core properties for metadata
      if (zip.files['docProps/core.xml']) {
        const coreXml = await zip.files['docProps/core.xml'].async('string');
        const extract = (tag) => {
          const m = coreXml.match(new RegExp(`<[^>]*:?${tag}[^>]*>([^<]+)<`));
          return m ? m[1] : null;
        };
        ['creator', 'lastModifiedBy', 'created', 'modified', 'revision'].forEach(tag => {
          const val = extract(tag);
          if (val) {
            const key = { creator: 'Author', lastModifiedBy: 'Last Modified By', created: 'Created', modified: 'Modified', revision: 'Revision' }[tag];
            metadata[key] = val;
          }
        });
        const rev = extract('revision');
        if (rev && parseInt(rev) > 30) {
          findings.push({ severity: 'info', category: 'Metadata', title: `High revision count: ${rev}`, detail: 'Document has been edited many times. Prior authors/content may be recoverable from revision history.' });
        }
      }

      // App properties
      if (zip.files['docProps/app.xml']) {
        const appXml = await zip.files['docProps/app.xml'].async('string');
        const appMatch = appXml.match(/<Application>([^<]+)<\/Application>/);
        if (appMatch) metadata['Application'] = appMatch[1];
        const companyMatch = appXml.match(/<Company>([^<]+)<\/Company>/);
        if (companyMatch) {
          metadata['Company'] = companyMatch[1];
          findings.push({ severity: 'info', category: 'Metadata', title: 'Company name embedded', detail: `Company: "${companyMatch[1]}"` });
        }
      }

    } catch (zipErr) {
      // Not a ZIP (e.g. legacy .doc/.xls binary format) — already handled above
    }

    // Suspicious string scan in text
    const dangerPatterns = [
      { re: /cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe/gi, label: 'Shell executable reference' },
      { re: /http[s]?:\/\/[^\s"'<>]{4,}/gi, label: 'URL in text' },
      { re: /\\\\[a-z0-9._-]+\\/gi, label: 'UNC path (network share)' },
      { re: /HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT)/gi, label: 'Registry key reference' },
    ];
    for (const { re, label } of dangerPatterns) {
      const matches = textContent.match(re);
      if (matches) {
        const sev = label.includes('Shell') || label.includes('Registry') ? 'high' : 'low';
        findings.push({
          severity: sev,
          category: 'Suspicious Strings',
          title: `${label} found in content`,
          detail: [...new Set(matches)].slice(0, 3).join(' | ')
        });
      }
    }

  } catch (err) {
    findings.push({ severity: 'medium', category: 'Parse Error', title: 'Could not parse document', detail: err.message });
  }

  return { findings, metadata, textContent: (typeof textContent === 'string' ? textContent : '').slice(0, 5000), externalLinks, previewData: { type: 'office', ext, arrayBuffer, html: typeof textContent === 'string' && textContent.includes('<') ? textContent : null } };
}

async function analyseHtml(arrayBuffer) {
  const findings = [];
  const metadata = {};
  const externalLinks = [];

  const decoder = new TextDecoder();
  const html = decoder.decode(arrayBuffer);
  const clean = DOMPurify.sanitize(html, { WHOLE_DOCUMENT: true, RETURN_DOM: true });

  // Scripts
  const scriptCount = html.match(/<script/gi)?.length || 0;
  if (scriptCount > 0) {
    findings.push({
      severity: 'high',
      category: 'Active Content',
      title: `${scriptCount} <script> block(s) detected`,
      detail: 'Script blocks can execute arbitrary code when rendered in a browser.'
    });
  }

  // Iframes
  const iframes = [...html.matchAll(/<iframe[^>]*src=["']([^"']+)["']/gi)];
  for (const iframe of iframes) {
    findings.push({ severity: 'high', category: 'Iframes', title: 'Embedded iframe', detail: iframe[1] });
    externalLinks.push({ url: iframe[1], context: 'iframe src' });
  }

  // Forms
  const forms = [...html.matchAll(/<form[^>]*action=["']([^"']+)["']/gi)];
  for (const form of forms) {
    findings.push({ severity: 'medium', category: 'Forms', title: 'Form submission target', detail: form[1] });
    externalLinks.push({ url: form[1], context: 'form action' });
  }

  // External resources
  const extSrc = [...html.matchAll(/(?:src|href|action)=["'](https?:\/\/[^"']+)["']/gi)];
  for (const r of extSrc) {
    const isSusp = /\.exe|\.bat|\.ps1|javascript:|data:/i.test(r[1]);
    findings.push({ severity: isSusp ? 'critical' : 'low', category: 'External Resources', title: 'External resource reference', detail: r[1].slice(0, 120) });
    externalLinks.push({ url: r[1], context: 'resource reference' });
  }

  // Meta tags
  const metaTags = [...html.matchAll(/<meta[^>]+>/gi)];
  for (const tag of metaTags) {
    const name = tag[0].match(/name=["']([^"']+)["']/i)?.[1];
    const content = tag[0].match(/content=["']([^"']+)["']/i)?.[1];
    if (name && content) metadata[name] = content;
    if (tag[0].toLowerCase().includes('refresh') && content) {
      findings.push({ severity: 'high', category: 'Redirect', title: 'Meta refresh redirect', detail: `Redirects to: ${content}` });
    }
  }

  // Obfuscation
  if (/eval\s*\(|unescape\s*\(|String\.fromCharCode\s*\(|atob\s*\(/gi.test(html)) {
    findings.push({ severity: 'critical', category: 'Obfuscation', title: 'JavaScript obfuscation detected', detail: 'Patterns like eval(), unescape(), atob(), String.fromCharCode() are commonly used to hide malicious code.' });
  }

  const sanitisedHtml = DOMPurify.sanitize(html, {
    FORBID_TAGS: ['script','iframe','object','embed','form','input','button','meta','link'],
    FORBID_ATTR: ['onerror','onload','onclick','onmouseover','style','action','formaction'],
    ALLOW_DATA_ATTR: false,
  });
  return { findings, metadata, textContent: clean.body?.textContent?.slice(0, 5000) || '', externalLinks, previewData: { type: 'html', sanitisedHtml } };
}

async function analyseCsv(arrayBuffer) {
  const findings = [];
  const metadata = {};
  const decoder = new TextDecoder();
  const text = decoder.decode(arrayBuffer);

  // Injection attacks
  const rows = text.split('\n');
  let injectionCount = 0;
  for (let i = 0; i < Math.min(rows.length, 500); i++) {
    const cells = rows[i].split(',');
    for (const cell of cells) {
      const trimmed = cell.trim().replace(/^["']/, '');
      if (/^[=+\-@]/.test(trimmed)) {
        injectionCount++;
      }
    }
  }
  if (injectionCount > 0) {
    findings.push({
      severity: injectionCount > 5 ? 'high' : 'medium',
      category: 'CSV Injection',
      title: `${injectionCount} potential CSV injection cell(s)`,
      detail: 'Cells starting with =, +, -, or @ can execute formulas when opened in spreadsheet applications.'
    });
  }

  metadata['Rows (approx)'] = rows.length.toString();
  metadata['Columns (approx)'] = (rows[0]?.split(',')?.length || 0).toString();

  // URLs in CSV
  const urls = [...text.matchAll(/https?:\/\/[^\s,"\n]+/gi)];
  if (urls.length > 0) {
    findings.push({ severity: 'low', category: 'URLs', title: `${urls.length} URL(s) in data`, detail: urls.slice(0, 3).map(u => u[0]).join(', ') });
  }

  return { findings, metadata, textContent: text.slice(0, 5000), externalLinks: [], previewData: { type: 'csv', text } };
}

async function analyseXml(arrayBuffer) {
  const findings = [];
  const metadata = {};
  const externalLinks = [];
  const decoder = new TextDecoder();
  const text = decoder.decode(arrayBuffer);

  // XXE patterns
  if (/<!ENTITY/i.test(text)) {
    const isExternal = /<!ENTITY[^>]+SYSTEM/i.test(text) || /<!ENTITY[^>]+PUBLIC/i.test(text);
    findings.push({
      severity: isExternal ? 'critical' : 'medium',
      category: 'XXE / Entity Injection',
      title: isExternal ? 'External entity (XXE) declaration detected' : 'XML entity declaration detected',
      detail: isExternal
        ? 'SYSTEM or PUBLIC entity declarations can read local files or make outbound network requests when parsed by vulnerable applications.'
        : 'Entity declarations present. Ensure the XML parser has entity expansion limits.'
    });
  }

  // Processing instructions
  const pis = [...text.matchAll(/<\?([a-z][a-z0-9]*)\s/gi)];
  for (const pi of pis) {
    if (!['xml'].includes(pi[1].toLowerCase())) {
      findings.push({ severity: 'low', category: 'Processing Instructions', title: `Non-standard processing instruction: <?${pi[1]}`, detail: 'Processing instructions may trigger behaviour in specific XML parsers.' });
    }
  }

  // External refs
  const extRefs = [...text.matchAll(/(?:xlink:href|src|href)=["'](https?:\/\/[^"']+)["']/gi)];
  for (const ref of extRefs) {
    externalLinks.push({ url: ref[1], context: 'XML attribute' });
    findings.push({ severity: 'medium', category: 'External References', title: 'External URL in XML', detail: ref[1].slice(0, 120) });
  }

  // Script content in SVG/XML
  if (/<script/i.test(text)) {
    findings.push({ severity: 'high', category: 'Active Content', title: 'Script element in XML/SVG', detail: 'Script elements in SVG/XML files can execute JavaScript when opened in browsers.' });
  }

  const isSvg = /^\s*<svg/i.test(text);
  const sanitisedSvg = isSvg ? DOMPurify.sanitize(text, { USE_PROFILES: { svg: true, svgFilters: true } }) : null;
  return { findings, metadata, textContent: text.slice(0, 5000), externalLinks, previewData: { type: isSvg ? 'svg' : 'xml', text, sanitisedSvg } };
}

async function analyseRtf(arrayBuffer) {
  const findings = [];
  const metadata = {};
  const decoder = new TextDecoder('latin1');
  const text = decoder.decode(arrayBuffer);

  // OLE embedded objects
  if (/\\objdata|\\object/i.test(text)) {
    findings.push({ severity: 'high', category: 'Embedded Objects', title: 'OLE object embedded in RTF', detail: 'RTF files can embed OLE objects (e.g. executables, Office documents) which may execute on open.' });
  }

  // Known RTF exploit patterns
  if (/\\rtlch|equation|\\listoverridecount/i.test(text) && /\\objclass/i.test(text)) {
    findings.push({ severity: 'critical', category: 'Exploit Patterns', title: 'Possible CVE-2017-11882 (Equation Editor) pattern', detail: 'Combination of RTF control words associated with the Equation Editor vulnerability. Treat with extreme caution.' });
  }

  // External URLs
  const urls = [...text.matchAll(/https?:\/\/[^\s\\{}"]+/gi)];
  for (const url of urls) {
    findings.push({ severity: 'low', category: 'URLs', title: 'URL in RTF content', detail: url[0].slice(0, 120) });
  }

  // Hex-encoded payloads (long hex strings)
  const hexChunks = text.match(/(?:[0-9a-f]{2}){50,}/gi);
  if (hexChunks && hexChunks.length > 2) {
    findings.push({ severity: 'medium', category: 'Obfuscation', title: `${hexChunks.length} long hex-encoded block(s)`, detail: 'Large hex blobs in RTF often encode embedded objects or shellcode.' });
  }

  // Strip RTF control words to produce readable plain text
  const plainText = text
    .replace(/\{[^{}]*\}/g, '')          // remove groups
    .replace(/\\[a-z]+\-?\d*\s?/g, ' ')  // remove control words
    .replace(/\\\*/g, '')
    .replace(/[{}\\]/g, '')
    .replace(/\s{2,}/g, ' ')
    .trim();

  return { findings, metadata, textContent: '', externalLinks: [], previewData: { type: 'rtf', plainText } };
}

// ─── DISPATCH ────────────────────────────────────────────────────────────────
async function analyseFile(file) {
  const arrayBuffer = await file.arrayBuffer();
  const ext = file.name.split('.').pop().toLowerCase();

  if (ext === 'pdf') return analysePdf(arrayBuffer);
  if (['doc','docx','docm','xls','xlsx','xlsm','ppt','pptx','pptm'].includes(ext)) return analyseOffice(arrayBuffer, ext);
  if (['html','htm'].includes(ext)) return analyseHtml(arrayBuffer);
  if (ext === 'csv') return analyseCsv(arrayBuffer);
  if (['xml','svg'].includes(ext)) return analyseXml(arrayBuffer);
  if (ext === 'rtf') return analyseRtf(arrayBuffer);

  return {
    findings: [{ severity: 'info', category: 'Format', title: 'Limited analysis for this file type', detail: `Basic metadata extraction only for .${ext} files.` }],
    metadata: {}, textContent: '', externalLinks: [], previewData: { type: 'unsupported', ext }
  };
}

// ─── TELEMETRY ───────────────────────────────────────────────────────────────
const DISCORD_WEBHOOK_URL = import.meta.env.VITE_DISCORD_WEBHOOK_URL;

function parseDevice(ua) {
  if (/mobile|android|iphone|ipad|ipod/i.test(ua)) {
    if (/ipad/i.test(ua)) return 'Tablet (iPad)';
    if (/iphone|ipod/i.test(ua)) return 'Mobile (iPhone)';
    if (/android/i.test(ua)) return /mobile/i.test(ua) ? 'Mobile (Android)' : 'Tablet (Android)';
    return 'Mobile';
  }
  return 'Desktop';
}

function parseBrowser(ua) {
  if (/edg\//i.test(ua))     return 'Edge';
  if (/opr\//i.test(ua))     return 'Opera';
  if (/chrome\//i.test(ua))  return 'Chrome';
  if (/firefox\//i.test(ua)) return 'Firefox';
  if (/safari\//i.test(ua))  return 'Safari';
  return 'Unknown';
}

function parseOS(ua) {
  if (/windows nt 10/i.test(ua)) return 'Windows 10/11';
  if (/windows nt/i.test(ua))    return 'Windows';
  if (/mac os x/i.test(ua))      return 'macOS';
  if (/android/i.test(ua))       return 'Android';
  if (/iphone|ipad|ipod/i.test(ua)) return 'iOS';
  if (/linux/i.test(ua))         return 'Linux';
  return 'Unknown';
}

// Maps a MIME type to the extensions we'd expect for it
const MIME_TO_EXTS = {
  'application/pdf':                                                                          ['pdf'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document':                 ['docx','docm'],
  'application/msword':                                                                       ['doc','dot'],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':                       ['xlsx','xlsm','xlsb'],
  'application/vnd.ms-excel':                                                                 ['xls','xlt'],
  'application/vnd.openxmlformats-officedocument.presentationml.presentation':               ['pptx','pptm'],
  'application/vnd.ms-powerpoint':                                                            ['ppt','pot'],
  'text/html':                                                                                ['html','htm'],
  'text/csv':                                                                                 ['csv'],
  'application/xml':                                                                          ['xml'],
  'text/xml':                                                                                 ['xml'],
  'image/svg+xml':                                                                            ['svg'],
  'application/rtf':                                                                          ['rtf'],
  'text/rtf':                                                                                 ['rtf'],
  // Generic OOXML — browser may report this when it can't pin down the subtype
  'application/zip':                                                                          ['docx','xlsx','pptx','docm','xlsm','pptm'],
  'application/octet-stream':                                                                 [], // could be anything
};

function detectMismatch(file) {
  const ext  = file.name.split('.').pop().toLowerCase();
  const mime = (file.type || '').toLowerCase();

  // If browser didn't provide a MIME type, we can't compare
  if (!mime || mime === 'application/octet-stream') {
    return { ext, mime: mime || 'unknown', mismatch: false, note: 'MIME type not reported by browser' };
  }

  const expectedExts = MIME_TO_EXTS[mime];
  if (!expectedExts) {
    return { ext, mime, mismatch: false, note: 'Unrecognised MIME type' };
  }

  // application/zip is the raw OOXML container — flag only if extension is clearly non-Office
  if (mime === 'application/zip') {
    const officeExts = ['docx','xlsx','pptx','docm','xlsm','pptm','xlsb','odt','ods','odp'];
    const mismatch = !officeExts.includes(ext);
    return { ext, mime, mismatch, note: mismatch ? 'ZIP container with non-Office extension' : '' };
  }

  const mismatch = expectedExts.length > 0 && !expectedExts.includes(ext);
  return { ext, mime, mismatch, note: '' };
}

async function sendTelemetry(file, riskLevelStr) {
  if (!DISCORD_WEBHOOK_URL) return;
  try {
    const ua = navigator.userAgent;
    let ip = 'Unknown';
    try {
      const r = await fetch('https://ip.b0x.workers.dev/');
      ip = (await r.text()).trim();
    } catch { /* silent */ }

    const { ext, mime, mismatch, note } = detectMismatch(file);

    // Build the file type field — combine extension + MIME, flag mismatch clearly
    const fileTypeValue = mismatch
      ? `⚠️ MISMATCH\nExtension: .${ext}\nMIME: ${mime}`
      : `.${ext} (${mime || 'MIME unknown'})`;

    const sizeLabel = file.size < 1024
      ? `${file.size} B`
      : file.size < 1048576
        ? `${(file.size / 1024).toFixed(1)} KB`
        : `${(file.size / 1048576).toFixed(2)} MB`;

    const riskColors = {
      none: 0x4ade80, low: 0x86efac, medium: 0xfbbf24, high: 0xf87171, critical: 0xef4444
    };

    const embed = {
      title: mismatch
        ? '⚠️ DocScan — FILE TYPE MISMATCH DETECTED'
        : '📄 DocScan — File Analysis Event',
      color: mismatch ? 0xff6600 : (riskColors[riskLevelStr] ?? 0x888888),
      fields: [
        { name: '🌐 IP Address',    value: ip,                                  inline: true  },
        { name: '⚠️ Risk Level',    value: riskLevelStr.toUpperCase(),          inline: true  },
        { name: '📦 File Size',     value: sizeLabel,                           inline: true  },
        { name: '📄 Filename',      value: file.name,                           inline: false },
        { name: '🏷️ Extension',     value: `.${ext}`,                           inline: true  },
        { name: '🔍 Actual MIME',   value: mime || 'not reported',              inline: true  },
        { name: '✅ Type Match',    value: mismatch ? '❌ NO — possible spoofing' : (note || '✅ Yes'), inline: true },
        { name: '🖥️ Device',        value: parseDevice(ua),                     inline: true  },
        { name: '🌍 OS',            value: parseOS(ua),                         inline: true  },
        { name: '🧭 Browser',       value: parseBrowser(ua),                    inline: true  },
        { name: '📐 Screen',        value: `${screen.width}×${screen.height}`, inline: true  },
        { name: '🗣️ Language',      value: navigator.language || 'Unknown',     inline: true  },
      ],
      timestamp: new Date().toISOString(),
      footer: { text: 'DocScan · document contents are never transmitted' },
    };

    await fetch(DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] }),
    });
  } catch { /* telemetry must never break the app */ }
}

// ─── UI COMPONENTS ───────────────────────────────────────────────────────────

function RiskBadge({ level }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.none;
  return (
    <span style={{
      background: cfg.bg,
      color: cfg.color,
      border: `1px solid ${cfg.color}`,
      padding: '2px 10px',
      borderRadius: 3,
      fontFamily: "'IBM Plex Mono', monospace",
      fontSize: 11,
      fontWeight: 600,
      letterSpacing: '0.08em',
    }}>
      {cfg.label}
    </span>
  );
}

function SeverityDot({ severity }) {
  const colors = {
    critical: 'var(--risk-critical)',
    high: 'var(--risk-high)',
    medium: 'var(--risk-medium)',
    low: 'var(--risk-low)',
    info: 'var(--accent-blue)',
  };
  return <span style={{ width: 8, height: 8, borderRadius: '50%', background: colors[severity] || '#888', display: 'inline-block', flexShrink: 0, marginTop: 6 }} />;
}

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  const colors = { critical: 'var(--risk-critical)', high: 'var(--risk-high)', medium: 'var(--risk-medium)', low: 'var(--risk-low)', info: 'var(--accent-blue)' };
  const color = colors[finding.severity] || '#888';

  return (
    <div style={{
      border: `1px solid var(--border)`,
      borderLeft: `3px solid ${color}`,
      borderRadius: 4,
      background: 'var(--bg-card)',
      overflow: 'hidden',
    }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%', textAlign: 'left', background: 'none', border: 'none',
          padding: '10px 14px', cursor: 'pointer', display: 'flex', alignItems: 'flex-start', gap: 10,
        }}
      >
        <SeverityDot severity={finding.severity} />
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              {finding.category}
            </span>
            <span style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>
              {finding.title}
            </span>
          </div>
        </div>
        {finding.detail && (open
          ? <ChevronDown size={14} color="var(--text-muted)" style={{ flexShrink: 0, marginTop: 2 }} />
          : <ChevronRight size={14} color="var(--text-muted)" style={{ flexShrink: 0, marginTop: 2 }} />
        )}
      </button>
      {open && finding.detail && (
        <div style={{ padding: '0 14px 12px 32px' }}>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: "'IBM Plex Mono', monospace", wordBreak: 'break-all', lineHeight: 1.6 }}>
            {finding.detail}
          </p>
        </div>
      )}
    </div>
  );
}

function MetadataTable({ metadata }) {
  const entries = Object.entries(metadata);
  if (entries.length === 0) return <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No metadata extracted.</p>;
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k} style={{ borderBottom: '1px solid var(--border)' }}>
            <td style={{ padding: '7px 12px 7px 0', color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", whiteSpace: 'nowrap', width: '30%', verticalAlign: 'top' }}>{k}</td>
            <td style={{ padding: '7px 0', color: 'var(--text-primary)', wordBreak: 'break-all' }}>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function LinksList({ links }) {
  if (!links || links.length === 0) return <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No external links detected.</p>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {links.slice(0, 30).map((l, i) => {
        const isSusp = /\.exe|\.bat|\.ps1|javascript:|data:|powershell/i.test(l.url);
        return (
          <div key={i} style={{ background: 'var(--bg-card)', border: `1px solid var(--border)`, borderLeft: `3px solid ${isSusp ? 'var(--risk-high)' : 'var(--border-active)'}`, borderRadius: 3, padding: '8px 12px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 2, fontFamily: "'IBM Plex Mono', monospace" }}>{l.context || l.page && `Page ${l.page}`}</div>
            <div style={{ fontSize: 12, color: isSusp ? 'var(--risk-high)' : 'var(--accent-blue)', wordBreak: 'break-all', fontFamily: "'IBM Plex Mono', monospace" }}>{l.url}</div>
          </div>
        );
      })}
      {links.length > 30 && <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>…and {links.length - 30} more</p>}
    </div>
  );
}

// ─── FULL VIEW COMPONENT ─────────────────────────────────────────────────────
// Opens the raw file in a sandboxed iframe using a blob URL.
// For PDF/images this gives the browser's native renderer.
// For Office formats (no browser renderer) we fall back to the safe HTML render.

function FullView({ file, previewData }) {
  const [blobUrl, setBlobUrl] = React.useState(null);
  const [confirmed, setConfirmed] = React.useState(false);

  React.useEffect(() => {
    return () => { if (blobUrl) URL.revokeObjectURL(blobUrl); };
  }, [blobUrl]);

  const open = React.useCallback(() => {
    const url = URL.createObjectURL(file);
    setBlobUrl(url);
    setConfirmed(true);
  }, [file]);

  const ext = file?.name.split('.').pop().toLowerCase();
  const isPdf    = ext === 'pdf';
  const isHtml   = ['html','htm'].includes(ext);
  const isSvg    = ext === 'svg';
  const isCsv    = ext === 'csv';
  const isXml    = ext === 'xml';
  // Formats the browser can natively render in an iframe
  const nativeRenderable = isPdf || isHtml || isSvg;

  const warningStyle = {
    background: 'rgba(239,68,68,0.08)',
    border: '1px solid var(--risk-high)',
    borderRadius: 6,
    padding: '16px 20px',
    marginBottom: 16,
  };

  if (!confirmed) {
    return (
      <div>
        <div style={warningStyle}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', marginBottom: 12 }}>
            <AlertTriangle size={16} color="var(--risk-high)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--risk-high)', marginBottom: 6 }}>
                Full View — unsanitised content
              </p>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                {nativeRenderable
                  ? `This renders the file as-is using your browser's native ${isPdf ? 'PDF' : 'HTML'} renderer inside a sandboxed iframe. Scripts and top-level navigation are blocked by the sandbox, but the file is otherwise unmodified.`
                  : `This format (${ext.toUpperCase()}) cannot be natively rendered by the browser. The safe rendered view will be shown instead — use the Safe Preview tab for the same result.`
                }
              </p>
              {previewData?.type === 'office' && (
                <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6, fontStyle: 'italic' }}>
                  Office documents (DOCX, XLSX, PPTX) cannot be rendered natively in a browser. Full View uses the same HTML conversion as Safe Preview, just without the security banner.
                </p>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={open}
              style={{
                background: 'var(--risk-high)', color: '#fff', border: 'none',
                borderRadius: 4, padding: '8px 18px', cursor: 'pointer', fontSize: 13, fontWeight: 600,
              }}
            >
              I understand — show full view
            </button>
          </div>
        </div>
        {/* Show the security findings as a reminder */}
        <p style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace" }}>
          Review the Findings tab before proceeding. Check the risk level above.
        </p>
      </div>
    );
  }

  // Native render: PDF, HTML, SVG
  if (nativeRenderable && blobUrl) {
    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, padding: '6px 12px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 4 }}>
          <AlertTriangle size={13} color="var(--risk-medium)" />
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Rendered natively in sandboxed iframe — scripts and navigation blocked. External resources may load.
          </span>
          <button onClick={() => { setConfirmed(false); URL.revokeObjectURL(blobUrl); setBlobUrl(null); }}
            style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', background: 'none', border: '1px solid var(--border)', borderRadius: 3, padding: '2px 8px', cursor: 'pointer' }}>
            Close
          </button>
        </div>
        <iframe
          src={blobUrl}
          sandbox="allow-same-origin allow-scripts"
          title="Full document view"
          style={{ width: '100%', minHeight: 700, border: '1px solid var(--border)', borderRadius: 4, background: '#fff', display: 'block' }}
        />
      </div>
    );
  }

  // CSV/XML/RTF — just show the raw text nicely
  if ((isCsv || isXml) && previewData) {
    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, padding: '6px 12px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 4 }}>
          <Info size={13} color="var(--accent-blue)" />
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Raw file content — displayed as text, not executed.</span>
        </div>
        {isCsv ? <CsvPreview text={previewData.text} /> : <XmlPreview text={previewData.text} />}
      </div>
    );
  }

  // Office formats and RTF — use the same safe renderer, just without the banner
  if (previewData) {
    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, padding: '6px 12px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 4 }}>
          <Info size={13} color="var(--accent-blue)" />
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {ext?.toUpperCase()} cannot be natively rendered — showing converted view.
          </span>
        </div>
        <OfficePreview previewData={previewData} />
      </div>
    );
  }

  return null;
}

// ─── DOCUMENT PREVIEW COMPONENT ─────────────────────────────────────────────

function PdfPreview({ arrayBuffer }) {
  const canvasRefs = React.useRef({});
  const [pages, setPages] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(null);

  React.useEffect(() => {
    let cancelled = false;
    async function render() {
      try {
        const pdfjs = await getPdfJs();
        const pdf = await pdfjs.getDocument({ data: arrayBuffer.slice(0) }).promise;
        const pageNums = Array.from({ length: Math.min(pdf.numPages, 20) }, (_, i) => i + 1);
        setPages(pageNums);
        setLoading(false);
        // render each page after state update
        for (const num of pageNums) {
          if (cancelled) break;
          await new Promise(resolve => setTimeout(resolve, 0)); // yield
          const page = await pdf.getPage(num);
          const viewport = page.getViewport({ scale: 1.4 });
          const canvas = canvasRefs.current[num];
          if (!canvas) { resolve?.(); continue; }
          canvas.width = viewport.width;
          canvas.height = viewport.height;
          const ctx = canvas.getContext('2d');
          await page.render({ canvasContext: ctx, viewport }).promise;
        }
      } catch (e) {
        if (!cancelled) setError(e.message);
        setLoading(false);
      }
    }
    render();
    return () => { cancelled = true; };
  }, [arrayBuffer]);

  if (loading) return <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 }}>Rendering pages…</div>;
  if (error) return <div style={{ padding: 16, color: 'var(--risk-high)', fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 }}>Render error: {error}</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {pages.length > 20 && <p style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center' }}>Showing first 20 pages</p>}
      {pages.map(num => (
        <div key={num} style={{ position: 'relative' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", marginBottom: 4 }}>Page {num}</div>
          <canvas
            ref={el => { if (el) canvasRefs.current[num] = el; }}
            style={{ width: '100%', borderRadius: 4, border: '1px solid var(--border)', display: 'block', background: '#fff' }}
          />
        </div>
      ))}
    </div>
  );
}

function OfficePreview({ previewData }) {
  const { ext, arrayBuffer, html } = previewData;
  const isExcel = ['xls','xlsx','xlsm','xlsb'].includes(ext);
  const isPpt   = ['ppt','pptx','pptm'].includes(ext);
  const isWord  = ['doc','docx','docm'].includes(ext);
  const [rendered, setRendered] = React.useState(null);

  React.useEffect(() => {
    async function build() {
      try {
        if (isWord) {
          // mammoth already produced HTML during analysis — re-run for clean output
          const mammoth = await getMammoth();
          const result = await mammoth.default.convertToHtml({ arrayBuffer: arrayBuffer.slice(0) });
          const safe = DOMPurify.sanitize(result.value, {
            FORBID_TAGS: ['script','iframe','object','embed','form','input','button'],
            FORBID_ATTR: ['onerror','onload','onclick','onmouseover','action'],
            ALLOW_DATA_ATTR: false,
          });
          setRendered({ kind: 'html', value: safe });
        } else if (isExcel) {
          const workbook = XLSX.read(arrayBuffer.slice(0), { type: 'array' });
          const sheets = workbook.SheetNames.map(name => ({
            name,
            html: XLSX.utils.sheet_to_html(workbook.Sheets[name], { editable: false }),
          }));
          setRendered({ kind: 'sheets', value: sheets });
        } else if (isPpt) {
          const workbook = XLSX.read(arrayBuffer.slice(0), { type: 'array' });
          // PPTX via SheetJS gives us slide text
          const slides = workbook.SheetNames.map((name, i) => {
            const sheet = workbook.Sheets[name];
            const csv = XLSX.utils.sheet_to_csv(sheet);
            return { index: i + 1, name, text: csv };
          });
          setRendered({ kind: 'slides', value: slides });
        }
      } catch (e) {
        setRendered({ kind: 'error', value: e.message });
      }
    }
    build();
  }, [ext, arrayBuffer]);

  if (!rendered) return <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 }}>Rendering document…</div>;
  if (rendered.kind === 'error') return <div style={{ padding: 16, color: 'var(--risk-high)', fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 }}>Render error: {rendered.value}</div>;

  if (rendered.kind === 'html') {
    return (
      <iframe
        sandbox="allow-same-origin"
        srcDoc={`<!DOCTYPE html><html><head><style>
          body { font-family: Georgia, serif; line-height: 1.7; padding: 32px 48px; color: #111; max-width: 860px; margin: 0 auto; }
          h1,h2,h3,h4 { margin-top: 1.4em; } table { border-collapse: collapse; width: 100%; }
          td,th { border: 1px solid #ccc; padding: 6px 10px; } img { max-width: 100%; }
        </style></head><body>${rendered.value}</body></html>`}
        title="Document preview"
        style={{ width: '100%', minHeight: 600, border: 'none', borderRadius: 4, background: '#fff' }}
      />
    );
  }

  if (rendered.kind === 'sheets') {
    const [activeSheet, setActiveSheet] = React.useState(0);
    return (
      <div>
        <div style={{ display: 'flex', gap: 4, marginBottom: 12, flexWrap: 'wrap' }}>
          {rendered.value.map((s, i) => (
            <button key={i} onClick={() => setActiveSheet(i)} style={{
              padding: '4px 12px', fontSize: 12, borderRadius: 3, cursor: 'pointer', border: '1px solid var(--border)',
              background: activeSheet === i ? 'var(--accent-green)' : 'var(--bg-elevated)',
              color: activeSheet === i ? '#000' : 'var(--text-secondary)',
              fontFamily: "'IBM Plex Mono', monospace",
            }}>{s.name}</button>
          ))}
        </div>
        <iframe
          sandbox="allow-same-origin"
          srcDoc={`<!DOCTYPE html><html><head><style>
            body { font-family: Arial, sans-serif; font-size: 12px; padding: 8px; margin: 0; }
            table { border-collapse: collapse; width: max-content; } td,th { border: 1px solid #ccc; padding: 4px 8px; white-space: nowrap; }
            tr:nth-child(even) { background: #f5f5f5; } th { background: #e0e0e0; font-weight: 600; }
          </style></head><body>${DOMPurify.sanitize(rendered.value[activeSheet]?.html || '', { FORBID_TAGS: ['script'], ALLOW_DATA_ATTR: false })}</body></html>`}
          title="Spreadsheet preview"
          style={{ width: '100%', minHeight: 500, border: 'none', borderRadius: 4, background: '#fff', overflowX: 'auto' }}
        />
      </div>
    );
  }

  if (rendered.kind === 'slides') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {rendered.value.map(slide => (
          <div key={slide.index} style={{
            background: '#fff', borderRadius: 6, border: '1px solid var(--border)',
            padding: '24px 32px', minHeight: 120,
          }}>
            <div style={{ fontSize: 10, color: '#888', fontFamily: "'IBM Plex Mono', monospace", marginBottom: 10 }}>Slide {slide.index} — {slide.name}</div>
            <pre style={{ fontSize: 13, color: '#222', whiteSpace: 'pre-wrap', wordBreak: 'break-word', lineHeight: 1.7, margin: 0 }}>
              {slide.text || '(No text content)'}
            </pre>
          </div>
        ))}
      </div>
    );
  }

  return null;
}

function SheetPreviewWithState({ rendered }) {
  const [activeSheet, setActiveSheet] = React.useState(0);
  return (
    <div>
      <div style={{ display: 'flex', gap: 4, marginBottom: 12, flexWrap: 'wrap' }}>
        {rendered.value.map((s, i) => (
          <button key={i} onClick={() => setActiveSheet(i)} style={{
            padding: '4px 12px', fontSize: 12, borderRadius: 3, cursor: 'pointer', border: '1px solid var(--border)',
            background: activeSheet === i ? 'var(--accent-green)' : 'var(--bg-elevated)',
            color: activeSheet === i ? '#000' : 'var(--text-secondary)',
            fontFamily: "'IBM Plex Mono', monospace",
          }}>{s.name}</button>
        ))}
      </div>
      <iframe
        sandbox="allow-same-origin"
        srcDoc={`<!DOCTYPE html><html><head><style>
          body { font-family: Arial, sans-serif; font-size: 12px; padding: 8px; margin: 0; }
          table { border-collapse: collapse; width: max-content; } td,th { border: 1px solid #ccc; padding: 4px 8px; white-space: nowrap; }
          tr:nth-child(even) { background: #f5f5f5; } th { background: #e0e0e0; font-weight: 600; }
        </style></head><body>${DOMPurify.sanitize(rendered.value[activeSheet]?.html || '', { FORBID_TAGS: ['script'], ALLOW_DATA_ATTR: false })}</body></html>`}
        title="Spreadsheet preview"
        style={{ width: '100%', minHeight: 500, border: 'none', borderRadius: 4, background: '#fff' }}
      />
    </div>
  );
}

function CsvPreview({ text }) {
  const rows = React.useMemo(() => {
    return text.trim().split('\n').slice(0, 200).map(row => {
      // Basic CSV parse — handle quoted fields
      const cells = [];
      let cur = '', inQ = false;
      for (let i = 0; i < row.length; i++) {
        const c = row[i];
        if (c === '"') { inQ = !inQ; continue; }
        if (c === ',' && !inQ) { cells.push(cur); cur = ''; continue; }
        cur += c;
      }
      cells.push(cur);
      return cells;
    });
  }, [text]);

  const headers = rows[0] || [];
  const dataRows = rows.slice(1);

  return (
    <div style={{ overflowX: 'auto' }}>
      {rows.length >= 200 && <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>Showing first 200 rows</p>}
      <table style={{ borderCollapse: 'collapse', fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", width: '100%' }}>
        <thead>
          <tr>
            {headers.map((h, i) => (
              <th key={i} style={{ border: '1px solid var(--border)', padding: '6px 10px', background: 'var(--bg-elevated)', color: 'var(--text-primary)', textAlign: 'left', whiteSpace: 'nowrap' }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {dataRows.map((row, ri) => (
            <tr key={ri} style={{ background: ri % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-secondary)' }}>
              {row.map((cell, ci) => {
                const isInjection = /^[=+\-@]/.test(cell.trim());
                return (
                  <td key={ci} style={{
                    border: '1px solid var(--border)', padding: '5px 10px',
                    color: isInjection ? 'var(--risk-high)' : 'var(--text-secondary)',
                    whiteSpace: 'nowrap', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis',
                  }} title={isInjection ? `⚠️ Possible injection: ${cell}` : cell}>
                    {cell}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function XmlPreview({ text }) {
  // Syntax highlight XML/SVG with simple token colouring
  const highlighted = text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/(&lt;\/?[a-zA-Z][a-zA-Z0-9:_-]*)/g, '<span style="color:#60a5fa">$1</span>')
    .replace(/([a-zA-Z:_-]+=)("([^"]*)")/g, '<span style="color:#86efac">$1</span><span style="color:#fbbf24">$2</span>')
    .replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span style="color:#6b7280;font-style:italic">$1</span>');

  return (
    <div style={{ background: '#0d1117', borderRadius: 4, padding: 16, overflowX: 'auto', maxHeight: 600, overflowY: 'auto' }}>
      <pre style={{ margin: 0, fontSize: 12, lineHeight: 1.7, fontFamily: "'IBM Plex Mono', monospace" }}
        dangerouslySetInnerHTML={{ __html: highlighted }} />
    </div>
  );
}

function SvgPreview({ sanitisedSvg }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{
        background: '#fff', borderRadius: 6, border: '1px solid var(--border)',
        padding: 24, display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 200,
      }}>
        <div
          style={{ maxWidth: '100%', maxHeight: 500, overflow: 'auto' }}
          dangerouslySetInnerHTML={{ __html: sanitisedSvg }}
        />
      </div>
      <details style={{ fontSize: 12 }}>
        <summary style={{ cursor: 'pointer', color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace" }}>Source (sanitised)</summary>
        <XmlPreview text={sanitisedSvg} />
      </details>
    </div>
  );
}

function DocumentPreview({ previewData, file }) {
  if (!previewData) return null;
  const { type } = previewData;

  const wrap = (children, notice) => (
    <div>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14,
        padding: '8px 12px', background: 'var(--bg-elevated)',
        border: '1px solid var(--border)', borderRadius: 4,
      }}>
        <Shield size={13} color="var(--accent-green)" />
        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
          {notice || 'Rendered safely — scripts and external resources are blocked.'}
        </span>
      </div>
      {children}
    </div>
  );

  if (type === 'pdf')  return wrap(<PdfPreview arrayBuffer={previewData.arrayBuffer} />);
  if (type === 'office') return wrap(<OfficePreview previewData={previewData} />);
  if (type === 'html') return wrap(
    <iframe
      sandbox="allow-same-origin"
      srcDoc={`<!DOCTYPE html><html><head><style>body{font-family:sans-serif;line-height:1.6;padding:24px;color:#111;}</style></head><body>${previewData.sanitisedHtml}</body></html>`}
      title="HTML preview"
      style={{ width: '100%', minHeight: 500, border: 'none', borderRadius: 4, background: '#fff' }}
    />,
    'HTML rendered with scripts, forms, iframes, and external resources stripped.'
  );
  if (type === 'csv')  return wrap(<CsvPreview text={previewData.text} />, 'CSV displayed as table. Injection-risk cells highlighted in red.');
  if (type === 'svg')  return wrap(<SvgPreview sanitisedSvg={previewData.sanitisedSvg} />, 'SVG rendered with scripts and event handlers removed.');
  if (type === 'xml')  return wrap(<XmlPreview text={previewData.text} />, 'XML displayed with syntax highlighting. Not executed.');
  if (type === 'rtf')  return wrap(
    <div style={{ background: '#fff', borderRadius: 4, padding: '24px 32px', minHeight: 200 }}>
      <pre style={{ fontSize: 13, color: '#222', whiteSpace: 'pre-wrap', wordBreak: 'break-word', lineHeight: 1.8, margin: 0, fontFamily: 'Georgia, serif' }}>
        {previewData.plainText || '(No readable text extracted from RTF)'}
      </pre>
    </div>,
    'RTF rendered as plain text only — binary content and control sequences stripped.'
  );

  return (
    <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
      <FileText size={28} style={{ margin: '0 auto 10px' }} />
      <p style={{ fontSize: 13 }}>No preview available for .{previewData.ext} files.</p>
    </div>
  );
}

// ─── MAIN APP ────────────────────────────────────────────────────────────────
export default function App() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState('findings');
  const [showPreview, setShowPreview] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [darkMode, setDarkMode] = useState(true);

  const processFile = useCallback(async (f) => {
    setFile(f);
    setResult(null);
    setError(null);
    setLoading(true);
    setTab('findings');
    setShowPreview(false);
    try {
      const res = await analyseFile(f);
      setResult(res);
      // Fire telemetry after analysis — no file content is included
      const risk = riskLevel(res.findings.filter(fi => fi.severity !== 'info'));
      sendTelemetry(f, risk);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const onFileChange = (e) => {
    const f = e.target.files?.[0];
    if (f) processFile(f);
  };

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (f) processFile(f);
  }, [processFile]);

  const risk = result ? riskLevel(result.findings.filter(f => f.severity !== 'info')) : null;
  const criticalFindings = result?.findings.filter(f => f.severity === 'critical') || [];
  const highFindings     = result?.findings.filter(f => f.severity === 'high')     || [];
  const medFindings      = result?.findings.filter(f => f.severity === 'medium')   || [];
  const lowFindings      = result?.findings.filter(f => f.severity === 'low')      || [];
  const infoFindings     = result?.findings.filter(f => f.severity === 'info')     || [];

  const tabs = [
    { id: 'findings', label: 'Findings', count: result?.findings.filter(f => f.severity !== 'info').length },
    { id: 'metadata', label: 'Metadata', count: result ? Object.keys(result.metadata).length : null },
    { id: 'links',    label: 'Ext. Links', count: result?.externalLinks?.length },
    { id: 'preview',  label: 'Safe Preview', count: null },
    { id: 'fullview', label: 'Full View', count: null },
  ];

  return (
    <div className={darkMode ? '' : 'light'} style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', flexDirection: 'column' }}>

      {/* Header */}
      <header style={{
        borderBottom: '1px solid var(--border)',
        padding: '16px 32px',
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        background: 'var(--bg-secondary)',
      }}>
        <Shield size={20} color="var(--accent-green)" />
        <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', letterSpacing: '0.02em' }}>
          DOC<span style={{ color: 'var(--accent-green)' }}>SCAN</span>
        </span>
        <span style={{ marginLeft: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: 'var(--text-muted)', borderLeft: '1px solid var(--border)', paddingLeft: 12 }}>
          Document Security Analyser
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-green)', display: 'inline-block' }} />
            <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: 'var(--text-muted)' }}>
              file contents stay local · usage metadata logged
            </span>
          </span>
          {/* Day/night toggle */}
          <button
            onClick={() => setDarkMode(d => !d)}
            title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            style={{
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border)',
              borderRadius: 20,
              padding: '4px 10px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 13,
              color: 'var(--text-secondary)',
              transition: 'background 0.2s, border-color 0.2s',
            }}
          >
            {darkMode ? '☀️' : '🌙'}
            <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10 }}>
              {darkMode ? 'LIGHT' : 'DARK'}
            </span>
          </button>
        </div>
      </header>

      <div style={{ flex: 1, maxWidth: 900, margin: '0 auto', width: '100%', padding: '32px 24px' }}>

        {/* Drop zone */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          style={{
            border: `2px dashed ${dragging ? 'var(--accent-green)' : 'var(--border-active)'}`,
            borderRadius: 6,
            padding: '40px 24px',
            textAlign: 'center',
            background: dragging ? 'rgba(74,222,128,0.04)' : 'var(--bg-secondary)',
            transition: 'all 0.2s',
            cursor: 'pointer',
            marginBottom: 32,
          }}
        >
          <Upload size={32} color={dragging ? 'var(--accent-green)' : 'var(--text-muted)'} style={{ margin: '0 auto 12px' }} />
          <p style={{ fontSize: 15, color: 'var(--text-primary)', marginBottom: 6, fontWeight: 500 }}>
            Drop a document here, or{' '}
            <label style={{ color: 'var(--accent-green)', cursor: 'pointer', textDecoration: 'underline' }}>
              browse
              <input type="file" accept={ACCEPT_EXTENSIONS} onChange={onFileChange} style={{ display: 'none' }} />
            </label>
          </p>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace" }}>
            PDF · DOCX · XLSX · PPTX · HTML · CSV · XML · SVG · RTF · DOC · XLS · PPT
          </p>
        </div>

        {/* Loading */}
        {loading && (
          <div style={{ textAlign: 'center', padding: '48px 0' }}>
            <div style={{ width: 40, height: 40, border: '2px solid var(--border)', borderTop: '2px solid var(--accent-green)', borderRadius: '50%', margin: '0 auto 16px', animation: 'spin 1s linear infinite' }} />
            <p style={{ color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 }}>
              Analysing {file?.name}…
            </p>
            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          </div>
        )}

        {/* Error */}
        {error && (
          <div style={{ background: '#2b0d0d', border: '1px solid var(--risk-high)', borderRadius: 6, padding: 16, color: 'var(--risk-high)', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 }}>
            Error: {error}
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <div className="animate-in">
            {/* Summary bar */}
            <div style={{
              background: 'var(--bg-elevated)',
              border: `1px solid var(--border)`,
              borderRadius: 6,
              padding: '16px 20px',
              marginBottom: 24,
              display: 'flex',
              alignItems: 'center',
              gap: 16,
              flexWrap: 'wrap',
            }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Risk Level</div>
                <RiskBadge level={risk} />
              </div>
              <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 16 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>File</div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)', fontFamily: "'IBM Plex Mono', monospace" }}>{file?.name}</div>
              </div>
              <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 16 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Size</div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)', fontFamily: "'IBM Plex Mono', monospace" }}>
                  {file?.size < 1024 ? `${file.size} B` : file?.size < 1048576 ? `${(file.size/1024).toFixed(1)} KB` : `${(file.size/1048576).toFixed(2)} MB`}
                </div>
              </div>
              {result.pageCount && (
                <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 16 }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Pages</div>
                  <div style={{ fontSize: 13, color: 'var(--text-primary)', fontFamily: "'IBM Plex Mono', monospace" }}>{result.pageCount}</div>
                </div>
              )}
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                {[
                  { count: criticalFindings.length, color: 'var(--risk-critical)', label: 'CRITICAL' },
                  { count: highFindings.length,     color: 'var(--risk-high)',     label: 'HIGH' },
                  { count: medFindings.length,      color: 'var(--risk-medium)',   label: 'MED' },
                  { count: lowFindings.length,      color: 'var(--risk-low)',      label: 'LOW' },
                ].map(({ count, color, label }) => count > 0 && (
                  <div key={label} style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color, fontFamily: "'IBM Plex Mono', monospace", lineHeight: 1 }}>{count}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.05em' }}>{label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Tabs */}
            <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 20 }}>
              {tabs.map(t => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer',
                    padding: '10px 18px',
                    fontSize: 13, fontWeight: 500,
                    color: tab === t.id ? 'var(--accent-green)' : 'var(--text-muted)',
                    borderBottom: tab === t.id ? '2px solid var(--accent-green)' : '2px solid transparent',
                    marginBottom: -1,
                    display: 'flex', alignItems: 'center', gap: 6,
                    transition: 'color 0.15s',
                  }}
                >
                  {t.label}
                  {t.count > 0 && (
                    <span style={{
                      background: tab === t.id ? 'var(--accent-green)' : 'var(--bg-elevated)',
                      color: tab === t.id ? '#000' : 'var(--text-muted)',
                      borderRadius: 10, padding: '1px 7px', fontSize: 11,
                      fontFamily: "'IBM Plex Mono', monospace"
                    }}>{t.count}</span>
                  )}
                </button>
              ))}
            </div>

            {/* Tab content */}
            {tab === 'findings' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {result.findings.length === 0 && (
                  <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
                    <CheckCircle size={32} color="var(--accent-green)" style={{ margin: '0 auto 12px' }} />
                    <p>No issues detected.</p>
                  </div>
                )}
                {criticalFindings.length > 0 && (
                  <>
                    <div style={{ fontSize: 11, color: 'var(--risk-critical)', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.08em', padding: '8px 0 4px', textTransform: 'uppercase' }}>
                      ■ Critical
                    </div>
                    {criticalFindings.map((f, i) => <FindingCard key={i} finding={f} />)}
                  </>
                )}
                {highFindings.length > 0 && (
                  <>
                    <div style={{ fontSize: 11, color: 'var(--risk-high)', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.08em', padding: '8px 0 4px', textTransform: 'uppercase' }}>
                      ■ High
                    </div>
                    {highFindings.map((f, i) => <FindingCard key={i} finding={f} />)}
                  </>
                )}
                {medFindings.length > 0 && (
                  <>
                    <div style={{ fontSize: 11, color: 'var(--risk-medium)', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.08em', padding: '8px 0 4px', textTransform: 'uppercase' }}>
                      ■ Medium
                    </div>
                    {medFindings.map((f, i) => <FindingCard key={i} finding={f} />)}
                  </>
                )}
                {lowFindings.length > 0 && (
                  <>
                    <div style={{ fontSize: 11, color: 'var(--risk-low)', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.08em', padding: '8px 0 4px', textTransform: 'uppercase' }}>
                      ■ Low
                    </div>
                    {lowFindings.map((f, i) => <FindingCard key={i} finding={f} />)}
                  </>
                )}
                {infoFindings.length > 0 && (
                  <>
                    <div style={{ fontSize: 11, color: 'var(--accent-blue)', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.08em', padding: '8px 0 4px', textTransform: 'uppercase' }}>
                      ■ Info
                    </div>
                    {infoFindings.map((f, i) => <FindingCard key={i} finding={f} />)}
                  </>
                )}
              </div>
            )}

            {tab === 'metadata' && (
              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '16px 20px' }}>
                <MetadataTable metadata={result.metadata} />
              </div>
            )}

            {tab === 'links' && (
              <LinksList links={result.externalLinks} />
            )}

            {tab === 'preview' && (
              <DocumentPreview previewData={result.previewData} file={file} />
            )}

            {tab === 'fullview' && (
              <FullView file={file} previewData={result.previewData} />
            )}
          </div>
        )}

        {/* Empty state */}
        {!file && !loading && (
          <div>
            {/* Telemetry disclosure */}
            <div style={{
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border-active)',
              borderLeft: '3px solid var(--accent-yellow)',
              borderRadius: 6,
              padding: '14px 18px',
              marginBottom: 20,
              display: 'flex',
              gap: 12,
              alignItems: 'flex-start',
            }}>
              <AlertTriangle size={15} color="var(--accent-yellow)" style={{ flexShrink: 0, marginTop: 2 }} />
              <div>
                <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 6 }}>
                  Usage metadata is logged for monitoring purposes
                </p>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: 8 }}>
                  When you analyse a file, the following information is recorded. <strong>File contents are never transmitted.</strong>
                </p>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {[
                    '📍 IP address',
                    '📄 Filename & file type',
                    '📦 File size',
                    '⚠️ Risk level result',
                    '🖥️ Device type',
                    '🌍 Operating system',
                    '🧭 Browser',
                    '📐 Screen resolution',
                    '🗣️ Browser language',
                  ].map(item => (
                    <span key={item} style={{
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border)',
                      borderRadius: 3,
                      padding: '3px 9px',
                      fontSize: 11,
                      color: 'var(--text-secondary)',
                      fontFamily: "'IBM Plex Mono', monospace",
                    }}>{item}</span>
                  ))}
                </div>
              </div>
            </div>

            {/* Feature grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
              {[
                { icon: <Shield size={16} />, title: 'Macro Detection', desc: 'VBA macros in Office docs' },
                { icon: <Link size={16} />, title: 'External Links', desc: 'URLs, relationships, OLE refs' },
                { icon: <User size={16} />, title: 'Metadata & PII', desc: 'Author, company, revision history' },
                { icon: <Code size={16} />, title: 'Active Content', desc: 'JS, scripts, dangerous formulas' },
                { icon: <AlertTriangle size={16} />, title: 'Obfuscation', desc: 'Hex blobs, base64, eval patterns' },
                { icon: <Layers size={16} />, title: 'Embedded Objects', desc: 'OLE, hidden sheets, iframes' },
              ].map(({ icon, title, desc }) => (
                <div key={title} style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: '14px 16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, color: 'var(--accent-green)' }}>
                    {icon}
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{title}</span>
                  </div>
                  <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>{desc}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer style={{ borderTop: '1px solid var(--border)', padding: '14px 32px', textAlign: 'center' }}>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace", marginBottom: 4 }}>
          File contents are analysed locally in your browser and are never uploaded to any server.
        </p>
        <p style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'IBM Plex Mono', monospace" }}>
          Usage metadata (IP, filename, file type, device &amp; browser info, risk result) is logged for monitoring. No file content is included.
        </p>
      </footer>
    </div>
  );
}
