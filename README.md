# DocScan — Document Security Analyser

A fully client-side document security analyser that runs entirely in the browser. No files are ever uploaded to a server.

## Supported File Types

| Format | Analysis |
|--------|----------|
| PDF | Metadata, embedded JS, AcroForm, external links, obfuscation |
| DOCX / DOC | VBA macros, OLE objects, hyperlinks, metadata, external relationships |
| XLSX / XLS / XLSM | VBA macros, dangerous formulas (WEBSERVICE, DDE, shell), hidden sheets, external refs |
| PPTX / PPT | VBA macros, OLE objects, embedded content, metadata |
| HTML / HTM | Scripts, iframes, forms, external resources, meta refresh, JS obfuscation |
| CSV | CSV injection cells (=, +, -, @), embedded URLs |
| XML / SVG | XXE entity injection, external references, embedded scripts |
| RTF | OLE objects, Equation Editor exploit patterns (CVE-2017-11882), hex payloads |
| HAR (Chrome/DevTools) | Authorization headers (Bearer/Basic, decoded), cookies/Set-Cookie, sensitive query params, POST bodies, JWTs, plaintext-HTTP endpoints |
| JAR (Java Archive) | Recursive archive scan + MANIFEST.MF, code-signing detection, secrets in .properties/.xml/.yml resources |
| ZIP / TAR / GZIP / BZIP2 / XZ (incl. .tgz/.tar.gz/.tbz2/.tar.bz2/.txz/.tar.xz) | Recursive extraction and scanning of every nested file, up to 5 levels deep, with hard resource-exhaustion limits (see below) |
| 7-Zip (.7z) / RAR (.rar) | Full extraction via the real 7-Zip codec compiled to WASM — one dependency covers both formats, since 7-Zip's own codec reads RAR natively (RAR4 fully, RAR5 read-only). Same recursive scanning and limits as other archives. Encrypted entries/archives are detected and skipped — never attempted, never prompted for |
| .env / .ini / .cfg / .conf / .properties / .toml / .yaml / .yml / .json / AWS `credentials`/`config` (no extension) | Shared secret scan + format-specific checks (AWS CLI credentials, Kubernetes kubeconfig, Docker registry auth, Terraform state, GCP service-account keys) |
| PEM / KEY / CRT / CER / CSR / SSH keys | Private-key/certificate block classification, always-critical private-key detection |
| EXE / DLL / SYS | Full PE32/PE32+ structural parsing: machine type, subsystem, compile timestamp, entry point, ASLR/DEP flags, per-section entropy (packing signal), full import table (DLL + function names) with suspicious-API classification (process injection, anti-debugging, persistence, credential access, keylogging, C2-adjacent networking) — plus the shared string/secret scan layered on top |
| ELF (Linux/Unix binaries, any/no extension) | Full ELF header + section/program header parsing: class/endianness/machine/entry point, static vs. dynamic linking, interpreter path, `DT_NEEDED`/`RPATH`/`RUNPATH`, per-section entropy, dynamic symbol table (imported library functions) with the same suspicious-category classification — plus the shared string/secret scan |
| Mach-O (macOS) | Magic-byte identification + printable-string scan (no dedicated structural parser yet) |
| PCAP / PCAPNG | Full protocol analysis: link/IP/TCP/UDP decoding, TCP stream reassembly (handles out-of-order arrival and exact-retransmission dedup), HTTP request/response parsing, DNS parsing with name-compression support and tunneling-pattern heuristics, TLS ClientHello parsing with SNI extraction and JA3 fingerprinting, SNMP community-string extraction, and cleartext-credential detection for FTP/Telnet/POP3/IMAP/LDAP — verified against real captures and an actual TLS handshake (JA3 hash matched independently-computed ground truth from `tshark` exactly) |
| Any other file | Falls back to a generic secret scan against decodable text content instead of a bare "unsupported" message |

A file's actual byte signature is checked against its extension for every supported type — a renamed or spoofed file (e.g. an executable saved as `.pdf`, or a ZIP saved as `.txt`) is still identified and flagged as a **Format Spoofing** finding rather than silently mis-analysed or skipped.

## Archive & Recursion Limits

Opening archives is the biggest new attack surface a static analyser can take on (decompression bombs, unbounded nesting, path traversal). These limits are enforced in code, not just documentation:

| Limit | Value |
|---|---|
| Max upload size | 250 MB |
| Max total decompressed size (whole recursive tree) | 1 GB |
| Max individual extracted file | 100 MB |
| Max files per archive | 10,000 |
| Max archive nesting depth | 5 |
| PCAP/binary string-scan coverage | First 300 MB of the capture, first 5,000 TCP streams, 5 MB per stream |

Archive entries with a path-traversal pattern (`../`, absolute paths) are detected and skipped rather than extracted — including cases where the underlying ZIP library normalizes the path internally before exposing it, by checking the archive's raw pre-normalization entry name. Nothing extracted from an archive is ever written to disk; everything stays in memory for the life of the analysis. GZIP and XZ streams are decompressed incrementally so a bomb is caught and aborted mid-stream rather than after the fact; BZIP2 uses a byte-bounded output sink for the same reason.

**Not yet implemented:** Mach-O binaries get string/secret scanning only, not the structural parsing PE and ELF now have. PCAP analysis never attempts TLS decryption (no key material is available, or sought) and doesn't do full RFC 793 TCP reassembly (no PAWS, no partial-overlap segment merging, no 32-bit sequence-number wraparound handling) — it correctly handles out-of-order arrival and exact retransmission for the vast majority of real captures, but a capture deliberately engineered to defeat that ordering could produce a garbled reassembly for that one stream rather than a crash.

### PCAP — verified against a real network capture and an actual TLS handshake, not just written to the spec

The DNS, TLS/JA3, HTTP, and SNMP parsers were checked against `tshark` (Wireshark's CLI) as ground truth, not just against the format specifications. Most notably: a real capture's TLS ClientHello — captured live via `tcpdump` while connecting to pypi.org — was fed through this pipeline's JA3 computation and produced `0149f47eabf9a20d0893e2a44e5a6323`, byte-for-byte identical to `tshark`'s own independently-computed JA3 hash for the same packet, including exact agreement on GREASE-value stripping. DNS name decompression was checked against 8 real compressed A-record answers, all correct. TCP stream reassembly was checked against a deliberately-crafted out-of-order capture (a secret split across two segments, with the second arriving first) and reassembled correctly.

### 7z/RAR — verified against real hostile fixtures, not just written and assumed to work

7z-wasm's underlying stdin handling can fall through to a native `window.prompt()` in a real browser if an encrypted archive is processed without an override — this build explicitly disables that (`stdin: () => null`) so a hostile password-protected archive can't pop a dialog in the user's tab. Encrypted entries are detected from the archive's technical listing and skipped entirely — not attempted, not silently ignored, but reported as their own finding. Archives with **encrypted headers** (where even the file listing needs a password) fail with a clear, specific message rather than a raw error code.

**Symlink-based path traversal** — the RAR/7z analogue of "Zip Slip," and not caught by the same `../`-in-filename check that protects ZIP/TAR — is defended in two independent layers: 7-Zip's own codec refuses to create a symlink pointing outside the extraction root (confirmed directly: `ERROR: Dangerous link path was ignored`), and this code additionally never follows a symlink when reading extracted output (`FS.lstat` + `FS.isLink` before any `readFile`), as defense in depth in case the first layer is ever wrong. This was verified against a real exploit sample — `rar5-evil-symlink-traversal.rar` from the `rarfile` Python library's own test suite — not a synthetic case written to make the code look good.

The 7z/RAR WASM module (~1.7MB) is lazy-loaded only when such a file is actually encountered, so it doesn't add to the initial page load for everyone else. Also verified: correct extraction of real multi-file `.7z` archives with nested directories, real RAR3 archives with Unicode filenames (which even the reference `unrar-free` CLI failed to decode correctly, but this pipeline handled correctly), and clean, non-hanging failure on empty/random/truncated input.

All binary parsing (PE/ELF) is defensive by design — it's reading untrusted, potentially malformed or deliberately hostile files. Every read is bounds-checked, every walk (sections, imports, symbols) is capped, and a parse failure degrades to the string/secret-scan fallback with a note rather than crashing the analysis. Verified against real production binaries (`/bin/ls`, `/bin/bash`, real PE executables) as well as deliberately truncated and corrupted inputs.

Suspicious-API findings (process injection, anti-debugging, persistence, credential access, keylogging for PE; shell execution, ptrace, privilege manipulation for ELF) are reported as **signals to weigh, not verdicts** — legitimate software imports these routinely (e.g. `bash` genuinely calls `execve`/`fork`; that's not a compromise indicator by itself). No malware-family identification or scoring is attempted.

## Security Checks

- **Macros / VBA** — Detects vbaProject.bin and macro-enabled file extensions
- **Dangerous Formulas** — WEBSERVICE, DDE, DDEAUTO, CALL, shell command strings
- **External Links** — URLs in content, relationships, annotations, and formulas
- **Embedded Objects** — OLE objects, hidden sheets, iframes
- **Metadata / PII** — Author, company, revision count, last modified by
- **Active Content** — JavaScript in PDFs/SVGs/HTML, AcroForm, XFA
- **Obfuscation** — Base64 blobs, hex payloads, eval/unescape patterns
- **XXE Injection** — SYSTEM/PUBLIC entity declarations in XML
- **CSV Injection** — Formula-triggering cell prefixes
- **RTF Exploits** — Known Equation Editor vulnerability signatures
- **Credentials & Secrets** — a shared two-tier detector (`src/lib/secrets.js`) used by every analyser: AWS/GCP/Azure keys, GitHub/Slack/Discord tokens & webhooks, JWTs (structurally validated), private key blocks, database connection strings, HTTP Basic/Bearer auth (Basic is base64-decoded and validated before being called "confirmed"), generic API-key/password assignments. "Potential secret" (pattern match) is always distinguished from "Confirmed credential" (format/structure validated) to keep false positives down. Matched values are always redacted before they reach a finding, telemetry, or the UI — but where the match came from an assignment (`VARIABLE_NAME = value`, a named cookie, `heroku_api_key=...`, etc.), the variable/key name itself is shown in full, since the name isn't sensitive and is often exactly what's needed to find the line in a large file (a redacted value alone — `sk_l…9xYz` — could be any of a dozen assignments; `AWS_SECRET_ACCESS_KEY = sk_l…9xYz` isn't).

## Resilience & Error Handling

Every analyser in this app runs against untrusted, potentially malformed or deliberately hostile input by design — so the UI is built to degrade gracefully rather than crash outright when a parser hands back something unexpected.

- **Defensive value formatting** — a shared `toDisplayString()` helper normalises anything a parser might return (PDF `Name` objects, dates, arrays, `null`/`undefined`, arbitrary objects) into a safe, readable string before it's ever handed to React as a child. This is applied both at the source (e.g. PDF metadata extraction) and again defensively at render time in the Metadata table and the Links/Archive/HAR/PCAP list views, so a single missed case in one analyser can't blank the screen. This exists because it already happened once: a PDF's `/Trapped` field could come back from pdf.js as a raw `{ name: 'False' }` object instead of a string, and rendering it directly crashed the whole app with an unrecoverable React error.
- **Error boundaries, not a blank screen** — a top-level boundary wraps the whole app as a last resort, a per-tab boundary isolates Findings/Metadata/Links/Preview/Full View from each other (an error in one tab no longer takes down the rest of the UI), and a compact per-row boundary wraps individual Findings and archive entries so one malformed item can't take an entire list down with it. Every boundary offers a "Reset view" action rather than requiring a hard refresh.
- **Console diagnostics** — every caught render error logs a single grouped console entry (`console.groupCollapsed`, look for **"DocScan render error"**) containing the underlying error, the full React component stack, and contextual info (active tab, file name/type/size, or the specific finding/entry involved). The same report is also stashed on `window.__docscanLastError` so it can be inspected or copied out of the console after the fact — useful when triaging a report from someone else.
- **Readable stack traces in production** — production builds emit hidden source maps (`build.sourcemap: 'hidden'` in `vite.config.js`): the `.map` files are generated alongside each bundle but never referenced from the shipped JS (no `//# sourceMappingURL` is added), so nothing changes for end users, but a `console.error` stack captured from production can be decoded back to real file/line/function names by pairing it with the matching `.map` file instead of showing opaque minified names like `xo`/`ks`/`Cc`.

## Deploy to Cloudflare Pages

### Option A — GitHub (recommended)

1. Push this repo to GitHub
2. Go to [Cloudflare Dashboard](https://dash.cloudflare.com) → **Workers & Pages** → **Create application** → **Pages**
3. Connect your GitHub repo
4. Set build settings:
   - **Framework preset:** None
   - **Build command:** `npm run build`
   - **Build output directory:** `dist`
5. Click **Save and Deploy**

Cloudflare will auto-deploy on every push to `main`.

### Option B — Direct upload (Wrangler CLI)

```bash
npm install
npm run build
npx wrangler pages deploy dist --project-name docscan
```

### Option C — Drag & drop

1. Run `npm run build` locally
2. Go to Cloudflare Dashboard → Workers & Pages → Create application → Pages
3. Choose **"Upload assets"** and drag the `dist/` folder

## Local Development

```bash
npm install
npm run dev
```

Visit `http://localhost:5173`

## Build

```bash
npm run build
```

Output goes to `dist/` — ready to deploy.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VITE_DISCORD_WEBHOOK_URL` | Optional | Discord webhook URL to receive usage telemetry |

If not set, telemetry is silently skipped and everything else works normally.

### Setting the variable in Cloudflare Pages

1. Go to your Pages project → **Settings** → **Environment variables**
2. Click **Add variable**
3. Name: `VITE_DISCORD_WEBHOOK_URL`
4. Value: your Discord webhook URL (e.g. `https://discord.com/api/webhooks/...`)
5. Set for **Production** (and optionally Preview)
6. Trigger a new deployment — Vite bakes the value in at build time

### Getting a Discord webhook URL

1. Open your Discord server → channel settings → **Integrations** → **Webhooks**
2. Click **New Webhook**, give it a name, choose a channel
3. Click **Copy Webhook URL**

### What is logged (per analysis event)

- IP address (via `https://ip.b0x.workers.dev/`)
- Filename and file extension
- File size
- Risk level result (CLEAN / LOW / MEDIUM / HIGH / CRITICAL)
- Finding count and finding **categories only** (e.g. "Secrets — Cloud Credentials (2), Format Spoofing (1)") — never the matched value, which is always redacted before it exists as a finding
- Device type, OS, browser
- Screen resolution
- Browser language

**File contents are never transmitted.** The disclosure is shown to users on the main page.


## Privacy

- **File contents are never transmitted** — all parsing happens in the browser using WebAssembly and JavaScript
- Usage metadata **is** sent off-device when `VITE_DISCORD_WEBHOOK_URL` is configured — see "What is logged" above for exactly what that includes (IP, filename/extension/size, risk result, finding categories/counts, device/OS/browser/screen/language). This is opt-in at deploy time: unset the variable and telemetry is silently skipped entirely.
- The `_headers` file's CSP intentionally allows exactly two external destinations — `discord.com` (the telemetry webhook) and `ip.b0x.workers.dev` (IP lookup for that telemetry) — and nothing else; `connect-src` blocks any other outbound request even if the code tried to make one

## Software Bill of Materials (SBOM)

`sbom.cdx.json` at the project root is a [CycloneDX](https://cyclonedx.org/) 1.5 SBOM covering every direct and transitive npm dependency, generated from `package.json`/`package-lock.json`. Regenerate it any time dependencies change:

```bash
npm install
npx --yes @cyclonedx/cyclonedx-npm --output-file sbom.cdx.json --output-format json --spec-version 1.5
```

Treat a diff in `sbom.cdx.json` the same as a diff in `package-lock.json` during review — a new component appearing there that wasn't part of a deliberate, discussed change is a signal to stop and ask why before merging, not to wave it through. (This file exists precisely because that happened once already during development: a WASM build of 7-Zip, added to enable RAR/7z extraction, showed up in a routine SBOM generation without ever having been proposed, reviewed, or tested, and was removed once found. Regenerating this file after any dependency change is how that stays caught going forward.)

**Update:** `7z-wasm` is back in this SBOM as of the Phase 3 archive-extraction work — this time added deliberately, with explicit sign-off, and tested against real hostile fixtures (a genuine RAR symlink-traversal exploit sample, header-encrypted and content-encrypted archives, truncated/corrupted input) before being considered done. See "7z/RAR — verified against real hostile fixtures" above for what was actually checked. This is the process the paragraph above describes working as intended, not a repeat of the earlier incident.

## Tech Stack

- **React 18** + **Vite**
- **pdfjs-dist** — PDF parsing
- **mammoth** — DOCX → HTML conversion
- **SheetJS (xlsx)** — Excel/PPTX parsing
- CSV, PCAP/PCAPNG, DNS, TLS, HTTP-over-TCP, and SNMP parsing are hand-rolled (no library) — see the "PCAP" section above for how the latter group was verified
- **JSZip** — ZIP/JAR/OOXML container inspection (bundled, not CDN)
- **fflate** — streaming GZIP decompression
- **seek-bzip** — BZIP2 decompression
- **xz-decompress** — XZ decompression (WASM)
- **7z-wasm** — 7-Zip/RAR extraction (the real 7-Zip codec, compiled to WASM)
- **blueimp-md5** — MD5 for JA3 TLS fingerprinting (Web Crypto's SubtleCrypto doesn't support MD5)
- **DOMPurify** — HTML sanitisation for content preview
- **Cloudflare Pages** — Hosting with strict security headers
