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
| .env / .ini / .cfg / .conf / .properties / .toml / .yaml / .yml / .json | Shared secret scan + format-specific checks (Kubernetes kubeconfig, Docker registry auth, Terraform state, GCP service-account keys) |
| PEM / KEY / CRT / CER / CSR / SSH keys | Private-key/certificate block classification, always-critical private-key detection |
| EXE / DLL / SYS / ELF / Mach-O | Magic-byte identification + printable-string extraction + secret scan + suspicious API/LOLBin string flags (no execution, no full header/import parsing yet) |
| PCAP / PCAPNG | Magic-byte identification + bounded printable-string scan for plaintext credentials (FTP/Telnet USER/PASS, SNMP community strings, HTTP Host headers, IPs, URLs) — not full packet/stream reconstruction |
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
| PCAP/binary string-scan coverage | First 50 MB |

Archive entries with a path-traversal pattern (`../`, absolute paths) are detected and skipped rather than extracted — including cases where the underlying ZIP library normalizes the path internally before exposing it, by checking the archive's raw pre-normalization entry name. Nothing extracted from an archive is ever written to disk; everything stays in memory for the life of the analysis. GZIP and XZ streams are decompressed incrementally so a bomb is caught and aborted mid-stream rather than after the fact; BZIP2 uses a byte-bounded output sink for the same reason.

**Not yet implemented:** 7-Zip and RAR archives are detected (and reported as such) but not extracted. Full PCAP protocol/stream reconstruction (TLS SNI, JA3/JA4, DNS analysis) and full PE/ELF binary structure parsing (import tables, section entropy) are planned for a later phase — see the in-app findings for a file when a deeper analysis pass would apply.

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
- **Credentials & Secrets** — a shared two-tier detector (`src/lib/secrets.js`) used by every analyser: AWS/GCP/Azure keys, GitHub/Slack/Discord tokens & webhooks, JWTs (structurally validated), private key blocks, database connection strings, HTTP Basic/Bearer auth (Basic is base64-decoded and validated before being called "confirmed"), generic API-key/password assignments. "Potential secret" (pattern match) is always distinguished from "Confirmed credential" (format/structure validated) to keep false positives down. Matched values are always redacted before they reach a finding, telemetry, or the UI.

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

- All file parsing happens in the browser using WebAssembly and JavaScript
- No telemetry, no analytics, no external requests
- The `_headers` file enforces strict CSP to prevent any unintended outbound connections
- `connect-src: 'self'` — the page cannot phone home even if the code tried to

## Tech Stack

- **React 18** + **Vite**
- **pdfjs-dist** — PDF parsing
- **mammoth** — DOCX → HTML conversion
- **SheetJS (xlsx)** — Excel/PPTX parsing
- **papaparse** — CSV parsing
- **JSZip** — ZIP/JAR/OOXML container inspection (bundled, not CDN)
- **fflate** — streaming GZIP decompression
- **seek-bzip** — BZIP2 decompression
- **xz-decompress** — XZ decompression (WASM)
- **DOMPurify** — HTML sanitisation for content preview
- **Cloudflare Pages** — Hosting with strict security headers
