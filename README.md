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
- **JSZip** (CDN, runtime only) — OOXML ZIP inspection
- **DOMPurify** — HTML sanitisation for content preview
- **Cloudflare Pages** — Hosting with strict security headers
