// ─── HAR (Chrome DevTools "HTTP Archive") ANALYSER ─────────────────────────
// A HAR export can contain a full recording of headers, cookies, auth tokens,
// and POST bodies for every request a browser session made — often far more
// sensitive than a typical document. This is scanned with the shared secret
// detector plus HAR-specific structural checks.

import { scanForSecrets } from './secrets.js';

const MAX_ENTRIES_SCANNED = 5000; // OWASP: resource exhaustion guard for huge HARs

function headerValue(headers, name) {
  const h = (headers || []).find(h => h.name?.toLowerCase() === name.toLowerCase());
  return h?.value;
}

function hostnameOf(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

export async function analyseHar(arrayBuffer) {
  const findings = [];
  const metadata = {};
  const externalLinks = [];
  let textContent = '';

  let har;
  try {
    const text = new TextDecoder('utf-8').decode(arrayBuffer);
    har = JSON.parse(text);
  } catch (e) {
    return {
      findings: [{ severity: 'medium', category: 'Parse Error', title: 'Could not parse HAR file', detail: e.message }],
      metadata, textContent: '', externalLinks, previewData: { type: 'har', entries: [] },
    };
  }

  const entries = har?.log?.entries || [];
  metadata['Total Requests'] = String(entries.length);
  if (har?.log?.creator?.name) metadata['Captured With'] = `${har.log.creator.name} ${har.log.creator.version || ''}`.trim();
  if (har?.log?.browser?.name) metadata['Browser'] = `${har.log.browser.name} ${har.log.browser.version || ''}`.trim();

  if (entries.length > MAX_ENTRIES_SCANNED) {
    findings.push({
      severity: 'info', category: 'Format',
      title: `Large HAR file — only first ${MAX_ENTRIES_SCANNED} of ${entries.length} requests scanned`,
      detail: 'Scan capped to protect against resource exhaustion on very large captures.',
    });
  }

  const hosts = new Set();
  const authHeaderCount = { count: 0 };
  const cookieCount = { count: 0 };
  const previewEntries = [];

  for (const entry of entries.slice(0, MAX_ENTRIES_SCANNED)) {
    const req = entry.request || {};
    const res = entry.response || {};
    const url = req.url || '';
    const host = hostnameOf(url);
    if (host) hosts.add(host);
    if (url) {
      externalLinks.push({ url, context: `${req.method || 'GET'} request` });
      textContent += url + '\n';
    }

    // Authorization headers (request + response, in case of proxied replay logs)
    const authReq = headerValue(req.headers, 'authorization');
    if (authReq) {
      authHeaderCount.count++;
      findings.push(...scanForSecrets(`Authorization: ${authReq}`, `HAR request to ${host || url}`));
    }

    // Cookies
    for (const c of req.cookies || []) {
      cookieCount.count++;
      findings.push(...scanForSecrets(`Cookie: ${c.name}=${c.value}`, `HAR cookie on ${host || url}`));
    }
    const setCookie = headerValue(res.headers, 'set-cookie');
    if (setCookie) {
      findings.push(...scanForSecrets(`Set-Cookie: ${setCookie}`, `HAR response from ${host || url}`));
    }

    // Query string params (API keys are very commonly leaked here)
    for (const q of req.queryString || []) {
      if (/key|token|secret|auth|password/i.test(q.name)) {
        findings.push({
          severity: 'medium',
          category: 'Secrets — Query Parameters',
          title: `Potential secret in query string: "${q.name}"`,
          detail: `${host || url} — value redacted`,
        });
      }
    }

    // POST bodies (form logins, API calls with credentials/tokens)
    if (req.postData?.text) {
      findings.push(...scanForSecrets(req.postData.text, `HAR POST body to ${host || url}`));
    }

    // Response bodies — capped per-entry to avoid scanning megabytes of HTML/JS per request
    if (res.content?.text && res.content.text.length < 200_000) {
      findings.push(...scanForSecrets(res.content.text, `HAR response body from ${host || url}`));
    }

    if (previewEntries.length < 2000) {
      previewEntries.push({ method: req.method, url, status: res.status, host });
    }
  }

  metadata['Distinct Hosts'] = String(hosts.size);
  metadata['Requests with Authorization header'] = String(authHeaderCount.count);
  metadata['Requests with cookies'] = String(cookieCount.count);

  if (authHeaderCount.count > 0) {
    findings.push({
      severity: 'info', category: 'Authentication',
      title: `${authHeaderCount.count} request(s) carried an Authorization header`,
      detail: 'A HAR file preserves live session/auth tokens — treat it like a password if sharing for debugging.',
    });
  }

  // Non-HTTPS endpoints — credentials/cookies over plaintext HTTP
  const insecure = entries.filter(e => (e.request?.url || '').startsWith('http://'));
  if (insecure.length > 0) {
    findings.push({
      severity: 'medium', category: 'Transport Security',
      title: `${insecure.length} request(s) made over plain HTTP`,
      detail: [...new Set(insecure.slice(0, 5).map(e => hostnameOf(e.request.url)))].join(', '),
    });
  }

  if (findings.length === 0) {
    findings.push({ severity: 'info', category: 'Format', title: 'No credentials or tokens detected', detail: `Scanned ${entries.length} request(s) across ${hosts.size} host(s).` });
  }

  return {
    findings,
    metadata,
    textContent: textContent.slice(0, 5000),
    externalLinks,
    previewData: { type: 'har', entries: previewEntries, totalRequests: entries.length },
  };
}
