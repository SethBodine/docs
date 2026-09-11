// ─── HTTP PARSER (from a reassembled TCP stream) ────────────────────────────
// Loose HTTP/1.x parsing over already-reassembled client→server and
// server→client byte streams. Not a strict parser — real captures have
// chunked encoding, pipelining, and other complexity a full HTTP parser
// would need to handle. This extracts what matters for a security scan
// (method, path, headers, a bounded slice of the body) and hands headers/
// body to the shared secret detector, the same as the HAR analyser does.

const MAX_BODY_SCAN = 200_000; // cap body bytes scanned for secrets, matches har.js's per-entry cap

function looksLikeHttpRequest(bytes) {
  const head = new TextDecoder('ascii', { fatal: false }).decode(bytes.subarray(0, 16));
  return /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+\S/.test(head);
}
function looksLikeHttpResponse(bytes) {
  const head = new TextDecoder('ascii', { fatal: false }).decode(bytes.subarray(0, 8));
  return /^HTTP\/\d/.test(head);
}

function parseHeaders(text) {
  const lines = text.split('\r\n');
  const startLine = lines[0] || '';
  const headers = {};
  let i = 1;
  for (; i < lines.length; i++) {
    if (lines[i] === '') { i++; break; }
    const idx = lines[i].indexOf(':');
    if (idx === -1) continue;
    headers[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim();
  }
  const bodyStart = lines.slice(0, i).join('\r\n').length + 2;
  return { startLine, headers, bodyStart };
}

/**
 * @param {Uint8Array} c2s - client-to-server stream bytes
 * @param {Uint8Array} s2c - server-to-client stream bytes
 * @returns {null | { method, path, host, status, headers, bodyText }}
 */
export function parseHttpStream(c2s, s2c) {
  if (c2s.length === 0 || !looksLikeHttpRequest(c2s)) return null;

  const reqText = new TextDecoder('utf-8', { fatal: false }).decode(c2s.subarray(0, Math.min(c2s.length, MAX_BODY_SCAN)));
  const { startLine, headers, bodyStart } = parseHeaders(reqText);
  const [method, path] = startLine.split(' ');
  const reqBody = reqText.slice(bodyStart, bodyStart + MAX_BODY_SCAN);

  let status = null, respHeaders = {}, respBody = '';
  if (s2c.length > 0 && looksLikeHttpResponse(s2c)) {
    const respText = new TextDecoder('utf-8', { fatal: false }).decode(s2c.subarray(0, Math.min(s2c.length, MAX_BODY_SCAN)));
    const parsed = parseHeaders(respText);
    const statusMatch = parsed.startLine.match(/^HTTP\/[\d.]+\s+(\d+)/);
    status = statusMatch ? parseInt(statusMatch[1], 10) : null;
    respHeaders = parsed.headers;
    respBody = respText.slice(parsed.bodyStart, parsed.bodyStart + MAX_BODY_SCAN);
  }

  return {
    method: method || 'GET',
    path: path || '/',
    host: headers['host'] || null,
    requestHeaders: headers,
    requestBody: reqBody,
    status,
    responseHeaders: respHeaders,
    responseBody: respBody,
  };
}
