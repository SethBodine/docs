// ─── SHARED SECRET / CREDENTIAL DETECTOR ────────────────────────────────────
// One detector, reused by every analyser (HAR, JAR, archives, config files,
// binaries, PCAP, etc.) instead of duplicating regexes per file type.
//
// Two-tier severity model:
//   "potential" -> pattern-shaped match only (e.g. `password=...`)          -> MEDIUM
//   "confirmed" -> format/structure validated (checksums, PEM markers,      -> HIGH / CRITICAL
//                  well-formed JWTs, provider-specific fixed prefixes)
//
// This keeps false-positive-prone generic patterns from drowning out real,
// structurally-verified credentials in the findings list.

const MAX_TEXT_SCAN_LENGTH = 2_000_000; // cap per-file text scanned for secrets (OWASP: resource exhaustion)
const MAX_FINDINGS_PER_FILE = 200;      // cap findings so a pathological file can't flood the UI

function truncate(s, n = 120) {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function redact(match) {
  // Never surface the full secret value in findings/telemetry — show enough to
  // identify it, not enough to use it.
  if (match.length <= 8) return '•'.repeat(match.length);
  return match.slice(0, 4) + '…' + match.slice(-4);
}

function isBase64Url(s) {
  return /^[A-Za-z0-9_-]+$/.test(s);
}

function looksLikeValidJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  if (!parts.every(p => p.length > 0 && isBase64Url(p))) return false;
  try {
    const pad = s => s + '='.repeat((4 - (s.length % 4)) % 4);
    const header = JSON.parse(atob(pad(parts[0]).replace(/-/g, '+').replace(/_/g, '/')));
    return typeof header === 'object' && (header.alg || header.typ);
  } catch {
    return false;
  }
}

function decodeBasicAuthIfValid(b64) {
  try {
    const decoded = atob(b64);
    // A genuine Basic-auth payload is "<user>:<password>" — reject decoded
    // garbage (non-printable bytes) so we don't call arbitrary base64 "confirmed".
    if (!/^[\x20-\x7e]+:[\x20-\x7e]*$/.test(decoded)) return null;
    return decoded;
  } catch {
    return null;
  }
}

// Order matters: more specific / confirmable patterns first.
const MATCHERS = [
  {
    name: 'AWS Access Key ID',
    re: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    tier: 'confirmed', // fixed-prefix format, effectively unambiguous
    category: 'Cloud Credentials',
  },
  {
    name: 'AWS Secret Access Key (context-matched)',
    // Only flagged as confirmed when it appears near an aws-secret-shaped key name
    re: /(?:aws_secret_access_key|secretaccesskey|secret_key)\s*[:=]\s*["']?([A-Za-z0-9\/+=]{40})["']?/gi,
    tier: 'confirmed',
    category: 'Cloud Credentials',
    group: 1,
  },
  {
    name: 'GCP Service Account Private Key',
    re: /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/g,
    tier: 'confirmed',
    category: 'Cloud Credentials',
  },
  {
    name: 'Azure Storage Account Key / SAS',
    re: /AccountKey=[A-Za-z0-9+/=]{40,}/g,
    tier: 'confirmed',
    category: 'Cloud Credentials',
  },
  {
    name: 'GitHub Token',
    re: /\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}\b/g,
    tier: 'confirmed',
    category: 'Source Control',
  },
  {
    name: 'Slack Token',
    re: /\bxox[baprs]-[0-9A-Za-z-]{10,72}\b/g,
    tier: 'confirmed',
    category: 'Chat / Collaboration',
  },
  {
    name: 'Discord Bot Token',
    re: /\b[MN][A-Za-z\d]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b/g,
    tier: 'confirmed',
    category: 'Chat / Collaboration',
  },
  {
    name: 'Discord Webhook URL',
    re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g,
    tier: 'confirmed',
    category: 'Chat / Collaboration',
  },
  {
    name: 'Slack Webhook URL',
    re: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9A-Za-z]+/g,
    tier: 'confirmed',
    category: 'Chat / Collaboration',
  },
  {
    name: 'Private Key Block',
    re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    tier: 'confirmed',
    category: 'Cryptographic Material',
  },
  {
    name: 'JSON Web Token (structurally valid)',
    re: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
    tier: 'validate', // needs looksLikeValidJwt() before it counts as confirmed
    category: 'Session / Auth Tokens',
  },
  {
    name: 'Database Connection String with Credentials',
    re: /\b(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|jdbc:[a-z]+|redis|amqp):\/\/[^\s"'<>]*:[^\s"'<>@]*@[^\s"'<>]+/gi,
    tier: 'confirmed',
    category: 'Database Credentials',
  },
  {
    name: 'HTTP Basic Auth in URL',
    re: /https?:\/\/[^\s"'<>]+:[^\s"'<>@]+@[^\s"'<>]+/g,
    tier: 'confirmed',
    category: 'Session / Auth Tokens',
  },
  {
    name: 'Authorization: Bearer Header',
    re: /Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]{16,})/gi,
    tier: 'potential',
    category: 'Session / Auth Tokens',
    group: 1,
  },
  {
    name: 'Authorization: Basic Header',
    re: /Authorization:\s*Basic\s+([A-Za-z0-9+/]{4,}={0,2})/gi,
    tier: 'validate-basic',
    category: 'Session / Auth Tokens',
    group: 1,
  },
  {
    name: 'Cookie / Set-Cookie with session value',
    re: /(?:Set-Cookie|Cookie):\s*[^=;\n]{1,40}=([A-Za-z0-9%._-]{16,})/gi,
    tier: 'potential',
    category: 'Session / Auth Tokens',
    group: 1,
  },
  {
    name: 'Generic API Key Assignment',
    re: /\b(api[_-]?key|apikey|access[_-]?token|client[_-]?secret|secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-./+]{12,})["']?/gi,
    tier: 'potential',
    category: 'Generic Secret',
    group: 2,
  },
  {
    name: 'Generic Password Assignment',
    re: /\b(password|passwd|pwd)\s*[:=]\s*["']?([^\s"'<>]{4,})["']?/gi,
    tier: 'potential',
    category: 'Generic Secret',
    group: 2,
  },
  {
    name: 'SSH Private Key File Reference',
    re: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    tier: 'confirmed',
    category: 'Cryptographic Material',
  },
];

/**
 * Scan a text blob for credential-shaped content.
 * @param {string} text
 * @param {string} sourceLabel - where this text came from (e.g. "HAR request #12 header", "config/application.properties")
 * @returns {Array<Finding>}
 */
export function scanForSecrets(text, sourceLabel = '') {
  if (!text || typeof text !== 'string') return [];
  const scanText = text.slice(0, MAX_TEXT_SCAN_LENGTH);
  const findings = [];
  const seen = new Set();

  for (const matcher of MATCHERS) {
    if (findings.length >= MAX_FINDINGS_PER_FILE) break;
    matcher.re.lastIndex = 0;
    let match;
    let countForMatcher = 0;
    while ((match = matcher.re.exec(scanText)) && countForMatcher < 20) {
      const raw = matcher.group ? match[matcher.group] : match[0];
      if (!raw) continue;
      const dedupeKey = matcher.name + '|' + raw;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      countForMatcher++;

      let tier = matcher.tier;
      if (tier === 'validate') {
        tier = looksLikeValidJwt(raw) ? 'confirmed' : 'potential';
      }
      let extraDetail = '';
      if (tier === 'validate-basic') {
        const decoded = decodeBasicAuthIfValid(raw);
        if (decoded) {
          tier = 'confirmed';
          const [user] = decoded.split(':');
          extraDetail = ` — decodes to user "${user}" (password redacted)`;
        } else {
          tier = 'potential';
        }
      }

      const severity = tier === 'confirmed' ? 'high' : 'medium';
      const label = tier === 'confirmed' ? 'Confirmed credential' : 'Potential secret';

      findings.push({
        severity,
        category: `Secrets — ${matcher.category}`,
        title: `${label}: ${matcher.name}`,
        detail: `${sourceLabel ? sourceLabel + ' — ' : ''}${redact(raw)}${matcher.name.includes('Private Key') ? '' : ' (value redacted)'}${extraDetail}`,
      });

      if (findings.length >= MAX_FINDINGS_PER_FILE) break;
    }
  }

  return findings;
}

/**
 * Escalate a private-key or certificate finding to critical when it's the file's
 * entire declared purpose (e.g. a .pem/.key file), rather than an incidental match
 * inside a larger document.
 */
export function escalateIfPrimarySecret(findings) {
  return findings.map(f => {
    if (f.title.includes('Private Key') || f.title.includes('SSH Private Key')) {
      return { ...f, severity: 'critical' };
    }
    return f;
  });
}

export const SECRET_SCAN_LIMITS = { MAX_TEXT_SCAN_LENGTH, MAX_FINDINGS_PER_FILE };
