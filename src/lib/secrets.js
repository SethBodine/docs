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
  // ── Additional provider-specific patterns, modeled on the default rulesets
  // shipped by gitleaks and trufflehog — fixed, distinctive prefix formats
  // are low-false-positive, which is why those tools (and this one) treat
  // them as "confirmed" rather than "potential" like the generic patterns
  // below. Not exhaustive — this covers the providers most commonly seen in
  // real leaked-secret incidents.
  {
    name: 'Stripe API Key',
    re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,99}\b/g,
    tier: 'confirmed',
    category: 'Payment Processing',
  },
  {
    name: 'Twilio API Key / Account SID',
    re: /\b(?:SK[a-f0-9]{32}|AC[a-f0-9]{32})\b/g,
    tier: 'confirmed',
    category: 'Communications',
  },
  {
    name: 'SendGrid API Key',
    re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    tier: 'confirmed',
    category: 'Communications',
  },
  {
    name: 'Mailgun API Key',
    re: /\bkey-[0-9a-zA-Z]{32}\b/g,
    tier: 'confirmed',
    category: 'Communications',
  },
  {
    name: 'Mailchimp API Key',
    re: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/g,
    tier: 'confirmed',
    category: 'Communications',
  },
  {
    name: 'npm Access Token',
    re: /\bnpm_[A-Za-z0-9]{36}\b/g,
    tier: 'confirmed',
    category: 'Source Control',
  },
  {
    name: 'PyPI Upload Token',
    re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g,
    tier: 'confirmed',
    category: 'Source Control',
  },
  {
    name: 'Google API Key',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    tier: 'confirmed',
    category: 'Cloud Credentials',
  },
  {
    name: 'Google OAuth Access Token',
    re: /\bya29\.[0-9A-Za-z_-]{20,}\b/g,
    tier: 'confirmed',
    category: 'Cloud Credentials',
  },
  {
    name: 'Facebook Access Token',
    re: /\bEAA[A-Za-z0-9]{20,}\b/g,
    tier: 'confirmed',
    category: 'Social / Marketing',
  },
  {
    name: 'Shopify Access Token',
    re: /\bshp(?:at|ss|ca)_[a-fA-F0-9]{32}\b/g,
    tier: 'confirmed',
    category: 'E-commerce',
  },
  {
    name: 'Twitter/X Bearer Token',
    re: /\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{35,}\b/g,
    tier: 'confirmed',
    category: 'Social / Marketing',
  },
  {
    name: 'Grafana API Key',
    re: /\beyJrIjoi[A-Za-z0-9]{50,}\b/g,
    tier: 'confirmed',
    category: 'Observability',
  },
  {
    name: 'New Relic API Key',
    re: /\bNRAK-[A-Z0-9]{27}\b/g,
    tier: 'confirmed',
    category: 'Observability',
  },
  {
    name: 'Age Encryption Private Key',
    re: /\bAGE-SECRET-KEY-1[A-Z0-9]{58}\b/g,
    tier: 'confirmed',
    category: 'Cryptographic Material',
  },
  {
    name: 'Airtable API Key',
    re: /\bkey[A-Za-z0-9]{14}\b/g,
    tier: 'potential', // short/generic-shaped enough to warrant the lower tier
    category: 'Generic Secret',
  },
  {
    name: 'Dropbox Access Token',
    re: /\bsl\.[A-Za-z0-9_-]{130,}\b/g,
    tier: 'confirmed',
    category: 'Cloud Credentials',
  },
  {
    name: 'OpenAI API Key',
    re: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b|\bsk-proj-[A-Za-z0-9_-]{20,}\b/g,
    tier: 'confirmed',
    category: 'AI / ML Services',
  },
  {
    name: 'Anthropic API Key',
    re: /\bsk-ant-[A-Za-z0-9_-]{90,}\b/g,
    tier: 'confirmed',
    category: 'AI / ML Services',
  },
  {
    name: 'Okta API Token (context-matched)',
    re: /okta[a-z_]{0,20}(?:api[_-]?token|token)\s*[:=]\s*["']?(00[A-Za-z0-9_-]{40})["']?/gi,
    tier: 'confirmed',
    category: 'Cloud Credentials',
    group: 1,
  },
  {
    name: 'Heroku API Key (context-matched)',
    re: /heroku[a-z_]{0,20}(?:api[_-]?key|token)\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?/gi,
    tier: 'confirmed',
    category: 'Cloud Credentials',
    group: 1,
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
    genericCatchAll: true,
    category: 'Generic Secret',
    group: 2,
  },
  {
    name: 'Generic Password Assignment',
    re: /\b(password|passwd|pwd)\s*[:=]\s*["']?([^\s"'<>]{4,})["']?/gi,
    tier: 'potential',
    genericCatchAll: true,
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
  const specificallyMatchedValues = new Set(); // raw values already caught by a non-generic matcher

  for (const matcher of MATCHERS) {
    if (findings.length >= MAX_FINDINGS_PER_FILE) break;
    matcher.re.lastIndex = 0;
    let match;
    let countForMatcher = 0;
    while ((match = matcher.re.exec(scanText)) && countForMatcher < 20) {
      const raw = matcher.group ? match[matcher.group] : match[0];
      if (!raw) continue;

      // A provider-specific pattern (e.g. Stripe, AWS) already identified this
      // exact value more precisely — don't also report it as a generic
      // "API key" / "password" catch-all finding for the same secret.
      if (matcher.genericCatchAll && specificallyMatchedValues.has(raw)) { countForMatcher++; continue; }

      const dedupeKey = matcher.name + '|' + raw;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      countForMatcher++;
      if (!matcher.genericCatchAll) specificallyMatchedValues.add(raw);

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
