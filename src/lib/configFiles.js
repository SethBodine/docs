// ─── CONFIG / CLOUD-CREDENTIAL / CRYPTO-KEY FILE ANALYSER ──────────────────
// Covers: .env, .ini/.cfg/.conf/.config/.properties, .toml, .yaml/.yml,
// kubeconfig, docker config.json / docker-compose.yml, AWS/GCP/Azure
// credential files, Terraform (.tf/.tfvars/.tfstate), and PEM/key/cert/SSH
// key files. These are treated as first-class targets rather than an
// afterthought — they're statistically more likely to contain a live
// credential than a Word document is.

import { scanForSecrets, escalateIfPrimarySecret } from './secrets.js';

const TEXT_EXTS = ['env', 'ini', 'cfg', 'conf', 'config', 'properties', 'toml', 'yaml', 'yml', 'tf', 'tfvars', 'tfstate', 'json'];
const PEM_EXTS = ['pem', 'key', 'crt', 'cer', 'csr'];
const SSH_KEY_NAMES = ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys', 'known_hosts'];

function decode(arrayBuffer) {
  try { return new TextDecoder('utf-8', { fatal: false }).decode(arrayBuffer); }
  catch { return ''; }
}

// ─── Generic structured config (.env / .ini / .yaml / .toml / .tf / kubeconfig / docker) ─
export async function analyseConfigFile(arrayBuffer, filename) {
  const text = decode(arrayBuffer);
  const findings = scanForSecrets(text, filename);
  const metadata = { 'File Type': 'Configuration / environment file', 'Size': `${text.length} chars` };

  const lower = filename.toLowerCase();

  if (lower.includes('kubeconfig') || /\bclient-key-data\s*:|client-certificate-data\s*:/i.test(text)) {
    metadata['Detected Format'] = 'Kubernetes kubeconfig';
    if (/client-key-data\s*:\s*\S+/i.test(text)) {
      findings.push({ severity: 'critical', category: 'Cloud Credentials', title: 'Embedded Kubernetes client private key', detail: 'kubeconfig contains client-key-data — this grants cluster access equivalent to a password.' });
    }
    if (/token\s*:\s*\S+/i.test(text)) {
      findings.push({ severity: 'high', category: 'Cloud Credentials', title: 'Embedded Kubernetes bearer token', detail: 'kubeconfig contains a service-account/user token.' });
    }
  }

  if (lower.includes('docker') && (lower.endsWith('.json') || lower.includes('config'))) {
    if (/"auth"\s*:\s*"[A-Za-z0-9+/=]+"/i.test(text)) {
      findings.push({ severity: 'high', category: 'Cloud Credentials', title: 'Docker registry credential (base64 auth)', detail: 'docker config.json stores registry login as base64(user:pass) — trivially reversible.' });
    }
  }

  if (lower.endsWith('.tfstate')) {
    findings.push({ severity: 'medium', category: 'Infrastructure', title: 'Terraform state file', detail: 'Terraform state commonly embeds provider credentials, connection strings, and resource attributes in plaintext. Treat as sensitive infrastructure data regardless of scan findings.' });
  }

  // AWS credentials/config file format: [profile] blocks with aws_access_key_id / aws_secret_access_key
  if (/\[.*\]\s*\n[^[]*aws_access_key_id/i.test(text) || lower.includes('credentials') && /aws_secret_access_key/i.test(text)) {
    metadata['Detected Format'] = 'AWS CLI credentials/config file';
  }

  // GCP service account JSON
  if (/"type"\s*:\s*"service_account"/i.test(text)) {
    metadata['Detected Format'] = 'GCP service account key';
    findings.push({ severity: 'critical', category: 'Cloud Credentials', title: 'GCP service account key file', detail: 'Grants programmatic access to the associated GCP project at the permission level of the service account.' });
  }

  if (findings.length === 0) {
    findings.push({ severity: 'info', category: 'Format', title: 'No credentials detected', detail: `Scanned as a text configuration file (.${filename.split('.').pop()}).` });
  }

  return {
    findings,
    metadata,
    textContent: text.slice(0, 5000),
    externalLinks: [...text.matchAll(/https?:\/\/[^\s"'<>]{4,}/g)].map(m => ({ url: m[0], context: 'Config file' })).slice(0, 50),
    previewData: { type: 'xml', text: text.slice(0, 20000) }, // reuse the existing plain-text preview renderer
  };
}

// ─── PEM / key / certificate / SSH key files ────────────────────────────────
const PEM_BLOCK_RE = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;

function classifyPemBlock(label) {
  if (/PRIVATE KEY/.test(label)) {
    if (/RSA/.test(label)) return { kind: 'RSA private key', severity: 'critical' };
    if (/EC/.test(label)) return { kind: 'EC private key', severity: 'critical' };
    if (/OPENSSH/.test(label)) return { kind: 'OpenSSH private key', severity: 'critical' };
    if (/DSA/.test(label)) return { kind: 'DSA private key', severity: 'critical' };
    if (/ENCRYPTED/.test(label)) return { kind: 'Encrypted private key', severity: 'high' };
    return { kind: 'Private key', severity: 'critical' };
  }
  if (/CERTIFICATE REQUEST/.test(label)) return { kind: 'Certificate Signing Request', severity: 'low' };
  if (/CERTIFICATE/.test(label)) return { kind: 'Certificate', severity: 'info' };
  if (/PUBLIC KEY/.test(label)) return { kind: 'Public key', severity: 'info' };
  return { kind: label, severity: 'low' };
}

export async function analysePemOrKey(arrayBuffer, filename) {
  const text = decode(arrayBuffer);
  const findings = [];
  const metadata = {};

  const blocks = [...text.matchAll(PEM_BLOCK_RE)];
  if (blocks.length === 0) {
    // Not PEM text — could be a DER-encoded binary cert/key, or an SSH public key line
    if (/^ssh-(rsa|ed25519|ecdsa|dss)\s+[A-Za-z0-9+/=]+/m.test(text)) {
      findings.push({ severity: 'info', category: 'Cryptographic Material', title: 'SSH public key', detail: 'Public keys are safe to share — this is not a credential by itself.' });
    } else {
      findings.push({ severity: 'low', category: 'Format', title: 'Binary or unrecognised key/certificate format', detail: 'Could not find a PEM text block (-----BEGIN...-----). This may be a DER-encoded (binary) key or certificate — full X.509 field parsing is planned for a later phase.' });
    }
  } else {
    metadata['PEM Blocks Found'] = String(blocks.length);
    const kinds = [];
    for (const block of blocks) {
      const { kind, severity } = classifyPemBlock(block[1]);
      kinds.push(kind);
      findings.push({
        severity,
        category: 'Cryptographic Material',
        title: `${kind} present`,
        detail: severity === 'critical' || severity === 'high'
          ? 'This file contains private key material. Treat it exactly like a password — anyone with this file can impersonate the key holder.'
          : `${kind} block found in file.`,
      });
    }
    metadata['Contents'] = kinds.join(', ');
  }

  // Also run the generic secret scanner in case a private key is embedded
  // inside a larger file (e.g. an .env with an inlined PEM value).
  findings.push(...escalateIfPrimarySecret(scanForSecrets(text, filename)));

  return {
    findings,
    metadata,
    textContent: text.slice(0, 5000),
    externalLinks: [],
    previewData: { type: 'xml', text: text.slice(0, 20000) },
  };
}

export function isConfigExt(ext) { return TEXT_EXTS.includes(ext); }
export function isPemExt(ext) { return PEM_EXTS.includes(ext); }
export function isSshKeyFilename(name) {
  const base = name.split('/').pop().toLowerCase();
  return SSH_KEY_NAMES.includes(base) || base.endsWith('.pub');
}
