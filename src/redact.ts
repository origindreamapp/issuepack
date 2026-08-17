import { createHash, randomBytes } from "node:crypto";

export type RedactionKind =
  | "AWS_ACCESS_KEY"
  | "BEARER_TOKEN"
  | "CREDENTIAL"
  | "EMAIL"
  | "GITHUB_TOKEN"
  | "GOOGLE_API_KEY"
  | "IP_ADDRESS"
  | "JWT"
  | "MAC_ADDRESS"
  | "OPENAI_API_KEY"
  | "PATH_USER"
  | "PRIVATE_KEY"
  | "SESSION_HEADER"
  | "SLACK_TOKEN"
  | "URL_CREDENTIALS";

export interface RedactionFinding {
  kind: RedactionKind;
  fingerprint: string;
}

export interface RedactionResult {
  text: string;
  findings: RedactionFinding[];
}

export interface RedactionOptions {
  fingerprintSalt?: string;
}

export type RedactionCounts = Partial<Record<RedactionKind, number>>;

const REDACTED_PREFIX = "[REDACTED:";

function fingerprint(value: string, salt: string): string {
  return createHash("sha256")
    .update(salt)
    .update("\0")
    .update(value)
    .digest("hex")
    .slice(0, 10);
}

function placeholder(
  kind: RedactionKind,
  value: string,
  findings: RedactionFinding[],
  salt: string,
): string {
  if (value.includes(REDACTED_PREFIX)) {
    return value;
  }

  const digest = fingerprint(value, salt);
  findings.push({ kind, fingerprint: digest });
  return `[REDACTED:${kind}:${digest}]`;
}

function replaceWhole(
  text: string,
  pattern: RegExp,
  kind: RedactionKind,
  findings: RedactionFinding[],
  salt: string,
): string {
  return text.replace(pattern, (match) => placeholder(kind, match, findings, salt));
}

export function countFindings(findings: RedactionFinding[]): RedactionCounts {
  const counts: RedactionCounts = {};

  for (const finding of findings) {
    counts[finding.kind] = (counts[finding.kind] ?? 0) + 1;
  }

  return counts;
}

export function mergeCounts(...groups: RedactionCounts[]): RedactionCounts {
  const merged: RedactionCounts = {};

  for (const group of groups) {
    for (const [kind, count] of Object.entries(group)) {
      const redactionKind = kind as RedactionKind;
      merged[redactionKind] = (merged[redactionKind] ?? 0) + (count ?? 0);
    }
  }

  return merged;
}

export function redactText(
  input: string,
  options: RedactionOptions = {},
): RedactionResult {
  const findings: RedactionFinding[] = [];
  const salt = options.fingerprintSalt ?? randomBytes(32).toString("hex");
  let text = input;

  text = replaceWhole(
    text,
    /-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----/g,
    "PRIVATE_KEY",
    findings,
    salt,
  );

  text = text.replace(
    /(\bauthorization\s*:\s*)([^\r\n]+)/gi,
    (_match, prefix: string, value: string) =>
      `${prefix}${placeholder("SESSION_HEADER", value, findings, salt)}`,
  );
  text = text.replace(
    /(\b(?:cookie|set-cookie)\s*:\s*)([^\r\n]+)/gi,
    (_match, prefix: string, value: string) =>
      `${prefix}${placeholder("SESSION_HEADER", value, findings, salt)}`,
  );
  text = text.replace(
    /\bBearer\s+([A-Za-z0-9._~+/=-]{8,})/gi,
    (_match, value: string) =>
      `Bearer ${placeholder("BEARER_TOKEN", value, findings, salt)}`,
  );

  text = replaceWhole(
    text,
    /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}\b/g,
    "OPENAI_API_KEY",
    findings,
    salt,
  );
  text = replaceWhole(
    text,
    /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    "GITHUB_TOKEN",
    findings,
    salt,
  );
  text = replaceWhole(
    text,
    /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    "AWS_ACCESS_KEY",
    findings,
    salt,
  );
  text = replaceWhole(
    text,
    /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    "SLACK_TOKEN",
    findings,
    salt,
  );
  text = replaceWhole(
    text,
    /\bAIza[0-9A-Za-z_-]{20,}\b/g,
    "GOOGLE_API_KEY",
    findings,
    salt,
  );
  text = replaceWhole(
    text,
    /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
    "JWT",
    findings,
    salt,
  );

  text = text.replace(
    /(\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/)([^@\s/]+)(@)/gi,
    (_match, prefix: string, value: string, suffix: string) =>
      `${prefix}${placeholder("URL_CREDENTIALS", value, findings, salt)}${suffix}`,
  );

  const credentialNames =
    "api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|client[_-]?secret";
  const quotedCredential = new RegExp(
    `((?:["']?)(?:${credentialNames})(?:["']?)\\s*[:=]\\s*)(["'])([^\\r\\n]*?)\\2`,
    "gi",
  );
  text = text.replace(
    quotedCredential,
    (_match, prefix: string, quote: string, value: string) =>
      `${prefix}${quote}${placeholder("CREDENTIAL", value, findings, salt)}${quote}`,
  );

  const unquotedCredential = new RegExp(
    `(\\b(?:${credentialNames})\\b\\s*[:=]\\s*)([^\\s,;}\\]]+)`,
    "gi",
  );
  text = text.replace(
    unquotedCredential,
    (_match, prefix: string, value: string) =>
      `${prefix}${placeholder("CREDENTIAL", value, findings, salt)}`,
  );

  text = text.replace(
    /([A-Za-z]:\\Users\\)([^\\/\s]+)/g,
    (_match, prefix: string, value: string) =>
      `${prefix}${placeholder("PATH_USER", value, findings, salt)}`,
  );
  text = text.replace(
    /(\/(?:home|Users)\/)([^/\s]+)/g,
    (_match, prefix: string, value: string) =>
      `${prefix}${placeholder("PATH_USER", value, findings, salt)}`,
  );

  text = replaceWhole(
    text,
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    "EMAIL",
    findings,
    salt,
  );
  text = replaceWhole(
    text,
    /\b(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\b/gi,
    "MAC_ADDRESS",
    findings,
    salt,
  );
  text = text.replace(
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    (match) => {
      const valid = match.split(".").every((part) => Number(part) <= 255);
      return valid ? placeholder("IP_ADDRESS", match, findings, salt) : match;
    },
  );

  return { text, findings };
}
