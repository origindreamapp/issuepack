import { createHmac, randomBytes } from "node:crypto";

export type RedactionKind =
  | "ANTHROPIC_API_KEY"
  | "AWS_ACCESS_KEY"
  | "BEARER_TOKEN"
  | "CREDENTIAL"
  | "EMAIL"
  | "GITLAB_TOKEN"
  | "GITHUB_TOKEN"
  | "GOOGLE_API_KEY"
  | "HUGGINGFACE_TOKEN"
  | "IP_ADDRESS"
  | "JWT"
  | "MAC_ADDRESS"
  | "NPM_TOKEN"
  | "OPENAI_API_KEY"
  | "PATH_USER"
  | "PRIVATE_KEY"
  | "SESSION_HEADER"
  | "SENDGRID_API_KEY"
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
const NON_SECRET_SENTINELS = new Set([
  "",
  "false",
  "none",
  "null",
  "redacted",
  "true",
  "undefined",
]);

export function fingerprintValue(value: string, salt: string): string {
  return createHmac("sha256", salt)
    .update(value)
    .digest("hex")
    .slice(0, 12);
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
  if (NON_SECRET_SENTINELS.has(value.trim().toLowerCase())) {
    return value;
  }

  const digest = fingerprintValue(value, salt);
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

function privateKeyLabel(line: string): string | undefined {
  const prefix = "-----BEGIN ";
  const suffix = "-----";
  if (!line.startsWith(prefix) || !line.endsWith(suffix)) {
    return undefined;
  }

  const label = line.slice(prefix.length, -suffix.length);
  if (label.length > 64) {
    return undefined;
  }
  const words = label.split(" ");
  if (
    words.length < 2 ||
    words.length > 6 ||
    words.at(-2) !== "PRIVATE" ||
    words.at(-1) !== "KEY"
  ) {
    return undefined;
  }
  for (const word of words) {
    if (!word) {
      return undefined;
    }
    for (const character of word) {
      const code = character.charCodeAt(0);
      const isUppercaseLetter = code >= 65 && code <= 90;
      const isDigit = code >= 48 && code <= 57;
      if (!isUppercaseLetter && !isDigit) {
        return undefined;
      }
    }
  }
  return label;
}

function redactPrivateKeyBlocks(
  input: string,
  findings: RedactionFinding[],
  salt: string,
): string {
  let output = "";
  let outputCursor = 0;
  let lineStart = 0;
  let openBlock: { label: string; start: number } | undefined;

  while (lineStart <= input.length) {
    let lineEnd = lineStart;
    while (
      lineEnd < input.length &&
      input[lineEnd] !== "\n" &&
      input[lineEnd] !== "\r"
    ) {
      lineEnd += 1;
    }
    let separatorLength = 0;
    if (lineEnd < input.length) {
      separatorLength =
        input[lineEnd] === "\r" && input[lineEnd + 1] === "\n" ? 2 : 1;
    }

    const line = input.slice(lineStart, lineEnd);
    const label = privateKeyLabel(line);
    if (label !== undefined) {
      openBlock = { label, start: lineStart };
    } else if (openBlock && line === `-----END ${openBlock.label}-----`) {
      const block = input.slice(openBlock.start, lineEnd);
      output += input.slice(outputCursor, openBlock.start);
      output += placeholder("PRIVATE_KEY", block, findings, salt);
      outputCursor = lineEnd;
      openBlock = undefined;
    }

    if (separatorLength === 0) {
      break;
    }
    lineStart = lineEnd + separatorLength;
  }

  return output + input.slice(outputCursor);
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

  text = redactPrivateKeyBlocks(text, findings, salt);

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
    /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}\b/g,
    "ANTHROPIC_API_KEY",
    findings,
    salt,
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
    /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    "GITLAB_TOKEN",
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
    /\bhf_[A-Za-z0-9]{20,}\b/g,
    "HUGGINGFACE_TOKEN",
    findings,
    salt,
  );
  text = replaceWhole(
    text,
    /\bnpm_[A-Za-z0-9]{20,}\b/g,
    "NPM_TOKEN",
    findings,
    salt,
  );
  text = replaceWhole(
    text,
    /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
    "SENDGRID_API_KEY",
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
    "api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?token|token|password|passwd|secret|client[_-]?secret|aws[_-]?secret[_-]?access[_-]?key|account[_-]?key|connection[_-]?string";
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
