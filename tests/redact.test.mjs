import assert from "node:assert/strict";
import test from "node:test";
import { countFindings, redactText } from "../dist/index.js";

test("redacts common credentials without exposing the original values", () => {
  const input = [
    "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    "github=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
    "Authorization: Bearer header.payload.signature-token",
    '"password": "correct-horse-battery-staple"',
    "database=postgres://admin:very-secret@db.example.test/app",
  ].join("\n");

  const result = redactText(input);

  assert.doesNotMatch(result.text, /correct-horse|very-secret|ghp_|sk-proj-/);
  assert.match(result.text, /\[REDACTED:OPENAI_API_KEY:/);
  assert.match(result.text, /\[REDACTED:GITHUB_TOKEN:/);
  assert.match(result.text, /\[REDACTED:SESSION_HEADER:/);
  assert.match(result.text, /\[REDACTED:CREDENTIAL:/);
  assert.match(result.text, /\[REDACTED:URL_CREDENTIALS:/);
});

test("uses stable placeholders so repeated values remain correlatable", () => {
  const result = redactText("email=user@example.com\nowner=user@example.com");
  const placeholders = result.text.match(/\[REDACTED:EMAIL:[a-f0-9]{12}\]/g);

  assert.equal(placeholders?.length, 2);
  assert.equal(placeholders?.[0], placeholders?.[1]);
});

test("classifies common provider tokens without exposing them", () => {
  const input = [
    "anthropic=sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456",
    "gitlab=glpat-abcdefghijklmnopqrstuvwxyz123456",
    "huggingface=hf_abcdefghijklmnopqrstuvwxyz123456",
    "npm=npm_abcdefghijklmnopqrstuvwxyz123456",
    "sendgrid=SG.abcdefghijklmnop.qrstuvwxyzABCDEFGH",
  ].join("\n");

  const result = redactText(input, { fingerprintSalt: "providers" });
  const counts = countFindings(result.findings);

  assert.equal(counts.ANTHROPIC_API_KEY, 1);
  assert.equal(counts.GITLAB_TOKEN, 1);
  assert.equal(counts.HUGGINGFACE_TOKEN, 1);
  assert.equal(counts.NPM_TOKEN, 1);
  assert.equal(counts.SENDGRID_API_KEY, 1);
  assert.equal(counts.OPENAI_API_KEY, undefined);
  assert.doesNotMatch(result.text, /sk-ant-|glpat-|hf_|npm_|SG\./);
});

test("redacts multi-word private key labels", () => {
  const input = [
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "c3ludGhldGljLWtleS1tYXRlcmlhbA==",
    "-----END ENCRYPTED PRIVATE KEY-----",
  ].join("\n");

  const result = redactText(input, { fingerprintSalt: "private-key" });

  assert.match(result.text, /\[REDACTED:PRIVATE_KEY:[a-f0-9]{12}\]/);
  assert.doesNotMatch(result.text, /c3ludGhldGlj/);
});

test("does not flag common empty-value sentinels", () => {
  const input = "token=null\npassword=false\nsecret=redacted\napi_key=undefined";
  const result = redactText(input, { fingerprintSalt: "sentinels" });

  assert.equal(result.text, input);
  assert.deepEqual(result.findings, []);
});

test("uses different fingerprints for different bundle salts", () => {
  const first = redactText("user@example.com", { fingerprintSalt: "bundle-one" });
  const second = redactText("user@example.com", { fingerprintSalt: "bundle-two" });

  assert.notEqual(first.text, second.text);
});

test("redaction is idempotent", () => {
  const once = redactText('token="secret-value" and admin@example.com');
  const twice = redactText(once.text);

  assert.equal(twice.text, once.text);
  assert.equal(twice.findings.length, 0);
});

test("redacts paths, network identifiers, and private keys", () => {
  const input = [
    "C:\\Users\\alice\\work\\app.log",
    "/home/bob/work/app.log",
    "host=192.168.1.23 mac=AA:BB:CC:DD:EE:FF",
    "-----BEGIN PRIVATE KEY-----",
    "ZmFrZS1rZXktbWF0ZXJpYWw=",
    "-----END PRIVATE KEY-----",
  ].join("\n");

  const result = redactText(input);
  const counts = countFindings(result.findings);

  assert.equal(counts.PATH_USER, 2);
  assert.equal(counts.IP_ADDRESS, 1);
  assert.equal(counts.MAC_ADDRESS, 1);
  assert.equal(counts.PRIVATE_KEY, 1);
  assert.doesNotMatch(result.text, /alice|bob|192\.168\.1\.23|AA:BB/);
});

test("leaves ordinary diagnostic text unchanged", () => {
  const input = "Node 24.4.1\nTests: 42 passed\nDuration: 1.25s";
  const result = redactText(input);

  assert.equal(result.text, input);
  assert.deepEqual(result.findings, []);
});
