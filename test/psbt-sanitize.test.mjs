// Gap F: duplicate keys + origin derivation on PSBT inspect.
// Run with: node --test test/psbt-sanitize.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { psbtSanitizeHtml } from "../src/js/psbt-editor.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const fixture = (name) => {
  const hex = readFileSync(join(root, "test/fixtures/psbt/sanitize", name), "utf8").trim();
  return new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
};
const inspect = (name) => psbtInspectDoc(fixture(name));

const VALID_HEX =
  "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffff" +
  "ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40" +
  "bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000" +
  "0001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf133" +
  "6f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1" +
  "f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000";

test("inspect still exposes rustBitcoinError (exact JSON key)", () => {
  const doc = inspect("valid-minimal.hex");
  assert.ok("rustBitcoinError" in doc);
  assert.equal(doc.rustBitcoinError, null);
  assert.equal(doc.sanitize.duplicateKeys.state, "complete");
  assert.equal(doc.sanitize.xpubDerivesChild.state, "complete");
});

test("BIP-174 valid vector 2 stays green (no new families, no false positives)", () => {
  const doc = psbtInspectDoc(new Uint8Array(VALID_HEX.match(/.{2}/g).map((b) => parseInt(b, 16))));
  assert.equal(doc.rustBitcoinError, null);
  assert.equal(doc.sanitize.duplicateKeys.state, "complete");
  assert.equal(doc.sanitize.duplicateKeys.findings.length, 0);
  assert.equal(doc.sanitize.xpubDerivesChild.state, "complete");
});

test("1. duplicate_keys scans Vec pairs: Core #35665 A and B each pass", () => {
  const a = inspect("core-35665-a.hex");
  const b = inspect("core-35665-b.hex");
  assert.equal(a.sanitize.duplicateKeys.state, "complete");
  assert.equal(b.sanitize.duplicateKeys.state, "complete");
  assert.equal(a.rustBitcoinError, null);
  assert.equal(b.rustBitcoinError, null);
});

test("2. combined #35665 A+B is a duplicate PSBT_GLOBAL_XPUB key", () => {
  const doc = inspect("duplicate-global-xpub.hex");
  assert.equal(doc.sanitize.duplicateKeys.state, "problem");
  const hit = doc.sanitize.duplicateKeys.findings.find((f) => f.code === "duplicate_key");
  assert.ok(hit);
  assert.equal(hit.scope, "global");
  assert.equal(hit.name, "PSBT_GLOBAL_XPUB");
  assert.equal(hit.index, null);
  assert.match(hit.key, /^01/i);
  assert.equal(typeof doc.rustBitcoinError, "string");
});

test("3. Core #36025: two TAP_LEAF_SCRIPT with the same control block", () => {
  const doc = inspect("duplicate-tap-same-block.hex");
  assert.equal(doc.sanitize.duplicateKeys.state, "problem");
  const hit = doc.sanitize.duplicateKeys.findings[0];
  assert.equal(hit.name, "PSBT_IN_TAP_LEAF_SCRIPT");
  assert.equal(hit.scope, "input");
  assert.equal(hit.index, 0);
});

test("4. BIP-371: two control blocks, one script is not a duplicate", () => {
  const doc = inspect("valid-tap-two-blocks-one-script.hex");
  assert.equal(doc.sanitize.duplicateKeys.state, "complete");
  assert.equal(doc.sanitize.duplicateKeys.findings.length, 0);
});

test("5. xpub_derives_child: matching unhardened child passes", () => {
  const doc = inspect("origin-match.hex");
  assert.equal(doc.sanitize.xpubDerivesChild.state, "complete");
  assert.equal(doc.sanitize.xpubDerivesChild.findings.length, 0);
});

test("6. xpub_derives_child: path/key mismatch is a problem", () => {
  const doc = inspect("origin-mismatch.hex");
  assert.equal(doc.sanitize.xpubDerivesChild.state, "problem");
  const hit = doc.sanitize.xpubDerivesChild.findings[0];
  assert.equal(hit.code, "xpub_derives_child");
  assert.equal(hit.reason, "mismatch");
  assert.equal(hit.name, "PSBT_IN_BIP32_DERIVATION");
  assert.equal(hit.fingerprint.length, 8);
});

test("7. x-only (32-byte) tap derivation matches the compressed child", () => {
  const doc = inspect("origin-xonly.hex");
  assert.equal(doc.sanitize.xpubDerivesChild.state, "complete", JSON.stringify(doc.sanitize.xpubDerivesChild));
});

test("8. hardened remaining path is incomplete, not a mismatch", () => {
  const doc = inspect("origin-hardened-gap.hex");
  assert.equal(doc.sanitize.xpubDerivesChild.state, "incomplete");
  assert.equal(doc.sanitize.xpubDerivesChild.findings[0].reason, "hardened_gap");
});

test("9. derivation without an applicable global xpub is incomplete", () => {
  const doc = inspect("origin-no-xpub.hex");
  assert.equal(doc.sanitize.xpubDerivesChild.state, "incomplete");
  assert.equal(doc.sanitize.xpubDerivesChild.findings[0].reason, "no_applicable_xpub");
});

test("10. multi-account same fingerprint: applicable xpub is selected", () => {
  const doc = inspect("multi-account-same-fp.hex");
  assert.equal(doc.sanitize.duplicateKeys.state, "complete");
  assert.equal(doc.sanitize.xpubDerivesChild.state, "complete", JSON.stringify(doc.sanitize.xpubDerivesChild));
});

test("11. banner is three-state and not a safety verdict", () => {
  const complete = psbtSanitizeHtml(inspect("valid-minimal.hex"));
  assert.match(complete, /LISTED CHECKS COMPLETE/);
  assert.match(complete, /Not a safety verdict/);
  assert.doesNotMatch(complete, /safe to sign|hardware|brick/i);

  const problem = psbtSanitizeHtml(inspect("duplicate-global-xpub.hex"));
  assert.match(problem, /ISSUES FOUND/);
  assert.match(problem, /Problem found/);
  assert.match(problem, /PSBT_GLOBAL_XPUB/);

  const incomplete = psbtSanitizeHtml(inspect("origin-no-xpub.hex"));
  assert.match(incomplete, /ANALYSIS INCOMPLETE/);
  assert.match(incomplete, /Incomplete/);
});

test("12. editor inspect banner and compare footer are wired (source)", () => {
  const editor = readFileSync(join(root, "src/js/psbt-editor.js"), "utf8");
  assert.match(editor, /psbtSanitizeHtml\(doc\)/);
  assert.match(editor, /psbted-sanitize-compare/);
  assert.match(editor, /Editor PSBT/);
  assert.match(editor, /Pasted PSBT/);
  assert.match(editor, /rustBitcoinError/);
});

test("13. no new workspace tab; inspect-only files stay inspect-only", () => {
  const app = readFileSync(join(root, "src/js/app.js"), "utf8");
  assert.doesNotMatch(app, /sanitize-gapf|psbt-sanitize/);
  const shell = readFileSync(join(root, "src/shell.html"), "utf8");
  assert.doesNotMatch(shell, /id="psbt-sanitize"/);
  const b64 = readFileSync(join(root, "src/js/psbt-wasm-b64.js"), "utf8");
  assert.match(b64, /GENERATED FILE - do not edit/);
});

test("findings never include proprietary values", () => {
  const editor = readFileSync(join(root, "src/js/psbt-editor.js"), "utf8");
  assert.doesNotMatch(editor, /finding\.value/);
  const doc = inspect("duplicate-global-xpub.hex");
  for (const f of doc.sanitize.duplicateKeys.findings) {
    assert.equal("value" in f, false);
  }
});
