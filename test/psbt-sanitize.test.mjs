// Gap F: duplicate keys + origin derivation on PSBT inspect.
// Run with: node --test test/psbt-sanitize.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { psbtSanitizeHtml } from "../src/js/psbt-editor.js";
import { secp256k1 } from "../src/js/secp256k1.js";

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

test("14. malformed key shapes are incomplete, never a silent match", () => {
  const legacy = inspect("origin-malformed-legacy-key.hex");
  assert.equal(legacy.sanitize.xpubDerivesChild.state, "incomplete");
  assert.equal(legacy.sanitize.xpubDerivesChild.findings[0].reason, "malformed_key");
  assert.equal(typeof legacy.rustBitcoinError, "string");
  assert.match(psbtSanitizeHtml(legacy), /key is not valid for this record type/);

  const tap = inspect("origin-malformed-tap-key.hex");
  assert.equal(tap.sanitize.xpubDerivesChild.state, "incomplete");
  assert.equal(tap.sanitize.xpubDerivesChild.findings[0].reason, "malformed_key");
  assert.equal(typeof tap.rustBitcoinError, "string");
});

// Hostile-size PSBTs for the work-budget regressions, built in memory (too
// repetitive to store as .hex). Same BIP-32 test vector 2 chain as the
// fixtures above.
const B = (h) => Buffer.from(h, "hex");
const BXPUB_M = B(
  "0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
);
const BTX = B(
  "02000000" + "01" + "00".repeat(32) + "00000000" + "00" + "ffffffff" + "01" + "e803000000000000" + "0151" + "00000000",
);
const bCompact = (n) => {
  if (n < 0xfd) return Buffer.from([n]);
  const b = Buffer.alloc(3);
  b[0] = 0xfd;
  b.writeUInt16LE(n, 1);
  return b;
};
const bKv = (key, value) => Buffer.concat([bCompact(key.length), key, bCompact(value.length), value]);
const bLe32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0);
  return b;
};
const bBe32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
};
const bHash160 = (bytes) => createHash("ripemd160").update(createHash("sha256").update(bytes).digest()).digest();
const bCkdPub = (xpub, index) => {
  const I = createHmac("sha512", xpub.subarray(13, 45))
    .update(Buffer.concat([xpub.subarray(45, 78), bBe32(index)]))
    .digest();
  const childPub = secp256k1.Point.fromBytes(xpub.subarray(45, 78))
    .add(secp256k1.Point.BASE.multiply(BigInt("0x" + I.subarray(0, 32).toString("hex"))))
    .toBytes(true);
  const out = Buffer.alloc(78);
  B("0488b21e").copy(out, 0);
  out[4] = xpub[4] + 1;
  bHash160(xpub.subarray(45, 78)).subarray(0, 4).copy(out, 5);
  bBe32(index).copy(out, 9);
  I.subarray(32).copy(out, 13);
  Buffer.from(childPub).copy(out, 45);
  return out;
};
const bOriginMaster = Buffer.alloc(4);
const bOriginM0 = Buffer.concat([bOriginMaster, bLe32(0)]);
const bUnsigned = bKv(B("00"), BTX);
const bGXpub = bKv(Buffer.concat([B("01"), BXPUB_M]), bOriginMaster);
// A valid secp256k1 key that is not the m/0 child: the generator point.
const bWrongPub = Buffer.from(secp256k1.Point.BASE.toBytes(true));
const bBadDeriv = bKv(Buffer.concat([B("06"), bWrongPub]), bOriginM0);
const hostilePsbt = (xpubCount, derivCount, deriv = bBadDeriv) =>
  Buffer.concat([
    B("70736274ff"),
    bUnsigned,
    ...Array(xpubCount).fill(bGXpub),
    B("00"),
    ...Array(derivCount).fill(deriv),
    B("00"),
    B("00"),
  ]);

test("15. derivation work is budgeted; exhaustion degrades to incomplete", () => {
  // 25 matching derivations, each a 200-step unhardened suffix: 5000 CKD
  // steps, past the 4096 budget. The first 20 verify, the rest degrade the
  // family to incomplete with a budget_exhausted notice (no false mismatch).
  let x = BXPUB_M;
  for (let i = 0; i < 200; i++) x = bCkdPub(x, 0);
  const deepOrigin = Buffer.concat([bOriginMaster, ...Array(200).fill(bLe32(0))]);
  const deepDeriv = bKv(Buffer.concat([B("06"), Buffer.from(x.subarray(45, 78))]), deepOrigin);
  const doc = psbtInspectDoc(new Uint8Array(hostilePsbt(1, 25, deepDeriv)));
  assert.equal(doc.sanitize.xpubDerivesChild.state, "incomplete");
  const reasons = doc.sanitize.xpubDerivesChild.findings.map((f) => f.reason);
  assert.ok(reasons.includes("budget_exhausted"), JSON.stringify(reasons));
  assert.ok(!reasons.includes("mismatch"), JSON.stringify(reasons));
  assert.match(psbtSanitizeHtml(doc), /analysis budget exhausted/);
});

test("16. repeated xpub records dedup to one candidate (no quadratic blowup)", () => {
  // 500 identical xpub records x 500 identical mismatching derivations.
  // Unpatched this is 250k child derivations (~10 s); with dedup each
  // derivation checks one candidate and the verdict is a real mismatch —
  // anything else (timeout, incomplete, budget_exhausted) is a regression.
  const doc = psbtInspectDoc(new Uint8Array(hostilePsbt(500, 500)));
  assert.equal(doc.sanitize.xpubDerivesChild.state, "problem");
  assert.equal(doc.sanitize.xpubDerivesChild.findings[0].reason, "mismatch");
  assert.equal(doc.sanitize.duplicateKeys.state, "problem");
});

test("17. zero-length suffixes also cost budget (distinct xpub flood)", () => {
  // 3000 *distinct* xpubs all claiming the same master fingerprint with an
  // empty path, x 3000 derivations with an empty path: every candidate has a
  // zero-length suffix. Each candidate must still cost budget (the key
  // comparison is real work), so the flood degrades to incomplete instead of
  // running 9M EC key parses at zero charge.
  const xpubPairs = [];
  for (let i = 0; i < 3000; i++) {
    xpubPairs.push(bKv(Buffer.concat([B("01"), bCkdPub(BXPUB_M, i)]), bOriginMaster));
  }
  const deriv = bKv(Buffer.concat([B("06"), bWrongPub]), bOriginMaster);
  const bytes = Buffer.concat([
    B("70736274ff"),
    bUnsigned,
    ...xpubPairs,
    B("00"),
    ...Array(3000).fill(deriv),
    B("00"),
    B("00"),
  ]);
  const doc = psbtInspectDoc(new Uint8Array(bytes));
  // The first derivation legitimately checks all 3000 candidates and is a
  // genuine mismatch; the budget then stops the rest. problem dominates
  // incomplete per the three-state precedence — the regression signal is
  // that the budget fired at all instead of running 9M zero-cost parses.
  assert.equal(doc.sanitize.xpubDerivesChild.state, "problem");
  const reasons = doc.sanitize.xpubDerivesChild.findings.map((f) => f.reason);
  assert.ok(reasons.includes("mismatch"), JSON.stringify(reasons));
  assert.ok(reasons.includes("budget_exhausted"), JSON.stringify(reasons));
});

test("18. unknown family state degrades to incomplete, never success", () => {
  const html = psbtSanitizeHtml({
    sanitize: {
      duplicateKeys: { state: "unrecognized", findings: [] },
      xpubDerivesChild: { state: "complete", findings: [] },
    },
  });
  assert.match(html, /ANALYSIS INCOMPLETE/);
  assert.doesNotMatch(html, /LISTED CHECKS COMPLETE/);
});

test("findings never include proprietary values", () => {
  const editor = readFileSync(join(root, "src/js/psbt-editor.js"), "utf8");
  assert.doesNotMatch(editor, /finding\.value/);
  const doc = inspect("duplicate-global-xpub.hex");
  for (const f of doc.sanitize.duplicateKeys.findings) {
    assert.equal("value" in f, false);
  }
});
