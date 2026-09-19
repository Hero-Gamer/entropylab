// Tests for src/js/self-test.js, the known-answer self-test app boot runs
// before wiring any input. Four things are proven here:
//   1. The shipped WebAssembly engine passes every vector.
//   2. Every expected value is independent of that engine: each one is
//      recomputed with @scure/bip32, @scure/bip39, @scure/btc-signer and
//      @noble/curves (pinned devDependencies), so a vector cannot have been
//      copied from the output it is meant to check.
//   3. No test can pass vacuously: each fails when its expectation moves, when
//      it throws, and when its expectation is missing or empty; and injected
//      engine faults (a fail-open verifier, a wrong child derivation) are
//      caught by exactly the tests that cover them.
//   4. The boot gate records its outcome and refuses to boot on any failure.
// Named *-wasm so the build-wasm gate also runs it against a fresh crate build.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { HDKey as ScureHDKey } from "@scure/bip32";
import * as scureBip39 from "@scure/bip39";
import { wordlist as scureEnglish } from "@scure/bip39/wordlists/english.js";
import * as btc from "@scure/btc-signer";
import { secp256k1 as nobleSecp } from "@noble/curves/secp256k1.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { wasmReady } from "../src/js/entropylab-wasm.js";
import { HDKey } from "../src/js/hdkey.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { SELF_TESTS, runSelfTests, selfTestGate } from "../src/js/self-test.js";

await wasmReady;

const ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const byName = (name) => {
  const found = SELF_TESTS.find((entry) => entry.name === name);
  assert.ok(found, `self-test "${name}" exists`);
  return found;
};
// Moves an expectation by one character, so the comparison, not the
// computation, is what gets exercised.
const shifted = (value) => value.slice(0, -1) + (value.endsWith("0") ? "1" : "0");

test("every self-test has a unique name and a non-empty expected string", () => {
  assert.ok(SELF_TESTS.length >= 10, `expected the vector barrage, found ${SELF_TESTS.length}`);
  const names = SELF_TESTS.map((entry) => entry.name);
  assert.equal(new Set(names).size, names.length, "self-test names must be unique");
  for (const { name, expected, run } of SELF_TESTS) {
    assert.ok(typeof name === "string" && name.length > 0, "every self-test is named");
    // Names are rendered as markup on the failure screen; keep them inert.
    assert.doesNotMatch(name, /[<>&"']/, `${name}: names must carry no markup characters`);
    assert.ok(typeof expected === "string" && expected.length > 0, `${name}: expected must be a non-empty string`);
    assert.equal(typeof run, "function", `${name}: run must be a function`);
  }
});

test("the shipped WebAssembly engine passes every published vector", () => {
  assert.deepEqual(runSelfTests(), []);
});

test("every expected value matches an independent implementation", () => {
  const expected = (name) => byName(name).expected;
  assert.equal(expected("BIP39 mnemonic encoding"), scureBip39.entropyToMnemonic(hexToBytes("7f".repeat(16)), scureEnglish));
  assert.equal(expected("BIP39 seed (PBKDF2-HMAC-SHA512)"), bytesToHex(scureBip39.mnemonicToSeedSync(ABANDON, "TREZOR")));
  const v1 = ScureHDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f"));
  assert.equal(expected("BIP32 private derivation"), v1.derive("m/0'/1/2'/2/1000000000").privateExtendedKey);
  const neutered = ScureHDKey.fromExtendedKey(v1.derive("m/0'/1/2'").publicExtendedKey).derive("m/2/1000000000");
  assert.equal(expected("BIP32 public derivation"), neutered.publicExtendedKey);
  const root = ScureHDKey.fromMasterSeed(scureBip39.mnemonicToSeedSync(ABANDON));
  const pub = (purpose) => root.derive(`m/${purpose}'/0'/0'/0/0`).publicKey;
  assert.equal(expected("P2PKH address (BIP44)"), btc.p2pkh(pub(44)).address);
  assert.equal(expected("P2SH-P2WPKH address (BIP49)"), btc.p2sh(btc.p2wpkh(pub(49))).address);
  assert.equal(expected("P2WPKH address (BIP84)"), btc.p2wpkh(pub(84)).address);
  assert.equal(expected("P2TR address (BIP86)"), btc.p2tr(pub(86).slice(1)).address);
  const one = new Uint8Array(32);
  one[31] = 1;
  const msghash = nobleSha256(utf8ToBytes("Satoshi Nakamoto"));
  const signature = nobleSecp.sign(msghash, one, { prehash: false, extraEntropy: false });
  assert.equal(expected("ECDSA signing (RFC 6979)"), bytesToHex(signature));
  assert.equal(expected("ECDSA verification"), "valid:true tampered:false");
});

test("every self-test fails when its expectation moves", () => {
  for (const entry of SELF_TESTS) {
    assert.deepEqual(runSelfTests([{ ...entry, expected: shifted(entry.expected) }]), [entry.name], `${entry.name} passed a wrong expectation`);
  }
});

test("a throwing, unexpected, or expectation-less test is a failure", () => {
  const run = () => "same";
  assert.deepEqual(runSelfTests([{ name: "throws", expected: "x", run: () => { throw new Error("engine fault"); } }]), ["throws"]);
  assert.deepEqual(runSelfTests([{ name: "missing expectation", run: () => undefined }]), ["missing expectation"]);
  assert.deepEqual(runSelfTests([{ name: "empty expectation", expected: "", run: () => "" }]), ["empty expectation"]);
  assert.deepEqual(runSelfTests([{ name: "non-string", expected: 1, run: () => 1 }]), ["non-string"]);
  // Control: the same shape with a real expectation passes.
  assert.deepEqual(runSelfTests([{ name: "control", expected: "same", run }]), []);
});

test("a fail-open or fail-closed verifier is caught", () => {
  const real = secp256k1.verify;
  try {
    secp256k1.verify = () => true; // accepts forged signatures
    assert.deepEqual(runSelfTests(), ["ECDSA verification"]);
    secp256k1.verify = () => false; // rejects everything
    assert.deepEqual(runSelfTests(), ["ECDSA verification"]);
  } finally {
    secp256k1.verify = real;
  }
  assert.deepEqual(runSelfTests(), [], "restoring the verifier restores a clean run");
});

test("a wrong child derivation is caught by exactly the tests that derive", () => {
  const real = HDKey.prototype.derive;
  try {
    // Off by one on the last path element: the kind of silent miscomputation
    // that produces a valid-looking but wrong key.
    HDKey.prototype.derive = function (path) {
      return real.call(this, path.replace(/(\d+)('?)$/, (_, index, hardened) => `${Number(index) + 1}${hardened}`));
    };
    assert.deepEqual(runSelfTests(), [
      "BIP32 private derivation",
      "BIP32 public derivation",
      "P2PKH address (BIP44)",
      "P2SH-P2WPKH address (BIP49)",
      "P2WPKH address (BIP84)",
      "P2TR address (BIP86)",
    ]);
  } finally {
    HDKey.prototype.derive = real;
  }
  assert.deepEqual(runSelfTests(), [], "restoring derivation restores a clean run");
});

test("the boot gate records a clean run and lets boot proceed", () => {
  const root = { dataset: {} };
  const reported = [];
  assert.equal(selfTestGate(root, (failed) => reported.push(failed)), true);
  assert.deepEqual(reported, []);
  assert.equal(root.dataset.selfTests, String(SELF_TESTS.length));
  assert.equal(root.dataset.selfTestsFailed, "0");
});

test("the boot gate reports failures and refuses to boot", () => {
  const root = { dataset: {} };
  const reported = [];
  const broken = SELF_TESTS.map((entry, index) => (index === 1 ? { ...entry, expected: shifted(entry.expected) } : entry));
  assert.equal(selfTestGate(root, (failed) => reported.push(failed), broken), false);
  assert.deepEqual(reported, [[SELF_TESTS[1].name]], "onFail receives exactly the failed names, once");
  assert.equal(root.dataset.selfTests, String(SELF_TESTS.length));
  assert.equal(root.dataset.selfTestsFailed, "1");
  // No <html> (a host broken enough to lose it) still refuses to boot.
  assert.equal(selfTestGate(null, () => {}, broken), false);
});

test("the module never talks to the network, browser storage, or a CSPRNG", () => {
  const src = readFileSync(new URL("../src/js/self-test.js", import.meta.url), "utf8");
  assert.doesNotMatch(src, /\bfetch\s*\(/);
  assert.doesNotMatch(src, /\bWebSocket\b/);
  assert.doesNotMatch(src, /\blocalStorage\b/);
  assert.doesNotMatch(src, /\bsessionStorage\b/);
  assert.doesNotMatch(src, /\bindexedDB\b/);
  assert.doesNotMatch(src, /\bgetRandomValues\b/);
  assert.doesNotMatch(src, /\bMath\.random\b/);
});
