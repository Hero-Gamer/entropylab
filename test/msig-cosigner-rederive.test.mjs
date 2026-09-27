// MS Station co-signer path edits.
//
// Contract: a co-signer's extended public key is replaced on a path edit only
// when a loaded session root reproduces that exact key (public key and chain
// code) at the row's previous origin; the replacement is the root's key at the
// new origin, hardened steps included. A key no session root reproduces is
// never replaced. Each co-signer's purpose, coin-type and account steps carry
// their own hardening, while wrong indexes and a non-standard BIP48 script
// step are still refused.
//
// The reference for every derived key is @scure/bip32 (BIP32), independent of
// the app's own derivation.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadFunction(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `missing ${name}`);
  let depth = 0;
  // The body opens at ") {": a default parameter may itself hold braces.
  for (let i = app.indexOf(") {", start) + 2; i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}" && --depth === 0) return app.slice(start, i + 1);
  }
  throw new Error(`unterminated ${name}`);
}
const load = (name, deps = {}) => new Function(...Object.keys(deps), `${loadFunction(name)}; return ${name};`)(...Object.values(deps));

const codec = createBase58check(sha256);
const hodlBase58Check = { decode: codec.decode, encode: codec.encode };
const hodlExtendedKeyVersions = {
  mainnet: { x: { pub: 0x0488b21e, prv: 0x0488ade4 } },
  testnet: { x: { pub: 0x043587cf, prv: 0x04358394 } },
};
const hodlNote = (key, vars) => (vars == null ? { key } : { key, vars });
const hodlError = (key) => new Error(key);
const hodlEq = load("hodlEq");
const hodlNetworkFamily = load("hodlNetworkFamily");
const hodlReversionExtendedKey = load("hodlReversionExtendedKey", { hodlBase58Check });
const hodlSerializeExtendedKey = load("hodlSerializeExtendedKey", { hodlReversionExtendedKey, hodlExtendedKeyVersions, hodlNetworkFamily });
const hodlNormalizeOriginPath = load("hodlNormalizeOriginPath");
const hodlOriginScriptError = load("hodlOriginScriptError", { hodlNormalizeOriginPath, hodlNote });
const hodlMultisigAccountKeyError = load("hodlMultisigAccountKeyError", { hodlNote });
const hodlMultisigAccountNumber = load("hodlMultisigAccountNumber", { hodlNormalizeOriginPath, hodlError });
const hodlMsigOriginHardening = load("hodlMsigOriginHardening", { hodlNormalizeOriginPath });
const hodlMsigRederivedKey = load("hodlMsigRederivedKey", { hodlEq, hodlSerializeExtendedKey });

// BIP39 "abandon" x11 + "about"; master fingerprint 73c5da0a.
const seed = mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
const otherSeed = mnemonicToSeedSync("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
const reference = (path, s = seed) => HDKey.fromMasterSeed(s).derive(path);
const STANDARD = { purpose: true, coinType: true, account: true, script: true, branch: false, address: false };

test("a session root re-derives the co-signer key at an edited origin, hardened or not", () => {
  const current = reference("m/48'/0'/0'/2'");
  for (const next of ["m/48'/0'/1'/2'", "m/48'/0'/0/2'", "m/48/0/7/2'"]) {
    assert.equal(hodlMsigRederivedKey(HDKey.fromMasterSeed(seed), current, "m/48'/0'/0'/2'", next, "mainnet"), reference(next).publicExtendedKey, next);
  }
  const testnetCurrent = reference("m/87'/1'/0'");
  const tpub = hodlMsigRederivedKey(HDKey.fromMasterSeed(seed), testnetCurrent, "m/87'/1'/0'", "m/87'/1'/3", "testnet");
  assert.match(tpub, /^tpub/);
  assert.equal(HDKey.fromExtendedKey(tpub, { private: 0x04358394, public: 0x043587cf }).publicKey.toString(), reference("m/87'/1'/3").publicKey.toString());
});

test("a key the session root does not reproduce at the previous origin is never replaced", () => {
  const sessionRoot = () => HDKey.fromMasterSeed(seed);
  // A key from another seed.
  assert.equal(hodlMsigRederivedKey(sessionRoot(), reference("m/48'/0'/0'/2'", otherSeed), "m/48'/0'/0'/2'", "m/48'/0'/1'/2'", "mainnet"), "");
  // This seed's key, but claimed at a different origin than the one that made it.
  assert.equal(hodlMsigRederivedKey(sessionRoot(), reference("m/48'/0'/0'/2'"), "m/48'/0'/0'/1'", "m/48'/0'/1'/2'", "mainnet"), "");
  // The right public key with a foreign chain code.
  const real = reference("m/48'/0'/0'/2'"), forged = new HDKey({ publicKey: real.publicKey, chainCode: reference("m/48'/0'/1'/2'").chainCode });
  assert.equal(hodlMsigRederivedKey(sessionRoot(), forged, "m/48'/0'/0'/2'", "m/48'/0'/1'/2'", "mainnet"), "");
});

test("each co-signer origin carries its own purpose, coin-type and account hardening", () => {
  const accept = (path, kind, purpose, coinType = 0) => {
    const origin = { fingerprint: "73c5da0a", path }, hardening = hodlMsigOriginHardening(origin, STANDARD);
    assert.equal(hodlOriginScriptError(origin, kind, "mainnet", purpose, coinType, hardening), "", path);
    return hardening;
  };
  accept("48/0h/0h/2h", "p2wsh", 48);
  accept("48h/0/0h/1h", "p2sh-p2wsh", 48);
  let hardening = accept("48h/0h/5/2h", "p2wsh", 48);
  assert.equal(hodlMultisigAccountNumber({ path: "48h/0h/5/2h" }, "p2wsh", 48, hardening.account), 5);
  hardening = accept("87h/0h/3", "p2tr", 87);
  assert.equal(hodlMultisigAccountNumber({ path: "87h/0h/3" }, "p2tr", 87, hardening.account), 3);
  // The depth-3 account key itself is checked against the same hardening.
  const bip87 = HDKey.fromMasterSeed(seed).derive("m/87'/0'/3");
  assert.equal(hodlMultisigAccountKeyError({ depth: bip87.depth, childNumber: bip87.index }, "p2tr", 87, hardening), "");
  // BIP45's single purpose step.
  hardening = accept("45", "p2sh", 45);
  const bip45 = HDKey.fromMasterSeed(seed).derive("m/45");
  assert.equal(hodlMultisigAccountKeyError({ depth: bip45.depth, childNumber: bip45.index }, "p2sh", 45, hardening), "");
});

test("per-row hardening still refuses wrong indexes and a non-standard script step", () => {
  const refuse = (path, kind, purpose, coinType = 0) => {
    const origin = { fingerprint: "73c5da0a", path };
    assert.notEqual(hodlOriginScriptError(origin, kind, "mainnet", purpose, coinType, hodlMsigOriginHardening(origin, STANDARD)), "", path);
  };
  refuse("48h/0h/0h/2", "p2wsh", 48); // BIP48 script type is always hardened
  refuse("48h/0h/0h/1h", "p2wsh", 48); // wrong script type
  refuse("49h/0h/0h/2h", "p2wsh", 48); // wrong purpose
  refuse("48/1h/0h/2h", "p2wsh", 48); // wrong coin type
  refuse("87h/0h/3/0", "p2tr", 87); // too deep
  refuse("46", "p2sh", 45);
  // The BIP48 script-account key must still end at the hardened script child.
  const unhardenedScript = HDKey.fromMasterSeed(seed).derive("m/48'/0'/0'/2");
  const origin = { path: "48h/0h/0h/2" };
  assert.notEqual(hodlMultisigAccountKeyError({ depth: unhardenedScript.depth, childNumber: unhardenedScript.index }, "p2wsh", 48, hodlMsigOriginHardening(origin, STANDARD)), "");
});
