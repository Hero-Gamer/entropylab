// Differential fuzz of BIP32 derivation: src/js/hdkey.js (the app's HDKey,
// rust-bitcoin's bip32 compiled to WASM) against @scure/bip32 (pinned, an
// independent implementation). Same seed, same path, same version bytes —
// every node must be byte-identical on both sides, and any disagreement fails
// the run. Published BIP32 vectors stay in hdkey-bip39-wasm.test.mjs; this
// suite sweeps seeds and paths those vectors never reach.
//
// Offline and deterministic: the PRNG below exists only in this file, the
// seed is fixed, and it is never reseeded from the clock, so a red run
// reproduces byte-for-byte. The iteration number, seed, and path are in every
// failure message.
//
// Run with `node --test test/hdkey-differential-fuzz.test.mjs` or `npm test`.
// HDKEY_FUZZ_ITERATIONS=5000 widens a local run; CI runs the default.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { HDKey, HARDENED_OFFSET } from "../src/js/hdkey.js";

// --- deterministic randomness ------------------------------------------------

const FUZZ_SEED = 0x5eed0032;
const DEFAULT_ITERATIONS = 200;
const ITERATIONS = process.env.HDKEY_FUZZ_ITERATIONS === undefined ? DEFAULT_ITERATIONS : Number(process.env.HDKEY_FUZZ_ITERATIONS);
const mulberry32 = (seed) => {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};
const rand = mulberry32(FUZZ_SEED);
const rint = (n) => Math.floor(rand() * n);
const pick = (items) => items[rint(items.length)];
const randomBytes = (n) => Uint8Array.from({ length: n }, () => rint(256));
// Uniform over 0..2^31-1, with the boundaries forced in now and then.
const randomIndex = () => (rint(8) === 0 ? pick([0, 1, HARDENED_OFFSET - 1]) : rint(HARDENED_OFFSET));

// Mainnet BIP32 version bytes, passed explicitly to both implementations.
const VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const view = (node) => ({
  publicKey: hex(node.publicKey),
  chainCode: hex(node.chainCode),
  depth: node.depth,
  index: node.index,
  parentFingerprint: node.parentFingerprint,
  xpub: node.publicExtendedKey,
  xprv: node.privateExtendedKey,
});

// Field by field, so a failure names the field, the case, and both values.
const assertSameNode = (left, right, where) => {
  const a = view(left), b = view(right);
  for (const field of Object.keys(a)) {
    assert.equal(a[field], b[field], `${where}: ${field} differs\n  src/js/hdkey.js: ${a[field]}\n  @scure/bip32:    ${b[field]}`);
  }
};

// Runs the same operation on both sides. Every input here is valid, so a
// throw on either side is a disagreement too, reported with the other
// side's result.
const both = (where, leftFn, rightFn) => {
  const run = (fn) => {
    try {
      return { node: fn() };
    } catch (error) {
      return { error };
    }
  };
  const l = run(leftFn), r = run(rightFn);
  if (l.error || r.error) {
    const show = (side) => (side.error ? `threw ${side.error.message}` : JSON.stringify(view(side.node)));
    assert.fail(`${where}: only ${l.error && r.error ? "neither" : l.error ? "@scure/bip32" : "src/js/hdkey.js"} succeeded\n  src/js/hdkey.js: ${show(l)}\n  @scure/bip32:    ${show(r)}`);
  }
  assertSameNode(l.node, r.node, where);
  return [l.node, r.node];
};

test(`src/js/hdkey.js and @scure/bip32 derive identical nodes (seed 0x${FUZZ_SEED.toString(16)}, ${ITERATIONS} iterations)`, () => {
  assert.ok(Number.isSafeInteger(ITERATIONS) && ITERATIONS > 0, `HDKEY_FUZZ_ITERATIONS must be a positive integer, got ${process.env.HDKEY_FUZZ_ITERATIONS}`);
  let ran = 0;
  for (let i = 0; i < ITERATIONS; i++) {
    const seed = randomBytes(pick([16, 32, 64]));
    const steps = Array.from({ length: 1 + rint(8) }, () => ({ index: randomIndex(), hardened: rint(2) === 1 }));
    const path = "m/" + steps.map(({ index, hardened }) => `${index}${hardened ? "'" : ""}`).join("/");
    const where = `iteration ${i}, seed ${hex(seed)}, path ${path}`;

    const [left, right] = both(`${where}, master`, () => HDKey.fromMasterSeed(seed, VERSIONS), () => ScureHDKey.fromMasterSeed(seed, VERSIONS));

    // Step by step, so a disagreement names the first node where it appears.
    let l = left, r = right;
    steps.forEach(({ index, hardened }, depth) => {
      const child = index + (hardened ? HARDENED_OFFSET : 0);
      [l, r] = both(`${where}, step ${depth + 1} (child ${child})`, () => l.deriveChild(child), () => r.deriveChild(child));
    });

    // The whole path through each side's own path parser lands on the same node.
    const [leftChild, rightChild] = both(`${where}, derive(path)`, () => left.derive(path), () => right.derive(path));
    assertSameNode(leftChild, r, `${where}, derive(path) against the stepwise walk`);

    // The xprv round-trips through fromExtendedKey to the same child.
    const [leftRestored] = both(`${where}, fromExtendedKey(xprv)`,
      () => HDKey.fromExtendedKey(leftChild.privateExtendedKey, VERSIONS),
      () => ScureHDKey.fromExtendedKey(rightChild.privateExtendedKey, VERSIONS));
    assertSameNode(leftRestored, rightChild, `${where}, fromExtendedKey(xprv) against the derived child`);
    ran += 1;
  }
  assert.equal(ran, ITERATIONS, "every iteration ran to the end");
});
