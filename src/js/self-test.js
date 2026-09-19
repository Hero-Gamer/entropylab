// Known-answer self-test: before boot wires a single input, run published
// test vectors through the same WebAssembly engine and JS glue the
// calculator uses, and refuse to start when this host computes any of them
// wrong. browser-check.js confirms the platform features exist (the
// WebAssembly check there only compiles an empty module); this confirms the
// host actually executes libsecp256k1, rust-bitcoin and rust-bip39 correctly.
// A miscompiling engine, a corrupted artifact, or a broken facade produces
// wrong keys silently; a fixed vector turns that into a visible failure.
//
// What this cannot catch: a targeted exploit that recognises these inputs,
// or a bug confined to inputs no vector exercises. It is a floor under the
// host, not a proof about it.
//
// Every expected value is a published vector (BIP32 test vector 1, the BIP39
// reference vectors, the BIP44/49/84/86 "abandon ... about" first receive
// addresses, the d = 1 "Satoshi Nakamoto" RFC 6979 signature), checked
// against @scure/bip32, @scure/bip39, @scure/btc-signer and @noble/curves in
// test/self-test-wasm.test.mjs. No randomness is generated or consumed.
import { entropyToMnemonic, mnemonicToSeedSync } from "./bip39.js";
import { HDKey } from "./hdkey.js";
import { addressFor } from "./addresses.js";
import { secp256k1 } from "./secp256k1.js";
import { hex } from "./coders.js";

const ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BIP32_V1_SEED = "000102030405060708090a0b0c0d0e0f";
const BIP32_V1_XPUB_M_0H_1_2H = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
// sha256("Satoshi Nakamoto"), signed with secret key 1.
const ECDSA_MSGHASH = "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e";
const ECDSA_SIG =
  "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8" +
  "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5";
const secretKeyOne = () => {
  const key = new Uint8Array(32);
  key[31] = 1;
  return key;
};

// The four address tests share one root so PBKDF2 runs once, not four times.
// It is a published test key, so holding it for the page's life is harmless.
let abandonRoot = null;
const firstReceive = (purpose, scriptType) => {
  if (!abandonRoot) abandonRoot = HDKey.fromMasterSeed(mnemonicToSeedSync(ABANDON));
  return addressFor(scriptType, abandonRoot.derive(`m/${purpose}'/0'/0'/0/0`).publicKey, "mainnet");
};

// Names are trusted literals: the failure screen renders them as markup.
export const SELF_TESTS = [
  {
    name: "BIP39 mnemonic encoding",
    expected: "legal winner thank year wave sausage worth useful legal winner thank yellow",
    run: () => entropyToMnemonic(hex.decode("7f".repeat(16))),
  },
  {
    name: "BIP39 seed (PBKDF2-HMAC-SHA512)",
    expected:
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553" +
      "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    run: () => hex.encode(mnemonicToSeedSync(ABANDON, "TREZOR")),
  },
  {
    name: "BIP32 private derivation",
    expected: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
    run: () => HDKey.fromMasterSeed(hex.decode(BIP32_V1_SEED)).derive("m/0'/1/2'/2/1000000000").privateExtendedKey,
  },
  {
    // Public-only (neutered) derivation from the published m/0'/1/2' xpub
    // must land on the same child as private derivation does.
    name: "BIP32 public derivation",
    expected: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
    run: () => HDKey.fromExtendedKey(BIP32_V1_XPUB_M_0H_1_2H).derive("m/2/1000000000").publicExtendedKey,
  },
  { name: "P2PKH address (BIP44)", expected: "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", run: () => firstReceive(44, "p2pkh") },
  { name: "P2SH-P2WPKH address (BIP49)", expected: "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", run: () => firstReceive(49, "p2sh-p2wpkh") },
  { name: "P2WPKH address (BIP84)", expected: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", run: () => firstReceive(84, "p2wpkh") },
  { name: "P2TR address (BIP86)", expected: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", run: () => firstReceive(86, "p2tr") },
  {
    name: "ECDSA signing (RFC 6979)",
    expected: ECDSA_SIG,
    run: () => hex.encode(secp256k1.sign(hex.decode(ECDSA_MSGHASH), secretKeyOne(), { prehash: false, extraEntropy: false })),
  },
  {
    // Fail-open is the dangerous direction: a verifier that accepts anything
    // would report forged signatures as valid. Require both answers.
    name: "ECDSA verification",
    expected: "valid:true tampered:false",
    run: () => {
      const pubkey = secp256k1.getPublicKey(secretKeyOne(), true);
      const msghash = hex.decode(ECDSA_MSGHASH);
      const tampered = hex.decode(ECDSA_SIG);
      tampered[63] ^= 1;
      const valid = secp256k1.verify(hex.decode(ECDSA_SIG), msghash, pubkey, { prehash: false });
      const forged = secp256k1.verify(tampered, msghash, pubkey, { prehash: false });
      return `valid:${valid} tampered:${forged}`;
    },
  },
];

// Returns the names of the tests this host fails. A test passes only when
// it returns exactly its expected string; a throw, a missing or empty
// expectation, or any other value is a failure, so a malformed entry can
// never pass by comparing undefined to undefined.
export const runSelfTests = (tests = SELF_TESTS) => {
  const failed = [];
  for (const { name, expected, run } of tests) {
    let ok = false;
    try {
      ok = typeof expected === "string" && expected !== "" && run() === expected;
    } catch {
      ok = false;
    }
    if (!ok) failed.push(name);
  }
  return failed;
};

// The boot gate: records the outcome on <html> (data-self-tests /
// data-self-tests-failed, alongside browser-check.js's barrage counters) so
// tests and support can confirm it ran, then hands any failures to `onFail`
// and returns false so the caller never boots. Returns true when every test
// passed.
export const selfTestGate = (root, onFail, tests = SELF_TESTS) => {
  const failed = runSelfTests(tests);
  if (root) {
    root.dataset.selfTests = String(tests.length);
    root.dataset.selfTestsFailed = String(failed.length);
  }
  if (failed.length === 0) return true;
  onFail(failed);
  return false;
};
