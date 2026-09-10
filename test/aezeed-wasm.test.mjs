// Tests for the aezeed (LND cipher seed) WASM facade (src/js/aezeed.js),
// backed by the scrypt crate and the vendored AEZ v5 module in
// entropylab-wasm/. Run with `npm test`.
//
// Three layers of assurance:
//  1. LND's published version-0 vectors (lnd/aezeed/cipherseed_test.go at
//     commit 63bd8e7, MIT). Those vectors were generated with weakened
//     scrypt parameters (n=16, r=8, p=1), so they exercise the raw export
//     with log_n=4; the KDF parameters are caller-fixed for exactly this
//     reason.
//  2. A production-parameter (n=2^15) characterization vector published in
//     guggero/cryptography-toolkit (e2e/aezeed.spec.mjs, MIT), through the
//     production facade.
//  3. Differential scrypt checks against @noble/hashes (pinned dev
//     dependency), anchored by the RFC 7914 section 12 vectors.
import { test } from "node:test";
import assert from "node:assert/strict";
import { scrypt as nobleScrypt } from "@noble/hashes/scrypt.js";
import { aezeedDecode, aezeedWordsToBytes, AEZEED_DEFAULT_PASSPHRASE } from "../src/js/aezeed.js";
import { wordlist } from "../src/js/bip39-english.js";
import { heap, wasmExports, withInput } from "../src/js/entropylab-wasm.js";

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const textBytes = (text) => new TextEncoder().encode(text);

// CRC-32C (Castagnoli, reflected 0x82F63B78), for crafting taxonomy inputs.
const crc32c = (bytes) => {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (0x82f63b78 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
};

// Raw export call with caller-chosen scrypt parameters (the facade fixes
// LND's production log_n=15; the LND vectors need the weakened log_n=4).
const decipherRaw = (seed33, passphrase, logN) => {
  const pass = textBytes(passphrase);
  let body = null;
  const code = withInput(seed33, (seedPtr) =>
    withInput(pass, (passPtr) => {
      const wasm = wasmExports();
      const outPtr = wasm.el_alloc(19);
      try {
        const produced = wasm.el_aezeed_decipher(seedPtr, passPtr, pass.length, logN, 8, 1, outPtr);
        if (produced === 19) body = heap().slice(outPtr, outPtr + 19);
        return produced;
      } finally {
        wasm.el_free(outPtr, 19);
      }
    }));
  return { code, body };
};

// LND cipherseed_test.go vectors: entropy 81b637d86359e6960de795e41e0b4cfd,
// salt "salt1", internal version 0.
const LND_ENTROPY = "81b637d86359e6960de795e41e0b4cfd";
const LND_VECTORS = [
  {
    mnemonic:
      "ability liquid travel stem barely drastic pact cupboard apple thrive " +
      "morning oak feature tissue couch old math inform success suggest drink " +
      "motion know royal",
    passphrase: AEZEED_DEFAULT_PASSPHRASE,
    birthday: 0,
  },
  {
    mnemonic:
      "able tree stool crush transfer cloud cross three profit outside hen " +
      "citizen plate ride require leg siren drum success suggest drink " +
      "require fiscal upgrade",
    passphrase: "!very_safe_55345_password*",
    birthday: 3365,
  },
];

test("LND's published aezeed vectors decipher (weakened scrypt, log_n=4)", () => {
  for (const vector of LND_VECTORS) {
    const seed = aezeedWordsToBytes(vector.mnemonic.split(" "));
    const { code, body } = decipherRaw(seed, vector.passphrase, 4);
    assert.equal(code, 19, "the vector deciphers");
    assert.equal(body[0], 0, "internal version");
    assert.equal((body[1] << 8) | body[2], vector.birthday, "birthday");
    assert.equal(bytesToHex(body.slice(3)), LND_ENTROPY, "entropy");
  }
});

// The toolkit's fixed-input characterization vector uses LND's production
// parameters, so it goes through the real facade.
const GOLDEN_MNEMONIC =
  "ability result leisure oven shiver wedding toe broccoli exclude " +
  "mosquito kind van action waste merit bundle robust source able " +
  "advice core humor kitchen siren";

test("a production-parameter vector deciphers through the facade", () => {
  const decoded = aezeedDecode(GOLDEN_MNEMONIC.split(" "), "");
  assert.equal(decoded.internalVersion, 1);
  assert.equal(decoded.birthdayDays, 0);
  assert.equal(decoded.birthdayTimestamp, 1231006505, "birthday 0 is the genesis timestamp");
  assert.equal(bytesToHex(decoded.entropy), "000102030405060708090a0b0c0d0e0f");
  assert.equal(bytesToHex(decoded.salt), "0001020304");
});

test("the error taxonomy distinguishes words, checksum, version, and passphrase", () => {
  const words = GOLDEN_MNEMONIC.split(" ");

  // Wrong count and unknown words fail before any bytes exist.
  assert.throws(() => aezeedDecode(words.slice(0, 23), ""), (e) => e.code === "count");
  const misspelled = [...words];
  misspelled[3] = "ovenn";
  assert.throws(() => aezeedDecode(misspelled, ""), (e) => e.code === "word" && e.vars.n === 4);

  // A swapped word fails the CRC-32C before any KDF work happens. (Words 2
  // and 3, not 1 and 2: the version check reads byte 0, which the first
  // word's high bits fill, and like LND it runs before the checksum.)
  const swapped = [...words];
  [swapped[1], swapped[2]] = [swapped[2], swapped[1]];
  assert.throws(() => aezeedDecode(swapped, ""), (e) => e.code === "checksum");

  // A wrong passphrase passes the checksum but fails AEZ authentication.
  // (Raw call with log_n=4 to keep the failing scrypt runs cheap.)
  const lndSeed = aezeedWordsToBytes(LND_VECTORS[0].mnemonic.split(" "));
  assert.equal(decipherRaw(lndSeed, "wrong-passphrase", 4).code, -4);

  // A nonzero external version is rejected even with a valid checksum.
  const versioned = aezeedWordsToBytes(words);
  versioned[0] = 1;
  const crc = crc32c(versioned.subarray(0, 29));
  new DataView(versioned.buffer).setUint32(29, crc, false);
  assert.equal(decipherRaw(versioned, "", 4).code, -2);

  // And the facade maps the version code to its taxonomy: rebuild the words
  // for the re-versioned bytes and decode through the facade.
  const bits = [...versioned].map((b) => b.toString(2).padStart(8, "0")).join("");
  const versionedWords = bits.match(/.{11}/g).map((chunk) => wordlist[parseInt(chunk, 2)]);
  assert.throws(() => aezeedDecode(versionedWords, ""), (e) => e.code === "version" && e.vars.v === 1);
});

test("the 11-bit word packer round-trips the wordlist boundaries", () => {
  // Index 0 ("abandon") packs to all-zero bytes; index 2047 ("zoo") to all
  // ones. Both are closed-form, so this does not lean on the implementation.
  assert.deepEqual(aezeedWordsToBytes(Array(24).fill("abandon")), new Uint8Array(33));
  assert.deepEqual(aezeedWordsToBytes(Array(24).fill("zoo")), new Uint8Array(33).fill(0xff));
  // And a full round trip through the packer and back.
  const words = GOLDEN_MNEMONIC.split(" ");
  const bytes = aezeedWordsToBytes(words);
  const bits = [...bytes].map((b) => b.toString(2).padStart(8, "0")).join("");
  assert.deepEqual(bits.match(/.{11}/g).map((chunk) => wordlist[parseInt(chunk, 2)]), words);
});

// el_scrypt differential and published vectors. RFC 7914 section 12 lists
// scrypt("password", "NaCl", N=1024, r=8, p=16, 64) and scrypt("", "", N=16,
// r=1, p=1, 64); both must match, and @noble/hashes must agree on the aezeed
// parameter shapes.
const elScrypt = (pass, salt, logN, r, p, dkLen) => {
  const passBytes = textBytes(pass);
  const saltBytes = textBytes(salt);
  let out = null;
  const code = withInput(passBytes, (passPtr) =>
    withInput(saltBytes, (saltPtr) => {
      const wasm = wasmExports();
      const outPtr = wasm.el_alloc(dkLen);
      try {
        const produced = wasm.el_scrypt(passPtr, passBytes.length, saltPtr, saltBytes.length, logN, r, p, outPtr, dkLen);
        if (produced === dkLen) out = heap().slice(outPtr, outPtr + dkLen);
        return produced;
      } finally {
        wasm.el_free(outPtr, dkLen);
      }
    }));
  assert.equal(code, dkLen, "el_scrypt succeeds");
  return out;
};

test("el_scrypt matches the RFC 7914 vectors", () => {
  assert.equal(
    bytesToHex(elScrypt("", "", 4, 1, 1, 64)),
    "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442" +
      "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
  );
  assert.equal(
    bytesToHex(elScrypt("password", "NaCl", 10, 8, 16, 64)),
    "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162" +
      "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
  );
});

test("el_scrypt matches @noble/hashes on the aezeed parameter shape", () => {
  for (const [pass, salt, logN] of [
    ["aezeed", "salt1", 4],
    ["!very_safe_55345_password*", "salt1", 4],
    ["aezeed", " ", 15],
  ]) {
    const expected = nobleScrypt(textBytes(pass), textBytes(salt), { N: 2 ** logN, r: 8, p: 1, dkLen: 32 });
    assert.equal(bytesToHex(elScrypt(pass, salt, logN, 8, 1, 32)), bytesToHex(expected), `scrypt(${pass}, ${salt}, 2^${logN})`);
  }
});
