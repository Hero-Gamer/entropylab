// aezeed (LND cipher seed) decoding for EntropyLab, backed by the scrypt and
// vendored AEZ v5 code in the entropylab-wasm crate (loaded by
// entropylab-wasm.js).
//
// aezeed is LND's 24-word seed scheme. It shares only the English wordlist
// with BIP39: the words decode (11 bits per word, big-endian bitstream) to
// 33 bytes laid out as version(1) || AEZ ciphertext(23) || salt(5) ||
// CRC-32C(4), and the ciphertext deciphers under an
// scrypt(passphrase, salt, N=2^15, r=8, p=1) key to internal version(1) ||
// birthday(2, big-endian days since the Bitcoin genesis block) ||
// entropy(16). LND feeds that entropy directly to BIP32 as the master seed.
// Unlike BIP39, a wrong passphrase is detected (AEZ authentication fails)
// instead of silently deriving an empty wallet.
//
// Decoding only: this module never creates seeds.
import { heap, wasmExports as wasm, wasmReady, withInput } from "./entropylab-wasm.js";
import { wordlist as bip39English } from "./bip39-english.js";

export const aezeedReady = wasmReady;

export const AEZEED_WORD_COUNT = 24;
export const AEZEED_DEFAULT_PASSPHRASE = "aezeed";
export const BITCOIN_GENESIS_TIMESTAMP = 1231006505;
const ENCIPHERED_LENGTH = 33;
const PLAINTEXT_LENGTH = 19;
// LND's production KDF parameters (aezeed/cipherseed.go).
const SCRYPT_LOG_N = 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

const textEncoder = new TextEncoder();

let wordIndexCache = null;
const wordIndex = () => {
  if (!wordIndexCache) wordIndexCache = new Map(bip39English.map((word, index) => [word, index]));
  return wordIndexCache;
};

// Errors carry a translatable spec (.key/.vars, picked up by the app's
// hodlErrorSpecFrom) plus a stable .code for tests: "count" | "word" |
// "version" | "checksum" | "passphrase".
const fail = (code, key, vars) => {
  const error = new Error(key);
  error.code = code;
  error.key = key;
  if (vars) error.vars = vars;
  return error;
};

// 24 aezeed words to their 33-byte encoding. `words` is an array of
// lowercase words (the caller normalizes whitespace and case).
export const aezeedWordsToBytes = (words) => {
  if (!Array.isArray(words) || words.length !== AEZEED_WORD_COUNT) {
    throw fail("count", "An aezeed cipher seed is exactly 24 words. You entered {n}.", { n: Array.isArray(words) ? words.length : 0 });
  }
  const index = wordIndex();
  const bytes = new Uint8Array(ENCIPHERED_LENGTH);
  let bit = 0;
  for (let n = 0; n < words.length; n++) {
    const value = index.get(words[n]);
    if (value === undefined) {
      throw fail("word", "Word {n} (“{word}”) is not on the BIP39 English list.", { n: n + 1, word: words[n] });
    }
    for (let i = 10; i >= 0; i--) {
      if ((value >> i) & 1) bytes[bit >> 3] |= 0x80 >> (bit & 7);
      bit++;
    }
  }
  return bytes;
};

// Deciphers an aezeed mnemonic. Returns { internalVersion, birthdayDays,
// birthdayTimestamp, entropy, salt } with entropy/salt as Uint8Array copies
// the caller owns (and should wipe). Throws the taxonomy above on bad words,
// an unsupported version, a checksum mismatch (mistyped words), or an AEZ
// authentication failure (wrong passphrase).
export const aezeedDecode = (words, passphrase = "") => {
  const seed = aezeedWordsToBytes(words);
  // LND substitutes the literal string "aezeed" for an empty passphrase.
  const pass = textEncoder.encode(passphrase === "" ? AEZEED_DEFAULT_PASSPHRASE : passphrase);
  let body = null;
  try {
    // The output buffer is hand-rolled (not withOutput) so the negative
    // error codes stay distinguishable instead of collapsing to null.
    const code = withInput(seed, (seedPtr) =>
      withInput(pass, (passPtr) => {
        const w = wasm();
        const outPtr = w.el_alloc(PLAINTEXT_LENGTH);
        try {
          const produced = w.el_aezeed_decipher(seedPtr, passPtr, pass.length, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, outPtr);
          if (produced === PLAINTEXT_LENGTH) body = heap().slice(outPtr, outPtr + PLAINTEXT_LENGTH);
          return produced;
        } finally {
          w.el_free(outPtr, PLAINTEXT_LENGTH);
        }
      }));
    if (code === -2) {
      throw fail("version", "Unsupported cipher seed version {v}. This tool understands aezeed version 0.", { v: seed[0] });
    }
    if (code === -3) {
      throw fail("checksum", "The cipher seed checksum does not match. A word is likely mistyped, missing, or swapped.");
    }
    if (code === -4) {
      throw fail("passphrase", "Deciphering failed: the aezeed passphrase is wrong.");
    }
    if (code !== PLAINTEXT_LENGTH || !body) throw new Error("aezeed decipher failed.");
    const birthdayDays = (body[1] << 8) | body[2];
    return {
      internalVersion: body[0],
      birthdayDays,
      birthdayTimestamp: BITCOIN_GENESIS_TIMESTAMP + birthdayDays * 86400,
      entropy: body.slice(3),
      salt: seed.slice(24, 29),
    };
  } finally {
    if (body) body.fill(0); // carries the wallet's master entropy
    seed.fill(0);
    pass.fill(0);
  }
};
