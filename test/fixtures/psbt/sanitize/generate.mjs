// Deterministic PSBT v0 sanitize fixtures. Run with:
//   node test/fixtures/psbt/sanitize/generate.mjs
// Rewrites the sibling .hex files. Keys are BIP-32 test vector 2 (master
// xpub at m, unhardened children at m/0 and m/1). Nothing here is random.
import { writeFileSync } from "node:fs";
import { createHmac, createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 } from "../../../../src/js/secp256k1.js";

const dir = dirname(fileURLToPath(import.meta.url));
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const unhex = (h) => Buffer.from(h, "hex");
const concat = (...parts) => Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : unhex(p))));
const compact = (n) => {
  if (n < 0xfd) return Buffer.from([n]);
  throw new Error("fixture pair too large for one-byte compact size");
};
const kv = (key, value) => concat(compact(key.length), key, compact(value.length), value);
const le32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0);
  return b;
};
const be32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
};

const hash160 = (bytes) => createHash("ripemd160").update(createHash("sha256").update(bytes).digest()).digest();

// BIP-32 test vector 2, chain m (78-byte xpub payload).
const XPUB_M = unhex(
  "0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
);

const ckdPub = (xpub, index) => {
  if (index >= 0x80000000) throw new Error("hardened");
  const chain = xpub.subarray(13, 45);
  const parentPub = xpub.subarray(45, 78);
  const data = concat(parentPub, be32(index));
  const I = createHmac("sha512", chain).update(data).digest();
  const IL = I.subarray(0, 32);
  const IR = I.subarray(32);
  const childPub = secp256k1.Point.fromBytes(parentPub)
    .add(secp256k1.Point.BASE.multiply(BigInt("0x" + hex(IL))))
    .toBytes(true);
  const out = Buffer.alloc(78);
  unhex("0488b21e").copy(out, 0);
  out[4] = xpub[4] + 1;
  hash160(parentPub).subarray(0, 4).copy(out, 5);
  be32(index).copy(out, 9);
  IR.copy(out, 13);
  Buffer.from(childPub).copy(out, 45);
  return out;
};

const xpubM = XPUB_M;
const xpubM0 = ckdPub(xpubM, 0);
const xpubM1 = ckdPub(xpubM, 1);
const pubM = xpubM.subarray(45, 78);
const pubM0 = xpubM0.subarray(45, 78);
const pubM1 = xpubM1.subarray(45, 78);
const xonlyM0 = pubM0.subarray(1);

// Tiny v0 unsigned tx: version 2, 1 input, 1 OP_TRUE output of 1000 sats.
const TX = unhex(
  "02000000" +
    "01" +
    "0000000000000000000000000000000000000000000000000000000000000000" +
    "00000000" +
    "00" +
    "ffffffff" +
    "01" +
    "e803000000000000" +
    "0151" +
    "00000000",
);

const psbt = (globalPairs, inputPairs, outputPairs) =>
  concat("70736274ff", ...globalPairs, "00", ...inputPairs, "00", ...outputPairs, "00");

const unsigned = kv(unhex("00"), TX);
const originMaster = Buffer.alloc(4); // fingerprint 00000000, empty path
const originM0 = concat(originMaster, le32(0));
const originM1 = concat(originMaster, le32(1));
const originM0h = concat(originMaster, le32(0x80000000)); // m/0'

const globalXpub = (xpub, origin) => kv(concat("01", xpub), origin);
const inBip32 = (pubkey, origin) => kv(concat("06", pubkey), origin);
const inTapBip32 = (xonly, origin) => kv(concat("16", xonly), concat("00", origin)); // zero leaf hashes
const tapLeaf = (controlBlock, script, leafVersion = 0xc0) =>
  kv(concat("15", controlBlock), concat(script, Buffer.from([leafVersion])));

const CB1 = unhex("c0" + "11".repeat(32));
const CB2 = unhex("c0" + "22".repeat(32));
const SCRIPT = unhex("51"); // OP_TRUE

const files = {
  "valid-minimal.hex": psbt([unsigned], [], []),
  // Core #35665 reproduction: same xpub key, two origin values. Each half is
  // a valid single-xpub PSBT; concatenated keys are a duplicate.
  "core-35665-a.hex": psbt([unsigned, globalXpub(xpubM0, originM0)], [], []),
  "core-35665-b.hex": psbt([unsigned, globalXpub(xpubM0, originM1)], [], []),
  "duplicate-global-xpub.hex": psbt(
    [unsigned, globalXpub(xpubM0, originM0), globalXpub(xpubM0, originM1)],
    [],
    [],
  ),
  // Core #36025: TAP_LEAF_SCRIPT is keyed by the control block. Same block
  // twice is a duplicate key even if the scripts differ.
  "duplicate-tap-same-block.hex": psbt(
    [unsigned],
    [tapLeaf(CB1, SCRIPT, 0xc0), tapLeaf(CB1, unhex("52"), 0xc0)],
    [],
  ),
  // BIP-371: two control blocks are two keys, even with the same script.
  "valid-tap-two-blocks-one-script.hex": psbt(
    [unsigned],
    [tapLeaf(CB1, SCRIPT), tapLeaf(CB2, SCRIPT)],
    [],
  ),
  "origin-match.hex": psbt(
    [unsigned, globalXpub(xpubM, originMaster)],
    [inBip32(pubM0, originM0)],
    [],
  ),
  "origin-mismatch.hex": psbt(
    [unsigned, globalXpub(xpubM, originMaster)],
    [inBip32(pubM1, originM0)], // path says m/0, key is m/1
    [],
  ),
  "origin-xonly.hex": psbt(
    [unsigned, globalXpub(xpubM, originMaster)],
    [inTapBip32(xonlyM0, originM0)],
    [],
  ),
  "origin-hardened-gap.hex": psbt(
    [unsigned, globalXpub(xpubM, originMaster)],
    [inBip32(pubM0, originM0h)],
    [],
  ),
  "origin-no-xpub.hex": psbt([unsigned], [inBip32(pubM0, originM0)], []),
  // Two xpubs, same master fingerprint, different paths. Child m/0 must
  // select the m/0 xpub and not treat the sibling as a collision.
  "multi-account-same-fp.hex": psbt(
    [unsigned, globalXpub(xpubM0, originM0), globalXpub(xpubM1, originM1)],
    [inBip32(pubM0, originM0)],
    [],
  ),
};

for (const [name, bytes] of Object.entries(files)) {
  writeFileSync(join(dir, name), hex(bytes) + "\n");
}

export const vectors = { pubM: hex(pubM), pubM0: hex(pubM0), pubM1: hex(pubM1), xonlyM0: hex(xonlyM0) };
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.stdout.write(`wrote ${Object.keys(files).length} sanitize fixtures\n`);
}
