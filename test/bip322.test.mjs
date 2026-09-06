import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyBip322 } from "../src/js/bip322.js";

const P2TR = "bc1pcquvhrqv0q68t4m0hfq6tpn006qrskyc7yrqnp2uyrf2emg3wynsdjyk38";
const P2TR_MESSAGE = "PURVOQ544B6HUATVBJZN5EZJUU";
const P2TR_SIGNATURE = "AUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8";

const P2WPKH = "bc1qqthe0hz8klx90e7stf6shclhsvqd5ly96pn53v";
const P2WPKH_MESSAGE = "2V6TUTMSH4VQ3Z7WZWKYD7DFNH";
const P2WPKH_SIGNATURE = "AkgwRQIhALC6hdfxNy1n45d7UXSskRBdfZW0Al259E1kDMpipdYkAiAJPfZqb+WurZuf1apU5xeE6Igui9dvt5tihQLDvxlY1AEhAqbnruyo677ktQjio7XOchO3w51Dh9AbRVngha5jtNfT";

const P2WSH = "bc1qw6g0rgrpuxvj4edkwtvzpmt3c5m08mhp8nuk3mrk4erufvlczp5ssdscjd";
const P2WSH_MESSAGE = "G7ZTXXOVJFHGDD6XYJAGBAMT5A";
const P2WSH_SIGNATURE = "BABIMEUCIQCKl1f9Cj26k0fFWE48+O4ibhYJYPytbDZWJRaaG9BybwIgCbk+3BViWkpuu2RI+41dwtlQ/m/01G860pTFCzDFfokBSDBFAiEA0O77DJsaM7IO+Ht06sp3umzXB64CNNOwf2isZuPfdmwCIGlggOwRSkXsqlPhE1gMdd5hf7ycL33Orfrr4v/XnMGSAUdSIQNsu/OwZurHvJMoiJoSAmmCHLoqIc5Wblh+rek+7rhASCECgYVkUspeAxwRfM6v4GRBhN/gGxTfpPqZuOlBIYZxTJZSrg==";

const FULL_ADDRESS = "bc1qrqtlzcq86850yzgsyq9sssawx2qxlx5yq3xpkd";
const FULL_MESSAGE = "KLE5MMJBTNF4AVZXIO3GIL5UWF";
const FULL_SIGNATURE = "AgAAAAABAUrfzHHOLAKmgCIFSTT3krp+cQxj1BDPBN4GBg3tRmFXAAAAAADgBwAAAQAAAAAAAAAAAWoCSDBFAiEAjYj85zyhQKa9DbMO0reDwdhkNwKJkF3q2qFcijXDgMUCIAaQ75s3fwqrCeYIUJugLvhxZFxQIVquGN90vIKCW3QLASEDMurnDzvc0zABUwVwCADfGXoDx/M3SQnYt7e3IHDoU3PgBwAA";
const FUTURE_VERSION_SIGNATURE = "AwAAAAABAUrfzHHOLAKmgCIFSTT3krp+cQxj1BDPBN4GBg3tRmFXAAAAAADgBwAAAQAAAAAAAAAAAWoCSDBFAiEAjYj85zyhQKa9DbMO0reDwdhkNwKJkF3q2qFcijXDgMUCIAaQ75s3fwqrCeYIUJugLvhxZFxQIVquGN90vIKCW3QLASEDMurnDzvc0zABUwVwC...";

const LEGACY_ADDRESS = "14vV3aCHBeStb5bkenkNHbe2YAFinYdXgc";
const LEGACY_MESSAGE = "Hello World";
const LEGACY_SIGNATURE = "IPg+QjkJZe3tgZttQ9tb8q3Me93e1VQbu2zYrYRjpWgFyxHArrut7BGI4yNvkywSXxs74wSG1zVF+qsYrj0iLy0=";

const result = (message, address, signature) => verifyBip322(message, address, signature);

test("BIP-322 simple verifies an official P2TR vector", async () => {
  const verified = await result(P2TR_MESSAGE, P2TR, P2TR_SIGNATURE);
  assert.equal(verified.state, "valid");
  assert.equal(verified.prefix, "smp");
  assert.equal(verified.challenge_type, "p2tr");
  assert.match(verified.message_hash, /^[0-9a-f]{64}$/);
});

test("canonical smp/ prefix verifies the same witness", async () => {
  const verified = await result(P2TR_MESSAGE, P2TR, `smp/${P2TR_SIGNATURE}`);
  assert.equal(verified.state, "valid");
  assert.equal(verified.prefix, "smp");
});

test("prefixless signature assumes simple variant", async () => {
  const verified = await result(P2TR_MESSAGE, P2TR, P2TR_SIGNATURE);
  assert.equal(verified.prefix, "smp");
});

test("legacy colon prefix is not accepted as a BIP-322 prefix", async () => {
  const verified = await result(P2TR_MESSAGE, P2TR, `smp:${P2TR_SIGNATURE}`);
  assert.equal(verified.state, "invalid");
});

test("malformed explicit prefix is rejected", async () => {
  const verified = await result(P2TR_MESSAGE, P2TR, `wat/${P2TR_SIGNATURE}`);
  assert.equal(verified.state, "invalid");
  assert.equal(verified.prefix, "unknown");
});

test("wrong address invalidates a valid witness", async () => {
  const verified = await result(P2TR_MESSAGE, "bc1p0v6x0v6x0v6x0v6x0v6x0v6x0v6x0v6x0v6x0v6x0v6x0v6x0", P2TR_SIGNATURE);
  assert.equal(verified.state, "invalid");
});

test("tampering with the message invalidates the witness", async () => {
  const verified = await result(`${P2TR_MESSAGE}!`, P2TR, P2TR_SIGNATURE);
  assert.equal(verified.state, "invalid");
});

test("BIP-322 simple verifies an official P2WPKH vector", async () => {
  const verified = await result(P2WPKH_MESSAGE, P2WPKH, P2WPKH_SIGNATURE);
  assert.equal(verified.state, "valid");
  assert.equal(verified.prefix, "smp");
  assert.equal(verified.challenge_type, "p2wpkh");
});

test("BIP-322 simple verifies an official P2WSH vector", async () => {
  const verified = await result(P2WSH_MESSAGE, P2WSH, P2WSH_SIGNATURE);
  assert.equal(verified.state, "valid");
  assert.equal(verified.prefix, "smp");
  assert.equal(verified.challenge_type, "p2wsh");
});

test("BIP-322 full verifies an official transaction vector", async () => {
  const verified = await result(FULL_MESSAGE, FULL_ADDRESS, `ful/${FULL_SIGNATURE}`);
  assert.equal(verified.state, "valid");
  assert.equal(verified.prefix, "ful");
  assert.equal(verified.challenge_type, "p2wpkh");
  assert.equal(verified.time_locks.active, false);
  assert.equal(verified.time_locks.T, 0);
  assert.equal(verified.time_locks.S, 0);
});

test("future full transaction version is inconclusive", async () => {
  const verified = await result(FULL_MESSAGE, FULL_ADDRESS, `ful/${FUTURE_VERSION_SIGNATURE}`);
  assert.equal(verified.state, "inconclusive");
  assert.equal(verified.prefix, "ful");
});

test("legacy BIP-137 P2PKH signature verifies only through prefixless fallback", async () => {
  const verified = await result(LEGACY_MESSAGE, LEGACY_ADDRESS, LEGACY_SIGNATURE);
  assert.equal(verified.state, "valid");
  assert.equal(verified.prefix, "legacy");
  assert.equal(verified.challenge_type, "p2pkh");
  assert.equal(verified.message_hash, null);
});

test("legacy signature cannot be forced through smp", async () => {
  const verified = await result(LEGACY_MESSAGE, LEGACY_ADDRESS, `smp/${LEGACY_SIGNATURE}`);
  assert.equal(verified.state, "invalid");
});

test("pof rejects a non-ASCII message before PSBT verification", async () => {
  const verified = await result("é", P2TR, "pof/not-a-psbt");
  assert.equal(verified.state, "invalid");
  assert.equal(verified.prefix, "pof");
  assert.match(verified.error, /ASCII/);
});

test("pof rejects malformed PSBT input", async () => {
  const verified = await result("proof", P2TR, "pof/not-a-psbt");
  assert.equal(verified.state, "invalid");
  assert.equal(verified.prefix, "pof");
});
