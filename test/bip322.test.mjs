import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyBip322 } from "../src/js/bip322.js";

const P2TR = "bc1pcquvhrqv0q68t4m0hfq6tpn006qrskyc7yrqnp2uyrf2emg3wynsdjyk38";
const P2TR_MESSAGE = "PURVOQ544B6HUATVBJZN5EZJUU";
const P2TR_SIGNATURE = "AUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8";

const P2WPKH = "bc1qqthe0hz8klx90e7stf6shclhsvqd5ly96pn53v";
const P2WPKH_MESSAGE = "2V6TUTMSH4VQ3Z7WZWKYD7DFNH";
const P2WPKH_SIGNATURE = "AkgwRQIhALC6hdfxNy1n45d7UXSskRBdfZW0Al259E1kDMpipdYkAiAJPfZqb+WurZuf1apU5xeE6Igui9dvt5tihQLDvxlY1AEhAqbnruyo677ktQjio7XOchO3w51Dh9AbRVngha5jtNfT";

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

test("legacy colon prefix is not accepted as a BIP-322 prefix", async () => {
  const verified = await result(P2TR_MESSAGE, P2TR, `smp:${P2TR_SIGNATURE}`);
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

test("pof rejects a non-ASCII message before PSBT verification", async () => {
  const verified = await result("é", P2TR, "pof/not-a-psbt");
  assert.equal(verified.state, "invalid");
  assert.equal(verified.prefix, "pof");
  assert.match(verified.error, /ASCII/);
});
