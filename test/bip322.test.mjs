import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyBip322 } from "../src/js/bip322.js";

const P2TR = "bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3";
const P2WPKH = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
const TAPROOT_SIGNATURE = "AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==";
const P2WPKH_SIGNATURE = "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";

const result = (message, address, signature) => verifyBip322(message, address, signature);

test("BIP-322 simple verifies a published P2TR vector", async () => {
  const verified = await result("Hello World", P2TR, TAPROOT_SIGNATURE);
  assert.equal(verified.state, "valid");
  assert.equal(verified.prefix, "smp");
  assert.equal(verified.challenge_type, "p2tr");
  assert.match(verified.message_hash, /^[0-9a-f]{64}$/);
});

test("canonical smp/ prefix verifies the same witness", async () => {
  const verified = await result("Hello World", P2TR, `smp/${TAPROOT_SIGNATURE}`);
  assert.equal(verified.state, "valid");
  assert.equal(verified.prefix, "smp");
});

test("legacy colon prefix is not accepted as a BIP-322 prefix", async () => {
  const verified = await result("Hello World", P2TR, `smp:${TAPROOT_SIGNATURE}`);
  assert.equal(verified.state, "invalid");
});

test("tampering with the message invalidates the witness", async () => {
  const verified = await result("Hello World!", P2TR, TAPROOT_SIGNATURE);
  assert.equal(verified.state, "invalid");
});

test("BIP-322 simple verifies a published P2WPKH vector", async () => {
  const verified = await result("Hello World", P2WPKH, P2WPKH_SIGNATURE);
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
