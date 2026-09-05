// Focused tests for the read-only UTXO verification labels in the PSBT
// flow visualizer. The verifier is intentionally a thin view over the
// inspector's already-decoded witness/non-witness UTXO fields.
import { test } from "node:test";
import assert from "node:assert/strict";
import { psbtVizHtml } from "../src/js/psbt-viz.js";

const doc = (pairs) => ({
  psbtVersion: 0,
  tx: {
    version: 2,
    locktime: 0,
    inputs: [{ txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 0 }],
    outputs: [{ value: "900", scriptPubKey: "6a00", asm: "OP_RETURN" }],
  },
  globals: [],
  inputs: [pairs],
  outputs: [[]],
  totalIn: null,
  totalOut: "900",
  fee: { known: false },
});

test("a matching non-witness UTXO is shown as verified", () => {
  const pairs = [{
    name: "PSBT_IN_NON_WITNESS_UTXO",
    decoded: {
      txid: "11".repeat(32),
      outputCount: 1,
      prevout: { vout: 0, value: "1000", scriptPubKey: "51" },
    },
  }];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("1000 sats"), "verified amount missing");
  assert.ok(html.includes("(verified)"), "matching non-witness claim was not marked verified");
  assert.ok(!html.includes("(unverified)"), "verified input was also marked unverified");
});

test("a witness-only UTXO is shown as an unverified claim", () => {
  const pairs = [{
    name: "PSBT_IN_WITNESS_UTXO",
    decoded: { value: "1000", scriptPubKey: "51" },
  }];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("1000 sats"), "witness claim amount missing");
  assert.ok(html.includes("(unverified)"), "witness-only claim was not marked unverified");
  assert.ok(!html.includes("(verified)"), "witness-only claim was incorrectly marked verified");
});

test("no usable UTXO declaration is unverified", () => {
  const html = psbtVizHtml(doc([]), "mainnet");
  assert.ok(html.includes("no amount claim"), "missing claim was not shown");
  assert.ok(html.includes("(unverified)"), "missing claim was not marked unverified");
});

test("a malformed non-witness declaration does not become verified", () => {
  const pairs = [{
    name: "PSBT_IN_NON_WITNESS_UTXO",
    decoded: null,
    decodeError: "non-witness utxo does not decode",
  }];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("no amount claim"), "malformed declaration should not supply an amount");
  assert.ok(html.includes("(unverified)"), "malformed declaration was incorrectly marked verified");
});

test("a non-witness declaration without a matched prevout is unverified", () => {
  const pairs = [{
    name: "PSBT_IN_NON_WITNESS_UTXO",
    decoded: { txid: "22".repeat(32), outputCount: 1 },
  }];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("no amount claim"), "unmatched non-witness declaration should not supply an amount");
  assert.ok(html.includes("(unverified)"), "unmatched non-witness declaration was incorrectly marked verified");
});

test("agreeing witness and non-witness claims are verified and do not conflict", () => {
  const pairs = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "1000", scriptPubKey: "51" } },
    { name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "1000", scriptPubKey: "51" } } },
  ];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("1000 sats"), "agreed amount missing");
  assert.ok(html.includes("(verified)"), "agreed non-witness claim was not marked verified");
  assert.ok(!html.includes("conflicting claims"), "agreeing claims incorrectly conflict");
});

test("disagreeing valid claims are a mismatch", () => {
  const pairs = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "5000", scriptPubKey: "51" } },
    { name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "1000", scriptPubKey: "51" } } },
  ];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("mismatch: conflicting claims: 5 000 vs 1 000 sats"), "valid disagreement was not marked mismatch");
});

test("verified status makes the script-comparison limitation explicit", () => {
  const pairs = [{
    name: "PSBT_IN_NON_WITNESS_UTXO",
    decoded: {
      txid: "11".repeat(32),
      outputCount: 1,
      prevout: { vout: 0, value: "1000", scriptPubKey: "51" },
    },
  }];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("scriptPubKey from the validated non-witness UTXO; witness script is not compared"), "verification limitation was not exposed in the UI");
});
