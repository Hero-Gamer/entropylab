import { test } from "node:test";
import assert from "node:assert/strict";
import { psbtCostFacts, psbtCostFactsFromDoc } from "../src/js/psbt-cost.js";
import { psbtVizHtml } from "../src/js/psbt-viz.js";

const witnessUtxo = (value) => ({
  name: "PSBT_IN_WITNESS_UTXO",
  value: "",
  decoded: { value: String(value), scriptPubKey: "0014" + "11".repeat(20) },
});

const finalWitness = () => ({
  name: "PSBT_IN_FINAL_SCRIPTWITNESS",
  value: "",
  decoded: { items: ["00".repeat(71), "02" + "22".repeat(32)] },
});

const doc = ({ finalized = true, secondInputAmount = 100000000n } = {}) => ({
  psbtVersion: 0,
  tx: {
    version: 2,
    locktime: 0,
    inputs: [
      { txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 0xffffffff },
      { txid: "22".repeat(32), vout: 1, scriptSig: "", sequence: 0xffffffff },
    ],
    outputs: [
      { value: "90000000", scriptPubKey: "0014" + "33".repeat(20) },
      { value: "99950000", scriptPubKey: "0014" + "44".repeat(20) },
    ],
  },
  globals: [],
  inputs: [
    finalized ? [witnessUtxo(100000000), finalWitness()] : [witnessUtxo(100000000)],
    finalized ? [witnessUtxo(secondInputAmount), finalWitness()] : [witnessUtxo(secondInputAmount)],
  ],
  outputs: [[], []],
  totalIn: "200000000",
  totalOut: "189950000",
  fee: { known: true, sats: "10050000" },
});

// BIP-174 valid vector 2. It has one finalized legacy input and one
// non-finalized nested-SegWit input, so exact final size is intentionally
// unavailable while the claimed fee is already unknown because input 0 has no
// UTXO amount claim.
const VALID_HEX =
  "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffff" +
  "ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40" +
  "bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000" +
  "0001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf133" +
  "6f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1" +
  "f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000";
const VALID = new Uint8Array(VALID_HEX.match(/.{2}/g).map((b) => parseInt(b, 16)));

test("finalized SegWit PSBT exposes exact fee, weight, vsize, and fee rate", () => {
  const facts = psbtCostFactsFromDoc(doc());
  assert.deepEqual(facts, {
    inputCount: 2,
    outputCount: 2,
    inputAmountSats: "200000000",
    outputAmountSats: "189950000",
    feeSats: "10050000",
    finalized: true,
    weight: 828,
    vsize: 207,
    feeRateSatPerVbyte: 48550.72463768116,
  });
});

test("incomplete PSBT never reports guessed exact weight or vsize", () => {
  const facts = psbtCostFactsFromDoc(doc({ finalized: false }));
  assert.equal(facts.inputAmountSats, "200000000");
  assert.equal(facts.outputAmountSats, "189950000");
  assert.equal(facts.feeSats, "10050000");
  assert.equal(facts.finalized, false);
  assert.equal(facts.weight, null);
  assert.equal(facts.vsize, null);
  assert.equal(facts.feeRateSatPerVbyte, null);
});

test("conflicting input amount declarations make the fee unknown", () => {
  const value = witnessUtxo(100000000);
  const conflicting = {
    name: "PSBT_IN_NON_WITNESS_UTXO",
    decoded: { prevout: { value: "90000000" } },
  };
  const fixture = doc();
  fixture.inputs[0] = [value, conflicting, finalWitness()];
  const facts = psbtCostFactsFromDoc(fixture);
  assert.equal(facts.inputAmountSats, null);
  assert.equal(facts.feeSats, null);
  assert.equal(facts.finalized, true);
  assert.equal(facts.weight, 828);
});

test("missing input amount leaves fee unknown but still permits exact finalized size", () => {
  const fixture = doc();
  fixture.inputs[1] = [finalWitness()];
  const facts = psbtCostFactsFromDoc(fixture);
  assert.equal(facts.inputAmountSats, null);
  assert.equal(facts.feeSats, null);
  assert.equal(facts.finalized, true);
  assert.equal(facts.weight, 828);
  assert.equal(facts.vsize, 207);
});

test("legacy final scriptSig is included in exact transaction size", () => {
  const fixture = doc();
  fixture.inputs[0] = [witnessUtxo(100000000), {
    name: "PSBT_IN_FINAL_SCRIPTSIG",
    value: "76a914" + "55".repeat(20) + "88ac",
  }];
  fixture.inputs[1] = [witnessUtxo(100000000), {
    name: "PSBT_IN_FINAL_SCRIPTSIG",
    value: "76a914" + "66".repeat(20) + "88ac",
  }];
  const facts = psbtCostFactsFromDoc(fixture);
  assert.equal(facts.finalized, true);
  assert.equal(facts.weight, 816);
  assert.equal(facts.vsize, 204);
});

test("raw PSBT path uses the real rust-bitcoin inspection document", () => {
  const facts = psbtCostFacts(VALID);
  assert.equal(facts.inputCount, 2);
  assert.equal(facts.outputCount, 2);
  assert.equal(facts.inputAmountSats, null);
  assert.equal(facts.outputAmountSats, "199909358");
  assert.equal(facts.feeSats, null);
  assert.equal(facts.finalized, false);
  assert.equal(facts.weight, null);
  assert.equal(facts.vsize, null);
  assert.equal(facts.feeRateSatPerVbyte, null);
});

test("PSBT visualizer exposes exact size when the transaction is finalized", () => {
  const html = psbtVizHtml(doc(), "mainnet");
  assert.ok(html.includes("207 vB · 828 WU"), "exact serialized size missing from transaction summary");
  assert.ok(html.includes("48550.72463768116 sat/vB"), "fee rate missing from transaction summary");
});
