import { test } from "node:test";
import assert from "node:assert/strict";
import { psbtCostFactsFromDoc } from "../src/js/psbt-cost.js";

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
  inputs: [
    finalized ? [witnessUtxo(100000000), finalWitness()] : [witnessUtxo(100000000)],
    finalized ? [witnessUtxo(secondInputAmount), finalWitness()] : [witnessUtxo(secondInputAmount)],
  ],
});

test("finalized SegWit PSBT exposes exact fee, weight, vsize, and fee rate", () => {
  const facts = psbtCostFactsFromDoc(doc());
  assert.deepEqual(facts, {
    inputCount: 2,
    outputCount: 2,
    inputAmountSats: "200000000",
    outputAmountSats: "189950000",
    feeSats: "10050000",
    finalized: true,
    weight: 832,
    vsize: 208,
    feeRateSatPerVbyte: 48317.307692307695,
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
  assert.equal(facts.weight, 832);
});

test("missing input amount leaves fee unknown but still permits exact finalized size", () => {
  const fixture = doc();
  fixture.inputs[1] = [finalWitness()];
  const facts = psbtCostFactsFromDoc(fixture);
  assert.equal(facts.inputAmountSats, null);
  assert.equal(facts.feeSats, null);
  assert.equal(facts.finalized, true);
  assert.equal(facts.weight, 832);
  assert.equal(facts.vsize, 208);
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
