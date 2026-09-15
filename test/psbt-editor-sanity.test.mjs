// The consensus layer over PSBT edits (psbt-wasm verify.rs): every edit is
// checked against Bitcoin's consensus rules and BIP-174's signer checks —
// UTXO claims, redeem/witness script bindings, signatures and final witness
// data — and error-severity problems gate the build unless the editor's
// Insane editing switch passes { insane: true }. These tests pin both the
// detections and the two severities' gate behavior.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2.js";
import { psbtBuildBytes, psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { psbtEditorBuildDoc, psbtProblemsHtml } from "../src/js/psbt-editor.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const fixtureDoc = (name) => {
  const b64 = readFileSync(join(root, `test/fixtures/psbt/${name}.b64`), "utf8").trim();
  return psbtInspectDoc(Uint8Array.from(atob(b64), (char) => char.charCodeAt(0)));
};
const rebuild = (doc, options) => psbtInspectDoc(psbtBuildBytes(psbtEditorBuildDoc(doc), options));
const codes = (doc) => doc.problems.map((problem) => `${problem.severity}:${problem.code}`);

test("fixtures carry exactly their honest problems (garbage partial sigs named, real final witness accepted)", () => {
  assert.deepEqual(codes(fixtureDoc("p2wpkh-1in-2out")), ["warning:partial_sig_invalid"]);
  // The finalized P2WPKH input's real signature verifies: no final-witness
  // finding. The fabricated partial/taproot signatures are named as warnings.
  assert.deepEqual(codes(fixtureDoc("mixed-many-inputs")), ["warning:partial_sig_invalid", "warning:tap_sig_invalid", "warning:partial_sig_invalid"]);
  assert.deepEqual(codes(fixtureDoc("p2tr-taproot")), ["warning:tap_sig_invalid"]);
  assert.deepEqual(codes(fixtureDoc("bip174-valid-vector-2")), []);
  assert.deepEqual(codes(fixtureDoc("no-amount-claims")), []);
  assert.deepEqual(codes(fixtureDoc("outputs-exceed-inputs")), ["warning:fee_impossible"]);
  assert.deepEqual(codes(fixtureDoc("no-outputs")), ["error:tx_consensus"]);
});

test("a corrupt final witness is an error and gates the build; insane editing bypasses the gate only", () => {
  const doc = fixtureDoc("mixed-many-inputs");
  const witness = doc.inputs[4].find((pair) => pair.name === "PSBT_IN_FINAL_SCRIPTWITNESS");
  // Flip one byte inside the witness signature: structurally fine, invalid.
  const corrupt = witness.value.slice(0, 10) + (witness.value[10] === "a" ? "b" : "a") + witness.value.slice(11);
  doc.inputs[4] = doc.inputs[4].map((pair) => (pair === witness ? { ...pair, value: corrupt } : pair));
  const inspected = rebuild(doc, { insane: true }); // must build under insane…
  assert.ok(inspected.problems.some((p) => p.severity === "error" && p.code === "final_witness_bad"));
  // …and must refuse under the default policy.
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)), /final witness/);
});

test("a non-witness UTXO whose txid is not the prevout gates the build (BIP-174 invalid)", () => {
  const doc = fixtureDoc("mixed-many-inputs");
  // Repoint input 0's prevout so the embedded previous transaction no longer
  // matches it (this also orphans input 0's nothing — it carries no sigs).
  doc.tx.inputs[0].txid = "ef".repeat(32);
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)), /non-witness UTXO's txid does not match/);
  const insane = rebuild(doc, { insane: true });
  assert.ok(insane.problems.some((p) => p.code === "nonwitness_txid_mismatch" && p.severity === "error"));
});

test("a witness UTXO declaring a non-witness output is an error (BIP-174 signer check)", () => {
  const doc = fixtureDoc("p2wpkh-1in-2out");
  // Rewrite the witness UTXO claim to a P2PKH script (76a914…88ac), same
  // amount: a witness UTXO for a non-witness input. The value layout is
  // 8-byte LE amount, compact-size script length, script.
  const claim = doc.inputs[0].find((pair) => pair.name === "PSBT_IN_WITNESS_UTXO");
  claim.value = claim.value.slice(0, 16) + "19" + "76a914" + "00".repeat(20) + "88ac";
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)), /witness UTXO declared for a non-witness input/);
  const insane = rebuild(doc, { insane: true });
  assert.ok(insane.problems.some((p) => p.code === "witness_utxo_on_legacy" && p.severity === "error"));
});

test("a redeemScript that does not hash to the claimed P2SH output is an error", () => {
  // bip174 vector 2's input 1 spends a P2SH output with a wrapped-segwit
  // redeem script; corrupting one redeem-script byte breaks the hash binding.
  const doc = fixtureDoc("bip174-valid-vector-2");
  const redeem = doc.inputs[1].find((pair) => pair.name === "PSBT_IN_REDEEM_SCRIPT");
  redeem.value = redeem.value.slice(0, -2) + (redeem.value.endsWith("00") ? "01" : "00");
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)), /redeemScript does not hash/);
  const insane = rebuild(doc, { insane: true });
  assert.ok(insane.problems.some((p) => p.code === "redeem_script_mismatch" && p.severity === "error"));
});

test("warnings never gate: a missing witness UTXO is listed and the build still succeeds", () => {
  // The spend is known to be segwit through a non-witness UTXO claim (an
  // embedded previous transaction paying a P2WPKH output), while the witness
  // UTXO BIP-174 expects for it is absent.
  const p2wpkhScript = "0014" + "11".repeat(20);
  const prevTx =
    "02000000" + "01" + "99".repeat(32) + "00000000" + "00" + "ffffffff" +
    "01" + "204e000000000000" + "16" + p2wpkhScript + "00000000";
  const prevTxid = bytesToHex(Uint8Array.from(hexToBytes(bytesToHex(sha256(sha256(hexToBytes(prevTx)))))).reverse());
  const doc = {
    tx: { version: 2, locktime: 0, inputs: [{ txid: prevTxid, vout: 0, scriptSig: "", sequence: 4294967295 }], outputs: [{ value: 1000, scriptPubKey: "51" }] },
    globals: [],
    inputs: [[{ key: "00", value: prevTx }]],
    outputs: [[]],
  };
  const fresh = psbtInspectDoc(psbtBuildBytes(doc)); // default policy — warnings do not block
  assert.ok(fresh.problems.some((p) => p.code === "missing_witness_utxo" && p.severity === "warning"));
});

test("an input with no UTXO claim at all cannot be classified — no finding, no gate", () => {
  const doc = fixtureDoc("p2wpkh-1in-2out");
  const without = psbtEditorBuildDoc(doc);
  without.inputs[0] = without.inputs[0].filter((pair) => pair.key !== "01");
  const fresh = psbtInspectDoc(psbtBuildBytes(without));
  assert.ok(!fresh.problems.some((p) => p.severity === "error"));
});

test("a sighash pair disagreeing with the partial signature's byte is a warning", () => {
  const doc = fixtureDoc("p2wpkh-1in-2out");
  const sighash = doc.inputs[0].find((pair) => pair.name === "PSBT_IN_SIGHASH_TYPE");
  sighash.value = "02000000"; // declares SIGHASH_NONE; the signature byte says ALL
  const fresh = rebuild(doc);
  assert.ok(fresh.problems.some((p) => p.code === "sighash_mismatch" && p.severity === "warning"));
});

test("a field that fails its typed decode is listed as an invalid-field warning", () => {
  // Hand-assembled: the fixture's unsigned transaction, one input map whose
  // sighash-type value is truncated to one byte, two empty output maps.
  const doc = fixtureDoc("p2wpkh-1in-2out");
  const unsignedTx = doc.globals.find((pair) => pair.key === "00").value;
  const raw =
    "70736274ff" + "01" + "00" + (unsignedTx.length / 2).toString(16).padStart(2, "0") + unsignedTx + "00" +
    "01" + "03" + "01" + "01" + "00" + "00" + "00";
  const inspected = psbtInspectDoc(hexToBytes(raw));
  assert.ok(inspected.problems.some((p) => p.code === "field_decode" && p.message.includes("PSBT_IN_SIGHASH_TYPE")));
});

test("insane mode changes no bytes when there is nothing to forgive", () => {
  const doc = psbtEditorBuildDoc(fixtureDoc("locktime-rbf"));
  const sane = psbtBuildBytes(doc);
  const insane = psbtBuildBytes(doc, { insane: true });
  assert.deepEqual([...insane], [...sane]);
});

test("the transaction sanity gate keeps its historic message under the unified layer", () => {
  const doc = psbtEditorBuildDoc(fixtureDoc("p2wpkh-1in-2out"));
  doc.tx.outputs = [];
  doc.outputs = [];
  assert.throws(() => psbtBuildBytes(doc), /consensus-invalid: bad-txns-vout-empty/);
  // …and insane mode builds even that (structural validity is kept).
  psbtBuildBytes(doc, { insane: true });
});

test("psbtProblemsHtml lists problems escaped, in the sanitize section's style", () => {
  const doc = fixtureDoc("p2wpkh-1in-2out");
  const html = psbtProblemsHtml(doc, false);
  assert.match(html, /psbted-sanitize/);
  assert.match(html, /warning\(s\), no consensus violations/);
  assert.match(html, /partial signature \(pubkey 0279be667ef9dcbb…\) signature does not verify/);
  // An error-severity problem names the gate and the escape hatch.
  const bad = { problems: [{ severity: "error", scope: "input 0", code: "x", message: "broke <script> it" }] };
  const badHtml = psbtProblemsHtml(bad, false);
  assert.match(badHtml, /Errors block the build and export/);
  assert.ok(!badHtml.includes("<script>"), "problem text must be escaped");
  assert.match(badHtml, /broke &lt;script&gt; it/);
  // Under insane editing the same list says it did not gate.
  assert.match(psbtProblemsHtml(bad, true), /did not block the build/);
});
