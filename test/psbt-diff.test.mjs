import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { comparePsbtDocs } from "../src/js/psbt-diff.js";

const doc = (overrides = {}) => ({
  tx: {
    version: 2,
    locktime: 0,
    inputs: [{ txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 }],
    outputs: [{ value: "1000", scriptPubKey: "0014" + "22".repeat(20) }],
  },
  globals: [
    { key: "00", value: "aa" },
    { key: "01", value: "bb" },
  ],
  inputs: [[{ key: "01", value: "cc", name: "PSBT_IN_WITNESS_UTXO" }]],
  outputs: [[]],
  ...overrides,
});

test("identical documents compare equal", () => {
  const result = comparePsbtDocs(doc(), doc());
  assert.equal(result.equal, true);
  assert.equal(result.changes.length, 0);
  assert.equal(result.transactionChanged, false);
  assert.equal(result.signingChanged, false);
  assert.equal(result.metadataChanged, false);
});

test("PSBT map ordering does not create a difference", () => {
  const before = doc();
  const after = doc({ globals: [before.globals[1], before.globals[0]], inputs: [[before.inputs[0][0]]] });
  assert.equal(comparePsbtDocs(before, after).equal, true);
});

test("transaction changes are reported separately", () => {
  const after = doc({ tx: { ...doc().tx, outputs: [{ value: "900", scriptPubKey: "0014" + "22".repeat(20) }] } });
  const result = comparePsbtDocs(doc(), after);
  assert.equal(result.transactionChanged, true);
  assert.equal(result.metadataChanged, false);
  assert.equal(result.signingChanged, false);
  assert.deepEqual(result.changes, [{ scope: "output", index: 0, field: "output[0].value", kind: "changed", before: "1000", after: "900", category: "transaction" }]);
});

test("partial signatures are classified as signing changes", () => {
  const after = doc({ inputs: [[{ key: "01", value: "cc", name: "PSBT_IN_WITNESS_UTXO" }, { key: "02aabb", value: "dd", name: "PSBT_IN_PARTIAL_SIG" }]] });
  const result = comparePsbtDocs(doc(), after);
  assert.equal(result.transactionChanged, false);
  assert.equal(result.signingChanged, true);
  assert.equal(result.metadataChanged, false);
  assert.equal(result.changes[0].kind, "added");
  assert.equal(result.changes[0].category, "signing");
});

test("sighash type is classified as a signing change", () => {
  const after = doc({ inputs: [[{ key: "01", value: "cc", name: "PSBT_IN_WITNESS_UTXO" }, { key: "08", value: "01", name: "PSBT_IN_SIGHASH_TYPE" }]] });
  const result = comparePsbtDocs(doc(), after);
  assert.equal(result.signingChanged, true);
  assert.equal(result.metadataChanged, false);
  assert.equal(result.changes[0].category, "signing");
  assert.equal(result.changes[0].name, "PSBT_IN_SIGHASH_TYPE");
});

test("metadata changes are distinguished from signing changes", () => {
  const after = doc({ globals: [{ key: "00", value: "aa" }, { key: "01", value: "changed", name: "PSBT_GLOBAL_XPUB" }] });
  const result = comparePsbtDocs(doc(), after);
  assert.equal(result.transactionChanged, false);
  assert.equal(result.signingChanged, false);
  assert.equal(result.metadataChanged, true);
  assert.equal(result.changes.length, 1);
  assert.equal(result.changes[0].kind, "changed");
  assert.equal(result.changes[0].category, "metadata");
});

test("added and removed transaction elements are reported without hiding map changes", () => {
  const before = doc();
  const after = doc({ tx: { ...before.tx, inputs: [], outputs: [before.tx.outputs[0], { value: "500", scriptPubKey: "0014" + "33".repeat(20) }] }, inputs: [], outputs: [[], []] });
  const result = comparePsbtDocs(before, after);
  assert.equal(result.transactionChanged, true);
  assert.ok(result.changes.some((change) => change.scope === "input" && change.kind === "removed"));
  assert.ok(result.changes.some((change) => change.scope === "output" && change.kind === "added"));
  assert.ok(result.changes.some((change) => change.scope === "input-map" && change.kind === "removed"));
});

test("map fields can be changed, added, and removed", () => {
  const before = doc();
  const after = doc({ globals: [{ key: "00", value: "changed" }, { key: "02", value: "new" }] });
  const result = comparePsbtDocs(before, after);
  assert.deepEqual(result.changes.map(({ scope, kind, key }) => ({ scope, kind, key })), [{ scope: "global", kind: "changed", key: "00" }, { scope: "global", kind: "removed", key: "01" }, { scope: "global", kind: "added", key: "02" }]);
});

test("reordered inputs are reported as changes (index matching is intentional in v1)", () => {
  const before = doc({ tx: { version: 2, locktime: 0, inputs: [{ txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 }, { txid: "22".repeat(32), vout: 1, scriptSig: "", sequence: 4294967295 }], outputs: [{ value: "1000", scriptPubKey: "0014" + "22".repeat(20) }] }, inputs: [[], []] });
  const after = doc({ tx: { version: 2, locktime: 0, inputs: [{ txid: "22".repeat(32), vout: 1, scriptSig: "", sequence: 4294967295 }, { txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 }], outputs: [{ value: "1000", scriptPubKey: "0014" + "22".repeat(20) }] }, inputs: [[], []] });
  const result = comparePsbtDocs(before, after);
  assert.equal(result.transactionChanged, true);
  assert.ok(result.changes.some((c) => c.field === "input[0].txid"));
});

test("a real committed PSBT fixture can be inspected and compared", () => {
  const fixturePath = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "psbt", "p2wpkh-1in-2out.b64");
  const encoded = readFileSync(fixturePath, "utf8").trim();
  const bytes = new Uint8Array(Buffer.from(encoded, "base64"));
  const before = psbtInspectDoc(bytes);
  const after = psbtInspectDoc(bytes);
  assert.equal(before.rustBitcoinError, null);
  assert.equal(comparePsbtDocs(before, after).equal, true);
});

test("invalid comparison inputs fail explicitly", () => {
  assert.throws(() => comparePsbtDocs(null, {}), /Both PSBT inspection documents are required/);
});
