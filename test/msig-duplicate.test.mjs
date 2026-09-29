import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const fields = {
  m: "2", n: "3", script: "p2wsh", keyOrder: "sorted", network: "mainnet",
  xpubs: ["cosigner-a", "cosigner-b", "cosigner-c"], specs: ["bip48", "bip48", "bip48"],
  branchStart: "0", branchRange: "2", addressStart: "11", addressRange: "5",
  descriptor: "", thresholdLocked: false, reuseSessionKeys: true,
};
const json = (value) => JSON.parse(JSON.stringify(value));

function harness() {
  const original = { id: 1, number: 1, name: "Original", fields: json(fields), result: { kind: "msig", m: 2, n: 3, script: "p2wsh" }, createdPolicy: "2-of-3" };
  const lab = { id: 0, number: 0, isLab: true, fields: {}, result: null };
  let nextId = 2;
  const context = vm.createContext({
    hodlMsigs: [lab, original], hodlActiveMsig: 1,
    hodlNewMsigState: () => ({ id: nextId, number: nextId++, name: "New", fields: {} }),
    hodlNewMsigLabState: () => ({ id: 0, number: 0, isLab: true, fields: {}, result: null }),
    hodlMsigNameTaken: () => false, hodlMsigPolicyName: () => "2-of-3",
    hodlCaptureMsig() {}, hodlRenderMsigTabs() {}, hodlRestoreMsig() {}, hodlSelectMsigLab() {},
    hodlSelectMsig: (index) => { context.hodlActiveMsig = index; },
  });
  for (const name of ["hodlMsigHasResult", "hodlCloneDerivedMsig", "hodlMsigIdentity", "hodlCommitDerivedMsig", "hodlFillMsigLabFromWallet", "hodlEditMsigInputs", "hodlDuplicateMsigInputs"]) {
    const source = app.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
    if (source) vm.runInContext(source[0], context);
  }
  return { context, original };
}

test("Duplicate copies all inputs and derives a new tab even when the inputs are identical", () => {
  const { context, original } = harness();
  const before = json(original);
  assert.equal(typeof context.hodlDuplicateMsigInputs, "function", "Duplicate action is missing");
  context.hodlDuplicateMsigInputs();
  const draft = context.hodlMsigs[context.hodlActiveMsig];
  assert.equal(draft.isLab, true);
  assert.equal(draft.result, null);
  assert.deepEqual(json(draft.fields), fields);
  assert.notEqual(draft.fields.xpubs, original.fields.xpubs);
  assert.notEqual(draft.fields.specs, original.fields.specs);
  draft.result = { ...original.result };
  context.hodlCommitDerivedMsig();
  assert.equal(context.hodlMsigs.length, 3);
  assert.equal(context.hodlMsigs[1], original);
  assert.deepEqual(json(original), before);
  assert.notEqual(context.hodlMsigs[context.hodlActiveMsig].id, original.id);
  assert.equal(context.hodlMsigs[0].duplicateOnDerive, undefined);
});

test("a duplicate with changed inputs never replaces another matching wallet", () => {
  const { context, original } = harness();
  const other = { ...original, id: 2, number: 2, fields: { ...json(fields), m: "1" } };
  context.hodlMsigs.push(other);
  assert.equal(typeof context.hodlDuplicateMsigInputs, "function", "Duplicate action is missing");
  context.hodlDuplicateMsigInputs();
  const draft = context.hodlMsigs[context.hodlActiveMsig];
  draft.fields.m = "1";
  draft.result = { ...original.result, m: 1 };
  context.hodlCommitDerivedMsig();
  assert.equal(context.hodlMsigs.length, 4);
  assert.equal(context.hodlMsigs[1], original);
  assert.equal(context.hodlMsigs[2], other);
});

test("Edit Input resets duplicate intent and retains existing identity-based replacement", () => {
  const { context } = harness();
  assert.equal(typeof context.hodlDuplicateMsigInputs, "function", "Duplicate action is missing");
  context.hodlDuplicateMsigInputs();
  context.hodlActiveMsig = 1;
  context.hodlEditMsigInputs();
  const draft = context.hodlMsigs[context.hodlActiveMsig];
  draft.result = { kind: "msig", m: 2, n: 3, script: "p2wsh" };
  context.hodlCommitDerivedMsig();
  assert.equal(context.hodlMsigs.length, 2);
  assert.equal(context.hodlActiveMsig, 1);
});

test("Duplicate refuses a station draft and an underived wallet; an unsuccessful derive keeps the original", () => {
  const { context, original } = harness();
  assert.equal(typeof context.hodlDuplicateMsigInputs, "function", "Duplicate action is missing");
  context.hodlActiveMsig = 0;
  context.hodlDuplicateMsigInputs();
  assert.equal(context.hodlMsigs[0].duplicateOnDerive, undefined);
  context.hodlActiveMsig = 1;
  original.result = null;
  context.hodlDuplicateMsigInputs();
  assert.equal(context.hodlActiveMsig, 1);
  original.result = { kind: "msig", m: 2, n: 3 };
  context.hodlDuplicateMsigInputs();
  context.hodlCommitDerivedMsig();
  assert.equal(context.hodlMsigs.length, 2);
  assert.equal(context.hodlMsigs[1], original);
});
