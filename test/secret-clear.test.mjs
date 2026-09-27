// Lifecycle clearing must discard application state, not only visible fields.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { createBase58check, hex } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { HDKey } from "../src/js/hdkey.js";
import { hex as appHex } from "../src/js/coders.js";

// The helpers that zero address-row key bytes (#546 B2). The lifecycle
// harness loads whichever of them app.js defines, so a source without them
// fails the byte-wiping tests on the bytes, not on a missing function.
const rowWipeHelpers = ["hodlZeroWalletRows", "hodlLiveWalletResults", "hodlWipeUnsharedWalletRows", "hodlSettleDerivationKeys"];

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

// Execute the real controller functions, with delayed crypto and a small DOM.
function functionSource(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  const next = app.indexOf("\nfunction ", start + 1);
  const asyncNext = app.indexOf("\nasync function ", start + 1);
  const end = Math.min(...[next, asyncNext].filter(value => value >= 0));
  return (app.slice(start - 6, start) === "async " ? "async " : "") + app.slice(start, end);
}

function raceHarness() {
  const pending = deferred(), decryptStarted = deferred(), events = {}, effects = [];
  const fields = new Map();
  const mirrors = [".dice-input-highlight", ".dice-word-grid", "#last-words", "#brain-lab-hex"]
    .map(selector => ({ selector, textContent: "secret mnemonic" }));
  const context = vm.createContext({
    document: {
      getElementById: id => fields.get(id) ?? null,
      querySelectorAll: selector => mirrors.filter(el => selector.split(", ").includes(el.selector)),
    },
    addEventListener: (type, callback) => { events[type] = callback; },
    hodlActiveDerivation: { kind: "key", cancelled: false }, hodlDerivationGeneration: 0,
    hodlJournalGeneration: 0, hodlJournalKeys: {}, hodlJournal: {},
    hodlKeys: [{ id: 1, number: 1, fields: {}, result: null }], hodlActiveKey: 0, hodlKeyManagerPending: [],
    hodlKeyMode: "hex", hodlTargetWordCount: 24, hodlNetworkChoice: "mainnet",
    hodlWalletResult: null, hodlOutEl: { innerHTML: "" }, hodlLastWordCache: new Map(),
    hodlBip85Note: "", hodlSpNote: "",
    hodlReadDerivationPlan: () => ({ network: "mainnet", coinType: 0 }),
    hodlNetworkFamily: value => value,
    hodlReadAddressWindow: () => ({ start: 0, range: 1 }),
    hodlReadBranchWindow: () => ({ start: 0, range: 2 }),
    hodlSelectedScriptType: () => "bip84", hodlDefaultHardening: () => ({}),
    hodlPassphraseBip39Enabled: () => false, hodlSelectedEntropy: () => ({}),
    hodlEntropyWalletWithProgress: () => pending.promise,
    hodlNewKeyState: () => ({ fields: {}, result: null }),
    hodlRestoreKey: () => { context.hodlWalletResult = null; },
    hodlJournalUnlocked: () => true,
    hodlConfirmKeyFingerprint: () => Promise.resolve(true),
    hodlJournalOpenExport: () => { decryptStarted.resolve(); return pending.promise; },
    hodlJournalWipeMem: () => { context.hodlJournalGeneration++; },
    hodlErrorSpecFrom: error => error.message,
  });
  fields.set("pass", { value: "private passphrase", dataset: {} });
  fields.set("dice", { value: "1 2 3 4 5 6", dataset: { previousValue: "1 2 3 4 5 6" } });
  for (const name of ["hodlThrowIfFailed", "hodlSetSelectedScriptType", "hodlCaptureKey",
    "hodlSnapshotKeySummary", "hodlCommitDerivedKey", "hodlJournalCaptureDerivedKey",
    "hodlFocusWalletResult", "hodlJournalLog", "hodlSetWorkspaceError", "hodlJournalSetStatus",
    "hodlKeyManagerStatus", "hodlPsbtWipeMem", "hodlBip85WipeMem", "hodlSpWipeMem",
    "hodlLnWipeMem", "hodlRenderBip85Tabs", "hodlSyncBip85View", "hodlVanityCancel",
    "hodlVanitySyncSource", "hodlVanitySyncControls", "hodlRefreshStationKeyPickers", "hodlRefreshMsigSessionPickers", "hodlSyncPsbtControls"])
    context[name] = (...args) => { effects.push([name, ...args]); };
  vm.runInContext('class HodlDerivationCancelledError extends Error {}', context);
  for (const name of ["hodlInvalidateDerivation", "hodlAssertDerivationActive", "hodlCalculateKey",
    "hodlWipeActiveKey", "hodlJournalImportFile", "hodlKeyManagerImportFile", "hodlInitSecretFieldAutoClear",
    "hodlAccountAddressBranches", ...rowWipeHelpers.filter((name) => app.includes(`function ${name}(`))])
    vm.runInContext(functionSource(name), context);
  context.hodlInitSecretFieldAutoClear();
  return { context, pending, decryptStarted, events, effects, mirrors, fields };
}

for (const teardown of ["clear", "pagehide", "pageshow", "stop"]) {
  for (const rejects of [false, true]) test(`${teardown} discards a late derivation ${rejects ? "error" : "result"}`, async () => {
    const { context, pending, events, effects } = raceHarness();
    const calculation = context.hodlCalculateKey({});
    const rejected = assert.rejects(calculation, error => error.constructor.name === "HodlDerivationCancelledError");
    if (teardown === "clear") context.hodlWipeActiveKey();
    else if (teardown === "stop") context.hodlActiveDerivation.cancelled = true;
    else events[teardown]({ persisted: true });
    effects.length = 0;
    if (rejects) pending.reject(new Error("late crypto failure"));
    else pending.resolve({ network: "mainnet", privateKey: "secret" });
    await rejected;
    assert.equal(context.hodlWalletResult, null);
    assert.deepEqual(effects, []);
  });
}

test("an uninterrupted derivation still commits its result", async () => {
  const { context, pending, effects } = raceHarness();
  const calculation = context.hodlCalculateKey({});
  const result = { network: "mainnet", privateKey: "secret" };
  pending.resolve(result);
  assert.equal(await calculation, true);
  assert.equal(context.hodlWalletResult, result);
  assert.ok(effects.some(([name]) => name === "hodlCommitDerivedKey"));
});

test("Multisig Clear prevents a suspended derivation from committing", async () => {
  const { context, pending, effects } = raceHarness();
  Object.assign(context, {
    hodlActiveMsig: 0, hodlMsigs: [{ id: 2, number: 1 }],
    hodlNewMsigState: () => ({ result: null }), hodlRestoreMsig: () => {},
    hodlValidatedMsigInputs: () => ({
      count: 1, addressStart: 0, branchStart: 0, branchRange: 1,
      kind: "p2wsh", keyTokens: ["key"], accountSummary: {},
    }),
    hodlMsigKeysSorted: () => true, hodlMsigInnerDescriptor: () => "descriptor",
    descriptorDerive: () => ({ address: "test address", pubkeys: [] }),
    hodlHex: { decode: value => value, encode: value => value },
    hodlAddressBranchRole: () => "receive", hodlAddressBranchLabel: () => "Receive",
    hodlDescriptorWithChecksum: value => value,
  });
  vm.runInContext(functionSource("hodlBuildMsig"), context);
  vm.runInContext(functionSource("hodlMsigBranchDescriptor"), context);
  vm.runInContext(functionSource("hodlMsigAddressRow"), context);
  vm.runInContext(functionSource("hodlWipeActiveMsig"), context);
  const operation = context.hodlBuildMsig({ setTotal() {}, step: () => pending.promise });
  const rejected = assert.rejects(operation, error => error.constructor.name === "HodlDerivationCancelledError");
  context.hodlWipeActiveMsig();
  effects.length = 0;
  pending.resolve();
  await rejected;
  assert.equal(context.hodlWalletResult, null);
  assert.deepEqual(effects, []);
});

test("pagehide and persisted pageshow erase rendered word copies", () => {
  const { events, mirrors } = raceHarness();
  for (const type of ["pagehide", "pageshow"]) {
    mirrors.forEach(el => { el.textContent = "secret mnemonic"; });
    events[type]({ persisted: true });
    assert.ok(mirrors.every(el => el.textContent === ""));
  }
});

test("pagehide and persisted pageshow drop the dice previousValue leftover", () => {
  // #423 leftover: the wipe blanked dice.value and left dataset.previousValue
  // holding the rolls. That is the raw entropy the visible field just lost.
  const { context, events } = raceHarness();
  const dice = context.document.getElementById("dice");
  for (const type of ["pagehide", "pageshow"]) {
    dice.value = "1 2 3 4 5 6";
    dice.dataset.previousValue = "1 2 3 4 5 6";
    events[type]({ persisted: true });
    assert.equal(dice.value, "");
    assert.equal(dice.dataset.previousValue, undefined);
  }
});

for (const name of ["hodlJournalImportFile", "hodlKeyManagerImportFile"]) {
  for (const phase of ["read", "decrypt"]) {
    for (const rejects of [false, true]) test(`${name} discards stale ${phase} ${rejects ? "failure" : "completion"}`, async () => {
      const { context, pending, decryptStarted, effects } = raceHarness();
      const read = deferred();
      const operation = context[name]({ size: 1, name: "notes.elkeys", text: () => read.promise });
      if (phase === "decrypt") {
        read.resolve('{"entropylabJournalExport":true}');
        await decryptStarted.promise;
      }
      context.hodlJournalWipeMem();
      effects.length = 0;
      const gate = phase === "read" ? read : pending;
      if (rejects) gate.reject(new Error("late import failure"));
      else gate.resolve(phase === "read" ? '{}' : { kind: "key-manager", content: "private" });
      await operation;
      assert.deepEqual(effects, []);
      assert.deepEqual(context.hodlJournal, {});
    });
  }
}

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const start = app.indexOf("function hodlInitSecretFieldAutoClear()");
const end = app.indexOf("\nfunction hodlBoot()", start);
const lifecycle = app.slice(start, end);

test("page lifecycle clearing replaces every cached key and clears PSBT private state", () => {
  assert.match(lifecycle, /hodlPsbtWipeMem\(\)/);
  assert.match(lifecycle, /hodlBip85WipeMem\(\)/);
  assert.match(lifecycle, /hodlSpWipeMem\(\)/);
  assert.match(lifecycle, /hodlJournalWipeMem\(\)/);
  assert.match(lifecycle, /hodlKeys\s*=\s*hodlKeys\.map\(\(state\)\s*=>\s*\{/);
  assert.match(lifecycle, /privateKeys\[kind\]\s*=\s*""/);
  assert.match(lifecycle, /if \(id !== "privateKeys"\) fields\[id\] = ""/);
  assert.match(lifecycle, /state\.result\s*=\s*null/);
  assert.match(lifecycle, /return state\.isLab \? hodlNewLabState\(\) : hodlNewKeyState\(state\.name, state\.id, state\.number\)/);
  assert.match(lifecycle, /hodlWalletResult\s*=\s*null[\s\S]*hodlRevealPrivate\s*=\s*false[\s\S]*hodlPickedLastWord\s*=\s*""[\s\S]*hodlDiceCoinPositions\s*=\s*\[\]/);
  assert.match(lifecycle, /addEventListener\("pagehide", clearSecretFields\)/);
  assert.match(lifecycle, /event\.persisted\) clearSecretFields\(\)/);
});

test("PSBT key and passphrase fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("psbt-key"\)/);
  assert.match(lifecycle, /getElementById\("psbt-pass"\)/);
  assert.match(lifecycle, /psbtKey\.value\s*=\s*""/);
  assert.match(lifecycle, /psbtPass\.value\s*=\s*""/);
});

test("PSBT text and anti-exfil transcript fields are explicitly cleared", () => {
  // #psbt-text can carry xprvs in proprietary fields; #psbt-ax-transcript
  // holds the anti-exfil host nonce.
  assert.match(lifecycle, /getElementById\("psbt-text"\)/);
  assert.match(lifecycle, /getElementById\("psbt-ax-transcript"\)/);
  assert.match(lifecycle, /psbtText\.value\s*=\s*""/);
  assert.match(lifecycle, /psbtAxTranscript\.value\s*=\s*""/);
});

// The Nonce Inspector loads the shared session key from its own fields, and
// its input can carry xprvs in proprietary PSBT fields, so page teardown has
// to empty all three the same way it empties the PSBT Inspector's.
test("pagehide and persisted pageshow empty the Nonce Inspector's key, passphrase and input", () => {
  const ids = ["nonce-key", "nonce-pass", "nonce-text"];
  for (const [type, event] of [["pagehide", {}], ["pageshow", { persisted: true }]]) {
    const { events, fields } = raceHarness();
    for (const id of ids) fields.set(id, { value: "xprv9s21ZrQH143K secret material", dataset: {} });
    events[type](event);
    for (const id of ids) assert.equal(fields.get(id).value, "", `${type} left #${id} filled`);
  }
});

test("BIP-85 parent and derived-child fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("bip85-key"\)/);
  assert.match(lifecycle, /bip85Key\.value\s*=\s*""/);
  assert.match(lifecycle, /bip85Out\.innerHTML\s*=\s*""/);
});

test("Lightning seed, passphrase, and derived output are explicitly cleared", () => {
  assert.match(lifecycle, /hodlLnWipeMem\(\)/);
  assert.match(lifecycle, /getElementById\("ln-seed"\)/);
  assert.match(lifecycle, /getElementById\("ln-pass"\)/);
  assert.match(lifecycle, /lnSeed\.value\s*=\s*""/);
  assert.match(lifecycle, /lnPass\.value\s*=\s*""/);
  assert.match(lifecycle, /lnOut\.innerHTML\s*=\s*""/);
  assert.match(lifecycle, /lnError\.textContent\s*=\s*""/);
});

test("Entropy Journal password, entries, and encrypted session are explicitly cleared", () => {
  // The lifecycle's hodlJournalWipeMem clears both the session notepad and the
  // encrypted notebook (keys, document, and every notebook field).
  assert.match(lifecycle, /hodlJournalWipeMem\(\)/);
  assert.match(app, /function hodlJournalWipeMem\(\) \{[\s\S]*?hodlJournalWipeNotebook\(\)[\s\S]*?hodlJournalClearFields\(\)/);
  assert.match(app, /journal-create-password/);
  assert.match(app, /journal-input/);
  assert.match(app, /journal-phrase/);
  assert.match(app, /journal-entry-notes/);
});

test("Silent Payments session key and passphrase fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("sp-key"\)/);
  assert.match(lifecycle, /getElementById\("sp-pass"\)/);
  assert.match(lifecycle, /spKey\.value\s*=\s*""/);
  assert.match(lifecycle, /spPass\.value\s*=\s*""/);
});

test("Silent Payments private-bearing inputs and revealed output are cleared", () => {
  // #sp-send-vins carries per-input derivation paths into the session's keys;
  // #sp-out renders revealed scan/spend private material. Both must go when
  // the page lifecycle clears.
  assert.match(lifecycle, /getElementById\("sp-send-vins"\)/);
  assert.match(lifecycle, /spVins\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-out"\)/);
  assert.match(lifecycle, /spOut\.innerHTML\s*=\s*""/);
  assert.match(lifecycle, /spError\.textContent\s*=\s*""/);
  assert.match(lifecycle, /spSession\.textContent\s*=\s*hodlSpNote/);
});

test("Silent Payments recipient, verify, and label fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("sp-recipients"\)/);
  assert.match(lifecycle, /spRecipients\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-verify-vins"\)/);
  assert.match(lifecycle, /spVerifyVins\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-verify-outputs"\)/);
  assert.match(lifecycle, /spVerifyOutputs\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-label"\)/);
  assert.match(lifecycle, /spLabel\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-payname"\)/);
  assert.match(lifecycle, /spPayname\.value\s*=\s*""/);
});

test("highlight mirrors, copy-button phrases, the last-word cache, and the PSBT editor are cleared", () => {
  // The .dice-input-highlight <pre> behind each input holds a second live
  // copy of the typed secret; copy buttons keep the phrase in data-phrase;
  // hodlLastWordCache retains partial mnemonics; the editor holds the loaded
  // PSBT (which can carry xprvs in proprietary fields).
  assert.match(lifecycle, /querySelectorAll\("\.dice-input-highlight, \.dice-word-grid, #last-words, #brain-lab-hex"\)/);
  assert.match(lifecycle, /highlight\.textContent\s*=\s*""/);
  assert.match(lifecycle, /querySelectorAll\("\[data-phrase\]"\)/);
  assert.match(lifecycle, /removeAttribute\("data-phrase"\)/);
  assert.match(lifecycle, /hodlLastWordCache\.clear\(\)/);
  assert.match(lifecycle, /getElementById\("psbted-wipe"\)/);
  assert.match(lifecycle, /psbtEditorWipe\.click\(\)/);
});

test("Vanity grinder salt, matches, and running workers are cleared", () => {
  // The imported/typed salt prefixes every candidate passphrase, and a found
  // passphrase is private key material — both go on pagehide/bfcache, and the
  // worker pool is cancelled so nothing keeps grinding (or holding the salt
  // in a worker's WASM heap) after the page hides.
  assert.match(lifecycle, /hodlVanityCancel\(\)/);
  assert.match(lifecycle, /hodlVanityMatches\s*=\s*\[\]/);
  assert.match(lifecycle, /hodlVanityFound\s*=\s*0/);
  assert.match(lifecycle, /hodlVanityReveal\s*=\s*false/);
  assert.match(lifecycle, /hodlVanitySource\s*=\s*""/);
  assert.match(lifecycle, /hodlVanityRun\s*=\s*null/);
  assert.match(lifecycle, /getElementById\("vanity-pass"\)/);
  assert.match(lifecycle, /vanityPass\.textContent\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("vanity-out"\)/);
  assert.match(lifecycle, /vanityOut\.innerHTML\s*=\s*""/);
  // The masked column is sized from the passphrase lengths; that width goes
  // with the matches, on the wipe and when results are cleared.
  assert.match(lifecycle, /vanityOut\.style\.removeProperty\("--vanity-pass-width"\)/);
  const renderStart = app.indexOf("function hodlRenderVanityOut()");
  const render = app.slice(renderStart, app.indexOf("\nfunction ", renderStart + 1));
  assert.match(render, /box\.style\.removeProperty\("--vanity-pass-width"\)/);
  assert.match(lifecycle, /getElementById\("vanity-error"\)/);
  assert.match(lifecycle, /vanityError\.textContent\s*=\s*""/);
});

test("the key Wipe button drops the cached partial mnemonics", () => {
  // Runs the real hodlWipeActiveKey. The cache keys are near-complete seeds,
  // so the wipe must clear them itself rather than wait for pagehide, and it
  // must do so even when no key slot is active.
  for (const activeKey of [-1, 0]) {
    const cache = new Map([["24:abandon abandon abandon", { candidates: [] }]]);
    const context = vm.createContext({
      hodlLastWordCache: cache,
      hodlInvalidateDerivation() {},
      hodlActiveKey: activeKey,
      hodlKeys: [{ name: "Key 1", id: 1, number: 1, isLab: false }],
      hodlNewKeyState: () => ({}),
      hodlNewLabState: () => ({}),
      hodlRestoreKey() {},
      hodlJournalLog() {},
      hodlWipeUnsharedWalletRows() {},
    });
    vm.runInContext(`${functionSource("hodlWipeActiveKey")}\nhodlWipeActiveKey();`, context);
    assert.equal(cache.size, 0, `Wipe (active key ${activeKey}) left partial mnemonics in the last-word cache`);
  }
});

// #546 B2: an address row keeps its private key as wipeable bytes, and the
// WIF text exists only while it is shown, copied or exported. Strings cannot
// be erased, so no string in a derived row may carry the key. Expected keys
// come from @scure/bip32 on BIP32 test vector 1 and the WIFs from an
// independent Base58Check encoder, not from app.js.
const vectorSeed = hex.decode("000102030405060708090a0b0c0d0e0f");
const wifOf = (key, network) => createBase58check(sha256).encode(Uint8Array.from([network === "testnet" ? 0xef : 0x80, ...key, 0x01]));
const stringsIn = (value, out = []) => {
  if (typeof value === "string") out.push(value);
  else if (value && typeof value === "object" && !ArrayBuffer.isView(value)) Object.values(value).forEach((entry) => stringsIn(entry, out));
  return out;
};
const vectorRows = (hodlDeriveAddressRows, network, role, count = 3) => {
  const coin = network === "testnet" ? 1 : 0, branch = role === "receive" ? 0 : 1;
  const account = HDKey.fromMasterSeed(vectorSeed).derive(`m/84'/${coin}'/0'`);
  return hodlDeriveAddressRows(account, `m/84h/${coin}h/0h`, "p2wpkh", network, count, role, 0).map((row, index) => ({
    row, key: ScureHDKey.fromMasterSeed(vectorSeed).derive(`m/84'/${coin}'/0'/${branch}/${index}`).privateKey,
  }));
};

test("derived address rows hold their private keys as bytes, never as text", async () => {
  const { hodlDeriveAddressRows } = await loadAppFunctions(["hodlDeriveAddressRows"]);
  for (const network of ["mainnet", "testnet"]) for (const role of ["receive", "change"]) {
    for (const [index, { row, key }] of vectorRows(hodlDeriveAddressRows, network, role).entries()) {
      const secrets = [wifOf(key, network), hex.encode(key)];
      assert.ok(!stringsIn(row).some((text) => secrets.some((secret) => text.includes(secret))), `${network} ${role}/${index}: the row holds its private key as text`);
      assert.deepEqual(row.privateKey, key, `${network} ${role}/${index}: the row's key bytes`);
    }
  }
});

test("a row's WIF is encoded only on request and matches an independent encoder", async () => {
  const { hodlDeriveAddressRows, hodlRowWif, hodlCompressedWifLength } = await loadAppFunctions(["hodlDeriveAddressRows", "hodlRowWif", "hodlCompressedWifLength"]);
  for (const network of ["mainnet", "testnet"]) for (const role of ["receive", "change"]) {
    for (const { row, key } of vectorRows(hodlDeriveAddressRows, network, role)) assert.equal(hodlRowWif(row), wifOf(key, network));
  }
  assert.equal(hodlRowWif({ privateKey: null, network: "mainnet" }), null, "a watch-only row has no WIF");
  // The hidden table masks a row's WIF by its fixed length instead of encoding
  // it: every compressed WIF, at the smallest and largest keys, on both
  // networks, is that long.
  const n1 = hex.decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"), one = new Uint8Array(32);
  one[31] = 1;
  for (const key of [one, n1]) for (const network of ["mainnet", "testnet"]) assert.equal(wifOf(key, network).length, hodlCompressedWifLength);
});

// A result's rows, the shape key results carry (accounts → addressBranches →
// rows); receive/change alias the same row objects.
const walletWithRows = (Bytes = Uint8Array) => {
  const rows = [0, 1].map((index) => ({ index, privateKey: new Bytes(32).fill(index + 7) }));
  return { rows, result: { accounts: [{ addressBranches: [{ branch: 0, rows }], receive: rows, change: [] }] } };
};
const zeroed = (rows) => rows.every((row) => row.privateKey.every((byte) => byte === 0));

test("Wipe zeroes a wallet's row key bytes unless another key tab still shows the wallet", () => {
  for (const shared of [false, true]) {
    const { rows, result } = walletWithRows();
    const active = { name: "Key 1", id: 1, number: 1, isLab: false, result };
    const context = vm.createContext({
      hodlLastWordCache: new Map(), hodlInvalidateDerivation() {}, hodlActiveKey: 0,
      hodlKeys: shared ? [active, { isLab: true, result }] : [active], hodlKeyManagerPending: [], hodlWalletResult: result,
      hodlNewKeyState: () => ({ result: null }), hodlNewLabState: () => ({ result: null }),
      hodlRestoreKey() { context.hodlWalletResult = context.hodlKeys[context.hodlActiveKey]?.result ?? null; }, hodlJournalLog() {},
    });
    for (const name of ["hodlAccountAddressBranches", ...rowWipeHelpers.filter((name) => app.includes(`function ${name}(`))]) vm.runInContext(functionSource(name), context);
    vm.runInContext(`${functionSource("hodlWipeActiveKey")}\nhodlWipeActiveKey();`, context);
    if (shared) assert.ok(rows.every((row) => row.privateKey.some((byte) => byte !== 0)), "Wipe zeroed keys another tab still shows");
    else assert.ok(zeroed(rows), "Wipe left the wallet's row key bytes in memory");
  }
});

test("pagehide and persisted pageshow zero every derived wallet's row key bytes", () => {
  for (const event of ["pagehide", "pageshow"]) {
    const { context, events } = raceHarness();
    context.hodlNewLabState = () => ({ fields: {}, result: null });
    const station = walletWithRows(), lab = walletWithRows(), pending = walletWithRows(), shown = walletWithRows();
    context.hodlKeys = [{ id: 1, number: 1, fields: {}, result: station.result }, { id: 2, number: 2, isLab: true, fields: {}, result: lab.result }];
    context.hodlKeyManagerPending = [{ result: pending.result }];
    context.hodlWalletResult = shown.result;
    events[event]({ persisted: true });
    for (const [name, wallet] of Object.entries({ station, lab, pending, shown })) assert.ok(zeroed(wallet.rows), `${event}: the ${name} wallet's row key bytes survived`);
  }
});

test("an ignored key's saved copy carries no key bytes", async () => {
  const { rows, result } = walletWithRows();
  result.masterFingerprint = "73c5da0a";
  const { hodlKeyManagerEntry } = await loadAppFunctions(["hodlKeyManagerEntry"]);
  const entry = hodlKeyManagerEntry({ id: 1, name: "Key 1", isLab: false, fields: {}, result });
  const copied = entry.result.accounts[0].addressBranches[0].rows;
  assert.ok(copied.every((row) => row.privateKey === undefined), "the copy kept the rows' key bytes");
  assert.equal(entry.result.masterFingerprint, "73c5da0a", "the copy keeps what identifies the key");
  assert.ok(rows.every((row) => row.privateKey instanceof Uint8Array), "copying must not touch the live rows");
});

// A key detached from a station moves, result and all, into the Key Manager's
// pending list, and the Key Station can still show that same result. The Key
// Manager's reset (Journal lock, unlock, create, wipe) zeroes every byte array
// its pending keys reach; it must not reach rows a station still shows.
test("a Key Manager reset leaves the row key bytes of a wallet a station still shows", () => {
  const context = vm.createContext({
    hodlKeyManagerIgnored: [], hodlKeyManagerIds: new Set(), hodlKeyManagerActiveId: "",
    document: { getElementById: () => null }, hodlKeyManagerStatus() {}, hodlKeyManagerRender() {},
  });
  // The wipe tests bytes with instanceof, so they must come from the context's
  // own realm, as they do in the page.
  const Bytes = vm.runInContext("Uint8Array", context), shared = walletWithRows(Bytes), alone = walletWithRows(Bytes);
  Object.assign(context, {
    hodlKeyManagerPending: [{ id: 1, result: shared.result }, { id: 2, result: alone.result }],
    hodlKeys: [{ isLab: true, result: shared.result }], hodlWalletResult: shared.result,
  });
  for (const name of ["hodlKeyManagerWipeValue", "hodlKeyManagerReset", ...["hodlLiveWalletResults"].filter((name) => app.includes(`function ${name}(`))]) vm.runInContext(functionSource(name), context);
  vm.runInContext("hodlKeyManagerReset();", context);
  assert.ok(shared.rows.every((row) => row.privateKey.some((byte) => byte !== 0)), "the reset zeroed keys the Key Station still shows");
  assert.ok(zeroed(alone.rows), "the reset left a pending-only wallet's row key bytes in memory");
});

// A derivation that never commits must not leave the row keys it made in
// memory either: stopped, wiped, hidden, failed, or declined at the
// fingerprint confirmation, before or after its rows are complete (Astra's
// review of #588). This runs the real derivation controller, progress
// tracker and address-row builder on BIP32 test vector 1, holding each
// progress pause until the test releases it. The stubbed wallet builder only
// strings the real rows together. Every key the row builder takes from a
// child node is recorded, so the assertions read the exact buffers the rows
// kept, and the expected keys come from @scure/bip32.
const vectorRowKey = (branch, index) => ScureHDKey.fromMasterSeed(vectorSeed).derive(`m/84'/0'/0'/${branch}/${index}`).privateKey;
const vectorRowKeys = [[0, 0], [0, 1], [1, 0], [1, 1]].map(([branch, index]) => vectorRowKey(branch, index));
const allZero = (keys) => keys.every((key) => key.every((byte) => byte === 0));
const noneZero = (keys) => keys.every((key) => key.some((byte) => byte !== 0));

async function derivationHarness({ failAtAddress = 0 } = {}) {
  const harness = raceHarness(), { context } = harness, keys = [], pauses = [];
  const real = await loadAppFunctions(["hodlPathComponent", "hodlAddressBranchRole", "hodlAddressOrThrow"]);
  let clock = 0, addresses = 0;
  Object.assign(context, {
    hodlActiveDerivation: null, hodlDerivationProgressTimers: {}, hodlHex: appHex,
    hodlPathComponent: real.hodlPathComponent, hodlAddressBranchRole: real.hodlAddressBranchRole,
    hodlAddressOrThrow(...args) {
      if (++addresses === failAtAddress) throw new Error("address failure");
      return real.hodlAddressOrThrow(...args);
    },
    // Every progress step yields, and each yield waits for the test.
    performance: { now: () => (clock += 20) }, setTimeout: () => 0, clearTimeout() {},
    hodlDerivationPause() { const gate = deferred(); pauses.push(gate); return gate.promise; },
    hodlResetDerivationProgress() {}, hodlSetDerivationButtonState() {}, hodlSyncDeriveButton() {}, hodlSyncMsigDeriveButton() {},
    async hodlEntropyWalletWithProgress(entropy, passphrase, network, count, accountIndex, addressStart, tracker) {
      const account = HDKey.fromMasterSeed(vectorSeed).derive("m/84'/0'/0'"), watched = {
        derive(path) {
          const child = account.derive(path);
          return { get publicKey() { return child.publicKey; }, get privateKey() { const key = child.privateKey; keys.push(key); return key; }, wipePrivateData: () => child.wipePrivateData() };
        },
      }, addressBranches = [];
      for (const branch of [0, 1]) addressBranches.push({ branch, rows: await context.hodlAddressRowsWithProgress(watched, "m/84h/0h/0h", "p2wpkh", "mainnet", 2, branch, 0, tracker) });
      account.wipePrivateData();
      return { kind: "hd", network: "mainnet", masterFingerprint: "3442193e", accounts: [{ addressBranches }] };
    },
  });
  for (const name of ["hodlDeriveWithProgress", "hodlCreateDerivationTracker", "hodlStopDerivation", "hodlAddressRowsWithProgress", "hodlDerivedAddressRow"])
    vm.runInContext(functionSource(name), context);
  // Releases held pauses until `done` holds; fails if the derivation stalls.
  const driveUntil = async (done) => {
    for (let spins = 0; !done(); spins++) {
      assert.ok(spins < 1000, "the derivation stalled");
      if (pauses.length) pauses.shift().resolve();
      else await new Promise((resolve) => setImmediate(resolve));
    }
  };
  const start = () => {
    const run = { settled: false };
    run.promise = context.hodlDeriveWithProgress("key", context.hodlCalculateKey).finally(() => { run.settled = true; });
    return run;
  };
  return { ...harness, keys, pauses, driveUntil, start };
}

for (const teardown of ["Wipe", "pagehide", "persisted pageshow", "Stop"]) {
  test(`${teardown} during a derivation's progress pause zeroes the rows it has built`, async () => {
    const { context, events, keys, pauses, driveUntil, start } = await derivationHarness();
    const run = start();
    await driveUntil(() => keys.length === 1 && pauses.length === 1);
    assert.deepEqual(keys[0], vectorRowKeys[0], "the first row holds its real key");
    if (teardown === "Wipe") context.hodlWipeActiveKey();
    else if (teardown === "Stop") context.hodlStopDerivation("key");
    else events[teardown.split(" ").pop()]({ persisted: true });
    // A hidden page can stay suspended mid-derivation: Wipe and page teardown
    // must not wait for it to unwind. Stop lets it unwind at the next pause.
    if (teardown !== "Stop") assert.ok(allZero(keys), `${teardown} left the partial rows' key bytes in memory`);
    await driveUntil(() => run.settled);
    await run.promise;
    assert.equal(context.hodlWalletResult, null, `${teardown}: the stopped derivation committed`);
    assert.equal(keys.length, 1, `${teardown}: the derivation kept deriving`);
    assert.ok(allZero(keys), `${teardown} left the partial rows' key bytes in memory`);
  });
}

test("a derivation that fails part-way zeroes the rows it had built", async () => {
  const { context, keys, driveUntil, start } = await derivationHarness({ failAtAddress: 3 });
  const run = start();
  await driveUntil(() => run.settled);
  assert.equal(await run.promise, undefined);
  assert.equal(context.hodlWalletResult, null);
  assert.equal(keys.length, 3, "the third row failed after taking its key");
  assert.ok(allZero(keys), "a failed derivation left its rows' key bytes in memory");
});

test("declining the fingerprint confirmation zeroes the finished result's row keys", async () => {
  const { context, keys, driveUntil, start } = await derivationHarness(), confirm = deferred();
  let asked = false;
  context.hodlConfirmKeyFingerprint = () => { asked = true; return confirm.promise; };
  const run = start();
  await driveUntil(() => asked);
  assert.deepEqual(keys, vectorRowKeys, "the finished result holds its real keys");
  confirm.resolve(false);
  await driveUntil(() => run.settled);
  await run.promise;
  assert.equal(context.hodlWalletResult, null, "the declined result committed");
  assert.ok(allZero(keys), "the declined result's row key bytes stayed in memory");
});

test("pagehide while the fingerprint confirmation is open zeroes the pending result's row keys", async () => {
  const { context, events, keys, driveUntil, start } = await derivationHarness(), confirm = deferred();
  let asked = false;
  context.hodlConfirmKeyFingerprint = () => { asked = true; return confirm.promise; };
  const run = start();
  await driveUntil(() => asked);
  assert.ok(noneZero(keys));
  events.pagehide({});
  assert.ok(allZero(keys), "pagehide left the pending result's row key bytes in memory");
  // Confirming after the page comes back must not revive the result.
  confirm.resolve(true);
  await driveUntil(() => run.settled);
  await run.promise;
  assert.equal(context.hodlWalletResult, null, "the confirmation committed a result the page had already wiped");
  assert.ok(allZero(keys));
});

test("a committed derivation keeps its row keys, and a later stopped one zeroes only its own", async () => {
  const { context, keys, pauses, driveUntil, start } = await derivationHarness();
  const first = start();
  await driveUntil(() => first.settled);
  await first.promise;
  const committed = keys.splice(0);
  assert.ok(context.hodlWalletResult, "the derivation committed");
  assert.deepEqual(committed, vectorRowKeys, "committing zeroed the keys the station now shows");
  const second = start();
  await driveUntil(() => keys.length === 1 && pauses.length === 1);
  context.hodlStopDerivation("key");
  await driveUntil(() => second.settled);
  await second.promise;
  assert.ok(allZero(keys), "the stopped derivation left its row key bytes in memory");
  assert.deepEqual(committed, vectorRowKeys, "stopping a derivation zeroed the keys of the wallet the station shows");
});

// The account node a wallet derives its rows from holds the account private
// key. A derivation that stops part-way must wipe it as a finished one does.
test("a stopped derivation wipes the account nodes it derived", async () => {
  const { hodlRootWalletWithProgress } = await loadAppFunctions(["hodlRootWalletWithProgress"]);
  const root = HDKey.fromMasterSeed(vectorSeed), derive = root.derive.bind(root), nodes = [];
  root.derive = (path) => { const node = derive(path); nodes.push(node); return node; };
  let steps = 0;
  const tracker = { setTotal() {}, step() { if (++steps === 3) throw new Error("stopped"); return null; } };
  await assert.rejects(hodlRootWalletWithProgress(root, "mainnet", 2, {}, 0, 0, tracker, 84, 0), /stopped/);
  assert.equal(nodes.length, 1);
  assert.ok(nodes.every((node) => node.privateKey === null), "the stopped derivation left the account private key in memory");
});

test("a stopped import of an account key wipes the imported node", async () => {
  // BIP32 test vector 1, chain m/0H/1/2H: a depth-3 extended private key.
  const xprv = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM";
  const { hodlParseExtendedKey } = await loadAppFunctions(["hodlParseExtendedKey"]), nodes = [];
  const { hodlImportedWalletWithProgress } = await loadAppFunctions(["hodlImportedWalletWithProgress"], {
    stubs: {
      hodlParseExtendedKey(value) { const parsed = hodlParseExtendedKey(value); nodes.push(parsed.node); return parsed; },
      hodlSelectedScriptType: () => "bip84",
    },
  });
  let steps = 0;
  const tracker = { setTotal() {}, step() { if (++steps === 3) throw new Error("stopped"); return null; } };
  await assert.rejects(hodlImportedWalletWithProgress(xprv, "mainnet", 2, 0, 0, tracker, 84, 0), /stopped/);
  assert.equal(nodes.length, 1);
  assert.ok(nodes[0].privateKey === null, "the stopped import left the imported private key in memory");
});
