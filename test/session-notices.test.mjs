// Session notices (#627): the clipboard notice, the pre-session machine
// notice, and the post-session restart reminder. Each is an honest, non-
// blocking warning: clipboard history/sync can keep a copy on and off the
// machine; the OS can write memory to disk; a browser cannot prevent or
// erase either. These tests pin the state machine — when each fires, that
// it never blocks, that dismissal is memory-only, and that page hide
// re-arms it — against hand-built DOM fakes.
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, "src/js/session-notices.js"), "utf8");

// A DOM fake good enough for the module: elements record set state,
// document.createElement returns fresh ones, and the banner's insertion
// spot collects what was placed there. The module under test is imported
// from a data URL so a fresh instance (fresh session state) serves each
// harness; i18n is stubbed to a pass-through.
let instance = 0;
const harness = async () => {
  const placed = [];
  const listeners = {};
  const fakeEl = (tag) => ({
    tag,
    className: "", textContent: "", innerHTML: "", hidden: false,
    style: {}, dataset: {}, attributes: {}, listeners: {}, children: [],
    removed: false,
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(type, callback) { this.listeners[type] = callback; },
    append(...kids) { this.children.push(...kids); },
    remove() { this.removed = true; },
    insertAdjacentElement(_position, element) { placed.push(element); },
  });
  globalThis.document = {
    createElement: fakeEl,
    getElementById: (id) => (id === "beta-warning" ? fakeEl("aside") : null),
    body: { prepend: (el) => placed.push(el) },
    addEventListener: (type, callback) => { listeners[type] = callback; },
  };
  globalThis.addEventListener = (type, callback) => { listeners[type] = callback; };
  const rewritten = source
    .replace('import { t } from "./i18n.js";', "const t = (text) => text;")
    .replace('"./i18n-labels.js"', JSON.stringify(pathToFileURL(join(root, "src/js/i18n-labels.js")).href));
  const notices = await import(`data:text/javascript;charset=utf-8,${encodeURIComponent(rewritten)}#${++instance}`);
  return { notices, placed, listeners };
};
const kindsPlaced = (placed) => placed.map((el) => el.dataset.noticeKind);
const dismissLatest = (placed) => placed.at(-1).children.at(-1).listeners.click();

// The classifier decides which copies count as secrets (#627 §1).
test("copies are flagged secret only for private-key shapes", async () => {
  const { notices } = await harness();
  const check = notices.sessionNoticeCopyIsSecret;
  // BIP32 test vector 1, chain m: the published master xprv.
  assert.ok(check("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"));
  // slip132 and testnet extended private key prefixes.
  for (const prefix of ["tprv", "yprv", "zprv", "vprv", "uprv", "Yprv", "Zprv", "Vprv"])
    assert.ok(check(prefix + "8adgzWYSWtMWPgNAc76tRwDNdRmn3Bp8KFHBVf4WmHNrEHLkbDMQCCJ3LNmNv3WiNiKNjnAYSVcmwSktUDo9BTSaWEQU"), `${prefix} must count`);
  // WIF: mainnet 5/K/L and testnet c/9, exactly 51 or 52 base58 characters.
  assert.ok(check("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5kNRvVciXGNqUK9f2bZd"));
  assert.ok(check("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"));
  assert.ok(check("cMahea7zqjxrtgAbB7LSGbd4YKB6cjHJnGqDBBc3sDkPfMKKw6YZ"));
  assert.ok(!check("K" + "a".repeat(49)), "a 50-character WIF must not count");
  assert.ok(!check("K" + "a".repeat(52)), "a 53-character WIF must not count");
  // 64 hex characters: a raw private key. The false positive it risks (a
  // hash) fires a mild notice, never a block.
  assert.ok(check("a".repeat(64)));
  assert.ok(!check("a".repeat(63)), "63 hex characters must not count");
  assert.ok(!check("a".repeat(65)), "65 hex characters must not count");
  // Public material and prose stay quiet.
  assert.ok(!check("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), "an address is public");
  assert.ok(!check("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"), "an xpub is watch-only");
  assert.ok(!check("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), "a phrase here means a copy path regressed into classification");
  assert.ok(!check(""), "empty");
});

// Paste targets: the fields the attribute guard covers (key|seed|pass
// endings) plus the journal's free-text secret fields.
test("pastes only notify on secret fields", async () => {
  const { notices } = await harness();
  for (const id of ["pass", "seed", "key", "bip85-key", "sp-key", "sp-pass", "psbt-key", "psbt-pass", "nonce-key", "nonce-pass", "ln-seed", "ln-pass", "journal-create-password", "journal-create-confirm", "journal-open-password", "journal-input", "journal-phrase", "journal-entry-notes", "journal-notes-text"])
    assert.ok(notices.sessionNoticePasteTargetsSecret(id), `#${id} pastes must notify`);
  for (const id of ["network", "vanity-prefix", "msig-descriptor", "journal-search", "journal-label", "sp-recipients", "psbt-text", ""])
    assert.ok(!notices.sessionNoticePasteTargetsSecret(id), `#${id} pastes must not notify`);
});

test("the clipboard notice fires once per session and never blocks the edit", async () => {
  const { notices, placed, listeners } = await harness();
  notices.initSessionNotices();
  assert.ok(listeners.paste, "init must listen for paste events");
  // The paste handler must not touch the event (no preventDefault) so the
  // paste itself always lands.
  const paste = (id) => listeners.paste({ target: { id }, preventDefault: () => assert.fail("the notice blocked a paste") });
  paste("seed");
  assert.deepEqual(kindsPlaced(placed), ["clipboard"], "first secret paste did not fire the notice");
  paste("key");
  paste("pass");
  assert.deepEqual(kindsPlaced(placed), ["clipboard"], "the notice repeated within the session");
});

test("a secret copy-out fires the same one-per-session clipboard notice", async () => {
  const { notices, placed } = await harness();
  notices.initSessionNotices();
  notices.sessionNoticeSecretCopyText("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
  assert.deepEqual(kindsPlaced(placed), ["clipboard"], "copying a WIF did not fire the notice");
  notices.sessionNoticeSecretCopied(); // known-secret copy path (a phrase)
  notices.sessionNoticeSecretCopyText("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"); // public copy
  assert.deepEqual(kindsPlaced(placed), ["clipboard"], "clipboard notice repeated or fired for a public copy");
});

test("the pre-session notice fires on the first accepted private material, once", async () => {
  const { notices, placed } = await harness();
  notices.initSessionNotices();
  notices.sessionNoticeSecretCopied(); // clipboard first, so the pre-session one queues
  notices.sessionNoticePrivateMaterialAccepted();
  assert.deepEqual(kindsPlaced(placed), ["clipboard"], "a second notice stayed queued behind the visible one");
  dismissLatest(placed);
  assert.deepEqual(kindsPlaced(placed), ["clipboard", "pre-session"], "dismissal revealed the queued pre-session notice");
  notices.sessionNoticePrivateMaterialAccepted();
  notices.sessionNoticePrivateMaterialAccepted();
  assert.deepEqual(kindsPlaced(placed).filter((kind) => kind === "pre-session"), ["pre-session"], "the pre-session notice repeated within the session");
});

test("the post-session reminder fires on a wipe only after private material was held", async () => {
  const { notices, placed } = await harness();
  notices.initSessionNotices();
  notices.sessionNoticeSessionEnded();
  assert.deepEqual(kindsPlaced(placed), [], "a wipe with no private material in the session fired a reminder");
  notices.sessionNoticePrivateMaterialAccepted();
  dismissLatest(placed);
  notices.sessionNoticeSessionEnded();
  assert.deepEqual(kindsPlaced(placed), ["pre-session", "post-session"], "ending a session that held private material fired no reminder");
  dismissLatest(placed);
  notices.sessionNoticeSessionEnded();
  assert.deepEqual(kindsPlaced(placed), ["pre-session", "post-session", "post-session"], "a later wipe did not fire the reminder again");
});

test("page hide and a bfcache restore dismiss any banner and re-arm the session", async () => {
  const { notices, placed, listeners } = await harness();
  notices.initSessionNotices();
  notices.sessionNoticePrivateMaterialAccepted();
  assert.equal(kindsPlaced(placed).length, 1);
  listeners.pagehide({});
  assert.ok(placed[0].removed, "page hide left the banner in the DOM");
  notices.sessionNoticeSessionEnded();
  assert.deepEqual(kindsPlaced(placed), ["pre-session"], "the reminder fired after the session was already gone");
  notices.sessionNoticePrivateMaterialAccepted();
  assert.deepEqual(kindsPlaced(placed), ["pre-session", "pre-session"], "a fresh page kept the old session's dismissal");
});

test("the notices carry no storage, no links, and role=alert", async () => {
  const { notices, placed } = await harness();
  notices.initSessionNotices();
  notices.sessionNoticePrivateMaterialAccepted();
  const banner = placed[0];
  assert.equal(banner.attributes.role, "alert", "the banner must announce itself");
  assert.ok(!banner.innerHTML.includes("http"), "the notice must not reference a URL");
  // Dismissal is memory-only: nothing may consult a storage API.
  assert.equal(typeof globalThis.localStorage, "undefined", "the test environment itself must not offer storage unexpectedly");
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB/i, "the module must not persist dismissal");
});

// ── Integration: the real handlers reach the notices (#631 review) ─────────
// The module tests above pin the state machine; these drive production
// handlers so a success path that skips its notice call is caught.

// BIP32 test vector 1, chain m (published): a valid root xprv.
const VECTOR1_XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

test("every successful PSBT session-key import records private material; a rejected one does not", async () => {
  const { loadAppFunctions } = await import("./app-slice-harness.mjs");
  const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
  Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
  let accepted = 0;
  const { hodlLoadPsbtKey } = await loadAppFunctions(["hodlLoadPsbtKey"], { stubs: { sessionNoticePrivateMaterialAccepted: () => accepted++ } });
  hodlLoadPsbtKey(VECTOR1_XPRV, "");
  assert.equal(accepted, 1, "a root xprv session key skipped the pre-session notice");
  hodlLoadPsbtKey("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", "");
  assert.equal(accepted, 2, "a WIF session key skipped the pre-session notice");
  hodlLoadPsbtKey("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
  assert.equal(accepted, 3, "a seed-phrase session key skipped the pre-session notice");
  assert.throws(() => hodlLoadPsbtKey("not a key", ""));
  assert.equal(accepted, 3, "a rejected key recorded private material");
});

test("Lightning copies of the entropy and root xprv fire the clipboard notice; the node pubkey stays quiet", async () => {
  const placed = [], listeners = {}, elements = new Map();
  const fakeEl = (id) => ({
    id, value: "", textContent: "", innerHTML: "", hidden: false, dataset: {}, children: [], listeners: {},
    setAttribute() {}, append(...kids) { this.children.push(...kids); }, remove() {},
    addEventListener(type, callback) { this.listeners[type] = callback; },
    insertAdjacentElement(_position, element) { placed.push(element); },
  });
  for (const id of ["ln-go", "ln-wipe", "ln-format", "ln-network", "ln-out", "ln-session", "beta-warning"]) elements.set(id, fakeEl(id));
  // Decoded aezeed entropy is 16 bytes (32 hex): the classifier alone cannot
  // see it, so the control must say it is secret.
  elements.set("ln-entropy", Object.assign(fakeEl("ln-entropy"), { textContent: "0".repeat(32) }));
  elements.set("ln-root-xprv", Object.assign(fakeEl("ln-root-xprv"), { textContent: VECTOR1_XPRV }));
  elements.set("ln-node-pubkey", Object.assign(fakeEl("ln-node-pubkey"), { textContent: "02" + "1".repeat(64) }));
  const copied = [];
  Object.assign(globalThis, {
    document: {
      getElementById: (id) => elements.get(id) ?? null,
      createElement: () => fakeEl(""),
      addEventListener: (type, callback) => { listeners[type] = callback; },
      body: { prepend: (element) => placed.push(element) },
    },
    addEventListener: (type, callback) => { listeners[type] = callback; },
  });
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async (text) => { copied.push(text); } } } });
  const { initSessionNotices } = await import("../src/js/session-notices.js");
  const { hodlInitLn } = await import("../src/js/lightning.js");
  initSessionNotices();
  hodlInitLn();
  const copy = (target) => elements.get("ln-out").listeners.click({ target: { closest: () => ({ dataset: { lnCopy: target } }) } });
  const clipboardNotices = () => placed.filter((element) => element.dataset.noticeKind === "clipboard").length;
  copy("ln-node-pubkey");
  assert.equal(clipboardNotices(), 0, "copying the public node key fired the clipboard notice");
  copy("ln-entropy");
  assert.equal(clipboardNotices(), 1, "copying the decoded aezeed entropy skipped the clipboard notice");
  listeners.pagehide({}); // a fresh page session re-arms the once-per-session notice
  copy("ln-root-xprv");
  assert.equal(clipboardNotices(), 2, "copying the root xprv skipped the clipboard notice");
  assert.equal(copied.length, 3, "the notice must never block the copy");
});
