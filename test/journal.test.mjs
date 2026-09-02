import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  JOURNAL_LOG_LIMIT,
  addNote,
  appendLog,
  createJournal,
  deleteNote,
  formatLog,
  formatNotes,
  formatStamp,
  snapshotSession,
  updateNote,
  wipeJournal,
} from "../src/js/journal.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

test("formatStamp is local wall-clock, not UTC ISO", () => {
  let stamp = formatStamp(new Date(2026, 8, 2, 9, 5, 7));
  assert.equal(stamp, "2026-09-02 09:05:07");
  assert.doesNotMatch(stamp, /T|Z/);
});

test("notes get incrementing ids and keep the typed time", () => {
  let journal = createJournal();
  let first = addNote(journal, { text: "dice from the kitchen table" }, new Date(2026, 8, 2, 10, 0, 0));
  let second = addNote(journal, { at: "2026-09-02 11:00:00", text: "passphrase hint is the dog" });
  assert.equal(first.id, 1);
  assert.equal(second.id, 2);
  assert.equal(first.at, "2026-09-02 10:00:00");
  assert.equal(journal.notes.length, 2);
  updateNote(journal, 1, { text: "updated" });
  assert.equal(journal.notes[0].text, "updated");
  assert.equal(deleteNote(journal, 1), true);
  assert.equal(journal.notes.length, 1);
  assert.match(formatNotes(journal.notes), /Written: 2026-09-02 11:00:00/);
});

test("the log is a ring buffer and never stores more than the cap", () => {
  let journal = createJournal();
  for (let i = 0; i < JOURNAL_LOG_LIMIT + 5; i++) {
    appendLog(journal, { tool: "calc", action: "derive", detail: `n=${i}` }, new Date(2026, 0, 1, 0, 0, 0));
  }
  assert.equal(journal.log.length, JOURNAL_LOG_LIMIT);
  assert.match(journal.log[0].detail, /n=5/);
  assert.match(formatLog(journal.log), /calc\tderive/);
});

test("a public snapshot names fingerprints and omits secrets unless asked", () => {
  let publicText = snapshotSession({
    capturedAt: "2026-09-02 10:00:00",
    version: "v0.1.3",
    commit: "abc1234",
    includePrivate: false,
    keys: [{ name: "Key Station", derived: false, mode: "dice" }, { name: "a1b2c3d4", derived: true, fingerprint: "a1b2c3d4", sheet: "Master fingerprint: a1b2c3d4\nxpub: xpub123" }],
    msigs: [],
    bip85: [{ name: "child", fingerprint: "deadbeef", app: "BIP-39", secret: "abandon abandon abandon" }],
    sp: { derived: false },
    psbt: { loaded: false },
  });
  assert.match(publicText, /fingerprint a1b2c3d4/);
  assert.doesNotMatch(publicText, /abandon abandon abandon/);
  let privateText = snapshotSession({
    capturedAt: "2026-09-02 10:00:00",
    includePrivate: true,
    keys: [],
    msigs: [],
    bip85: [{ name: "child", fingerprint: "deadbeef", app: "BIP-39", secret: "abandon abandon abandon" }],
    sp: { derived: false },
    psbt: { loaded: false },
  });
  assert.match(privateText, /abandon abandon abandon/);
});

test("wipe drops notes, log, and snapshot text", () => {
  let journal = createJournal();
  addNote(journal, { text: "secret hint" });
  appendLog(journal, { tool: "calc", action: "derive", detail: "fp=aa" });
  journal.stateText = "xprv...";
  wipeJournal(journal);
  assert.equal(journal.notes.length, 0);
  assert.equal(journal.log.length, 0);
  assert.equal(journal.stateText, "");
});

test("the journal module never talks to the network, browser storage, or a CSPRNG", () => {
  const src = read("src/js/journal.js");
  assert.doesNotMatch(src, /\bfetch\s*\(|XMLHttpRequest|WebSocket|\blocalStorage\b|\bsessionStorage\b|indexedDB|Math\.random|crypto\.getRandomValues/);
});
