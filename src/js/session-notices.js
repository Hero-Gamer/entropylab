// Session notices (#627): three honest, non-blocking warnings about things
// the page cannot control, fired at the moments a user still has a choice.
//
//   1. Clipboard notice — fires the first time in a page session a secret is
//      pasted into a secret field, or copied out through one of the app's own
//      copy controls. Clipboard history and sync can keep a copy, possibly on
//      other devices; EntropyLab cannot remove it. The notice never blocks the
//      paste or copy, never writes to the clipboard, and never suggests the
//      clipboard was cleared.
//   2. Pre-session notice — fires the first time in a page session a station
//      accepts private material. The operating system can write memory to disk
//      (swap, hibernation) and the browser cannot prevent it; for real funds
//      the machine needs full-disk encryption on and hibernation off before
//      the keys arrive.
//   3. Post-session reminder — fires when the user ends a session that held
//      private material (a station's wipe). Closing the browser and restarting
//      the computer is a precaution, not an erasure — it is not guaranteed to
//      clear memory, and nothing here advises deleting hiberfil.sys or the
//      pagefile (on SSDs that does not erase them either).
//
// The banner reuses the beta-warning paradigm (same markup and classes),
// pinned to the foot of the viewport: dismissible, no-print, memory-only
// state (nothing is remembered across page loads, and a page hide re-arms
// the session). A kind shows once per page session; a second notice queues
// behind a visible one.
// `data-notice-kind` is the test hook.
import { t } from "./i18n.js";
import { hodlSessionNoticeTexts } from "./i18n-labels.js";

const KINDS = hodlSessionNoticeTexts;

// The clipboard notice's two trigger shapes. Paste: secret-bearing fields
// (the attribute guard's key|seed|pass endings, the entropy transcript
// fields, the SP vin JSON, and the journal's free-text fields). Copy: text
// that looks like private key material (a WIF, an extended private key, a
// 32-byte hex string) — phrase-family copies call the known-secret hook
// directly instead.
const SECRET_FIELD_ID = /(^|-)(key|seed|pass)$/;
const SECRET_TEXT_IDS = new Set([
  "dice", "cards", "direct-cards", "hex", "bin", "base4", "base8", "base32", "base64", "seed-numbers",
  "sp-send-vins", "sp-verify-vins",
  "journal-create-password", "journal-create-confirm", "journal-open-password",
  "journal-input", "journal-phrase", "journal-entry-notes", "journal-notes-text",
]);
export const sessionNoticePasteTargetsSecret = (id) =>
  SECRET_FIELD_ID.test(id || "") || SECRET_TEXT_IDS.has(id);

const WIF = /^[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}$/;
const XPRV = /^(?:xprv|tprv|yprv|zprv|vprv|uprv|Yprv|Zprv|Vprv|Uprv)[1-9A-HJ-NP-Za-km-z]+$/;
const HEX_KEY = /^[0-9a-fA-F]{64}$/;
export const sessionNoticeCopyIsSecret = (text) =>
  WIF.test(text.trim()) || XPRV.test(text.trim()) || HEX_KEY.test(text.trim());

let materialHeld = false; // the session accepted private material
let clipboardShown = false, preSessionShown = false; // once-per-session flags
let current = null; // the visible aside
const pending = []; // kinds queued behind the visible notice

// Pinned to the viewport (the CSS), so it shows wherever the user has
// scrolled to when the click that fired it happened.
const place = (element) => document.body.append(element);

const build = (kind) => {
  const aside = document.createElement("aside");
  aside.className = "beta-warning session-notice no-print";
  aside.setAttribute("role", "alert");
  aside.dataset.noticeKind = kind;
  const text = document.createElement("div");
  text.className = "beta-warning-text";
  const lead = document.createElement("strong");
  lead.textContent = t(KINDS[kind].title);
  const body = document.createElement("span");
  body.textContent = t(KINDS[kind].body);
  text.append(lead, " ", body);
  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.className = "beta-warning-dismiss";
  dismiss.setAttribute("aria-label", t(KINDS[kind].dismiss));
  dismiss.innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M18 6 6 18M6 6l12 12"/></svg>';
  dismiss.addEventListener("click", () => {
    current?.remove();
    current = null;
    pump();
  });
  aside.append(text, dismiss);
  return aside;
};

const pump = () => {
  if (current) return;
  const kind = pending.shift();
  if (!kind) return;
  place(current = build(kind));
};

// Queueing rather than stacking: one banner at a time, and a kind already
// visible or queued is not duplicated.
const show = (kind) => {
  if (current?.dataset.noticeKind === kind || pending.includes(kind)) return;
  pending.push(kind);
  pump();
};

// A secret crossed the clipboard — paste into a secret field (via the paste
// listener) or a copy the call site knows is secret (seed phrase, WIF, xprv,
// BIP-85 child), or a copy whose text classifies as key material.
export const sessionNoticeSecretCopied = () => {
  if (clipboardShown) return;
  clipboardShown = true;
  show("clipboard");
};
export const sessionNoticeSecretCopyText = (text) => {
  if (sessionNoticeCopyIsSecret(text)) sessionNoticeSecretCopied();
};

// A station accepted private material: a derived/imported key, a session
// key, an aezeed, a journal open. First acceptance per session only.
export const sessionNoticePrivateMaterialAccepted = () => {
  materialHeld = true;
  if (preSessionShown) return;
  preSessionShown = true;
  show("pre-session");
};

// A wipe the user asked for. Only meaningful if the session held private
// material; fires per wipe, so a multi-key teardown keeps reminding.
export const sessionNoticeSessionEnded = () => {
  if (materialHeld) show("post-session");
};

const resetSessionNotices = () => {
  current?.remove();
  current = null;
  pending.length = 0;
  materialHeld = false;
  clipboardShown = false;
  preSessionShown = false;
};

export const initSessionNotices = () => {
  document.addEventListener("paste", (event) => {
    // The paste itself always lands; the notice is advisory.
    if (sessionNoticePasteTargetsSecret(event.target?.id ?? "")) sessionNoticeSecretCopied();
  });
  addEventListener("pagehide", resetSessionNotices);
  addEventListener("pageshow", (event) => {
    if (event.persisted) resetSessionNotices();
  });
};
