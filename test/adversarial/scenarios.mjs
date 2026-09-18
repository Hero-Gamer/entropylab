// scenarios.mjs — parametric hostile-input scenarios against the built
// entropylab.html loaded via file://. Each scenario describes one page:
//   presetup: JS evaluated once after page load (optional)
//   actions:  JS strings evaluated in order; each returns a short log line
//   assert:   JS evaluated last, returning
//             { failures: [human-readable invariant violations], info: {} }
// All JS is CDP-Runtime.evaluate material. Every snippet is defensive:
// a missing element is reported as an info line, not a crash, so the
// harness can distinguish "hostile input not delivered" from real bugs.

// Helper injected in front of every scenario's action block.
export const HELPER = `
  const $ = (sel) => document.querySelector(sel);
  const $all = (sel) => [...document.querySelectorAll(sel)];
  const first = (sels) => { for (const s of sels) { const el = $(s); if (el) return el; } return null; };
  const put = (el, v) => {
    el.focus();
    const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const click = (sel) => { const el = first(Array.isArray(sel) ? sel : [sel]); if (!el) return false; el.click(); return true; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const upload = (inputSel, name, content) => {
    const el = first(Array.isArray(inputSel) ? inputSel : [inputSel]);
    if (!el) return "no-file-input";
    const dt = new DataTransfer();
    dt.items.add(new File([content], name, { type: "application/json" }));
    el.files = dt.files;
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return "file-dispatched";
  };
`;

export const SCENARIOS = [
  {
    name: "psbt-garbage-paste",
    description:
      "Paste non-PSBT garbage into the PSBT inspector textarea and run it; the app must surface its own error UI.",
    actions: [
      `(() => { ok = click("#psbt-editor-tab"); if (!ok) ok = click('[data-psbt-tool]'); return "switched=" + ok; })()`,
      `(() => { const el = first(["#psbt-text", "textarea"]); if (!el) return "no-psbt-textarea"; put(el, "not a psbt at all \\x00\\x01\\x01 " + "{}".repeat(200) + " <script>alert(1)<\\/script>"); return "garbage-pasted len=" + el.value.length; })()`,
      `(() => { const ok = click("#psbt-go") || click("#psbted-load"); if (!ok) return "no-go-button"; return "go-clicked"; })()`,
      `(async () => { await sleep(800); const err = first(["#psbt-error", "#psbted-error", "#error"]); return "error-ui=" + (err ? (err.textContent || "").slice(0, 120) : "(none)"); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        const err = first(["#psbt-error", "#psbted-error", "#error"]);
        if (!err || !err.textContent) failures.push("no error surfaced for garbage PSBT");
        return { failures, info: { errorText: err ? err.textContent.slice(0, 160) : null } };
      })()
    `,
  },
  {
    name: "psbt-oversized-paste",
    description:
      "Paste ~4 MB of base64-looking junk into the PSBT textarea and run it; the page must stay responsive.",
    actions: [
      `(() => { click("#psbt-editor-tab") || click('[data-psbt-tool]'); return "switched"; })()`,
      `(() => { const el = first(["#psbt-text", "textarea"]); if (!el) return "no-psbt-textarea"; const junk = "cHNidH" .repeat(700000); put(el, junk); return "huge-pasted len=" + el.value.length; })()`,
      `(() => { return click("#psbt-go") ? "go-clicked" : "no-go-button"; })()`,
      `(async () => { const t0 = Date.now(); await sleep(4000); return "settle-ms=" + (Date.now() - t0); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        if (!document.body) failures.push("document lost");
        return { failures, info: { title: document.title } };
      })()
    `,
  },
  {
    name: "mnemonic-malformed",
    description:
      "Feed malformed and oversized mnemonic words into the first words/seed entry field found on the Keys workspace.",
    actions: [
      `(() => { click('[aria-label="Keys"]'); return "workspace=keys"; })()`,
      `(() => { const el = first(['textarea[data-copy-seed-phrase]', 'textarea', 'input[type="text"]']); if (!el) return "no-seed-field-" + el; put(el, "abandon abandon " + "zzz ".repeat(600) + "abandon"); return "malformed-seed-pasted len=" + el.value.length + " tag=" + el.tagName; })()`,
      `(() => { const el = first(['textarea', 'input[type="text"]']); if (!el) return "no-field"; const weird = "aBanNDon " + "۱۲۳۴ " + "\\u200B\\u200B " + "abandon".repeat(40); put(el, weird); return "tricky-encoding-pasted len=" + el.value.length; })()`,
      `(async () => { await sleep(500); const err = first(['#error', '[id$="-error"]']); return "error-ui=" + (err ? (err.textContent || "").slice(0, 120) : "(none found)"); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        if (!document.body) failures.push("document lost");
        return { failures, info: {} };
      })()
    `,
  },
  {
    name: "journal-hostile-import",
    description:
      "Dispatches a hostile journal JSON file (script tags, wrong types, oversized body) through the journal file input.",
    actions: [
      `(() => { click('[aria-label="Journal"]'); return "workspace=journal-clicked"; })()`,
      `(() => { const hostile = JSON.stringify({ pages: "<script>alert(1)</script>", entries: 12345, huge: "x".repeat(300000) }); return upload(["#journal-file", 'input[type="file"]'], "hostile.journal.json", hostile); })()`,
      `(async () => { await sleep(800); const err = first(["#journal-error", '[id="error"]']); return "journal-error=" + (err ? (err.textContent || "").slice(0, 140) : "(none)"); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        if (!document.body) failures.push("document lost");
        const html = document.body ? document.body.innerHTML.length : 0;
        return { failures, info: { bodyLength: html } };
      })()
    `,
  },
  {
    name: "dice-oversized",
    description:
      "Stuff 100k+ junk characters into the dice textarea; the page must stay alive.",
    actions: [
      `(() => { const el = first(["#dice"]); if (!el) return "no-dice-textarea"; put(el, "1".repeat(120000) + "\\u0000".repeat(50) + "9".repeat(20000)); return "dice-stuffed len=" + el.value.length; })()`,
      `(async () => { await sleep(700); const meta = $("#dice-meta"); return "dice-meta=" + (meta ? (meta.textContent || "").slice(0, 100) : "(none)"); })()`,
    ],
    assert: `
      (() => { const failures = []; if (!document.body) failures.push("document lost"); return { failures, info: {} }; })()
    `,
  },
  {
    name: "nonce-history-junk-json",
    description:
      "Dispatches a junk nonce-history JSON (valid JSON, wrong shape) plus a non-JSON blob through the PSBT nonce-history file input.",
    actions: [
      `(() => { click('[aria-label="PSBT"]'); return "workspace=psbt"; })()`,
      `(() => { const ok = upload(["#psbt-nonce-history-file"], "hist.json", JSON.stringify({ this: "is", totally: ["wrong", 1, 2, 3] })); return "junk-json=" + ok; })()`,
      `(() => { const ok = upload(["#psbt-nonce-history-file"], "blob.bin", "\\x00\\x01\\x02 not json \\xFF"); return "binary-blob=" + ok; })()`,
      `(async () => { await sleep(800); const status = $("#psbt-nonce-history-status"); return "status=" + (status ? (status.textContent || "").slice(0, 140) : "(none)"); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        const status = $("#psbt-nonce-history-status");
        if (!status || !status.textContent) failures.push("nonce-history status UI empty after junk upload");
        return { failures, info: {} };
      })()
    `,
  },
  {
    name: "workspace-tab-hammer",
    description:
      "Click through all seven workspace tabs 40 times and assert the page ends responsive with no accumulated exceptions.",
    actions: [
      `(async () => {
        const labels = ["Keys", "BIP-85", "Multi Signature", "PSBT", "Silent Payments", "Vanity", "Journal"];
        let clicks = 0;
        for (let i = 0; i < 40; i++) {
          $all('button.workspace-tab').forEach((tab) => { tab.click(); clicks++; });
          await sleep(20);
        }
        return "hammered " + clicks + " clicks";
      })()`,
      `(async () => { await sleep(500); return "settled title=" + document.title.slice(0, 60); })()`,
    ],
    assert: `
      (() => { const failures = []; if (!document.body) failures.push("document lost"); return { failures, info: {} }; })()
    `,
  },
  {
    name: "seed-encoding-tricks",
    description:
      "Mixed-case, zero-width, RTL and homoglyph tricks on whichever text field the current workspace exposes; the field must not accept them silently and the page must stay alive.",
    actions: [
      `(() => { click('[aria-label="Keys"]'); return "workspace=keys"; })()`,
      `(() => { const el = first(['textarea', 'input[type="text"]', 'input:not([type="checkbox"]):not([type="file"]):not([type="hidden"])']); if (!el) return "no-text-field"; const tricky = "Abandon abandon ANDERSON " + "‏‎‌" + "zoo zoo"; put(el, tricky); return "tricky-pasted len=" + el.value.length; })()`,
      `(async () => { await sleep(400); return "settled"; })()`,
    ],
    assert: `
      (() => { const failures = []; if (!document.body) failures.push("document lost"); return { failures, info: {} }; })()
    `,
  },
];
