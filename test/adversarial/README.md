# jev-adversarial

Adversarial browser-testing harness for the EntropyLab app judged by Jev
(TypeSafe System One). **Scratch/exploratory tooling — it lives outside the
repo (entropylab-scratch/jev-adversarial) and the repo must not be modified.**

## How it works

1. `harness.mjs` launches one headless Chrome (`--headless=new
   --remote-debugging-port=0`, temp profile) and connects to the browser
   over CDP using Node's built-in WebSocket (Node 22+; developed on 24).
2. For each scenario in `scenarios.mjs` it opens a separate target (isolated
   page) — all of them in **parallel** by default — navigates to
   `file:///C:/Users/steve/entropylab/entropylab.html`, and:
   - installs a tap script before any page JS that records
     fetch/XHR/sendBeacon/WebSocket/EventSource attempts, uncaught errors,
     and unhandled rejections (the app "must never network");
   - runs each scenario's `actions` (CDP-`Runtime.evaluate` JS: paste garbage,
     dispatch file uploads, hammer tabs);
   - runs the scenario's `assert` hook plus the common invariants
     (no network attempts, page still alive after the input);
   - collects console errors, uncaught exceptions, and CDP `Log` entries.
3. Each scenario's compact log goes to Jev via `jev.mjs`'s `verdict()`
   helper, which mirrors `triage-issues.ps1` exactly
   (`POST https://api.typesafe.ai/v1/systemone` with
   `{ state, model: "jev-latest", questions }`, answers on
   `response.answers`, types `noul` / `choice` / `score`). Jev returns
   **ok / suspect / broken** plus severity, network-egress, and
   hang-or-freeze scores.
4. A plain-text table is printed, along with per-scenario action logs and
   any invariant failures.

The API key comes from `TYPESAFE_API_KEY` (process env first, then the
Windows User-scoped registry value via PowerShell — same as the ps1). It
is never printed.

## Running

```bash
node harness.mjs                     # all scenarios, parallel
node harness.mjs --serial            # one scenario at a time
node harness.mjs --scenario=dice-oversized
node harness.mjs --scenario=psbt --serial
```

Also: `node --check harness.mjs` for a syntax check without launching.

## Scenarios

| scenario | what it does |
| --- | --- |
| `psbt-garbage-paste` | junk + script tag into `#psbt-text`; asserts the app surfaces its own error element |
| `psbt-oversized-paste` | ~4 MB of base64-looking junk into the PSBT textarea; page must stay responsive |
| `mnemonic-malformed` | malformed/oversized/repeated mnemonic into the first text field on the Keys workspace |
| `journal-hostile-import` | hostile journal JSON (script tags, wrong types, huge) dispatched through `#journal-file` |
| `dice-oversized` | 120k chars + NULs into `#dice`; page must stay alive |
| `nonce-history-junk-json` | wrong-shape JSON + binary blob through the nonce-history file input; asserts status UI reports something |
| `workspace-tab-hammer` | 40 rounds of clicking every workspace tab; no crash, no exception accumulation |
| `seed-encoding-tricks` | mixed-case/RTL/zero-width/homoglyph strings into a seed field |

## What it asserts

- The app never attempts a network call (fetch/XHR/Beacon/WS/ES tap).
- The app never throws an uncaught exception or unhandled rejection
  while digesting hostile input.
- The page remains alive/responsive after each scenario.
- Scenario-specific: error/status UI actually reports the bad input
  (PSBT garbage, nonce-history junk).

## Notes

- The page URL is a plain `file:///` URL with no query params: the built
  page has no `nosim` or debug flags (checked against src and the built
  artifact).
- Jev's question types used here are only the ones that exist in
  `triage-issues.ps1` (`noul`, `choice`, `score`). If the System One
  endpoint contract changes, update `jev.mjs` in one place.
