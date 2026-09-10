// Issue #389: a crafted .elkeys payload passes Key Manager validation with
// attacker-controlled strings inside the cached result — the address-row
// index, for one — and "Use in Key Station" restores that cached result
// without re-derivation. The renderers are the injection boundary: an address
// index must come out as a validated number or as escaped text, never as
// markup. These tests run the real vault parser and the real app.js table
// renderer against such a payload.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseKeyVault, serializeKeyVault } from "../src/js/keymanager.js";
import { addressQrButtonHtml } from "../src/js/address-qr.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

// The real escaping helpers and table renderer from app.js; hodlPrivateValue
// (the WIF cell) is sliced too, with its two globals stubbed.
const source = [
  loadSlice("hodlEscapeHtml"),
  loadSlice("hodlDisplayDerivationPath"),
  loadSlice("hodlAddressIndexHtml"),
  loadSlice("hodlPrivateValue"),
  loadSlice("hodlAddressTableRows"),
].join("\n");
const loadRows = (revealPrivate = false) =>
  new Function("hodlRevealPrivate", "hodlT", "hodlAddressQrButton", `${source}; return hodlAddressTableRows;`)(
    revealPrivate,
    (text, vars) => text.replace("{n}", String(vars?.n ?? "{n}")),
    addressQrButtonHtml,
  );

const ATTACK_INDEX = '<svg onload="alert(document.domain)">';
const craftedRow = { index: ATTACK_INDEX, path: "m/84'/0'/0'/0/0", address: "bc1qexampleaddress000000000000000000000000" };

test("the vault parser carries imported result metadata through unchecked (the renderer is the boundary)", () => {
  const entry = {
    id: 7,
    number: 2,
    name: "Imported key",
    createdAt: "2026-09-03T12:00:00.000Z",
    fields: { seed: "user supplied words" },
    result: { masterFingerprint: "deadbeef", kind: "hd", accounts: [{ rows: [craftedRow] }] },
  };
  const [parsed] = parseKeyVault(serializeKeyVault([entry])).keys;
  assert.equal(parsed.result.accounts[0].rows[0].index, ATTACK_INDEX, "a string index survives parsing — validation must not be the only line of defense");
});

test("the address table renders a crafted index as inert text (issue #389)", () => {
  const html = loadRows()([craftedRow]);
  assert.ok(!html.includes("<svg"), "no element markup from the import");
  assert.ok(!html.includes('onload="'), "no live event-handler attribute");
  assert.ok(html.includes("&lt;svg onload=&quot;alert(document.domain)&quot;&gt;"), "the payload shows as escaped text");
  // Same guarantee with the private-sheet column enabled.
  const wifHtml = loadRows(true)([{ ...craftedRow, wif: "L1xWifExample" }]);
  assert.ok(!wifHtml.includes("<svg"));
});

test("legitimate numeric indexes render unchanged", () => {
  const html = loadRows()([
    { index: 0, path: "m/84'/0'/0'/0/0", address: "bc1qzero" },
    { index: 2147483647, path: "m/84'/0'/0'/1", address: "bc1qmax" },
  ]);
  assert.ok(html.includes('<th scope="row">0</th>'));
  assert.ok(html.includes('<th scope="row">2147483647</th>'));
  // Other non-integer shapes degrade to escaped text, never to markup.
  for (const index of [-1, 1.5, "3", null, undefined, '3<img src=x onerror=alert(1)>']) {
    const cell = loadRows()([{ index, path: "m/0/0", address: "bc1qx" }]);
    assert.ok(!cell.includes("<img"), `index ${String(index)} stays inert`);
    assert.ok(!/<th scope="row"><\/th>/.test(cell) || index == null, "only nullish indexes render empty");
  }
});

test("the first-address lead and the multisig lead route the index through the same guard", () => {
  const show = loadSlice("hodlShowAccount");
  assert.ok(show.includes("address #${hodlAddressIndexHtml(firstIndex)}"), "HD account heading");
  assert.ok(show.includes('address ${hodlAddressIndexHtml(firstIndex)} QR code'), "HD account QR label");
  const msig = loadSlice("hodlShowMsig");
  assert.ok(msig.includes("address #${hodlAddressIndexHtml(firstIndex)}"), "multisig heading");
  assert.ok(msig.includes('address ${hodlAddressIndexHtml(firstIndex)} QR code'), "multisig QR label");
});
