// MS Station co-signer derivation specs.
//
// Contract: each co-signer card follows one derivation spec, chosen from the
// specs that serve the selected script type. A spec supplies the card's path
// template and field names: BIP48 m/48'/coin'/account'/script' with script 2'
// for Native and 1' for Nested SegWit, BIP87 m/87'/coin'/account' for every
// script type, BIP45 m/45' for Legacy only, and the single-sig account specs
// m/44'|49'|84'|86'/coin'/account' for the script type each belongs to.
// Custom serves every script type and supplies no template. A pasted origin
// pre-selects the spec its purpose names when that spec serves the script
// type, and Custom otherwise.
//
// Expected paths are the published ones: BIP48, BIP87, BIP45, BIP44, BIP49,
// BIP84 and BIP86, independent of the app.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadSource(name, opener) {
  const start = app.indexOf(opener);
  assert.ok(start >= 0, `missing ${name}`);
  let depth = 0;
  for (let i = app.indexOf(opener.endsWith("[") ? "[" : ") {", start) + (opener.endsWith("[") ? 0 : 2); i < app.length; i++) {
    if (app[i] === "{" || app[i] === "[") depth++;
    else if ((app[i] === "}" || app[i] === "]") && --depth === 0) return app.slice(start, i + 1);
  }
  throw new Error(`unterminated ${name}`);
}
const names = ["hodlMsigSpecsFor", "hodlMsigSpec", "hodlMsigSpecFromOrigin", "hodlMsigSpecComponents", "hodlMsigSpecStepLabels"];
const hodlNormalizeOriginPath = new Function(`${loadSource("hodlNormalizeOriginPath", "function hodlNormalizeOriginPath(")}; return hodlNormalizeOriginPath;`)();
const api = new Function("hodlNormalizeOriginPath", "hodlTText", `${loadSource("hodlMsigSpecs", "const hodlMsigSpecs = [")};\n${names.map((name) => loadSource(name, `function ${name}(`)).join("\n")}; return { ${names.join(", ")} };`)(hodlNormalizeOriginPath, (key, vars) => key.replace(/\{(\w+)\}/g, (_, name) => String(vars?.[name])));
const { hodlMsigSpecsFor, hodlMsigSpec, hodlMsigSpecFromOrigin, hodlMsigSpecComponents, hodlMsigSpecStepLabels } = api;

const ALL = { purpose: true, coinType: true, account: true, address: false };
const path = (components) => components && "m" + components.map(({ index, hardened }) => `/${index}${hardened ? "'" : ""}`).join("");
const ids = (kind) => hodlMsigSpecsFor(kind).map((spec) => spec.id);

test("each script type offers exactly the specs that serve it, Custom always", () => {
  assert.deepEqual(ids("p2wsh").sort(), ["bip48", "bip84", "bip87", "custom"]);
  assert.deepEqual(ids("p2sh-p2wsh").sort(), ["bip48", "bip49", "bip87", "custom"]);
  assert.deepEqual(ids("p2sh").sort(), ["bip44", "bip45", "bip87", "custom"]);
  assert.deepEqual(ids("p2tr").sort(), ["bip86", "bip87", "custom"]);
  assert.equal(hodlMsigSpec("custom").purpose, null);
  assert.equal(hodlMsigSpec("nope"), null);
});

test("a spec's template is its published path", () => {
  assert.equal(path(hodlMsigSpecComponents("bip48", "p2wsh", 0, 0, ALL)), "m/48'/0'/0'/2'");
  assert.equal(path(hodlMsigSpecComponents("bip48", "p2sh-p2wsh", 1, 3, ALL)), "m/48'/1'/3'/1'");
  assert.equal(path(hodlMsigSpecComponents("bip87", "p2tr", 0, 5, ALL)), "m/87'/0'/5'");
  assert.equal(path(hodlMsigSpecComponents("bip87", "p2sh", 1, 0, ALL)), "m/87'/1'/0'");
  assert.equal(path(hodlMsigSpecComponents("bip45", "p2sh", 0, 7, ALL)), "m/45'");
  assert.equal(path(hodlMsigSpecComponents("bip44", "p2sh", 0, 2, ALL)), "m/44'/0'/2'");
  assert.equal(path(hodlMsigSpecComponents("bip49", "p2sh-p2wsh", 0, 0, ALL)), "m/49'/0'/0'");
  assert.equal(path(hodlMsigSpecComponents("bip84", "p2wsh", 1, 0, ALL)), "m/84'/1'/0'");
  assert.equal(path(hodlMsigSpecComponents("bip86", "p2tr", 0, 0, ALL)), "m/86'/0'/0'");
  // The purpose, coin-type and account hardening follow the selection; the
  // BIP48 script step is hardened by the specification itself.
  assert.equal(path(hodlMsigSpecComponents("bip48", "p2wsh", 0, 0, { purpose: false, coinType: false, account: false })), "m/48/0/0/2'");
  assert.equal(hodlMsigSpecComponents("custom", "p2wsh", 0, 0, ALL), null);
});

test("a spec names one field per template step; Custom names none", () => {
  assert.equal(hodlMsigSpecStepLabels("bip48").length, 4);
  assert.equal(hodlMsigSpecStepLabels("bip87").length, 3);
  assert.equal(hodlMsigSpecStepLabels("bip84").length, 3);
  assert.equal(hodlMsigSpecStepLabels("bip45").length, 1);
  assert.deepEqual(hodlMsigSpecStepLabels("custom"), []);
  for (const id of ["bip48", "bip87", "bip45", "bip44", "bip49", "bip84", "bip86"]) {
    assert.ok(hodlMsigSpecStepLabels(id).every((label) => typeof label === "string" && label), id);
  }
});

test("a pasted origin pre-selects the spec its purpose names, where that spec serves the script type", () => {
  assert.equal(hodlMsigSpecFromOrigin({ path: "48h/0h/0h/2h" }, "p2wsh"), "bip48");
  assert.equal(hodlMsigSpecFromOrigin({ path: "48/0/0/1h" }, "p2sh-p2wsh"), "bip48");
  assert.equal(hodlMsigSpecFromOrigin({ path: "87h/1h/0h" }, "p2wsh"), "bip87");
  assert.equal(hodlMsigSpecFromOrigin({ path: "87h/0h/0h" }, "p2tr"), "bip87");
  assert.equal(hodlMsigSpecFromOrigin({ path: "45h" }, "p2sh"), "bip45");
  assert.equal(hodlMsigSpecFromOrigin({ path: "84h/0h/0h" }, "p2wsh"), "bip84");
  assert.equal(hodlMsigSpecFromOrigin({ path: "86h/0h/0h" }, "p2tr"), "bip86");
  // A purpose no spec for this script type uses, or none at all, is Custom.
  assert.equal(hodlMsigSpecFromOrigin({ path: "0h" }, "p2wsh"), "custom");
  assert.equal(hodlMsigSpecFromOrigin({ path: "48h/0h/0h/2h" }, "p2tr"), "custom");
  assert.equal(hodlMsigSpecFromOrigin({ path: "45h" }, "p2wsh"), "custom");
  assert.equal(hodlMsigSpecFromOrigin({ path: "84h/0h/0h" }, "p2sh"), "custom");
  assert.equal(hodlMsigSpecFromOrigin({ path: "69420h/0h/0h" }, "p2wsh"), "custom");
  assert.equal(hodlMsigSpecFromOrigin(null, "p2wsh"), "custom");
});
