import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { hodlLocaleCodes, hodlLocaleIsComplete, hodlNormalizeLocale, t, hodlSetLocale, hodlGetLocale } from "../src/js/i18n.js";
import * as labelTables from "../src/js/i18n-labels.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

test("the English source text is the key: no en.json catalog ships", () => {
  assert.deepEqual(
    readdirSync(join(root, "src/locales")).filter((name) => name === "en.json"),
    [],
    "src/locales/en.json must not exist — English lives at the call site",
  );
});

test("every locale catalog is in exact sync with the extracted source strings", () => {
  // Missing translations and dead entries are both CI failures; run
  // `npm run i18n:sync` after editing UI copy to re-baseline the catalogs.
  execFileSync(process.execPath, [join(root, "scripts/i18n-sync.mjs")], { stdio: "pipe" });
});

test("catalogs are complete: every source string has a non-empty translation", () => {
  // Runtime picker visibility gates on this; the sync script keeps it true.
  for (const code of hodlLocaleCodes) {
    if (code === "en") continue;
    assert.ok(hodlLocaleIsComplete(code), `${code} catalog has empty entries — run npm run i18n:sync and translate`);
  }
});

test("t interpolates placeholders and falls back to the English source", () => {
  hodlSetLocale("en", false);
  assert.equal(t("{n} words", { n: 12 }), "12 words");
  assert.equal(t("This string was never catalogued"), "This string was never catalogued");
});

test("t translates through the active locale catalog", () => {
  const es = JSON.parse(execFileSync("cat", [join(root, "src/locales/es.json")], { encoding: "utf8" }));
  const entry = Object.entries(es).find(([, value]) => value);
  assert.ok(entry, "es catalog is empty");
  hodlSetLocale("es", false);
  assert.equal(t(entry[0]), entry[1]);
  assert.equal(hodlGetLocale(), "es");
  hodlSetLocale("en", false);
  assert.equal(t(entry[0]), entry[0]);
});

test("locale allowlist rejects unknown codes", () => {
  assert.equal(hodlNormalizeLocale("pt-BR"), "en");
  assert.equal(hodlNormalizeLocale("pt"), "pt");
  assert.equal(hodlLocaleIsComplete("en"), true);
});

test("the enum-family label tables are non-empty strings keyed by their enum values", () => {
  assert.equal(labelTables.hodlKeyModeLabels.dice, "Dice rolls");
  assert.equal(labelTables.hodlNetworkNames.regtest, "Regtest");
  assert.ok(Object.keys(labelTables.hodlHexFormatLabels).length >= 6);
  for (const table of Object.values(labelTables)) {
    const walk = (value) => {
      if (typeof value === "string") assert.ok(value.length > 0, "empty label");
      else if (Array.isArray(value)) value.forEach(walk);
      else if (value && typeof value === "object") Object.values(value).forEach(walk);
    };
    walk(table);
  }
});
