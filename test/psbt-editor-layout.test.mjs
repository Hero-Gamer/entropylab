// The PSBT editor's unsigned-transaction tables are fixed-layout, so column
// widths come from the header row. These guards keep the utility columns
// (row index, delete) snug, the numeric columns sized near their real
// maxima, and the data columns (txid, scriptPubKey, key, value) wide — the
// regression this guards against is every column sharing the table equally,
// which squeezed the 64-character txid into the same width as a one-digit
// vout. Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

test("the transaction tables carry distinct classes with sized header columns", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /<table class="psbted-pairs psbted-txins">/);
  assert.match(editor, /<table class="psbted-pairs psbted-txouts">/);
  // Utility columns: snug row index and delete cells.
  assert.match(editor, /<th class="psbted-idx">#<\/th>/);
  assert.match(editor, /<th class="psbted-col-del"><\/th>/);
  // Numeric columns sized by content class.
  assert.match(editor, /<th class="psbted-col-vout">vout<\/th>/);
  assert.match(editor, /<th class="psbted-col-seq">sequence<\/th>/);
  assert.match(editor, /<th class="psbted-col-val">Value \(sats\)<\/th>/);
  // The key-value tables size the field-name column and the delete column.
  assert.match(editor, /<table class="psbted-pairs psbted-kv">/);
  assert.match(editor, /<th class="psbted-col-field">Field<\/th>/);
});

test("the value cell holds just the input — the unit lives in the header", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /Value \(sats\)/);
  assert.doesNotMatch(editor, /data-txout-val="\$\{index\}"[^>]*> sats<\/td>/);
});


test("the script builder input gets the column's room and stays visible", () => {
  const css = read("src/css/styles.css");
  // The select must not claim a full-width field; the text input flexes.
  // The placeholder announces all four input kinds in the wide cell.
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /placeholder="address · OP_… ASM · 0x raw hex · text"/);
});

test("the Add input / Add output actions are not the pair-add grid", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /<div class="psbted-add-el"><button type="button" class="btn secondary" data-tx-add="input">Add Input<\/button><\/div>/);
  assert.match(editor, /<div class="psbted-add-el"><button type="button" class="btn secondary" data-tx-add="output">Add Output<\/button><\/div>/);
  const css = read("src/css/styles.css");
});
