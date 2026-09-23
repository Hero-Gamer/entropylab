// Tests for the pure half of src/js/address-qr.js — the per-row QR button
// markup. initAddressQr is DOM-bound and covered by the browser suite
// (test/browser-suite.html), which drives a row button through the overlay.
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { addressQrButtonHtml } from "../src/js/address-qr.js";

const ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

test("an empty address renders no button", () => {
  assert.equal(addressQrButtonHtml(""), "");
  assert.equal(addressQrButtonHtml(null), "");
  assert.equal(addressQrButtonHtml(undefined), "");
});

test("the button carries the address and label in data attributes", () => {
  const html = addressQrButtonHtml(ADDRESS, "Address #3");
  assert.match(html, /^<button type="button" class="addr-qr no-print" /);
  assert.ok(html.includes(`data-address-qr="${ADDRESS}"`), "address missing from the button");
  assert.ok(html.includes(`data-address-qr-label="Address #3"`), "label missing from the button");
  assert.ok(html.includes('aria-label="Show QR code for Address #3"'), "aria-label missing");
  assert.ok(html.endsWith(">QR</button>"), "button text missing");
});

test("a missing label falls back to the address itself", () => {
  const html = addressQrButtonHtml(ADDRESS);
  assert.ok(html.includes(`data-address-qr-label="${ADDRESS}"`));
});

test("markup from a hostile value stays inert", () => {
  const hostile = `"><img src=x onerror=alert(1)>`;
  const html = addressQrButtonHtml(hostile, 'key "quoted"');
  assert.ok(!html.includes("<img"), "unescaped markup in button");
  assert.ok(html.includes("&lt;img"), "value was not escaped");
  assert.ok(html.includes("key &quot;quoted&quot;"), "label was not escaped");
});

test("a payload can ask the overlay for an animated sequence", () => {
  // A PSBT is larger than one code can hold, so its button opts in; an
  // address does not, and must not gain the attribute by default.
  assert.ok(!addressQrButtonHtml(ADDRESS, "Address #3").includes("data-address-qr-animate"), "an address asked to animate");
  const psbt = addressQrButtonHtml("cHNidP8BAHE", "Edited PSBT (base64)", { animate: "psbt" });
  assert.ok(psbt.includes('data-address-qr-animate="psbt"'), "the PSBT button does not ask for a sequence");
  // The kind is attribute data like any other: it escapes.
  assert.ok(addressQrButtonHtml("x", "y", { animate: '"><img src=x>' }).includes("&quot;&gt;&lt;img"), "animate kind was not escaped");
});
