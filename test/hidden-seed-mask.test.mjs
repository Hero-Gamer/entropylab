// A hidden seed phrase must not give away its words. The mask used to draw
// one bullet per letter of each word, so a screenshot of the hidden card
// showed every word's length: BIP39 words are 3 to 8 letters, and a length
// narrows a word from 2,048 candidates to between 88 and 555 (about 2.3 bits
// per word, 28 bits of a 12-word seed). The hidden field may show how many
// words there are, which its label already says, and nothing else.
//
// Phrases: the published BIP39 vectors (trezor/python-mnemonic).
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
const view = await loadAppFunctions(["hodlSeedPhraseField"], { settable: ["hodlRevealPrivate"] });
delete globalThis.document;
delete globalThis.window;

// Same word count, different word lengths.
const twelve = [
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "legal winner thank year wave sausage worth useful legal winner thank yellow",
  "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
];
const twentyFour = [
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
  "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
];
const label = (count) => `Your seed phrase \xB7 ${count} words`;

test("a hidden seed phrase looks the same whatever its words are", () => {
  view.__set.hodlRevealPrivate(false);
  for (const [count, phrases] of [[12, twelve], [24, twentyFour]]) {
    const hidden = phrases.map((phrase) => view.hodlSeedPhraseField(label(count), phrase));
    assert.deepEqual(new Set(hidden).size, 1, `${count} words: the hidden field depends on the words`);
    for (const phrase of phrases) for (const word of new Set(phrase.split(" "))) assert.ok(!hidden[0].includes(word), `${count} words: the hidden field shows "${word}"`);
  }
});

test("a revealed seed phrase still shows every word in order", () => {
  view.__set.hodlRevealPrivate(true);
  for (const phrase of [...twelve, ...twentyFour]) {
    const html = view.hodlSeedPhraseField(label(phrase.split(" ").length), phrase);
    const shown = [...html.matchAll(/>([a-z]+)</g)].map((match) => match[1]);
    assert.deepEqual(shown, phrase.split(" "));
  }
});
