// Toolchain pins must agree across the files that carry them, or
// "reproducible build" quietly means something different depending on where
// it runs: the CI workflow's NODE_VERSION drives every GitHub job, the
// Dockerfile's ARG NODE_VERSION drives the dev image, and each crate's
// rust-toolchain.toml drives `npm run build:wasm` (the image's
// `rustup target add --toolchain` must name the same channel). This suite
// owns the agreement; the pins themselves live in those files.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

test("the CI workflow and the Dockerfile pin the same exact Node version", () => {
  const workflow = read(".github/workflows/ci-cd.yml").match(/^  NODE_VERSION: "([^"]+)"$/m);
  const dockerfile = read("Dockerfile").match(/^ARG NODE_VERSION=v(.+)$/m);
  assert.ok(workflow, "ci-cd.yml carries an exact NODE_VERSION pin");
  assert.ok(dockerfile, "Dockerfile carries ARG NODE_VERSION");
  assert.equal(workflow[1], dockerfile[1]);
});

test("all WASM crates and the dev image pin the same Rust channel", () => {
  const channels = ["entropylab-wasm", "psbt-wasm", "vanity-wasm"].map((crate) => {
    const channel = read(`${crate}/rust-toolchain.toml`).match(/^channel = "([^"]+)"$/m);
    assert.ok(channel, `${crate}/rust-toolchain.toml pins a channel`);
    return channel[1];
  });
  assert.equal(new Set(channels).size, 1, "the three crates pin one channel");
  const image = read("Dockerfile").match(/--toolchain (\S+)/);
  assert.ok(image, "Dockerfile adds the wasm target for an explicit toolchain");
  assert.equal(image[1], channels[0]);
});

test("the dev image pins linux/amd64, one Ubuntu snapshot, and exact clang", () => {
  const dockerfile = read("Dockerfile");
  assert.match(dockerfile, /^FROM --platform=linux\/amd64 ubuntu:24\.04@sha256:496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4$/m);
  assert.doesNotMatch(dockerfile, /sha256:69cecf4bbf72d2d44a9eef1b71fb98c7fb973d78af11399deccef19beb008ad9/, "the multi-arch index is not a clang pin");
  assert.match(dockerfile, /^ARG UBUNTU_SNAPSHOT=20260916T000000Z$/m);
  assert.match(dockerfile, /snapshot\.ubuntu\.com\/ubuntu\/\$\{UBUNTU_SNAPSHOT\}/);
  assert.match(dockerfile, /^ARG CLANG_VERSION=1:18\.0-59~exp2$/m);
  assert.match(dockerfile, /^ARG CLANG18_VERSION=1:18\.1\.3-1ubuntu1$/m);
  assert.match(dockerfile, /"clang=\$\{CLANG_VERSION\}"/);
  assert.match(dockerfile, /"clang-18=\$\{CLANG18_VERSION\}"/);
});

test("build-wasm compiles inside that image and stamps the commit time", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const job = workflow.match(/^  build-wasm:\n[\s\S]*?(?=^  [\w-]+:)/m)?.[0] ?? "";
  assert.match(job, /platforms: linux\/amd64/);
  assert.match(job, /docker run --rm --platform linux\/amd64[\s\S]*npm run build:wasm/);
  assert.match(job, /safe\.directory \/workspace/);
  assert.doesNotMatch(job, /rm -rf/, "the runner must not delete root-owned target directories");
  const source = read("scripts/build-wasm.mjs");
  assert.match(source, /safe\.directory=\*/);
  assert.match(source, /SOURCE_DATE_EPOCH/);
  assert.match(source, /--format=%ct/);
});

test("published checksums include the three WASM modules, and reproduce checks the image bytes", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const reproduce = workflow.match(/^  reproduce:\n[\s\S]*?(?=^  [\w-]+:)/m)?.[0] ?? "";
  assert.match(reproduce, /^    needs: \[build-wasm\]/m);
  assert.match(reproduce, /name: entropylab-wasm/);
  assert.match(reproduce, /diff \/tmp\/wasm-first\.hashes \/tmp\/wasm-published\.hashes/);
  assert.match(reproduce, /--platform linux\/amd64/);
});
