# Reproductions

CI proves every build reproducible inside GitHub. The page builds to the same
bytes on the runner and inside the pinned dev image, and the WASM modules build
to the same bytes twice in that image and match the modules CI publishes. What
CI cannot prove is that someone else's machine gets those bytes too. This log
records each rebuild outside GitHub that matched the published hashes, so the
cross-machine claim in SECURITY.md and the README rests on recorded evidence.

To add a row, rebuild a published commit and compare:

- **The page:** check out the commit stamped in the page's footer, run
  `npm ci --ignore-scripts && npm run build` (in the dev image with
  `docker compose run --rm dev`, or on the host), and compare
  `sha256sum entropylab.html` with `SHA256SUMS.txt`.
- **The WASM modules:** at the same commit, run `npm run build:wasm` inside
  the dev image, and compare `sha256sum src/js/*-wasm-b64.js` with
  `WASM-SHA256SUMS.txt`. A host clang is a different compiler, so only a
  rebuild in the image counts.

A row records one match: what was rebuilt, where, and the SHA-256 it matched.

| Date | Commit | Rebuilt | SHA-256 | Environment | By |
|---|---|---|---|---|---|
| 2026-09-29 | `cb55bd9` (v1.0.0) | `entropylab.html`, from the committed WASM modules | `2b9828abadad8030588d2de512d73519f7ce06d3764fd5c3e1caaed34693131a` | Windows 11 Home 10.0.26200, x86_64, Node 24.14.0, on the host (no container) | MrHodlX |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/entropylab-wasm-b64.js`, `npm run build:wasm` | `6c5b1324b3d612eaac81470bbe4aa3a0bf11556b1c5a14a7f2aed5c4922e32df` | the dev image (see the note) in Docker 29.1.3, WSL2 Ubuntu 26.04 on the same laptop | MrHodlX |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/psbt-wasm-b64.js`, `npm run build:wasm` | `98f801939635980600edfe9ab7320ee3f76c046cd2f90baa01a0dcf2defad468` | the dev image (see the note) in Docker 29.1.3, WSL2 Ubuntu 26.04 on the same laptop | MrHodlX |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/vanity-wasm-b64.js`, `npm run build:wasm` | `8f9b26cf68b8f77584564b5ecc957d55db5ec7bcc75f3b1195046f69cb2a57f1` | the dev image (see the note) in Docker 29.1.3, WSL2 Ubuntu 26.04 on the same laptop | MrHodlX |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `entropylab.html`, from the modules rebuilt above | `2b9828abadad8030588d2de512d73519f7ce06d3764fd5c3e1caaed34693131a` | the dev image (see the note) in Docker 29.1.3, WSL2 Ubuntu 26.04 on the same laptop | MrHodlX |

Note: the dev image was built on this machine on 2026-09-24 from the
Dockerfile as it stands at `cb55bd9` (unchanged since `8a9eae4`): Node
v22.23.2, clang 18.1.3, the 20260916 Ubuntu snapshot. Image
`sha256:fc1c4cd530d05822c76e5d8dadb48642bad3eb7df4cc7ce31ae00b404ab9181b`.
The modules were compiled from a clean clone with one cargo job
(`CARGO_BUILD_JOBS=1`, for memory; the job count does not change the
output).
