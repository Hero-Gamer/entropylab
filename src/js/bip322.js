// Thin BIP-322 UI/API wrapper. Cryptographic verification stays in the
// pinned Rust/WASM implementation; this module only validates inputs and
// normalizes deterministic errors/results.
import { bip322WasmVerify, psbtWasmReady } from "./psbt-wasm.js";

const MAX_SIGNATURE_BYTES = 2_000_000;

const validateMessage = (message) => {
  if (typeof message !== "string") throw new Error("BIP-322 message must be text.");
};

export const verifyBip322 = async (message, address, signature) => {
  validateMessage(message);
  if (typeof address !== "string" || !address.trim()) throw new Error("BIP-322 address is required.");
  if (typeof signature !== "string" || !signature.trim()) throw new Error("BIP-322 signature is required.");
  if (signature.length > MAX_SIGNATURE_BYTES) throw new Error("BIP-322 signature is too large.");
  await psbtWasmReady;
  const result = bip322WasmVerify(message, address.trim(), signature.trim());
  if (!result || typeof result !== "object") throw new Error("BIP-322 verifier returned an invalid result.");
  if (!["valid", "inconclusive", "invalid"].includes(result.state)) throw new Error("BIP-322 verifier returned an unknown state.");
  return result;
};

export const bip322StateLabel = (state) => ({
  valid: "Valid",
  inconclusive: "Inconclusive",
  invalid: "Invalid",
}[state] || "Invalid");
