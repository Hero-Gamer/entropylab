// Thin BIP-322 UI/API wrapper. Cryptographic verification stays in the
// pinned Rust/WASM implementation; this module only validates inputs and
// normalizes deterministic errors/results.
import { bip322WasmVerify, psbtWasmReady } from "./psbt-wasm.js";

const MAX_MESSAGE_BYTES = 330;
const MAX_SIGNATURE_BYTES = 2_000_000;

const validateMessage = (message) => {
  if (typeof message !== "string") throw new Error("BIP-322 message must be text.");
  const bytes = new TextEncoder().encode(message);
  if (bytes.length < 2 || bytes.length > MAX_MESSAGE_BYTES) throw new Error("BIP-322 message must be 2-330 ASCII bytes.");
  if (![...bytes].every((byte) => byte >= 0x20 && byte <= 0x7e)) throw new Error("BIP-322 message must contain printable ASCII only.");
  if (message.startsWith(" ") || message.endsWith(" ")) throw new Error("BIP-322 message must not begin or end with a space.");
  if (message.includes("   ")) throw new Error("BIP-322 message must not contain three consecutive spaces.");
};

export const verifyBip322 = async (message, addressOrDescriptor, signature) => {
  validateMessage(message);
  if (typeof addressOrDescriptor !== "string" || !addressOrDescriptor.trim()) throw new Error("BIP-322 address or descriptor is required.");
  if (typeof signature !== "string" || !signature.trim()) throw new Error("BIP-322 signature is required.");
  if (signature.length > MAX_SIGNATURE_BYTES) throw new Error("BIP-322 signature is too large.");
  await psbtWasmReady;
  const result = bip322WasmVerify(message, addressOrDescriptor.trim(), signature.trim());
  if (!result || typeof result !== "object") throw new Error("BIP-322 verifier returned an invalid result.");
  if (!["valid", "inconclusive", "invalid"].includes(result.state)) throw new Error("BIP-322 verifier returned an unknown state.");
  return result;
};

export const bip322StateLabel = (state) => ({
  valid: "Valid",
  inconclusive: "Inconclusive",
  invalid: "Invalid",
}[state] || "Invalid");
