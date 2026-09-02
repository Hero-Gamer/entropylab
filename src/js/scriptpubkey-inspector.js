import {
  Address,
  NETWORK as MAINNET,
  OutScript,
  TEST_NETWORK as TESTNET,
} from "@scure/btc-signer";
import { bech32mDecode, fromWords } from "./bech32.js";
import { addressFromScript } from "./addresses.js";

const REGTEST = { bech32: "bcrt", pubKeyHash: 0x6f, scriptHash: 0xc4 };
const MAX_SCRIPT_BYTES = 10000;
const SCRIPT_TYPE_LABELS = Object.freeze({
  pkh: "P2PKH",
  sh: "P2SH",
  wpkh: "P2WPKH",
  wsh: "P2WSH",
  tr: "P2TR",
  ms: "Bare multisig",
  pk: "Pay to public key (P2PK)",
  p2a: "Pay to Anchor (P2A)",
  tr_ns: "Taproot script path",
  tr_ms: "Taproot multisig script",
  tr_pk: "Taproot P2PK script",
});

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const hexToBytes = (text) => {
  const hex = String(text ?? "").replace(/\s/g, "");
  if (!hex) throw new Error("Script hex is empty.");
  if (hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new Error("Script must be an even number of hexadecimal digits.");
  if (hex.length > MAX_SCRIPT_BYTES * 2) throw new Error(`Script exceeds the ${MAX_SCRIPT_BYTES}-byte inspection limit.`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

const equalBytes = (a, b) => {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

const networkObject = (network) => {
  if (network === "mainnet") return MAINNET;
  if (network === "regtest") return REGTEST;
  return TESTNET; // testnet and signet use the same address parameters.
};

const networkName = (network) => network === "mainnet" ? "mainnet" : network === "regtest" ? "regtest" : "testnet formats";

export const classifyScript = (script) => {
  if (!(script instanceof Uint8Array)) throw new Error("Script must be a Uint8Array.");
  if (!script.length) return { type: "invalid", label: "Empty script", addressable: false };

  try {
    const decoded = OutScript.decode(script);
    const type = String(decoded.type);
    return {
      type,
      label: SCRIPT_TYPE_LABELS[type] || `Recognized output script (${type})`,
      addressable: ["pkh", "sh", "wpkh", "wsh", "tr", "p2a"].includes(type),
    };
  } catch {
    // A byte-valid script need not be an addressable output template. Keep
    // that distinction explicit instead of treating every non-addressable
    // script as malformed.
    if (script[0] === 0x6a) return { type: "op_return", label: "OP_RETURN", addressable: false };
    return { type: "unknown", label: "Unrecognized or unsupported script", addressable: false };
  }
};

export const inspectScriptPubKey = (input, network = "mainnet") => {
  const script = input instanceof Uint8Array ? input : hexToBytes(input);
  const classification = classifyScript(script);
  let address = null;
  if (classification.addressable) {
    address = addressFromScript(script, network === "regtest" ? "testnet" : network === "mainnet" ? "mainnet" : "testnet");
    // rust-bitcoin's current address facade uses testnet parameters for both
    // public test networks. Regtest's distinct bcrt HRP is handled below.
    if (network === "regtest" && classification.type !== "p2a") {
      try {
        const decoded = OutScript.decode(script);
        address = Address(REGTEST).encode(decoded);
      } catch {
        address = null;
      }
    }
    if (network === "regtest" && classification.type === "p2a") address = "bcrt1pfeesnyr2tx";
  }
  return {
    scriptHex: bytesToHex(script),
    ...classification,
    address,
    network: networkName(network),
  };
};

const decodeSilentPayment = (text) => {
  const raw = String(text ?? "").trim();
  if (!/^t?sp1/i.test(raw)) return null;
  const decoded = bech32mDecode(raw.toLowerCase());
  if (!decoded || !["sp", "tsp"].includes(decoded.prefix) || decoded.words[0] !== 0) {
    return { valid: false };
  }
  try {
    const payload = fromWords(decoded.words.slice(1));
    return { valid: payload.length === 66 };
  } catch {
    return { valid: false };
  }
};

export const inspectAddress = (input, network = "mainnet") => {
  const text = String(input ?? "").trim();
  if (!text) return { state: "empty" };

  const silent = decodeSilentPayment(text);
  if (silent) {
    return silent.valid
      ? { state: "silent-payment", address: text.toLowerCase() }
      : { state: "invalid-silent-payment", address: text };
  }

  try {
    const decoded = Address(networkObject(network)).decode(text);
    const script = OutScript.encode(decoded);
    const classification = classifyScript(script);
    return {
      state: "recognized",
      address: text,
      scriptHex: bytesToHex(script),
      type: classification.type,
      label: classification.label,
    };
  } catch {
    return { state: "invalid", address: text };
  }
};

export const compareAddressAndScript = (addressInput, scriptInput, network = "mainnet") => {
  const address = inspectAddress(addressInput, network);
  const script = String(scriptInput ?? "").trim() ? inspectScriptPubKey(scriptInput, network) : null;
  const comparableAddress = address.state === "recognized";
  const comparableScript = script && script.type !== "invalid";
  return {
    address,
    script,
    state: address.state === "silent-payment" || address.state === "invalid-silent-payment"
      ? address.state
      : !comparableAddress || !comparableScript
        ? "incomplete"
        : equalBytes(hexToBytes(address.scriptHex), hexToBytes(script.scriptHex)) ? "match" : "mismatch",
  };
};

const escapeHtml = (value) => String(value ?? "").replace(/[&<>\"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[char]);

const STYLE = `
.scriptpubkey-inspector-launch { margin-left: .75rem; white-space: nowrap; }
.scriptpubkey-inspector { margin: 1rem 0 1.5rem; padding: 1rem; border: 1px solid var(--border, #444); border-radius: 8px; background: var(--panel, transparent); }
.scriptpubkey-inspector[hidden] { display: none; }
.scriptpubkey-inspector-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.scriptpubkey-inspector label { display: block; font-weight: 600; margin-bottom: .35rem; }
.scriptpubkey-inspector textarea, .scriptpubkey-inspector select { width: 100%; box-sizing: border-box; }
.scriptpubkey-inspector textarea { min-height: 7rem; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.scriptpubkey-inspector-output { margin-top: 1rem; }
.scriptpubkey-inspector-row { display: grid; grid-template-columns: minmax(9rem, auto) 1fr; gap: .75rem; padding: .4rem 0; border-bottom: 1px solid var(--border, #444); }
.scriptpubkey-inspector-value { overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.scriptpubkey-inspector-status { margin-top: 1rem; padding: .7rem; border-radius: 6px; font-weight: 700; }
.scriptpubkey-inspector-status[data-state="match"] { border: 1px solid currentColor; }
@media (max-width: 700px) { .scriptpubkey-inspector-grid { grid-template-columns: 1fr; } .scriptpubkey-inspector-launch { margin: .5rem 0 0; } }
`;

const makeInspector = () => {
  if (document.getElementById("scriptpubkey-inspector")) return;
  const workspace = document.getElementById("workspace");
  if (!workspace) return;
  const launch = document.createElement("button");
  launch.type = "button";
  launch.className = "btn secondary scriptpubkey-inspector-launch";
  launch.textContent = "ScriptPubKey inspector";
  launch.setAttribute("aria-expanded", "false");
  launch.setAttribute("aria-controls", "scriptpubkey-inspector");
  workspace.append(launch);

  const panel = document.createElement("section");
  panel.id = "scriptpubkey-inspector";
  panel.className = "scriptpubkey-inspector";
  panel.hidden = true;
  panel.setAttribute("aria-labelledby", "scriptpubkey-inspector-title");
  panel.innerHTML = `
    <h2 id="scriptpubkey-inspector-title">ScriptPubKey inspector</h2>
    <p>Inspect an output script offline and compare it with an ordinary Bitcoin address. A match means only that both inputs resolve to the same scriptPubKey bytes.</p>
    <div class="scriptpubkey-inspector-grid">
      <div>
        <label for="scriptpubkey-inspector-address">Address</label>
        <textarea id="scriptpubkey-inspector-address" autocomplete="off" spellcheck="false" placeholder="bc1q…"></textarea>
      </div>
      <div>
        <label for="scriptpubkey-inspector-script">scriptPubKey hex</label>
        <textarea id="scriptpubkey-inspector-script" autocomplete="off" spellcheck="false" placeholder="0014…"></textarea>
      </div>
    </div>
    <div style="margin-top:.75rem">
      <label for="scriptpubkey-inspector-network">Network</label>
      <select id="scriptpubkey-inspector-network">
        <option value="mainnet">Bitcoin Mainnet</option>
        <option value="testnet">Testnet / Signet</option>
        <option value="regtest">Regtest</option>
      </select>
    </div>
    <div class="scriptpubkey-inspector-output" id="scriptpubkey-inspector-output" aria-live="polite"></div>
    <button type="button" class="btn secondary" id="scriptpubkey-inspector-close">Close</button>
  `;
  workspace.insertAdjacentElement("afterend", panel);

  const style = document.createElement("style");
  style.textContent = STYLE;
  document.head.append(style);

  const addressInput = panel.querySelector("#scriptpubkey-inspector-address");
  const scriptInput = panel.querySelector("#scriptpubkey-inspector-script");
  const networkInput = panel.querySelector("#scriptpubkey-inspector-network");
  const output = panel.querySelector("#scriptpubkey-inspector-output");

  const render = () => {
    const result = compareAddressAndScript(addressInput.value, scriptInput.value, networkInput.value);
    const rows = [];
    if (result.address.state === "recognized") {
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Address type</strong><span>${escapeHtml(result.address.label)}</span></div>`);
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Address → scriptPubKey</strong><span class="scriptpubkey-inspector-value">${escapeHtml(result.address.scriptHex)}</span></div>`);
    } else if (result.address.state === "silent-payment") {
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Address</strong><span>Valid Silent Payment address; it does not directly represent one fixed scriptPubKey.</span></div>`);
    } else if (result.address.state === "invalid-silent-payment") {
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Address</strong><span>Invalid Silent Payment address.</span></div>`);
    } else if (result.address.state !== "empty") {
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Address</strong><span>Invalid or not valid on the selected network.</span></div>`);
    }
    if (result.script) {
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Script type</strong><span>${escapeHtml(result.script.label)}</span></div>`);
      if (result.script.address) rows.push(`<div class="scriptpubkey-inspector-row"><strong>scriptPubKey → address</strong><span class="scriptpubkey-inspector-value">${escapeHtml(result.script.address)}</span></div>`);
    }
    let status = "";
    if (result.state === "match") status = `<div class="scriptpubkey-inspector-status" data-state="match">✓ Address and supplied scriptPubKey match.</div>`;
    else if (result.state === "mismatch") status = `<div class="scriptpubkey-inspector-status">Address and supplied scriptPubKey do not match.</div>`;
    else if (result.state === "silent-payment") status = `<div class="scriptpubkey-inspector-status">Silent Payment address: output derivation is outside this inspector.</div>`;
    else if (result.state === "invalid-silent-payment") status = `<div class="scriptpubkey-inspector-status">Invalid Silent Payment address.</div>`;
    else if (result.script && !result.script.address) status = `<div class="scriptpubkey-inspector-status">The supplied script is valid as hex but has no standard address representation in this inspector.</div>`;
    output.innerHTML = rows.join("") + status;
  };

  [addressInput, scriptInput, networkInput].forEach((input) => input.addEventListener("input", render));
  networkInput.addEventListener("change", render);
  launch.addEventListener("click", () => {
    panel.hidden = false;
    launch.setAttribute("aria-expanded", "true");
    addressInput.focus();
    render();
  });
  panel.querySelector("#scriptpubkey-inspector-close").addEventListener("click", () => {
    panel.hidden = true;
    launch.setAttribute("aria-expanded", "false");
    launch.focus();
  });
};

if (typeof document !== "undefined") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", makeInspector, { once: true });
  else makeInspector();
}
