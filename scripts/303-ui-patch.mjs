import fs from "node:fs";

const appPath = "src/js/app.js";
const shellPath = "src/shell.html";

let app = fs.readFileSync(appPath, "utf8");
let shell = fs.readFileSync(shellPath, "utf8");

if (!app.includes('import { verifyBip322 } from "./bip322.js";')) {
  app = app.replace(
    'import { initPsbtEditor } from "./psbt-editor.js";\n',
    'import { initPsbtEditor } from "./psbt-editor.js";\nimport { verifyBip322 } from "./bip322.js";\n',
  );
}

const oldTabs = 'var hodlWorkspaceTabs = [["calc", "Keys", "Keys"], ["vanity", "Vanity", "Vanity"], ["bip85", "BIP-85", "BIP85"], ["msig", "Multi Signature", "MultiSig"], ["sp", "Silent Payments", "SP"], ["psbt", "PSBT", "PSBT"], ["journal", "Journal", "Journal"]];';
const newTabs = 'var hodlWorkspaceTabs = [["calc", "Keys", "Keys"], ["vanity", "Vanity", "Vanity"], ["bip85", "BIP-85", "BIP85"], ["msig", "Multi Signature", "MultiSig"], ["sp", "Silent Payments", "SP"], ["psbt", "PSBT", "PSBT"], ["bip322", "BIP-322", "BIP322"], ["journal", "Journal", "Journal"]];';
if (!app.includes(newTabs)) app = app.replace(oldTabs, newTabs);

const showMarker = '  document.getElementById("sp-manager").hidden = id !== "sp";';
if (!app.includes('document.getElementById("bip322-manager").hidden')) {
  app = app.replace(showMarker, `${showMarker}\n  document.getElementById("bip322-manager").hidden = id !== "bip322";`);
  app = app.replace('  document.getElementById("sp-card").hidden = id !== "sp";', '  document.getElementById("sp-card").hidden = id !== "sp";\n  document.getElementById("bip322-card").hidden = id !== "bip322";');
  app = app.replace('  ["bip85", "sp", "msig", "calc", "vanity"].forEach((tool) => {', '  ["bip85", "sp", "msig", "calc", "vanity", "bip322"].forEach((tool) => {');
}

if (!app.includes('function hodlInitBip322()')) {
  const initPsbtMarker = 'function hodlInitPsbt() {';
  const fn = String.raw`function hodlInitBip322() {
  let message = document.getElementById("bip322-message");
  let address = document.getElementById("bip322-address");
  let signature = document.getElementById("bip322-signature");
  let verify = document.getElementById("bip322-verify");
  let result = document.getElementById("bip322-result");
  if (!message || !address || !signature || !verify || !result) return;
  let render = (data) => {
    result.replaceChildren();
    let state = document.createElement("p");
    state.className = "bip322-state";
    state.textContent = data.state === "inconclusive" && data.time_locks?.active ? "Inconclusive (T,S)" : data.state === "valid" ? "Valid" : data.state === "inconclusive" ? "Inconclusive" : "Invalid";
    state.dataset.state = data.state;
    result.append(state);
    if (data.error) {
      let error = document.createElement("p");
      error.className = "err";
      error.textContent = data.error;
      result.append(error);
    }
    let fields = [
      ["Prefix", data.prefix],
      ["Message hash", data.message_hash],
      ["Challenge type", data.challenge_type],
      ["0x09 message", data.signed_message_0x09],
      ["nLockTime (T)", data.time_locks?.T ?? data.time_locks?.nLockTime],
      ["nSequence (S)", data.time_locks?.S ?? data.time_locks?.nSequence],
    ];
    let dl = document.createElement("dl");
    dl.className = "bip322-details";
    for (let [label, value] of fields) {
      if (value == null) continue;
      let dt = document.createElement("dt");
      dt.textContent = label;
      let dd = document.createElement("dd");
      dd.textContent = String(value);
      dl.append(dt, dd);
    }
    result.append(dl);
    if (data.prefix === "legacy" && data.state === "valid") {
      let banner = document.createElement("aside");
      banner.className = "bip322-warning";
      banner.textContent = "Legacy P2PKH-only, deprecated — BIP-137 / Electrum style, not generic";
      result.append(banner);
    }
    if (data.prefix === "pof" && data.state !== "invalid") {
      let banner = document.createElement("aside");
      banner.className = "bip322-warning";
      banner.textContent = "Cryptographically valid offline — unspent NOT checked, cluster would leak if pasted online";
      result.append(banner);
      if (Array.isArray(data.pof_claims?.claims)) {
        let claims = document.createElement("ul");
        claims.className = "bip322-claims";
        for (let claim of data.pof_claims.claims) {
          let item = document.createElement("li");
          item.textContent = `${claim.outpoint} · ${claim.amount_sat == null ? "amount unavailable" : `${claim.amount_sat} sats`} · ${claim.label}`;
          claims.append(item);
        }
        result.append(claims);
      }
    }
  };
  verify.onclick = async () => {
    result.replaceChildren();
    let busy = document.createElement("p");
    busy.className = "muted";
    busy.textContent = "Verifying locally…";
    result.append(busy);
    verify.disabled = true;
    try {
      render(await verifyBip322(message.value, address.value, signature.value));
    } catch (error) {
      result.replaceChildren();
      let failure = document.createElement("p");
      failure.className = "err";
      failure.textContent = error instanceof Error ? error.message : String(error);
      result.append(failure);
    } finally {
      verify.disabled = false;
    }
  };
}
`;
  app = app.replace(initPsbtMarker, fn + initPsbtMarker);
}

if (!app.includes('  hodlInitBip322();')) {
  app = app.replace('  hodlInitPsbt();\n', '  hodlInitPsbt();\n  hodlInitBip322();\n');
}

const psbtTab = '<button type="button" class="workspace-tab" role="tab" aria-selected="false" aria-label="PSBT"><span class="workspace-tab-full">PSBT</span><span class="workspace-tab-short">PSBT</span></button>';
const bip322Tab = `${psbtTab}\n        <button type="button" class="workspace-tab" role="tab" aria-selected="false" aria-label="BIP-322"><span class="workspace-tab-full">BIP-322</span><span class="workspace-tab-short">BIP322</span></button>`;
if (!shell.includes('aria-label="BIP-322"')) shell = shell.replace(psbtTab, bip322Tab);

const journalIntro = '    <div class="tool-intro" id="journal-tool-intro" hidden>';
const bip322Intro = `    <div class="tool-intro" id="bip322-tool-intro" hidden>
        <div class="kicker">Verify offline. Sign elsewhere.</div>
        <h2>BIP-322 signed message verifier.</h2>
        <p class="muted tool-intro-note">Verify smp/ful/pof and legacy P2PKH signatures entirely offline. EntropyLab never signs, broadcasts, fetches, or checks the chain. Proof-of-funds amounts are unverified claims only.</p>
      </div>
      <section class="key-manager no-print" id="bip322-manager" hidden></section>
      <section class="card no-print" id="bip322-card" role="tabpanel" hidden>
        <label class="field">Message<textarea id="bip322-message" rows="4" autocomplete="off" spellcheck="false" placeholder="Enter the exact message"></textarea></label>
        <label class="field">Address<input id="bip322-address" type="text" autocomplete="off" spellcheck="false" placeholder="Bitcoin address"></label>
        <label class="field">Signature<textarea id="bip322-signature" rows="8" autocomplete="off" spellcheck="false" placeholder="smp/... · ful/... · pof/... · or legacy base64"></textarea></label>
        <div class="row"><button class="btn" id="bip322-verify" type="button">Verify offline</button></div>
        <div id="bip322-result" aria-live="polite"></div>
        <p class="muted">No network access is used. This verifier does not sign or broadcast. Proof-of-funds cannot establish that UTXOs are unspent, complete, or exclusively owned.</p>
      </section>
`;
if (!shell.includes('id="bip322-card"')) shell = shell.replace(journalIntro, bip322Intro + journalIntro);

fs.writeFileSync(appPath, app);
fs.writeFileSync(shellPath, shell);
