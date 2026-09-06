import fs from "node:fs";
const path = "src/css/styles.css";
let css = fs.readFileSync(path, "utf8");
const marker = "\n/* BIP-322 verifier state and detail styling. */\n";
if (!css.includes(marker)) {
  css += `${marker}.bip322-state { display: inline-flex; align-items: center; width: fit-content; margin: 1rem 0 .75rem; padding: .35rem .65rem; border: 1px solid var(--border); border-radius: 999px; font-weight: 700; }\n.bip322-state[data-state=\"valid\"] { border-color: var(--good); color: var(--good); }\n.bip322-state[data-state=\"inconclusive\"] { border-color: var(--warn); color: var(--warn); }\n.bip322-state[data-state=\"invalid\"] { border-color: var(--bad); color: var(--bad); }\n.bip322-details { display: grid; grid-template-columns: minmax(9rem, max-content) 1fr; gap: .4rem .9rem; margin: .75rem 0; }\n.bip322-details dt { font-weight: 700; color: var(--muted); }\n.bip322-details dd { margin: 0; overflow-wrap: anywhere; }\n.bip322-warning { margin: .75rem 0; padding: .75rem; border: 1px solid var(--warn); border-radius: 10px; }\n.bip322-claims { margin: .75rem 0; padding-left: 1.25rem; }\n`;
  fs.writeFileSync(path, css);
}
