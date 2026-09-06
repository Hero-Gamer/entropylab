import fs from "node:fs";
const path = "scripts/303-ui-patch.mjs";
let source = fs.readFileSync(path, "utf8");
source = source.replace(
  '          item.textContent = `${claim.outpoint} · ${claim.amount_sat == null ? "amount unavailable" : `${claim.amount_sat} sats`} · ${claim.label}`;',
  '          let amount = claim.amount_sat == null ? "amount unavailable" : String(claim.amount_sat) + " sats";\n          item.textContent = String(claim.outpoint) + " · " + amount + " · " + String(claim.label);',
);
fs.writeFileSync(path, source);
