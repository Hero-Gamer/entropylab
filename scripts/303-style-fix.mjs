import fs from "node:fs";
const path = "src/css/styles.css";
let css = fs.readFileSync(path, "utf8").replaceAll("var(--good)", "var(--ok)").replaceAll("var(--bad)", "var(--danger)");
fs.writeFileSync(path, css);
