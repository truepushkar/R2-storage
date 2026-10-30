// Rebuilds worker.js from the source fragments in this folder.
// Usage: node build/assemble.js
const fs = require("fs");
const path = require("path");
const d = __dirname;
const root = path.join(d, "..");

const css = fs.readFileSync(path.join(d, "01-css.txt"), "utf8");
const clientHome = fs.readFileSync(path.join(d, "client", "home.js"), "utf8");
const clientDash = fs.readFileSync(path.join(d, "client", "dashboard.js"), "utf8");

// Escape for splicing INSIDE a template literal in the generated Worker.
function forTemplate(s) {
  return s.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$\{/g, "\\${");
}

const parts = [
  "00-backend.js",
  "02-shell.js",
  "03-home.js",
  "05-docs.js",
  "06-status-preview.js",
  "07-dashboard.js",
];

let out = "";
for (const part of parts) {
  let text = fs.readFileSync(path.join(d, part), "utf8");
  text = text.replace(String.fromCharCode(34) + "__CSS__" + String.fromCharCode(34), JSON.stringify(css));
  text = text.split("$" + "{CLIENT_HOME}").join(forTemplate(clientHome));
  text = text.split("$" + "{CLIENT_DASH}").join(forTemplate(clientDash));
  out += text + "\n";
}

fs.writeFileSync(path.join(root, "worker.js"), out);
console.log("worker.js rebuilt:", out.length, "chars");