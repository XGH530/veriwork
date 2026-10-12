const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.resolve(__dirname, "..");
global.window = {};
global.document = {
  querySelector: () => null,
  querySelectorAll: () => [],
  addEventListener: () => {},
  getElementById: () => null
};
global.performance = { now: () => Date.now() };
global.localStorage = { getItem: () => null, setItem: () => {} };
global.location = { protocol: "file:", origin: "file://", search: "" };

vm.runInThisContext(fs.readFileSync(path.join(root, "data.js"), "utf8"), { filename: "data.js" });
vm.runInThisContext(fs.readFileSync(path.join(root, "app.js"), "utf8"), { filename: "app.js" });

let passed = 0;
for (const item of APP_DATA.evaluationCases) {
  const result = window.VeriWork.analyzeContract(item.text, { caseType: "评测样本" });
  const actual = new Set(result.risks.map((risk) => risk.id));
  const missing = item.expected.filter((id) => !actual.has(id));
  if (missing.length === 0) {
    passed += 1;
    console.log(`PASS ${item.id}`);
  } else {
    console.error(`FAIL ${item.id}: missing ${missing.join(",")}; actual ${[...actual].join(",")}`);
  }
}

console.log(`SUMMARY ${passed}/${APP_DATA.evaluationCases.length}`);
process.exitCode = passed === APP_DATA.evaluationCases.length ? 0 : 1;
