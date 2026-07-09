"use strict";

const fs = require("node:fs");
const path = require("node:path");

if (process.env.WHOATHERE_INERT_FIXTURE !== "1") {
  throw new Error("inert fixture execution gate is closed");
}

const output = process.env.WHOATHERE_INERT_CANARY_OUTPUT;
if (!output || !path.isAbsolute(output)) {
  throw new Error("an explicit absolute inert-fixture output path is required");
}

fs.writeFileSync(output, `${process.argv[2] || "unknown"}\n`, { flag: "wx", mode: 0o600 });
