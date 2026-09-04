import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("the sandbox base permits Claude Code's required install script", () => {
  const dockerfile = readFileSync(new URL("../fly/Dockerfile", import.meta.url), "utf8");
  assert.match(dockerfile, /npm install -g --allow-scripts=@anthropic-ai\/claude-code/);
});

test("the core image hashes every copied runtime artifact after the final COPY", () => {
  const dockerfile = readFileSync(new URL("../deploy/core/Dockerfile", import.meta.url), "utf8");
  const hash = dockerfile.indexOf("RUN find . -type f -exec sha256sum {} +");
  assert.ok(hash > dockerfile.lastIndexOf("COPY "));
});
