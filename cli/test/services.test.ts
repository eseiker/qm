import assert from "node:assert/strict";
import { test } from "node:test";
import { effectiveCoreEnvironment } from "../src/config.ts";
import { virtualServiceEnv } from "../src/services.ts";

const envWithPrototypeKey = (value: string, extra: Record<string, string> = {}): Record<string, string> =>
  Object.defineProperty({ ...extra }, "__proto__", {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });

test("virtual service environment preserves prototype-named variables", () => {
  const result = virtualServiceEnv(["core", "slack"], {
    slack: envWithPrototypeKey("virtual", { MODEL_PROVIDER: "anthropic" }),
  });

  assert.equal(Object.getPrototypeOf(result), Object.prototype);
  assert.equal(Object.hasOwn(result, "__proto__"), true);
  assert.equal(result["__proto__"], "virtual");
  assert.equal(result.MODEL_PROVIDER, "anthropic");
});

test("core environment overrides virtual environment including prototype-named variables", () => {
  const result = effectiveCoreEnvironment({
    services: ["core", "slack"],
    env: {
      slack: envWithPrototypeKey("virtual", { MODEL_PROVIDER: "anthropic" }),
      core: envWithPrototypeKey("core", { MODEL_PROVIDER: "openai" }),
    },
  });

  assert.equal(Object.getPrototypeOf(result), Object.prototype);
  assert.equal(Object.hasOwn(result, "__proto__"), true);
  assert.equal(result["__proto__"], "core");
  assert.equal(result.MODEL_PROVIDER, "openai");
});
