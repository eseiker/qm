import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as contract from "../src/contract.ts";
import type { QmConfig, SandboxConfig } from "../src/contract.ts";

const configWithSandbox = (sandbox: SandboxConfig): QmConfig => ({
  contract: 1,
  orgId: "acme",
  publicUrl: "https://acme.example.com",
  target: "fly",
  services: ["core"],
  plugins: [],
  skills: [],
  env: {},
  imageOverrides: {},
  sandbox,
});

test("contract.d.ts declares exactly the value exports contract.ts provides at runtime", () => {
  const dts = readFileSync(new URL("../src/contract.d.ts", import.meta.url), "utf8");
  const declared = new Set<string>();
  for (const clause of dts.matchAll(/export\s+(type\s+)?\{([^}]*)\}/g)) {
    if (clause[1]) continue;
    for (const item of clause[2]!.split(",")) {
      const name = item.trim();
      if (!name || name.startsWith("type ")) continue;
      declared.add(name.includes(" as ") ? name.split(" as ").pop()!.trim() : name);
    }
  }
  const runtime = Object.keys(contract).sort();
  assert.deepEqual([...declared].sort(), runtime, "contract.d.ts value exports must match contract.ts runtime exports");
});

test("the contract type retains the v0.1.6 sandbox shape", () => {
  const sandbox: SandboxConfig = {
    backend: "sprites",
    app: "acme-sandboxes",
    image: "registry.fly.io/acme-sandboxes:latest",
    baseImage: "ghcr.io/yc-software/qm-sandbox-base:latest",
    env: { TZ: "UTC" },
    secretEnv: ["COMPANY_TOKEN"],
  };
  assert.equal(sandbox.app, "acme-sandboxes");
});

test("contract env derivation enforces the legacy sandbox environment migration boundary", () => {
  assert.deepEqual(
    contract.sandboxCoreEnv(
      configWithSandbox({
        backend: "sprites",
        env: {},
        secretEnv: [],
        baseImage: `ghcr.io/yc-software/qm-sandbox-base@sha256:${"b".repeat(64)}`,
      }),
    ),
    { env: { SANDBOX_BACKEND: "sprites" }, missingSecrets: [] },
  );
  assert.throws(
    () => contract.sandboxCoreEnv(configWithSandbox({ backend: "sprites", env: { TZ: "UTC" } })),
    /sandbox.env from v0.1.6 cannot be migrated automatically.*stage each value.*verify the replacement.*remove sandbox.env.*roll the deployment.*confirm no live references/,
  );
  assert.throws(
    () => contract.sandboxCoreEnv(configWithSandbox({ backend: "sprites", secretEnv: ["TOKEN"] })),
    /sandbox.secretEnv from v0.1.6 cannot be migrated automatically \(TOKEN\).*verify the replacement.*remove sandbox.secretEnv.*roll the deployment.*confirm no live references.*delete Fly secrets FLY_RESIDENT_ENV_TOKEN/,
  );
});
