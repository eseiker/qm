import { createHash } from "node:crypto";
import { type Target, type QmConfig } from "../config.ts";
import {
  currentDeploymentLayerState,
  deploymentLayerBundle,
  type DeploymentLayerBundle,
  type DeploymentLayerState,
} from "../deployment-layer.ts";
import { CliError, errMessage, header, ok, step } from "../log.ts";
import { parseToolDescriptor, type ToolDescriptor } from "../sandbox-layer.ts";
import type { FileIdentity } from "../util.ts";
import { runChecks } from "./check.ts";
import { hostingProvider } from "../backends/registry.ts";

export function expectedDescriptors(bundle: DeploymentLayerBundle): ToolDescriptor[] {
  return bundle.tools.map((file) => parseToolDescriptor(file.content, file.path));
}

export interface ConformanceDeployment {
  config: QmConfig;
  configIdentity: FileIdentity;
  configDir: string;
  sandboxDir: string;
  target: Target;
  envFile?: string;
}

export async function runConformance(
  deployment: ConformanceDeployment,
  opts: { runtime?: boolean } = {},
): Promise<void> {
  const { config, configIdentity, configDir, sandboxDir, target, envFile } = deployment;
  header(`qm conformance — ${config.orgId}`);
  const checked = runChecks(config, configDir, sandboxDir, { report: false });
  step("config.v1: pass");
  step(`sandbox.descriptors: pass (${checked.layer.tools.length} tools, ${checked.layer.skills.length} skills)`);
  step("secrets.computed-set: pass");
  if (opts.runtime === false) {
    ok("static conformance passed");
    return;
  }
  let live: DeploymentLayerState;
  try {
    live = await currentDeploymentLayerState({
      config,
      configIdentity,
      configDir,
      transport: hostingProvider(target).deploymentLayerTransport,
      ...(envFile !== undefined ? { envFile } : {}),
    });
  } catch (error) {
    throw new CliError(`runtime.layer-resolved: ${errMessage(error)}`);
  }
  const bundle = deploymentLayerBundle(sandboxDir);
  const expectedHash = createHash("sha256").update(JSON.stringify(bundle)).digest("hex");
  if (live.contentHash !== expectedHash) {
    throw new CliError(
      "runtime.layer-resolved: live content hash differs from the directory's complete tools and skills layer",
    );
  }
  if (live.status === "degraded" || live.runtimeContentHash !== expectedHash) {
    throw new CliError(
      "runtime.layer-resolved: the core stores the directory's layer but is still serving a previous resolved layer",
    );
  }
  step("runtime.layer-resolved: pass");
  ok("deployment directory conforms to contract v1");
}
