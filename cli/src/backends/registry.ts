import { existsSync, realpathSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { awsWorkloadArchitecture, loadConfigAt, type QmConfig } from "../config.ts";
import { CliError, errMessage, note } from "../log.ts";
import type { Target } from "../providers.ts";
import { syncDeploymentLayer, type DeploymentLayerTransport } from "../deployment-layer.ts";
import { TARGET_ENV_DEFAULTS, type TargetEnvDefaults } from "../target-env-defaults.ts";
import { computedSecrets } from "../secrets.ts";
import { renderTerraformVars } from "../terraform.ts";
import {
  buildAwsMicrovmImage,
  deleteAwsMicrovmImage,
  deleteAwsTaskDefinitions,
  microvmBuildArchiveSha256,
} from "../commands/infra.ts";
import { awsScaffold, dockerScaffold, flyScaffold, type ProviderScaffold } from "../provider-scaffold.ts";
import type { ResolvedPlugin } from "../plugins.ts";
import { runnableServices } from "../services.ts";
import {
  awsCheckLive,
  awsDoctor,
  awsDown,
  awsLogs,
  awsRollback,
  awsSecretsPush,
  awsStatus,
  awsUp,
  awsPreflightUp,
  type AwsUpPreflight,
  awsDeploymentLayerTransport,
} from "./aws.ts";
import { dockerDeploymentLayerTransport, dockerDown, dockerLogs, dockerStatus, dockerUp } from "./docker.ts";
import { doctorCommon, localDoctorSecrets } from "./doctor.ts";
import {
  flyCheckLive,
  flyDoctor,
  flyDown,
  flyLogs,
  flyRollback,
  flySecretsPush,
  flyStatus,
  flyUp,
  flyPreflightUp,
  flyDeploymentLayerTransport,
} from "./fly.ts";
import type { Backend, BackendUpOptions } from "./types.ts";
import type { FileIdentity } from "../util.ts";

export interface DeployContext {
  config: QmConfig;
  configPath: string;
  configIdentity: FileIdentity;
  configDir: string;
  sandboxDir: string;
  envFile?: string;
  target: Target;
  awsMicrovmBuildPlanned?: boolean;
  awsPreflight?: AwsUpPreflight;
  flyPreflighted?: boolean;
}

export function assertDeploymentEnvironmentDisjoint(ctx: DeployContext, allowMissing = false): void {
  if (ctx.envFile !== undefined && !ctx.envFile.trim()) {
    throw new CliError("--env-file needs a non-empty path", { clause: "cli.invocation" });
  }
  const environmentPath = resolve(ctx.envFile ?? join(ctx.configDir, ".env"));
  const configPath = resolve(ctx.configPath);
  if (ctx.envFile !== undefined && !existsSync(environmentPath)) {
    if (allowMissing) return;
    throw new CliError(`--env-file not found: ${ctx.envFile}`);
  }
  if (!existsSync(environmentPath)) return;
  const environment = statSync(environmentPath, { bigint: true });
  if (!environment.isFile()) throw new CliError("the deployment environment path must be a regular file");
  if (
    environmentPath === configPath ||
    (existsSync(configPath) && realpathSync(environmentPath) === realpathSync(configPath)) ||
    (environment.dev === ctx.configIdentity.dev && environment.ino === ctx.configIdentity.ino)
  ) {
    throw new CliError("the deployment environment file must be physically disjoint from the deployment config");
  }
}

type InfraOperation = "render" | "build-image" | "delete-image" | "delete-task-definitions";

export interface HostingProvider {
  id: Target;
  /** How this target's CLI reaches the deployed core's /v1/deployment-layer endpoint. */
  deploymentLayerTransport: DeploymentLayerTransport;
  /** Per-target env defaults applied when a service env var is not set explicitly. */
  envDefaults: TargetEnvDefaults;
  /** Optional `qm infra` operations; targets without managed infra omit this. */
  infra?: Partial<Record<InfraOperation, (ctx: DeployContext) => void | Promise<void>>>;
  upFlags: readonly string[];
  upOptions(ctx: DeployContext, flags: Readonly<Record<string, string | boolean>>, dryRun: boolean): BackendUpOptions;
  preflightUp(ctx: DeployContext, opts: BackendUpOptions): Promise<DeployContext>;
  createBackend(ctx: DeployContext): Backend;
  coordinates(config: QmConfig): { accountOrOrganization?: string; region?: string };
  scaffold: ProviderScaffold;
  validateConfig(config: QmConfig, plugins: readonly ResolvedPlugin[]): Array<{ clause: string; message: string }>;
}

export async function prepareUpSubstrate(ctx: DeployContext, opts: BackendUpOptions): Promise<DeployContext> {
  if (opts.buildOnly || (opts.only && !opts.only.includes("core"))) return ctx;
  if (ctx.target === "aws") {
    const targetSource = microvmBuildArchiveSha256();
    const coreEnv = ctx.config.env.core;
    if (
      ctx.awsPreflight?.microvmRebuildRequired ||
      !coreEnv?.AWS_DEPLOY_IMAGE_VERSION?.trim() ||
      coreEnv.AWS_DEPLOY_IMAGE_SOURCE_SHA256 !== targetSource
    ) {
      if (opts.dryRun) {
        return {
          ...ctx,
          config: {
            ...ctx.config,
            env: {
              ...ctx.config.env,
              core: {
                ...coreEnv,
                AWS_DEPLOY_IMAGE_VERSION: "pending-build",
                AWS_DEPLOY_IMAGE_SOURCE_SHA256: targetSource,
              },
            },
          },
          awsMicrovmBuildPlanned: true,
        };
      }
      if (!opts.yes) return ctx;
      await buildAwsMicrovmImage(ctx.config, ctx.configPath);
      const loaded = loadConfigAt(ctx.configPath, { target: ctx.target });
      return {
        ...ctx,
        config: loaded.config,
        configIdentity: loaded.configIdentity,
        ...(ctx.awsPreflight ? { awsPreflight: { ...ctx.awsPreflight, microvmRebuildRequired: false } } : {}),
      };
    }
  }
  return ctx;
}

const stringFlag = (flags: Readonly<Record<string, string | boolean>>, name: string): string | undefined => {
  const value = flags[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !value.trim()) {
    throw new CliError(`--${name} needs a non-empty value`, { clause: "cli.invocation" });
  }
  return value;
};

const buildFromOptions = (
  flags: Readonly<Record<string, string | boolean>>,
): Pick<BackendUpOptions, "buildFrom" | "buildFromPath"> => {
  const value = flags["build-from"];
  if (typeof value === "string" && !value.trim()) {
    throw new CliError("--build-from needs a non-empty path when a value is provided", { clause: "cli.invocation" });
  }
  return {
    buildFrom: value !== undefined,
    ...(typeof value === "string" ? { buildFromPath: value } : {}),
  };
};

const onlyOptions = (flags: Readonly<Record<string, string | boolean>>): string[] | undefined => {
  const raw = stringFlag(flags, "only");
  if (raw === undefined) return undefined;
  const names = raw
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
  if (names.length === 0) throw new CliError(`--only was given no components (e.g. --only core,web-ui)`);
  const duplicate = names.find((name, index) => names.indexOf(name) !== index);
  if (duplicate) throw new CliError(`--only lists ${duplicate} more than once`);
  return names;
};

const docker: HostingProvider = {
  id: "docker",
  deploymentLayerTransport: dockerDeploymentLayerTransport,
  envDefaults: TARGET_ENV_DEFAULTS.docker,
  scaffold: dockerScaffold,
  upFlags: ["build-from", "only"],
  upOptions: (_ctx, flags, dryRun) => {
    if (flags["only"] !== undefined) {
      throw new CliError(
        `--only is not supported for target docker; docker up always reconciles the full local stack`,
        { clause: "cli.invocation" },
      );
    }
    return { dryRun, ...buildFromOptions(flags) };
  },
  preflightUp: async (ctx, _opts) => {
    assertDeploymentEnvironmentDisjoint(ctx);
    return ctx;
  },
  createBackend: (ctx) => {
    const source = {
      configDir: ctx.configDir,
      configPath: ctx.configPath,
      configIdentity: ctx.configIdentity,
      ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
    };
    return {
      up: async (opts) => {
        await dockerUp(ctx.config, source, {
          sandboxDir: ctx.sandboxDir,
          buildFrom: opts.buildFrom ?? false,
          ...(opts.buildFromPath !== undefined ? { buildFromPath: opts.buildFromPath } : {}),
          dryRun: opts.dryRun,
        });
        if (!opts.dryRun) {
          await syncDeploymentLayer({
            config: ctx.config,
            configIdentity: ctx.configIdentity,
            transport: hostingProvider(ctx.target).deploymentLayerTransport,
            configDir: ctx.configDir,
            sandboxDir: ctx.sandboxDir,
            ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
          });
        }
      },
      status: () => dockerStatus(ctx.config, source),
      logs: (service, opts) => dockerLogs(ctx.config, source, service, opts),
      down: (opts) => dockerDown(ctx.config, source, opts),
      rollback: () => {
        throw new CliError("rollback is not implemented for target docker");
      },
      doctor: () =>
        doctorCommon(ctx.config, localDoctorSecrets(ctx.configDir, ctx.envFile, ctx.configIdentity), {
          requiredSecretValues: true,
          configDir: ctx.configDir,
        }),
      secretsPush: () => {
        computedSecrets(ctx.config);
        note("docker reads .env directly; no secret upload is needed");
      },
    };
  },
  coordinates: () => ({}),
  validateConfig: () => [],
};

const fly: HostingProvider = {
  id: "fly",
  deploymentLayerTransport: flyDeploymentLayerTransport,
  envDefaults: TARGET_ENV_DEFAULTS.fly,
  scaffold: flyScaffold,
  upFlags: ["build-from", "only", "image-label", "image-from", "image-repo-prefix", "build-only"],
  upOptions: (_ctx, flags, dryRun) => {
    const only = onlyOptions(flags);
    const imageFrom = stringFlag(flags, "image-from");
    const imageLabel = stringFlag(flags, "image-label");
    const imageRepoPrefix = stringFlag(flags, "image-repo-prefix");
    return {
      dryRun,
      buildOnly: flags["build-only"] === true,
      ...buildFromOptions(flags),
      ...(only ? { only } : {}),
      ...(imageFrom ? { imageFrom } : {}),
      ...(imageLabel ? { imageLabel } : {}),
      ...(imageRepoPrefix ? { imageRepoPrefix } : {}),
    };
  },
  preflightUp: async (ctx, opts) => {
    assertDeploymentEnvironmentDisjoint(ctx);
    flyPreflightUp(ctx.config, ctx.configDir, {
      dryRun: opts.dryRun,
      configPath: ctx.configPath,
      configIdentity: ctx.configIdentity,
      ...(opts.buildFrom !== undefined ? { buildFrom: opts.buildFrom } : {}),
      ...(opts.buildFromPath !== undefined ? { buildFromPath: opts.buildFromPath } : {}),
      ...(opts.only ? { only: opts.only } : {}),
      ...(opts.imageFrom ? { imageFrom: opts.imageFrom } : {}),
      ...(opts.imageLabel ? { imageLabel: opts.imageLabel } : {}),
      ...(opts.imageRepoPrefix ? { imageRepoPrefix: opts.imageRepoPrefix } : {}),
      ...(opts.buildOnly ? { buildOnly: true } : {}),
      ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
    });
    return { ...ctx, flyPreflighted: true };
  },
  createBackend: (ctx) => ({
    up: async (opts) => {
      await flyUp(ctx.config, ctx.configDir, {
        dryRun: opts.dryRun,
        configPath: ctx.configPath,
        configIdentity: ctx.configIdentity,
        ...(opts.buildFrom !== undefined ? { buildFrom: opts.buildFrom } : {}),
        ...(opts.buildFromPath !== undefined ? { buildFromPath: opts.buildFromPath } : {}),
        ...(opts.only ? { only: opts.only } : {}),
        ...(opts.imageFrom ? { imageFrom: opts.imageFrom } : {}),
        ...(opts.imageLabel ? { imageLabel: opts.imageLabel } : {}),
        ...(opts.imageRepoPrefix ? { imageRepoPrefix: opts.imageRepoPrefix } : {}),
        ...(opts.buildOnly ? { buildOnly: true } : {}),
        ...(ctx.flyPreflighted ? { preflighted: true } : {}),
        ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
      });
      if (!opts.dryRun && !opts.buildOnly && (!opts.only || opts.only.includes("core"))) {
        await syncDeploymentLayer({
          config: ctx.config,
          configIdentity: ctx.configIdentity,
          transport: hostingProvider(ctx.target).deploymentLayerTransport,
          configDir: ctx.configDir,
          sandboxDir: ctx.sandboxDir,
          ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
          allowUnavailable: true,
        });
      }
    },
    status: () => flyStatus(ctx.config, ctx.configDir),
    logs: (service, opts) => flyLogs(ctx.config, ctx.configDir, service, opts),
    down: () => flyDown(ctx.config, ctx.configDir),
    rollback: (to) => flyRollback(ctx.config, ctx.configPath, to),
    doctor: () => flyDoctor(ctx.config, ctx.configDir, ctx.envFile, ctx.configIdentity),
    secretsPush: (values) => flySecretsPush(ctx.config, ctx.configDir, values),
    checkLive: (opts) => flyCheckLive(ctx.config, ctx.configDir, opts),
  }),
  coordinates: (config) => ({
    ...(config.flyOrg ? { accountOrOrganization: config.flyOrg } : {}),
    ...(config.region ? { region: config.region } : {}),
  }),
  validateConfig: (config) => {
    const errors: Array<{ clause: string; message: string }> = [];
    if (!config.region?.trim())
      errors.push({ clause: "config.v1", message: 'contract config.fly.region: target "fly" requires "region"' });
    if (!config.flyOrg?.trim())
      errors.push({ clause: "config.v1", message: 'contract config.fly.flyOrg: target "fly" requires "flyOrg"' });
    const core = config.env.core ?? {};
    if (core.SNAPSHOT_STORE !== "s3" || core.TRANSFER_STORE !== "s3") {
      errors.push({
        clause: "config.v1",
        message:
          'contract config.fly.durability: a Fly deployment requires env.core.SNAPSHOT_STORE and TRANSFER_STORE to be "s3"',
      });
    }
    if (!core.S3_BUCKET?.trim() || !core.S3_REGION?.trim()) {
      errors.push({
        clause: "config.v1",
        message: "contract config.fly.durability: a Fly deployment requires env.core.S3_BUCKET and S3_REGION",
      });
    }
    return errors;
  },
};

const aws: HostingProvider = {
  id: "aws",
  deploymentLayerTransport: awsDeploymentLayerTransport,
  envDefaults: TARGET_ENV_DEFAULTS.aws,
  infra: {
    render: (ctx) => renderTerraformVars(ctx.config, ctx.configDir),
    "build-image": async (ctx) => {
      await buildAwsMicrovmImage(ctx.config, ctx.configPath);
    },
    "delete-image": (ctx) => deleteAwsMicrovmImage(ctx.config, { configPath: ctx.configPath }),
    "delete-task-definitions": (ctx) => deleteAwsTaskDefinitions(ctx.config),
  },
  scaffold: awsScaffold,
  upFlags: ["build-from", "only", "yes", "image-label"],
  upOptions: (ctx, flags, dryRun) => {
    const only = onlyOptions(flags);
    const unknown = only?.filter((name) => !ctx.config.aws || !Object.hasOwn(ctx.config.aws.services, name)) ?? [];
    if (unknown.length) throw new CliError(`--only has unknown AWS workload(s): ${unknown.join(", ")}`);
    const imageLabel = stringFlag(flags, "image-label");
    return {
      dryRun,
      yes: flags["yes"] === true,
      ...buildFromOptions(flags),
      ...(imageLabel ? { imageLabel } : {}),
      ...(only ? { only } : {}),
    };
  },
  preflightUp: async (ctx, opts) => {
    assertDeploymentEnvironmentDisjoint(ctx);
    return {
      ...ctx,
      awsPreflight: await awsPreflightUp(ctx.config, ctx.configDir, {
        dryRun: opts.dryRun,
        configIdentity: ctx.configIdentity,
        ...(opts.yes !== undefined ? { yes: opts.yes } : {}),
        ...(opts.buildFrom !== undefined ? { buildFrom: opts.buildFrom } : {}),
        ...(opts.buildFromPath !== undefined ? { buildFromPath: opts.buildFromPath } : {}),
        ...(opts.imageLabel ? { imageLabel: opts.imageLabel } : {}),
        ...(opts.only ? { only: opts.only } : {}),
        ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
      }),
    };
  },
  createBackend: (ctx) => ({
    up: (opts) =>
      awsUp(ctx.config, ctx.configDir, {
        dryRun: opts.dryRun,
        configIdentity: ctx.configIdentity,
        ...(opts.yes !== undefined ? { yes: opts.yes } : {}),
        ...(opts.buildFrom !== undefined ? { buildFrom: opts.buildFrom } : {}),
        ...(opts.buildFromPath !== undefined ? { buildFromPath: opts.buildFromPath } : {}),
        ...(opts.imageLabel ? { imageLabel: opts.imageLabel } : {}),
        ...(opts.only ? { only: opts.only } : {}),
        ...(ctx.awsMicrovmBuildPlanned ? { microvmBuildPlanned: true } : {}),
        ...(ctx.awsPreflight ? { preflight: ctx.awsPreflight } : {}),
        sandboxDir: ctx.sandboxDir,
        ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
      }),
    status: () => awsStatus(ctx.config, ctx.configDir),
    logs: (service, opts) => awsLogs(ctx.config, service, opts, ctx.configDir),
    down: () => awsDown(ctx.config, ctx.configDir),
    rollback: (to) =>
      awsRollback(ctx.config, to, {
        configDir: ctx.configDir,
        configIdentity: ctx.configIdentity,
        ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
      }),
    doctor: () => awsDoctor(ctx.config, ctx.configDir),
    secretsPush: (values) => awsSecretsPush(ctx.config, ctx.configDir, values),
    checkLive: (opts) =>
      awsCheckLive(ctx.config, {
        ...opts,
        configDir: ctx.configDir,
        configIdentity: ctx.configIdentity,
        sandboxDir: ctx.sandboxDir,
        ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
      }),
  }),
  coordinates: (config) =>
    config.aws ? { accountOrOrganization: config.aws.accountId, region: config.aws.region } : {},
  validateConfig: (config, plugins) => {
    if (!config.aws) return [];
    const errors: Array<{ clause: string; message: string }> = [];
    const workloads = new Set<string>([...runnableServices(config.services), ...plugins.map((plugin) => plugin.name)]);
    for (const name of workloads) {
      if (!Object.hasOwn(config.aws.services, name)) {
        errors.push({
          clause: "config.v1",
          message: `contract aws.services.${name}: every AWS service and plugin needs ECS/ECR coordinates`,
        });
        continue;
      }
      try {
        awsWorkloadArchitecture(config, name);
      } catch (error) {
        errors.push({ clause: "config.v1", message: `contract ${errMessage(error)}` });
      }
    }
    for (const name of Object.keys(config.aws.services)) {
      if (!workloads.has(name)) {
        errors.push({
          clause: "config.v1",
          message: `contract aws.services.${name}: coordinates do not match an enabled service or discovered plugin`,
        });
      }
    }
    return errors;
  },
};

export const HOSTING_PROVIDERS = { docker, fly, aws } satisfies Record<Target, HostingProvider>;

export const hostingProvider = (target: Target): HostingProvider => HOSTING_PROVIDERS[target];

export const hostingProviderUpFlags = (): string[] => [
  ...new Set(Object.values(HOSTING_PROVIDERS).flatMap((provider) => provider.upFlags)),
];
