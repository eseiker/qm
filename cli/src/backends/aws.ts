import { createHash, randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lookup, resolveCname } from "node:dns/promises";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  mkdtempSync,
  openSync,
  readSync,
  rmSync,
  writeFileSync,
  type BigIntStats,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  assertAwsLeaseHeld,
  awsCapture,
  awsCaptureAsync,
  awsCliErrorMatches,
  awsLeaseBoundary,
  awsLeaseOperation,
  awsRunInherit,
  awsRunInheritAsync,
  awsText,
  awsTextAsync,
  deployLocksTable,
  withAwsLease,
} from "../aws-lease.ts";
import { CliError, dim, errMessage, header, note, ok, step, warn } from "../log.ts";
import {
  awsWorkloadArchitecture,
  effectiveDeployAppsDomain,
  effectivePortalPublicUrl,
  isReservedSecretEnvironmentName,
  isDigestPinned,
  sandboxBackend,
  sandboxCoreEnv,
  securityScreenEnv,
  type AwsConfig,
  type QmConfig,
} from "../config.ts";
import { manifestRef } from "../manifest.ts";
import {
  computedSecrets,
  deploymentStoreSecretValue,
  materializeSecretValues,
  runtimeSecretNames,
  secretsForService,
  validateCompleteSecretValues,
  type ComputedSecret,
} from "../secrets.ts";
import {
  brokerWiring,
  brandEnvOf,
  orgEnv,
  runnableServices,
  serviceDef,
  isServiceName,
  isVirtualService,
  virtualServiceEnv,
  type LogOpts,
  type ServiceName,
} from "../services.ts";
import { discoverPlugins, type ResolvedPlugin } from "../plugins.ts";
import {
  assertNoNulSecret,
  assertSecretByteLength,
  canonicalJson,
  capture,
  envNum,
  gitSubprocessEnvironment,
  invalidSecretNames,
  isInvalidSecret,
  isMissingOrPlaceholder,
  processErrorMatches,
  promptHidden,
  readEnvFile,
  resolveBuildRepoRoot,
  sleep,
  streamLabeled,
  type FileIdentity,
} from "../util.ts";
import { doctorCommon } from "./doctor.ts";
import { readRenderedFile } from "../safe-write.ts";
import { awsObjectStoreBucket, declaredVariables, terraformVarsDrift } from "../terraform.ts";
import {
  clearDeploymentLayer,
  currentDeploymentLayerState,
  deploymentLayerBody,
  syncDeploymentLayerBody,
  type DeploymentLayerPrecondition,
  type DeploymentLayerSyncResult,
  type DeploymentLayerState,
  httpDeploymentLayerTransport,
  type DeploymentLayerTransport,
} from "../deployment-layer.ts";
import { buildxInvocation, sourceBuildEnvironment } from "../buildx.ts";

const awsHttpDeploymentLayerTransport = httpDeploymentLayerTransport({
  secretFallback: (config) => {
    if (!config.aws) return undefined;
    const value = awsJson<{ SecretString?: string }>(config.aws, [
      "secretsmanager",
      "get-secret-value",
      "--secret-id",
      `${config.aws.secretsPrefix}CORE_SIGNING_SECRET`,
    ]).SecretString;
    assertNoNulSecret("CORE_SIGNING_SECRET", value);
    return value;
  },
  timeoutMs: 60_000,
});

export const awsDeploymentLayerTransport: DeploymentLayerTransport = async (options) => {
  await awsLeaseBoundary();
  try {
    const result = await awsHttpDeploymentLayerTransport(options);
    await awsLeaseBoundary();
    return result;
  } catch (error) {
    await awsLeaseBoundary();
    throw error;
  }
};
export interface AwsUpOpts {
  dryRun?: boolean;
  yes?: boolean;
  buildFrom?: boolean;
  buildFromPath?: string;
  imageLabel?: string;
  only?: string[];
  sandboxDir?: string;
  envFile?: string;
  configIdentity: FileIdentity;
  microvmBuildPlanned?: boolean;
  preflight?: AwsUpPreflight;
}

export interface AwsUpPreflight {
  microvmRebuildRequired: boolean;
  publicApiUrlNeedsUpdate: boolean;
  secretArns: Record<string, string>;
  secretValues: ReadonlyMap<string, string>;
}

export interface EcsTaskDefinition {
  family: string;
  networkMode: "awsvpc";
  requiresCompatibilities: ["FARGATE"];
  cpu: string;
  memory: string;
  runtimePlatform: { cpuArchitecture: "ARM64" | "X86_64"; operatingSystemFamily: "LINUX" };
  executionRoleArn: string;
  taskRoleArn: string;
  containerDefinitions: Array<Record<string, unknown>>;
}

function requireAws(config: QmConfig): AwsConfig {
  if (!config.aws) throw new CliError('target "aws" requires an aws block');
  return config.aws;
}

type AwsServiceSpec = AwsConfig["services"][string];

function ownAwsServiceSpec(aws: AwsConfig, workload: string): AwsServiceSpec | undefined {
  if (!Object.hasOwn(aws.services, workload)) return undefined;
  const value = (aws.services as Record<string, unknown>)[workload];
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return value as AwsServiceSpec;
}

function awsServiceSpec(aws: AwsConfig, workload: string): AwsServiceSpec {
  const spec = ownAwsServiceSpec(aws, workload);
  if (!spec) throw new CliError(`aws.services.${workload} is missing`);
  return spec;
}

function rdsInstanceIdentifier(aws: AwsConfig): string {
  return aws.rdsInstance ?? `${aws.cluster}-core`;
}

function awsTopology(
  config: QmConfig,
  configDir: string,
): { aws: AwsConfig; workloads: string[]; plugins: ResolvedPlugin[] } {
  const aws = requireAws(config);
  const discovered = discoverPlugins(configDir, config);
  if (discovered.errors.length) throw new CliError(discovered.errors.join("\n"));
  const workloads = [...runnableServices(config.services), ...discovered.plugins.map((plugin) => plugin.name)];
  const enabled = new Set(workloads);
  const stale = Object.keys(aws.services)
    .filter((workload) => !enabled.has(workload))
    .sort();
  const missing = workloads.filter((workload) => !ownAwsServiceSpec(aws, workload));
  if (stale.length || missing.length) {
    const problems = [
      ...(stale.length ? [`disabled workloads: ${stale.join(", ")}`] : []),
      ...(missing.length ? [`missing enabled workloads: ${missing.join(", ")}`] : []),
    ];
    throw new CliError(`aws.services topology mismatch (${problems.join("; ")})`);
  }
  for (const workload of workloads) assertWorkloadSecretDestinations(config, workload);
  return { aws, workloads, plugins: discovered.plugins };
}

function containerSecretNames(service: string, secret: ComputedSecret): string[] {
  const names = runtimeSecretNames(service, secret);
  return names.length ? names : [secret.name];
}

function awsArgs(aws: AwsConfig, args: string[]): string[] {
  assertAwsLeaseHeld();
  return [...args, "--region", aws.region];
}

function awsJson<T>(aws: AwsConfig, args: string[]): T {
  const raw = awsCapture(process.env.AWS_BIN ?? "aws", awsArgs(aws, [...args, "--output", "json"]));
  if (!raw.trim()) return {} as T;
  return JSON.parse(raw) as T;
}

async function awsJsonAsync<T>(aws: AwsConfig, args: string[]): Promise<T> {
  const raw = await awsCaptureAsync(process.env.AWS_BIN ?? "aws", awsArgs(aws, [...args, "--output", "json"]));
  if (!raw.trim()) return {} as T;
  return JSON.parse(raw) as T;
}

function assertAwsCallerAccount(aws: AwsConfig): void {
  const account = awsText(aws, ["sts", "get-caller-identity", "--query", "Account"]);
  if (account !== aws.accountId) {
    throw new CliError(`authenticated to AWS account ${account || "unknown"}, expected ${aws.accountId}`);
  }
}

function registerTaskDefinition(config: QmConfig, file: string): Promise<string> {
  return awsTextAsync(config.aws!, [
    "ecs",
    "register-task-definition",
    "--cli-input-json",
    `file://${file}`,
    "--tags",
    JSON.stringify([
      { key: "ManagedBy", value: "qm-cli" },
      { key: "Deployment", value: config.orgId },
    ]),
    "--query",
    "taskDefinition.taskDefinitionArn",
  ]);
}

function deployImageCoordinates(config: QmConfig): { name: string; version?: string } {
  const name = config.env.core?.AWS_DEPLOY_IMAGE?.trim();
  const version = config.env.core?.AWS_DEPLOY_IMAGE_VERSION?.trim();
  if (!name || isMissingOrPlaceholder(name)) {
    throw new CliError("AWS requires an exact env.core.AWS_DEPLOY_IMAGE coordinate");
  }
  const usableVersion =
    version && version !== "pending-build" && !isMissingOrPlaceholder(version) ? version : undefined;
  if (usableVersion && !/^[1-9][0-9]*$/.test(usableVersion)) {
    throw new CliError("AWS_DEPLOY_IMAGE_VERSION must be a positive integer image version");
  }
  return { name, ...(usableVersion ? { version: usableVersion } : {}) };
}

function microvmImageVersion(value: unknown): string | undefined {
  if (typeof value === "string" && /^[1-9][0-9]*$/.test(value)) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return String(value);
  return undefined;
}

const microvmImageVersionStates = new Set([
  "IN_PROGRESS",
  "SUCCESSFUL",
  "FAILED",
  "DELETING",
  "DELETED",
  "DELETE_FAILED",
]);
const microvmImageVersionStatuses = new Set(["ACTIVE", "INACTIVE"]);

export function guardLambdaMicrovms(e: unknown): never {
  if (processErrorMatches(e, /invalid choice:?\s*'?lambda-microvms/i)) {
    throw new CliError(
      "this AWS CLI lacks the `lambda-microvms` commands needed to build/verify the AWS deploy MicroVM image; install an AWS CLI with Lambda MicroVMs support",
    );
  }
  throw e instanceof Error ? e : new Error(errMessage(e));
}

function awsDeployImageStatus(config: QmConfig): { current: boolean; reason?: string } {
  const aws = requireAws(config);
  const { name, version } = deployImageCoordinates(config);
  const expectedArn = `arn:aws:lambda:${aws.region}:${aws.accountId}:microvm-image:${name}`;
  let image: Record<string, unknown>;
  try {
    image = awsJson<Record<string, unknown>>(aws, [
      "lambda-microvms",
      "get-microvm-image",
      "--image-identifier",
      expectedArn,
    ]);
  } catch (e) {
    if (awsCliErrorMatches(e, "ResourceNotFoundException")) {
      return { current: false, reason: `AWS deploy image ${name} does not exist` };
    }
    guardLambdaMicrovms(e);
  }
  const envelope: unknown = image;
  const detailValue =
    typeof envelope === "object" && envelope !== null && !Array.isArray(envelope)
      ? ((envelope as Record<string, unknown>).image ?? envelope)
      : envelope;
  if (typeof detailValue !== "object" || detailValue === null || Array.isArray(detailValue)) {
    throw new CliError(`AWS deploy image ${name} returned an invalid response without an ARN`);
  }
  const detail = detailValue as Record<string, unknown>;
  const arn = detail.imageArn ?? detail.imageARN ?? detail.arn;
  if (arn !== expectedArn) {
    if (arn === undefined) throw new CliError(`AWS deploy image ${name} returned an invalid response without an ARN`);
    throw new CliError(`AWS deploy image ${name} resolves to ${String(arn)}, expected ${expectedArn}`);
  }
  if (!version) {
    return { current: false, reason: `AWS deploy image ${name} has no recorded AWS_DEPLOY_IMAGE_VERSION` };
  }
  const response = awsJson<{ items?: Array<{ imageVersion?: string | number; state?: string; status?: string }> }>(
    aws,
    ["lambda-microvms", "list-microvm-image-versions", "--image-identifier", expectedArn],
  );
  if (
    !Array.isArray(response.items) ||
    !response.items.every(
      (item) =>
        item !== null &&
        typeof item === "object" &&
        microvmImageVersion(item.imageVersion) !== undefined &&
        typeof item.state === "string" &&
        microvmImageVersionStates.has(item.state) &&
        typeof item.status === "string" &&
        microvmImageVersionStatuses.has(item.status),
    )
  ) {
    throw new CliError(`AWS deploy image ${name} returned an invalid versions response`);
  }
  const versions = response.items;
  const pinned = versions.find((item) => microvmImageVersion(item.imageVersion) === version);
  if (!pinned || pinned.state !== "SUCCESSFUL" || pinned.status !== "ACTIVE") {
    return { current: false, reason: `AWS deploy image ${name} version ${version} is not SUCCESSFUL and ACTIVE` };
  }
  return { current: true };
}

export function awsDeployImageNeedsRebuild(config: QmConfig): boolean {
  return !awsDeployImageStatus(config).current;
}

function assertAwsDeployImage(config: QmConfig): void {
  const status = awsDeployImageStatus(config);
  if (!status.current) throw new CliError(status.reason ?? "AWS deploy image is not ready");
}

function secretValueFrom(config: QmConfig, name: string, arns?: Record<string, string>): string {
  if (arns?.[name]) return arns[name];
  const aws = requireAws(config);
  return `arn:aws:secretsmanager:${aws.region}:${aws.accountId}:secret:${aws.secretsPrefix}${name}`;
}

const forbiddenCoreEndpointNames = new Set(["AGENT_API_URL", "SLACK_API_URL"]);

function withoutAwsEndpointEnvironment(
  config: QmConfig,
  workload: string,
  values: Readonly<Record<string, string>> | undefined,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(values ?? {}).filter(
      ([name]) => !(name.startsWith("AWS_ENDPOINT_URL") && isReservedSecretEnvironmentName(config, workload, name)),
    ),
  );
}

export function serviceEnvironment(config: QmConfig, service: ServiceName): Record<string, string> {
  const aws = requireAws(config);
  const def = serviceDef(service);
  const coreUrl = `http://core.${aws.networking.cloudMapNamespace}:8080`;
  const coreEnv =
    service === "core"
      ? {
          ...(config.model ? { PI_MODEL: config.model } : {}),
          ...(config.modelProvider ? { MODEL_PROVIDER: config.modelProvider } : {}),
          ...virtualServiceEnv(config.services, config.env),
        }
      : {};
  const env: Record<string, string> = {
    ...orgEnv(service, config.orgId, config.publicUrl, config.services.includes("portal"), brandEnvOf(config)),
    ...(service === "core" ? {} : { CORE_API_URL: coreUrl }),
    ...coreEnv,
    ...withoutAwsEndpointEnvironment(config, service, config.env[service]),
    ...(service === "core" ? securityScreenEnv(config) : {}),
  };
  if (service === "core") {
    const stores = {
      DEPLOY_PROVIDER: "aws",
      AWS_DEPLOY_REGION: aws.region,
      SESSION_STORE: "postgres",
      RUN_STORE: "postgres",
      SNAPSHOT_STORE: "s3",
      TRANSFER_STORE: "s3",
      S3_BUCKET: config.env.core?.S3_BUCKET?.trim() || awsObjectStoreBucket(config),
      S3_REGION: aws.region,
    };
    if (!usesAwsMicrovmSandboxes(config)) {
      Object.assign(env, sandboxCoreEnv(config).env, {
        ...stores,
      });
    } else {
      Object.assign(env, {
        SANDBOX_BACKEND: "aws",
        AWS_SANDBOX_REGION: aws.region,
        AWS_SANDBOX_IMAGE: config.env.core?.AWS_DEPLOY_IMAGE ?? "",
        AWS_SANDBOX_IMAGE_VERSION: config.env.core?.AWS_DEPLOY_IMAGE_VERSION ?? "",
        AWS_SANDBOX_EXEC_ROLE_ARN:
          config.env.core?.AWS_DEPLOY_EXEC_ROLE_ARN ?? `arn:aws:iam::${aws.accountId}:role/${aws.cluster}-microvm-exec`,
        AWS_SANDBOX_S3_BUCKET: awsObjectStoreBucket(config),
        ...stores,
      });
    }
  }
  if (service === "portal") {
    env.WEB_UI_UPSTREAM = `http://web-ui.${aws.networking.cloudMapNamespace}:8080`;
    env.ADMIN_UPSTREAM = `http://admin.${aws.networking.cloudMapNamespace}:8080`;
    env.PORTAL_XFF_TRUSTED_HOPS = "1";
    const appsDomain = effectiveDeployAppsDomain(config);
    if (appsDomain) env.DEPLOY_APPS_DOMAIN = appsDomain;
  }
  if (config.services.includes("auth")) {
    Object.assign(
      env,
      brokerWiring(service, {
        publicUrl: effectivePortalPublicUrl(config),
        authBaseUrl: `http://auth.${aws.networking.cloudMapNamespace}:8080`,
        ...(config.env.auth?.AUTH_ALLOWED_EMAIL_DOMAIN
          ? { allowedEmailDomain: config.env.auth.AUTH_ALLOWED_EMAIL_DOMAIN }
          : {}),
      }),
    );
  }
  delete env.REQUIRE_SIGNED_PORTAL_IDENTITY;
  if (config.services.includes("portal") && service === "core") {
    env.REQUIRE_SIGNED_PORTAL_IDENTITY = "1";
  }
  if (service === "core") {
    for (const name of forbiddenCoreEndpointNames) delete env[name];
    env.DATA_DIR = "/data";
  }
  env.NODE_ENV = "production";
  env[def.docker.portEnv] = String(def.docker.internalPort);
  return Object.fromEntries(Object.entries(env).sort(([a], [b]) => a.localeCompare(b)));
}

function workloadEnvironment(config: QmConfig, workload: string): Record<string, string> {
  if (isServiceName(workload)) return serviceEnvironment(config, workload);
  const plugin = config.plugins.find((entry) => entry.name === workload);
  return Object.fromEntries(
    Object.entries({
      CORE_API_URL: `http://core.${requireAws(config).networking.cloudMapNamespace}:8080`,
      ...orgEnv(workload, config.orgId, config.publicUrl, config.services.includes("portal"), brandEnvOf(config)),
      ...withoutAwsEndpointEnvironment(config, workload, plugin?.env),
      NODE_ENV: "production",
      PORT: "8080",
    }).sort(([a], [b]) => a.localeCompare(b)),
  );
}

function allWorkloadSecrets(config: QmConfig, workload: string): ComputedSecret[] {
  const secrets = secretsForService(config, workload);
  if (!isServiceName(workload) && !secrets.some((secret) => secret.name === "CORE_SIGNING_SECRET")) {
    const signing = computedSecrets(config).find((secret) => secret.name === "CORE_SIGNING_SECRET");
    if (signing) return [...secrets, signing];
  }
  return secrets;
}

function workloadSecrets(config: QmConfig, workload: string, available?: Record<string, string>) {
  return allWorkloadSecrets(config, workload).filter((secret) => secret.required || Boolean(available?.[secret.name]));
}

function assertWorkloadSecretDestinations(config: QmConfig, workload: string): void {
  const providerEnvironment = workloadEnvironment(config, workload);
  const enabled = new Set<string>(["core", ...config.services]);
  const configured = Object.entries(config.secretEnv ?? {}).flatMap(([service, entries]) => {
    if (!enabled.has(service) || (isVirtualService(service) ? "core" : service) !== workload) return [];
    return Object.keys(entries ?? {});
  });
  const plugin = config.plugins.find((entry) => entry.name === workload);
  configured.push(...(plugin?.secrets ?? []).map((secret) => secret.name));
  const conflicts = configured.filter(
    (name) =>
      isReservedSecretEnvironmentName(config, workload, name) ||
      Object.hasOwn(providerEnvironment, name) ||
      (workload === "core" && forbiddenCoreEndpointNames.has(name)),
  );
  if (conflicts.length) {
    throw new CliError(
      `AWS secret destinations overlap provider-owned environment for ${workload}: ${[...new Set(conflicts)].sort().join(", ")}`,
    );
  }
}

function workloadArchitecture(config: QmConfig, workload: string): "arm64" | "amd64" {
  requireAws(config);
  return awsWorkloadArchitecture(config, workload);
}

export function renderTaskDefinition(
  config: QmConfig,
  service: string,
  image: string,
  secretArns?: Record<string, string>,
): EcsTaskDefinition {
  if (!isDigestPinned(image)) throw new CliError(`aws task image for ${service} must be pinned by digest`);
  assertWorkloadSecretDestinations(config, service);
  const aws = requireAws(config);
  const spec = awsServiceSpec(aws, service);
  const internalPort = isServiceName(service) ? serviceDef(service).docker.internalPort : 8080;
  const executionRoleArn = spec.executionRoleArn ?? `arn:aws:iam::${aws.accountId}:role/${aws.cluster}-task-execution`;
  const taskRoleArn =
    spec.taskRoleArn ??
    `arn:aws:iam::${aws.accountId}:role/${aws.cluster}-${service === "core" ? "core-task" : "task"}`;
  const secrets = workloadSecrets(config, service, secretArns)
    .flatMap((secret) =>
      containerSecretNames(service, secret).map((name) => ({
        name,
        valueFrom: secretValueFrom(config, secret.name, secretArns),
      })),
    )
    .sort((a, b) => a.name.localeCompare(b.name));
  const healthCheck = isServiceName(service)
    ? {
        command: [
          "CMD",
          "node",
          "-e",
          `fetch('http://127.0.0.1:${internalPort}/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))`,
        ],
        interval: 10,
        timeout: 5,
        retries: 3,
        startPeriod: 30,
      }
    : undefined;
  return {
    family: spec.ecsService,
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: String(spec.cpu),
    memory: String(spec.memory),
    runtimePlatform: {
      cpuArchitecture: workloadArchitecture(config, service) === "arm64" ? "ARM64" : "X86_64",
      operatingSystemFamily: "LINUX",
    },
    executionRoleArn,
    taskRoleArn,
    containerDefinitions: [
      {
        name: service,
        image,
        essential: true,
        environment: Object.entries(workloadEnvironment(config, service)).map(([name, value]) => ({ name, value })),
        secrets,
        portMappings: [{ containerPort: internalPort, hostPort: internalPort, protocol: "tcp" }],
        ...(healthCheck ? { healthCheck } : {}),
        ...(spec.stopTimeout !== undefined ? { stopTimeout: spec.stopTimeout } : {}),
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-group": spec.logGroup ?? `/ecs/${spec.ecsService}`,
            "awslogs-region": aws.region,
            "awslogs-stream-prefix": service,
          },
        },
      },
    ],
  };
}

function ecrHost(aws: AwsConfig): string {
  return `${aws.accountId}.dkr.ecr.${aws.region}.amazonaws.com`;
}

function expectedWorkloadImageRepository(config: QmConfig, workload: string): string {
  const aws = requireAws(config);
  const repository = ownAwsServiceSpec(aws, workload)?.ecrRepository;
  if (!repository) throw new CliError(`aws.services.${workload} is missing`);
  return `${ecrHost(aws)}/${repository}`;
}

export function isPinnedWorkloadImage(config: QmConfig, workload: string, image: string): boolean {
  const repository = expectedWorkloadImageRepository(config, workload).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${repository}@sha256:[0-9a-f]{64}$`).test(image);
}

async function dockerLogin(aws: AwsConfig, buildEnv: NodeJS.ProcessEnv): Promise<void> {
  const password = await awsTextAsync(aws, ["ecr", "get-login-password"]);
  assertNoNulSecret("ECR login password", password);
  const result = await awsLeaseOperation(() =>
    spawnSync("docker", ["login", "--username", "AWS", "--password-stdin", ecrHost(aws)], {
      input: `${password}\n`,
      encoding: "utf8",
      stdio: ["pipe", "inherit", "inherit"],
      env: buildEnv,
    }),
  );
  if (result.status !== 0) throw new CliError("docker login to ECR failed");
}

function sourceImage(config: QmConfig, service: ServiceName): string {
  return config.imageOverrides[service] ?? manifestRef(service);
}

function workloadSourceImage(
  config: QmConfig,
  workload: string,
  plugin: ResolvedPlugin | undefined,
): string | undefined {
  return (
    plugin?.image ??
    config.plugins.find((entry) => entry.name === workload)?.image ??
    (isServiceName(workload) ? sourceImage(config, workload) : undefined)
  );
}

function workloadImageProvenance(
  config: QmConfig,
  workload: string,
  plugin: ResolvedPlugin | undefined,
  opts: Pick<AwsUpOpts, "buildFrom" | "buildFromPath">,
): DeploymentImageProvenance {
  if (plugin?.kind === "source") {
    return { kind: "source-build", source: "plugin" };
  }
  if (opts.buildFrom && isServiceName(workload)) {
    return { kind: "source-build", source: "checkout" };
  }
  const source = workloadSourceImage(config, workload, plugin);
  if (!source) throw new CliError(`AWS workload ${workload} has no source image`);
  return { kind: "configured", source };
}

interface SourceBuildSnapshot {
  root: string;
}

interface AwsSourceBuildAdmission {
  baseEnv: NodeJS.ProcessEnv;
  fileValues: ReadonlyMap<string, string>;
  sensitiveNames: ReadonlySet<string>;
  sensitiveValues: ReadonlySet<string>;
}

function sourceBuildAdmission(
  config: QmConfig,
  configDir: string,
  envFile: string | undefined,
  configIdentity: FileIdentity,
): AwsSourceBuildAdmission {
  const baseEnv = { ...process.env };
  const fileValues = readEnvFile(resolve(envFile ?? join(configDir, ".env")), {
    required: envFile !== undefined,
    protectedIdentity: configIdentity,
  });
  const sensitiveNames = new Set([...computedSecrets(config).map((secret) => secret.name), "DATABASE_URL"]);
  const sensitiveValues = new Set<string>();
  for (const name of sensitiveNames) {
    for (const value of [
      fileValues.get(name),
      baseEnv[name],
      selectedSecretValue(name, fileValues.get(name), baseEnv),
    ]) {
      if (value !== undefined) sensitiveValues.add(value);
    }
  }
  return { baseEnv, fileValues, sensitiveNames, sensitiveValues };
}

function awsSourceBuildEnvironment(
  admission: AwsSourceBuildAdmission,
  remoteValues: ReadonlyMap<string, string>,
): NodeJS.ProcessEnv {
  return sourceBuildEnvironment(admission.baseEnv, {
    sensitiveNames: admission.sensitiveNames,
    sensitiveValues: [...admission.sensitiveValues, ...remoteValues.values()],
  });
}

function sourceBuildSnapshot(
  workload: string,
  plugin: ResolvedPlugin | undefined,
  opts: Pick<AwsUpOpts, "buildFrom" | "buildFromPath">,
): SourceBuildSnapshot | undefined {
  if (plugin?.kind === "source") return { root: plugin.sourceDir! };
  if (opts.buildFrom && isServiceName(workload)) {
    return { root: resolveBuildRepoRoot(opts.buildFromPath, [workload]) };
  }
  return undefined;
}

async function sourceImageDigest(source: string, buildEnv: NodeJS.ProcessEnv): Promise<string> {
  const pinned = source.match(/@(?<digest>sha256:[0-9a-f]{64})$/)?.groups?.digest;
  if (pinned) return pinned;
  const invocation = buildxInvocation(["imagetools", "inspect", source], buildEnv);
  const output = await awsCaptureAsync(invocation.command, invocation.args, { env: invocation.env });
  const digest = output.match(/^Digest:\s*(sha256:[0-9a-f]{64})\s*$/m)?.[1];
  if (!digest) throw new CliError(`registry did not return an immutable digest for AWS source image ${source}`);
  return digest;
}

async function plannedWorkloadImage(
  config: QmConfig,
  workload: string,
  plugin: ResolvedPlugin | undefined,
  buildEnv: NodeJS.ProcessEnv,
): Promise<string> {
  const source = workloadSourceImage(config, workload, plugin);
  if (!source) throw new CliError(`AWS workload ${workload} has no source image`);
  return `${expectedWorkloadImageRepository(config, workload)}@${await sourceImageDigest(source, buildEnv)}`;
}

function workloadBuildArgs(config: QmConfig, workload: string): Record<string, string> {
  return { ...ownAwsServiceSpec(requireAws(config), workload)?.buildArgs };
}

export function imageTransferArgs(source: string, tagged: string): string[] {
  return ["imagetools", "create", "--prefer-index=false", "--tag", tagged, source];
}

async function publishWorkloadImage(
  config: QmConfig,
  workload: string,
  plugin: ResolvedPlugin | undefined,
  label: string,
  opts: AwsUpOpts,
  snapshot: SourceBuildSnapshot | undefined,
  buildEnv: NodeJS.ProcessEnv,
): Promise<string> {
  const aws = requireAws(config);
  const spec = awsServiceSpec(aws, workload);
  const tagged = `${ecrHost(aws)}/${spec.ecrRepository}:${label}`;
  const platform = `linux/${workloadArchitecture(config, workload)}`;
  if (plugin?.kind === "source") {
    const args = [
      "build",
      "--platform",
      platform,
      "--provenance=false",
      "--push",
      "-f",
      plugin.dockerfile!,
      "-t",
      tagged,
    ];
    for (const [name, value] of Object.entries(workloadBuildArgs(config, workload)))
      args.push("--build-arg", `${name}=${value}`);
    args.push(snapshot!.root);
    const invocation = buildxInvocation(args, buildEnv);
    await awsRunInheritAsync(invocation.command, invocation.args, { env: invocation.env });
  } else if (opts.buildFrom && isServiceName(workload)) {
    const root = snapshot!.root;
    const dockerfile = join(root, spec.dockerfile ?? join("deploy", workload, "Dockerfile"));
    if (spec.dockerfile && !existsSync(dockerfile)) {
      throw new CliError(`aws.services.${workload}.dockerfile is missing from the build checkout: ${spec.dockerfile}`);
    }
    const args = ["build", "--platform", platform, "--provenance=false", "--push", "-f", dockerfile, "-t", tagged];
    for (const [name, value] of Object.entries(workloadBuildArgs(config, workload)))
      args.push("--build-arg", `${name}=${value}`);
    args.push(root);
    const invocation = buildxInvocation(args, buildEnv);
    await awsRunInheritAsync(invocation.command, invocation.args, { env: invocation.env });
  } else {
    const source = workloadSourceImage(config, workload, plugin);
    if (!source) throw new CliError(`AWS workload ${workload} has no source image`);
    const invocation = buildxInvocation(imageTransferArgs(source, tagged), buildEnv);
    await awsRunInheritAsync(invocation.command, invocation.args, { env: invocation.env });
  }
  const response = await awsJsonAsync<{ imageDetails?: Array<{ imageDigest?: string }> }>(aws, [
    "ecr",
    "describe-images",
    "--repository-name",
    spec.ecrRepository,
    "--image-ids",
    `imageTag=${label}`,
  ]);
  const digest = response.imageDetails?.[0]?.imageDigest;
  if (!digest) throw new CliError(`ECR did not return a digest for ${tagged}`);
  return `${ecrHost(aws)}/${spec.ecrRepository}@${digest}`;
}

function verifiedAwsSecretArn(aws: AwsConfig, name: string, id: string, arn: unknown): string {
  const prefix = `arn:aws:secretsmanager:${aws.region}:${aws.accountId}:secret:${id}-`;
  if (typeof arn !== "string" || !arn.startsWith(prefix) || !/^[A-Za-z0-9]{6}$/.test(arn.slice(prefix.length))) {
    throw new CliError(`AWS secret ${name} returned an ARN outside the configured account and secret path`);
  }
  return arn;
}

interface AwsSecretSnapshot {
  arns: Record<string, string>;
  publicApiUrlNeedsUpdate: boolean;
  values: ReadonlyMap<string, string>;
}

function awsSecretSnapshot(
  config: QmConfig,
  expectedCoreSigningSecret?: string,
  stagePublicApiUrl = false,
): AwsSecretSnapshot {
  const aws = requireAws(config);
  const secrets = computedSecrets(config);
  const pairs: Array<readonly [string, string]> = [];
  const values = new Map<string, string>();
  const expectedPublicApiUrl = configuredAwsPublicApiUrl(config);
  let publicApiUrlNeedsUpdate = false;
  for (const secret of secrets) {
    const id = `${aws.secretsPrefix}${secret.name}`;
    try {
      const value = awsJson<{ ARN?: string; SecretString?: string }>(aws, [
        "secretsmanager",
        "get-secret-value",
        "--secret-id",
        id,
      ]);
      assertNoNulSecret(secret.name, value.SecretString);
      if (value.SecretString === undefined) {
        if (stagePublicApiUrl && secret.name === "PUBLIC_API_URL" && expectedPublicApiUrl !== undefined) {
          values.set(secret.name, expectedPublicApiUrl);
          publicApiUrlNeedsUpdate = true;
          pairs.push([secret.name, verifiedAwsSecretArn(aws, secret.name, id, value.ARN)]);
          continue;
        }
        if (!secret.required) continue;
        throw new CliError(`required AWS secret ${secret.name} has no usable, non-placeholder AWSCURRENT value`);
      }
      if (stagePublicApiUrl && secret.name === "PUBLIC_API_URL" && expectedPublicApiUrl !== undefined) {
        values.set(secret.name, expectedPublicApiUrl);
        publicApiUrlNeedsUpdate = value.SecretString !== expectedPublicApiUrl;
      } else {
        values.set(secret.name, value.SecretString);
      }
      pairs.push([secret.name, verifiedAwsSecretArn(aws, secret.name, id, value.ARN)]);
    } catch (error) {
      if (
        stagePublicApiUrl &&
        secret.name === "PUBLIC_API_URL" &&
        expectedPublicApiUrl !== undefined &&
        awsCliErrorMatches(error, "ResourceNotFoundException")
      ) {
        const described = awsJson<{ ARN?: unknown }>(aws, ["secretsmanager", "describe-secret", "--secret-id", id]);
        pairs.push([secret.name, verifiedAwsSecretArn(aws, secret.name, id, described.ARN)]);
        values.set(secret.name, expectedPublicApiUrl);
        publicApiUrlNeedsUpdate = true;
        continue;
      }
      if (!secret.required && awsCliErrorMatches(error, "ResourceNotFoundException")) continue;
      throw error;
    }
  }
  const invalid = [...invalidSecretNames(values)].sort();
  if (invalid.length === 1) {
    const name = invalid[0]!;
    const required = secrets.find((secret) => secret.name === name)?.required === true;
    throw new CliError(`${required ? "required " : ""}AWS secret ${name} has no usable runtime value`);
  }
  if (invalid.length) throw new CliError(`AWS secrets failed runtime validation: ${invalid.join(", ")}`);
  materializeSecretValues(config, values, { completeness: "complete", managedBy: "all" });
  if (expectedCoreSigningSecret !== undefined && values.get("CORE_SIGNING_SECRET") !== expectedCoreSigningSecret) {
    throw new CliError(
      "CORE_SIGNING_SECRET selected for deployment does not match its authoritative AWS Secrets Manager value",
    );
  }
  return { arns: Object.fromEntries(pairs), publicApiUrlNeedsUpdate, values };
}

async function ensureAwsPublicApiUrl(config: QmConfig, snapshot: AwsSecretSnapshot): Promise<AwsSecretSnapshot> {
  if (!snapshot.publicApiUrlNeedsUpdate) return snapshot;
  const expected = configuredAwsPublicApiUrl(config);
  if (expected === undefined) return snapshot;
  const aws = requireAws(config);
  const id = `${aws.secretsPrefix}PUBLIC_API_URL`;
  const confirm = (): AwsSecretSnapshot => awsSecretSnapshot(config);
  try {
    await awsTextAsync(
      aws,
      ["secretsmanager", "put-secret-value", "--secret-id", id, "--secret-string", "file:///dev/stdin"],
      { input: expected },
    );
  } catch (error) {
    let confirmed: AwsSecretSnapshot | undefined;
    try {
      confirmed = confirm();
    } catch {
      confirmed = undefined;
    }
    if (confirmed?.values.get("PUBLIC_API_URL") === expected) return confirmed;
    throw error;
  }
  const confirmed = confirm();
  if (confirmed.values.get("PUBLIC_API_URL") !== expected) {
    throw new CliError("AWS did not persist the configured PUBLIC_API_URL value");
  }
  step("PUBLIC_API_URL: updated from the configured public API coordinate");
  return confirmed;
}

function secretArns(config: QmConfig, expectedCoreSigningSecret?: string): Record<string, string> {
  return awsSecretSnapshot(config, expectedCoreSigningSecret).arns;
}

function remoteAwsSecretValues(config: QmConfig, replacements: ReadonlySet<string> = new Set()): Map<string, string> {
  const aws = requireAws(config);
  const values = new Map<string, string>();
  for (const secret of computedSecrets(config)) {
    if (replacements.has(secret.name)) continue;
    const id = `${aws.secretsPrefix}${secret.name}`;
    try {
      const value = awsJson<{ ARN?: unknown; SecretString?: string }>(aws, [
        "secretsmanager",
        "get-secret-value",
        "--secret-id",
        id,
      ]);
      assertNoNulSecret(secret.name, value.SecretString);
      if (value.SecretString !== undefined) {
        verifiedAwsSecretArn(aws, secret.name, id, value.ARN);
        values.set(secret.name, value.SecretString);
      }
    } catch (error) {
      if (!awsCliErrorMatches(error, "ResourceNotFoundException")) throw error;
    }
  }
  return values;
}

function assertAwsSecretReplacementValid(config: QmConfig, replacements: ReadonlyMap<string, string>): void {
  const futureValues = remoteAwsSecretValues(config, new Set(replacements.keys()));
  for (const [name, value] of replacements) futureValues.set(name, value);
  materializeSecretValues(config, futureValues, { completeness: "complete", managedBy: "all" });
}

function assertAwsSecretContainers(aws: AwsConfig, uploads: ReadonlyArray<{ name: string; id: string }>): void {
  for (const secret of uploads) {
    try {
      const value = awsJson<{ ARN?: unknown }>(aws, ["secretsmanager", "describe-secret", "--secret-id", secret.id]);
      verifiedAwsSecretArn(aws, secret.name, secret.id, value.ARN);
    } catch (error) {
      if (awsCliErrorMatches(error, "ResourceNotFoundException")) {
        throw new CliError(
          `AWS secret container ${secret.id} is missing; apply the rendered Terraform before pushing secrets`,
        );
      }
      throw error;
    }
  }
}

function assertAwsPublicApiUrl(config: QmConfig): void {
  const expected = configuredAwsPublicApiUrl(config);
  if (expected === undefined) return;
  const aws = requireAws(config);
  const value = awsText(aws, [
    "secretsmanager",
    "get-secret-value",
    "--secret-id",
    `${aws.secretsPrefix}PUBLIC_API_URL`,
    "--query",
    "SecretString",
  ]);
  assertNoNulSecret("PUBLIC_API_URL", value);
  const bound = config.apiUrl ? ("apiUrl" as const) : ("publicUrl" as const);
  let normalized: string;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:") throw new Error("not HTTPS");
    normalized = parsed.toString().replace(/\/$/, "");
  } catch {
    throw new CliError(`required AWS secret PUBLIC_API_URL must be a valid HTTPS URL equal to the configured ${bound}`);
  }
  if (normalized !== expected) {
    throw new CliError(`required AWS secret PUBLIC_API_URL must equal the configured HTTPS ${bound} (${expected})`);
  }
}

function configuredAwsPublicApiUrl(config: QmConfig): string | undefined {
  if (!computedSecrets(config).some((secret) => secret.name === "PUBLIC_API_URL")) return undefined;
  const bound = config.apiUrl ? ("apiUrl" as const) : ("publicUrl" as const);
  let expected: string;
  try {
    const parsed = new URL(config.apiUrl ?? config.publicUrl);
    if (parsed.protocol !== "https:") throw new Error("not HTTPS");
    expected = parsed.toString().replace(/\/$/, "");
  } catch {
    throw new CliError(`configured AWS ${bound} must be a valid HTTPS URL for PUBLIC_API_URL`);
  }
  return expected;
}

function liveTask(config: QmConfig, service: string): Record<string, unknown> | null {
  const aws = requireAws(config);
  const spec = awsServiceSpec(aws, service);
  const described = awsJson<{ services?: Array<{ taskDefinition?: string }> }>(aws, [
    "ecs",
    "describe-services",
    "--cluster",
    aws.cluster,
    "--services",
    spec.ecsService,
  ]);
  const arn = described.services?.[0]?.taskDefinition;
  if (!arn) return null;
  return (
    awsJson<{ taskDefinition?: Record<string, unknown> }>(aws, [
      "ecs",
      "describe-task-definition",
      "--task-definition",
      arn,
    ]).taskDefinition ?? null
  );
}

function normalizeLiveTask(task: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!task) return null;
  const copy = structuredClone(task);
  for (const key of [
    "taskDefinitionArn",
    "revision",
    "status",
    "requiresAttributes",
    "compatibilities",
    "registeredAt",
    "registeredBy",
    "deregisteredAt",
  ])
    delete copy[key];
  for (const key of ["volumes", "placementConstraints"] as const) {
    if (Array.isArray(copy[key]) && copy[key].length === 0) delete copy[key];
  }
  if (copy.enableFaultInjection === false) delete copy.enableFaultInjection;
  const containers = copy.containerDefinitions;
  if (Array.isArray(containers)) {
    for (const value of containers) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
      const container = value as Record<string, unknown>;
      if (container.cpu === 0) delete container.cpu;
      for (const key of ["mountPoints", "volumesFrom", "systemControls", "resourceRequirements", "ulimits"] as const) {
        if (Array.isArray(container[key]) && container[key].length === 0) delete container[key];
      }
      for (const key of ["environment", "secrets", "portMappings"] as const) {
        if (Array.isArray(container[key])) {
          container[key] = [...container[key]].sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b)));
        }
      }
    }
  }
  if (Array.isArray(copy.requiresCompatibilities)) copy.requiresCompatibilities.sort();
  return copy;
}

function taskReviewShape(task: Record<string, unknown>): Record<string, unknown> {
  const normalized = normalizeLiveTask(task)!;
  const values = Array.isArray(normalized.containerDefinitions) ? normalized.containerDefinitions : [];
  normalized.containerDefinitions = Object.fromEntries(
    values.map((value) => {
      const container = value as Record<string, unknown>;
      const shaped = { ...container };
      for (const field of ["environment", "secrets"] as const) {
        const entries = Array.isArray(shaped[field]) ? (shaped[field] as Array<Record<string, unknown>>) : [];
        shaped[field] = Object.fromEntries(
          entries.map((entry) => [String(entry.name), field === "environment" ? entry.value : entry.valueFrom]),
        );
      }
      return [String(container.name), shaped];
    }),
  );
  return normalized;
}

export interface TaskDefinitionChange {
  path: string;
  live: unknown;
  desired: unknown;
}

function diffTaskValues(desired: unknown, live: unknown, path: string, out: TaskDefinitionChange[]): void {
  if (canonicalJson(desired) === canonicalJson(live)) return;
  if (
    desired &&
    live &&
    typeof desired === "object" &&
    typeof live === "object" &&
    !Array.isArray(desired) &&
    !Array.isArray(live)
  ) {
    const expected = desired as Record<string, unknown>;
    const actual = live as Record<string, unknown>;
    for (const key of [...new Set([...Object.keys(expected), ...Object.keys(actual)])].sort()) {
      diffTaskValues(expected[key], actual[key], path ? `${path}.${key}` : key, out);
    }
    return;
  }
  out.push({
    path,
    live: live === undefined ? "<absent>" : live,
    desired: desired === undefined ? "<absent>" : desired,
  });
}

export function taskDefinitionChanges(
  desired: EcsTaskDefinition,
  live: Record<string, unknown> | null,
): TaskDefinitionChange[] {
  const out: TaskDefinitionChange[] = [];
  diffTaskValues(
    taskReviewShape(desired as unknown as Record<string, unknown>),
    live ? taskReviewShape(live) : null,
    "taskDefinition",
    out,
  );
  return out;
}

export function taskDefinitionDiff(desired: EcsTaskDefinition, live: Record<string, unknown> | null): string[] {
  return taskDefinitionChanges(desired, live).map((change) => change.path);
}

interface EcsDeploymentState {
  id?: string;
  status?: string;
  taskDefinition?: string;
  rolloutState?: string;
  runningCount?: number;
  failedTasks?: number;
}

interface EcsServiceState {
  serviceName?: string;
  status?: string;
  desiredCount?: number;
  runningCount?: number;
  taskDefinition?: string;
  networkConfiguration?: {
    awsvpcConfiguration?: {
      subnets?: string[];
      securityGroups?: string[];
      assignPublicIp?: "ENABLED" | "DISABLED";
    };
  };
  deployments?: EcsDeploymentState[];
  tags?: Array<{ key?: string; value?: string }>;
}

async function awsLiveSession(config: QmConfig, core: EcsServiceState): Promise<void> {
  const aws = requireAws(config);
  if (!core.taskDefinition) throw new Error("core service has no live task definition");
  if (!core.networkConfiguration?.awsvpcConfiguration) throw new Error("core service has no VPC network configuration");
  const started = await awsJsonAsync<{
    tasks?: Array<{ taskArn?: string }>;
    failures?: Array<{ arn?: string; reason?: string; detail?: string }>;
  }>(aws, [
    "ecs",
    "run-task",
    "--cluster",
    aws.cluster,
    "--task-definition",
    core.taskDefinition,
    "--launch-type",
    "FARGATE",
    "--network-configuration",
    JSON.stringify(core.networkConfiguration),
    "--overrides",
    JSON.stringify({
      containerOverrides: [
        {
          name: "core",
          command: [
            "node",
            "src/deployment/postdeploy-smoke.ts",
            "session",
            `http://core.${aws.networking.cloudMapNamespace}:8080`,
          ],
        },
      ],
    }),
    "--count",
    "1",
  ]);
  const taskArn = started.tasks?.[0]?.taskArn;
  if (!taskArn) {
    const failure = started.failures?.[0];
    throw new Error(
      `could not start canary task: ${failure?.reason ?? failure?.detail ?? failure?.arn ?? "no task returned"}`,
    );
  }
  await awsTextAsync(aws, ["ecs", "wait", "tasks-stopped", "--cluster", aws.cluster, "--tasks", taskArn]);
  const stopped = await awsJsonAsync<{
    tasks?: Array<{
      stoppedReason?: string;
      containers?: Array<{ name?: string; exitCode?: number; reason?: string }>;
    }>;
  }>(aws, ["ecs", "describe-tasks", "--cluster", aws.cluster, "--tasks", taskArn]);
  const task = stopped.tasks?.[0];
  const coreContainer = task?.containers?.find((container) => container.name === "core");
  if (coreContainer?.exitCode !== 0) {
    throw new Error(
      `canary task exited ${coreContainer?.exitCode ?? "without a code"}: ${coreContainer?.reason ?? task?.stoppedReason ?? "unknown reason"}`,
    );
  }
}

type DeploymentImageProvenance =
  | { kind: "configured"; source: string }
  | { kind: "source-build"; source?: "plugin" | "checkout"; gitCommit?: string; dirty?: boolean };

interface DeploymentManifest {
  id: string;
  previous?: string;
  createdAt: string;
  imageLabel?: string;
  dbSnapshot?: string;
  tasks: Record<string, string>;
  imageProvenance?: Record<string, DeploymentImageProvenance>;
  layer?: { key: string; sha256: string };
}

const usesAwsMicrovmSandboxes = (config: QmConfig): boolean => sandboxBackend(config) === "aws";

const DEPLOYMENT_POINTER_KEY = "deployment/current";
const DEPLOYMENT_MANIFEST_PREFIX = "deployment/manifest/";
const ECS_SERVICE_BATCH_SIZE = 10;

function chunks<T>(values: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < values.length; i += size) out.push(values.slice(i, i + size));
  return out;
}

function describedServices(config: QmConfig, workloads: string[]): Map<string, EcsServiceState> {
  const aws = requireAws(config);
  const byEcsName = new Map(workloads.map((name) => [awsServiceSpec(aws, name).ecsService, name]));
  const out = new Map<string, EcsServiceState>();
  const failures: string[] = [];
  for (const batch of chunks([...byEcsName.keys()], ECS_SERVICE_BATCH_SIZE)) {
    const response = awsJson<{
      services?: EcsServiceState[];
      failures?: Array<{ arn?: string; reason?: string; detail?: string }>;
    }>(aws, ["ecs", "describe-services", "--cluster", aws.cluster, "--include", "TAGS", "--services", ...batch]);
    for (const service of response.services ?? []) {
      const workload = service.serviceName ? byEcsName.get(service.serviceName) : undefined;
      if (workload) out.set(workload, service);
    }
    for (const failure of response.failures ?? []) {
      failures.push(`${failure.arn ?? "unknown service"}: ${failure.reason ?? failure.detail ?? "describe failed"}`);
    }
  }
  for (const workload of workloads) {
    if (!out.has(workload))
      failures.push(`${awsServiceSpec(aws, workload).ecsService}: missing from DescribeServices response`);
  }
  if (failures.length)
    throw new CliError(`could not describe AWS services:\n${failures.map((failure) => `  - ${failure}`).join("\n")}`);
  return out;
}

function assertOwnedServices(config: QmConfig, states: Map<string, EcsServiceState>, workloads: string[]): void {
  for (const workload of workloads) {
    const service = states.get(workload)!;
    const tags = Object.fromEntries(
      (service.tags ?? []).flatMap((tag) => (tag.key && tag.value ? [[tag.key, tag.value] as const] : [])),
    );
    if (tags["Deployment"] !== config.orgId || tags["ManagedBy"] !== "terraform") {
      throw new CliError(
        `refusing to mutate ${service.serviceName ?? workload}: ownership tags do not match deployment ${config.orgId}`,
      );
    }
  }
}

interface RolloutTarget {
  taskDefinition: string;
  desiredCount: number;
  deploymentId?: string;
}

async function awaitServiceTargets(config: QmConfig, expected: Record<string, RolloutTarget>): Promise<void> {
  const pollMs = envNum("QM_AWS_ROLLOUT_POLL_MS", 15_000);
  const deadline = Date.now() + envNum("QM_AWS_ROLLOUT_DEADLINE_MS", 20 * 60_000);
  let healthyStreak = 0;
  let failurePolls = new Map<string, number>();
  let describeFailures = 0;
  const failing = new Map<string, { polls: number; baseRunning: number }>();
  for (;;) {
    let states: ReadonlyMap<string, EcsServiceState>;
    try {
      states = describedServices(config, Object.keys(expected));
      describeFailures = 0;
    } catch (error) {
      assertAwsLeaseHeld();
      describeFailures += 1;
      if (describeFailures > 2 || Date.now() > deadline) throw error;
      note(`could not poll AWS services (${errMessage(error)}); retrying`);
      await sleep(pollMs);
      continue;
    }
    const failures: Array<{ identity: string; message: string }> = [];
    const fail = (workload: string, kind: string, message: string): void =>
      void failures.push({ identity: `${workload}:${kind}`, message });
    const waiting: string[] = [];
    let draining = 0;
    const failingNow = new Set<string>();
    for (const [workload, want] of Object.entries(expected)) {
      const state = states.get(workload)!;
      const primary = (state.deployments ?? []).filter((deployment) => deployment.status === "PRIMARY");
      const deployment = primary[0];
      const running = deployment?.runningCount ?? 0;
      if (state.status !== "ACTIVE") {
        fail(workload, "service-status", `${workload}: service is ${state.status ?? "missing"}`);
      } else if (
        state.taskDefinition !== want.taskDefinition ||
        primary.length !== 1 ||
        deployment?.taskDefinition !== want.taskDefinition
      ) {
        fail(
          workload,
          "task-definition",
          `${workload}: requested task definition is not the sole PRIMARY deployment (service runs ${state.taskDefinition ?? "no task"} — an ECS circuit-breaker rollback or a concurrent deploy)`,
        );
      } else if (want.deploymentId !== undefined && deployment.id !== want.deploymentId) {
        fail(
          workload,
          "deployment-id",
          `${workload}: PRIMARY deployment is ${deployment.id ?? "unknown"}, expected ${want.deploymentId}`,
        );
      } else if (deployment.rolloutState === "FAILED") {
        fail(
          workload,
          "rollout-failed",
          `${workload}: PRIMARY rollout is FAILED (failedTasks=${deployment.failedTasks ?? 0} — an ECS circuit-breaker abort)`,
        );
      } else if (state.desiredCount !== want.desiredCount) {
        fail(
          workload,
          "desired-count",
          `${workload}: ${state.desiredCount ?? 0} desired, expected ${want.desiredCount}`,
        );
      } else if ((deployment.failedTasks ?? 0) > 0 && running < want.desiredCount) {
        failingNow.add(workload);
        const tracked = failing.get(workload);
        if (!tracked || running > tracked.baseRunning) failing.set(workload, { polls: 1, baseRunning: running });
        else tracked.polls += 1;
        const streak = failing.get(workload)!;
        if (streak.polls >= 4) {
          fail(
            workload,
            "failed-tasks",
            `${workload}: PRIMARY deployment keeps failing tasks with no replacement starting (failedTasks=${deployment.failedTasks}, ${running}/${want.desiredCount} running across ${streak.polls} polls)`,
          );
        } else {
          waiting.push(
            `${workload} (${running}/${want.desiredCount}, ${deployment.failedTasks} failed; awaiting replacement)`,
          );
        }
      } else if (running < want.desiredCount) {
        waiting.push(`${workload} (${running}/${want.desiredCount})`);
      } else if (deployment.rolloutState !== "COMPLETED") {
        draining += 1;
      }
    }
    for (const workload of failing.keys()) {
      if (!failingNow.has(workload)) failing.delete(workload);
    }
    if (failures.length) {
      healthyStreak = 0;
      const next = new Map<string, number>();
      const confirmed: string[] = [];
      for (const failure of failures) {
        const polls = (failurePolls.get(failure.identity) ?? 0) + 1;
        next.set(failure.identity, polls);
        if (polls >= 2) confirmed.push(failure.message);
      }
      failurePolls = next;
      if (confirmed.length || Date.now() > deadline) {
        const fatal = confirmed.length ? confirmed : failures.map((failure) => failure.message);
        throw new CliError(
          `AWS deployment did not reach the requested state:\n${fatal.map((failure) => `  - ${failure}`).join("\n")}`,
        );
      }
      note(`possible rollout failure; confirming: ${failures.map((failure) => failure.message).join("; ")}`);
      await sleep(pollMs);
      continue;
    }
    failurePolls = new Map();
    if (waiting.length === 0) {
      if (draining === 0) return;
      healthyStreak += 1;
      if (healthyStreak >= 3) return;
    } else {
      healthyStreak = 0;
    }
    if (Date.now() > deadline) {
      throw new CliError(
        `timed out waiting for the AWS rollout: ${waiting.length ? `still starting ${waiting.join(", ")}` : "confirming health while old tasks drain"}`,
      );
    }
    note(
      waiting.length
        ? `waiting on ${waiting.join(", ")}`
        : `new tasks healthy; old task(s) still draining protected turns (${healthyStreak}/3)`,
    );
    await sleep(pollMs);
  }
}

function dynamoString(item: Record<string, { S?: string }> | undefined, name: string): string | undefined {
  return item?.[name]?.S;
}

function deploymentManifest(aws: AwsConfig, id: string): DeploymentManifest {
  const response = awsJson<{ Item?: Record<string, { S?: string }> }>(aws, [
    "dynamodb",
    "get-item",
    "--table-name",
    deployLocksTable(aws),
    "--key",
    JSON.stringify({ lockKey: { S: `${DEPLOYMENT_MANIFEST_PREFIX}${id}` } }),
    "--consistent-read",
  ]);
  const raw = dynamoString(response.Item, "manifest");
  if (!raw) throw new CliError(`AWS deployment manifest ${id} is missing`);
  try {
    return JSON.parse(raw) as DeploymentManifest;
  } catch {
    throw new CliError(`AWS deployment manifest ${id} is invalid`);
  }
}

function currentDeploymentManifest(aws: AwsConfig): DeploymentManifest | undefined {
  return deploymentManifestAtPointer(aws, DEPLOYMENT_POINTER_KEY);
}

function deploymentManifestAtPointer(aws: AwsConfig, key: string): DeploymentManifest | undefined {
  const response = awsJson<{ Item?: Record<string, { S?: string }> }>(aws, [
    "dynamodb",
    "get-item",
    "--table-name",
    deployLocksTable(aws),
    "--key",
    JSON.stringify({ lockKey: { S: key } }),
    "--consistent-read",
  ]);
  const id = dynamoString(response.Item, "manifestId");
  return id ? deploymentManifest(aws, id) : undefined;
}

async function manifestTransaction(
  aws: AwsConfig,
  manifest: DeploymentManifest | undefined,
  pointerId: string,
): Promise<void> {
  const table = deployLocksTable(aws);
  const writes: unknown[] = [];
  if (manifest) {
    writes.push({
      Put: {
        TableName: table,
        Item: {
          lockKey: { S: `${DEPLOYMENT_MANIFEST_PREFIX}${manifest.id}` },
          manifest: { S: JSON.stringify(manifest) },
        },
      },
    });
    if (manifest.imageLabel)
      writes.push({
        Put: {
          TableName: table,
          Item: {
            lockKey: { S: `deployment/label/${manifest.imageLabel}` },
            manifestId: { S: manifest.id },
          },
        },
      });
  }
  writes.push({
    Put: {
      TableName: table,
      Item: {
        lockKey: { S: DEPLOYMENT_POINTER_KEY },
        manifestId: { S: pointerId },
      },
    },
  });
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await awsTextAsync(aws, ["dynamodb", "transact-write-items", "--transact-items", JSON.stringify(writes)]);
      return;
    } catch (error) {
      assertAwsLeaseHeld();
      lastError = error;
    }
  }
  throw new CliError(
    `AWS deployment manifest write failed: ${errMessage(lastError)}; run \`qm check --live\` to establish the current manifest before deploying again`,
  );
}

function deploymentManifestForTarget(aws: AwsConfig, target: string): DeploymentManifest {
  const labeled = deploymentManifestAtPointer(aws, `deployment/label/${target}`);
  return labeled ?? deploymentManifest(aws, target);
}

async function recordDeploymentManifest(
  aws: AwsConfig,
  tasks: Record<string, string>,
  release: {
    id?: string;
    imageLabel?: string;
    dbSnapshot?: string;
    layer?: DeploymentManifest["layer"];
    imageProvenance?: DeploymentManifest["imageProvenance"];
  },
): Promise<DeploymentManifest> {
  const current = currentDeploymentManifest(aws);
  const manifest: DeploymentManifest = {
    id: release.id ?? randomUUID(),
    ...(current ? { previous: current.id } : {}),
    createdAt: new Date().toISOString(),
    ...(release.imageLabel ? { imageLabel: release.imageLabel } : {}),
    ...(release.dbSnapshot ? { dbSnapshot: release.dbSnapshot } : {}),
    tasks,
    ...(release.imageProvenance ? { imageProvenance: release.imageProvenance } : {}),
    ...(release.layer ? { layer: release.layer } : {}),
  };
  await manifestTransaction(aws, manifest, manifest.id);
  return manifest;
}

async function putDeploymentLayerArtifact(
  config: QmConfig,
  body: string,
): Promise<NonNullable<DeploymentManifest["layer"]>> {
  if (Buffer.byteLength(body) > 1_000_000)
    throw new CliError("deployment layer exceeds the core API's 1 MB request limit");
  const aws = requireAws(config);
  const sha256 = createHash("sha256").update(body).digest("hex");
  const key = `deployment/layers/${sha256}.json`;
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-"));
  const file = join(dir, "layer.json");
  try {
    writeFileSync(file, body);
    await awsTextAsync(aws, [
      "s3api",
      "put-object",
      "--bucket",
      awsObjectStoreBucket(config),
      "--key",
      key,
      "--body",
      file,
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return { key, sha256 };
}

function getDeploymentLayerArtifact(config: QmConfig, layer: DeploymentManifest["layer"]): string {
  if (!layer) throw new CliError("target AWS deployment manifest has no restorable deployment layer");
  const aws = requireAws(config);
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-"));
  const file = join(dir, "layer.json");
  try {
    awsText(aws, [
      "s3api",
      "get-object",
      "--bucket",
      awsObjectStoreBucket(config),
      "--key",
      layer.key,
      file,
      "--range",
      "bytes=0-1000000",
    ]);
    return readAwsDeploymentLayerArtifact(file, layer.sha256);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function sameAwsArtifactStat(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function readAwsDeploymentLayerArtifact(file: string, expectedHash: string): string {
  let descriptor: number;
  try {
    descriptor = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    throw new CliError("AWS deployment-layer artifact is invalid or does not match its manifest", { cause: error });
  }
  try {
    const initial = fstatSync(descriptor, { bigint: true });
    if (!initial.isFile() || initial.nlink !== 1n || initial.size < 0n || initial.size > 1_000_000n) {
      throw new CliError("AWS deployment-layer artifact is invalid or does not match its manifest");
    }
    const size = Number(initial.size);
    const snapshot = (): Buffer => {
      const bytes = Buffer.allocUnsafe(size + 1);
      let length = 0;
      while (length < bytes.length) {
        const count = readSync(descriptor, bytes, length, bytes.length - length, length);
        if (count === 0) break;
        length += count;
      }
      return bytes.subarray(0, length);
    };
    const first = snapshot();
    const between = fstatSync(descriptor, { bigint: true });
    const second = snapshot();
    const after = fstatSync(descriptor, { bigint: true });
    if (
      !sameAwsArtifactStat(initial, between) ||
      !sameAwsArtifactStat(between, after) ||
      first.length !== size ||
      second.length !== size ||
      !first.equals(second) ||
      createHash("sha256").update(first).digest("hex") !== expectedHash
    ) {
      throw new CliError("AWS deployment-layer artifact is invalid or does not match its manifest");
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(first);
    } catch (error) {
      throw new CliError("AWS deployment-layer artifact is invalid or does not match its manifest", { cause: error });
    }
  } finally {
    closeSync(descriptor);
  }
}

function assertAwsLayerApplied(
  result: DeploymentLayerSyncResult | undefined,
  expected: NonNullable<DeploymentManifest["layer"]> | string,
): void {
  const expectedHash = typeof expected === "string" ? expected : expected.sha256;
  if (!result || result.status === "degraded" || result.durable !== true || result.contentHash !== expectedHash) {
    throw new CliError("AWS deployment layer was not durably applied with the expected content hash");
  }
}

async function retryLiveProbe<T>(probe: () => Promise<T>): Promise<T> {
  const deadline = Date.now() + envNum("QM_AWS_LIVE_PROBE_DEADLINE_MS", 2 * 60_000);
  for (;;) {
    try {
      return await probe();
    } catch (error) {
      assertAwsLeaseHeld();
      if (Date.now() >= deadline) throw error;
      note(`live probe failed (${errMessage(error)}); retrying while old tasks drain`);
      await sleep(envNum("QM_AWS_LIVE_PROBE_POLL_MS", 5_000));
    }
  }
}

async function syncAwsLayerAfterRoll(
  args: Parameters<typeof syncDeploymentLayerBody>[0],
  body: string,
  expected: NonNullable<DeploymentManifest["layer"]> | string,
  operationId: string = randomBytes(16).toString("hex"),
  observe?: (result: DeploymentLayerSyncResult) => void,
): Promise<void> {
  await retryLiveProbe(async () => {
    const result = await syncDeploymentLayerBody({ ...args, operationId }, body);
    if (result) observe?.(result);
    assertAwsLayerApplied(result, expected);
  });
}

async function clearAwsLayerAfterRoll(
  args: Parameters<typeof clearDeploymentLayer>[0],
  expected: string,
): Promise<void> {
  const operationId = randomBytes(16).toString("hex");
  await retryLiveProbe(async () => {
    assertAwsLayerApplied(await clearDeploymentLayer({ ...args, operationId }), expected);
  });
}

function sameLayerPrecondition(left: DeploymentLayerState, right: DeploymentLayerState): boolean {
  return (
    left.precondition.generation === right.precondition.generation &&
    left.precondition.source === right.precondition.source &&
    left.precondition.contentHash === right.precondition.contentHash &&
    left.precondition.operationId === right.precondition.operationId
  );
}

interface AwsLayerAttempt {
  before: DeploymentLayerState;
  desiredHash: string;
  operationId: string;
  applied?: DeploymentLayerPrecondition;
}

function observeAwsLayerAttempt(attempt: AwsLayerAttempt, result: DeploymentLayerSyncResult): void {
  if (!result.changed || result.operationId !== attempt.operationId || result.contentHash !== attempt.desiredHash)
    return;
  attempt.applied = {
    generation: result.version,
    contentHash: result.contentHash,
    source: "durable",
    operationId: result.operationId,
  };
}

async function restoreAwsLayerAfterFailure(
  args: Parameters<typeof currentDeploymentLayerState>[0],
  attempt: AwsLayerAttempt,
  conflict: string,
): Promise<void> {
  const { before, desiredHash, operationId } = attempt;
  let applied = attempt.applied;
  if (!applied) {
    const current = await retryLiveProbe(() => currentDeploymentLayerState(args));
    if (sameLayerPrecondition(current, before)) {
      if (current.status === "applied" && current.runtimeContentHash === before.runtimeContentHash) return;
      if (!before.bootstrapped) {
        await syncAwsLayerAfterRoll({ ...args, precondition: current.precondition }, before.body, before.contentHash);
        return;
      }
    }
    if (
      current.precondition.generation !== before.precondition.generation + 1 ||
      current.precondition.source !== "durable" ||
      current.precondition.contentHash !== desiredHash ||
      current.precondition.operationId !== operationId
    ) {
      throw new CliError(conflict);
    }
    applied = current.precondition;
  }
  if (before.bootstrapped) {
    await clearAwsLayerAfterRoll({ ...args, precondition: applied }, desiredHash);
    return;
  }
  await syncAwsLayerAfterRoll({ ...args, precondition: applied }, before.body, before.contentHash);
}

function throwAfterCompensation(error: unknown, failures: string[]): never {
  if (failures.length) throw new CliError(`${errMessage(error)}; compensation also failed (${failures.join("; ")})`);
  throw error;
}

function workloadDesiredCount(config: QmConfig, workload: string): number {
  return ownAwsServiceSpec(requireAws(config), workload)?.desiredCount ?? 1;
}

function serviceSnapshot(
  config: QmConfig,
  workloads: string[],
): {
  tasks: Record<string, string>;
  counts: Record<string, number>;
} {
  return serviceSnapshotFromStates(describedServices(config, workloads), workloads);
}

function serviceSnapshotFromStates(
  states: ReadonlyMap<string, EcsServiceState>,
  workloads: string[],
): ReturnType<typeof serviceSnapshot> {
  const tasks: Record<string, string> = {};
  const counts: Record<string, number> = {};
  for (const workload of workloads) {
    const state = states.get(workload)!;
    if (!state.taskDefinition) throw new CliError(`${workload}: ECS service has no task definition`);
    tasks[workload] = state.taskDefinition;
    counts[workload] = state.desiredCount ?? 0;
  }
  return { tasks, counts };
}

function taskDefinitionEntries(
  value: unknown,
  valueName: "value" | "valueFrom",
  workload: string,
  action: string,
): Map<string, string> {
  if (!Array.isArray(value)) {
    throw new CliError(`cannot ${action} with an invalid ${workload} task definition`);
  }
  const entries = new Map<string, string>();
  for (const item of value) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new CliError(`cannot ${action} with an invalid ${workload} task definition`);
    }
    const record = item as Record<string, unknown>;
    const name = record.name;
    const entryValue = record[valueName];
    if (typeof name !== "string" || !name || typeof entryValue !== "string" || entries.has(name))
      throw new CliError(`cannot ${action} with an invalid ${workload} task definition`);
    entries.set(name, entryValue);
  }
  return entries;
}

function assertTaskDefinitionReactivatable(
  config: QmConfig,
  workload: string,
  task: Record<string, unknown> | undefined,
  action: string,
): void {
  const containers = task?.containerDefinitions;
  const matches = Array.isArray(containers)
    ? containers.filter(
        (item): item is Record<string, unknown> =>
          typeof item === "object" && item !== null && !Array.isArray(item) && item.name === workload,
      )
    : [];
  const container =
    Array.isArray(containers) && containers.length === 1 && matches.length === 1 ? matches[0] : undefined;
  if (!container || typeof container.image !== "string" || !isPinnedWorkloadImage(config, workload, container.image)) {
    throw new CliError(`cannot ${action} while ${workload} lacks a trusted digest-pinned task definition`);
  }
  const environment = taskDefinitionEntries(container.environment, "value", workload, action);
  if (canonicalJson(Object.fromEntries(environment)) !== canonicalJson(workloadEnvironment(config, workload))) {
    throw new CliError(`cannot ${action} while ${workload} has stale or unowned environment entries`);
  }
  const secrets = taskDefinitionEntries(container.secrets, "valueFrom", workload, action);
  const aws = requireAws(config);
  const allowed = new Map<string, string>();
  for (const secret of allWorkloadSecrets(config, workload)) {
    for (const name of containerSecretNames(workload, secret)) allowed.set(name, secret.name);
  }
  const secretArns: Record<string, string> = {};
  const providerEnvironment = workloadEnvironment(config, workload);
  for (const [name, valueFrom] of secrets) {
    const storeName = allowed.get(name);
    if (
      !storeName ||
      Object.hasOwn(providerEnvironment, name) ||
      (workload === "core" && forbiddenCoreEndpointNames.has(name))
    ) {
      throw new CliError(`cannot ${action} while ${workload} has stale or unowned secret entries`);
    }
    const arn = verifiedAwsSecretArn(aws, storeName, `${aws.secretsPrefix}${storeName}`, valueFrom);
    if (secretArns[storeName] !== undefined && secretArns[storeName] !== arn) {
      throw new CliError(`cannot ${action} while ${workload} has inconsistent secret entries`);
    }
    secretArns[storeName] = arn;
  }
  const missing = workloadSecrets(config, workload)
    .flatMap((secret) => containerSecretNames(workload, secret))
    .filter((name) => !secrets.has(name));
  if (missing.length) {
    throw new CliError(`cannot ${action} while ${workload} is missing required secret entries`);
  }
  if (taskDefinitionChanges(renderTaskDefinition(config, workload, container.image, secretArns), task!).length) {
    throw new CliError(`cannot ${action} while ${workload} has stale or unowned task-definition fields`);
  }
}

function assertTaskDefinitionsReactivatable(config: QmConfig, targets: Record<string, string>, action: string): void {
  const aws = requireAws(config);
  for (const [workload, target] of Object.entries(targets)) {
    const task = awsJson<{ taskDefinition?: Record<string, unknown> }>(aws, [
      "ecs",
      "describe-task-definition",
      "--task-definition",
      target,
    ]).taskDefinition;
    assertTaskDefinitionReactivatable(config, workload, task, action);
  }
}

function trustedDeploymentBaseline(
  config: QmConfig,
  snapshot: ReturnType<typeof serviceSnapshot>,
  workloads: string[],
  action = "deploy --only",
): DeploymentManifest {
  const aws = requireAws(config);
  const allWorkloads = Object.keys(aws.services);
  const current = currentDeploymentManifest(aws);
  if (!current || allWorkloads.some((workload) => !current.tasks[workload])) {
    throw new CliError(
      "the first AWS deployment must include every workload; omit --only until a complete deployment manifest exists",
    );
  }
  for (const workload of workloads) {
    if (
      snapshot.tasks[workload] !== current.tasks[workload] ||
      snapshot.counts[workload] !== workloadDesiredCount(config, workload)
    ) {
      throw new CliError(
        `cannot ${action} while untouched workload ${workload} differs from the current deployment manifest`,
      );
    }
    assertTaskDefinitionsReactivatable(config, { [workload]: current.tasks[workload]! }, action);
  }
  return current;
}

async function applyServiceTargets(
  config: QmConfig,
  targets: Record<string, string>,
  desiredCounts?: Record<string, number>,
): Promise<void> {
  const aws = requireAws(config);
  const workloads = Object.keys(targets);
  const states = describedServices(config, workloads);
  assertOwnedServices(config, states, workloads);
  const before = serviceSnapshotFromStates(states, workloads);
  const expectedCounts = Object.fromEntries(
    workloads.map((workload) => [workload, desiredCounts?.[workload] ?? before.counts[workload]!]),
  );
  const changed: string[] = [];
  try {
    for (const workload of workloads) {
      const args = [
        "ecs",
        "update-service",
        "--cluster",
        aws.cluster,
        "--service",
        awsServiceSpec(aws, workload).ecsService,
        "--task-definition",
        targets[workload]!,
        "--desired-count",
        String(expectedCounts[workload]),
        "--deployment-configuration",
        "deploymentCircuitBreaker={enable=true,rollback=true}",
      ];
      changed.push(workload);
      await awsTextAsync(aws, args);
    }
    await awaitServiceTargets(
      config,
      Object.fromEntries(
        workloads.map((workload) => [
          workload,
          { taskDefinition: targets[workload]!, desiredCount: expectedCounts[workload]! },
        ]),
      ),
    );
  } catch (error) {
    assertAwsLeaseHeld();
    const restoreFailures: string[] = [];
    for (const workload of [...changed].reverse()) {
      try {
        await awsTextAsync(aws, [
          "ecs",
          "update-service",
          "--cluster",
          aws.cluster,
          "--service",
          awsServiceSpec(aws, workload).ecsService,
          "--task-definition",
          before.tasks[workload]!,
          "--desired-count",
          String(before.counts[workload]),
          "--deployment-configuration",
          "deploymentCircuitBreaker={enable=true,rollback=true}",
        ]);
      } catch (restoreError) {
        assertAwsLeaseHeld();
        restoreFailures.push(`${workload}: ${errMessage(restoreError)}`);
      }
    }
    if (changed.length && restoreFailures.length === 0) {
      try {
        await awaitServiceTargets(
          config,
          Object.fromEntries(
            changed.map((workload) => [
              workload,
              { taskDefinition: before.tasks[workload]!, desiredCount: before.counts[workload]! },
            ]),
          ),
        );
      } catch (restoreError) {
        assertAwsLeaseHeld();
        restoreFailures.push(errMessage(restoreError));
      }
    }
    const detail = restoreFailures.length
      ? `; restoring the prior service set also failed (${restoreFailures.join("; ")})`
      : "";
    throw new CliError(`${errMessage(error)}${detail}`);
  }
}

function reportTaskChanges(
  config: QmConfig,
  services: string[],
  images: Record<string, string>,
  arns: Record<string, string>,
): Array<{ service: string; task: EcsTaskDefinition; changed: boolean }> {
  const desired = services.map((service) => ({
    service,
    task: renderTaskDefinition(config, service, images[service]!, arns),
    live: liveTask(config, service),
  }));
  return desired.map((item) => {
    const changes = taskDefinitionChanges(item.task, item.live);
    step(
      `${item.service}: ${changes.length ? `${changes.length} task-definition change${changes.length === 1 ? "" : "s"}` : "no task-definition change"}`,
    );
    if (changes.length) note(JSON.stringify({ service: item.service, changes }, null, 2));
    return { service: item.service, task: item.task, changed: changes.length > 0 };
  });
}

async function promoteStagedImage(config: QmConfig, service: string, image: string, label: string): Promise<void> {
  const aws = requireAws(config);
  const repository = awsServiceSpec(aws, service).ecrRepository;
  const digest = image.split("@")[1];
  if (!digest) throw new CliError(`staged image for ${service} is not digest-pinned`);
  const staged = awsJson<{ images?: Array<{ imageManifest?: string; imageManifestMediaType?: string }> }>(aws, [
    "ecr",
    "batch-get-image",
    "--repository-name",
    repository,
    "--image-ids",
    `imageDigest=${digest}`,
  ]).images?.[0];
  if (!staged?.imageManifest) throw new CliError(`ECR did not return the staged manifest for ${service}@${digest}`);
  try {
    await awsTextAsync(aws, [
      "ecr",
      "put-image",
      "--repository-name",
      repository,
      "--image-tag",
      label,
      "--image-manifest",
      staged.imageManifest,
      ...(staged.imageManifestMediaType ? ["--image-manifest-media-type", staged.imageManifestMediaType] : []),
    ]);
  } catch (error) {
    if (!awsCliErrorMatches(error, "ImageAlreadyExistsException")) throw error;
  }
}

const PREDEPLOY_SNAPSHOT_INFIX = "-predeploy-";
const PREDEPLOY_SNAPSHOT_CLUSTER_TAG = "QmCluster";

function dbSnapshotRestoreHint(aws: AwsConfig, snapshot: string): string {
  return `restore: aws rds restore-db-instance-from-db-snapshot --db-snapshot-identifier ${snapshot} --db-instance-identifier ${rdsInstanceIdentifier(aws)}-restored --region ${aws.region}, then repoint the stack at the restored instance`;
}

async function takePredeployDbSnapshot(
  config: QmConfig,
  deploymentId: string,
  manifestDbSnapshot?: string,
): Promise<string> {
  const aws = requireAws(config);
  const database = rdsInstanceIdentifier(aws);
  const instance = awsJson<{ DBInstances?: Array<{ DBInstanceStatus?: string; BackupRetentionPeriod?: number }> }>(
    aws,
    ["rds", "describe-db-instances", "--db-instance-identifier", database],
  ).DBInstances?.[0];
  if (instance?.DBInstanceStatus !== "available") {
    throw new CliError(
      `database ${database} is ${instance?.DBInstanceStatus ?? "missing"}; refusing to deploy without an available source for the pre-deploy snapshot`,
    );
  }
  const retention = instance.BackupRetentionPeriod ?? 0;
  const minimumRetention = aws.dbRetentionMinDays ?? 1;
  if (retention < minimumRetention) {
    throw new CliError(
      `database ${database} keeps ${retention} day(s) of automated backups, below the required ${minimumRetention}; raise its backup retention (db_backup_retention_days in the reference module) or lower aws.dbRetentionMinDays before deploying`,
    );
  }
  const snapshot = `${database}${PREDEPLOY_SNAPSHOT_INFIX}${deploymentId}`;
  step(`pre-deploy database snapshot: creating ${snapshot}`);
  await awsTextAsync(aws, [
    "rds",
    "create-db-snapshot",
    "--db-instance-identifier",
    database,
    "--db-snapshot-identifier",
    snapshot,
    "--tags",
    JSON.stringify([
      { Key: "ManagedBy", Value: "qm-cli" },
      { Key: PREDEPLOY_SNAPSHOT_CLUSTER_TAG, Value: aws.cluster },
    ]),
  ]);
  const pollMs = envNum("QM_AWS_DB_SNAPSHOT_POLL_MS", 15_000);
  const deadline = Date.now() + envNum("QM_AWS_DB_SNAPSHOT_DEADLINE_MS", 30 * 60_000);
  let describeFailures = 0;
  for (;;) {
    let status: string | undefined;
    try {
      status = awsJson<{ DBSnapshots?: Array<{ Status?: string }> }>(aws, [
        "rds",
        "describe-db-snapshots",
        "--db-snapshot-identifier",
        snapshot,
      ]).DBSnapshots?.[0]?.Status;
      describeFailures = 0;
    } catch (error) {
      assertAwsLeaseHeld();
      describeFailures += 1;
      if (describeFailures > 2 || Date.now() > deadline) throw error;
      note(`could not poll pre-deploy database snapshot ${snapshot} (${errMessage(error)}); retrying`);
      await sleep(pollMs);
      continue;
    }
    if (status === "available") break;
    if (status !== "creating" && status !== "pending") {
      throw new CliError(`pre-deploy database snapshot ${snapshot} is ${status ?? "missing"} instead of creating`);
    }
    if (Date.now() > deadline)
      throw new CliError(`timed out waiting for pre-deploy database snapshot ${snapshot} to become available`);
    await sleep(pollMs);
  }
  ok(`pre-deploy database snapshot ${snapshot} is available (${dbSnapshotRestoreHint(aws, snapshot)})`);
  await prunePredeployDbSnapshots(
    aws,
    database,
    new Set([snapshot, ...(manifestDbSnapshot ? [manifestDbSnapshot] : [])]),
  );
  return snapshot;
}

function prunablePredeploySnapshot(tags: Array<{ Key?: string; Value?: string }>, cluster: string): boolean {
  const owner = tags.find((tag) => tag.Key === PREDEPLOY_SNAPSHOT_CLUSTER_TAG);
  if (owner) return owner.Value === cluster;
  return tags.some((tag) => tag.Key === "ManagedBy" && tag.Value === "qm-cli");
}

async function prunePredeployDbSnapshots(aws: AwsConfig, database: string, referenced: Set<string>): Promise<void> {
  const keep = Math.max(envNum("QM_AWS_DB_SNAPSHOT_KEEP", 20), 1);
  const stale = (
    awsJson<{
      DBSnapshots?: Array<{
        DBSnapshotIdentifier?: string;
        SnapshotCreateTime?: string;
        TagList?: Array<{ Key?: string; Value?: string }>;
      }>;
    }>(aws, ["rds", "describe-db-snapshots", "--db-instance-identifier", database, "--snapshot-type", "manual"])
      .DBSnapshots ?? []
  )
    .filter(
      (item) =>
        item.DBSnapshotIdentifier?.startsWith(`${database}${PREDEPLOY_SNAPSHOT_INFIX}`) &&
        !referenced.has(item.DBSnapshotIdentifier) &&
        prunablePredeploySnapshot(item.TagList ?? [], aws.cluster),
    )
    .sort((a, b) => (b.SnapshotCreateTime ?? "\uffff").localeCompare(a.SnapshotCreateTime ?? "\uffff"))
    .slice(keep - 1);
  for (const snapshot of stale) {
    try {
      await awsTextAsync(aws, [
        "rds",
        "delete-db-snapshot",
        "--db-snapshot-identifier",
        snapshot.DBSnapshotIdentifier!,
      ]);
      step(`pruned pre-deploy database snapshot ${snapshot.DBSnapshotIdentifier}`);
    } catch (error) {
      assertAwsLeaseHeld();
      warn(`could not prune pre-deploy database snapshot ${snapshot.DBSnapshotIdentifier}: ${errMessage(error)}`);
    }
  }
}

function awsUpInputs(config: QmConfig, configDir: string, opts: AwsUpOpts) {
  const topology = awsTopology(config, configDir);
  const { aws } = topology;
  if (new URL(config.publicUrl).protocol !== "https:") {
    throw new CliError(
      "AWS deploy requires an HTTPS publicUrl; configure an ACM certificate, update publicUrl, and rerender/apply Terraform before running `qm up`",
    );
  }
  const plugins = new Map(topology.plugins.map((plugin) => [plugin.name, plugin]));
  const services = opts.only ?? topology.workloads;
  for (const service of services) workloadArchitecture(config, service);
  if (opts.buildFrom) resolveBuildRepoRoot(opts.buildFromPath, services.filter(isServiceName));
  if (opts.imageLabel && opts.imageLabel !== aws.imageLabel) {
    throw new CliError(
      `--image-label ${opts.imageLabel} differs from durable aws.imageLabel ${aws.imageLabel}; update and commit the deployment directory first`,
    );
  }
  const label = aws.imageLabel;
  if (!label) throw new CliError("aws.imageLabel is required");
  if (!opts.dryRun && !opts.yes) throw new CliError("AWS deploy requires --yes after reviewing `qm plan`");
  return { topology, aws, plugins, services, label, allServices: Object.keys(aws.services) };
}

async function awsPreflightUpWithAdmission(
  config: QmConfig,
  configDir: string,
  opts: AwsUpOpts,
  admission: AwsSourceBuildAdmission,
): Promise<AwsUpPreflight> {
  const { aws, allServices, services } = awsUpInputs(config, configDir, opts);
  const expectedCoreSigningSecret = selectedSecretValue(
    "CORE_SIGNING_SECRET",
    admission.fileValues.get("CORE_SIGNING_SECRET"),
    admission.baseEnv,
  );
  for (const name of new Set([...computedSecrets(config).map((secret) => secret.name), "DATABASE_URL"])) {
    assertNoNulSecret(name, selectedSecretValue(name, admission.fileValues.get(name), admission.baseEnv));
  }
  assertAwsCallerAccount(aws);
  assertAwsPublicFrontDoor(config);
  if (!opts.dryRun) await assertAwsPublicNetwork(config);
  configuredAwsPublicApiUrl(config);
  const microvmRebuildRequired = services.includes("core") && awsDeployImageNeedsRebuild(config);
  assertOwnedServices(config, describedServices(config, allServices), allServices);
  const secrets = awsSecretSnapshot(config, expectedCoreSigningSecret, true);
  return {
    microvmRebuildRequired,
    publicApiUrlNeedsUpdate: secrets.publicApiUrlNeedsUpdate,
    secretArns: secrets.arns,
    secretValues: secrets.values,
  };
}

export async function awsPreflightUp(config: QmConfig, configDir: string, opts: AwsUpOpts): Promise<AwsUpPreflight> {
  return awsPreflightUpWithAdmission(
    config,
    configDir,
    opts,
    sourceBuildAdmission(config, configDir, opts.envFile, opts.configIdentity),
  );
}

export async function awsUp(config: QmConfig, _configDir: string, opts: AwsUpOpts): Promise<void> {
  const buildAdmission = sourceBuildAdmission(config, _configDir, opts.envFile, opts.configIdentity);
  const { aws, plugins, services, label, allServices } = awsUpInputs(config, _configDir, opts);
  const preflight = opts.preflight ?? (await awsPreflightUpWithAdmission(config, _configDir, opts, buildAdmission));
  const requiresDeployImage = services.includes("core");
  const microvmBuildPlanned =
    requiresDeployImage &&
    opts.dryRun === true &&
    (opts.microvmBuildPlanned === true || preflight.microvmRebuildRequired);
  if (requiresDeployImage && !opts.dryRun && !opts.preflight && preflight.microvmRebuildRequired) {
    throw new CliError("AWS deployment publisher MicroVM image requires a rebuild before service deployment");
  }
  header(`qm ${opts.dryRun ? "plan" : "up"} — ${config.orgId} (aws)`);
  if (microvmBuildPlanned) step("deployment publisher MicroVM image: rebuild required before the core deployment");
  let arns = preflight.secretArns;
  if (opts.dryRun) {
    const buildEnv = awsSourceBuildEnvironment(buildAdmission, preflight.secretValues);
    if (services.includes("core")) {
      step(`sandbox substrate: ${sandboxBackend(config)}`);
    }
    step(
      aws.predeployDbSnapshot === false
        ? "pre-deploy database snapshot: disabled (aws.predeployDbSnapshot)"
        : `pre-deploy database snapshot: ${rdsInstanceIdentifier(aws)}${PREDEPLOY_SNAPSHOT_INFIX}<deployment-id> before the first mutation`,
    );
    const before = serviceSnapshot(config, allServices);
    const selected = new Set(services);
    if (allServices.some((service) => !selected.has(service))) {
      trustedDeploymentBaseline(
        config,
        before,
        allServices.filter((name) => !selected.has(name)),
      );
    }
    const images: Record<string, string> = {};
    for (const service of services) {
      const spec = awsServiceSpec(aws, service);
      const sourceBuild = (opts.buildFrom && isServiceName(service)) || plugins.get(service)?.kind === "source";
      if (sourceBuild) {
        images[service] = `${ecrHost(aws)}/${spec.ecrRepository}@sha256:${"0".repeat(64)}`;
        step(`${service}: source build planned; image digest is unresolved until build`);
        continue;
      }
      images[service] = await plannedWorkloadImage(config, service, plugins.get(service), buildEnv);
    }
    reportTaskChanges(config, services, images, arns);
    for (const service of services) {
      step(`${service}: desired count ${before.counts[service] ?? 0} → ${workloadDesiredCount(config, service)}`);
    }
    if (opts.sandboxDir && existsSync(opts.sandboxDir) && (!opts.only || opts.only.includes("core"))) {
      const hash = createHash("sha256").update(deploymentLayerBody(opts.sandboxDir)).digest("hex");
      try {
        const current = currentDeploymentManifest(aws);
        step(`deployment layer: ${current?.layer?.sha256 === hash ? "unchanged" : "changed"} (${hash.slice(0, 12)})`);
      } catch {
        step(`deployment layer: desired ${hash.slice(0, 12)} (live state unavailable)`);
      }
    } else {
      step("deployment layer: preserved (no sandbox directory selected for core)");
    }
    note("Plan only. Re-run `qm up --yes` to deploy.");
    return;
  }
  for (const name of new Set([...computedSecrets(config).map((secret) => secret.name), "DATABASE_URL"])) {
    assertNoNulSecret(name, selectedSecretValue(name, buildAdmission.fileValues.get(name), buildAdmission.baseEnv));
  }
  const releaseId = randomUUID();
  const stagingLabel = `qm-staging-${releaseId}`;
  const staged = new Set<string>();
  const promotedServices = new Set<string>();
  let before: ReturnType<typeof serviceSnapshot> | undefined;
  let applied = false;
  let current: DeploymentManifest | undefined;
  let recorded: DeploymentManifest | undefined;
  let releaseSucceeded = false;
  let previousLayerBody: string | undefined;
  let previousLayerBootstrapped = false;
  let desiredLayerBody: string | undefined;
  let desiredLayer: DeploymentManifest["layer"];
  let layerChanged = false;
  let layerAttempt: AwsLayerAttempt | undefined;
  let dbSnapshot: string | undefined;
  await withAwsLease(aws, async () => {
    try {
      const refreshed = await awsPreflightUpWithAdmission(config, _configDir, opts, buildAdmission);
      if (requiresDeployImage && refreshed.microvmRebuildRequired) {
        throw new CliError("AWS deployment publisher MicroVM image requires a rebuild before service deployment");
      }
      const reconciledSecrets = await ensureAwsPublicApiUrl(config, {
        arns: refreshed.secretArns,
        publicApiUrlNeedsUpdate: refreshed.publicApiUrlNeedsUpdate,
        values: refreshed.secretValues,
      });
      arns = reconciledSecrets.arns;
      const buildEnv = awsSourceBuildEnvironment(buildAdmission, reconciledSecrets.values);
      before = serviceSnapshot(config, allServices);
      current = currentDeploymentManifest(aws);
      const selected = new Set(services);
      if (allServices.some((service) => !selected.has(service))) {
        trustedDeploymentBaseline(
          config,
          before,
          allServices.filter((name) => !selected.has(name)),
        );
      }
      if (aws.predeployDbSnapshot === false) note("pre-deploy database snapshot: disabled (aws.predeployDbSnapshot)");
      else dbSnapshot = await takePredeployDbSnapshot(config, releaseId, current?.dbSnapshot);
      if (current?.layer) {
        desiredLayer = current.layer;
      } else {
        if (current || before.counts.core !== 0) {
          const previousState = await currentDeploymentLayerState({
            config,
            configIdentity: opts.configIdentity,
            transport: awsDeploymentLayerTransport,
            configDir: _configDir,
            ...(opts.envFile !== undefined ? { envFile: opts.envFile } : {}),
          });
          previousLayerBody = previousState.body;
          previousLayerBootstrapped = previousState.bootstrapped;
        } else {
          previousLayerBody = JSON.stringify({ contract: 1, tools: [], skills: [] });
          previousLayerBootstrapped = true;
        }
        if (!previousLayerBootstrapped) {
          desiredLayer = await putDeploymentLayerArtifact(config, previousLayerBody);
          if (current) {
            current.layer = desiredLayer;
            await manifestTransaction(aws, current, current.id);
          }
        }
      }
      if (opts.sandboxDir && existsSync(opts.sandboxDir) && (!opts.only || opts.only.includes("core"))) {
        previousLayerBody ??= getDeploymentLayerArtifact(config, desiredLayer);
        desiredLayerBody = deploymentLayerBody(opts.sandboxDir);
        desiredLayer = await putDeploymentLayerArtifact(config, desiredLayerBody);
        layerChanged = desiredLayer.sha256 !== current?.layer?.sha256;
        if (!layerChanged) {
          const state = await currentDeploymentLayerState({
            config,
            configIdentity: opts.configIdentity,
            transport: awsDeploymentLayerTransport,
            configDir: _configDir,
            ...(opts.envFile !== undefined ? { envFile: opts.envFile } : {}),
          });
          if (
            state.status === "applied" &&
            state.contentHash === desiredLayer.sha256 &&
            state.runtimeContentHash === desiredLayer.sha256
          ) {
            desiredLayerBody = undefined;
          }
        }
      }
      await dockerLogin(aws, buildEnv);
      const images: Record<string, string> = {};
      const selectedImageProvenance: Record<string, DeploymentImageProvenance> = {};
      for (const service of services) {
        staged.add(service);
        const snapshot = sourceBuildSnapshot(service, plugins.get(service), opts);
        selectedImageProvenance[service] = workloadImageProvenance(config, service, plugins.get(service), opts);
        images[service] = await publishWorkloadImage(
          config,
          service,
          plugins.get(service),
          stagingLabel,
          opts,
          snapshot,
          buildEnv,
        );
      }
      const desired = reportTaskChanges(config, services, images, arns);
      const targets: Record<string, string> = {};
      for (const item of desired) {
        if (!item.changed) {
          targets[item.service] = before.tasks[item.service]!;
          continue;
        }
        const file = join(mkdtempSync(join(tmpdir(), "qm-task-")), `${item.service}.json`);
        writeFileSync(file, JSON.stringify(item.task));
        const taskDefinition = await registerTaskDefinition(config, file);
        targets[item.service] = taskDefinition;
      }
      const rolloutTargets = Object.fromEntries(
        services
          .filter(
            (service) =>
              desired.find((item) => item.service === service)!.changed ||
              before!.counts[service] !== workloadDesiredCount(config, service),
          )
          .map((service) => [service, targets[service]!]),
      );
      if (Object.keys(rolloutTargets).length) {
        await applyServiceTargets(
          config,
          rolloutTargets,
          Object.fromEntries(
            Object.keys(rolloutTargets).map((service) => [service, workloadDesiredCount(config, service)]),
          ),
        );
        applied = true;
      }
      await awaitServiceTargets(
        config,
        Object.fromEntries(
          services.map((service) => [
            service,
            { taskDefinition: targets[service]!, desiredCount: workloadDesiredCount(config, service) },
          ]),
        ),
      );
      if (desiredLayerBody) {
        const layerPreSyncState = await currentDeploymentLayerState({
          config,
          configIdentity: opts.configIdentity,
          transport: awsDeploymentLayerTransport,
          configDir: _configDir,
          ...(opts.envFile !== undefined ? { envFile: opts.envFile } : {}),
        });
        const operationId = randomBytes(16).toString("hex");
        layerAttempt = { before: layerPreSyncState, desiredHash: desiredLayer!.sha256, operationId };
        await syncAwsLayerAfterRoll(
          {
            config,
            configIdentity: opts.configIdentity,
            transport: awsDeploymentLayerTransport,
            configDir: _configDir,
            ...(opts.envFile !== undefined ? { envFile: opts.envFile } : {}),
            precondition: layerPreSyncState.precondition,
          },
          desiredLayerBody,
          desiredLayer!,
          operationId,
          (result) => observeAwsLayerAttempt(layerAttempt!, result),
        );
      }
      const releaseTasks = { ...before.tasks, ...targets };
      const releaseImageProvenance = { ...current?.imageProvenance, ...selectedImageProvenance };
      const sameTasks = current && allServices.every((service) => current!.tasks[service] === releaseTasks[service]);
      const sameImageProvenance =
        current && canonicalJson(current.imageProvenance ?? {}) === canonicalJson(releaseImageProvenance);
      releaseSucceeded = true;
      if (!current || !sameTasks || !sameImageProvenance || current.imageLabel !== label || layerChanged) {
        recorded = await recordDeploymentManifest(aws, releaseTasks, {
          id: releaseId,
          imageLabel: label,
          ...(dbSnapshot ? { dbSnapshot } : {}),
          ...(desiredLayer ? { layer: desiredLayer } : {}),
          imageProvenance: releaseImageProvenance,
        });
      } else if (dbSnapshot) {
        try {
          await awsTextAsync(aws, ["rds", "delete-db-snapshot", "--db-snapshot-identifier", dbSnapshot]);
          note(`nothing changed, so no manifest references pre-deploy database snapshot ${dbSnapshot}; deleted it`);
        } catch (error) {
          assertAwsLeaseHeld();
          warn(`could not delete the unreferenced pre-deploy database snapshot ${dbSnapshot}: ${errMessage(error)}`);
        }
      }
      for (const service of services) {
        try {
          await promoteStagedImage(config, service, images[service]!, label);
          promotedServices.add(service);
        } catch (error) {
          assertAwsLeaseHeld();
          warn(
            `AWS deployment succeeded, but could not promote ${service}:${label}: ${errMessage(error)}; preserving staging tag ${stagingLabel} so the deployed digest remains pullable; rerun \`qm up --yes\` to retry promotion`,
          );
        }
      }
    } catch (error) {
      if (releaseSucceeded) throw error;
      assertAwsLeaseHeld();
      const compensationFailures: string[] = [];
      if (layerAttempt) {
        try {
          await restoreAwsLayerAfterFailure(
            {
              config,
              configIdentity: opts.configIdentity,
              transport: awsDeploymentLayerTransport,
              configDir: _configDir,
              ...(opts.envFile !== undefined ? { envFile: opts.envFile } : {}),
            },
            layerAttempt,
            "deployment layer changed concurrently after the failed AWS deployment; refusing to overwrite it",
          );
        } catch (restoreError) {
          assertAwsLeaseHeld();
          compensationFailures.push(`restoring the pre-deploy deployment layer: ${errMessage(restoreError)}`);
        }
      }
      if (applied && before) {
        try {
          await applyServiceTargets(config, before.tasks, before.counts);
        } catch (restoreError) {
          assertAwsLeaseHeld();
          compensationFailures.push(`restoring the pre-deploy manifest: ${errMessage(restoreError)}`);
        }
      }
      throwAfterCompensation(error, compensationFailures);
    } finally {
      for (const service of staged) {
        if (releaseSucceeded && !promotedServices.has(service)) continue;
        try {
          await awsTextAsync(aws, [
            "ecr",
            "batch-delete-image",
            "--repository-name",
            awsServiceSpec(aws, service).ecrRepository,
            "--image-ids",
            `imageTag=${stagingLabel}`,
          ]);
        } catch (error) {
          assertAwsLeaseHeld();
          if (!awsCliErrorMatches(error, "ImageNotFoundException"))
            warn(`could not clean staging image ${service}:${stagingLabel}: ${errMessage(error)}`);
        }
      }
    }
  });
  ok(`AWS services stable on ${label} (deployment ${recorded?.id ?? current?.id})`);
}

export function awsStatus(config: QmConfig, configDir = process.cwd()): void {
  const { aws, workloads } = awsTopology(config, configDir);
  assertAwsCallerAccount(aws);
  const result = describedServices(config, workloads);
  header(`qm status — ${config.orgId} (aws)`);
  for (const workload of workloads) {
    const service = result.get(workload)!;
    note(`${service.serviceName}: ${service.runningCount}/${service.desiredCount} running · ${service.taskDefinition}`);
  }
  if (config.services.includes("slack")) note("slack: virtual service running in the core task");
}

export function awsLogs(
  config: QmConfig,
  service: string | undefined,
  opts: LogOpts,
  configDir = process.cwd(),
): void | Promise<void> {
  const { aws, workloads } = awsTopology(config, configDir);
  assertAwsCallerAccount(aws);
  if (opts.tail !== undefined)
    note(`(--tail is a docker-only line count; aws logs tail has none, so it's ignored on the aws target)`);
  const logArgs = (name: string): string[] => {
    const spec = ownAwsServiceSpec(aws, name);
    if (!spec) throw new CliError(`unknown AWS workload ${name}`);
    return awsArgs(aws, [
      "logs",
      "tail",
      spec.logGroup ?? `/ecs/${spec.ecsService}`,
      ...(opts.follow ? ["--follow"] : []),
    ]);
  };
  if (service) {
    const resolved = isVirtualService(service) ? "core" : service;
    if (isVirtualService(service)) note(`${service} is a virtual service; showing core logs`);
    awsRunInherit(process.env.AWS_BIN ?? "aws", logArgs(resolved));
    return;
  }
  return streamLabeled(
    workloads.map((name) => ({ label: name, command: process.env.AWS_BIN ?? "aws", args: logArgs(name) })),
    (label, line) => note(`${dim(label)} | ${line}`),
  );
}

export async function awsDown(config: QmConfig, configDir = process.cwd()): Promise<void> {
  const { aws, workloads } = awsTopology(config, configDir);
  assertAwsCallerAccount(aws);
  assertOwnedServices(config, describedServices(config, workloads), workloads);
  await withAwsLease(aws, async () => {
    const before = serviceSnapshot(config, workloads);
    await applyServiceTargets(config, before.tasks, Object.fromEntries(workloads.map((workload) => [workload, 0])));
  });
  ok(
    "AWS services set to zero desired tasks; protected tasks finish in-flight turns before stopping. Infrastructure and data were retained.",
  );
}

function firstRolledBackDbSnapshot(aws: AwsConfig, current: DeploymentManifest, targetId: string): string | undefined {
  const seen = new Set<string>();
  let oldest: string | undefined;
  let manifest: DeploymentManifest | undefined = current;
  while (manifest && !seen.has(manifest.id)) {
    if (manifest.id === targetId) return oldest;
    if (manifest.dbSnapshot) oldest = manifest.dbSnapshot;
    seen.add(manifest.id);
    if (!manifest.previous) return undefined;
    try {
      manifest = deploymentManifest(aws, manifest.previous);
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export async function awsRollback(
  config: QmConfig,
  to?: string,
  layerOpts?: { configDir: string; configIdentity: FileIdentity; envFile?: string },
): Promise<void> {
  const { aws, workloads: services } = awsTopology(config, layerOpts?.configDir ?? process.cwd());
  assertAwsCallerAccount(aws);
  let before: ReturnType<typeof serviceSnapshot> | undefined;
  let applied = false;
  let layerAttempt: AwsLayerAttempt | undefined;
  let rolledBack = false;
  let targetManifest: DeploymentManifest | undefined;
  await withAwsLease(aws, async () => {
    try {
      before = serviceSnapshot(config, services);
      const currentManifest = currentDeploymentManifest(aws);
      if (!to) {
        if (!currentManifest?.previous) throw new CliError("no previous recorded AWS deployment to roll back to");
        targetManifest = deploymentManifest(aws, currentManifest.previous);
      } else {
        targetManifest = deploymentManifestForTarget(aws, to);
      }
      const target = targetManifest;
      const missing = services.filter((service) => !target.tasks[service]);
      if (missing.length)
        throw new CliError(`target AWS deployment manifest is missing workloads: ${missing.join(", ")}`);
      const targets = Object.fromEntries(services.map((service) => [service, target.tasks[service]!]));
      assertTaskDefinitionsReactivatable(config, targets, "roll back");
      await ensureAwsPublicApiUrl(config, awsSecretSnapshot(config, undefined, true));
      let targetLayerBody: string | undefined;
      let layerNeedsSync = false;
      if (layerOpts) {
        targetLayerBody = getDeploymentLayerArtifact(config, target.layer);
        if (currentManifest?.layer) getDeploymentLayerArtifact(config, currentManifest.layer);
        else if (currentManifest)
          throw new CliError(
            `current AWS deployment manifest ${currentManifest.id} has no restorable deployment layer`,
          );
        layerNeedsSync = currentManifest?.layer?.sha256 !== target.layer!.sha256;
      }
      const changedTargets = Object.fromEntries(
        services
          .filter((service) => before!.tasks[service] !== targets[service])
          .map((service) => [service, targets[service]!]),
      );
      if (Object.keys(changedTargets).length) {
        await applyServiceTargets(
          config,
          changedTargets,
          Object.fromEntries(Object.keys(changedTargets).map((service) => [service, before!.counts[service]!])),
        );
        applied = true;
      }
      await awaitServiceTargets(
        config,
        Object.fromEntries(
          services.map((service) => [
            service,
            { taskDefinition: targets[service]!, desiredCount: before!.counts[service]! },
          ]),
        ),
      );
      if (targetLayerBody && layerOpts && layerNeedsSync) {
        if (before.counts.core === 0) {
          note(
            "deployment layer sync deferred: core is scaled to zero, so `check --live` will flag the layer until the next `qm up` applies it",
          );
        } else {
          const rollbackLayerPreSyncState = await currentDeploymentLayerState({
            config,
            configIdentity: layerOpts.configIdentity,
            transport: awsDeploymentLayerTransport,
            configDir: layerOpts.configDir,
            ...(layerOpts.envFile !== undefined ? { envFile: layerOpts.envFile } : {}),
          });
          const operationId = randomBytes(16).toString("hex");
          layerAttempt = { before: rollbackLayerPreSyncState, desiredHash: target.layer!.sha256, operationId };
          await syncAwsLayerAfterRoll(
            {
              config,
              configIdentity: layerOpts.configIdentity,
              transport: awsDeploymentLayerTransport,
              configDir: layerOpts.configDir,
              ...(layerOpts.envFile !== undefined ? { envFile: layerOpts.envFile } : {}),
              precondition: rollbackLayerPreSyncState.precondition,
            },
            targetLayerBody,
            target.layer!,
            operationId,
            (result) => observeAwsLayerAttempt(layerAttempt!, result),
          );
        }
      }
      rolledBack = true;
      if (currentManifest?.id !== target.id) {
        await manifestTransaction(aws, undefined, target.id);
        const dbSnapshot = currentManifest && firstRolledBackDbSnapshot(aws, currentManifest, target.id);
        if (dbSnapshot) {
          note(
            `rollback restores code and configuration, not data; the database snapshot taken before the first rolled-back deployment is ${dbSnapshot} (${dbSnapshotRestoreHint(aws, dbSnapshot)})`,
          );
        }
      }
    } catch (error) {
      if (rolledBack) throw error;
      assertAwsLeaseHeld();
      const compensationFailures: string[] = [];
      if (layerAttempt && layerOpts) {
        try {
          await restoreAwsLayerAfterFailure(
            {
              config,
              configIdentity: layerOpts.configIdentity,
              transport: awsDeploymentLayerTransport,
              configDir: layerOpts.configDir,
              ...(layerOpts.envFile !== undefined ? { envFile: layerOpts.envFile } : {}),
            },
            layerAttempt,
            "deployment layer changed concurrently after the failed AWS rollback; refusing to overwrite it",
          );
        } catch (restoreError) {
          assertAwsLeaseHeld();
          compensationFailures.push(`restoring the pre-rollback deployment layer: ${errMessage(restoreError)}`);
        }
      }
      if (applied && before) {
        try {
          await applyServiceTargets(config, before.tasks, before.counts);
        } catch (restoreError) {
          assertAwsLeaseHeld();
          compensationFailures.push(`restoring the pre-rollback manifest: ${errMessage(restoreError)}`);
        }
      }
      throwAfterCompensation(error, compensationFailures);
    }
  });
  ok(`rolled back ${config.orgId}`);
}

function selectedSecretValue(
  name: string,
  fileValue: string | undefined,
  ambientEnv: Readonly<NodeJS.ProcessEnv> = process.env,
): string | undefined {
  if (name !== "CORE_SIGNING_SECRET") return deploymentStoreSecretValue(name, fileValue, ambientEnv);
  if (ambientEnv.QM_DEPLOY_ENV_FILE_ONLY === "1") {
    return fileValue === undefined || fileValue === "" ? undefined : fileValue;
  }
  return fileValue === undefined || fileValue === "" ? ambientEnv.CORE_SIGNING_SECRET : fileValue;
}

export async function awsSecretsPush(
  config: QmConfig,
  configDir: string,
  sourceValues: ReadonlyMap<string, string>,
): Promise<void> {
  const ambientEnv = { ...process.env };
  const { aws, workloads } = awsTopology(config, configDir);
  const resolved: Array<{ name: string; value: string }> = [];
  for (const secret of computedSecrets(config).filter((item) => item.managedBy === "operator")) {
    const supplied =
      secret.name === "PUBLIC_API_URL"
        ? configuredAwsPublicApiUrl(config)
        : selectedSecretValue(secret.name, sourceValues.get(secret.name), ambientEnv);
    assertNoNulSecret(secret.name, supplied);
    if (!secret.required && !supplied) {
      step(`${secret.name}: optional, not supplied`);
      continue;
    }
    const value = supplied ?? (await promptHidden(secret.name));
    assertNoNulSecret(secret.name, value);
    assertSecretByteLength(secret.name, value);
    resolved.push({ name: secret.name, value });
  }
  const invalid = [...invalidSecretNames(new Map(resolved.map(({ name, value }) => [name, value])))].sort();
  if (invalid.length === 1) {
    throw new CliError(
      `${invalid[0]} must have a non-empty, non-placeholder runtime value; signing keys must be at least 32 characters`,
    );
  }
  if (invalid.length) throw new CliError(`selected AWS secrets failed runtime validation: ${invalid.join(", ")}`);
  const resolvedValues = new Map(resolved.map(({ name, value }) => [name, value]));
  validateCompleteSecretValues(config, resolvedValues);
  assertAwsCallerAccount(aws);
  assertAwsSecretReplacementValid(config, resolvedValues);
  const uploads = resolved.map((secret) => ({
    name: secret.name,
    id: `${aws.secretsPrefix}${secret.name}`,
    value: secret.value,
  }));
  await withAwsLease(aws, async () => {
    assertAwsSecretReplacementValid(config, resolvedValues);
    assertAwsSecretContainers(aws, uploads);
    const baseline = currentDeploymentManifest(aws);
    const states = describedServices(config, workloads);
    assertOwnedServices(config, states, workloads);
    const before = baseline ? serviceSnapshotFromStates(states, workloads) : undefined;
    if (baseline) {
      const drifted = workloads.filter(
        (workload) => !baseline.tasks[workload] || before!.tasks[workload] !== baseline.tasks[workload],
      );
      if (drifted.length)
        throw new CliError(
          `cannot rotate secrets while workloads differ from the current deployment manifest: ${drifted.join(", ")}`,
        );
    } else {
      const active = workloads.filter((workload) => {
        const state = states.get(workload)!;
        return state.desiredCount !== 0 || state.runningCount !== 0;
      });
      if (active.length) {
        throw new CliError(
          `cannot defer secret activation without a current deployment manifest while workloads are active: ${active.join(", ")}`,
        );
      }
    }
    const uploaded = Object.fromEntries(uploads.map((secret) => [secret.name, secret.id]));
    const affected = workloads.filter((workload) =>
      workloadSecrets(config, workload, uploaded).some((secret) => uploaded[secret.name]),
    );
    if (baseline && before) {
      assertTaskDefinitionsReactivatable(
        config,
        Object.fromEntries(affected.map((workload) => [workload, baseline.tasks[workload]!])),
        "rotate secrets",
      );
    }
    for (const secret of uploads) {
      try {
        await awsTextAsync(
          aws,
          ["secretsmanager", "put-secret-value", "--secret-id", secret.id, "--secret-string", "file:///dev/stdin"],
          { input: secret.value },
        );
      } catch (error) {
        if (awsCliErrorMatches(error, "ResourceNotFoundException")) {
          throw new CliError(
            `AWS secret container ${secret.id} is missing; apply the rendered Terraform before pushing secrets`,
          );
        }
        throw error;
      }
      step(`${secret.name}: uploaded`);
    }
    if (!baseline || !before) {
      if (affected.length) step("secret activation deferred to the first complete AWS deployment");
      return;
    }
    const arns = secretArns(config);
    const targets = { ...before.tasks };
    const changed: Record<string, string> = {};
    for (const workload of affected) {
      const live =
        awsJson<{ taskDefinition?: Record<string, unknown> }>(aws, [
          "ecs",
          "describe-task-definition",
          "--task-definition",
          before.tasks[workload]!,
        ]).taskDefinition ?? null;
      const container = (live?.containerDefinitions as Array<Record<string, unknown>> | undefined)?.find(
        (item) => item.name === workload,
      );
      if (
        !container ||
        typeof container.image !== "string" ||
        !isPinnedWorkloadImage(config, workload, container.image)
      ) {
        throw new CliError(`cannot rotate secrets while ${workload} lacks a trusted digest-pinned image`);
      }
      const desired = renderTaskDefinition(config, workload, container.image, arns);
      if (!taskDefinitionChanges(desired, live).length) continue;
      const dir = mkdtempSync(join(tmpdir(), "qm-task-"));
      try {
        const file = join(dir, `${workload}.json`);
        writeFileSync(file, JSON.stringify(desired));
        targets[workload] = await registerTaskDefinition(config, file);
        changed[workload] = targets[workload]!;
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
    let changedApplied = false;
    let rotated = false;
    try {
      if (Object.keys(changed).length) {
        await applyServiceTargets(
          config,
          changed,
          Object.fromEntries(Object.keys(changed).map((workload) => [workload, before.counts[workload]!])),
        );
        changedApplied = true;
      }
      const unchanged = affected.filter((workload) => !changed[workload]);
      const forcedDeployments: Record<string, string> = {};
      for (const workload of unchanged) {
        const service = (
          await awsJsonAsync<{ service?: { deployments?: EcsDeploymentState[] } }>(aws, [
            "ecs",
            "update-service",
            "--cluster",
            aws.cluster,
            "--service",
            awsServiceSpec(aws, workload).ecsService,
            "--force-new-deployment",
          ])
        ).service;
        const primary = (service?.deployments ?? []).filter((deployment) => deployment.status === "PRIMARY");
        if (primary.length !== 1 || !primary[0]?.id)
          throw new CliError(`AWS did not identify the replacement deployment for ${workload}`);
        forcedDeployments[workload] = primary[0].id;
      }
      if (unchanged.length) {
        await awaitServiceTargets(
          config,
          Object.fromEntries(
            unchanged.map((workload) => [
              workload,
              {
                taskDefinition: before.tasks[workload]!,
                desiredCount: before.counts[workload]!,
                deploymentId: forcedDeployments[workload]!,
              },
            ]),
          ),
        );
      }
      rotated = true;
      if (Object.keys(changed).length) {
        await recordDeploymentManifest(aws, targets, {
          imageLabel: baseline.imageLabel ?? aws.imageLabel,
          ...(baseline.layer ? { layer: baseline.layer } : {}),
          ...(baseline.imageProvenance ? { imageProvenance: baseline.imageProvenance } : {}),
        });
      }
    } catch (error) {
      if (rotated || !changedApplied) throw error;
      assertAwsLeaseHeld();
      const compensationFailures: string[] = [];
      try {
        await applyServiceTargets(
          config,
          Object.fromEntries(Object.keys(changed).map((workload) => [workload, before.tasks[workload]!])),
          Object.fromEntries(Object.keys(changed).map((workload) => [workload, before.counts[workload]!])),
        );
      } catch (restoreError) {
        assertAwsLeaseHeld();
        compensationFailures.push(`restoring pre-rotation task definitions: ${errMessage(restoreError)}`);
      }
      throwAfterCompensation(error, compensationFailures);
    }
    for (const workload of affected) step(`${workload}: restarted with rotated secrets`);
  });
  ok("operator secrets uploaded to AWS Secrets Manager");
}

function githubRemoteRepository(remote: string): string | undefined {
  const scp = /^git@github\.com:([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?$/.exec(remote);
  if (scp) return scp[1];
  const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/]*)/.exec(remote)?.[1];
  let url: URL;
  try {
    url = new URL(remote);
  } catch {
    return undefined;
  }
  const ssh = url.protocol === "ssh:";
  if (
    !["git:", "http:", "https:", "ssh:"].includes(url.protocol) ||
    url.hostname !== "github.com" ||
    url.port ||
    (ssh
      ? authority?.toLowerCase() !== "git@github.com" || url.username !== "git" || Boolean(url.password)
      : authority?.toLowerCase() !== "github.com" || Boolean(url.username) || Boolean(url.password)) ||
    url.search ||
    url.hash
  ) {
    return undefined;
  }
  const path = /^\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/.exec(url.pathname);
  return path ? `${path[1]}/${path[2]}` : undefined;
}

export function githubTrustSubject(configDir: string, deployBranch?: string, deployEnvironment?: string): string {
  const source = existsSync(join(configDir, "infra"))
    ? readRenderedFile(configDir, ["infra", "terraform.tfvars"])
    : undefined;
  const tfValue = (name: string): string | undefined => {
    const raw = source?.match(new RegExp(`^${name}\\s*=\\s*("(?:[^"\\\\]|\\\\.)*")\\s*$`, "m"))?.[1];
    return raw ? (JSON.parse(raw) as string) : undefined;
  };
  let repo = process.env.GITHUB_REPOSITORY;
  if (!repo && source !== undefined) {
    repo = tfValue("github_repository");
    if (!repo || repo === "replace-me/repository" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
      throw new Error("infra/terraform.tfvars must set an explicit github_repository owner/name");
    }
  }
  if (!repo) {
    let remote: string;
    try {
      remote = capture("git", ["-C", configDir, "config", "--local", "--get", "remote.origin.url"], {
        env: gitSubprocessEnvironment(),
      }).trim();
    } catch {
      throw new Error("cannot derive the GitHub repository from this deployment checkout");
    }
    repo = githubRemoteRepository(remote);
    if (!repo) throw new Error("cannot derive the GitHub repository from this deployment checkout");
  }
  if (deployEnvironment) return `repo:${repo}:environment:${deployEnvironment}`;
  const tfRef = tfValue("github_ref");
  if (tfRef !== undefined && !/^refs\/heads\/\S+$/.test(tfRef)) {
    throw new Error("infra/terraform.tfvars github_ref must be a refs/heads/* branch ref");
  }
  const ref = deployBranch ? `refs/heads/${deployBranch}` : (tfRef ?? "refs/heads/main");
  return `repo:${repo}:ref:${ref}`;
}

export function assertGithubDeployTrust(statements: unknown, accountId: string, expectedSubject: string): void {
  let list: unknown[] = [];
  if (Array.isArray(statements)) list = statements;
  else if (statements) list = [statements];
  if (list.length !== 1 || typeof list[0] !== "object" || list[0] === null || Array.isArray(list[0])) {
    throw new Error("deploy role must have exactly one trust statement");
  }
  const statement = list[0] as Record<string, unknown>;
  const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
  if (statement.Effect !== "Allow" || actions.length !== 1 || actions[0] !== "sts:AssumeRoleWithWebIdentity") {
    throw new Error("deploy role trust must only allow GitHub OIDC assumption");
  }
  const principal = statement.Principal as Record<string, unknown> | undefined;
  if (
    principal?.Federated !== `arn:aws:iam::${accountId}:oidc-provider/token.actions.githubusercontent.com` ||
    Object.keys(principal).length !== 1
  ) {
    throw new Error("deploy role trust must name only the account's GitHub OIDC provider");
  }
  const condition = statement.Condition as Record<string, unknown> | undefined;
  const equals = condition?.StringEquals as Record<string, unknown> | undefined;
  const live = equals?.["token.actions.githubusercontent.com:sub"];
  const rawSubjects: unknown[] = Array.isArray(live) ? live : [live].filter((s) => s !== undefined);
  const withoutIdPins = (subject: string): string =>
    subject.replace(/^repo:([^/:@]+)(?:@\d+)?\/([^/:@]+)(?:@\d+)?:/, "repo:$1/$2:");
  const subjects = rawSubjects.map((subject) => (typeof subject === "string" ? withoutIdPins(subject) : subject));
  const repoPrefix = `${expectedSubject.split(":").slice(0, 2).join(":")}:`;
  if (
    !condition ||
    Object.keys(condition).length !== 1 ||
    !equals ||
    Object.keys(equals).length !== 2 ||
    equals["token.actions.githubusercontent.com:aud"] !== "sts.amazonaws.com" ||
    !subjects.includes(expectedSubject) ||
    !subjects.every(
      (subject) => typeof subject === "string" && subject.startsWith(repoPrefix) && !subject.includes("*"),
    )
  ) {
    const rendered = rawSubjects.length > 0 ? rawSubjects.join(", ") : "missing";
    throw new Error(
      `OIDC trust must pin audience and only ${repoPrefix}* subjects including ${expectedSubject} (live subject: ${rendered})`,
    );
  }
}

export function assertAwsPublicListener(
  publicUrl: string,
  listener: { Protocol?: string; Port?: number; Certificates?: Array<{ CertificateArn?: string }> },
): void {
  const protocol = new URL(publicUrl).protocol;
  if (protocol === "https:") {
    if (listener.Protocol !== "HTTPS" || listener.Port !== 443) {
      throw new Error(
        `publicUrl is HTTPS but the ALB listener is ${listener.Protocol ?? "missing"}:${listener.Port ?? "missing"}; configure certificate_arn and apply Terraform`,
      );
    }
    if (!listener.Certificates?.some((certificate) => Boolean(certificate.CertificateArn))) {
      throw new Error(
        "publicUrl is HTTPS but the ALB listener has no certificate; configure certificate_arn and apply Terraform",
      );
    }
    return;
  }
  if (protocol === "http:") {
    if (listener.Protocol !== "HTTP" || listener.Port !== 80) {
      throw new Error(
        `publicUrl is HTTP but the ALB listener is ${listener.Protocol ?? "missing"}:${listener.Port ?? "missing"}`,
      );
    }
    return;
  }
  throw new Error(`publicUrl must use http or https (got ${protocol})`);
}

function assertAwsAppsCertificate(config: QmConfig, listenerArn: string): void {
  const appsDomain = effectiveDeployAppsDomain(config);
  if (!appsDomain) return;
  const aws = requireAws(config);
  const required = `*.${appsDomain}`;
  const arns: string[] = [];
  const markers = new Set<string>();
  let marker: string | undefined;
  do {
    const listed = awsJson<unknown>(aws, [
      "elbv2",
      "describe-listener-certificates",
      "--listener-arn",
      listenerArn,
      "--no-paginate",
      ...(marker ? ["--marker", marker] : []),
    ]);
    if (!listed || typeof listed !== "object" || Array.isArray(listed)) {
      throw new Error("AWS returned an invalid public-listener certificate list");
    }
    const record = listed as Record<string, unknown>;
    if (!Array.isArray(record.Certificates)) {
      throw new Error("AWS public listener certificate list is missing");
    }
    for (const certificate of record.Certificates) {
      if (!certificate || typeof certificate !== "object" || Array.isArray(certificate)) {
        throw new Error("AWS returned an invalid public-listener certificate entry");
      }
      const arn = (certificate as Record<string, unknown>).CertificateArn;
      if (typeof arn !== "string" || arn.length === 0) {
        throw new Error("AWS public listener certificate entry is missing its ARN");
      }
      arns.push(arn);
    }
    const next = record.NextMarker;
    if (next === undefined) {
      marker = undefined;
    } else if (typeof next !== "string" || next.length === 0 || markers.has(next)) {
      throw new Error("AWS public listener certificate list returned an invalid pagination marker");
    } else {
      markers.add(next);
      marker = next;
    }
  } while (marker);
  if (arns.length === 0) throw new Error("AWS public listener certificate list is missing");
  for (const arn of new Set(arns)) {
    const described = awsJson<unknown>(aws, ["acm", "describe-certificate", "--certificate-arn", arn]);
    if (!described || typeof described !== "object" || Array.isArray(described)) {
      throw new Error(`AWS returned an invalid ACM certificate response for ${arn}`);
    }
    const certificate = (described as Record<string, unknown>).Certificate;
    if (!certificate || typeof certificate !== "object" || Array.isArray(certificate)) {
      throw new Error(`AWS ACM certificate ${arn} is missing`);
    }
    const record = certificate as Record<string, unknown>;
    if (record.CertificateArn !== arn || !Array.isArray(record.SubjectAlternativeNames)) {
      throw new Error(`AWS ACM certificate ${arn} returned invalid identity or subject-alternative names`);
    }
    const names = record.SubjectAlternativeNames;
    if (!names.every((name) => typeof name === "string")) {
      throw new Error(`AWS ACM certificate ${arn} returned invalid subject-alternative names`);
    }
    if (names.some((name) => name.trim().toLowerCase().replace(/\.$/, "") === required)) return;
  }
  throw new Error(
    `AWS public listener certificates do not cover ${required}; attach an ACM certificate whose subject-alternative names include ${required} and apply Terraform`,
  );
}

interface AwsPublicListener {
  ListenerArn?: string;
  Protocol?: string;
  Port?: number;
  Certificates?: Array<{ CertificateArn?: string }>;
  DefaultActions?: Array<{
    Type?: string;
    TargetGroupArn?: string;
    FixedResponseConfig?: { StatusCode?: string };
    RedirectConfig?: { Protocol?: string; Port?: string; StatusCode?: string };
  }>;
}

interface AwsPublicFrontDoor {
  loadBalancerArn: string;
  dnsName: string;
  listener: AwsPublicListener;
}

function awsPublicOrigin(config: QmConfig): URL {
  const value = config.env.core?.AWS_PUBLIC_ORIGIN_URL?.trim() || config.publicUrl;
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("protocol");
    return url;
  } catch {
    throw new Error("env.core.AWS_PUBLIC_ORIGIN_URL must be an HTTP(S) URL when set");
  }
}

function isHttpsRedirectListener(listener: AwsPublicListener): boolean {
  if (listener.Protocol !== "HTTP" || listener.Port !== 80) return false;
  const actions = listener.DefaultActions ?? [];
  return actions.length === 1 && actions[0]?.Type === "redirect" && actions[0].RedirectConfig?.Protocol === "HTTPS";
}

interface AwsEcsRoutingService {
  serviceName?: string;
  status?: string;
  serviceRegistries?: Array<{ registryArn?: string }>;
  loadBalancers?: Array<{ targetGroupArn?: string }>;
}

function awsEcsRoutingServices(config: QmConfig): ReadonlyMap<string, AwsEcsRoutingService> {
  const aws = requireAws(config);
  const entries = Object.entries(aws.services);
  const services: AwsEcsRoutingService[] = [];
  const failures: Array<{ arn?: string; reason?: string }> = [];
  for (const batch of chunks(
    entries.map(([, spec]) => spec.ecsService),
    ECS_SERVICE_BATCH_SIZE,
  )) {
    const described = awsJson<{
      services?: AwsEcsRoutingService[];
      failures?: Array<{ arn?: string; reason?: string }>;
    }>(aws, ["ecs", "describe-services", "--cluster", aws.cluster, "--services", ...batch]);
    services.push(...(described.services ?? []));
    failures.push(...(described.failures ?? []));
  }
  if (failures.length) {
    throw new Error(
      `could not describe ECS routing attachments: ${failures.map((failure) => `${failure.arn ?? "unknown"} (${failure.reason ?? "unknown"})`).join(", ")}`,
    );
  }
  return new Map(
    entries.map(([name, spec]) => {
      const service = services.find((candidate) => candidate.serviceName === spec.ecsService);
      if (!service) throw new Error(`ECS service ${spec.ecsService} is missing`);
      return [name, service] as const;
    }),
  );
}

function awsPublicFrontDoor(config: QmConfig): AwsPublicFrontDoor {
  const aws = requireAws(config);
  const albName =
    aws.alb ?? `${aws.cluster.slice(0, 23)}-${createHash("sha1").update(aws.cluster).digest("hex").slice(0, 8)}`;
  const loadBalancer = awsJson<{
    LoadBalancers?: Array<{ LoadBalancerArn?: string; DNSName?: string; State?: { Code?: string } }>;
  }>(aws, ["elbv2", "describe-load-balancers", "--names", albName]).LoadBalancers?.[0];
  if (!loadBalancer?.LoadBalancerArn || !loadBalancer.DNSName || loadBalancer.State?.Code !== "active") {
    throw new Error(`load balancer is ${loadBalancer?.State?.Code ?? "missing"}`);
  }
  const listeners =
    awsJson<{ Listeners?: AwsPublicListener[] }>(aws, [
      "elbv2",
      "describe-listeners",
      "--load-balancer-arn",
      loadBalancer.LoadBalancerArn,
    ]).Listeners ?? [];
  const origin = awsPublicOrigin(config);
  const httpsFrontDoor = origin.protocol === "https:";
  const redirects = httpsFrontDoor ? listeners.filter(isHttpsRedirectListener) : [];
  const candidates = listeners.filter((listener) => !redirects.includes(listener));
  if (candidates.length !== 1 || redirects.length > 1) {
    const found = listeners
      .map(
        (listener) =>
          `${listener.Protocol ?? "unknown"}:${listener.Port ?? "?"} (default ${listener.DefaultActions?.map((action) => action.Type ?? "unknown").join("+") || "none"})`,
      )
      .join(", ");
    throw new Error(
      `expected exactly one public listener${httpsFrontDoor ? " plus at most one port-80 HTTPS-redirect listener" : ""}, found ${found || "none"}`,
    );
  }
  const listener = candidates[0];
  if (!listener?.ListenerArn) throw new Error("public listener is missing");
  assertAwsPublicListener(origin.toString(), listener);
  assertAwsAppsCertificate(config, listener.ListenerArn);
  return { loadBalancerArn: loadBalancer.LoadBalancerArn, dnsName: loadBalancer.DNSName, listener };
}

const validAlbHostname = (value: string): boolean =>
  value.length <= 128 &&
  value.includes(".") &&
  value
    .split(".")
    .every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));

function awsCoreHostnames(config: QmConfig): string[] {
  const hosts: string[] = [];
  const normalize = (value: string, source: string): string => {
    const host = value.trim().toLowerCase().replace(/\.$/, "");
    if (!validAlbHostname(host)) {
      throw new Error(`${source} ${JSON.stringify(value)} does not derive a valid ALB host-header hostname`);
    }
    return host;
  };
  const api = config.apiUrl?.trim();
  if (api) {
    let hostname: string;
    try {
      hostname = new URL(api).hostname;
    } catch {
      throw new Error(
        `apiUrl ${JSON.stringify(api)} is not a valid URL, so the ALB host rule for the core API cannot be derived`,
      );
    }
    const apiHost = normalize(hostname, "apiUrl");
    if (apiHost !== new URL(config.publicUrl).hostname.toLowerCase().replace(/\.$/, "")) hosts.push(apiHost);
  }
  const apps = effectiveDeployAppsDomain(config);
  if (apps) {
    const source = "the apps domain (env.core.DEPLOY_APPS_DOMAIN or AWS_DEPLOY_APPS_DOMAIN)";
    const wildcard = `*.${normalize(apps, source)}`;
    if (wildcard.length > 128) {
      throw new Error(`${source} ${JSON.stringify(apps)} does not derive a valid ALB host-header hostname`);
    }
    hosts.push(wildcard);
  }
  return [...new Set(hosts)];
}

function assertAwsPublicRouting(
  config: QmConfig,
  ecsServices?: ReadonlyMap<string, AwsEcsRoutingService>,
): ReadonlyMap<string, string> {
  const aws = requireAws(config);
  const hash = (value: string, length: number): string =>
    createHash("sha1").update(value).digest("hex").slice(0, length);
  const targetName = (name: string): string =>
    ownAwsServiceSpec(aws, name)?.targetGroup ??
    `${aws.cluster.slice(0, 20)}-${name.replaceAll("-", "").slice(0, 4)}-${hash(`${aws.cluster}:${name}`, 6)}`;
  const hasPortal = Boolean(ownAwsServiceSpec(aws, "portal"));
  const coreHosts = hasPortal ? awsCoreHostnames(config) : [];
  let ingress = ["core"];
  if (hasPortal) ingress = coreHosts.length ? ["portal", "core"] : ["portal"];
  const { loadBalancerArn, listener } = awsPublicFrontDoor(config);
  const targetGroups =
    awsJson<{ TargetGroups?: Array<{ TargetGroupArn?: string; TargetGroupName?: string }> }>(aws, [
      "elbv2",
      "describe-target-groups",
      "--load-balancer-arn",
      loadBalancerArn,
    ]).TargetGroups ?? [];
  const routingServices = ecsServices ?? awsEcsRoutingServices(config);
  const targets = new Map<string, string>();
  for (const name of ingress) {
    const expectedName = targetName(name);
    const target = targetGroups.find((group) => group.TargetGroupName === expectedName);
    if (!target?.TargetGroupArn) throw new Error(`target group for ${name} is missing`);
    targets.set(name, target.TargetGroupArn);
    if (
      !(routingServices.get(name)?.loadBalancers ?? []).some((item) => item.targetGroupArn === target.TargetGroupArn)
    ) {
      throw new Error(`ECS service ${name} is not attached to its target group`);
    }
  }
  for (const name of Object.keys(aws.services)) {
    if (!ingress.includes(name) && (routingServices.get(name)?.loadBalancers ?? []).length) {
      throw new Error(`private ECS service ${name} is attached to a load balancer`);
    }
  }
  if (targetGroups.length !== ingress.length) throw new Error("ALB has target groups for private or unknown services");
  const defaults = listener.DefaultActions ?? [];
  if (hasPortal) {
    if (
      defaults.length !== 1 ||
      defaults[0]?.Type !== "forward" ||
      defaults[0].TargetGroupArn !== targets.get("portal")
    ) {
      throw new Error("portal listener default does not route only to portal");
    }
  } else if (
    defaults.length !== 1 ||
    defaults[0]?.Type !== "fixed-response" ||
    defaults[0].FixedResponseConfig?.StatusCode !== "404" ||
    defaults[0].TargetGroupArn
  ) {
    throw new Error("non-portal listener default must return a fixed 404 response");
  }
  const rules =
    awsJson<{
      Rules?: Array<{
        IsDefault?: boolean;
        Actions?: Array<{ Type?: string; TargetGroupArn?: string }>;
        Conditions?: Array<{
          Field?: string;
          Values?: string[];
          PathPatternConfig?: { Values?: string[] };
          HostHeaderConfig?: { Values?: string[] };
        }>;
      }>;
    }>(aws, ["elbv2", "describe-rules", "--listener-arn", listener.ListenerArn!]).Rules ?? [];
  const nonDefault = rules.filter((rule) => !rule.IsDefault);
  if (hasPortal && !coreHosts.length && nonDefault.length)
    throw new Error("portal mode must not expose non-default ALB rules");
  if (hasPortal && coreHosts.length) {
    const found: string[] = [];
    for (const rule of nonDefault) {
      const action = rule.Actions?.length === 1 ? rule.Actions[0] : undefined;
      const condition = rule.Conditions?.length === 1 ? rule.Conditions[0] : undefined;
      const values =
        condition?.Field === "host-header" ? (condition.HostHeaderConfig?.Values ?? condition.Values ?? []) : [];
      if (action?.Type !== "forward" || action.TargetGroupArn !== targets.get("core") || !values.length) {
        throw new Error(
          `portal ALB has a non-default rule that is not a single host-header forward to core (expected only ${coreHosts.join(", ")})`,
        );
      }
      found.push(...values.map((value) => value.toLowerCase()));
    }
    if (found.length !== coreHosts.length || coreHosts.some((host) => !found.includes(host))) {
      throw new Error(
        `portal ALB host rules must route exactly ${coreHosts.join(", ")} to core (live: ${found.join(", ") || "none"})`,
      );
    }
  }
  if (!hasPortal) {
    const coreRule = nonDefault.filter(
      (rule) =>
        rule.Actions?.length === 1 &&
        rule.Actions[0]?.Type === "forward" &&
        rule.Actions[0].TargetGroupArn === targets.get("core") &&
        rule.Conditions?.length === 1 &&
        rule.Conditions[0]?.Field === "path-pattern" &&
        rule.Conditions[0].PathPatternConfig?.Values?.length === 1 &&
        rule.Conditions[0].PathPatternConfig.Values[0] === "/v1/*",
    );
    if (coreRule.length !== 1) {
      throw new Error("non-portal ALB must route only /v1/* directly to core");
    }
    if (nonDefault.length !== 1) throw new Error("non-portal ALB has unexpected non-default rules");
  }
  return targets;
}

function assertAwsPublicFrontDoor(config: QmConfig): void {
  try {
    assertAwsPublicRouting(config);
  } catch (error) {
    throw new CliError(`AWS public front door is not ready for deployment: ${errMessage(error)}`);
  }
}

async function assertAwsPublicNetwork(config: QmConfig, rejectServerErrors = false): Promise<void> {
  assertAwsLeaseHeld();
  const albHostname = awsPublicFrontDoor(config).dnsName.toLowerCase().replace(/\.$/, "");
  const endpoints = [
    { label: "public URL", origin: awsPublicOrigin(config), url: config.publicUrl },
    ...(config.apiUrl && config.apiUrl !== config.publicUrl
      ? [{ label: "public API URL", origin: new URL(config.apiUrl), url: config.apiUrl }]
      : []),
  ];
  for (const endpoint of endpoints) {
    const originHostname = endpoint.origin.hostname.toLowerCase().replace(/\.$/, "");
    if (originHostname !== albHostname) {
      const [cnames, publicAddresses, albAddresses] = await Promise.all([
        resolveCname(originHostname).catch(() => []),
        lookup(originHostname, { all: true })
          .then((values) => values.map((value) => value.address))
          .catch(() => []),
        lookup(albHostname, { all: true })
          .then((values) => values.map((value) => value.address))
          .catch(() => []),
      ]);
      assertAwsLeaseHeld();
      const cnameMatch = cnames.some((name) => name.toLowerCase().replace(/\.$/, "") === albHostname);
      const albSet = new Set(albAddresses);
      const addressMatch = publicAddresses.some((address) => albSet.has(address));
      if (!cnameMatch && !addressMatch) {
        const originLabel = endpoint.label === "public URL" ? "public" : "public API";
        throw new CliError(
          `AWS ${originLabel} origin ${originHostname} does not resolve to this stack's ALB ${albHostname}`,
        );
      }
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      assertAwsLeaseHeld();
      const response = await fetch(endpoint.url, { redirect: "manual", signal: controller.signal });
      assertAwsLeaseHeld();
      await response.body?.cancel();
      assertAwsLeaseHeld();
      if (rejectServerErrors && response.status >= 500) throw new Error(`HTTP ${response.status}`);
    } catch (error) {
      assertAwsLeaseHeld();
      throw new CliError(
        `AWS ${endpoint.label} is not reachable with trusted TLS and matching DNS: ${errMessage(error)}`,
      );
    } finally {
      clearTimeout(timeout);
    }
  }
  assertAwsLeaseHeld();
}

function assertAwsHealthyIngress(config: QmConfig, targets: ReadonlyMap<string, string>): void {
  const aws = requireAws(config);
  for (const [name, targetGroupArn] of targets) {
    const health =
      awsJson<{ TargetHealthDescriptions?: Array<{ TargetHealth?: { State?: string; Reason?: string } }> }>(aws, [
        "elbv2",
        "describe-target-health",
        "--target-group-arn",
        targetGroupArn,
      ]).TargetHealthDescriptions ?? [];
    if (!health.some((target) => target.TargetHealth?.State === "healthy")) {
      const states = health.map(
        (target) =>
          `${target.TargetHealth?.State ?? "unknown"}${target.TargetHealth?.Reason ? ` (${target.TargetHealth.Reason})` : ""}`,
      );
      throw new Error(`${name} target group has no healthy targets${states.length ? `: ${states.join(", ")}` : ""}`);
    }
  }
}

export function assertAwsDeploymentStorage(config: QmConfig): void {
  const aws = requireAws(config);
  const tableName = deployLocksTable(aws);
  const table = awsJson<{ Table?: { TableStatus?: string } }>(aws, [
    "dynamodb",
    "describe-table",
    "--table-name",
    tableName,
  ]).Table;
  if (table?.TableStatus !== "ACTIVE")
    throw new Error(`deploy-lock table ${tableName} is ${table?.TableStatus ?? "missing"}`);
  awsText(aws, [
    "s3api",
    "list-objects-v2",
    "--bucket",
    awsObjectStoreBucket(config),
    "--prefix",
    "deployment/",
    "--max-keys",
    "1",
  ]);
}

export function probeAwsSecretStore(
  secrets: ComputedSecret[],
  read: (name: string) => string,
  checkPublicApiUrl: () => void,
): { values: Map<string, string>; pending: string[]; failures: string[] } {
  const values = new Map<string, string>();
  const pending: string[] = [];
  const failures: string[] = [];
  for (const secret of secrets) {
    const label = secret.required ? `secret ${secret.name}` : `optional secret ${secret.name}`;
    try {
      const value = read(secret.name);
      assertNoNulSecret(secret.name, value);
      if (isInvalidSecret(secret.name, value)) throw new Error("missing, placeholder, or insecure value");
      values.set(secret.name, value);
      if (secret.required && secret.name === "PUBLIC_API_URL") checkPublicApiUrl();
      step(secret.required ? `${label}: ok` : `${label}: configured`);
    } catch (error) {
      if (awsCliErrorMatches(error, "ResourceNotFoundException")) {
        if (secret.required) {
          pending.push(secret.name);
          step(`${label}: not pushed yet — run \`qm secrets push\` before the first deploy`);
        } else {
          warn(`${label}: not configured`);
        }
      } else {
        failures.push(`${label}: ${errMessage(error)}`);
        warn(`${label}: failed`);
      }
    }
  }
  const invalid = [...invalidSecretNames(values)].sort();
  if (invalid.length) failures.push(`secrets failed runtime validation: ${invalid.join(", ")}`);
  return { values, pending, failures };
}

export async function awsDoctor(config: QmConfig, configDir: string): Promise<void> {
  const { aws } = awsTopology(config, configDir);
  const hasVendoredInfra = existsSync(join(configDir, "infra"));
  const tfvars = hasVendoredInfra ? readRenderedFile(configDir, ["infra", "terraform.tfvars"]) : undefined;
  const variables = tfvars === undefined ? undefined : readRenderedFile(configDir, ["infra", "variables.tf"]);
  header(`qm doctor — ${config.orgId} (aws)`);
  assertAwsCallerAccount(aws);
  step("AWS caller account: ok");
  const failures: string[] = [];
  const check = (label: string, fn: () => void): void => {
    try {
      fn();
      step(`${label}: ok`);
    } catch (error) {
      failures.push(`${label}: ${(error as Error).message}`);
      warn(`${label}: failed`);
    }
  };
  const checkAsync = async (label: string, fn: () => Promise<void>): Promise<void> => {
    try {
      await fn();
      step(`${label}: ok`);
    } catch (error) {
      failures.push(`${label}: ${(error as Error).message}`);
      warn(`${label}: failed`);
    }
  };
  if (tfvars !== undefined)
    check("Terraform coordinates", () => {
      const drift = terraformVarsDrift(config, tfvars, variables === undefined ? [] : declaredVariables(variables));
      if (drift.length)
        throw new Error(`terraform.tfvars drift (${drift.join(", ")}); run \`qm infra render\` and commit the result`);
    });
  else step("Terraform coordinates: external infrastructure (no vendored infra/terraform.tfvars)");
  check("ECS cluster", () => {
    const cluster = awsJson<{ clusters?: Array<{ status?: string }> }>(aws, [
      "ecs",
      "describe-clusters",
      "--clusters",
      aws.cluster,
    ]).clusters?.[0];
    if (cluster?.status !== "ACTIVE") throw new Error(`cluster is ${cluster?.status ?? "missing"}`);
  });
  check("deployment state stores", () => assertAwsDeploymentStorage(config));
  const snapshotBucket = config.env.core?.S3_BUCKET?.trim();
  if (snapshotBucket)
    check(`core S3 bucket ${snapshotBucket}`, () => {
      try {
        awsText(aws, ["s3api", "head-bucket", "--bucket", snapshotBucket]);
      } catch (error) {
        throw new Error(`the env.core.S3_BUCKET override is missing or not readable: ${errMessage(error)}`, {
          cause: error,
        });
      }
    });
  check("deployment publisher MicroVM image", () => assertAwsDeployImage(config));
  check("deploy role", () => {
    const expectedSubject = githubTrustSubject(configDir, aws.deployBranch, aws.deployEnvironment);
    const role = awsJson<{ Role?: { Arn?: string; AssumeRolePolicyDocument?: { Statement?: unknown } } }>(aws, [
      "iam",
      "get-role",
      "--role-name",
      aws.deployRoleArn.split("/").pop()!,
    ]);
    if (role.Role?.Arn !== aws.deployRoleArn) throw new Error("role ARN differs from config");
    assertGithubDeployTrust(role.Role.AssumeRolePolicyDocument?.Statement, aws.accountId, expectedSubject);
    if (process.env.GITHUB_ACTIONS === "true") {
      const caller = awsJson<{ Arn?: string }>(aws, ["sts", "get-caller-identity"]);
      const roleName = aws.deployRoleArn.split("/").pop()!;
      if (!caller.Arn?.includes(`:assumed-role/${roleName}/`))
        throw new Error("workflow is not actually running as the configured deploy role");
    }
  });
  check("GitHub OIDC provider", () => {
    const arn = `arn:aws:iam::${aws.accountId}:oidc-provider/token.actions.githubusercontent.com`;
    const provider = awsJson<{ Url?: string; ClientIDList?: string[] }>(aws, [
      "iam",
      "get-open-id-connect-provider",
      "--open-id-connect-provider-arn",
      arn,
    ]);
    if (provider.Url !== "token.actions.githubusercontent.com")
      throw new Error("GitHub OIDC provider URL is incorrect");
    if (!provider.ClientIDList?.includes("sts.amazonaws.com"))
      throw new Error("GitHub OIDC provider does not trust sts.amazonaws.com");
  });
  check("RDS", () => {
    const database = awsJson<{
      DBInstances?: Array<{
        DBInstanceStatus?: string;
        Endpoint?: { Address?: string; Port?: number };
        VpcSecurityGroups?: Array<{ VpcSecurityGroupId?: string }>;
      }>;
    }>(aws, ["rds", "describe-db-instances", "--db-instance-identifier", rdsInstanceIdentifier(aws)]).DBInstances?.[0];
    if (database?.DBInstanceStatus !== "available")
      throw new Error(`database is ${database?.DBInstanceStatus || "missing"}`);
    const coreService = aws.services.core;
    if (!coreService) throw new Error("aws.services.core is missing");
    const coreGroups =
      awsJson<{ services?: Array<{ networkConfiguration?: { awsvpcConfiguration?: { securityGroups?: string[] } } }> }>(
        aws,
        ["ecs", "describe-services", "--cluster", aws.cluster, "--services", coreService.ecsService],
      ).services?.[0]?.networkConfiguration?.awsvpcConfiguration?.securityGroups ?? [];
    const databaseGroups = (database.VpcSecurityGroups ?? []).flatMap((group) =>
      group.VpcSecurityGroupId ? [group.VpcSecurityGroupId] : [],
    );
    const permissions = databaseGroups.length
      ? (awsJson<{
          SecurityGroups?: Array<{
            IpPermissions?: Array<{
              IpProtocol?: string;
              FromPort?: number;
              ToPort?: number;
              UserIdGroupPairs?: Array<{ GroupId?: string }>;
            }>;
          }>;
        }>(aws, ["ec2", "describe-security-groups", "--group-ids", ...databaseGroups]).SecurityGroups?.flatMap(
          (group) => group.IpPermissions ?? [],
        ) ?? [])
      : [];
    const reachable = permissions.some(
      (permission) =>
        permission.IpProtocol === "tcp" &&
        (permission.FromPort ?? Infinity) <= 5432 &&
        (permission.ToPort ?? -Infinity) >= 5432 &&
        (permission.UserIdGroupPairs ?? []).some((pair) => pair.GroupId && coreGroups.includes(pair.GroupId)),
    );
    if (!reachable) throw new Error("database security groups do not allow the core ECS service on port 5432");
    const databaseUrl = awsText(aws, [
      "secretsmanager",
      "get-secret-value",
      "--secret-id",
      `${aws.secretsPrefix}DATABASE_URL`,
      "--query",
      "SecretString",
    ]);
    assertNoNulSecret("DATABASE_URL", databaseUrl);
    if (!database.Endpoint?.Address || new URL(databaseUrl).hostname !== database.Endpoint.Address)
      throw new Error("DATABASE_URL does not point at the configured RDS endpoint");
  });
  const ecsServices = new Map<string, AwsEcsRoutingService>();
  for (const service of Object.keys(aws.services)) {
    const spec = awsServiceSpec(aws, service);
    check(`ECS service ${spec.ecsService}`, () => {
      const found = awsJson<{
        services?: Array<{
          status?: string;
          serviceRegistries?: Array<{ registryArn?: string }>;
          loadBalancers?: Array<{ targetGroupArn?: string }>;
        }>;
      }>(aws, ["ecs", "describe-services", "--cluster", aws.cluster, "--services", spec.ecsService]).services?.[0];
      if (found?.status !== "ACTIVE") throw new Error(`service is ${found?.status ?? "missing"}`);
      ecsServices.set(service, found);
    });
    check(`ECR ${spec.ecrRepository}`, () => {
      const repository = awsJson<{ repositories?: Array<{ repositoryArn?: string }> }>(aws, [
        "ecr",
        "describe-repositories",
        "--repository-names",
        spec.ecrRepository,
      ]).repositories?.[0];
      if (!repository?.repositoryArn) throw new Error("repository is missing");
    });
  }
  const logGroups = new Map<string, string[]>();
  for (const [name, spec] of Object.entries(aws.services)) {
    const group = spec.logGroup ?? `/ecs/${spec.ecsService}`;
    logGroups.set(group, [...(logGroups.get(group) ?? []), name]);
  }
  for (const [group, names] of logGroups) {
    check(`CloudWatch log group ${group}`, () => {
      const found =
        awsJson<{ logGroups?: Array<{ logGroupName?: string }> }>(aws, [
          "logs",
          "describe-log-groups",
          "--log-group-name-prefix",
          group,
        ]).logGroups ?? [];
      if (!found.some((item) => item.logGroupName === group)) {
        throw new Error(
          `log group is missing — the awslogs driver refuses to start ${names.join(", ")} without it; create it or fix aws.services.${names.join("/")}.logGroup`,
        );
      }
    });
  }
  check("Cloud Map routing", () => {
    const namespaces =
      awsJson<{ Namespaces?: Array<{ Id?: string; Name?: string }> }>(aws, ["servicediscovery", "list-namespaces"])
        .Namespaces ?? [];
    const namespace = namespaces.find((item) => item.Name === aws.networking.cloudMapNamespace);
    if (!namespace?.Id) throw new Error(`namespace ${aws.networking.cloudMapNamespace} is missing`);
    const services =
      awsJson<{ Services?: Array<{ Arn?: string; Name?: string }> }>(aws, [
        "servicediscovery",
        "list-services",
        "--filters",
        `Name=NAMESPACE_ID,Values=${namespace.Id},Condition=EQ`,
      ]).Services ?? [];
    for (const name of Object.keys(aws.services)) {
      const discovery = services.find((service) => service.Name === name);
      if (!discovery?.Arn) throw new Error(`service ${name} is missing from ${aws.networking.cloudMapNamespace}`);
      const registries = ecsServices.get(name)?.serviceRegistries ?? [];
      if (!registries.some((registry) => registry.registryArn === discovery.Arn))
        throw new Error(`ECS service ${name} is not registered to its Cloud Map service`);
    }
  });
  check("ALB routing", () => assertAwsPublicRouting(config, ecsServices));
  await checkAsync("public URL DNS and TLS", () => assertAwsPublicNetwork(config));
  const probe = probeAwsSecretStore(
    computedSecrets(config),
    (name) =>
      awsText(aws, [
        "secretsmanager",
        "get-secret-value",
        "--secret-id",
        `${aws.secretsPrefix}${name}`,
        "--query",
        "SecretString",
      ]),
    () => assertAwsPublicApiUrl(config),
  );
  failures.push(...probe.failures);
  const runtimeSecrets = probe.values;
  if (failures.length) throw new CliError(`doctor failed:\n${failures.map((failure) => `  - ${failure}`).join("\n")}`);
  const runtimeNames = ["SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"] as const;
  const priorRuntime = new Map(runtimeNames.map((name) => [name, process.env[name]]));
  for (const name of runtimeNames) {
    const stored = runtimeSecrets.get(name);
    if (stored !== undefined) process.env[name] = stored;
    else delete process.env[name];
  }
  try {
    await doctorCommon(config, runtimeSecrets, { configDir, requiredSecretValues: probe.pending.length === 0 });
  } finally {
    for (const name of runtimeNames) {
      const prior = priorRuntime.get(name);
      if (prior === undefined) delete process.env[name];
      else process.env[name] = prior;
    }
  }
  ok("all AWS deployment prerequisites are ready");
}

async function checkLive(
  config: QmConfig,
  opts: {
    report?: boolean;
    configDir?: string;
    configIdentity: FileIdentity;
    envFile?: string;
    sandboxDir?: string;
  },
): Promise<void> {
  const configDir = opts.configDir ?? process.cwd();
  const buildAdmission = sourceBuildAdmission(config, configDir, opts.envFile, opts.configIdentity);
  const { aws, workloads: services, plugins: resolvedPlugins } = awsTopology(config, configDir);
  const plugins = new Map(resolvedPlugins.map((plugin) => [plugin.name, plugin]));
  assertAwsCallerAccount(aws);
  const failures: string[] = [];
  try {
    assertAwsDeployImage(config);
  } catch (error) {
    failures.push(`deploy image drift: ${errMessage(error)}`);
  }
  const secrets = awsSecretSnapshot(config);
  const arns = secrets.arns;
  const buildEnv = awsSourceBuildEnvironment(buildAdmission, secrets.values);
  const states = describedServices(config, services);
  const manifest = currentDeploymentManifest(aws);
  if (!manifest)
    throw new CliError("live drift detected: no current AWS deployment manifest", { clause: "aws.live-drift" });
  const desiredImages: Record<string, string> = {};
  for (const service of services) {
    const provenance = manifest.imageProvenance?.[service];
    if (!provenance) continue;
    const plugin = plugins.get(service);
    if (provenance.kind === "source-build") {
      if (plugin?.kind === "image" || (isServiceName(service) && config.imageOverrides[service])) {
        failures.push(
          `${service}: image build provenance drift (deployed from source, current workload uses a configured image)`,
        );
      }
      continue;
    }
    if (plugin?.kind === "source") {
      failures.push(
        `${service}: image build provenance drift (deployed from a configured image, current workload builds from source)`,
      );
      continue;
    }
    const source = workloadSourceImage(config, service, plugin);
    if (!source) {
      failures.push(`${service}: configured image source is missing for prebuilt deployment`);
      continue;
    }
    try {
      desiredImages[service] = await plannedWorkloadImage(config, service, plugin, buildEnv);
    } catch (error) {
      failures.push(`${service}: could not resolve desired image: ${errMessage(error)}`);
    }
  }
  if (manifest.imageLabel !== aws.imageLabel)
    failures.push(
      `deployment manifest label ${manifest.imageLabel ?? "missing"} does not match configured release ${aws.imageLabel ?? "missing"}`,
    );
  for (const service of services) {
    const state = states.get(service)!;
    const expectedTask = manifest.tasks[service];
    if (!expectedTask) {
      failures.push(`${service}: missing from current deployment manifest ${manifest.id}`);
      continue;
    }
    const primary = (state.deployments ?? []).filter((deployment) => deployment.status === "PRIMARY");
    const wantCount = workloadDesiredCount(config, service);
    const draining = primary[0]?.rolloutState === "IN_PROGRESS" && (primary[0]?.runningCount ?? 0) >= wantCount;
    if (
      state.status !== "ACTIVE" ||
      state.desiredCount !== wantCount ||
      (draining ? (state.runningCount ?? 0) < wantCount : state.runningCount !== wantCount)
    ) {
      failures.push(
        `${service}: runtime is ${state.status ?? "missing"} with ${state.runningCount ?? 0}/${state.desiredCount ?? 0} running, expected ${wantCount}`,
      );
    }
    if (
      primary.length !== 1 ||
      primary[0]?.taskDefinition !== state.taskDefinition ||
      (primary[0]?.rolloutState !== "COMPLETED" && !draining)
    ) {
      failures.push(`${service}: configured task is not the sole healthy PRIMARY deployment`);
    }
    if (state.taskDefinition !== expectedTask)
      failures.push(`${service}: service task does not match deployment manifest ${manifest.id}`);
    const live =
      awsJson<{ taskDefinition?: Record<string, unknown> }>(aws, [
        "ecs",
        "describe-task-definition",
        "--task-definition",
        expectedTask,
      ]).taskDefinition ?? null;
    if (!live) {
      failures.push(`${service}: no live task definition`);
      continue;
    }
    const container = (live.containerDefinitions as Array<Record<string, unknown>> | undefined)?.find(
      (item) => item.name === service,
    );
    const liveEnv = Object.fromEntries(
      ((container?.environment as Array<{ name: string; value: string }> | undefined) ?? []).map((item) => [
        item.name,
        item.value,
      ]),
    );
    const expectedEnv = workloadEnvironment(config, service);
    if (canonicalJson(liveEnv) !== canonicalJson(expectedEnv))
      failures.push(`${service}: environment drift (including live-only keys)`);
    const expectedSecrets = workloadSecrets(config, service, arns)
      .flatMap((secret) => containerSecretNames(service, secret))
      .sort();
    const liveSecretEntries = (container?.secrets as Array<{ name: string; valueFrom?: string }> | undefined) ?? [];
    const liveSecrets = liveSecretEntries.map((secret) => secret.name).sort();
    if (JSON.stringify(liveSecrets) !== JSON.stringify(expectedSecrets)) failures.push(`${service}: secret-name drift`);
    const repository = expectedWorkloadImageRepository(config, service);
    if (typeof container?.image !== "string" || !isPinnedWorkloadImage(config, service, container.image)) {
      failures.push(`${service}: live image is not a digest from ${repository}`);
    } else {
      const desiredImage = desiredImages[service];
      if (desiredImage && container.image !== desiredImage) {
        failures.push(`${service}: image drift (live ${container.image}, desired ${desiredImage})`);
      }
      const comparisonImage = desiredImage ?? `${repository}@sha256:${"0".repeat(64)}`;
      const fields = taskDefinitionDiff(renderTaskDefinition(config, service, comparisonImage, arns), live).filter(
        (field) => desiredImage || field !== `taskDefinition.containerDefinitions.${service}.image`,
      );
      if (fields.length) failures.push(`${service}: task-definition drift (${fields.join(", ")})`);
    }
  }
  try {
    const targets = assertAwsPublicRouting(config);
    assertAwsHealthyIngress(config, targets);
  } catch (error) {
    failures.push(`public front-door drift: ${errMessage(error)}`);
  }
  try {
    await retryLiveProbe(() => assertAwsPublicNetwork(config, true));
  } catch (error) {
    failures.push(`public network drift: ${errMessage(error)}`);
  }
  if (!manifest.layer) {
    failures.push(`deployment manifest ${manifest.id} has no deployment-layer artifact`);
  } else {
    try {
      getDeploymentLayerArtifact(config, manifest.layer);
      if (opts.sandboxDir && existsSync(opts.sandboxDir)) {
        const directoryHash = createHash("sha256").update(deploymentLayerBody(opts.sandboxDir)).digest("hex");
        if (directoryHash !== manifest.layer.sha256)
          failures.push("deployment layer does not match the deployment directory");
      }
      await retryLiveProbe(async () => {
        const state = await currentDeploymentLayerState({
          config,
          configIdentity: opts.configIdentity,
          transport: awsDeploymentLayerTransport,
          configDir,
          ...(opts.envFile !== undefined ? { envFile: opts.envFile } : {}),
        });
        if (state.contentHash !== manifest.layer!.sha256)
          throw new Error("deployment layer content does not match the current manifest");
        if (state.status !== "applied" || state.runtimeContentHash !== manifest.layer!.sha256)
          throw new Error("deployment layer is not applied by the live core");
      });
    } catch (error) {
      failures.push(`deployment layer drift: ${errMessage(error)}`);
    }
  }
  if (!failures.length) {
    try {
      await awsLiveSession(config, states.get("core")!);
      if (opts.report ?? true) step("core: private live session smoke passed");
    } catch (error) {
      failures.push(`core: private live session smoke failed: ${errMessage(error)}`);
    }
  }
  if (failures.length)
    throw new CliError(`live drift detected:\n${failures.map((failure) => `  - ${failure}`).join("\n")}`, {
      clause: "aws.live-drift",
    });
  if (opts.report ?? true) ok("live AWS deployment matches the directory in both directions");
}

export async function awsCheckLive(
  config: QmConfig,
  opts: {
    report?: boolean;
    configDir?: string;
    configIdentity: FileIdentity;
    envFile?: string;
    sandboxDir?: string;
  },
): Promise<void> {
  try {
    await checkLive(config, opts);
  } catch (error) {
    if (error instanceof CliError && error.clause === "aws.live-drift") throw error;
    throw new CliError(errMessage(error), { clause: "aws.live-drift", cause: error });
  }
}
