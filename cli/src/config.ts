import { existsSync } from "node:fs";
import { isIP } from "node:net";
import { isAbsolute, resolve } from "node:path";
import { CliError, die, errMessage } from "./log.ts";
import {
  AUTH_BROKER_ENV_KEYS,
  AUTH_SERVICE_BROKER_ENV_KEYS,
  SERVICE_NAMES,
  VIRTUAL_SERVICE_NAMES,
  isDeclaredService,
  isServiceName,
  isVirtualService,
  pluginNameError,
  runnableServices,
  serviceDef,
  virtualServiceEnv,
  type DeclaredServiceName,
  type ServiceName,
} from "./services.ts";
import {
  hostingProviderChoices,
  isTarget,
  type Target,
  SANDBOX_BACKEND_POLICY,
  targetsAllowingSandboxBackend,
} from "./providers.ts";
import {
  canonicalHttpOrigin as normalizedHttpOrigin,
  decodeUtf8,
  envNum,
  isEnvVarName,
  isMissingOrPlaceholder,
  readRegularFileSnapshot,
  readUtf8File,
  validEmail,
  validEmailDomain,
  type FileIdentity,
  type RegularFileSnapshot,
} from "./util.ts";

export const CONFIG_FILENAME = "qm.config.jsonc";

export const CONTRACT_VERSION = 1 as const;

export const validOrgId = (value: string): boolean =>
  value.length <= 63 && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(value);

export type { Target } from "./providers.ts";

export interface PluginSecret {
  name: string;
  description?: string;
  required?: boolean;
}

export interface PluginEntry {
  name: string;
  image?: string;
  env?: Record<string, string>;
  secrets?: PluginSecret[];
}

export interface SandboxConfig {
  backend?: "local" | "sprites" | "aws";
  app?: string;
  namePrefix?: string;
  image?: string;
  baseImage?: string;
  env?: Record<string, string>;
  secretEnv?: string[];
}

export interface SecurityScreenConfig {
  backend: "proxy";
  provider: string;
  endpoint: string;
  rollout: "shadow" | "enforce";
}

export interface AwsServiceConfig {
  ecrRepository: string;
  ecsService: string;
  cpu: number;
  memory: number;
  desiredCount?: number;
  architecture?: "arm64" | "amd64";
  taskRoleArn?: string;
  executionRoleArn?: string;
  buildArgs?: Record<string, string>;
  dockerfile?: string;
  targetGroup?: string;
  logGroup?: string;
  stopTimeout?: number;
}

export interface AwsConfig {
  accountId: string;
  region: string;
  cluster: string;
  deployRoleArn: string;
  secretsPrefix: string;
  imageLabel: string;
  alb?: string;
  rdsInstance?: string;
  predeployDbSnapshot?: boolean;
  dbRetentionMinDays?: number;
  deployBranch?: string;
  deployEnvironment?: string;
  objectStoreBucket?: string;
  networking: {
    cloudMapNamespace: string;
  };
  services: Record<string, AwsServiceConfig>;
}

export function awsWorkloadArchitecture(config: QmConfig, workload: string): "arm64" | "amd64" {
  const services = config.aws?.services;
  if (!services || !Object.hasOwn(services, workload)) throw new CliError(`aws.services.${workload} is missing`);
  const service = services[workload]!;
  const externalImage =
    config.plugins.some((plugin) => plugin.name === workload && plugin.image) ||
    (isServiceName(workload) && Boolean(config.imageOverrides[workload]));
  if (!service.architecture && externalImage) {
    throw new CliError(
      `aws.services.${workload}.architecture is required because ${workload} uses an external prebuilt image`,
    );
  }
  return service.architecture ?? "arm64";
}

export const MODEL_PROVIDERS = ["anthropic", "openai", "openrouter"] as const;
export type ModelProvider = (typeof MODEL_PROVIDERS)[number];

export const MODEL_PROVIDER_KEYS: Readonly<Record<ModelProvider, string>> = {
  anthropic: "ANTHROPIC_API_KEY",
  openai: "OPENAI_API_KEY",
  openrouter: "OPENROUTER_API_KEY",
};

export const MODEL_PROVIDER_HARNESSES: Readonly<Record<ModelProvider, readonly string[]>> = {
  anthropic: ["pi", "opencode", "claude", "mock"],
  openai: ["pi", "opencode", "codex", "mock"],
  openrouter: ["pi", "mock"],
};

export const isModelProvider = (value: unknown): value is ModelProvider =>
  typeof value === "string" && (MODEL_PROVIDERS as readonly string[]).includes(value);

export const EMAIL_TRANSPORTS = ["resend", "smtp"] as const;
export type EmailTransport = (typeof EMAIL_TRANSPORTS)[number];

export const isEmailTransport = (value: unknown): value is EmailTransport =>
  typeof value === "string" && (EMAIL_TRANSPORTS as readonly string[]).includes(value);

export interface QmConfig {
  contract: typeof CONTRACT_VERSION;
  orgId: string;
  publicUrl: string;
  apiUrl?: string;
  target: Target;
  model?: string;
  modelProvider?: ModelProvider;
  basePort?: number;
  services: DeclaredServiceName[];
  plugins: PluginEntry[];
  skills: string[];
  env: Partial<Record<DeclaredServiceName, Record<string, string>>>;
  secretEnv?: Partial<Record<DeclaredServiceName, Record<string, string>>>;
  securityScreen?: SecurityScreenConfig;
  vms?: Partial<Record<ServiceName, { size?: string; memory?: string }>>;
  imageOverrides: Partial<Record<ServiceName, string>>;
  sandbox?: SandboxConfig;
  botName?: string;
  orgName?: string;
  appPrefix?: string;
  region?: string;
  flyOrg?: string;
  imageFrom?: string;
  deployAppPrefix?: string;
  aws?: AwsConfig;
}

const BUILT_IN_PROVIDER_ENVIRONMENT_NAMES = [
  "ALLOW_UNSIGNED_TEST_IDENTITY",
  "AWS_ACCESS_KEY_ID",
  "AWS_CONFIG_FILE",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_DEFAULT_PROFILE",
  "AWS_DEFAULT_REGION",
  "AWS_EC2_METADATA_SERVICE_ENDPOINT",
  "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
  "AWS_PROFILE",
  "AWS_REGION",
  "AWS_ROLE_ARN",
  "AWS_ROLE_SESSION_NAME",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "DATA_DIR",
  "ECS_AGENT_URI",
  "ECS_TASK_PROTECTION",
  "FLY_ALLOC_ID",
  "FLY_APP_NAME",
  "FLY_IMAGE_REF",
  "FLY_MACHINE_ID",
  "FLY_MACHINE_VERSION",
  "FLY_PRIVATE_IP",
  "FLY_PROCESS_GROUP",
  "FLY_PUBLIC_IP",
  "FLY_VM_MEMORY_MB",
  "KUBERNETES_SERVICE_HOST",
  "NODE_ENV",
  "PRIMARY_REGION",
] as const;

const CORE_PROVIDER_ENVIRONMENT_NAMES = [
  "AGENT_API_URL",
  "AWS_DEPLOY_REGION",
  "CORE_API_URL",
  "DATABASE_CA_CERT_FILE",
  "DOCKER_HOST",
  "FLY_DEPLOY_APP_PREFIX",
  "FLY_ORG",
  "ORG_ID",
  "ORG_BRAND_ORG_NAME",
  "ORG_BRAND_SELF_LABEL",
  "PI_MODEL",
  "QM_CORE_CONTAINER",
  "REQUIRE_SIGNED_PORTAL_IDENTITY",
  "RUN_STORE",
  "SESSION_STORE",
  "SLACK_API_URL",
] as const;

const CORE_PLAINTEXT_PROVIDER_ENVIRONMENT_NAMES = [
  "AWS_DEPLOY_DATA_BUCKET",
  "AWS_DEPLOY_DATA_PREFIX",
  "AWS_DEPLOY_DATA_ROLE_ARN",
  "AWS_DEPLOY_EGRESS_CONNECTORS",
  "AWS_DEPLOY_INGRESS_CONNECTORS",
  "AWS_DEPLOY_PROFILE",
  "AWS_SANDBOX_EGRESS_CONNECTORS",
  "AWS_SANDBOX_INGRESS_CONNECTORS",
  "AWS_SANDBOX_PROFILE",
  "AWS_SANDBOX_S3_PREFIX",
  "DEPLOYMENT_LAYER",
  "FLY_REGION",
  "S3_BUCKET",
  "S3_PREFIX",
  "S3_REGION",
  "SECRETS_BACKEND",
  "SECRETS_PREFIX",
  "SNAPSHOT_STORE",
  "TRANSFER_STORE",
] as const;

const PLUGIN_PROVIDER_ENVIRONMENT_NAMES = [
  "AWS_ACCESS_KEY_ID",
  "AWS_CONFIG_FILE",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_DEFAULT_PROFILE",
  "AWS_DEFAULT_REGION",
  "AWS_EC2_METADATA_SERVICE_ENDPOINT",
  "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
  "AWS_PROFILE",
  "AWS_REGION",
  "AWS_ROLE_ARN",
  "AWS_ROLE_SESSION_NAME",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "CORE_API_URL",
  "CORE_ORG_ID",
  "FLY_REGION",
  "PORT",
  "QM_DEPLOYMENT_ID",
] as const;

const CORE_RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES = [
  "ALLOW_UNAUTHENTICATED_CORE",
  "APPROVAL_SUMMARY_TIMEOUT_MS",
  "AWS_DEPLOY_AGENT_PORT",
  "AWS_DEPLOY_APP_PORT",
  "AWS_DEPLOY_APPS_DOMAIN",
  "AWS_DEPLOY_DATA_BUCKET",
  "AWS_DEPLOY_DATA_PREFIX",
  "AWS_DEPLOY_DATA_ROLE_ARN",
  "AWS_DEPLOY_EGRESS_CONNECTORS",
  "AWS_DEPLOY_EXEC_ROLE_ARN",
  "AWS_DEPLOY_IMAGE",
  "AWS_DEPLOY_IMAGE_VERSION",
  "AWS_DEPLOY_INGRESS_CONNECTORS",
  "AWS_DEPLOY_MAX_DURATION_SEC",
  "AWS_DEPLOY_MAX_IDLE_SEC",
  "AWS_DEPLOY_PROFILE",
  "AWS_DEPLOY_ROTATE_AFTER_SEC",
  "AWS_DEPLOY_SNAPSHOT_INTERVAL_MS",
  "AWS_DEPLOY_SUSPENDED_SEC",
  "AWS_DEPLOY_TOKEN_TTL_MIN",
  "AWS_SANDBOX_AGENT_PORT",
  "AWS_SANDBOX_CPUS",
  "AWS_SANDBOX_DISK_GB",
  "AWS_SANDBOX_EGRESS_CONNECTORS",
  "AWS_SANDBOX_EXEC_ROLE_ARN",
  "AWS_SANDBOX_IMAGE",
  "AWS_SANDBOX_IMAGE_VERSION",
  "AWS_SANDBOX_INGRESS_CONNECTORS",
  "AWS_SANDBOX_MAX_DURATION_SEC",
  "AWS_SANDBOX_MAX_IDLE_SEC",
  "AWS_SANDBOX_MEMORY_MB",
  "AWS_SANDBOX_PROFILE",
  "AWS_SANDBOX_REGION",
  "AWS_SANDBOX_ROTATE_AFTER_SEC",
  "AWS_SANDBOX_S3_BUCKET",
  "AWS_SANDBOX_S3_PREFIX",
  "AWS_SANDBOX_SNAPSHOT_INTERVAL_MS",
  "AWS_SANDBOX_SUSPENDED_SEC",
  "BACKGROUND_JOB_TTL_MAX_SEC",
  "BACKGROUND_JOB_TTL_SEC",
  "BACKGROUND_WORK_ENABLED",
  "BUDGET_USD_PER_WINDOW",
  "BUDGET_WINDOW_MS",
  "CLAUDE_AUTH_CREDENTIAL",
  "CLAUDE_BIN",
  "CLAUDE_MODEL",
  "CODEX_AUTH_CREDENTIAL",
  "CODEX_BIN",
  "CODEX_MODEL",
  "CRON_FIRE_CONCURRENCY",
  "DEEP_IDLE_MACHINE_MS",
  "DEPLOYMENT_LAYER",
  "DEPLOY_APPS_DOMAIN",
  "DEPLOY_APPS_LOGIN_URL",
  "DEPLOY_DIAL_TIMEOUT_MS",
  "DEPLOY_GIT_DIR",
  "DEPLOY_IDLE_TTL_MS",
  "DEPLOY_PROVIDER",
  "DEV_IDLE_MACHINE_MS",
  "EAGER_PROVISION",
  "EGRESS_SERVICE_HOSTS",
  "EXECUTE_SCRATCH",
  "EXEC_TIMEOUT_DEFAULT_SEC",
  "EXEC_TIMEOUT_MAX_SEC",
  "FLY_DEPLOY_BASE_IMAGE",
  "FLY_REGION",
  "GIT_SHA",
  "HARNESS",
  "HARNESS_SECURITY_POSTURE",
  "HEARTBEAT_INTERVAL_MS",
  "INSIGHTS_INTERVAL_MS",
  "LEASE_TTL_MS",
  "LOCAL_SANDBOX_CPUS",
  "LOCAL_SANDBOX_DOCKER_BIN",
  "LOCAL_SANDBOX_IMAGE",
  "LOCAL_SANDBOX_MEMORY_MB",
  "MAX_ATTEMPTS",
  "MAX_CLAIMS",
  "MAX_CONTEXT_ENTRIES",
  "MAX_CONTEXT_TOKENS",
  "MEMORY_CAPTURE",
  "MEMORY_CAPTURE_MAX_TURNS",
  "MEMORY_CAPTURE_QUIET_MS",
  "MEMORY_CONSOLIDATE_AFTER",
  "MEMORY_PROVIDER_CONFIG",
  "MEMORY_RECALL",
  "MEMORY_STRATEGY",
  "MODEL_PROVIDER",
  "MONITOR_HEARTBEAT_SEC",
  "MONITOR_POLL_MS",
  "OPENCODE_MODEL",
  "ORG_BRAND_ACCENT",
  "ORG_BRAND_MARK",
  "ORG_BUDGET_USD_PER_WINDOW",
  "PI_CAPTURE_REQUESTS",
  "PI_DETECT_MODEL",
  "PI_JUDGE_MODEL",
  "PI_SYSTEM_CACHE_SPLIT",
  "PI_TITLE_MODEL",
  "PLUGIN_SKILLS_DIRS",
  "PORTER_CLUSTER_ID",
  "PORTER_DEPLOY_APPS_DOMAIN",
  "PORTER_DEPLOY_CLUSTER_ID",
  "PORTER_DEPLOY_PROJECT_ID",
  "PORTER_DEPLOY_RUNNER_IMAGE",
  "PORTER_DEPLOY_TTL_SEC",
  "PORTER_DEPLOY_URL",
  "PORTER_DEPLOY_VISIBILITY",
  "PORTER_SANDBOX_BASE_URL",
  "PORTER_SANDBOX_EGRESS_PROXY_URL",
  "PORTER_SANDBOX_HOME",
  "PORTER_SANDBOX_IMAGE",
  "PORTER_SANDBOX_NAME_PREFIX",
  "PORTER_SANDBOX_TTL_SEC",
  "PROCESS_REAPER_INTERVAL_MS",
  "PUBLIC_WEB_URL",
  "RATE_LIMIT_PER_WINDOW",
  "RATE_LIMIT_WINDOW_MS",
  "REACH_DENIED_NOTIFY_CHANNEL",
  "REACH_EXEC",
  "REAPER_INTERVAL_MS",
  "RUN_MAX_AGE_MS",
  "S3_BUCKET",
  "S3_PREFIX",
  "S3_REGION",
  "SANDBOX_BACKEND",
  "SANDBOX_SECONDARY_BACKEND",
  "SANDBOX_TIMEOUT_SEC",
  "SECRETS_BACKEND",
  "SECRETS_PREFIX",
  "SECURITY_SCREEN_BACKEND",
  "SECURITY_SCREEN_PROXY_ENDPOINT",
  "SECURITY_SCREEN_PROXY_PROVIDER",
  "SECURITY_SCREEN_PROXY_ROLLOUT",
  "SECURITY_SCREEN_TIMEOUT_MS",
  "SEED_SKILLS",
  "SESSION_TAPE_MODE",
  "SHARED_OWNER_AUTH_ISOLATION",
  "SHUTDOWN_DRAIN_MS",
  "SLACK_EMOJI_FALLBACK_PRINCIPAL",
  "SLACK_IDENTITY_EMAIL",
  "SKILLS_SEED_DIR",
  "SKILL_SYNC_POLL_MS",
  "SMOLMACHINES_BASE_URL",
  "SMOLMACHINES_CPUS",
  "SMOLMACHINES_DISK_GB",
  "SMOLMACHINES_EGRESS_PROXY_URL",
  "SMOLMACHINES_IMAGE",
  "SMOLMACHINES_MEMORY_MB",
  "SMOLMACHINES_NAME_PREFIX",
  "SNAPSHOT_STORE",
  "SPRITES_BASE_URL",
  "SPRITES_EGRESS_PROXY_URL",
  "SPRITES_NAME_PREFIX",
  "SURFACE_DEBUG_FOOTER",
  "TRANSFER_STORE",
  "TURN_WALL_CLOCK_SEC",
  "WORKERS",
] as const;

const PORTAL_RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES = [
  "AUTH_BROKER_PREFIX",
  "AUTH_BROKER_UPSTREAM",
  "DEPLOY_APPS_DOMAIN",
  "OIDC_AUTH_ENDPOINT",
  "OIDC_ISSUER",
  "OIDC_JWKS_URI",
  "OIDC_PRINCIPAL_CLAIM",
  "OIDC_SCOPES",
  "OIDC_TOKEN_ENDPOINT",
  "OIDC_USERINFO_ENDPOINT",
  "PORTAL_APPS_DOMAIN",
  "PORTAL_COOKIE_DOMAIN",
  "PORTAL_DEPLOYMENTS_ENABLED",
  "PORTAL_DEV_PRINCIPAL",
  "PORTAL_DIRECT_APPS_DOMAIN",
  "PORTAL_FAVICON_EMOJI",
  "PORTAL_IMPERSONATE_TTL_S",
  "PORTAL_LOCAL_AUTH_BYPASS",
  "PORTAL_PLAYGROUND",
  "PORTAL_PLAYGROUND_MINTS_PER_IP",
  "PORTAL_PLAYGROUND_MINT_WINDOW_S",
  "PORTAL_PUBLIC_URL",
  "PORTAL_SESSION_MAX_TTL_S",
  "PORTAL_SESSION_TTL_S",
  "PORTAL_XFF_TRUSTED_HOPS",
  "USER",
  "WEB_UI_UPSTREAM",
  "ADMIN_UPSTREAM",
] as const;

const AUTH_RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES = [
  "AUTH_ACCESS_TTL_S",
  "AUTH_ALLOWED_EMAIL_DOMAIN",
  "AUTH_CLIENT_ID",
  "AUTH_CODE_TTL_S",
  "AUTH_EMAIL_TRANSPORT",
  "AUTH_ISSUER",
  "AUTH_LINK_TTL_S",
  "AUTH_REDIRECT_URI",
  "AUTH_REQUEST_TTL_S",
  "AUTH_SEND_LIMIT_PER_EMAIL",
  "AUTH_SEND_LIMIT_PER_IP",
  "AUTH_SEND_WINDOW_S",
  "SMTP_PORT",
  "SMTP_TLS",
] as const;

const WEB_UI_RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES = [
  "DEPLOY_APPS_DOMAIN",
  "STATE_FEED_RECONNECT_MS",
  "WEB_DELIVERY_POLL_MS",
  "WEB_UI_DEV",
  "WEB_UI_FAVICON_EMOJI",
  "WEB_UI_PRINCIPALS",
  "WEB_UI_PUBLIC_URL",
] as const;

const RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES: Readonly<Record<string, readonly string[]>> = {
  core: CORE_RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES,
  portal: PORTAL_RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES,
  auth: AUTH_RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES,
  "web-ui": WEB_UI_RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES,
};

const PLAINTEXT_CONTROL_PREFIXES = [
  "AWS_DEPLOY_",
  "AWS_SANDBOX_",
  "FLY_DEPLOY_",
  "LOCAL_SANDBOX_",
  "PORTER_",
  "SANDBOX_",
  "SMOLMACHINES_",
  "SPRITES_",
] as const;

const PLAINTEXT_CONTROL_SECRET_NAMES = new Set([
  "AWS_DEPLOY_GATE_SECRET",
  "FLY_DEPLOY_API_TOKEN",
  "PORTER_DEPLOY_API_TOKEN",
  "SMOLMACHINES_TOKEN",
  "SPRITES_TOKEN",
]);

const FLY_OWNER_ENVIRONMENT_NAME = /^QM_OWNER_[0-9A-F]+$/u;
const AWS_ENDPOINT_ENVIRONMENT_NAME = /^AWS_ENDPOINT_URL(?:_[A-Z0-9_]+)?$/u;

function dangerousRuntimeEnvironmentName(name: string): boolean {
  const normalized = name.toUpperCase();
  return (
    ["BASH_ENV", "ENV", "NODE_OPTIONS", "NODE_PATH", "NODE_TLS_REJECT_UNAUTHORIZED", "SSLKEYLOGFILE"].includes(
      normalized,
    ) ||
    normalized.startsWith("LD_") ||
    normalized.startsWith("DYLD_")
  );
}

function runtimePlaintextEnvironmentName(service: string, name: string): boolean {
  const workload = isVirtualService(service) ? "core" : service;
  return (
    (RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES[workload] ?? []).includes(name) ||
    (!PLAINTEXT_CONTROL_SECRET_NAMES.has(name) && PLAINTEXT_CONTROL_PREFIXES.some((prefix) => name.startsWith(prefix)))
  );
}

function providerManagedEnvironmentName(name: string): boolean {
  return (
    AWS_ENDPOINT_ENVIRONMENT_NAME.test(name) ||
    dangerousRuntimeEnvironmentName(name) ||
    BUILT_IN_PROVIDER_ENVIRONMENT_NAMES.some((entry) => entry === name)
  );
}

function pluginProviderManagedEnvironmentName(name: string): boolean {
  return providerManagedEnvironmentName(name) || PLUGIN_PROVIDER_ENVIRONMENT_NAMES.some((entry) => entry === name);
}

export function securityScreenEnv(config: Pick<QmConfig, "securityScreen">): Record<string, string> {
  const screen = config.securityScreen;
  if (!screen) return {};
  return {
    SECURITY_SCREEN_BACKEND: screen.backend,
    SECURITY_SCREEN_PROXY_PROVIDER: screen.provider,
    SECURITY_SCREEN_PROXY_ENDPOINT: screen.endpoint,
    SECURITY_SCREEN_PROXY_ROLLOUT: screen.rollout,
  };
}

export function configPathInDir(dir: string): string | undefined {
  const candidate = resolve(dir, CONFIG_FILENAME);
  return existsSync(candidate) ? candidate : undefined;
}

export function findConfigPath(start = process.cwd()): string | undefined {
  let dir = resolve(start);
  for (;;) {
    const candidate = configPathInDir(dir);
    if (candidate) return candidate;
    const parent = resolve(dir, "..");
    if (parent === dir) return undefined;
    dir = parent;
  }
}

export interface LoadedConfig {
  config: QmConfig;
  path: string;
  configIdentity: FileIdentity;
}

export function loadConfigInDir(dir: string, overrides?: { target?: Target }): LoadedConfig {
  const path = configPathInDir(dir);
  if (!path) {
    die(`no ${CONFIG_FILENAME} in ${resolve(dir)} — run \`qm init\` there, or pass --config <path>.`);
  }
  return loadConfigAt(path, overrides);
}

export const appPrefixOf = (config: QmConfig): string => config.appPrefix ?? config.orgId;

export const dockerBasePort = (config: QmConfig): number => envNum("QM_BASE_PORT", config.basePort ?? 8080);

export const isDigestPinned = (ref: string): boolean => /@sha256:[0-9a-f]{64}$/.test(ref);

export type EffectiveSandboxBackend = "local" | "sprites" | "aws" | "porter" | "smolmachines";

export function sandboxBackend(
  config: Pick<QmConfig, "target" | "sandbox"> & Partial<Pick<QmConfig, "env">>,
): EffectiveSandboxBackend {
  const configured = config.env?.core?.SANDBOX_BACKEND?.trim();
  if (configured === "porter" || configured === "smolmachines") return configured;
  if (config.sandbox?.backend) return config.sandbox.backend;
  if (config.target === "fly") return "sprites";
  if (config.target === "docker") return config.sandbox?.app ? "sprites" : "local";
  return "aws";
}

export const localSandboxActive = (config: QmConfig): boolean =>
  config.target === "docker" && sandboxBackend(config) === "local";

export function effectiveCoreEnvironment(config: Pick<QmConfig, "services" | "env">): Record<string, string> {
  return {
    ...virtualServiceEnv(config.services, config.env),
    ...config.env.core,
  };
}

const DEPLOY_APPS_SHARED_PLATFORM_SUFFIXES = [
  "onporter.run",
  "withporter.run",
  "porter.run",
  "fly.dev",
  "herokuapp.com",
  "onrender.com",
  "railway.app",
  "vercel.app",
  "netlify.app",
  "ondigitalocean.app",
  "azurewebsites.net",
  "elasticbeanstalk.com",
  "amazonaws.com",
  "cloudfront.net",
  "github.io",
  "pages.dev",
  "workers.dev",
];

const DEPLOY_APPS_HOSTNAME_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const DEPLOY_APPS_HOSTNAME = new RegExp(`^${DEPLOY_APPS_HOSTNAME_LABEL}(?:\\.${DEPLOY_APPS_HOSTNAME_LABEL})+$`);

function validDeploymentRoutingDomain(value: string, maxLength: number): boolean {
  return value.length <= maxLength && DEPLOY_APPS_HOSTNAME.test(value) && !/^\d+$/u.test(value.split(".").at(-1)!);
}

function canonicalHttpOrigin(value: unknown, name: string, path: string): string {
  const message = `${path}: ${name} must be a non-empty http(s) origin URL without credentials, a path, query, fragment, or trailing hostname dot`;
  if (typeof value !== "string" || !value.trim()) throw new CliError(message);
  const normalized = normalizedHttpOrigin(value);
  if (!normalized) throw new CliError(message);
  return normalized;
}

const CREDENTIAL_ENDPOINT_ENVIRONMENT = {
  ANTHROPIC_BASE_URL: false,
  OPENAI_BASE_URL: false,
  OPENROUTER_BASE_URL: false,
  PORTER_DEPLOY_URL: true,
  PORTER_SANDBOX_BASE_URL: true,
  PORTER_SANDBOX_EGRESS_PROXY_URL: true,
  SMOLMACHINES_BASE_URL: true,
  SMOLMACHINES_EGRESS_PROXY_URL: true,
  SPRITES_BASE_URL: true,
  SPRITES_EGRESS_PROXY_URL: true,
} as const;

function canonicalCredentialEndpoint(value: string, name: string, httpsOnly: boolean, path: string): string {
  const message = `${path}: env.core.${name} must be a canonical ${httpsOnly ? "HTTPS" : "HTTP(S)"} URL without credentials, a query, fragment, controls, or ambiguous separators`;
  const authority = value.slice(value.indexOf("://") + 3).split(/[/?#]/u, 1)[0] ?? "";
  if (
    value !== value.trim() ||
    /[\p{Cc}\p{Cf}\\]/u.test(value) ||
    value.includes("?") ||
    value.includes("#") ||
    authority.includes("%") ||
    authority.includes("@") ||
    authority.endsWith(":") ||
    !/^https?:\/\/[^/\\?#\s@]+(?:\/[^?#\\\s]*)?$/iu.test(value)
  ) {
    throw new CliError(message);
  }
  try {
    const url = new URL(value);
    if (
      (url.protocol !== "http:" && url.protocol !== "https:") ||
      (httpsOnly && url.protocol !== "https:") ||
      !url.hostname ||
      url.hostname.endsWith(".") ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    ) {
      throw new Error("url");
    }
    const suffix = url.pathname === "/" ? "" : url.pathname.replace(/\/+$/u, "");
    return `${url.origin}${suffix}`;
  } catch {
    throw new CliError(message);
  }
}

function validateCredentialEndpoints(config: QmConfig, path: string): void {
  for (const source of ["env", "secretEnv"] as const) {
    for (const [service, entries] of Object.entries(config[source] ?? {})) {
      if ((isVirtualService(service) ? "core" : service) !== "core") continue;
      for (const [name, httpsOnly] of Object.entries(CREDENTIAL_ENDPOINT_ENVIRONMENT)) {
        const value = entries?.[name];
        if (value === undefined) continue;
        if (source === "secretEnv") {
          throw new CliError(
            `${path}: secretEnv.${service}.${name} controls a credential-bearing endpoint and must be configured as a non-secret environment value`,
          );
        }
        entries[name] = canonicalCredentialEndpoint(value, name, httpsOnly, path);
      }
    }
  }
}

function validateRuntimeControlValues(config: QmConfig, path: string): void {
  const environment = effectiveCoreEnvironment(config);
  for (const name of ["SNAPSHOT_STORE", "TRANSFER_STORE"] as const) {
    const value = environment[name];
    if (value !== undefined && value !== "local" && value !== "s3") {
      throw new CliError(`${path}: env.core.${name} must be "local" or "s3"`);
    }
  }
  const timeout = environment.SECURITY_SCREEN_TIMEOUT_MS;
  if (timeout !== undefined) {
    const parsed = Number(timeout);
    if (!/^[1-9][0-9]*$/u.test(timeout) || !Number.isSafeInteger(parsed) || parsed < 1_000 || parsed > 2_147_483_647) {
      throw new CliError(`${path}: env.core.SECURITY_SCREEN_TIMEOUT_MS must be an integer from 1000 to 2147483647`);
    }
  }
}

function canonicalDeployAppsDomain(value: string, name: string, path: string): string {
  const canonical = value.toLowerCase().replace(/\.$/u, "");
  if (!validDeploymentRoutingDomain(canonical, 126)) {
    throw new CliError(`${path}: env.core.${name} must be a bare DNS name without a scheme, port, path, or wildcard`);
  }
  const shared = DEPLOY_APPS_SHARED_PLATFORM_SUFFIXES.find(
    (suffix) => canonical === suffix || canonical.endsWith(`.${suffix}`),
  );
  if (shared) {
    throw new CliError(`${path}: env.core.${name} must not use shared platform domain ${shared}`);
  }
  return canonical;
}

function canonicalPorterDeployAppsDomain(value: string, path: string): string {
  const canonical = value.toLowerCase().replace(/\.$/u, "");
  if (!validDeploymentRoutingDomain(canonical, 189)) {
    throw new CliError(
      `${path}: env.core.PORTER_DEPLOY_APPS_DOMAIN must be a bare DNS name no longer than 189 characters`,
    );
  }
  return canonical;
}

export function effectiveDeployAppsDomain(config: Pick<QmConfig, "services" | "env">): string | undefined {
  const environment = effectiveCoreEnvironment(config);
  const common = environment.DEPLOY_APPS_DOMAIN?.trim().toLowerCase().replace(/\.$/u, "");
  if (common) return common;
  return environment.AWS_DEPLOY_APPS_DOMAIN?.trim().toLowerCase().replace(/\.$/u, "") || undefined;
}

export function effectivePortalPublicUrl(config: Pick<QmConfig, "publicUrl">): string {
  return config.publicUrl;
}

export function sandboxCoreEnv(
  config: QmConfig,
  _lookup?: (name: string) => string | undefined,
): { env: Record<string, string>; missingSecrets: string[] } {
  assertMigratedSandboxEnvironment(config.sandbox, "config", config.target, config.aws?.secretsPrefix);
  const env: Record<string, string> = {};
  const missingSecrets: string[] = [];
  const sb = config.sandbox;
  const backend = sandboxBackend(config);
  env.SANDBOX_BACKEND = backend;
  if (localSandboxActive(config)) {
    if (sb?.image) env.LOCAL_SANDBOX_IMAGE = sb.image;
    return { env, missingSecrets };
  }
  if (backend === "sprites" && sb?.namePrefix) env.SPRITES_NAME_PREFIX = sb.namePrefix;
  return { env, missingSecrets };
}

function stripJsonComments(text: string): string {
  let out = "";
  for (let i = 0; i < text.length;) {
    const ch = text[i]!;
    if (ch === '"') {
      const end = scanString(text, i);
      out += text.slice(i, end);
      i = end;
    } else if (ch === "/" && text[i + 1] === "/") {
      for (; i < text.length && text[i] !== "\n"; i++) out += " ";
    } else if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      const stop = end === -1 ? text.length : end + 2;
      for (; i < stop; i++) out += text[i] === "\n" ? "\n" : " ";
    } else {
      out += ch;
      i++;
    }
  }
  return out;
}

function stripTrailingCommas(text: string): string {
  let out = text;
  for (let i = 0; i < out.length; i++) {
    if (out[i] === '"') {
      i = scanString(out, i) - 1;
      continue;
    }
    if (out[i] !== ",") continue;
    const next = skipWs(out, i + 1);
    if (out[next] === "}" || out[next] === "]") out = out.slice(0, i) + " " + out.slice(i + 1);
  }
  return out;
}

function parseConfigJson(text: string): unknown {
  const normalized = stripTrailingCommas(stripJsonComments(text));
  assertConfigNesting(normalized);
  const value: unknown = JSON.parse(normalized);
  assertNoDuplicateObjectKeys(normalized);
  return value;
}

const skipWs = (s: string, i: number): number => {
  while (i < s.length && /\s/.test(s[i]!)) i++;
  return i;
};

function scanString(s: string, i: number): number {
  for (i++; i < s.length; i++) {
    if (s[i] === "\\") i++;
    else if (s[i] === '"') return i + 1;
  }
  throw new CliError("config has an unterminated string");
}

function assertConfigNesting(text: string): void {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '"') {
      i = scanString(text, i) - 1;
    } else if (text[i] === "{" || text[i] === "[") {
      if (++depth > 256) throw new CliError("config nesting exceeds 256 levels");
    } else if (text[i] === "}" || text[i] === "]") {
      depth--;
    }
  }
}

function assertNoDuplicateObjectKeys(text: string): void {
  const valueEnd = (start: number): number => {
    let i = skipWs(text, start);
    if (text[i] === '"') return scanString(text, i);
    if (text[i] === "{") return objectEnd(i);
    if (text[i] === "[") return arrayEnd(i);
    while (i < text.length && !/[\s,\]}]/.test(text[i]!)) i++;
    return i;
  };
  const objectEnd = (start: number): number => {
    const keys = new Set<string>();
    let i = skipWs(text, start + 1);
    if (text[i] === "}") return i + 1;
    while (i < text.length) {
      const end = scanString(text, i);
      const key = JSON.parse(text.slice(i, end)) as string;
      if (keys.has(key)) throw new CliError(`config contains duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      i = skipWs(text, end);
      i = valueEnd(skipWs(text, i + 1));
      i = skipWs(text, i);
      if (text[i] === "}") return i + 1;
      i = skipWs(text, i + 1);
    }
    return i;
  };
  const arrayEnd = (start: number): number => {
    let i = skipWs(text, start + 1);
    if (text[i] === "]") return i + 1;
    while (i < text.length) {
      i = skipWs(text, valueEnd(i));
      if (text[i] === "]") return i + 1;
      i = skipWs(text, i + 1);
    }
    return i;
  };
  valueEnd(0);
}

function scanValue(s: string, i: number): number {
  const ch = s[i]!;
  if (ch === '"') return scanString(s, i);
  if (ch === "{" || ch === "[") {
    const close = ch === "{" ? "}" : "]";
    let depth = 0;
    for (; i < s.length; i++) {
      const c = s[i]!;
      if (c === '"') i = scanString(s, i) - 1;
      else if (c === ch) depth++;
      else if (c === close && --depth === 0) return i + 1;
    }
    throw new CliError(`config has an unbalanced ${ch}`);
  }
  while (i < s.length && !/[,}\]\s]/.test(s[i]!)) i++;
  return i;
}

interface PropSpan {
  key: string;
  keyStart: number;
  valueStart: number;
  valueEnd: number;
  commaEnd?: number;
}

function objectProps(s: string, objStart: number): { props: PropSpan[]; openBrace: number; closeBrace: number } {
  let i = skipWs(s, objStart);
  if (s[i] !== "{") throw new CliError("config value is not an object");
  const openBrace = i;
  i++;
  const props: PropSpan[] = [];
  for (;;) {
    i = skipWs(s, i);
    if (i >= s.length) throw new CliError("config object is not closed");
    if (s[i] === "}") return { props, openBrace, closeBrace: i };
    if (s[i] !== '"') throw new CliError("config object has a non-string key");
    const keyStart = i;
    const keyEnd = scanString(s, i);
    const key = JSON.parse(s.slice(i, keyEnd)) as string;
    i = skipWs(s, keyEnd);
    if (s[i] !== ":") throw new CliError(`config key ${JSON.stringify(key)} has no value`);
    i = skipWs(s, i + 1);
    const valueEnd = scanValue(s, i);
    const valueStart = i;
    i = skipWs(s, valueEnd);
    const commaEnd = s[i] === "," ? i + 1 : undefined;
    props.push({ key, keyStart, valueStart, valueEnd, ...(commaEnd ? { commaEnd } : {}) });
    if (commaEnd) i = commaEnd;
  }
}

function updateConfigStringMap(raw: string, key: string, updates: Record<string, string>): string {
  const stripped = stripJsonComments(raw);
  const root = objectProps(stripped, 0);
  const edits: Array<{ start: number; end: number; text: string }> = [];
  const entry = ([k, v]: [string, string]): string => `${JSON.stringify(k)}: ${JSON.stringify(v)}`;
  const property = root.props.find((p) => p.key === key);
  if (property) {
    const obj = objectProps(stripped, property.valueStart);
    const missing: Array<[string, string]> = [];
    for (const [k, v] of Object.entries(updates)) {
      const prop = obj.props.find((p) => p.key === k);
      if (prop) edits.push({ start: prop.valueStart, end: prop.valueEnd, text: JSON.stringify(v) });
      else missing.push([k, v]);
    }
    if (missing.length) {
      const body = missing.map(entry).join(", ");
      const text = obj.props.length ? ` ${body},` : ` ${body} `;
      edits.push({ start: obj.openBrace + 1, end: obj.openBrace + 1, text });
    }
  } else {
    const body = Object.entries(updates).map(entry).join(", ");
    const separator = root.props.length && root.props.at(-1)!.commaEnd === undefined ? "," : "";
    const text = `${separator}\n  ${JSON.stringify(key)}: { ${body} }\n`;
    edits.push({ start: root.closeBrace, end: root.closeBrace, text });
  }
  edits.sort((a, b) => b.start - a.start);
  let out = raw;
  for (const e of edits) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return out;
}

export const updateConfigImageOverrides = (raw: string, updates: Record<string, string>): string =>
  updateConfigStringMap(raw, "imageOverrides", updates);

function configCoreSpan(raw: string): { stripped: string; core: ReturnType<typeof objectProps> } {
  const stripped = stripJsonComments(raw);
  const root = objectProps(stripped, 0);
  const envProp = root.props.find((p) => p.key === "env");
  if (!envProp) throw new CliError('config has no top-level "env" object');
  const env = objectProps(stripped, envProp.valueStart);
  const coreProp = env.props.find((p) => p.key === "core");
  if (!coreProp) throw new CliError('config has no "env.core" object');
  return { stripped, core: objectProps(stripped, coreProp.valueStart) };
}

function removeConfigCoreEnv(raw: string, key: string): string {
  const { stripped, core } = configCoreSpan(raw);
  const index = core.props.findIndex((prop) => prop.key === key);
  if (index < 0) return raw;
  const prop = core.props[index]!;
  let start = prop.keyStart;
  const end = prop.commaEnd ?? prop.valueEnd;
  if (prop.commaEnd === undefined && index > 0) {
    start = skipWs(stripped, core.props[index - 1]!.valueEnd);
    if (stripped[start] !== ",") throw new CliError(`config env.core key ${JSON.stringify(key)} has no separator`);
  }
  return raw.slice(0, start) + raw.slice(end);
}

export function updateConfigCoreEnv(raw: string, updates: Record<string, string | undefined>): string {
  let out = raw;
  for (const [key, value] of Object.entries(updates)) {
    if (value === undefined) out = removeConfigCoreEnv(out, key);
  }
  const assigned = Object.entries(updates).filter((entry): entry is [string, string] => entry[1] !== undefined);
  if (!assigned.length) return out;
  const { core } = configCoreSpan(out);
  const edits: Array<{ start: number; end: number; text: string }> = [];
  const missing: Array<[string, string]> = [];
  for (const [key, value] of assigned) {
    const prop = core.props.find((p) => p.key === key);
    if (prop) edits.push({ start: prop.valueStart, end: prop.valueEnd, text: JSON.stringify(value) });
    else missing.push([key, value]);
  }
  if (missing.length) {
    const body = missing.map(([key, value]) => `${JSON.stringify(key)}: ${JSON.stringify(value)}`).join(", ");
    edits.push({
      start: core.openBrace + 1,
      end: core.openBrace + 1,
      text: core.props.length ? ` ${body},` : ` ${body} `,
    });
  }
  edits.sort((a, b) => b.start - a.start);
  for (const edit of edits) out = out.slice(0, edit.start) + edit.text + out.slice(edit.end);
  return out;
}

export function loadConfigAt(
  path: string,
  overrides?: { target?: Target; snapshot?: RegularFileSnapshot },
): LoadedConfig {
  const abs = resolve(path);
  let raw: unknown;
  let configIdentity: FileIdentity;
  try {
    const snapshot = overrides?.snapshot ?? readRegularFileSnapshot(abs);
    configIdentity = snapshot.identity;
    raw = parseConfigJson(decodeUtf8(snapshot.content));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") throw new CliError(`config file not found: ${path}`);
    throw new CliError(`${abs} is not valid JSON: ${errMessage(e)}`);
  }
  assertConfigHasNoNul(raw, abs);
  if (overrides?.target !== undefined) {
    if (!isPlainObject(raw)) throw new CliError(`${abs}: expected a JSON object`);
    raw = { ...raw, target: overrides.target };
  }
  return { config: validate(raw, abs), path: abs, configIdentity };
}

const isPlainObject = (x: unknown): x is Record<string, unknown> =>
  typeof x === "object" && x !== null && !Array.isArray(x);

function assertConfigHasNoNul(value: unknown, path: string): void {
  if (typeof value === "string") {
    if (value.includes("\0")) throw new CliError(`${path}: configuration must not contain NUL bytes`);
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) assertConfigHasNoNul(entry, path);
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    if (key.includes("\0")) throw new CliError(`${path}: configuration must not contain NUL bytes`);
    assertConfigHasNoNul(entry, path);
  }
}

function validateSecurityScreen(raw: unknown, path: string): SecurityScreenConfig | undefined {
  if (raw === undefined) return undefined;
  if (!isPlainObject(raw)) throw new CliError(`${path}: "securityScreen" must be an object`);
  const allowed = new Set(["backend", "provider", "endpoint", "rollout"]);
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) throw new CliError(`${path}: "securityScreen.${key}" is not recognized`);
  }
  if (raw.backend !== "proxy") throw new CliError(`${path}: "securityScreen.backend" must be "proxy"`);
  if (
    typeof raw.provider !== "string" ||
    raw.provider.length > 63 ||
    !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(raw.provider)
  ) {
    throw new CliError(`${path}: "securityScreen.provider" must be a lowercase DNS label`);
  }
  if (raw.provider === "surface" || raw.provider === "origin") {
    throw new CliError(`${path}: "securityScreen.provider" must not collide with a security screen metadata field`);
  }
  if (typeof raw.endpoint !== "string") {
    throw new CliError(`${path}: "securityScreen.endpoint" must be an HTTPS URL`);
  }
  try {
    const endpoint = new URL(raw.endpoint);
    if (
      endpoint.protocol !== "https:" ||
      endpoint.username ||
      endpoint.password ||
      endpoint.hash ||
      endpoint.hostname.endsWith(".")
    ) {
      throw new Error("endpoint");
    }
  } catch {
    throw new CliError(
      `${path}: "securityScreen.endpoint" must be an HTTPS URL without credentials, a fragment, or a trailing hostname dot`,
    );
  }
  if (raw.rollout !== "shadow" && raw.rollout !== "enforce") {
    throw new CliError(`${path}: "securityScreen.rollout" must be "shadow" or "enforce"`);
  }
  return {
    backend: raw.backend,
    provider: raw.provider,
    endpoint: raw.endpoint,
    rollout: raw.rollout,
  };
}

export function readConfigOrgId(path: string): string | undefined {
  try {
    const raw = parseConfigJson(readUtf8File(path));
    const orgId = isPlainObject(raw) ? raw.orgId : undefined;
    return typeof orgId === "string" && validOrgId(orgId) ? orgId : undefined;
  } catch {
    return undefined;
  }
}

const VALID_TOP_LEVEL_KEYS: ReadonlySet<string> = new Set([
  "contract",
  "orgId",
  "publicUrl",
  "apiUrl",
  "target",
  "model",
  "modelProvider",
  "basePort",
  "services",
  "plugins",
  "skills",
  "env",
  "secretEnv",
  "securityScreen",
  "vms",
  "imageOverrides",
  "sandbox",
  "botName",
  "orgName",
  "appPrefix",
  "region",
  "flyOrg",
  "imageFrom",
  "deployAppPrefix",
  "aws",
]);

function validate(raw: unknown, path: string): QmConfig {
  if (!isPlainObject(raw)) throw new CliError(`${path}: expected a JSON object`);
  const o = raw;

  for (const key of Object.keys(o)) {
    if (key !== "//" && !VALID_TOP_LEVEL_KEYS.has(key)) {
      throw new CliError(`${path}: unknown top-level field ${JSON.stringify(key)}`);
    }
  }

  const contract = o["contract"];
  if (contract !== CONTRACT_VERSION) {
    if (typeof contract === "number" && Number.isInteger(contract)) {
      throw new CliError(
        `${path}: unsupported contract major ${contract}; this CLI supports contract ${CONTRACT_VERSION}`,
      );
    }
    throw new CliError(`${path}: "contract" must be ${CONTRACT_VERSION}`);
  }

  const orgId = o["orgId"];
  if (typeof orgId !== "string" || !validOrgId(orgId)) {
    throw new CliError(`${path}: "orgId" must be a lowercase DNS label (a-z, 0-9, and hyphens between)`);
  }

  const publicUrl = canonicalHttpOrigin(o["publicUrl"], '"publicUrl"', path);

  const apiUrl = o["apiUrl"] === undefined ? undefined : canonicalHttpOrigin(o["apiUrl"], '"apiUrl"', path);

  const target = o["target"];
  if (!isTarget(target)) throw new CliError(`${path}: "target" must be ${hostingProviderChoices()}`);

  const servicesRaw = o["services"];
  if (!Array.isArray(servicesRaw)) throw new CliError(`${path}: "services" must be an array`);
  const services: DeclaredServiceName[] = [];
  for (const s of servicesRaw) {
    if (typeof s !== "string" || !isDeclaredService(s)) {
      throw new CliError(
        `${path}: unknown service ${JSON.stringify(s)} — valid: ${[...SERVICE_NAMES, ...VIRTUAL_SERVICE_NAMES].join(", ")}`,
      );
    }
    if (!services.includes(s)) services.push(s);
  }
  if (!services.includes("core")) throw new CliError(`${path}: "services" must include "core"`);
  if (services.includes("auth") && !services.includes("portal")) {
    throw new CliError(
      `${path}: the "auth" sign-in broker requires "portal" — the portal is the only service that publishes it`,
    );
  }

  const plugins = validatePlugins(o["plugins"], path);
  for (const [index, plugin] of plugins.entries()) {
    const managed =
      Object.keys(plugin.env ?? {}).find((name) => pluginProviderManagedEnvironmentName(name)) ??
      plugin.secrets?.find(
        (secret) =>
          pluginProviderManagedEnvironmentName(secret.name) ||
          runtimePlaintextEnvironmentName(plugin.name, secret.name),
      )?.name ??
      PLUGIN_PROVIDER_ENVIRONMENT_NAMES.find(
        (name) => plugin.env?.[name] !== undefined || plugin.secrets?.some((secret) => secret.name === name),
      ) ??
      Object.keys(plugin.env ?? {}).find((name) => FLY_OWNER_ENVIRONMENT_NAME.test(name)) ??
      plugin.secrets?.find((secret) => FLY_OWNER_ENVIRONMENT_NAME.test(secret.name))?.name;
    if (managed) {
      const source = plugin.env?.[managed] !== undefined ? "env" : "secrets";
      throw new CliError(`${path}: "plugins[${index}].${source}.${managed}" is managed by the deployment provider`);
    }
  }
  const skills = validateStringArray(o["skills"], path, "skills");
  const env = validateServiceMap(o["env"], path, "env", (v, k) => validateStringMap(v, path, `env.${k}`));
  const secretEnv = validateServiceMap(o["secretEnv"], path, "secretEnv", (v, k) => {
    const entries = validateStringMap(v, path, `secretEnv.${k}`);
    for (const [envName, storeName] of Object.entries(entries)) {
      if (!isEnvVarName(storeName))
        throw new CliError(
          `${path}: "secretEnv.${k}.${envName}" must name a secret-store entry (a valid env-var-shaped name)`,
        );
    }
    return entries;
  });
  const plaintextDestinations = new Map<string, Set<string>>();
  for (const [service, entries] of Object.entries(env)) {
    const workload = isVirtualService(service) ? "core" : service;
    const names = plaintextDestinations.get(workload) ?? new Set<string>();
    plaintextDestinations.set(workload, names);
    for (const name of Object.keys(entries ?? {})) names.add(name);
  }
  for (const [service, entries] of Object.entries(secretEnv)) {
    const workload = isVirtualService(service) ? "core" : service;
    for (const name of Object.keys(entries ?? {})) {
      if (plaintextDestinations.get(workload)?.has(name)) {
        throw new CliError(
          `${path}: "secretEnv.${service}.${name}" conflicts with a plaintext ${workload} environment value`,
        );
      }
    }
  }
  for (const [service, entries] of Object.entries(env)) {
    const workload = isVirtualService(service) ? "core" : service;
    const managedSecret = ["DEPLOY_APPS_SESSION_SECRET", "PORTAL_SESSION_SECRET"].find(
      (name) => workload === "core" && entries?.[name] !== undefined,
    );
    if (managedSecret) {
      throw new CliError(
        `${path}: "env.${service}.${managedSecret}" is a managed secret destination and cannot be configured as plaintext`,
      );
    }
  }
  for (const [service, entries] of Object.entries(secretEnv)) {
    const workload = isVirtualService(service) ? "core" : service;
    if (workload !== "core") continue;
    const managed = ["DEPLOY_APPS_LOGIN_URL", "PUBLIC_WEB_URL"].find((name) => entries?.[name] !== undefined);
    if (managed) {
      throw new CliError(
        `${path}: "secretEnv.${service}.${managed}" controls the gated deployment login origin and must be configured as a non-secret environment value`,
      );
    }
  }
  for (const source of ["env", "secretEnv"] as const) {
    for (const [service, entries] of Object.entries(source === "env" ? env : secretEnv)) {
      const workload = isVirtualService(service) ? "core" : service;
      let managed =
        Object.keys(entries ?? {}).find((name) => FLY_OWNER_ENVIRONMENT_NAME.test(name)) ??
        Object.keys(entries ?? {}).find((name) => providerManagedEnvironmentName(name));
      if (!managed && workload === "core") {
        managed =
          CORE_PROVIDER_ENVIRONMENT_NAMES.find((name) => entries?.[name] !== undefined) ??
          (entries?.DATABASE_URL !== undefined ? "DATABASE_URL" : undefined);
      }
      if (!managed && workload !== "core") {
        managed = [
          "CORE_ORG_ID",
          "CORE_API_URL",
          ...(workload === "auth" ? ["AUTH_BRAND_NAME"] : []),
          "FLY_REGION",
        ].find((name) => entries?.[name] !== undefined);
      }
      if (managed) {
        throw new CliError(`${path}: "${source}.${service}.${managed}" is managed by the core runtime and provider`);
      }
    }
  }
  for (const source of ["env", "secretEnv"] as const) {
    const portal = (source === "env" ? env : secretEnv).portal;
    const managed = ["WEB_UI_UPSTREAM", "ADMIN_UPSTREAM", "PORTAL_XFF_TRUSTED_HOPS", "PORTAL_DIRECT_APPS_DOMAIN"].find(
      (name) => portal?.[name] !== undefined,
    );
    if (managed) {
      throw new CliError(`${path}: "${source}.portal.${managed}" is managed by the deployment provider`);
    }
  }
  const virtualCoreConfiguration = new Map([
    ["SANDBOX_BACKEND", "the core sandbox"],
    ["SANDBOX_SECONDARY_BACKEND", "the core sandbox"],
    ["SPRITES_NAME_PREFIX", "the core sandbox"],
    ["AWS_DEPLOY_APPS_DOMAIN", "deployment routing"],
    ["DEPLOY_APPS_DOMAIN", "deployment routing"],
    ["DEPLOY_APPS_LOGIN_URL", "deployment routing"],
    ["DEPLOYMENT_LAYER", "the deployment layer"],
    ["FLY_REGION", "the deployment provider"],
    ["PORTER_DEPLOY_APPS_DOMAIN", "deployment routing"],
    ["PUBLIC_WEB_URL", "deployment routing"],
    ["S3_BUCKET", "durable storage"],
    ["S3_REGION", "durable storage"],
    ["SNAPSHOT_STORE", "durable storage"],
    ["TRANSFER_STORE", "durable storage"],
  ]);
  for (const name of CORE_PLAINTEXT_PROVIDER_ENVIRONMENT_NAMES) {
    if (!virtualCoreConfiguration.has(name)) virtualCoreConfiguration.set(name, "core provider configuration");
  }
  for (const service of services.filter(isVirtualService)) {
    for (const source of ["env", "secretEnv"] as const) {
      const configured = [...virtualCoreConfiguration.keys()].find(
        (name) => (source === "env" ? env : secretEnv)[service]?.[name] !== undefined,
      );
      if (configured) {
        throw new CliError(
          `${path}: "${source}.${service}.${configured}" controls ${virtualCoreConfiguration.get(configured)} and must be configured under env.core or its structured configuration`,
        );
      }
    }
  }
  validateSecretSelectorEnvironment(env, path);
  for (const [service, entries] of Object.entries(secretEnv)) {
    const workload = isVirtualService(service) ? "core" : service;
    for (const name of Object.keys(entries ?? {})) {
      const contract = SECRET_SELECTOR_ENVIRONMENT_CONTRACTS[workload]?.[name];
      if (contract?.kind === "enumerated" || contract?.secretBacked === false) {
        throw new CliError(
          `${path}: "secretEnv.${service}.${name}" controls deployment secret requirements and must be configured as a non-secret environment value`,
        );
      }
    }
  }
  for (const source of [env, secretEnv]) {
    for (const name of ["DEPLOY_APPS_DOMAIN", "PORTAL_APPS_DOMAIN"] as const) {
      if (source.portal?.[name] !== undefined) {
        throw new CliError(
          `${path}: portal ${name} is derived from the core deployment routing domain and cannot be overridden`,
        );
      }
    }
  }
  if (secretEnv.core?.PORTER_DEPLOY_APPS_DOMAIN !== undefined) {
    throw new CliError(
      `${path}: secretEnv.core.PORTER_DEPLOY_APPS_DOMAIN controls deployment routing and must be configured as a non-secret environment value`,
    );
  }
  const sandboxRaw = normalizeLegacySandboxEnvironment(o["sandbox"], env, path, target);
  const securityScreen = validateSecurityScreen(o["securityScreen"], path);
  const managedSecurityScreenEnv = [
    "SECURITY_SCREEN_BACKEND",
    "SECURITY_SCREEN_PROXY_PROVIDER",
    "SECURITY_SCREEN_PROXY_ENDPOINT",
    "SECURITY_SCREEN_PROXY_ROLLOUT",
  ];
  for (const [service, values] of Object.entries(env)) {
    for (const name of [...managedSecurityScreenEnv, "SECURITY_SCREEN_PROXY_TOKEN"]) {
      if (values?.[name] !== undefined) {
        throw new CliError(`${path}: "env.${service}.${name}" is managed by securityScreen and cannot be overridden`);
      }
    }
  }
  for (const [service, values] of Object.entries(secretEnv)) {
    for (const name of managedSecurityScreenEnv) {
      if (values?.[name] !== undefined) {
        throw new CliError(
          `${path}: "secretEnv.${service}.${name}" is managed by securityScreen and cannot be overridden`,
        );
      }
    }
    if (service !== "core" && values?.SECURITY_SCREEN_PROXY_TOKEN !== undefined) {
      throw new CliError(`${path}: SECURITY_SCREEN_PROXY_TOKEN may be routed only to core`);
    }
  }
  if (securityScreen && secretEnv.core?.SECURITY_SCREEN_PROXY_TOKEN === undefined) {
    throw new CliError(`${path}: securityScreen requires secretEnv.core.SECURITY_SCREEN_PROXY_TOKEN`);
  }
  if (!securityScreen && secretEnv.core?.SECURITY_SCREEN_PROXY_TOKEN !== undefined) {
    throw new CliError(`${path}: secretEnv.core.SECURITY_SCREEN_PROXY_TOKEN requires securityScreen`);
  }
  for (const [service, values] of Object.entries(env)) {
    const workload = isVirtualService(service) ? "core" : service;
    if (!isServiceName(workload)) continue;
    const portEnv = serviceDef(workload).docker.portEnv;
    if (values?.[portEnv] !== undefined) {
      throw new CliError(
        `${path}: "env.${service}.${portEnv}" is managed by the deployment target and cannot be overridden`,
      );
    }
  }
  for (const [service, entries] of Object.entries(secretEnv)) {
    const workload = isVirtualService(service) ? "core" : service;
    if (!isServiceName(workload)) continue;
    const portEnv = serviceDef(workload).docker.portEnv;
    if (entries?.[portEnv] !== undefined) {
      throw new CliError(
        `${path}: "secretEnv.${service}.${portEnv}" is managed by the deployment target and cannot be overridden`,
      );
    }
  }
  if (secretEnv.core?.SANDBOX_BACKEND !== undefined) {
    throw new CliError(`${path}: SANDBOX_BACKEND must be a non-secret sandbox selection`);
  }
  if (secretEnv.core?.SPRITES_NAME_PREFIX !== undefined) {
    throw new CliError(`${path}: SPRITES_NAME_PREFIX must be a non-secret sandbox namespace`);
  }
  const derivedSandboxEnvironment = [
    "LOCAL_SANDBOX_IMAGE",
    "AWS_SANDBOX_REGION",
    "AWS_SANDBOX_IMAGE",
    "AWS_SANDBOX_IMAGE_VERSION",
    "AWS_SANDBOX_EXEC_ROLE_ARN",
    "AWS_SANDBOX_S3_BUCKET",
  ];
  for (const source of [
    ["env", env],
    ["secretEnv", secretEnv],
  ] as const) {
    for (const [service, values] of Object.entries(source[1])) {
      if ((isVirtualService(service) ? "core" : service) !== "core") continue;
      const name = derivedSandboxEnvironment.find((candidate) => values?.[candidate] !== undefined);
      if (name) {
        throw new CliError(
          `${path}: "${source[0]}.${service}.${name}" is derived from the sandbox configuration and cannot be overridden`,
        );
      }
    }
  }
  if (env.admin?.QM_VERSION !== undefined) {
    throw new CliError(`${path}: "env.admin.QM_VERSION" is baked into the Admin image and cannot be overridden`);
  }
  if (secretEnv.admin?.QM_VERSION !== undefined) {
    throw new CliError(`${path}: "secretEnv.admin.QM_VERSION" is baked into the Admin image and cannot be overridden`);
  }
  const retiredUpdateEnv = Object.keys(env.admin ?? {}).find((name) => name.startsWith("QM_UPDATE_GITHUB_"));
  const retiredUpdateSecret = Object.keys(secretEnv.admin ?? {}).find((name) => name.startsWith("QM_UPDATE_GITHUB_"));
  if (retiredUpdateEnv || retiredUpdateSecret) {
    const field = retiredUpdateEnv ? `env.admin.${retiredUpdateEnv}` : `secretEnv.admin.${retiredUpdateSecret}`;
    throw new CliError(
      `${path}: "${field}" belongs to the retired browser updater; drain every queued or running update job, remove its workflows and all QM_UPDATE_GITHUB_* config, delete the repository QM_DEPLOY_ENV secret, revoke every resident QM_UPDATE_GITHUB_TOKEN copy, revoke and delete every FLY_SANDBOX_API_TOKEN source copy, and unset the deployed core FLY_API_TOKEN alias`,
    );
  }
  const portalMountsAdmin = services.includes("portal") && services.includes("admin");
  if (portalMountsAdmin && env.admin?.ADMIN_BASE_PATH !== undefined && env.admin.ADMIN_BASE_PATH !== "/admin") {
    throw new CliError(`${path}: env.admin.ADMIN_BASE_PATH must be "/admin" when portal and admin are enabled`);
  }
  if (portalMountsAdmin && secretEnv.admin?.ADMIN_BASE_PATH !== undefined) {
    throw new CliError(
      `${path}: secretEnv.admin.ADMIN_BASE_PATH is managed by the deployment target and cannot be overridden`,
    );
  }
  for (const [i, plugin] of plugins.entries()) {
    if (plugin.env?.PORT !== undefined) {
      throw new CliError(
        `${path}: "plugins[${i}].env.PORT" is managed by the deployment target and cannot be overridden`,
      );
    }
  }
  const imageOverrides = validateServiceMap(o["imageOverrides"], path, "imageOverrides", (v, k) => {
    if (typeof v !== "string") throw new CliError(`${path}: "imageOverrides.${k}" must be a string`);
    return v;
  });
  const sandbox = validateSandbox(
    sandboxRaw,
    path,
    target,
    isPlainObject(o["aws"]) && typeof o["aws"].secretsPrefix === "string" ? o["aws"].secretsPrefix : undefined,
  );
  const out: QmConfig = {
    contract,
    orgId,
    publicUrl: publicUrl.replace(/\/$/, ""),
    target,
    services,
    plugins,
    skills,
    env,
    imageOverrides,
  };
  if (Object.keys(secretEnv).length) out.secretEnv = secretEnv;
  if (securityScreen) out.securityScreen = securityScreen;
  if (typeof apiUrl === "string") out.apiUrl = apiUrl.replace(/\/$/, "");
  if (sandbox) out.sandbox = sandbox;
  if (typeof o["model"] === "string") out.model = o["model"];
  if (o["modelProvider"] !== undefined) {
    if (!isModelProvider(o["modelProvider"])) {
      throw new CliError(
        `${path}: "modelProvider" must be one of ${MODEL_PROVIDERS.join(", ")} — it selects which provider key the deployment requires; omit it to supply the base model key from the Admin page instead`,
      );
    }
    out.modelProvider = o["modelProvider"];
  }
  if (o["basePort"] !== undefined) {
    const bp = o["basePort"];
    if (typeof bp !== "number" || !Number.isInteger(bp) || bp <= 0) {
      throw new CliError(`${path}: "basePort" must be a positive integer (the docker host port base)`);
    }
    out.basePort = bp;
  }
  const identityName = (key: "botName" | "orgName", cap: number, what: string): string | undefined => {
    if (o[key] === undefined) return undefined;
    const name = typeof o[key] === "string" ? o[key].trim() : "";
    if (!name || name.length > cap || /[<>{}\u0000-\u001F\u007F-\u009F\u2028\u2029"\\]/.test(name)) {
      throw new CliError(
        `${path}: "${key}" must be a nonempty string of at most ${cap} characters without <>{}, quotes, backslashes, or control characters — ${what}`,
      );
    }
    return name;
  };
  const botName = identityName(
    "botName",
    31,
    'it names the bot everywhere users see it: the Slack apps (including the "<botName> SSO" sign-in app, which Slack caps at 35 characters), the prompt identity, and sign-in pages',
  );
  if (botName) out.botName = botName;
  const orgName = identityName("orgName", 40, "it is how the bot refers to your organization");
  if (orgName) out.orgName = orgName;
  if (typeof o["appPrefix"] === "string") out.appPrefix = o["appPrefix"];
  if (typeof o["region"] === "string") out.region = o["region"];
  if (typeof o["flyOrg"] === "string") out.flyOrg = o["flyOrg"];
  if (typeof o["imageFrom"] === "string") out.imageFrom = o["imageFrom"];
  if (typeof o["deployAppPrefix"] === "string") out.deployAppPrefix = o["deployAppPrefix"];
  if (o["aws"] !== undefined) {
    const configuredSecretNames = [
      ...plugins.flatMap((plugin) => (plugin.secrets ?? []).map((secret) => secret.name)),
      ...Object.values(secretEnv).flatMap((entries) => Object.values(entries ?? {})),
    ];
    out.aws = validateAws(o["aws"], path, runnableServices(services), configuredSecretNames);
  }
  if (target === "aws" && !out.aws) throw new CliError(`${path}: target "aws" requires an "aws" block`);
  for (const [service, entries] of Object.entries(out.secretEnv ?? {})) {
    const name = Object.keys(entries ?? {}).find((entry) => isReservedSecretEnvironmentName(out, service, entry));
    if (name) {
      throw new CliError(`${path}: "secretEnv.${service}.${name}" is managed outside the deployment secret store`);
    }
  }
  validatePublicCoordinateEnvironment(out, path);
  validateCredentialEndpoints(out, path);
  validateRuntimeControlValues(out, path);
  validateDeployAppsDomains(out, path);
  validateModelProvider(out, path);
  validatePublicTransport(out, path);
  validateSandboxSecondaryBackend(out, path);
  validateSlackEvents(out, path);
  validateAwsDeploymentProvider(out, path);
  validateFlyWorkloadNamespaces(out, path);
  validatePortalTrust(out, path);
  if (target === "aws") {
    validateAwsFrontDoor(out, path);
    const externalImages = [
      ...plugins.filter((plugin) => plugin.image).map((plugin) => plugin.name),
      ...Object.keys(imageOverrides).filter((service) => services.includes(service as DeclaredServiceName)),
    ];
    for (const workload of new Set([...runnableServices(services), ...externalImages])) {
      if (out.aws?.services[workload]) awsWorkloadArchitecture(out, workload);
    }
  }
  if (o["vms"] !== undefined) {
    out.vms = validateServiceMap(o["vms"], path, "vms", (v, k) => {
      if (!isPlainObject(v)) {
        throw new CliError(`${path}: "vms.${k}" must be an object (e.g. { "memory": "4gb" })`);
      }
      const vm = v;
      const vmOut: { size?: string; memory?: string } = {};
      for (const f of ["size", "memory"] as const) {
        const fv = vm[f];
        if (fv === undefined) continue;
        if (typeof fv !== "string") throw new CliError(`${path}: "vms.${k}.${f}" must be a string`);
        vmOut[f] = fv;
      }
      return vmOut;
    });
  }
  return out;
}

function configuredHarness(config: QmConfig): string {
  return effectiveCoreEnvironment(config).HARNESS?.trim() || (config.target === "fly" ? "pi" : "mock");
}

function isProtectedTransport(url: string): boolean {
  const parsed = new URL(url);
  if (parsed.protocol === "https:") return true;
  const host = parsed.hostname;
  if (host === "localhost" || host === "[::1]" || host === "::1") return true;
  return isIP(host) === 4 && host.split(".")[0] === "127";
}

function validatePublicTransport(config: QmConfig, path: string): void {
  const harness = configuredHarness(config);
  if (harness === "mock") return;
  if ([config.publicUrl, config.apiUrl].some((url) => url && !isProtectedTransport(url))) {
    throw new CliError(
      `${path}: HARNESS=${harness} requires an HTTPS publicUrl and apiUrl, or loopback origins, so sandbox capabilities never cross the network in cleartext`,
    );
  }
}

export function mockHarnessWarning(config: QmConfig): string | undefined {
  if (configuredHarness(config) !== "mock") return undefined;
  const unset = !effectiveCoreEnvironment(config).HARNESS?.trim();
  return `env.core.HARNESS is ${unset ? "unset, which means" : "set to"} "mock": this deployment answers every message with canned text and calls no model provider. Set it to "pi" for a deployment that runs real agent turns.`;
}

export function effectiveModelProvider(config: QmConfig): ModelProvider | undefined {
  const override = effectiveCoreEnvironment(config).MODEL_PROVIDER?.trim();
  return isModelProvider(override) ? override : config.modelProvider;
}

function validateModelProvider(config: QmConfig, path: string): void {
  const override = effectiveCoreEnvironment(config).MODEL_PROVIDER;
  if (override !== undefined && (!isModelProvider(override) || override !== override.trim())) {
    throw new CliError(
      `${path}: env.core.MODEL_PROVIDER must be one of ${MODEL_PROVIDERS.join(", ")}, or unset to use "modelProvider"`,
    );
  }
  const provider = effectiveModelProvider(config);
  if (!provider) return;
  const harness = configuredHarness(config);
  if (!MODEL_PROVIDER_HARNESSES[provider].includes(harness)) {
    throw new CliError(
      `${path}: model provider "${provider}" cannot serve a base model on env.core.HARNESS "${harness}" — that harness runs no ${provider} model, so every agent turn would be refused. Use ${MODEL_PROVIDER_HARNESSES[provider].join(", ")}, or pick a provider that harness can bill.`,
    );
  }
}

function validatePublicCoordinateEnvironment(config: QmConfig, path: string): void {
  for (const source of ["env", "secretEnv"] as const) {
    for (const [service, entries] of Object.entries(config[source] ?? {})) {
      const workload = isVirtualService(service) ? "core" : service;
      let names: string[] = [];
      if (workload === "core") names = ["PUBLIC_WEB_URL", "WEB_UI_PUBLIC_URL"];
      else if (workload === "web-ui") names = ["WEB_UI_PUBLIC_URL"];
      else if (workload === "portal") names = ["PORTAL_PUBLIC_URL"];
      for (const name of names) {
        const value = entries?.[name];
        if (value === undefined) continue;
        if (source === "secretEnv") {
          throw new CliError(
            `${path}: "secretEnv.${service}.${name}" is a public coordinate and must not be configured as a secret`,
          );
        }
        const canonical = canonicalHttpOrigin(value, `env.${service}.${name}`, path);
        if (canonical !== config.publicUrl) {
          throw new CliError(`${path}: env.${service}.${name} must match publicUrl`);
        }
        entries[name] = canonical;
      }
    }
  }
}

function validateDeployAppsDomains(config: QmConfig, path: string): void {
  const core = config.env.core;
  for (const name of ["DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_APPS_DOMAIN"] as const) {
    const value = core?.[name];
    if (value !== undefined) core![name] = canonicalDeployAppsDomain(value, name, path);
  }
  if (core?.PORTER_DEPLOY_APPS_DOMAIN !== undefined) {
    core.PORTER_DEPLOY_APPS_DOMAIN = canonicalPorterDeployAppsDomain(core.PORTER_DEPLOY_APPS_DOMAIN, path);
  }
  for (const name of ["DEPLOY_APPS_LOGIN_URL", "PUBLIC_WEB_URL"] as const) {
    const value = core?.[name];
    if (value !== undefined) core![name] = canonicalHttpOrigin(value, `env.core.${name}`, path);
  }
  const environment = effectiveCoreEnvironment(config);
  const appsDomain = effectiveDeployAppsDomain(config);
  const porterDomain = environment.PORTER_DEPLOY_APPS_DOMAIN?.trim().toLowerCase().replace(/\.$/u, "");
  if (environment.DEPLOY_PROVIDER === "porter" && appsDomain && porterDomain === appsDomain) {
    throw new CliError(
      `${path}: the effective gated deployment apps domain and PORTER_DEPLOY_APPS_DOMAIN must use distinct gated and direct domains`,
    );
  }
  if (
    environment.DEPLOY_PROVIDER === "porter" &&
    !environment.DEPLOY_APPS_DOMAIN &&
    environment.AWS_DEPLOY_APPS_DOMAIN &&
    environment.PORTER_DEPLOY_APPS_DOMAIN
  ) {
    throw new CliError(
      `${path}: env.core.AWS_DEPLOY_APPS_DOMAIN and PORTER_DEPLOY_APPS_DOMAIN are ambiguous when DEPLOY_PROVIDER is porter; set DEPLOY_APPS_DOMAIN for the gated portal domain or keep only the Porter ingress domain`,
    );
  }
  if (environment.DEPLOY_APPS_LOGIN_URL && !appsDomain) {
    throw new CliError(`${path}: env.core.DEPLOY_APPS_LOGIN_URL requires a gated deployment apps domain`);
  }
  if (appsDomain && !config.services.includes("portal")) {
    throw new CliError(`${path}: a gated deployment apps domain requires the portal service`);
  }
  if (!config.services.includes("portal")) return;
  if (config.secretEnv?.portal?.PORTAL_COOKIE_DOMAIN !== undefined) {
    throw new CliError(
      `${path}: secretEnv.portal.PORTAL_COOKIE_DOMAIN controls browser cookie scope and must be configured as a non-secret environment value`,
    );
  }
  const cookieRaw = config.env.portal?.PORTAL_COOKIE_DOMAIN;
  const cookie = cookieRaw
    ?.trim()
    .toLowerCase()
    .replace(/^\.|\.$/gu, "");
  if (cookieRaw !== undefined) {
    if (!cookie || cookieRaw !== cookieRaw.trim() || !DEPLOY_APPS_HOSTNAME.test(cookie)) {
      throw new CliError(`${path}: env.portal.PORTAL_COOKIE_DOMAIN must be a bare DNS name`);
    }
    if (DEPLOY_APPS_SHARED_PLATFORM_SUFFIXES.includes(cookie)) {
      throw new CliError(`${path}: env.portal.PORTAL_COOKIE_DOMAIN must not be a shared platform domain`);
    }
    config.env.portal!.PORTAL_COOKIE_DOMAIN = cookie;
  }
  const portalPublicUrl = effectivePortalPublicUrl(config);
  const portalOrigin = new URL(portalPublicUrl);
  const publicHost = portalOrigin.hostname.toLowerCase();
  if (appsDomain) {
    const loginUrl = environment.DEPLOY_APPS_LOGIN_URL ?? environment.PUBLIC_WEB_URL ?? config.publicUrl;
    const loginOrigin = new URL(loginUrl);
    if (loginOrigin.origin !== portalOrigin.origin) {
      throw new CliError(`${path}: the effective core deployment login origin must match the portal public origin`);
    }
    if (portalOrigin.protocol !== "https:" || loginOrigin.protocol !== "https:") {
      throw new CliError(`${path}: gated deployment apps require HTTPS portal and login origins`);
    }
    if (publicHost.length > 253 || !DEPLOY_APPS_HOSTNAME.test(publicHost) || isIP(publicHost)) {
      throw new CliError(`${path}: a gated deployment apps domain requires a valid DNS portal host`);
    }
    try {
      const representative = new URL(`https://x.${appsDomain}`);
      if (representative.hostname !== `x.${appsDomain}`) throw new Error("hostname");
    } catch {
      throw new CliError(`${path}: the deployment apps domain must derive valid deployment hostnames`);
    }
  }
  const within = (host: string, domain: string): boolean => host === domain || host.endsWith(`.${domain}`);
  if (cookie && !within(publicHost, cookie)) {
    throw new CliError(`${path}: env.portal.PORTAL_COOKIE_DOMAIN must cover the portal publicUrl host`);
  }
  if (porterDomain) {
    const effectiveCookieDomain = cookie ?? (appsDomain ? publicHost : undefined);
    const hostOnlyCollision =
      !effectiveCookieDomain &&
      publicHost.endsWith(`.${porterDomain}`) &&
      publicHost.split(".").length === porterDomain.split(".").length + 1;
    if (
      hostOnlyCollision ||
      (effectiveCookieDomain &&
        (within(porterDomain, effectiveCookieDomain) || within(effectiveCookieDomain, porterDomain)))
    ) {
      throw new CliError(
        `${path}: PORTER_DEPLOY_APPS_DOMAIN must keep every direct app host outside the portal session cookie domain`,
      );
    }
  }
  if (!appsDomain) return;
  if (!cookie && !publicHost.includes(".")) {
    throw new CliError(`${path}: a gated deployment apps domain requires a dotted portal publicUrl host`);
  }
  if (cookie ? !within(appsDomain, cookie) : !appsDomain.endsWith(`.${publicHost}`)) {
    throw new CliError(
      `${path}: the deployment apps domain must be under the portal publicUrl host or covered with it by env.portal.PORTAL_COOKIE_DOMAIN`,
    );
  }
}

const SANDBOX_RUNTIME_BACKENDS: readonly EffectiveSandboxBackend[] = [
  "aws",
  "local",
  "sprites",
  "smolmachines",
  "porter",
];

export const SLACK_OIDC_TOPOLOGY_ENV_KEYS = [
  "OIDC_ISSUER",
  "OIDC_AUTH_ENDPOINT",
  "OIDC_TOKEN_ENDPOINT",
  "OIDC_USERINFO_ENDPOINT",
] as const;

const EXTERNAL_OIDC_HTTPS_ENV_KEYS = [...SLACK_OIDC_TOPOLOGY_ENV_KEYS, "OIDC_JWKS_URI"] as const;

type SecretSelectorEnvironmentContract =
  { kind: "enumerated"; values: readonly string[] } | { kind: "presence"; secretBacked?: false };

export const SECRET_SELECTOR_ENVIRONMENT_CONTRACTS: Readonly<
  Record<string, Readonly<Record<string, SecretSelectorEnvironmentContract>>>
> = {
  core: {
    HARNESS: { kind: "enumerated", values: ["mock", "pi", "opencode", "codex", "claude"] },
    MODEL_PROVIDER: { kind: "enumerated", values: MODEL_PROVIDERS },
    SANDBOX_BACKEND: { kind: "enumerated", values: SANDBOX_RUNTIME_BACKENDS },
    SANDBOX_SECONDARY_BACKEND: { kind: "enumerated", values: SANDBOX_RUNTIME_BACKENDS },
    DEPLOY_PROVIDER: { kind: "enumerated", values: ["aws", "docker", "fly", "porter"] },
    SLACK_EVENTS_MODE: { kind: "enumerated", values: ["http", "socket"] },
    SLACK_IDENTITY_EMAIL: { kind: "enumerated", values: ["0", "1"] },
    SLACK_EMOJI_FALLBACK_PRINCIPAL: { kind: "presence", secretBacked: false },
    CODEX_AUTH_CREDENTIAL: { kind: "presence", secretBacked: false },
    CLAUDE_AUTH_CREDENTIAL: { kind: "presence", secretBacked: false },
    CODEX_BIN: { kind: "presence", secretBacked: false },
    CLAUDE_BIN: { kind: "presence", secretBacked: false },
    LOCAL_SANDBOX_DOCKER_BIN: { kind: "presence", secretBacked: false },
    CODEX_MODEL: { kind: "presence", secretBacked: false },
    CLAUDE_MODEL: { kind: "presence", secretBacked: false },
    OPENCODE_MODEL: { kind: "presence", secretBacked: false },
    PI_DETECT_MODEL: { kind: "presence", secretBacked: false },
    PI_JUDGE_MODEL: { kind: "presence", secretBacked: false },
    PI_TITLE_MODEL: { kind: "presence", secretBacked: false },
    AWS_DEPLOY_APPS_DOMAIN: { kind: "presence", secretBacked: false },
    DEPLOY_APPS_DOMAIN: { kind: "presence", secretBacked: false },
    GOOGLE_OAUTH_CLIENT_ID: { kind: "presence" },
    DROPBOX_OAUTH_CLIENT_ID: { kind: "presence" },
    LINEAR_OAUTH_CLIENT_ID: { kind: "presence" },
  },
  portal: {
    OIDC_CLIENT_ID: { kind: "presence" },
    OIDC_ALLOWED_EMAILS: { kind: "presence" },
    OIDC_ALLOWED_EMAIL_DOMAIN: { kind: "presence" },
    PORTAL_EXPECTED_TEAM_ID: { kind: "presence" },
  },
  auth: {
    AUTH_ALLOWED_EMAIL_DOMAIN: { kind: "presence", secretBacked: false },
    AUTH_EMAIL_TRANSPORT: { kind: "enumerated", values: EMAIL_TRANSPORTS },
  },
};

function validateSecretSelectorEnvironment(
  env: Partial<Record<DeclaredServiceName, Record<string, string>>>,
  path: string,
): void {
  for (const [service, values] of Object.entries(env)) {
    const workload = isVirtualService(service) ? "core" : service;
    const contracts = SECRET_SELECTOR_ENVIRONMENT_CONTRACTS[workload];
    if (!contracts) continue;
    for (const [name, value] of Object.entries(values ?? {})) {
      const contract = contracts[name];
      if (!contract) continue;
      if (!value || value !== value.trim()) {
        throw new CliError(`${path}: env.${service}.${name} must be a nonblank value without surrounding whitespace`);
      }
      if (contract.kind === "enumerated" && !contract.values.includes(value)) {
        throw new CliError(
          `${path}: env.${service}.${name} must be one of ${contract.values.map((entry) => JSON.stringify(entry)).join(", ")}`,
        );
      }
    }
  }
}

function runtimeSandboxBackend(value: string | undefined, name: string, path: string): EffectiveSandboxBackend {
  if (value === undefined || value.trim() === "") return "local";
  const backend = value.trim();
  if (SANDBOX_RUNTIME_BACKENDS.includes(backend as EffectiveSandboxBackend)) {
    return backend as EffectiveSandboxBackend;
  }
  throw new CliError(`${path}: env.core.${name} must be one of ${SANDBOX_RUNTIME_BACKENDS.join(", ")}, or unset`);
}

function validateSandboxSecondaryBackend(config: QmConfig, path: string): void {
  const environment = effectiveCoreEnvironment(config);
  const secondaryRaw = environment.SANDBOX_SECONDARY_BACKEND;
  if (secondaryRaw === undefined || secondaryRaw.trim() === "") return;
  const secondary = runtimeSandboxBackend(secondaryRaw, "SANDBOX_SECONDARY_BACKEND", path);
  const primary =
    environment.SANDBOX_BACKEND === undefined
      ? sandboxBackend(config)
      : runtimeSandboxBackend(environment.SANDBOX_BACKEND, "SANDBOX_BACKEND", path);
  if (secondary === primary) {
    throw new CliError(`${path}: env.core.SANDBOX_SECONDARY_BACKEND must differ from SANDBOX_BACKEND`);
  }
}

function validateSlackEvents(config: QmConfig, path: string): void {
  if (!config.services.includes("slack")) return;
  const environment = effectiveCoreEnvironment(config);
  if (environment.SLACK_EVENTS_MODE !== "http") return;
  const port = Number(environment.SLACK_EVENTS_PORT?.trim());
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new CliError(`${path}: Slack HTTP events mode requires SLACK_EVENTS_PORT to be an integer from 1 to 65535`);
  }
}

function validateAwsDeploymentProvider(config: QmConfig, path: string): void {
  if (config.target !== "aws") return;
  const provider = effectiveCoreEnvironment(config).DEPLOY_PROVIDER;
  if (provider !== undefined && provider.trim() !== "aws") {
    throw new CliError(`${path}: AWS env.core.DEPLOY_PROVIDER must be "aws" or unset`);
  }
}

function validateFlyWorkloadNamespaces(config: QmConfig, path: string): void {
  if (config.target !== "fly") return;
  const appPrefix = appPrefixOf(config);
  const deployAppPrefix = config.deployAppPrefix ?? `${appPrefix}-d`;
  for (const workload of [...runnableServices(config.services), ...config.plugins.map((plugin) => plugin.name)]) {
    const app = `${appPrefix}-${workload}`;
    if (app.startsWith(`${deployAppPrefix}-`)) {
      throw new CliError(
        `${path}: Fly workload app ${app} overlaps the per-deployment app namespace ${deployAppPrefix}-*`,
      );
    }
  }
}

const MANAGED_BROKER_ENV_KEYS = {
  portal: AUTH_BROKER_ENV_KEYS,
  auth: AUTH_SERVICE_BROKER_ENV_KEYS,
} as const;
const AUTH_BROKER_ROUTE_ENV_KEYS = ["AUTH_BROKER_UPSTREAM", "AUTH_BROKER_PREFIX"] as const;

function reservedSecretEnvironmentNames(config: QmConfig, service: string): ReadonlySet<string> {
  const plugin = config.plugins.some((entry) => entry.name === service);
  if (plugin) return new Set(PLUGIN_PROVIDER_ENVIRONMENT_NAMES);
  const workload = isVirtualService(service) ? "core" : service;
  const reserved = new Set<string>([...BUILT_IN_PROVIDER_ENVIRONMENT_NAMES, "PORT", "QM_DEPLOYMENT_ID"]);
  for (const name of RUNTIME_PLAINTEXT_ENVIRONMENT_NAMES[workload] ?? []) reserved.add(name);
  if (workload !== "core") reserved.add("FLY_REGION");
  if (workload === "core") {
    for (const name of [
      ...CORE_PROVIDER_ENVIRONMENT_NAMES,
      ...CORE_PLAINTEXT_PROVIDER_ENVIRONMENT_NAMES,
      "PUBLIC_WEB_URL",
      "WEB_UI_PUBLIC_URL",
      "DEPLOY_APPS_LOGIN_URL",
    ]) {
      reserved.add(name);
    }
    reserved.add("DATABASE_URL");
  } else {
    reserved.add("CORE_API_URL");
    reserved.add("CORE_ORG_ID");
  }
  if (workload === "web-ui") reserved.add("WEB_UI_PUBLIC_URL");
  if (workload === "auth") reserved.add("AUTH_BRAND_NAME");
  if (workload === "admin") {
    reserved.add("ADMIN_BASE_PATH");
    reserved.add("QM_VERSION");
  }
  if (workload === "portal") {
    for (const name of [
      ...AUTH_BROKER_ROUTE_ENV_KEYS,
      "PORTAL_PUBLIC_URL",
      "PORTAL_COOKIE_DOMAIN",
      "PORTAL_DIRECT_APPS_DOMAIN",
      "WEB_UI_UPSTREAM",
      "ADMIN_UPSTREAM",
      "PORTAL_XFF_TRUSTED_HOPS",
      "DEPLOY_APPS_DOMAIN",
      "PORTAL_APPS_DOMAIN",
      ...EXTERNAL_OIDC_HTTPS_ENV_KEYS,
    ]) {
      reserved.add(name);
    }
  }
  for (const [name, contract] of Object.entries(SECRET_SELECTOR_ENVIRONMENT_CONTRACTS[workload] ?? {})) {
    if (contract.kind === "enumerated" || contract.secretBacked === false) reserved.add(name);
  }
  if (config.services.includes("auth")) {
    for (const name of MANAGED_BROKER_ENV_KEYS[workload as keyof typeof MANAGED_BROKER_ENV_KEYS] ?? []) {
      reserved.add(name);
    }
  }
  return reserved;
}

export function isReservedSecretEnvironmentName(config: QmConfig, service: string, name: string): boolean {
  return (
    FLY_OWNER_ENVIRONMENT_NAME.test(name) ||
    AWS_ENDPOINT_ENVIRONMENT_NAME.test(name) ||
    dangerousRuntimeEnvironmentName(name) ||
    runtimePlaintextEnvironmentName(service, name) ||
    reservedSecretEnvironmentNames(config, service).has(name)
  );
}

function validateBrokerTrust(config: QmConfig, path: string, secrets?: ReadonlyMap<string, string>): void {
  const authEnv = config.env.auth ?? {};
  for (const [service, names] of Object.entries(MANAGED_BROKER_ENV_KEYS)) {
    for (const source of ["env", "secretEnv"] as const) {
      const values = config[source]?.[service as DeclaredServiceName];
      const overridden = names.find((name) => values?.[name] !== undefined);
      if (!overridden) continue;
      if (service === "portal") {
        throw new CliError(
          `${path}: ${source}.portal.${overridden} is derived from the built-in auth broker — remove it, or drop "auth" from "services" to use an external identity provider`,
        );
      }
      throw new CliError(`${path}: ${source}.auth.${overridden} is derived from publicUrl and cannot be set`);
    }
  }
  const expectedTeamSource = ["env", "secretEnv"].find(
    (source) => config[source as "env" | "secretEnv"]?.portal?.PORTAL_EXPECTED_TEAM_ID !== undefined,
  );
  if (expectedTeamSource) {
    throw new CliError(
      `${path}: ${expectedTeamSource}.portal.PORTAL_EXPECTED_TEAM_ID belongs to Slack sign-in and has no meaning with the built-in auth broker`,
    );
  }
  const transport = authEnv.AUTH_EMAIL_TRANSPORT?.trim();
  if (!isEmailTransport(transport)) {
    throw new CliError(
      `${path}: env.auth.AUTH_EMAIL_TRANSPORT must be ${EMAIL_TRANSPORTS.map((t) => JSON.stringify(t)).join(" or ")}`,
    );
  }
  if (authEnv.SMTP_PORT !== undefined) {
    const port = Number(authEnv.SMTP_PORT);
    if (!/^[1-9][0-9]*$/u.test(authEnv.SMTP_PORT) || !Number.isInteger(port) || port > 65_535) {
      throw new CliError(`${path}: env.auth.SMTP_PORT must be a TCP port number from 1 to 65535`);
    }
  }
  if (authEnv.SMTP_TLS !== undefined && !["starttls", "implicit", "none"].includes(authEnv.SMTP_TLS)) {
    throw new CliError(`${path}: env.auth.SMTP_TLS must be exactly starttls, implicit, or none`);
  }
  const domain = authEnv.AUTH_ALLOWED_EMAIL_DOMAIN?.trim();
  if (
    authEnv.AUTH_ALLOWED_EMAIL_DOMAIN !== undefined &&
    (isMissingOrPlaceholder(domain) || !validEmailDomain(domain!))
  ) {
    throw new CliError(
      `${path}: env.auth.AUTH_ALLOWED_EMAIL_DOMAIN must be a valid, non-placeholder email domain when set`,
    );
  }
  if (!secrets || domain) return;
  const allowed = (secrets.get("AUTH_ALLOWED_EMAILS") ?? "")
    .split(",")
    .map((email) => email.trim())
    .filter(Boolean);
  if (!allowed.length || allowed.some((email) => isMissingOrPlaceholder(email) || !validEmail(email))) {
    throw new CliError(
      `${path}: the built-in auth broker requires env.auth.AUTH_ALLOWED_EMAIL_DOMAIN or a valid AUTH_ALLOWED_EMAILS in the target secret store — without one, anybody with an inbox could sign in`,
    );
  }
}

function isSlackIssuer(issuer: string): boolean {
  try {
    const host = new URL(issuer).hostname;
    return host === "slack.com" || host.endsWith(".slack.com");
  } catch {
    return false;
  }
}

function canonicalExternalOidcUrl(
  value: string,
  name: (typeof EXTERNAL_OIDC_HTTPS_ENV_KEYS)[number],
  path: string,
): string {
  const message = `${path}: env.portal.${name} must be an absolute HTTPS URL without credentials, a fragment, controls, or ambiguous separators`;
  const authority = value.slice("https://".length).split(/[/?#]/u, 1)[0] ?? "";
  if (
    value !== value.trim() ||
    /[\p{Cc}\p{Cf}\\]/u.test(value) ||
    value.includes("#") ||
    value.endsWith("?") ||
    authority.includes("%") ||
    authority.endsWith(":") ||
    !/^https:\/\/[^/\\?#\s@]+(?:[/?#]|$)/iu.test(value)
  ) {
    throw new CliError(message);
  }
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      !url.hostname ||
      url.hostname.endsWith(".") ||
      url.username ||
      url.password ||
      url.hash ||
      (name === "OIDC_ISSUER" && url.search)
    ) {
      throw new Error("url");
    }
    if (name === "OIDC_ISSUER" && isSlackIssuer(url.toString()) && url.pathname !== "/") {
      throw new Error("slack issuer");
    }
    return name === "OIDC_ISSUER" && url.pathname === "/" && !url.search ? url.origin : url.toString();
  } catch {
    throw new CliError(message);
  }
}

export function validatePortalTrust(config: QmConfig, path = "config", secrets?: ReadonlyMap<string, string>): void {
  if (!config.services.includes("portal")) return;
  if (!config.services.includes("auth")) {
    const storedTopologyName = EXTERNAL_OIDC_HTTPS_ENV_KEYS.find(
      (name) => config.secretEnv?.portal?.[name] !== undefined,
    );
    if (storedTopologyName) {
      throw new CliError(
        `${path}: secretEnv.portal.${storedTopologyName} controls OIDC topology and must be configured as a non-secret environment value`,
      );
    }
  }
  if (config.services.includes("auth")) return validateBrokerTrust(config, path, secrets);
  const env = config.env.portal ?? {};
  for (const name of EXTERNAL_OIDC_HTTPS_ENV_KEYS) {
    if (env[name] !== undefined) env[name] = canonicalExternalOidcUrl(env[name], name, path);
  }
  const issuer = env.OIDC_ISSUER?.trim() || "https://slack.com";
  const jwksUri = env.OIDC_JWKS_URI?.trim();
  if (!isSlackIssuer(issuer) && isMissingOrPlaceholder(jwksUri)) {
    throw new CliError(`${path}: portal requires env.portal.OIDC_JWKS_URI when using a non-Slack OIDC issuer`);
  }
  if (env.OIDC_CLIENT_ID !== undefined && isMissingOrPlaceholder(env.OIDC_CLIENT_ID)) {
    throw new CliError(`${path}: env.portal.OIDC_CLIENT_ID may not be a placeholder when configured`);
  }
  if (secrets && isMissingOrPlaceholder(env.OIDC_CLIENT_ID ?? secrets.get("OIDC_CLIENT_ID"))) {
    throw new CliError(
      `${path}: portal requires a non-placeholder OIDC_CLIENT_ID in env.portal or the target secret store`,
    );
  }
  const domain = env.OIDC_ALLOWED_EMAIL_DOMAIN?.trim();
  const allowedEmails =
    env.OIDC_ALLOWED_EMAILS?.split(",")
      .map((email) => email.trim())
      .filter(Boolean) ?? [];
  const configuredTeam = env.PORTAL_EXPECTED_TEAM_ID?.trim();
  if (domain !== undefined && (isMissingOrPlaceholder(domain) || !validEmailDomain(domain))) {
    throw new CliError(
      `${path}: env.portal.OIDC_ALLOWED_EMAIL_DOMAIN must be a valid, non-placeholder email domain when set`,
    );
  }
  if (allowedEmails.some((email) => isMissingOrPlaceholder(email) || !validEmail(email))) {
    throw new CliError(`${path}: env.portal.OIDC_ALLOWED_EMAILS must contain valid, non-placeholder email addresses`);
  }
  if ((domain || allowedEmails.length) && (env.OIDC_PRINCIPAL_CLAIM ?? "email") !== "email") {
    throw new CliError(
      `${path}: portal requires env.portal.OIDC_PRINCIPAL_CLAIM=email when using an email trust boundary`,
    );
  }
  if (env.PORTAL_EXPECTED_TEAM_ID !== undefined && isMissingOrPlaceholder(configuredTeam)) {
    throw new CliError(
      `${path}: env.portal.PORTAL_EXPECTED_TEAM_ID is optional, but may not be a placeholder when configured`,
    );
  }
  if (
    secrets &&
    !domain &&
    !allowedEmails.length &&
    isMissingOrPlaceholder(configuredTeam ?? secrets.get("PORTAL_EXPECTED_TEAM_ID"))
  ) {
    throw new CliError(
      `${path}: portal requires OIDC_ALLOWED_EMAILS, OIDC_ALLOWED_EMAIL_DOMAIN, or a non-placeholder PORTAL_EXPECTED_TEAM_ID in env.portal or the target secret store`,
    );
  }
}

function validateAwsFrontDoor(config: QmConfig, path: string): void {
  const hasPortal = config.services.includes("portal");
  const hasWebUi = config.services.includes("web-ui");
  const publicUrl = new URL(config.publicUrl);
  const protocol = publicUrl.protocol;
  if (publicUrl.pathname !== "/" || publicUrl.search || publicUrl.hash || publicUrl.username || publicUrl.password) {
    throw new CliError(`${path}: AWS publicUrl must be an origin URL without credentials, a path, query, or fragment`);
  }
  if (config.apiUrl && new URL(config.apiUrl).protocol !== protocol) {
    throw new CliError(`${path}: AWS apiUrl must use the same protocol as publicUrl`);
  }
  const deployImage = config.env.core?.AWS_DEPLOY_IMAGE?.trim();
  if (isMissingOrPlaceholder(deployImage) || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(deployImage!)) {
    throw new CliError(
      `${path}: AWS requires env.core.AWS_DEPLOY_IMAGE to name a non-placeholder, stack-owned deployment publisher MicroVM image`,
    );
  }
  if (hasWebUi && !hasPortal) {
    throw new CliError(
      `${path}: AWS web-ui requires the authenticated portal; a portal-free ALB must never expose the Web UI`,
    );
  }
  if (config.services.includes("admin") && !hasPortal) {
    throw new CliError(`${path}: AWS admin requires the authenticated portal`);
  }
  if (hasPortal && !hasWebUi) {
    throw new CliError(`${path}: AWS portal requires web-ui`);
  }
  if (hasPortal && protocol !== "https:") {
    throw new CliError(`${path}: AWS portal requires an HTTPS publicUrl and ACM certificate`);
  }
  const harness = configuredHarness(config);
  if (protocol !== "https:" && harness !== "mock") {
    throw new CliError(
      `${path}: AWS HARNESS=${harness} requires an HTTPS publicUrl so sandbox capabilities never cross the Internet in cleartext`,
    );
  }
}

function validatePlugins(raw: unknown, path: string): PluginEntry[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) throw new CliError(`${path}: "plugins" must be an array`);
  const seen = new Set<string>();
  return raw.map((p, i) => {
    if (typeof p !== "object" || p === null) throw new CliError(`${path}: plugins[${i}] must be an object`);
    const e = p as Record<string, unknown>;
    if (typeof e["name"] !== "string" || !e["name"].trim()) throw new CliError(`${path}: plugins[${i}].name required`);
    const name = e["name"];
    const nameError = pluginNameError(name);
    if (nameError) throw new CliError(`${path}: plugins[${i}].name ${JSON.stringify(name)} ${nameError}`);
    if (seen.has(name)) throw new CliError(`${path}: duplicate plugin name ${JSON.stringify(name)}`);
    seen.add(name);
    const entry: PluginEntry = { name };
    if (e["image"] !== undefined) {
      if (typeof e["image"] !== "string" || !e["image"].trim()) {
        throw new CliError(`${path}: plugins[${i}].image must be a non-empty string (a pullable image ref) when set`);
      }
      entry.image = e["image"];
    }
    if (e["env"] !== undefined) entry.env = validateStringMap(e["env"], path, `plugins[${i}].env`);
    if (e["secrets"] !== undefined) entry.secrets = validatePluginSecrets(e["secrets"], path, i);
    return entry;
  });
}

function validatePluginSecrets(raw: unknown, path: string, pluginIndex: number): PluginSecret[] {
  if (!Array.isArray(raw)) throw new CliError(`${path}: plugins[${pluginIndex}].secrets must be an array`);
  const seen = new Set<string>();
  return raw.map((value, i) => {
    const field = `plugins[${pluginIndex}].secrets[${i}]`;
    if (!isPlainObject(value)) throw new CliError(`${path}: ${field} must be an object`);
    const name = value["name"];
    if (typeof name !== "string" || !isEnvVarName(name))
      throw new CliError(`${path}: ${field}.name must be a valid env var name`);
    if (seen.has(name)) throw new CliError(`${path}: duplicate plugin secret ${JSON.stringify(name)}`);
    seen.add(name);
    const out: PluginSecret = { name };
    if (value["description"] !== undefined) {
      if (typeof value["description"] !== "string")
        throw new CliError(`${path}: ${field}.description must be a string`);
      out.description = value["description"];
    }
    if (value["required"] !== undefined) {
      if (typeof value["required"] !== "boolean") throw new CliError(`${path}: ${field}.required must be a boolean`);
      out.required = value["required"];
    }
    return out;
  });
}

function validateAws(
  raw: unknown,
  path: string,
  enabledServices: ServiceName[],
  configuredSecretNames: string[],
): AwsConfig {
  if (!isPlainObject(raw)) throw new CliError(`${path}: "aws" must be an object`);
  const requiredString = (value: unknown, field: string): string => {
    if (typeof value !== "string" || !value.trim())
      throw new CliError(`${path}: "aws.${field}" must be a non-empty string`);
    return value;
  };
  const networking = raw["networking"];
  if (!isPlainObject(networking)) throw new CliError(`${path}: "aws.networking" must be an object`);
  const accountId = requiredString(raw["accountId"], "accountId");
  if (!/^\d{12}$/.test(accountId)) throw new CliError(`${path}: "aws.accountId" must be exactly 12 digits`);
  const cluster = requiredString(raw["cluster"], "cluster");
  if (cluster.length > 49 || !/^[a-z](?:[a-z0-9]|-(?=[a-z0-9]))*$/.test(cluster)) {
    throw new CliError(
      `${path}: "aws.cluster" must be at most 49 lowercase letters, digits, and single hyphens, start with a letter, and end with a letter or digit so its derived IAM and RDS names are valid`,
    );
  }
  const region = requiredString(raw["region"], "region");
  if (/^(?:cn-|us-gov-|us-iso|eu-isoe-)/.test(region)) {
    throw new CliError(
      `${path}: "aws.region" must be in the commercial AWS partition; GovCloud, China, and isolated partitions are not supported`,
    );
  }
  const secretsPrefix = requiredString(raw["secretsPrefix"], "secretsPrefix");
  if (secretsPrefix.length > 256 || !/^[A-Za-z0-9/_+=.@-]+$/.test(secretsPrefix)) {
    throw new CliError(
      `${path}: "aws.secretsPrefix" must be at most 256 AWS secret-name characters (letters, digits, /_+=.@-) so computed secret names fit`,
    );
  }
  const oversizedSecret = configuredSecretNames.find((name) => `${secretsPrefix}${name}`.length > 512);
  if (oversizedSecret) {
    throw new CliError(
      `${path}: "aws.secretsPrefix" plus computed secret ${JSON.stringify(oversizedSecret)} exceeds the 512-character AWS secret-name limit`,
    );
  }
  const imageLabel = requiredString(raw["imageLabel"], "imageLabel");
  if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(imageLabel)) {
    throw new CliError(
      `${path}: "aws.imageLabel" must be a valid OCI/ECR tag (1-128 letters, digits, underscores, periods, or hyphens; the first character cannot be a period or hyphen)`,
    );
  }
  let alb: string | undefined;
  if (raw["alb"] !== undefined) {
    alb = requiredString(raw["alb"], "alb");
    if (alb.length > 32 || !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(alb) || alb.startsWith("internal-")) {
      throw new CliError(
        `${path}: "aws.alb" must be a valid load balancer name (at most 32 letters, digits, and interior hyphens, not starting with "internal-")`,
      );
    }
  }
  let rdsInstance: string | undefined;
  if (raw["rdsInstance"] !== undefined) {
    rdsInstance = requiredString(raw["rdsInstance"], "rdsInstance");
    if (rdsInstance.length > 63 || !/^[a-z](?:[a-z0-9-]*[a-z0-9])?$/.test(rdsInstance) || rdsInstance.includes("--")) {
      throw new CliError(
        `${path}: "aws.rdsInstance" must be a valid DB instance identifier (at most 63 lowercase characters, starting with a letter, no double or trailing hyphens)`,
      );
    }
  }
  let predeployDbSnapshot: boolean | undefined;
  if (raw["predeployDbSnapshot"] !== undefined) {
    if (typeof raw["predeployDbSnapshot"] !== "boolean") {
      throw new CliError(
        `${path}: "aws.predeployDbSnapshot" must be a boolean (false skips the pre-deploy RDS snapshot)`,
      );
    }
    predeployDbSnapshot = raw["predeployDbSnapshot"];
  }
  let dbRetentionMinDays: number | undefined;
  if (raw["dbRetentionMinDays"] !== undefined) {
    const days = raw["dbRetentionMinDays"];
    if (typeof days !== "number" || !Number.isInteger(days) || days < 0 || days > 35) {
      throw new CliError(
        `${path}: "aws.dbRetentionMinDays" must be an integer between 0 and 35 (the RDS automated-backup retention range)`,
      );
    }
    dbRetentionMinDays = days;
  }
  let objectStoreBucket: string | undefined;
  if (raw["objectStoreBucket"] !== undefined) {
    objectStoreBucket = requiredString(raw["objectStoreBucket"], "objectStoreBucket");
    if (
      objectStoreBucket.length < 3 ||
      objectStoreBucket.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(objectStoreBucket) ||
      objectStoreBucket.includes("..") ||
      /^\d{1,3}(\.\d{1,3}){3}$/.test(objectStoreBucket)
    ) {
      throw new CliError(
        `${path}: "aws.objectStoreBucket" must be a valid S3 bucket name (3-63 lowercase letters, digits, and interior hyphens or dots; not IP-address-formatted)`,
      );
    }
  }
  let deployBranch: string | undefined;
  if (raw["deployBranch"] !== undefined) {
    deployBranch = requiredString(raw["deployBranch"], "deployBranch");
    const segments = deployBranch.split("/");
    if (
      deployBranch.length > 255 ||
      deployBranch.startsWith("refs/") ||
      deployBranch.includes("..") ||
      !/^[A-Za-z0-9._/-]+$/.test(deployBranch) ||
      segments.some(
        (segment) => !segment || segment.startsWith(".") || segment.endsWith(".") || segment.endsWith(".lock"),
      )
    ) {
      throw new CliError(`${path}: "aws.deployBranch" must be a valid git branch name (not a refs/* path)`);
    }
  }
  let deployEnvironment: string | undefined;
  if (raw["deployEnvironment"] !== undefined) {
    deployEnvironment = requiredString(raw["deployEnvironment"], "deployEnvironment");
    if (deployEnvironment.length > 255 || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(deployEnvironment)) {
      throw new CliError(`${path}: "aws.deployEnvironment" must be a valid GitHub environment name`);
    }
  }
  const cloudMapNamespace = requiredString(networking["cloudMapNamespace"], "networking.cloudMapNamespace");
  const namespaceLabels = cloudMapNamespace.split(".");
  if (
    cloudMapNamespace.length > 253 ||
    namespaceLabels.some(
      (label) => label.length === 0 || label.length > 63 || !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label),
    )
  ) {
    throw new CliError(
      `${path}: "aws.networking.cloudMapNamespace" must be a valid DNS namespace of at most 253 characters with labels of at most 63 characters`,
    );
  }
  const roleArn = (value: unknown, field: string): string => {
    const arn = requiredString(value, field);
    const match = arn.match(/^arn:aws:iam::([0-9]{12}):role\/[A-Za-z0-9_+=,.@/-]{1,512}$/);
    if (!match || match[1] !== accountId) {
      throw new CliError(
        `${path}: "aws.${field}" must be an IAM role ARN in account ${accountId} and the commercial AWS partition`,
      );
    }
    return arn;
  };
  const deployRoleArn = roleArn(raw["deployRoleArn"], "deployRoleArn");
  const servicesRaw = raw["services"];
  if (!isPlainObject(servicesRaw))
    throw new CliError(`${path}: "aws.services" must be an object keyed by service name`);
  const services: Record<string, AwsServiceConfig> = Object.create(null) as Record<string, AwsServiceConfig>;
  const coordinates = {
    ecrRepository: new Map<string, string>(),
    ecsService: new Map<string, string>(),
    targetGroup: new Map<string, string>(),
  };
  const validFargateSize = (cpu: number, memory: number): boolean => {
    const range = (min: number, max: number, step: number): boolean =>
      memory >= min && memory <= max && (memory - min) % step === 0;
    if (cpu === 256) return [512, 1024, 2048].includes(memory);
    if (cpu === 512) return range(1024, 4096, 1024);
    if (cpu === 1024) return range(2048, 8192, 1024);
    if (cpu === 2048) return range(4096, 16384, 1024);
    if (cpu === 4096) return range(8192, 30720, 1024);
    if (cpu === 8192) return range(16384, 61440, 4096);
    if (cpu === 16384) return range(32768, 122880, 8192);
    return false;
  };
  for (const [name, value] of Object.entries(servicesRaw)) {
    if (!isServiceName(name) && pluginNameError(name)) {
      throw new CliError(`${path}: "aws.services" has invalid workload name "${name}"`);
    }
    if (!isPlainObject(value)) throw new CliError(`${path}: "aws.services.${name}" must be an object`);
    const positiveInt = (field: "cpu" | "memory"): number => {
      const n = value[field];
      if (typeof n !== "number" || !Number.isInteger(n) || n <= 0) {
        throw new CliError(`${path}: "aws.services.${name}.${field}" must be a positive integer`);
      }
      return n;
    };
    const service: AwsServiceConfig = {
      ecrRepository: requiredString(value["ecrRepository"], `services.${name}.ecrRepository`),
      ecsService: requiredString(value["ecsService"], `services.${name}.ecsService`),
      cpu: positiveInt("cpu"),
      memory: positiveInt("memory"),
    };
    if (!validFargateSize(service.cpu, service.memory)) {
      throw new CliError(
        `${path}: "aws.services.${name}" cpu ${service.cpu} and memory ${service.memory} are not a supported Fargate task size`,
      );
    }
    for (const field of ["ecrRepository", "ecsService"] as const) {
      const previous = coordinates[field].get(service[field]);
      if (previous) {
        throw new CliError(
          `${path}: "aws.services.${name}.${field}" duplicates aws.services.${previous}.${field} (${JSON.stringify(service[field])})`,
        );
      }
      coordinates[field].set(service[field], name);
    }
    for (const role of ["taskRoleArn", "executionRoleArn"] as const) {
      if (value[role] !== undefined) service[role] = roleArn(value[role], `services.${name}.${role}`);
    }
    if (value["architecture"] !== undefined) {
      if (value["architecture"] !== "arm64" && value["architecture"] !== "amd64") {
        throw new CliError(`${path}: "aws.services.${name}.architecture" must be "arm64" or "amd64"`);
      }
      service.architecture = value["architecture"];
    }
    if (value["desiredCount"] !== undefined) {
      const desiredCount = value["desiredCount"];
      if (typeof desiredCount !== "number" || !Number.isInteger(desiredCount) || desiredCount <= 0) {
        throw new CliError(`${path}: "aws.services.${name}.desiredCount" must be a positive integer`);
      }
      service.desiredCount = desiredCount;
    }
    if (value["targetGroup"] !== undefined) {
      const targetGroup = requiredString(value["targetGroup"], `services.${name}.targetGroup`);
      if (targetGroup.length > 32 || !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(targetGroup)) {
        throw new CliError(
          `${path}: "aws.services.${name}.targetGroup" must be a valid target group name (at most 32 letters, digits, and interior hyphens)`,
        );
      }
      const previous = coordinates.targetGroup.get(targetGroup);
      if (previous) {
        throw new CliError(
          `${path}: "aws.services.${name}.targetGroup" duplicates aws.services.${previous}.targetGroup (${JSON.stringify(targetGroup)})`,
        );
      }
      coordinates.targetGroup.set(targetGroup, name);
      service.targetGroup = targetGroup;
    }
    if (value["logGroup"] !== undefined) {
      const logGroup = requiredString(value["logGroup"], `services.${name}.logGroup`);
      if (logGroup.length > 512 || !/^[A-Za-z0-9_/.#-]+$/.test(logGroup)) {
        throw new CliError(
          `${path}: "aws.services.${name}.logGroup" must be a valid CloudWatch log group name (at most 512 characters: letters, digits, _ / . # -)`,
        );
      }
      service.logGroup = logGroup;
    }
    if (value["stopTimeout"] !== undefined) {
      const stopTimeout = value["stopTimeout"];
      if (typeof stopTimeout !== "number" || !Number.isInteger(stopTimeout) || stopTimeout < 2 || stopTimeout > 120) {
        throw new CliError(
          `${path}: "aws.services.${name}.stopTimeout" must be an integer between 2 and 120 seconds (the Fargate limit)`,
        );
      }
      service.stopTimeout = stopTimeout;
    }
    if (value["buildArgs"] !== undefined) {
      service.buildArgs = validateStringMap(value["buildArgs"], path, `aws.services.${name}.buildArgs`);
      if (name === "admin" && service.buildArgs.QM_VERSION !== undefined) {
        throw new CliError(`${path}: "aws.services.admin.buildArgs.QM_VERSION" is reserved and cannot be overridden`);
      }
    }
    if (value["dockerfile"] !== undefined) {
      const dockerfile = requiredString(value["dockerfile"], `services.${name}.dockerfile`);
      if (isAbsolute(dockerfile) || dockerfile.includes("\\") || dockerfile.split("/").includes("..")) {
        throw new CliError(
          `${path}: "aws.services.${name}.dockerfile" must be a forward-slash relative path inside the build checkout`,
        );
      }
      service.dockerfile = dockerfile;
    }
    services[name] = service;
  }
  for (const name of enabledServices) {
    if (!Object.hasOwn(services, name)) {
      throw new CliError(`${path}: "aws.services.${name}" is required because ${name} is enabled`);
    }
  }
  const netOut: AwsConfig["networking"] = {
    cloudMapNamespace,
  };
  for (const key of ["subnets", "securityGroups"] as const) {
    if (networking[key] !== undefined) {
      throw new CliError(
        `${path}: "aws.networking.${key}" is not supported; network placement belongs to the provisioned ECS services`,
      );
    }
  }
  const out: AwsConfig = {
    accountId,
    region,
    cluster,
    deployRoleArn,
    secretsPrefix,
    imageLabel,
    networking: netOut,
    services,
  };
  if (alb) out.alb = alb;
  if (rdsInstance) out.rdsInstance = rdsInstance;
  if (predeployDbSnapshot !== undefined) out.predeployDbSnapshot = predeployDbSnapshot;
  if (dbRetentionMinDays !== undefined) out.dbRetentionMinDays = dbRetentionMinDays;
  if (deployBranch) out.deployBranch = deployBranch;
  if (deployEnvironment) out.deployEnvironment = deployEnvironment;
  if (objectStoreBucket) out.objectStoreBucket = objectStoreBucket;
  return out;
}

const validSpriteNamePrefix = (value: string): boolean => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(value);

function assertMigratedSandboxEnvironment(
  sandbox: { env?: unknown; secretEnv?: unknown } | undefined,
  path: string,
  target: Target,
  awsSecretsPrefix?: string,
): void {
  if (!sandbox) return;
  if (sandbox.env !== undefined) {
    if (!isPlainObject(sandbox.env)) {
      throw new CliError(`${path}: "sandbox.env" must be an object`);
    }
    if (Object.keys(sandbox.env).length) {
      throw new CliError(
        `${path}: sandbox.env from v0.1.6 cannot be migrated automatically because Sprites does not expose resident environment configuration; first stage each value in the sandbox tool or skill that consumes it and verify the replacement, then remove sandbox.env, roll the deployment, and confirm no live references remain before deleting the retired provider values`,
      );
    }
  }
  if (sandbox.secretEnv === undefined) return;
  if (!Array.isArray(sandbox.secretEnv) || sandbox.secretEnv.some((value) => typeof value !== "string")) {
    throw new CliError(`${path}: "sandbox.secretEnv" must be an array of strings`);
  }
  if (!sandbox.secretEnv.length) return;
  const invalid = sandbox.secretEnv.find((name) => !isEnvVarName(name));
  if (invalid) {
    throw new CliError(`${path}: "sandbox.secretEnv" entry ${JSON.stringify(invalid)} is not a valid env var name`);
  }
  const unique = [...new Set(sandbox.secretEnv)];
  let source = ".env or environment entries";
  let removal = unique.join(", ");
  if (target === "fly") {
    source = "Fly secrets";
    removal = unique.map((name) => `FLY_RESIDENT_ENV_${name}`).join(", ");
  }
  if (target === "aws") {
    source = "AWS Secrets Manager entries";
    removal = unique.map((name) => `${awsSecretsPrefix ?? "<aws.secretsPrefix>"}${name}`).join(", ");
  }
  throw new CliError(
    `${path}: sandbox.secretEnv from v0.1.6 cannot be migrated automatically (${unique.join(", ")}); first stage each credential in a supported connector, keychain, or tool path and verify the replacement, then remove sandbox.secretEnv, roll the deployment, confirm no live references remain, and finally delete ${source} ${removal}`,
  );
}

function normalizeLegacySandboxEnvironment(
  raw: unknown,
  env: Partial<Record<DeclaredServiceName, Record<string, string>>>,
  path: string,
  target: Target,
): unknown {
  const configuredBackend = env.core?.SANDBOX_BACKEND;
  const configuredPrefix = env.core?.SPRITES_NAME_PREFIX;
  if (configuredBackend === undefined && configuredPrefix === undefined) return raw;
  if (raw !== undefined && !isPlainObject(raw)) {
    throw new CliError(`${path}: "sandbox" must be an object (e.g. { "backend": "sprites" })`);
  }
  const sandbox = { ...raw } as Record<string, unknown>;
  let changed = false;
  if (configuredBackend !== undefined) {
    const backend = configuredBackend.trim();
    if (backend === "local" || backend === "sprites" || backend === "aws") {
      if (sandbox["backend"] !== undefined && sandbox["backend"] !== backend) {
        throw new CliError(`${path}: env.core.SANDBOX_BACKEND conflicts with sandbox.backend`);
      }
      sandbox["backend"] = backend;
      if (backend !== "sprites" && sandbox["app"] !== undefined) {
        delete sandbox["app"];
        delete sandbox["image"];
        delete sandbox["baseImage"];
      }
      changed = true;
      delete env.core!.SANDBOX_BACKEND;
    } else if (backend === "porter" || backend === "smolmachines") {
      if (
        (sandbox["backend"] !== undefined && sandbox["backend"] !== "sprites") ||
        sandbox["namePrefix"] !== undefined
      ) {
        throw new CliError(`${path}: env.core.SANDBOX_BACKEND conflicts with the sandbox block`);
      }
      if (sandbox["app"] !== undefined && (typeof sandbox["app"] !== "string" || !sandbox["app"].trim())) {
        throw new CliError(`${path}: "sandbox.app" must be a non-empty string`);
      }
      for (const field of ["image", "baseImage"] as const) {
        if (sandbox[field] !== undefined && (typeof sandbox[field] !== "string" || !sandbox[field].trim())) {
          throw new CliError(`${path}: "sandbox.${field}" must be a non-empty string`);
        }
      }
      for (const field of ["backend", "app", "image", "baseImage"] as const) {
        if (sandbox[field] === undefined) continue;
        delete sandbox[field];
        changed = true;
      }
      env.core!.SANDBOX_BACKEND = backend;
    } else {
      throw new CliError(
        `${path}: env.core.SANDBOX_BACKEND must be "local", "sprites", "aws", "porter", or "smolmachines"`,
      );
    }
  }
  if (configuredPrefix !== undefined) {
    if (configuredPrefix === "") {
      delete env.core!.SPRITES_NAME_PREFIX;
      if (!changed) return raw;
      return Object.keys(sandbox).length ? sandbox : undefined;
    }
    if (configuredPrefix !== configuredPrefix.trim() || !validSpriteNamePrefix(configuredPrefix)) {
      throw new CliError(
        `${path}: env.core.SPRITES_NAME_PREFIX must contain lowercase letters, digits, and interior hyphens without surrounding whitespace`,
      );
    }
    const runtimeBackend = env.core?.SANDBOX_BACKEND;
    if (
      runtimeBackend === "porter" ||
      runtimeBackend === "smolmachines" ||
      sandbox["backend"] === "local" ||
      sandbox["backend"] === "aws"
    ) {
      throw new CliError(`${path}: env.core.SPRITES_NAME_PREFIX requires the Sprites sandbox backend`);
    }
    if (sandbox["namePrefix"] !== undefined) {
      const structured =
        typeof sandbox["namePrefix"] === "string" ? sandbox["namePrefix"].trim() : sandbox["namePrefix"];
      if (structured !== configuredPrefix) {
        throw new CliError(`${path}: env.core.SPRITES_NAME_PREFIX conflicts with sandbox.namePrefix`);
      }
      if (sandbox["backend"] === undefined) sandbox["backend"] = "sprites";
    } else {
      const selectedSprites =
        sandbox["backend"] === "sprites" || target === "fly" || (target === "docker" && sandbox["app"] !== undefined);
      if (!selectedSprites) {
        throw new CliError(`${path}: env.core.SPRITES_NAME_PREFIX requires the Sprites sandbox backend`);
      }
      sandbox["backend"] = "sprites";
      sandbox["namePrefix"] = configuredPrefix;
    }
    changed = true;
    delete env.core!.SPRITES_NAME_PREFIX;
  }
  if (!changed) return raw;
  return Object.keys(sandbox).length ? sandbox : undefined;
}

function validateSandbox(
  raw: unknown,
  path: string,
  target: Target,
  awsSecretsPrefix?: string,
): SandboxConfig | undefined {
  if (raw === undefined) return undefined;
  if (!isPlainObject(raw)) {
    throw new CliError(`${path}: "sandbox" must be an object (e.g. { "backend": "sprites" })`);
  }
  const o = raw;
  assertMigratedSandboxEnvironment(o, path, target, awsSecretsPrefix);
  const unsupported = Object.keys(o).filter(
    (key) => !["backend", "app", "namePrefix", "image", "baseImage", "secretEnv", "env"].includes(key),
  );
  if (unsupported.length) {
    throw new CliError(
      `${path}: unsupported sandbox field${unsupported.length === 1 ? "" : "s"}: ${unsupported.join(", ")}`,
    );
  }
  const out: SandboxConfig = {};
  if (o["backend"] !== undefined) {
    if (o["backend"] !== "local" && o["backend"] !== "sprites" && o["backend"] !== "aws") {
      throw new CliError(
        `${path}: "sandbox.backend" must be "local" (Docker containers on the deployment host), "sprites" (Fly Sprites), or "aws" (Lambda MicroVM sandboxes)`,
      );
    }
    out.backend = o["backend"];
  }
  if (o["app"] !== undefined) {
    if (typeof o["app"] !== "string" || !o["app"].trim()) {
      throw new CliError(`${path}: "sandbox.app" must be a non-empty string`);
    }
    out.app = o["app"];
  }
  if (o["namePrefix"] !== undefined) {
    if (typeof o["namePrefix"] !== "string" || !validSpriteNamePrefix(o["namePrefix"].trim())) {
      throw new CliError(`${path}: "sandbox.namePrefix" must contain lowercase letters, digits, and interior hyphens`);
    }
    out.namePrefix = o["namePrefix"].trim();
  }
  if (o["image"] !== undefined) {
    if (typeof o["image"] !== "string" || !o["image"].trim()) {
      throw new CliError(`${path}: "sandbox.image" must be a non-empty string (a pullable rootfs image ref)`);
    }
    out.image = o["image"];
  }
  if (o["baseImage"] !== undefined && (typeof o["baseImage"] !== "string" || !o["baseImage"].trim())) {
    throw new CliError(`${path}: "sandbox.baseImage" must be a non-empty string`);
  }
  if (o["baseImage"] !== undefined && !out.app && !isDigestPinned(o["baseImage"] as string)) {
    throw new CliError(`${path}: "sandbox.baseImage" is accepted only as inert v0.1.6 metadata beside "sandbox.app"`);
  }
  if (!Object.keys(out).length) return undefined;
  if (out.backend !== undefined && !SANDBOX_BACKEND_POLICY[target].allowed.includes(out.backend)) {
    const targets = targetsAllowingSandboxBackend(out.backend)
      .map((allowed) => JSON.stringify(allowed))
      .join(" or ");
    const label = out.backend === "aws" ? " (Lambda MicroVM sandboxes)" : "";
    throw new CliError(`${path}: "sandbox.backend": ${JSON.stringify(out.backend)}${label} requires target ${targets}`);
  }
  if (SANDBOX_BACKEND_POLICY[target].requireExplicit && out.backend === undefined) {
    throw new CliError(
      `${path}: target ${JSON.stringify(target)} requires an explicit "sandbox.backend" — "sprites" runs Fly Sprites and optional "sandbox.namePrefix" selects their durable namespace; "aws" runs Lambda MicroVM sandboxes (or omit the whole "sandbox" block for the MicroVM default)`,
    );
  }
  const effectiveBackend = sandboxBackend({ target, sandbox: out });
  if (out.namePrefix && effectiveBackend !== "sprites") {
    throw new CliError(`${path}: "sandbox.namePrefix" requires the Sprites sandbox backend`);
  }
  if (effectiveBackend === "local" && (out.app || out.namePrefix)) {
    const field = out.namePrefix ? "namePrefix" : "app";
    throw new CliError(`${path}: "sandbox.backend": "local" ignores "sandbox.${field}" — remove it`);
  }
  if (effectiveBackend === "aws") {
    const stray = (["app", "namePrefix", "image"] as const).filter((key) => out[key] !== undefined);
    if (stray.length) {
      throw new CliError(
        `${path}: "sandbox.backend": "aws" runs Lambda MicroVM sandboxes, which ignore ${stray.map((key) => `"sandbox.${key}"`).join(", ")} — remove them`,
      );
    }
  }
  if (effectiveBackend === "sprites" && out.image) {
    if (out.app) delete out.image;
    else throw new CliError(`${path}: "sandbox.backend": "sprites" cannot consume "sandbox.image"`);
  }
  return Object.keys(out).length ? out : undefined;
}

function validateStringArray(raw: unknown, path: string, field: string): string[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw) || raw.some((v) => typeof v !== "string")) {
    throw new CliError(`${path}: "${field}" must be an array of strings`);
  }
  return raw as string[];
}

function validateStringMap(raw: unknown, path: string, field: string): Record<string, string> {
  if (!isPlainObject(raw)) {
    throw new CliError(`${path}: "${field}" must be an object of string values`);
  }
  const entries: Array<[string, string]> = [];
  for (const [k, v] of Object.entries(raw)) {
    if (!isEnvVarName(k)) {
      throw new CliError(`${path}: "${field}" key ${JSON.stringify(k)} is not a valid env var name`);
    }
    if (typeof v !== "string") throw new CliError(`${path}: "${field}.${k}" must be a string`);
    entries.push([k, v]);
  }
  return Object.fromEntries(entries);
}

function validateServiceMap<T>(
  raw: unknown,
  path: string,
  field: string,
  value: (v: unknown, key: string) => T,
): Partial<Record<DeclaredServiceName, T>> {
  if (raw === undefined) return {};
  if (!isPlainObject(raw)) {
    throw new CliError(`${path}: "${field}" must be an object keyed by service name`);
  }
  const out: Partial<Record<DeclaredServiceName, T>> = Object.create(null) as Partial<Record<DeclaredServiceName, T>>;
  for (const [k, v] of Object.entries(raw)) {
    if (!(field === "env" || field === "secretEnv" ? isDeclaredService(k) : isServiceName(k)))
      throw new CliError(`${path}: "${field}" has unknown service "${k}"`);
    out[k as DeclaredServiceName] = value(v, k);
  }
  return out;
}
