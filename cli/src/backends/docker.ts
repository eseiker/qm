import { httpDeploymentLayerTransport, type DeploymentLayerTransport } from "../deployment-layer.ts";
import { buildxInvocation, sourceBuildEnvironment } from "../buildx.ts";

import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { CliError, bold, die, dim, errMessage, header, note, ok, step, warn } from "../log.ts";
import {
  capture,
  captureBoth,
  assertNoNulSecret,
  isInvalidSecret,
  readEnvFile,
  resolveBuildRepoRoot,
  runInherit,
  sleep,
  streamLabeled,
  tailString,
  which,
  type FileIdentity,
} from "../util.ts";
import { manifestRef, sandboxBaseRef } from "../manifest.ts";
import {
  brokerWiring,
  ordered,
  brandEnvOf,
  orgEnv,
  runnableServices,
  serviceDef,
  teardownOrdered,
  virtualServiceEnv,
  type LogOpts,
  type ServiceName,
} from "../services.ts";
import {
  dockerBasePort,
  effectiveDeployAppsDomain,
  effectivePortalPublicUrl,
  localSandboxActive,
  sandboxCoreEnv,
  securityScreenEnv,
  type QmConfig,
} from "../config.ts";
import { discoverPlugins, type ResolvedPlugin } from "../plugins.ts";
import {
  computedSecrets,
  deploymentStoreSecretValue,
  materializeSecretValues,
  runtimeSecretNames,
  secretsForService,
  validateCompleteSecretValues,
} from "../secrets.ts";
import { readDeploymentState, withDeploymentLock, writeDeploymentState, type DeploymentState } from "../state.ts";

/** Deployment-layer transport for docker: signed HTTP to the locally published core port. */
export const dockerDeploymentLayerTransport: DeploymentLayerTransport = httpDeploymentLayerTransport({
  urlOf: (config) => new URL(`http://127.0.0.1:${dockerBasePort(config)}/v1/deployment-layer`),
});

const safe = (s: string): string => s.replace(/[^A-Za-z0-9_.-]/g, "-");
const ORG_LABEL_KEY = "qm.org";
const DATABASE_CA_CERT_ENV = "DATABASE_CA_CERT_FILE";
const DATABASE_CA_CERT_FILE = "/app/.qm-database-ca-cert.pem";
const AWS_CONTAINER_CREDENTIAL_ENV = [
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
] as const;
const DOCKER_PROVIDER_ENV = new Set([
  "BUILDKIT_COLORS",
  "BUILDKIT_PROGRESS",
  "BUILDX_BUILDER",
  "BUILDX_CONFIG",
  "BUILDX_EXPERIMENTAL",
  "DOCKER_API_VERSION",
  "DOCKER_BUILDKIT",
  "DOCKER_BUILDX_BIN",
  "DOCKER_CERT_PATH",
  "DOCKER_CLI_EXPERIMENTAL",
  "DOCKER_CONFIG",
  "DOCKER_CONTENT_TRUST",
  "DOCKER_CONTENT_TRUST_SERVER",
  "DOCKER_CONTEXT",
  "DOCKER_CUSTOM_HEADERS",
  "DOCKER_DEFAULT_PLATFORM",
  "DOCKER_HIDE_LEGACY_COMMANDS",
  "DOCKER_HOST",
  "DOCKER_SCAN_SUGGEST",
  "DOCKER_TLS",
  "DOCKER_TLS_VERIFY",
  "HOME",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "PATH",
  "SSH_AUTH_SOCK",
  "TEMP",
  "TMP",
  "TMPDIR",
  "USER",
  "XDG_CONFIG_HOME",
  "CURL_CA_BUNDLE",
  "EXPERIMENTAL_BUILDKIT_SOURCE_POLICY",
  "KUBECONFIG",
  "NODE_EXTRA_CA_CERTS",
  "REQUESTS_CA_BUNDLE",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "http_proxy",
  "https_proxy",
  "no_proxy",
]);
const orgLabelArgs = (ctx: DockerCtx): string[] => ["--label", `${ORG_LABEL_KEY}=${ctx.config.orgId}`];
const baseHostPort = (ctx: DockerCtx): number => dockerBasePort(ctx.config);

function isDockerProviderEnvironment(name: string): boolean {
  return DOCKER_PROVIDER_ENV.has(name) || /^(?:BUILDKIT|BUILDX|DOCKER)_/.test(name);
}

function stripAwsContainerCredentialEnvironment(env: Record<string, string | undefined>): void {
  for (const name of AWS_CONTAINER_CREDENTIAL_ENV) delete env[name];
}

function dockerProcessEnvironment(
  config: QmConfig,
  fileValues: ReadonlyMap<string, string>,
): {
  ambientEnv: Readonly<NodeJS.ProcessEnv>;
  env: NodeJS.ProcessEnv;
  selectedSecrets: ReadonlyMap<string, string | undefined>;
  selectedSecretValues: ReadonlySet<string>;
} {
  const ambientEnv = { ...process.env };
  const env = { ...ambientEnv };
  const secretNames = new Set(["DATABASE_CA_CERT_FILE", "DATABASE_URL", "POSTGRES_PASSWORD"]);
  const selectedSecrets = new Map<string, string | undefined>();
  const selectedSecretValues = new Set<string>();
  const sensitiveValues = new Set<string>();
  for (const secret of computedSecrets(config)) {
    if (isDockerProviderEnvironment(secret.name)) {
      throw new CliError(`${secret.name} cannot be used as a Docker secret-store entry`);
    }
    secretNames.add(secret.name);
    const selected =
      deploymentStoreSecretValue(secret.name, fileValues.get(secret.name), ambientEnv) ??
      (secret.name === "PUBLIC_API_URL" ? (config.apiUrl ?? config.publicUrl) : undefined);
    assertNoNulSecret(secret.name, selected);
    selectedSecrets.set(secret.name, selected);
    if (selected !== undefined) {
      selectedSecretValues.add(selected);
      sensitiveValues.add(selected);
    }
    const ambient = ambientEnv[secret.name];
    if (ambient !== undefined) sensitiveValues.add(ambient);
    for (const alias of secret.aliases ?? []) {
      secretNames.add(alias.name);
      const aliasValue = ambientEnv[alias.name];
      if (aliasValue !== undefined && !isDockerProviderEnvironment(alias.name)) sensitiveValues.add(aliasValue);
    }
  }
  const databaseUrl = deploymentStoreSecretValue("DATABASE_URL", fileValues.get("DATABASE_URL"), ambientEnv);
  assertNoNulSecret("DATABASE_URL", databaseUrl);
  selectedSecrets.set("DATABASE_URL", databaseUrl);
  if (databaseUrl !== undefined) {
    selectedSecretValues.add(databaseUrl);
    sensitiveValues.add(databaseUrl);
  }
  if (ambientEnv.POSTGRES_PASSWORD !== undefined) {
    selectedSecretValues.add(ambientEnv.POSTGRES_PASSWORD);
    sensitiveValues.add(ambientEnv.POSTGRES_PASSWORD);
  }
  for (const [name, value] of Object.entries(env)) {
    if (name.startsWith("GIT_")) {
      delete env[name];
      continue;
    }
    if (isDockerProviderEnvironment(name)) {
      if (value !== undefined && selectedSecretValues.has(value)) {
        throw new CliError(`Docker provider control ${name} must not equal a selected deployment secret`);
      }
      continue;
    }
    if (secretNames.has(name) || (value !== undefined && sensitiveValues.has(value))) delete env[name];
  }
  if (selectedSecretValues.has("false")) {
    throw new CliError("Docker source-build controls must not equal a selected deployment secret");
  }
  stripAwsContainerCredentialEnvironment(env);
  env.BUILDX_GIT_INFO = "false";
  env.BUILDX_GIT_LABELS = "false";
  return { ambientEnv, env, selectedSecrets, selectedSecretValues };
}

interface DockerCtx {
  config: QmConfig;
  configDir: string;
  sandboxDir: string;
  network: string;
  prefix: string;
  databaseUrl: string;
  signingSecret?: string;
  envFile?: string;
  ambientEnv: Readonly<NodeJS.ProcessEnv>;
  fileValues: ReadonlyMap<string, string>;
  sandboxEnv: Record<string, string>;
  buildFrom: boolean;
  processEnv: NodeJS.ProcessEnv;
  sourceBuildEnv?: NodeJS.ProcessEnv;
  selectedSecrets: ReadonlyMap<string, string | undefined>;
  selectedSecretValues: ReadonlySet<string>;
  dockerSocket?: { path: string; gid?: string };
  repoRoot?: string;
}

export interface DockerEnvironmentSource {
  configDir: string;
  configPath: string;
  configIdentity: FileIdentity;
  envFile?: string;
}

function dockerEnvironmentSnapshot(source: DockerEnvironmentSource): {
  envFile?: string;
  fileValues: ReadonlyMap<string, string>;
} {
  if (source.envFile !== undefined && !source.envFile.trim()) {
    throw new CliError("--env-file needs a non-empty path", { clause: "cli.invocation" });
  }
  const explicit = source.envFile !== undefined;
  const path = source.envFile !== undefined ? resolve(source.envFile) : join(source.configDir, ".env");
  return {
    envFile: path,
    fileValues: readEnvFile(path, { required: explicit, protectedIdentity: source.configIdentity }),
  };
}

const dockerPrefix = (config: QmConfig): string => `qm-${safe(config.orgId)}`;
const cname = (ctx: DockerCtx, name: string): string => `${ctx.prefix}-${name}`;
const pgVolume = (ctx: DockerCtx): string => `${ctx.prefix}-pgdata`;

const localSandboxImage = (config: QmConfig): string =>
  config.sandbox?.image ?? `${dockerPrefix(config).toLowerCase()}-sandbox-local:latest`;

function localAgentSource(): Buffer {
  const source = new URL("../../templates/aws/microvm-agent/agent.mjs", import.meta.url);
  const packaged = new URL("../../../templates/aws/microvm-agent/agent.mjs", import.meta.url);
  return readFileSync(existsSync(source) ? source : packaged);
}

function ensureLocalSandboxImage(config: QmConfig, env: NodeJS.ProcessEnv): string {
  const image = localSandboxImage(config);
  if (config.sandbox?.image) return image;
  const base = sandboxBaseRef();
  const agent = localAgentSource();
  const source = createHash("sha256").update(base).update("\0").update(agent).digest("hex");
  try {
    const labeled = capture(
      "docker",
      ["image", "inspect", "-f", '{{index .Config.Labels "qm.local-sandbox-source"}}', image],
      { env },
    ).trim();
    if (labeled === source) return image;
  } catch {
    void 0;
  }
  const dir = mkdtempSync(join(tmpdir(), "qm-local-sandbox-"));
  try {
    writeFileSync(join(dir, "agent.mjs"), agent);
    writeFileSync(
      join(dir, "Dockerfile"),
      `ARG BASE\nFROM \${BASE}\nCOPY agent.mjs /opt/qm/agent.mjs\nENV HOME=/root\nWORKDIR /root\nEXPOSE 8080\nCMD ["node", "/opt/qm/agent.mjs"]\n`,
    );
    dockerInherit(
      [
        "build",
        "--build-arg",
        `BASE=${base}`,
        "--label",
        `qm.local-sandbox-base=${base}`,
        "--label",
        `qm.local-sandbox-source=${source}`,
        "-t",
        image,
        dir,
      ],
      env,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return image;
}

function dockerEndpoint(env: NodeJS.ProcessEnv): string {
  const context = env.DOCKER_CONTEXT?.trim();
  const host = env.DOCKER_HOST?.trim();
  if (!context && host) return host;
  const inspectEnv = { ...env };
  delete inspectEnv.DOCKER_CERT_PATH;
  delete inspectEnv.DOCKER_CONTEXT;
  delete inspectEnv.DOCKER_HOST;
  delete inspectEnv.DOCKER_TLS;
  delete inspectEnv.DOCKER_TLS_VERIFY;
  let output: string;
  try {
    output = capture(
      "docker",
      ["context", "inspect", "--format", "{{json .Endpoints.docker.Host}}", ...(context ? ["--", context] : [])],
      { env: inspectEnv },
    ).trim();
  } catch {
    throw new CliError("Docker target cannot resolve the effective Docker context");
  }
  try {
    const endpoint: unknown = JSON.parse(output);
    if (typeof endpoint === "string" && endpoint) return endpoint;
  } catch {
    void 0;
  }
  throw new CliError("Docker target cannot resolve the effective Docker context");
}

function hostDockerSocket(
  env: NodeJS.ProcessEnv,
  selectedSecretValues: ReadonlySet<string>,
): { path: string; gid?: string } {
  const endpoint = dockerEndpoint(env);
  if (selectedSecretValues.has(endpoint)) {
    throw new CliError("Docker provider control DOCKER_HOST must not equal a selected deployment secret");
  }
  if (!endpoint.startsWith("unix://")) {
    throw new CliError("Docker target requires a Unix Docker socket");
  }
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new CliError("Docker target requires a Unix Docker socket");
  }
  if (parsed.protocol !== "unix:" || parsed.hostname || parsed.search || parsed.hash) {
    throw new CliError("Docker target requires a Unix Docker socket");
  }
  let path: string;
  try {
    path = decodeURIComponent(parsed.pathname);
  } catch {
    throw new CliError("Docker target requires a valid Unix Docker socket path");
  }
  if (!isAbsolute(path)) throw new CliError("Docker target requires an absolute Unix Docker socket");
  try {
    const identity = statSync(path);
    delete env.DOCKER_CERT_PATH;
    delete env.DOCKER_CONTEXT;
    delete env.DOCKER_TLS;
    delete env.DOCKER_TLS_VERIFY;
    env.DOCKER_HOST = endpoint;
    return { path, gid: String(identity.gid) };
  } catch {
    throw new CliError(`Docker target cannot read the Docker socket at ${path}`);
  }
}

function requireDocker(env: NodeJS.ProcessEnv): void {
  if (!which("docker")) die("docker not found on PATH (the docker target needs a running Docker daemon).");
  try {
    capture("docker", ["version", "-f", "{{.Server.Version}}"], { env });
  } catch {
    die("the Docker daemon is not reachable — start Docker (or OrbStack) and retry.");
  }
}

function docker(args: string[], env: NodeJS.ProcessEnv, allow?: RegExp): string {
  try {
    return capture("docker", args, { env, ...(allow ? { allow } : {}) });
  } catch (e) {
    throw dockerError(args, errMessage(e));
  }
}

function dockerInherit(args: string[], env: NodeJS.ProcessEnv, hint?: string): void {
  const buildArgs = ["build", "--provenance=false", ...args.slice(1)];
  const invocation =
    args[0] === "build"
      ? buildxInvocation(["build", "--load", "--provenance=false", ...args.slice(1)], env, buildArgs)
      : { command: "docker", args, env };
  try {
    runInherit(invocation.command, invocation.args, { env: invocation.env });
  } catch {
    throw new CliError(`docker ${args.slice(0, 2).join(" ")} failed.${hint ? `\n${hint}` : ""}`);
  }
}

function dockerError(args: string[], message: string): CliError {
  let hint = "";
  if (/port is already allocated|address already in use/i.test(message)) {
    hint = `\nhint: a host port is already in use — set QM_BASE_PORT to a free base port.`;
  }
  return new CliError(`docker ${args.slice(0, 3).join(" ")}… failed:\n${message}${hint}`);
}

function containerRunning(name: string, env: NodeJS.ProcessEnv): boolean {
  try {
    return docker(["inspect", "-f", "{{.State.Running}}", name], env, /No such object/).trim() === "true";
  } catch {
    return false;
  }
}

function inspectExists(args: string[], env: NodeJS.ProcessEnv, notFound: RegExp): boolean {
  const out = docker(args, env, notFound);
  return out.trim().length > 0 && !notFound.test(out);
}

function containerExists(name: string, env: NodeJS.ProcessEnv): boolean {
  return inspectExists(["inspect", "-f", "{{.Id}}", name], env, /No such object|No such container/i);
}

function volumeExists(name: string, env: NodeJS.ProcessEnv): boolean {
  return inspectExists(["volume", "inspect", "-f", "{{.Name}}", name], env, /No such volume|not found/i);
}

function pgContainerPassword(ctx: DockerCtx): string | undefined {
  if (!containerExists(cname(ctx, "pg"), ctx.processEnv)) return undefined;
  try {
    const output = docker(
      ["inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", cname(ctx, "pg")],
      ctx.processEnv,
    );
    return output
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l.startsWith("POSTGRES_PASSWORD="))
      ?.slice("POSTGRES_PASSWORD=".length);
  } catch {
    return undefined;
  }
}

function imageRef(ctx: DockerCtx, service: ServiceName): string {
  return ctx.config.imageOverrides[service] ?? manifestRef(service);
}

function resolveImage(ctx: DockerCtx, service: ServiceName): string {
  if (ctx.buildFrom) {
    const root = ctx.repoRoot!;
    const dockerfile = join(root, "deploy", service, "Dockerfile");
    if (!existsSync(dockerfile)) throw new CliError(`no Dockerfile at ${dockerfile}`);
    const tag = `qm-${service}:local`;
    step(`building ${service} from ${dockerfile}`);
    dockerInherit(["build", "-f", dockerfile, "-t", tag, root], ctx.sourceBuildEnv!);
    return tag;
  }
  const ref = imageRef(ctx, service);
  step(`pulling ${ref}`);
  dockerInherit(
    ["pull", ref],
    ctx.processEnv,
    `failed to pull ${ref} — the portable images may not be published yet; ` +
      `re-run with --build-from to build locally from deploy/${service}/Dockerfile.`,
  );
  return ref;
}

function resolvePluginImage(ctx: DockerCtx, p: ResolvedPlugin): string {
  if (p.kind === "source") {
    const tag = `${ctx.prefix}-${p.name}:local`;
    step(`building plugin ${p.name} from ${p.dockerfile}`);
    dockerInherit(["build", "-f", p.dockerfile!, "-t", tag, p.sourceDir!], ctx.sourceBuildEnv!);
    return tag;
  }
  step(`pulling plugin ${p.name} (${p.image})`);
  dockerInherit(["pull", p.image!], ctx.processEnv, `failed to pull ${p.image} for plugin ${p.name}.`);
  return p.image!;
}

function ensureNetwork(ctx: DockerCtx): void {
  docker(["network", "create", ctx.network], ctx.processEnv, /already exists/);
}

function persistRestart(name: string, env: NodeJS.ProcessEnv): void {
  docker(["update", "--restart", "unless-stopped", name], env);
}

function externalDatabaseUrl(ctx: DockerCtx): string | undefined {
  return ctx.selectedSecrets.get("DATABASE_URL");
}

function ensurePostgres(ctx: DockerCtx, dryRun: boolean): string {
  const fromEnv = externalDatabaseUrl(ctx);
  if (fromEnv) {
    step("Postgres: using DATABASE_URL from the environment");
    return fromEnv;
  }

  const pgName = cname(ctx, "pg");
  const url = (password: string): string => `postgres://postgres:${password}@pg:5432/qm`;

  if (dryRun) {
    step(`Postgres: would run ${pgName} (image postgres:16, volume ${pgVolume(ctx)})`);
    return url(readDeploymentState(ctx.config.orgId)?.pgPassword ?? "<generated>");
  }
  return withDeploymentLock(ctx.config.orgId, () => {
    const state = readDeploymentState(ctx.config.orgId);
    let password: string;
    const existing = pgContainerPassword(ctx);
    if (existing) {
      password = existing;
    } else if (volumeExists(pgVolume(ctx), ctx.processEnv)) {
      if (!state?.pgPassword) {
        throw new CliError(
          `Postgres volume ${pgVolume(ctx)} exists but its password is unknown (deployment state missing). ` +
            `Set DATABASE_URL to point at it, or 'qm down --purge' to recreate it (DESTROYS data).`,
        );
      }
      password = state.pgPassword;
    } else {
      password = state?.pgPassword ?? randomBytes(16).toString("hex");
    }

    const stateOut: DeploymentState = { orgId: ctx.config.orgId, network: ctx.network, pgPassword: password };
    writeDeploymentState(stateOut);

    if (!containerRunning(pgName, ctx.processEnv)) {
      step(`Postgres: starting ${pgName}`);
      docker(["rm", "-f", pgName], ctx.processEnv, /No such container|is not running/);
      const secretFile = writeSecretEnvFile({ POSTGRES_PASSWORD: password });
      try {
        launchContainer(
          pgName,
          {
            args: [
              "run",
              "-d",
              "--name",
              pgName,
              ...orgLabelArgs(ctx),
              "--network",
              ctx.network,
              "--network-alias",
              "pg",
              "--restart",
              "no",
              "--env-file",
              secretFile.path,
              "-e",
              "POSTGRES_DB=qm",
              "-v",
              `${pgVolume(ctx)}:/var/lib/postgresql/data`,
              "postgres:16",
            ],
          },
          ctx.processEnv,
        );
      } finally {
        secretFile.cleanup();
      }
    }
    return url(password);
  });
}

async function waitPostgres(ctx: DockerCtx): Promise<void> {
  for (let i = 0; i < 60; i++) {
    try {
      docker(["exec", cname(ctx, "pg"), "pg_isready", "-U", "postgres"], ctx.processEnv);
      persistRestart(cname(ctx, "pg"), ctx.processEnv);
      return;
    } catch {
      await sleep(1000);
    }
  }
  throw new CliError("Postgres did not become ready in 60s");
}

function secretValues(ctx: DockerCtx, service: string): Record<string, string> {
  const out = new Map<string, string>();
  for (const secret of secretsForService(ctx.config, service)) {
    if (secret.managedBy === "terraform" && service === "core") continue;
    const value = ctx.selectedSecrets.get(secret.name);
    if (value === undefined) continue;
    for (const name of runtimeSecretNames(service, secret)) {
      out.set(name, value);
    }
  }
  return Object.fromEntries(out);
}

export function dockerServiceEnv(config: QmConfig, service: ServiceName): Record<string, string> {
  const def = serviceDef(service);
  const out: Record<string, string> = {
    [def.docker.portEnv]: String(def.docker.internalPort),
    CORE_API_URL: "http://core:8080",
    ...orgEnv(service, config.orgId, config.publicUrl, config.services.includes("portal"), brandEnvOf(config)),
  };
  if (service === "core" && localSandboxActive(config)) {
    out.DOCKER_HOST = "unix:///var/run/docker.sock";
    out.QM_CORE_CONTAINER = `${dockerPrefix(config)}-core`;
  }
  if (service === "portal") {
    const appsDomain = effectiveDeployAppsDomain(config);
    if (appsDomain) out.DEPLOY_APPS_DOMAIN = appsDomain;
    if (config.services.includes("web-ui")) out.WEB_UI_UPSTREAM = "http://web-ui:8080";
    if (config.services.includes("admin")) out.ADMIN_UPSTREAM = "http://admin:8080";
  }
  if (config.services.includes("auth")) {
    Object.assign(
      out,
      brokerWiring(service, {
        publicUrl: effectivePortalPublicUrl(config),
        authBaseUrl: `http://${dockerPrefix(config)}-auth.internal:8080`,
        ...(config.env.auth?.AUTH_ALLOWED_EMAIL_DOMAIN
          ? { allowedEmailDomain: config.env.auth.AUTH_ALLOWED_EMAIL_DOMAIN }
          : {}),
      }),
    );
  }
  return out;
}

function serviceEnv(ctx: DockerCtx, service: ServiceName): Record<string, string> {
  const { config } = ctx;
  const out: Record<string, string> = {};
  if (ctx.signingSecret) out.CORE_SIGNING_SECRET = ctx.signingSecret;
  if (service === "core") {
    Object.assign(
      out,
      orgEnv("core", config.orgId, config.publicUrl, config.services.includes("portal"), brandEnvOf(config)),
    );
    out.PORT = "8080";
    out.DATABASE_URL = ctx.databaseUrl;
    if (config.model) out.PI_MODEL = config.model;
    if (config.modelProvider) out.MODEL_PROVIDER = config.modelProvider;
    Object.assign(out, ctx.sandboxEnv);
  } else {
    Object.assign(out, dockerServiceEnv(config, service));
  }
  const virtualEnv = service === "core" ? virtualServiceEnv(config.services, config.env) : {};
  const selectedSecrets: Record<string, string> = {
    ...secretValues(ctx, service),
    ...(ctx.signingSecret ? { CORE_SIGNING_SECRET: ctx.signingSecret } : {}),
    ...(service === "core" && ctx.databaseUrl ? { DATABASE_URL: ctx.databaseUrl } : {}),
  };
  const env = {
    ...out,
    ...virtualEnv,
    ...config.env[service],
    ...(service === "core" ? securityScreenEnv(config) : {}),
    ...selectedSecrets,
  };
  for (const key of secretEnvKeys(ctx, service)) {
    if (!Object.hasOwn(selectedSecrets, key)) delete env[key];
  }
  if (service === "portal") {
    if (config.services.includes("web-ui")) env.WEB_UI_UPSTREAM = "http://web-ui:8080";
    else delete env.WEB_UI_UPSTREAM;
    if (config.services.includes("admin")) env.ADMIN_UPSTREAM = "http://admin:8080";
    else delete env.ADMIN_UPSTREAM;
    if (config.services.includes("auth")) {
      const upstream = out.AUTH_BROKER_UPSTREAM;
      const prefix = out.AUTH_BROKER_PREFIX;
      if (!upstream || !prefix) throw new CliError("Docker auth broker wiring is incomplete");
      env.AUTH_BROKER_UPSTREAM = upstream;
      env.AUTH_BROKER_PREFIX = prefix;
    } else {
      delete env.AUTH_BROKER_UPSTREAM;
      delete env.AUTH_BROKER_PREFIX;
    }
  }
  if (service === "web-ui" || service === "admin") delete env.ALLOW_UNSIGNED_TEST_IDENTITY;
  env.NODE_ENV = "production";
  if (service === "core") {
    env.PUBLIC_API_URL = config.apiUrl ?? config.publicUrl;
    delete env.AGENT_API_URL;
    delete env.SLACK_API_URL;
    env.DATA_DIR = "/data";
    env.SESSION_STORE = "postgres";
    env.RUN_STORE = "postgres";
    if (existingLayerSubdirs(ctx).length) env.DEPLOYMENT_LAYER = "/layer";
    else delete env.DEPLOYMENT_LAYER;
    if (localSandboxActive(config)) {
      env.DOCKER_HOST = "unix:///var/run/docker.sock";
      env.QM_CORE_CONTAINER = `${ctx.prefix}-core`;
    } else {
      delete env.DOCKER_HOST;
      delete env.QM_CORE_CONTAINER;
    }
    if (config.services.includes("portal")) env.REQUIRE_SIGNED_PORTAL_IDENTITY = "1";
  }
  stripAwsContainerCredentialEnvironment(env);
  return env;
}

function secretEnvKeys(ctx: DockerCtx, service: string): Set<string> {
  const keys = new Set<string>();
  for (const secret of secretsForService(ctx.config, service)) {
    for (const name of runtimeSecretNames(service, secret)) keys.add(name);
  }
  if (ctx.signingSecret) keys.add("CORE_SIGNING_SECRET");
  if (service === "core") {
    keys.add("DATABASE_URL");
  }
  return keys;
}

function assertSecretEnvFileValues(entries: Record<string, string>): void {
  for (const [key, value] of Object.entries(entries)) {
    if (/[\r\n]/.test(value)) {
      throw new CliError(`secret ${key} contains a newline and cannot be serialized to docker --env-file`);
    }
  }
}

function writeSecretEnvFile(entries: Record<string, string>): { path: string; cleanup: () => void } {
  assertSecretEnvFileValues(entries);
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  const path = join(dir, "secrets.env");
  try {
    chmodSync(dir, 0o700);
    writeFileSync(
      path,
      `${Object.entries(entries)
        .map(([k, v]) => `${k}=${v}`)
        .join("\n")}\n`,
      { mode: 0o600 },
    );
    return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
}

function writeSecretFile(value: string): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "qm-secret-"));
  const path = join(dir, "value");
  try {
    chmodSync(dir, 0o700);
    writeFileSync(path, value, { mode: 0o444 });
    chmodSync(path, 0o444);
    return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
}

function pushEnvArgs(
  args: string[],
  env: Record<string, string>,
  secretKeys: Set<string>,
  selectedSecretValues: ReadonlySet<string>,
): { cleanup: () => void } {
  const secrets = new Map<string, string>();
  for (const [k, v] of Object.entries(env)) {
    if (secretKeys.has(k) || selectedSecretValues.has(v)) secrets.set(k, v);
    else args.push("-e", `${k}=${v}`);
  }
  const file = secrets.size ? writeSecretEnvFile(Object.fromEntries(secrets)) : undefined;
  if (file) args.push("--env-file", file.path);
  return { cleanup: file?.cleanup ?? (() => {}) };
}

function runArgs(
  ctx: DockerCtx,
  service: ServiceName,
  image: string,
): { args: string[]; cleanup: () => void; copy?: { path: string; destination: string } } {
  const def = serviceDef(service);
  const args = [
    "run",
    "-d",
    "--name",
    cname(ctx, service),
    ...orgLabelArgs(ctx),
    "--network",
    ctx.network,
    "--network-alias",
    service,
    "--network-alias",
    `${cname(ctx, service)}.internal`,
    "--restart",
    "no",
  ];
  const env = serviceEnv(ctx, service);
  const multilineCa =
    service === "core" && /[\r\n]/.test(env.DATABASE_CA_CERT ?? "") ? env.DATABASE_CA_CERT : undefined;
  if (multilineCa !== undefined) {
    delete env.DATABASE_CA_CERT;
    env.DATABASE_CA_CERT_FILE = DATABASE_CA_CERT_FILE;
  }
  const pushed = pushEnvArgs(args, env, secretEnvKeys(ctx, service), ctx.selectedSecretValues);
  let copied: { path: string; cleanup: () => void } | undefined;
  try {
    copied = multilineCa === undefined ? undefined : writeSecretFile(multilineCa);
    if (service === "core") {
      args.push("-v", `${ctx.prefix}-coredata:/data`);
      for (const m of layerMounts(ctx)) args.push("-v", m);
      for (const m of skillMounts(ctx)) args.push("-v", m);
      if (ctx.dockerSocket) {
        args.push("-v", `${ctx.dockerSocket.path}:/var/run/docker.sock`);
        if (ctx.dockerSocket.gid) args.push("--group-add", ctx.dockerSocket.gid);
      }
    }
    if (def.docker.hostPortOffset !== undefined) {
      args.push("-p", `${baseHostPort(ctx) + def.docker.hostPortOffset}:${def.docker.internalPort}`);
    }
    args.push(image);
    return {
      args,
      cleanup: () => {
        try {
          copied?.cleanup();
        } finally {
          pushed.cleanup();
        }
      },
      ...(copied ? { copy: { path: copied.path, destination: DATABASE_CA_CERT_FILE } } : {}),
    };
  } catch (error) {
    try {
      copied?.cleanup();
    } finally {
      pushed.cleanup();
    }
    throw error;
  }
}

function launchContainer(
  name: string,
  run: { args: string[]; copy?: { path: string; destination: string } },
  env: NodeJS.ProcessEnv,
): void {
  try {
    if (!run.copy) {
      docker(run.args, env);
      return;
    }
    const args = [...run.args];
    args[0] = "create";
    const detached = args.indexOf("-d");
    if (detached !== -1) args.splice(detached, 1);
    docker(args, env);
    docker(["cp", run.copy.path, `${name}:${run.copy.destination}`], env);
    docker(["start", name], env);
  } catch (error) {
    try {
      docker(["rm", "-f", name], env, /No such container|No such object|is not running/i);
    } catch (cleanupError) {
      throw new CliError(
        `container ${name} launch failed (${errMessage(error)}); cleanup also failed (${errMessage(cleanupError)})`,
      );
    }
    throw error;
  }
}

function skillMounts(ctx: DockerCtx): string[] {
  return ctx.config.skills.map((s, i) => `${resolve(ctx.configDir, s)}:/app/plugins/deployment-skills-${i}/skills:ro`);
}

function existingLayerSubdirs(ctx: DockerCtx): Array<"skills" | "tools"> {
  return (["skills", "tools"] as const).filter((s) => existsSync(join(ctx.sandboxDir, s)));
}

function layerMounts(ctx: DockerCtx): string[] {
  return existingLayerSubdirs(ctx).map((sub) => `${join(ctx.sandboxDir, sub)}:/layer/${sub}:ro`);
}

function noteLogTail(name: string, logs: string): void {
  note(`--- ${name} logs (tail) ---`);
  note(tailString(logs, 25));
}

async function waitReady(ctx: DockerCtx, service: ServiceName): Promise<void> {
  const def = serviceDef(service);
  const name = cname(ctx, service);
  for (let i = 0; i < 90; i++) {
    const logs = captureBoth("docker", ["logs", name], { env: ctx.processEnv });
    if (def.readiness.test(logs)) {
      persistRestart(name, ctx.processEnv);
      return;
    }
    if (!containerRunning(name, ctx.processEnv)) {
      noteLogTail(name, logs);
      throw new CliError(`${service} exited before becoming ready (see logs above)`);
    }
    await sleep(1000);
  }
  throw new CliError(`${service} did not become ready in 90s`);
}

async function waitPluginUp(name: string, env: NodeJS.ProcessEnv): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await sleep(1000);
    if (!containerRunning(name, env)) {
      noteLogTail(name, captureBoth("docker", ["logs", name], { env }));
      throw new CliError(`plugin ${name} exited on boot (see logs above) — check the image and its env`);
    }
  }
  persistRestart(name, env);
}

function buildCtx(
  config: QmConfig,
  source: DockerEnvironmentSource,
  opts: {
    sandboxDir?: string;
    buildFrom: boolean;
    localSandboxImage?: string;
  },
): DockerCtx {
  const { configDir } = source;
  const prefix = dockerPrefix(config);
  const snapshot = dockerEnvironmentSnapshot(source);
  const dockerEnvironment = dockerProcessEnvironment(config, snapshot.fileValues);
  const ctx: DockerCtx = {
    config,
    configDir,
    sandboxDir: resolve(opts.sandboxDir ?? join(configDir, "sandbox")),
    network: prefix,
    prefix,
    databaseUrl: "",
    ambientEnv: dockerEnvironment.ambientEnv,
    fileValues: snapshot.fileValues,
    sandboxEnv: {},
    buildFrom: opts.buildFrom,
    processEnv: dockerEnvironment.env,
    selectedSecrets: dockerEnvironment.selectedSecrets,
    selectedSecretValues: dockerEnvironment.selectedSecretValues,
    ...(snapshot.envFile !== undefined ? { envFile: snapshot.envFile } : {}),
  };
  const signingSecret = ctx.selectedSecrets.get("CORE_SIGNING_SECRET");
  if (signingSecret) ctx.signingSecret = signingSecret;
  const sb = sandboxCoreEnv(config);
  ctx.sandboxEnv = {
    ...sb.env,
    ...(opts.localSandboxImage ? { LOCAL_SANDBOX_IMAGE: opts.localSandboxImage } : {}),
  };
  return ctx;
}

function captureSourceBuildEnvironment(ctx: DockerCtx): void {
  ctx.sourceBuildEnv = sourceBuildEnvironment(ctx.processEnv, {
    sensitiveNames: [...ctx.selectedSecrets.keys(), DATABASE_CA_CERT_ENV, "POSTGRES_PASSWORD"],
    sensitiveValues: ctx.selectedSecretValues,
  });
}

function assertDockerReservedEnvironment(ctx: DockerCtx): void {
  const configured = {
    ...virtualServiceEnv(ctx.config.services, ctx.config.env),
    ...ctx.config.env.core,
  };
  const secretCollision = secretsForService(ctx.config, "core").some((secret) =>
    runtimeSecretNames("core", secret).includes(DATABASE_CA_CERT_ENV),
  );
  if (Object.hasOwn(configured, DATABASE_CA_CERT_ENV) || secretCollision) {
    throw new CliError(`${DATABASE_CA_CERT_ENV} is reserved for Docker database CA delivery`);
  }
}

function warnUnforwardedEnvKeys(ctx: DockerCtx): void {
  if (!ctx.envFile) return;
  const injected = new Set(computedSecrets(ctx.config).map((secret) => secret.name));
  injected.add("CORE_SIGNING_SECRET");
  injected.add("DATABASE_URL");
  const dropped = [...ctx.fileValues.keys()].filter((key) => !injected.has(key));
  if (!dropped.length) return;
  warn(
    `.env keys not forwarded to any container: ${dropped.join(", ")} — only computed secret names are ` +
      `injected. Move non-secret settings to "env.<service>" in the QM deployment config.`,
  );
}

function missingRequiredOperatorSecrets(ctx: DockerCtx): string[] {
  const lookup = (name: string): string | undefined => ctx.selectedSecrets.get(name);
  return computedSecrets(ctx.config)
    .filter(
      (secret) =>
        secret.required && secret.managedBy === "operator" && isInvalidSecret(secret.name, lookup(secret.name)),
    )
    .map((secret) => secret.name);
}

function assertExplicitFileOnlySecrets(ctx: DockerCtx): void {
  if (ctx.ambientEnv.QM_DEPLOY_ENV_FILE_ONLY !== "1") return;
  const names = new Set([...computedSecrets(ctx.config).map((secret) => secret.name), "DATABASE_URL"]);
  const ambientOnly = [...names].filter((name) => {
    const fileValue = ctx.fileValues.get(name);
    return (!fileValue || fileValue.trim() === "") && (ctx.ambientEnv[name]?.trim() ?? "") !== "";
  });
  if (ambientOnly.length) {
    throw new CliError(
      `automatic Docker update will not use ambient-only deployment secrets (${ambientOnly.join(", ")}); add them to the explicit deployment env file`,
    );
  }
}

function assertDockerSelectedSecrets(ctx: DockerCtx, dryRun: boolean): void {
  const values = new Map<string, string>();
  const databaseUrl = externalDatabaseUrl(ctx);
  if (databaseUrl) {
    if (/[\r\n]/.test(databaseUrl)) {
      throw new CliError("DATABASE_URL cannot contain CR or LF for Docker deployment");
    }
    if (isInvalidSecret("DATABASE_URL", databaseUrl)) {
      throw new CliError(
        "Docker deployment secrets are missing, placeholders, malformed, too short, or not distinct: DATABASE_URL",
      );
    }
  }
  for (const secret of computedSecrets(ctx.config)) {
    const value = ctx.selectedSecrets.get(secret.name);
    if (
      value !== undefined &&
      /[\r\n]/.test(value) &&
      !(
        secret.name === "DATABASE_CA_CERT" &&
        secret.services.length === 1 &&
        secret.services[0] === "core" &&
        !secret.aliases?.length
      )
    ) {
      throw new CliError(`${secret.name} cannot contain CR or LF for Docker deployment`);
    }
    if (value !== undefined) values.set(secret.name, value);
  }
  try {
    if (dryRun) {
      materializeSecretValues(ctx.config, values, { completeness: "partial", managedBy: "operator" });
    } else {
      validateCompleteSecretValues(ctx.config, values);
    }
  } catch (error) {
    throw new CliError(
      `Docker deployment secrets are missing, placeholders, malformed, too short, or not distinct: ${errMessage(error)}`,
    );
  }
}

export async function dockerUp(
  config: QmConfig,
  source: DockerEnvironmentSource,
  opts: { sandboxDir?: string; buildFrom?: boolean; buildFromPath?: string; dryRun?: boolean } = {},
): Promise<void> {
  const { configDir } = source;
  const resolvedLocalImage = localSandboxActive(config) ? localSandboxImage(config) : undefined;
  const ctx = buildCtx(config, source, {
    sandboxDir: opts.sandboxDir,
    buildFrom: opts.buildFrom ?? false,
    ...(resolvedLocalImage ? { localSandboxImage: resolvedLocalImage } : {}),
  });
  assertExplicitFileOnlySecrets(ctx);
  const plugins = discoverPlugins(configDir, config).plugins;
  assertDockerSelectedSecrets(ctx, opts.dryRun ?? false);
  assertDockerReservedEnvironment(ctx);
  if (!opts.dryRun) {
    const dockerSocket = hostDockerSocket(ctx.processEnv, ctx.selectedSecretValues);
    if (localSandboxActive(config)) ctx.dockerSocket = dockerSocket;
  }
  captureSourceBuildEnvironment(ctx);
  if (ctx.buildFrom) {
    ctx.repoRoot = resolveBuildRepoRoot(opts.buildFromPath, runnableServices(config.services), ctx.sourceBuildEnv);
  }
  if (!opts.dryRun) requireDocker(ctx.processEnv);

  header(`qm up — ${config.orgId} (target: docker${opts.buildFrom ? ", build-from-source" : ""})`);
  if (opts.dryRun) note(bold("DRY RUN — no containers will be started.\n"));
  warnUnforwardedEnvKeys(ctx);
  const missingRequired = missingRequiredOperatorSecrets(ctx);
  if (opts.dryRun && missingRequired.length) {
    warn(`MISSING required secrets — add them to .env before up: ${missingRequired.join(", ")}`);
  }

  if (opts.dryRun) {
    ctx.databaseUrl = ensurePostgres(ctx, true);
    step(`network: ${ctx.network}`);
    if (resolvedLocalImage) step(`sandbox: local image ${resolvedLocalImage}`);
    for (const def of ordered(runnableServices(config.services))) {
      const ports =
        def.docker.hostPortOffset !== undefined ? ` (host :${baseHostPort(ctx) + def.docker.hostPortOffset})` : "";
      step(
        `${def.name}: image ${ctx.buildFrom ? `build deploy/${def.name}/Dockerfile` : imageRef(ctx, def.name)}${ports}`,
      );
      note(`     env: ${Object.keys(serviceEnv(ctx, def.name)).join(", ") || "(none)"}`);
      if (def.name === "core") {
        const subs = existingLayerSubdirs(ctx);
        note(
          `     layer: ${subs.length ? `${ctx.sandboxDir} → /layer (${subs.join(", ")})` : `(no skills/ or tools/ in ${ctx.sandboxDir})`}`,
        );
      }
    }
    for (const p of plugins) {
      step(
        p.kind === "image"
          ? `plugin ${p.name}: pull ${p.image}`
          : `plugin ${p.name}: build plugins/${p.name}/Dockerfile`,
      );
    }
    note("\n" + bold("Plan only. Re-run without --dry-run to apply."));
    return;
  }

  if (missingRequired.length) {
    throw new CliError(
      `required secrets have no value in ./.env or the environment: ${missingRequired.join(", ")}\n` +
        `Add them to .env (see .env.example; generate signing secrets with: openssl rand -hex 32).`,
    );
  }

  if (localSandboxActive(config)) ensureLocalSandboxImage(config, ctx.sourceBuildEnv!);
  ensureNetwork(ctx);
  ctx.databaseUrl = ensurePostgres(ctx, false);
  if (!externalDatabaseUrl(ctx)) await waitPostgres(ctx);

  for (const def of ordered(runnableServices(config.services))) {
    const image = resolveImage(ctx, def.name);
    docker(["rm", "-f", cname(ctx, def.name)], ctx.processEnv, /No such container|is not running/);
    step(`starting ${def.name}`);
    const run = runArgs(ctx, def.name, image);
    try {
      launchContainer(cname(ctx, def.name), run, ctx.processEnv);
    } finally {
      run.cleanup();
    }
    await waitReady(ctx, def.name);
    ok(`${def.name} ready`);
  }

  for (const p of plugins) {
    const image = resolvePluginImage(ctx, p);
    docker(["rm", "-f", cname(ctx, p.name)], ctx.processEnv, /No such container|is not running/);
    step(`starting plugin ${p.name} (${image})`);
    const args = [
      "run",
      "-d",
      "--name",
      cname(ctx, p.name),
      ...orgLabelArgs(ctx),
      "--network",
      ctx.network,
      "--network-alias",
      p.name,
      "--restart",
      "no",
    ];
    const wiring = {
      CORE_API_URL: "http://core:8080",
      ...orgEnv(p.name, config.orgId, config.publicUrl, config.services.includes("portal"), brandEnvOf(config)),
      PORT: "8080",
    };
    const selectedSecrets: Record<string, string> = {
      ...(ctx.signingSecret ? { CORE_SIGNING_SECRET: ctx.signingSecret } : {}),
      ...secretValues(ctx, p.name),
    };
    const env: Record<string, string> = {
      ...wiring,
      ...p.env,
      ...selectedSecrets,
    };
    for (const key of secretEnvKeys(ctx, p.name)) {
      if (!Object.hasOwn(selectedSecrets, key)) delete env[key];
    }
    env.NODE_ENV = "production";
    stripAwsContainerCredentialEnvironment(env);
    const pushed = pushEnvArgs(args, env, secretEnvKeys(ctx, p.name), ctx.selectedSecretValues);
    args.push(image);
    try {
      launchContainer(cname(ctx, p.name), { args }, ctx.processEnv);
    } finally {
      pushed.cleanup();
    }
    await waitPluginUp(cname(ctx, p.name), ctx.processEnv);
    ok(`plugin ${p.name} running`);
  }

  printUrls(ctx);
}

function printUrls(ctx: DockerCtx): void {
  note("");
  ok(`stack up — ${ctx.config.orgId}`);
  const has = (s: ServiceName): boolean => ctx.config.services.includes(s);
  const url = (s: ServiceName): string =>
    `http://localhost:${baseHostPort(ctx) + serviceDef(s).docker.hostPortOffset!}`;
  if (has("portal")) note(`   portal : ${url("portal")}  (public front door)`);
  if (has("auth"))
    note(`   auth   : ${url("portal")}/idp/authorize  (sign-in broker, published only through the portal)`);
  if (has("web-ui")) note(`   web-ui : ${url("web-ui")}`);
  if (has("admin")) note(`   admin  : ${url("admin")}/admin`);
  note(`   core   : ${url("core")}`);
  note(`   status : qm status   ·   logs: qm logs core   ·   stop: qm down`);
}

export function dockerStatus(config: QmConfig, source: DockerEnvironmentSource): void {
  const snapshot = dockerEnvironmentSnapshot(source);
  const { env, selectedSecretValues } = dockerProcessEnvironment(config, snapshot.fileValues);
  hostDockerSocket(env, selectedSecretValues);
  requireDocker(env);
  header(`qm status — ${config.orgId}`);
  dockerInherit(
    [
      "ps",
      "-a",
      "--filter",
      `label=${ORG_LABEL_KEY}=${config.orgId}`,
      "--format",
      "table {{.Names}}\t{{.Status}}\t{{.Ports}}",
    ],
    env,
  );
  if (config.services.includes("slack")) note("slack: virtual service running in the core container");
}

function psNames(args: string[], env: NodeJS.ProcessEnv): string[] {
  return docker(["ps", ...args, "--format", "{{.Names}}"], env)
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

function listDeploymentContainers(orgId: string, env: NodeJS.ProcessEnv): string[] {
  return psNames(["-a", "--filter", `label=${ORG_LABEL_KEY}=${orgId}`], env);
}

export async function dockerLogs(
  config: QmConfig,
  source: DockerEnvironmentSource,
  service: string | undefined,
  opts: LogOpts = {},
): Promise<void> {
  const snapshot = dockerEnvironmentSnapshot(source);
  const { env, selectedSecretValues } = dockerProcessEnvironment(config, snapshot.fileValues);
  hostDockerSocket(env, selectedSecretValues);
  requireDocker(env);
  const prefix = dockerPrefix(config);
  const tail = String(opts.tail ?? 200);

  if (service) {
    const resolved = service === "slack" ? "core" : service;
    if (service === "slack") note("slack is a virtual service; showing core logs");
    const name = `${prefix}-${resolved}`;
    if (!containerExists(name, env))
      die(`no container ${name} (is the stack up? services: ${config.services.join(", ")})`);
    const args = ["logs", "--tail", tail];
    if (opts.follow) args.push("-f");
    args.push(name);
    dockerInherit(args, env);
    return;
  }

  const names = listDeploymentContainers(config.orgId, env);
  if (names.length === 0) die(`no containers for ${config.orgId} (is the stack up? run \`qm up\`)`);
  await streamPrefixedLogs(names, prefix, { follow: opts.follow ?? false, tail }, env);
}

function streamPrefixedLogs(
  names: string[],
  prefix: string,
  opts: { follow: boolean; tail: string },
  env: NodeJS.ProcessEnv,
): Promise<void> {
  return streamLabeled(
    names.map((name) => ({
      label: name.slice(prefix.length + 1),
      command: "docker",
      args: ["logs", "--tail", opts.tail, ...(opts.follow ? ["-f"] : []), name],
      env,
    })),
    (label, line) => note(`${dim(label)} | ${line}`),
  );
}

export async function dockerDown(
  config: QmConfig,
  source: DockerEnvironmentSource,
  opts: { purge?: boolean } = {},
): Promise<void> {
  const snapshot = dockerEnvironmentSnapshot(source);
  const { env, selectedSecretValues } = dockerProcessEnvironment(config, snapshot.fileValues);
  hostDockerSocket(env, selectedSecretValues);
  requireDocker(env);
  const prefix = dockerPrefix(config);
  header(`qm down — ${config.orgId}`);
  const serviceNames = teardownOrdered(runnableServices(config.services)).map((d) => `${prefix}-${d.name}`);
  const pgName = `${prefix}-pg`;
  const known = new Set([...serviceNames, pgName]);
  const pluginNames = [
    ...new Set([
      ...config.plugins.map((p) => `${prefix}-${p.name}`),
      ...listDeploymentContainers(config.orgId, env).filter((n) => !known.has(n)),
    ]),
  ];
  const candidates = [...pluginNames, ...serviceNames, pgName];
  const present = new Set(psNames(["-a"], env));
  for (const name of candidates) {
    if (!present.has(name)) continue;
    step(`removing ${name}`);
    docker(["rm", "-f", name], env, /No such container/);
  }
  if (opts.purge) {
    warn("purging the network and Postgres volume (durable data will be lost)");
    docker(["network", "rm", prefix], env, /not found|No such/);
    docker(["volume", "rm", `${prefix}-pgdata`, `${prefix}-coredata`], env, /No such volume|not found|in use/);
  }
  ok("down.");
}
