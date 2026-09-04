import { CliError } from "./log.ts";

export interface BuildxInvocation {
  command: string;
  args: string[];
  env: NodeJS.ProcessEnv;
}

export interface SourceBuildEnvironmentOptions {
  sensitiveNames: Iterable<string>;
  sensitiveValues: Iterable<string | undefined>;
}

const SOURCE_BUILD_ENVIRONMENT_NAMES = new Set([
  "ALL_PROXY",
  "BUILDKIT_COLORS",
  "BUILDKIT_HOST",
  "BUILDKIT_PROGRESS",
  "BUILDX_BUILDER",
  "BUILDX_CONFIG",
  "BUILDX_EXPERIMENTAL",
  "CURL_CA_BUNDLE",
  "DOCKER_API_VERSION",
  "DOCKER_AUTH_CONFIG",
  "DOCKER_BUILDKIT",
  "DOCKER_BUILDX_BIN",
  "DOCKER_CERT_PATH",
  "DOCKER_CLI_EXPERIMENTAL",
  "DOCKER_CLI_PLUGIN_EXTRA_DIRS",
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
  "EXPERIMENTAL_BUILDKIT_SOURCE_POLICY",
  "HOME",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "KUBECONFIG",
  "LANG",
  "LANGUAGE",
  "LC_ADDRESS",
  "LC_ALL",
  "LC_COLLATE",
  "LC_CTYPE",
  "LC_IDENTIFICATION",
  "LC_MEASUREMENT",
  "LC_MESSAGES",
  "LC_MONETARY",
  "LC_NAME",
  "LC_NUMERIC",
  "LC_PAPER",
  "LC_TELEPHONE",
  "LC_TIME",
  "LOGNAME",
  "NODE_EXTRA_CA_CERTS",
  "NO_PROXY",
  "PATH",
  "REQUESTS_CA_BUNDLE",
  "SSH_AUTH_SOCK",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "TEMP",
  "TMP",
  "TMPDIR",
  "USER",
  "XDG_CONFIG_HOME",
  "all_proxy",
  "http_proxy",
  "https_proxy",
  "no_proxy",
]);

function sourceBuildEnvironmentName(name: string): boolean {
  return SOURCE_BUILD_ENVIRONMENT_NAMES.has(name);
}

export function sourceBuildEnvironment(
  baseEnv: Readonly<NodeJS.ProcessEnv>,
  options: SourceBuildEnvironmentOptions,
): NodeJS.ProcessEnv {
  const sensitiveNames = new Set(options.sensitiveNames);
  const sensitiveValues = new Set(
    [...options.sensitiveValues].filter((value): value is string => value !== undefined && value.trim() !== ""),
  );
  const env = Object.create(null) as NodeJS.ProcessEnv;
  for (const [name, value] of Object.entries(baseEnv)) {
    if (value === undefined || !sourceBuildEnvironmentName(name)) continue;
    const effectiveValue = name === "DOCKER_BUILDX_BIN" ? value.trim() : value;
    if (name === "DOCKER_BUILDX_BIN" && !effectiveValue) continue;
    if (sensitiveNames.has(name) || sensitiveValues.has(value) || sensitiveValues.has(effectiveValue)) {
      throw new CliError(`source-build provider control ${name} conflicts with a deployment secret`);
    }
    env[name] = effectiveValue;
  }
  if (
    sensitiveNames.has("BUILDX_GIT_INFO") ||
    sensitiveNames.has("BUILDX_GIT_LABELS") ||
    sensitiveValues.has("false")
  ) {
    throw new CliError("source-build metadata controls conflict with a deployment secret");
  }
  env.BUILDX_GIT_INFO = "false";
  env.BUILDX_GIT_LABELS = "false";
  return env;
}

export function buildxInvocation(
  args: string[],
  baseEnv: NodeJS.ProcessEnv,
  dockerFallback?: string[],
): BuildxInvocation {
  const env = Object.assign(Object.create(null) as NodeJS.ProcessEnv, baseEnv);
  const command = Object.hasOwn(env, "DOCKER_BUILDX_BIN") ? env.DOCKER_BUILDX_BIN : undefined;
  return command ? { command, args, env } : { command: "docker", args: dockerFallback ?? ["buildx", ...args], env };
}
