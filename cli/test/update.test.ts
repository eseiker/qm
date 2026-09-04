import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { compareVersions, runUpdate } from "../src/commands/update.ts";
import { updateConfigCoreEnv, type QmConfig } from "../src/config.ts";
import { cliPackageName } from "../src/manifest.ts";
import type { Target } from "../src/providers.ts";

const PACKAGE_NAME = cliPackageName();
const CURRENT = "0.1.6";
const LATEST = "0.1.7";
const COMMIT = "a".repeat(40);
const INTEGRITY_BYTES = Buffer.alloc(64, 0xcd);
const INTEGRITY = `sha512-${INTEGRITY_BYTES.toString("base64")}`;
const INTEGRITY_HEX = INTEGRITY_BYTES.toString("hex");
const OTHER_INTEGRITY = `sha512-${Buffer.alloc(64, 0xab).toString("base64")}`;
const REGISTRY = "https://registry.npmjs.org/";
const REPOSITORY = "https://github.com/yc-software/qm";
const REPOSITORY_ID = "1316527318";
const REPOSITORY_OWNER_ID = "153323858";
const RUN_ID = "987654321";
const INVOCATION = `${REPOSITORY}/actions/runs/${RUN_ID}/attempts/2`;
const SANDBOX_BASE = `ghcr.io/yc-software/qm/sandbox-base@sha256:${"c".repeat(64)}`;
const DARWIN_ALLOW_DIRECTORY_ACL =
  "everyone allow list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit";
const DARWIN_DENY_DELETE_ACL = "everyone deny delete";
const MANIFEST = {
  sandboxBase: SANDBOX_BASE,
  services: {
    admin: `ghcr.io/yc-software/qm/admin@sha256:${"1".repeat(64)}`,
    auth: `ghcr.io/yc-software/qm/auth@sha256:${"2".repeat(64)}`,
    core: `ghcr.io/yc-software/qm/core@sha256:${"e".repeat(64)}`,
    "egress-proxy": `ghcr.io/yc-software/qm/egress-proxy@sha256:${"3".repeat(64)}`,
    portal: `ghcr.io/yc-software/qm/portal@sha256:${"4".repeat(64)}`,
    "web-ui": `ghcr.io/yc-software/qm/web-ui@sha256:${"5".repeat(64)}`,
  },
};

interface FakeState {
  deploymentDir: string;
  version: string;
  tarball: string;
  integrity: string;
  manifest: Record<string, unknown>;
  audit: Record<string, unknown>;
  failInstall?: boolean;
  failMutation?: boolean;
  failAudit?: boolean;
  targetExit?: number;
  packagePatch?: Record<string, unknown>;
  lockPatch?: Record<string, unknown>;
  failIdentity?: boolean;
  tamperMutationTree?: boolean;
  targetMutation?: "config" | "package";
  configPath: string;
  npmPrefix?: string;
  npmRoot?: string;
  mutationPackagePatch?: Record<string, unknown>;
  deleteLockRecord?: string;
  omitHiddenLockRecord?: string;
  waitForSignal?: boolean;
  signalAtStart?: boolean;
  signalReady?: string;
  signalLog?: string;
  signalPid?: string;
  hardlinkMutationPath?: string;
  targetConfigBody?: string;
  targetConfigHardlinkPath?: string;
  targetConfigMode?: number;
  targetProbeBins?: string[];
  targetGitDir?: string;
  targetGitConfigDir?: string;
  targetGitConfigLog?: string;
  targetExecutableMutationPath?: string;
  targetExecutableMutationTarget?: string;
  targetAbsentInputMutationPath?: string;
  targetAwsCacheDirectory?: string;
  targetSandboxMutationPath?: string;
  targetEnvironmentMutationPath?: string;
  targetDockerAuth?: boolean;
  requireAbsentSandbox?: boolean;
  targetSignalAtStart?: boolean;
  signalHeartbeat?: boolean;
  forwardedSignal?: "SIGTERM" | "SIGQUIT";
}

interface NpmCall {
  args: string[];
  cwd: string;
  configs: Record<string, string>;
  npmConfigEnv: string[];
  verifierPackage?: Record<string, unknown>;
  execPath: string;
  stateRootMode?: number;
  transactionMode?: number;
  home?: string;
  tmpdir?: string;
  nodeOptions?: string;
  path?: string;
}

interface TargetCall {
  args: string[];
  cwd: string;
  entry: string;
  path?: string;
  awsBin?: string;
  flyBin?: string;
  dockerBuildxBin?: string;
  dockerPluginDirs?: string;
  dockerHooks?: string;
  dockerHints?: string;
  dockerConfig?: string;
  dockerConfigBody?: string;
  dockerContexts?: boolean;
  buildxConfig?: string;
  dockerHost?: string;
  dockerContext?: string;
  buildxBuilder?: string;
  buildkitHost?: string;
  kubeconfig?: string;
  home?: string;
  awsConfig?: string;
  awsConfigBody?: string;
  awsCredentials?: string;
  awsCredentialsBody?: string;
  awsAlias?: boolean;
  awsPager?: string;
  awsAutoPrompt?: string;
  awsDataPath?: string;
  botocorePlugins?: string;
  awsSsoCache?: string;
  buildxGitInfo?: string;
  buildxGitLabels?: string;
  gitConfigCount?: string;
  gitConfigKey?: string;
  gitConfigValue?: string;
  nixLd?: string;
  nixLdArch?: string;
  nixLdLibraryPath?: string;
  nixLdLibraryPathArch?: string;
  nixLdLog?: string;
  nixLdFlags?: string;
  deploymentEnvBody?: string;
  deployEnvFileOnly?: string;
  futureDeploymentSecret?: string;
  coreSigningSecret?: string;
  awsSecretAccessKey?: string;
  awsProfile?: string;
  botoConfig?: string;
  googleCredentials?: string;
  vaultAddress?: string;
  awsHistoryFile?: string;
  nodeOptions?: string;
  bashEnvironment?: string;
  bashFunction?: string;
  pythonPath?: string;
  ldPreload?: string;
  dyldInsertLibraries?: string;
  opensslConfig?: string;
  gconvPath?: string;
  sslKeyLogFile?: string;
  flyHar?: string;
  buildkitSourcePolicy?: string;
}

interface RemoteState {
  metadata: Record<string, unknown>;
}

interface Fixture {
  dir: string;
  config: QmConfig;
  configPath: string;
  sandboxDir: string;
  npmLog: string;
  npmPath: string;
  targetBin: string;
  sigstoreLog: string;
  targetLog: string;
  statePath: string;
  fetcher: typeof fetch;
  remote: RemoteState;
  previousEnv: Record<string, string | undefined>;
}

function repository(): Record<string, string> {
  return {
    type: "git",
    url: "git+https://github.com/yc-software/qm.git",
    directory: "cli",
  };
}

function tarball(version: string): string {
  return `${REGISTRY}@yc-software/qm/-/qm-${version}.tgz`;
}

function attestationUrl(version: string): string {
  return `${REGISTRY}-/npm/v1/attestations/@yc-software%2fqm@${version}`;
}

function metadata(version: string): Record<string, unknown> {
  return {
    name: PACKAGE_NAME,
    version,
    dependencies: {},
    repository: repository(),
    gitHead: COMMIT,
    dist: {
      tarball: tarball(version),
      integrity: INTEGRITY,
      attestations: {
        url: attestationUrl(version),
        provenance: { predicateType: "https://slsa.dev/provenance/v1" },
      },
    },
  };
}

function statement(version: string, workflowPath = ".github/workflows/release.yml"): Record<string, unknown> {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {
        name: `pkg:npm/%40yc-software/qm@${version}`,
        digest: { sha512: INTEGRITY_HEX },
      },
    ],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
        externalParameters: {
          workflow: {
            ref: "refs/heads/main",
            repository: REPOSITORY,
            path: workflowPath,
          },
        },
        internalParameters: {
          github: {
            event_name: "workflow_dispatch",
            repository_id: REPOSITORY_ID,
            repository_owner_id: REPOSITORY_OWNER_ID,
          },
        },
        resolvedDependencies: [
          {
            uri: `git+${REPOSITORY}@refs/heads/main`,
            digest: { gitCommit: COMMIT },
          },
        ],
      },
      runDetails: {
        builder: { id: "https://github.com/actions/runner/github-hosted" },
        metadata: { invocationId: INVOCATION },
      },
    },
  };
}

function audit(
  version: string,
  workflowPath?: string,
  certificatePatch: Record<string, string> = {},
): Record<string, unknown> {
  const payload = Buffer.from(JSON.stringify(statement(version, workflowPath)), "utf8").toString("base64");
  return {
    invalid: [],
    missing: [],
    verified: [
      {
        name: PACKAGE_NAME,
        version,
        location: `node_modules/${PACKAGE_NAME}`,
        registry: REGISTRY.replace(/\/+$/, ""),
        attestations: {
          url: attestationUrl(version),
          provenance: { predicateType: "https://slsa.dev/provenance/v1" },
        },
        attestationBundles: [
          {
            predicateType: "https://slsa.dev/provenance/v1",
            bundle: {
              verificationMaterial: {
                certificate: {
                  rawBytes: Buffer.from(
                    JSON.stringify({
                      "1.3.6.1.4.1.57264.1.11": "github-hosted",
                      "1.3.6.1.4.1.57264.1.12": REPOSITORY,
                      "1.3.6.1.4.1.57264.1.13": COMMIT,
                      "1.3.6.1.4.1.57264.1.14": "refs/heads/main",
                      "1.3.6.1.4.1.57264.1.15": REPOSITORY_ID,
                      "1.3.6.1.4.1.57264.1.16": "https://github.com/yc-software",
                      "1.3.6.1.4.1.57264.1.17": REPOSITORY_OWNER_ID,
                      "1.3.6.1.4.1.57264.1.18": `${REPOSITORY}/.github/workflows/release.yml@refs/heads/main`,
                      "1.3.6.1.4.1.57264.1.19": COMMIT,
                      "1.3.6.1.4.1.57264.1.20": "workflow_dispatch",
                      "1.3.6.1.4.1.57264.1.22": "public",
                      ...certificatePatch,
                    }),
                  ).toString("base64"),
                },
              },
              dsseEnvelope: {
                payloadType: "application/vnd.in-toto+json",
                payload,
              },
            },
          },
        ],
      },
    ],
  };
}

function remoteState(version: string): RemoteState {
  return { metadata: metadata(version) };
}

function requestUrl(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

function configFor(target: Target): QmConfig {
  const common: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.com",
    target,
    services: ["core"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  if (target === "docker") return { ...common, sandbox: { backend: "local" } };
  if (target === "fly") {
    return {
      ...common,
      region: "iad",
      flyOrg: "acme",
      env: {
        core: {
          SNAPSHOT_STORE: "s3",
          TRANSFER_STORE: "s3",
          S3_BUCKET: "acme-qm",
          S3_REGION: "us-east-1",
        },
      },
      sandbox: {
        backend: "sprites",
        app: "acme-sandboxes",
      },
    };
  }
  if (target === "aws") {
    return {
      ...common,
      env: { core: { AWS_DEPLOY_IMAGE: "acme-qm-sandbox" } },
      sandbox: {
        backend: "sprites",
        app: "acme-sandboxes",
      },
      aws: {
        accountId: "123456789012",
        region: "us-east-1",
        cluster: "acme-qm",
        deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
        secretsPrefix: "acme/qm/",
        imageLabel: "latest",
        networking: { cloudMapNamespace: "acme.internal" },
        services: { core: { ecrRepository: "core", ecsService: "core", cpu: 256, memory: 512 } },
      },
    };
  }
  return {
    ...common,
    sandbox: {
      backend: "sprites",
      app: "acme-sandboxes",
    },
  };
}

function fakeNpmBody(): string {
  return `#!/usr/bin/env node
import { spawn } from "node:child_process";
import { appendFileSync, chmodSync, linkSync, lstatSync, mkdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
const args = process.argv.slice(2);
const state = JSON.parse(readFileSync(process.env.UPDATE_STATE, "utf8"));
if (state.signalAtStart) {
  const forwardedSignal = state.forwardedSignal ?? "SIGTERM";
  process.on(forwardedSignal, () => {
    appendFileSync(state.signalLog, "signal\\n");
    setTimeout(() => {
      appendFileSync(state.signalLog, "done\\n");
      process.exit(0);
    }, 200);
  });
  writeFileSync(state.signalLog, "installed\\n");
  writeFileSync(state.signalReady, "ready\\n");
  if (state.signalPid) writeFileSync(state.signalPid, String(process.pid));
  setImmediate(() => process.kill(process.ppid, forwardedSignal));
  setInterval(() => {}, 1000);
  await new Promise(() => {});
}
const verifier = basename(process.cwd()) === "verifier";
const projection = basename(process.cwd()) === "project-check";
if (!verifier && !projection && realpathSync(process.cwd()) !== state.deploymentDir) process.exit(97);
const has = (path) => { try { lstatSync(path); return true; } catch (error) { if (error.code === "ENOENT") return false; throw error; } };
const configs = {};
for (const arg of args) {
  const match = /^--(userconfig|globalconfig)=(.+)$/.exec(arg);
  if (match) configs[match[1]] = readFileSync(match[2], "utf8");
}
const call = {
  args,
  cwd: process.cwd(),
  configs,
  execPath: process.execPath,
  npmConfigEnv: Object.keys(process.env).filter((name) => name.toLowerCase().startsWith("npm_config_")).sort(),
  stateRootMode: verifier ? statSync(dirname(dirname(process.cwd()))).mode & 0o7777 : undefined,
  transactionMode: verifier ? statSync(dirname(process.cwd())).mode & 0o7777 : undefined,
  home: process.env.HOME,
  tmpdir: process.env.TMPDIR,
  nodeOptions: process.env.NODE_OPTIONS,
  path: process.env.PATH,
};
try {
  call.verifierPackage = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8"));
} catch {}
appendFileSync(process.env.UPDATE_NPM_LOG, JSON.stringify(call) + "\\n");
if (args[0] === "install" && args.includes("--package-lock-only=true")) {
  const packagePath = join(process.cwd(), "package.json");
  const lockPath = join(process.cwd(), "package-lock.json");
  const pkg = JSON.parse(readFileSync(packagePath, "utf8"));
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  const root = lock.packages[""];
  for (const field of ["name", "version", "license", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta", "bin", "engines", "os", "cpu", "libc"]) {
    if (pkg[field] === undefined) delete root[field];
    else root[field] = structuredClone(pkg[field]);
  }
  writeFileSync(lockPath, JSON.stringify(lock, null, 2) + "\\n");
  process.exit(0);
}
if (args[0] === "prefix") {
  process.stdout.write((state.npmPrefix ?? process.cwd()) + "\\n");
  process.exit(0);
}
if (args[0] === "root") {
  process.stdout.write((state.npmRoot ?? join(process.cwd(), "node_modules")) + "\\n");
  process.exit(0);
}
if (args[0] === "install") {
  if (verifier && state.waitForSignal) {
    const program = ${JSON.stringify(
      'const { appendFileSync, writeFileSync } = require("node:fs"); const [log, ready, signal, heartbeat] = process.argv.slice(1); process.on(signal, () => { appendFileSync(log, "signal\\n"); setTimeout(() => { appendFileSync(log, "done\\n"); process.exit(0); }, 200); }); writeFileSync(ready, "ready\\n"); setInterval(() => { if (heartbeat === "true") appendFileSync(log, "tick\\n"); }, 50);',
    )};
    if (state.signalPid) writeFileSync(state.signalPid, String(process.pid));
    spawn(process.execPath, ["-e", program, state.signalLog, state.signalReady, state.forwardedSignal ?? "SIGTERM", String(state.signalHeartbeat === true)], { stdio: "ignore" });
    setInterval(() => {}, 1000);
  }
  if (!verifier && state.targetExecutableMutationPath && state.targetExecutableMutationTarget) {
    rmSync(state.targetExecutableMutationPath, { force: true });
    symlinkSync(state.targetExecutableMutationTarget, state.targetExecutableMutationPath);
  }
  if (!verifier && state.targetAbsentInputMutationPath) writeFileSync(state.targetAbsentInputMutationPath, "created\\n");
  if ((verifier && state.failInstall) || (!verifier && state.failMutation)) process.exit(31);
  const packageDir = join(process.cwd(), "node_modules", "@yc-software", "qm");
  if (has(packageDir)) rmSync(packageDir, { recursive: true, force: true });
  mkdirSync(join(packageDir, "dist", "bin"), { recursive: true });
  mkdirSync(join(packageDir, "dist", "src"), { recursive: true });
  mkdirSync(join(packageDir, "templates"), { recursive: true });
  const pkg = {
    name: ${JSON.stringify(PACKAGE_NAME)},
    version: state.version,
    type: "module",
    repository: ${JSON.stringify(repository())},
    bin: { qm: "dist/bin/qm.js" },
    exports: { "./contract": "./dist/src/contract.js" },
    ...(state.packagePatch ?? {}),
  };
  writeFileSync(join(packageDir, "package.json"), JSON.stringify(pkg, null, 2) + "\\n");
  writeFileSync(join(packageDir, "manifest.json"), JSON.stringify(state.manifest, null, 2) + "\\n");
  writeFileSync(join(packageDir, "dist", "bin", "qm.js"), [
    'import { spawnSync } from "node:child_process";',
    'import { appendFileSync, chmodSync, existsSync, linkSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";',
    'import { join } from "node:path";',
    'const state = JSON.parse(readFileSync(process.env.QM_TEST_UPDATE_STATE ?? process.env.UPDATE_STATE, "utf8"));',
    'const dockerConfig = process.env.DOCKER_CONFIG;',
    'const awsConfig = process.env.AWS_CONFIG_FILE;',
    'const awsCredentials = process.env.AWS_SHARED_CREDENTIALS_FILE;',
    'const envFileIndex = process.argv.indexOf("--env-file");',
    'const deploymentEnvBody = envFileIndex >= 0 ? readFileSync(process.argv[envFileIndex + 1], "utf8") : undefined;',
    'if (state.requireAbsentSandbox && existsSync(process.argv[process.argv.indexOf("--sandbox-dir") + 1])) process.exit(98);',
    'appendFileSync(process.env.QM_TEST_UPDATE_TARGET_LOG ?? process.env.UPDATE_TARGET_LOG, JSON.stringify({ args: process.argv.slice(2), cwd: process.cwd(), entry: import.meta.url, path: process.env.PATH, awsBin: process.env.AWS_BIN, flyBin: process.env.FLY_BIN, dockerBuildxBin: process.env.DOCKER_BUILDX_BIN, dockerPluginDirs: process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS, dockerHooks: process.env.DOCKER_CLI_HOOKS, dockerHints: process.env.DOCKER_CLI_HINTS, dockerConfig, dockerConfigBody: dockerConfig ? readFileSync(join(dockerConfig, "config.json"), "utf8") : undefined, dockerContexts: dockerConfig ? existsSync(join(dockerConfig, "contexts")) : undefined, buildxConfig: process.env.BUILDX_CONFIG, dockerHost: process.env.DOCKER_HOST, dockerContext: process.env.DOCKER_CONTEXT, buildxBuilder: process.env.BUILDX_BUILDER, buildkitHost: process.env.BUILDKIT_HOST, kubeconfig: process.env.KUBECONFIG, home: process.env.HOME, awsConfig, awsConfigBody: awsConfig ? readFileSync(awsConfig, "utf8") : undefined, awsCredentials, awsCredentialsBody: awsCredentials ? readFileSync(awsCredentials, "utf8") : undefined, awsAlias: process.env.HOME ? existsSync(join(process.env.HOME, ".aws", "cli", "alias")) : undefined, awsPager: process.env.AWS_PAGER, awsAutoPrompt: process.env.AWS_CLI_AUTO_PROMPT, awsDataPath: process.env.AWS_DATA_PATH, buildxGitInfo: process.env.BUILDX_GIT_INFO, buildxGitLabels: process.env.BUILDX_GIT_LABELS, gitConfigCount: process.env.GIT_CONFIG_COUNT, gitConfigKey: process.env.GIT_CONFIG_KEY_0, gitConfigValue: process.env.GIT_CONFIG_VALUE_0, nixLd: process.env.NIX_LD, nixLdArch: process.env.NIX_LD_x86_64_linux, nixLdLibraryPath: process.env.NIX_LD_LIBRARY_PATH, nixLdLibraryPathArch: process.env.NIX_LD_LIBRARY_PATH_x86_64_linux, nixLdLog: process.env.NIX_LD_LOG, nixLdFlags: process.env.NIX_LDFLAGS, deploymentEnvBody, deployEnvFileOnly: process.env.QM_DEPLOY_ENV_FILE_ONLY, futureDeploymentSecret: process.env.FUTURE_DEPLOYMENT_SECRET, coreSigningSecret: process.env.CORE_SIGNING_SECRET, awsSecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, awsProfile: process.env.AWS_PROFILE, botoConfig: process.env.BOTO_CONFIG, googleCredentials: process.env.GOOGLE_APPLICATION_CREDENTIALS, vaultAddress: process.env.VAULT_ADDR, awsHistoryFile: process.env.AWS_CLI_HISTORY_FILE, nodeOptions: process.env.NODE_OPTIONS, bashEnvironment: process.env.BASH_ENV, bashFunction: process.env["BASH_FUNC_qm_probe%%"], pythonPath: process.env.PYTHONPATH, ldPreload: process.env.LD_PRELOAD, dyldInsertLibraries: process.env.DYLD_INSERT_LIBRARIES, opensslConfig: process.env.OPENSSL_CONF, gconvPath: process.env.GCONV_PATH, sslKeyLogFile: process.env.SSLKEYLOGFILE, flyHar: process.env.FLYCTL_OUTPUT_HAR, buildkitSourcePolicy: process.env.EXPERIMENTAL_BUILDKIT_SOURCE_POLICY }) + "\\\\n");',
    'if (state.targetAwsCacheDirectory) { mkdirSync(state.targetAwsCacheDirectory, { recursive: true }); writeFileSync(join(state.targetAwsCacheDirectory, "credentials.json"), "{}\\\\n", { mode: 0o600 }); }',
    'for (const command of state.targetProbeBins ?? []) spawnSync(command, [], { stdio: "ignore" });',
    'if (state.targetGitDir) spawnSync("git", ["-C", state.targetGitDir, "status"], { stdio: "ignore" });',
    'if (state.targetGitConfigDir && state.targetGitConfigLog) { const result = spawnSync("git", ["-C", state.targetGitConfigDir, "config", "--get", "remote.origin.url"], { encoding: "utf8" }); writeFileSync(state.targetGitConfigLog, JSON.stringify({ status: result.status, stdout: result.stdout, stderr: result.stderr })); }',
    'if (state.targetMutation === "config") appendFileSync(state.configPath, "\\\\n");',
    'if (typeof state.targetConfigBody === "string") writeFileSync(state.configPath, state.targetConfigBody);',
    'if (state.targetConfigHardlinkPath) { rmSync(state.configPath); linkSync(state.targetConfigHardlinkPath, state.configPath); }',
    'if (state.targetConfigMode !== undefined) chmodSync(state.configPath, state.targetConfigMode);',
    'if (state.targetSandboxMutationPath) writeFileSync(state.targetSandboxMutationPath, "changed\\\\n");',
    'if (state.targetEnvironmentMutationPath) writeFileSync(state.targetEnvironmentMutationPath, "changed\\\\n");',
    'if (state.targetDockerAuth) { const path = join(process.env.DOCKER_CONFIG, "config.json"); const config = JSON.parse(readFileSync(path, "utf8")); config.auths = { "registry.example": {} }; writeFileSync(path, JSON.stringify(config) + "\\\\n"); }',
    'if (state.targetMutation === "package") appendFileSync(join(state.deploymentDir, "node_modules/@yc-software/qm/dist/src/contract.js"), "tampered\\\\n");',
    'if (state.targetSignalAtStart) { process.kill(process.ppid, "SIGTERM"); setInterval(() => {}, 1000); await new Promise(() => {}); }',
    'if (state.targetExit) process.exit(state.targetExit);',
  ].join("\\n") + "\\n");
  chmodSync(join(packageDir, "dist", "bin", "qm.js"), args.includes("--bin-links=true") ? 0o755 : 0o644);
  writeFileSync(join(packageDir, "dist", "src", "contract.js"), "export const targetContract = true;\\n");
  writeFileSync(join(packageDir, "templates", "target-only.txt"), "target-template\\n");
  if (!verifier && state.tamperMutationTree) appendFileSync(join(packageDir, "dist", "src", "contract.js"), "tampered\\n");
  const packageRecord = {
    version: state.version,
    resolved: state.tarball,
    integrity: state.integrity,
    bin: { qm: "dist/bin/qm.js" },
    ...(state.lockPatch ?? {}),
  };
  const packagePath = join(process.cwd(), "package.json");
  const rootPackage = JSON.parse(readFileSync(packagePath, "utf8"));
  rootPackage.dependencies[${JSON.stringify(PACKAGE_NAME)}] = state.version;
  if (!verifier && state.mutationPackagePatch) Object.assign(rootPackage, state.mutationPackagePatch);
  writeFileSync(packagePath, JSON.stringify(rootPackage, null, 2) + "\\n");
  const lockPath = join(process.cwd(), "package-lock.json");
  const lock = has(lockPath) ? JSON.parse(readFileSync(lockPath, "utf8")) : { packages: {} };
  lock.lockfileVersion = 3;
  lock.packages ??= {};
  lock.packages[""] ??= {};
  lock.packages[""].dependencies = { ...rootPackage.dependencies };
  lock.packages[${JSON.stringify(`node_modules/${PACKAGE_NAME}`)}] = packageRecord;
  if (!verifier && state.deleteLockRecord) delete lock.packages[state.deleteLockRecord];
  delete lock.dependencies;
  writeFileSync(lockPath, JSON.stringify(lock, null, 2) + "\\n");
  if (!verifier) {
    const hiddenPath = join(process.cwd(), "node_modules", ".package-lock.json");
    const lockMetadata = { ...lock };
    delete lockMetadata.packages;
    const hiddenPackages = Object.fromEntries(Object.entries(lock.packages).filter(([key]) => key !== ""));
    if (state.omitHiddenLockRecord) delete hiddenPackages[state.omitHiddenLockRecord];
    writeFileSync(hiddenPath, JSON.stringify({ ...lockMetadata, packages: hiddenPackages }, null, 2) + "\\n");
    if (state.hardlinkMutationPath) {
      const linked = join(process.cwd(), state.hardlinkMutationPath);
      linkSync(linked, join(process.cwd(), "npm-created-hardlink"));
    }
  }
  if (args.includes("--bin-links=true")) {
    const binDirectory = join(process.cwd(), "node_modules", ".bin");
    const bin = join(binDirectory, "qm");
    mkdirSync(binDirectory, { recursive: true });
    if (has(bin)) rmSync(bin, { force: true });
    symlinkSync("../@yc-software/qm/dist/bin/qm.js", bin);
  }
  process.exit(0);
}
if (args[0] === "audit" && args[1] === "signatures") {
  if (state.failAudit) process.exit(32);
  process.stdout.write(JSON.stringify(state.audit));
  process.exit(0);
}
process.exit(33);
`;
}

function fakeSigstoreBody(): string {
  return `const { appendFileSync, readFileSync } = require("node:fs");
exports.verify = async (bundle, options) => {
  const state = JSON.parse(readFileSync(process.env.UPDATE_STATE, "utf8"));
  appendFileSync(process.env.UPDATE_SIGSTORE_LOG, JSON.stringify({ bundle, options }) + "\\n");
  if (state.failIdentity) throw new Error("identity mismatch");
};
`;
}

function fakePackageArgumentBody(): string {
  return `const parse = (spec) => {
  if (typeof spec !== "string" || !spec.trim()) throw new Error("invalid package argument");
  if (spec.startsWith("npm:")) {
    const body = spec.slice(4);
    const separator = body.lastIndexOf("@");
    const scopedNameEnd = body.startsWith("@") ? body.indexOf("/") : -1;
    const hasTarget = separator > Math.max(0, scopedNameEnd);
    const targetName = hasTarget ? body.slice(0, separator) : body;
    const target = hasTarget ? body.slice(separator + 1) : "latest";
    if (!body || !target) throw new Error("invalid alias");
    return { type: "alias", subSpec: { ...parse(target), name: targetName } };
  }
  if (spec.startsWith("file:") || spec.startsWith("./") || spec.startsWith("../") || spec.startsWith("/")) return { type: "directory" };
  if (/^https?:/.test(spec)) return { type: "remote" };
  if (/^(?:git\\+|git@|github:|gitlab:|bitbucket:)/.test(spec)) return { type: "git" };
  const hosted = spec.split("/");
  if (!spec.startsWith("@") && hosted.length === 2 && hosted.every(Boolean)) return { type: "git" };
  if (/^\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?$/.test(spec)) return { type: "version" };
  if (/^(?:[~^<>=*]|\\d+(?:\\.[x*])?)/.test(spec)) return { type: "range" };
  if (/^[A-Za-z][0-9A-Za-z._-]*$/.test(spec)) return { type: "tag" };
  throw new Error("invalid package argument");
};
parse.resolve = (name, spec) => {
  const parts = typeof name === "string" ? name.split("/") : [];
  const validPart = (value) => /^[a-z0-9][a-z0-9._-]*$/u.test(value);
  if (
    typeof name !== "string" ||
    !name ||
    name === "." ||
    name === ".." ||
    name === "node_modules" ||
    /[\\s%\\\\:]/u.test(name) ||
    (name.startsWith("@")
      ? parts.length !== 2 || !validPart(parts[0].slice(1)) || !validPart(parts[1])
      : parts.length !== 1 || !validPart(name))
  ) throw new Error("invalid package name");
  return { ...parse(spec), name };
};
module.exports = parse;
`;
}

function fakeSigstoreCoreBody(): string {
  return `exports.X509Certificate = class {
  static parse(raw) {
    const claims = JSON.parse(raw.toString("utf8"));
    return {
      extension(oid) {
        const claim = claims[oid];
        if (typeof claim !== "string") return undefined;
        const value = Buffer.from(claim, "utf8");
        return { value, valueObj: { subs: [{ value }] } };
      },
    };
  }
};
`;
}

function writeInstalled(dir: string, version: string): string {
  const packageDir = join(dir, "node_modules", "@yc-software", "qm");
  mkdirSync(join(packageDir, "dist", "bin"), { recursive: true });
  mkdirSync(join(packageDir, "dist", "src"), { recursive: true });
  mkdirSync(join(packageDir, "templates"), { recursive: true });
  writeFileSync(
    join(packageDir, "package.json"),
    `${JSON.stringify({ name: PACKAGE_NAME, version, type: "module", bin: { qm: "dist/bin/qm.js" } }, null, 2)}\n`,
  );
  writeFileSync(join(packageDir, "manifest.json"), `${JSON.stringify(MANIFEST, null, 2)}\n`);
  writeFileSync(join(packageDir, "dist", "bin", "qm.js"), "throw new Error('old QM entry invoked');\n");
  writeFileSync(join(packageDir, "dist", "src", "contract.js"), "export const targetContract = false;\n");
  writeFileSync(join(packageDir, "templates", "old-only.txt"), "old-template\n");
  return packageDir;
}

function fixture(current = CURRENT, latest = LATEST, target: Target = "docker", baseDir = tmpdir()): Fixture {
  const dir = mkdtempSync(join(baseDir, "qm-update-secure-"));
  const targetBin = mkdtempSync(join(baseDir, "qm-update-provider-bin-"));
  const config = configFor(target);
  const configPath = join(dir, "qm.config.jsonc");
  const sandboxDir = join(dir, "sandbox");
  const npmLog = join(dir, "npm.log");
  const targetLog = join(dir, "target.log");
  const statePath = join(dir, "state.json");
  const npmRoot = join(dir, "trusted-npm");
  const npmPath = join(npmRoot, "bin", "npm-cli.mjs");
  const sigstoreDir = join(npmRoot, "node_modules", "sigstore");
  const sigstoreCoreDir = join(npmRoot, "node_modules", "@sigstore", "core");
  const packageArgumentDir = join(npmRoot, "node_modules", "npm-package-arg");
  const sigstoreLog = join(dir, "sigstore.log");
  const packagePath = join(dir, "package.json");
  const lockPath = join(dir, "package-lock.json");
  const installedVersion = /^\d+\.\d+\.\d+$/.test(current) ? current : CURRENT;
  mkdirSync(sandboxDir);
  for (const name of [
    "aws",
    "docker",
    "docker-buildx",
    "docker-credential-desktop",
    "fly",
    "flyctl",
    "getfacl",
    "git",
    "stat",
  ]) {
    const executable = join(targetBin, name);
    writeFileSync(executable, "#!/bin/sh\nexit 0\n");
    chmodSync(executable, 0o755);
  }
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
  writeFileSync(
    packagePath,
    `${JSON.stringify({ private: true, dependencies: { [PACKAGE_NAME]: current } }, null, 2)}\n`,
  );
  writeFileSync(
    lockPath,
    `${JSON.stringify(
      {
        name: "qm-deployment",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": { dependencies: { [PACKAGE_NAME]: current } },
          [`node_modules/${PACKAGE_NAME}`]: {
            version: installedVersion,
            resolved: `https://registry.npmjs.org/@yc-software/qm/-/qm-${installedVersion}.tgz`,
            integrity: INTEGRITY,
            bin: { qm: "dist/bin/qm.js" },
          },
        },
      },
      null,
      2,
    )}\n`,
  );
  writeInstalled(dir, installedVersion);
  const state: FakeState = {
    deploymentDir: realpathSync(dir),
    configPath: realpathSync(configPath),
    version: latest,
    tarball: tarball(latest),
    integrity: INTEGRITY,
    manifest: structuredClone(MANIFEST),
    audit: audit(latest),
  };
  writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
  mkdirSync(dirname(npmPath), { recursive: true });
  mkdirSync(sigstoreDir, { recursive: true });
  mkdirSync(sigstoreCoreDir, { recursive: true });
  mkdirSync(packageArgumentDir, { recursive: true });
  writeFileSync(
    join(npmRoot, "package.json"),
    `${JSON.stringify({ name: "npm", version: "11.13.0", bin: { npm: "bin/npm-cli.mjs" } }, null, 2)}\n`,
  );
  writeFileSync(
    join(sigstoreDir, "package.json"),
    `${JSON.stringify({ name: "sigstore", version: "4.1.0", main: "index.cjs" }, null, 2)}\n`,
  );
  writeFileSync(join(sigstoreDir, "index.cjs"), fakeSigstoreBody());
  writeFileSync(
    join(sigstoreCoreDir, "package.json"),
    `${JSON.stringify({ name: "@sigstore/core", version: "3.0.0", main: "index.cjs" }, null, 2)}\n`,
  );
  writeFileSync(join(sigstoreCoreDir, "index.cjs"), fakeSigstoreCoreBody());
  writeFileSync(
    join(packageArgumentDir, "package.json"),
    `${JSON.stringify({ name: "npm-package-arg", version: "13.0.0", main: "index.cjs" }, null, 2)}\n`,
  );
  writeFileSync(join(packageArgumentDir, "index.cjs"), fakePackageArgumentBody());
  writeFileSync(npmPath, fakeNpmBody());
  chmodSync(npmPath, 0o755);
  const remote = remoteState(latest);
  const fetcher = (async (input: string | URL | Request): Promise<Response> => {
    let url: string;
    if (typeof input === "string") url = input;
    else if (input instanceof URL) url = input.href;
    else url = input.url;
    const routes = new Map<string, Record<string, unknown>>([
      [`https://registry.npmjs.org/@yc-software%2fqm/latest`, remote.metadata],
    ]);
    const body = routes.get(url);
    return body
      ? new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } })
      : new Response(JSON.stringify({ error: url }), { status: 404 });
  }) as typeof fetch;
  const names = ["HOME", "UPDATE_STATE", "UPDATE_NPM_LOG", "UPDATE_SIGSTORE_LOG", "UPDATE_TARGET_LOG"];
  const previousEnv = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  process.env.HOME = targetBin;
  process.env.UPDATE_STATE = statePath;
  process.env.UPDATE_NPM_LOG = npmLog;
  process.env.UPDATE_SIGSTORE_LOG = sigstoreLog;
  process.env.UPDATE_TARGET_LOG = targetLog;
  return {
    dir,
    config,
    configPath,
    sandboxDir,
    npmLog,
    npmPath,
    targetBin,
    sigstoreLog,
    targetLog,
    statePath,
    fetcher,
    remote,
    previousEnv,
  };
}

function updateState(f: Fixture, mutate: (state: FakeState) => void): void {
  const state = JSON.parse(readFileSync(f.statePath, "utf8")) as FakeState;
  mutate(state);
  writeFileSync(f.statePath, `${JSON.stringify(state, null, 2)}\n`);
}

function writeConfig(f: Fixture): void {
  writeFileSync(f.configPath, `${JSON.stringify(f.config, null, 2)}\n`);
}

function npmCalls(f: Fixture): NpmCall[] {
  if (!existsSync(f.npmLog)) return [];
  return readFileSync(f.npmLog, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as NpmCall);
}

function targetCalls(f: Fixture): TargetCall[] {
  if (!existsSync(f.targetLog)) return [];
  return readFileSync(f.targetLog, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as TargetCall);
}

function clean(f: Fixture): void {
  for (const [name, value] of Object.entries(f.previousEnv)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(f.dir, { recursive: true, force: true });
  rmSync(f.targetBin, { recursive: true, force: true });
}

function addDarwinAcl(path: string, acl: string): void {
  const result = spawnSync("/bin/chmod", ["+a", acl, path], { stdio: "pipe" });
  assert.equal(result.status, 0, result.stderr.toString());
}

function removeDarwinAcl(path: string): void {
  spawnSync("/bin/chmod", ["-N", path], { stdio: "ignore" });
}

function updateOptions(
  f: Fixture,
  overrides: Partial<Parameters<typeof runUpdate>[0]> = {},
): Parameters<typeof runUpdate>[0] {
  return {
    config: f.config,
    configDir: f.dir,
    configPath: f.configPath,
    sandboxDir: f.sandboxDir,
    target: f.config.target,
    yes: true,
    version: LATEST,
    fetcher: f.fetcher,
    testNpmPath: f.npmPath,
    testTargetPath: f.targetBin,
    testGetfaclPath: join(f.targetBin, "getfacl"),
    testTargetEnvironment: {
      QM_TEST_UPDATE_STATE: f.statePath,
      QM_TEST_UPDATE_TARGET_LOG: f.targetLog,
    },
    testNpmEnvironment: {
      UPDATE_STATE: f.statePath,
      UPDATE_NPM_LOG: f.npmLog,
      UPDATE_SIGSTORE_LOG: f.sigstoreLog,
      UPDATE_TARGET_LOG: f.targetLog,
    },
    ...overrides,
  };
}

function invokeInstalled(f: Fixture, ...args: string[]): void {
  const entry = join(f.dir, "node_modules", "@yc-software", "qm", "dist", "bin", "qm.js");
  const result = spawnSync(process.execPath, [entry, ...args], {
    cwd: f.dir,
    env: process.env,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
}

function deploymentPackage(f: Fixture): Record<string, unknown> {
  return JSON.parse(readFileSync(join(f.dir, "package.json"), "utf8")) as Record<string, unknown>;
}

function deploymentLock(f: Fixture): Record<string, unknown> {
  return JSON.parse(readFileSync(join(f.dir, "package-lock.json"), "utf8")) as Record<string, unknown>;
}

function writeHiddenLock(f: Fixture, lock = deploymentLock(f)): Record<string, Record<string, unknown>> {
  const hidden = structuredClone(lock);
  const packages = hidden.packages as Record<string, Record<string, unknown>>;
  delete packages[""];
  writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(hidden, null, 2)}\n`);
  return packages;
}

function pinnedVersion(f: Fixture): string | undefined {
  const dependencies = deploymentPackage(f).dependencies as Record<string, string>;
  return dependencies[PACKAGE_NAME];
}

function digestRecord(digest: ReturnType<typeof createHash>, ...values: Array<string | Buffer>): void {
  for (const value of values) {
    const bytes = typeof value === "string" ? Buffer.from(value) : value;
    digest.update(`${bytes.length}:`);
    digest.update(bytes);
  }
}

function treeDigest(root: string): string {
  const digest = createHash("sha256");
  const visit = (path: string, relativePath: string): void => {
    const identity = lstatSync(path);
    if (identity.isDirectory() && !identity.isSymbolicLink()) {
      digestRecord(digest, "d", relativePath, String(identity.mode & 0o7777));
      for (const name of readdirSync(path).sort()) {
        visit(join(path, name), relativePath ? `${relativePath}/${name}` : name);
      }
    } else if (identity.isFile()) {
      digestRecord(digest, "f", relativePath, String(identity.mode & 0o7777), readFileSync(path));
    } else if (identity.isSymbolicLink()) {
      digestRecord(digest, "l", relativePath, readlinkSync(path));
    } else {
      assert.fail(`${path} has an unsupported filesystem type`);
    }
  };
  visit(root, "");
  return digest.digest("hex");
}

test("version comparison accepts exact stable versions with arbitrarily large components", () => {
  assert.equal(compareVersions("0.1.9", "0.1.10"), -1);
  assert.equal(compareVersions("1.0.0", "0.99.99"), 1);
  assert.equal(compareVersions("1.0.0", "1.0.0"), 0);
  assert.equal(compareVersions("9007199254740993.0.0", "9007199254740992.0.0"), 1);
  for (const version of ["1.0.0-rc.1", "1.0.0+build.1", "01.0.0"]) {
    assert.throws(() => compareVersions(version, "1.0.0"), /invalid QM version/);
  }
});

test("discovery accepts only the exact promoted stable release", async (t) => {
  await t.test("an exact promoted version is reported without installation", async () => {
    const f = fixture();
    try {
      await runUpdate(updateOptions(f, { yes: false, version: LATEST }));
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });

  await t.test("a requested version other than npm latest is rejected", async () => {
    const f = fixture();
    try {
      await assert.rejects(runUpdate(updateOptions(f, { version: "0.1.8" })), /not the promoted latest release/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("a downgrade is rejected", async () => {
    const f = fixture("0.2.0", LATEST);
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /older than the deployment's current/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("a non-stable requested version is rejected before network access", async () => {
    const f = fixture();
    let requests = 0;
    const fetcher = (async (): Promise<Response> => {
      requests++;
      return new Response("{}");
    }) as typeof fetch;
    try {
      await assert.rejects(
        runUpdate(updateOptions(f, { version: "0.1.7-rc.1", fetcher })),
        /not an exact stable version/,
      );
      assert.equal(requests, 0);
    } finally {
      clean(f);
    }
  });

  await t.test("a non-stable latest dist-tag is rejected", async () => {
    const f = fixture();
    f.remote.metadata.version = "0.1.7-rc.1";
    try {
      await assert.rejects(
        runUpdate(updateOptions(f, { yes: false, version: undefined })),
        /latest points to non-stable/,
      );
    } finally {
      clean(f);
    }
  });

  await t.test("deprecated metadata is rejected even without a message", async () => {
    const f = fixture();
    f.remote.metadata.deprecated = null;
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /is deprecated/);
    } finally {
      clean(f);
    }
  });

  await t.test("runtime dependencies are rejected", async () => {
    const f = fixture();
    f.remote.metadata.dependencies = { leftpad: "1.0.0" };
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /unexpectedly declares runtime dependencies/);
    } finally {
      clean(f);
    }
  });
});

test("trusted npm uses private configuration and an allowlisted environment", async () => {
  const f = fixture();
  const priorRegistry = process.env.NPM_CONFIG_REGISTRY;
  const priorSaveDev = process.env.npm_config_save_dev;
  const priorNpmBin = process.env.NPM_BIN;
  const priorNodeOptions = process.env.NODE_OPTIONS;
  try {
    process.env.NPM_CONFIG_REGISTRY = "https://attacker.invalid/";
    process.env.npm_config_save_dev = "true";
    process.env.NPM_BIN = join(f.dir, "attacker-npm");
    process.env.NODE_OPTIONS = "--no-warnings";
    await runUpdate(updateOptions(f));
    const calls = npmCalls(f);
    assert.deepEqual(
      calls.map((call) => call.args.slice(0, 2)),
      [
        ["install", "--dry-run=false"],
        ["audit", "signatures"],
        ["prefix", "--global=false"],
        ["root", "--global=false"],
        ["install", "--package-lock-only=true"],
        ["install", "--save=true"],
      ],
    );
    assert.equal(
      calls.some((call) => ["ci", "exec"].includes(call.args[0]!)),
      false,
    );
    for (const call of calls) {
      assert.equal(
        call.cwd === realpathSync(f.dir) || call.cwd.endsWith("/verifier") || call.cwd.endsWith("/project-check"),
        true,
      );
      assert.equal(call.execPath, process.execPath);
      assert.deepEqual(call.npmConfigEnv, []);
      assert.equal(call.nodeOptions, undefined);
      assert.match(call.path ?? "", /qm-update-.*\/path$/);
      assert.match(call.home ?? "", /qm-update-/);
      assert.match(call.tmpdir ?? "", /qm-update-/);
      assert.equal(call.args.includes(`--registry=${REGISTRY}`), true);
      const userConfig = call.args.find((arg) => arg.startsWith("--userconfig="));
      const globalConfig = call.args.find((arg) => arg.startsWith("--globalconfig="));
      assert.ok(userConfig);
      assert.ok(globalConfig);
      assert.notEqual(userConfig, globalConfig);
      assert.deepEqual(call.configs, { userconfig: "", globalconfig: "" });
    }
    const verifierInstall = calls[0]!;
    const mutationInstall = calls[5]!;
    assert.equal(verifierInstall.stateRootMode, 0o700);
    assert.equal(verifierInstall.transactionMode, 0o700);
    assert.equal(verifierInstall.args.includes("--offline=false"), true);
    for (const call of calls.slice(0, 2)) {
      assert.equal(call.args.includes("--prefer-online=true"), true);
      assert.equal(
        call.args.some((arg) => arg.startsWith("--prefer-offline")),
        false,
      );
    }
    assert.equal(verifierInstall.args.includes("--ignore-scripts=true"), true);
    assert.equal(verifierInstall.args.includes("--foreground-scripts=false"), true);
    assert.equal(verifierInstall.args.includes("--bin-links=true"), true);
    assert.equal(verifierInstall.args.includes("--workspaces=false"), true);
    assert.equal(verifierInstall.args.includes("--engine-strict=true"), true);
    assert.equal(
      verifierInstall.args.some((arg) => arg.startsWith("--save-prod")),
      false,
    );
    assert.equal(
      verifierInstall.args.some((arg) => arg.startsWith("--save-dev")),
      false,
    );
    assert.deepEqual(verifierInstall.verifierPackage, { private: true, dependencies: { [PACKAGE_NAME]: LATEST } });
    for (const arg of [
      "--offline=true",
      "--save=true",
      "--save-exact=true",
      "--save-prod=true",
      "--ignore-scripts=true",
      "--engine-strict=true",
      "--lockfile-version=3",
      "--workspaces=false",
      `--@yc-software:registry=${REGISTRY}`,
    ]) {
      assert.equal(mutationInstall.args.includes(arg), true, arg);
    }
    assert.equal(mutationInstall.args.includes("--prefer-offline=true"), true);
    assert.equal(
      mutationInstall.args.some((arg) => arg.startsWith("--prefer-online")),
      false,
    );
    for (const call of calls.slice(2, 4)) assert.equal(call.args.includes("--workspaces=false"), false);
  } finally {
    if (priorRegistry === undefined) delete process.env.NPM_CONFIG_REGISTRY;
    else process.env.NPM_CONFIG_REGISTRY = priorRegistry;
    if (priorSaveDev === undefined) delete process.env.npm_config_save_dev;
    else process.env.npm_config_save_dev = priorSaveDev;
    if (priorNpmBin === undefined) delete process.env.NPM_BIN;
    else process.env.NPM_BIN = priorNpmBin;
    if (priorNodeOptions === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = priorNodeOptions;
    clean(f);
  }
});

test("the verified target excludes deployment executables from PATH", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const externalBin = mkdtempSync(join(tmpdir(), "qm-update-target-bin-"));
  const deploymentBin = join(f.dir, "node_modules", ".bin");
  const probeLog = join(f.dir, "target-probe.log");
  const previousPath = process.env.PATH;
  const writeProbe = (dir: string, name: string, label: string): void => {
    mkdirSync(dir, { recursive: true });
    const path = join(dir, name);
    writeFileSync(path, `#!/bin/sh\nprintf '%s\\n' ${JSON.stringify(label)} >> ${JSON.stringify(probeLog)}\n`);
    chmodSync(path, 0o755);
  };
  try {
    for (const name of ["aws", "docker"]) {
      writeProbe(deploymentBin, name, `deployment:${name}`);
      writeProbe(externalBin, name, `external:${name}`);
    }
    writeProbe(externalBin, "docker-buildx", "external:docker-buildx");
    process.env.PATH = [deploymentBin, externalBin].join(delimiter);
    updateState(f, (state) => void (state.targetProbeBins = ["aws", "docker"]));
    await runUpdate(updateOptions(f, { testTargetPath: process.env.PATH }));
    const call = targetCalls(f)[0]!;
    const targetPath = call.path?.split(delimiter) ?? [];
    assert.match(targetPath[0] ?? "", /qm-update-[^/]+\/target-path$/);
    assert.equal(targetPath.length, 1);
    assert.equal(targetPath.includes(realpathSync(deploymentBin)), false);
    assert.equal(targetPath.includes(realpathSync(externalBin)), false);
    assert.equal(call.gitConfigCount, undefined);
    assert.equal(call.gitConfigKey, undefined);
    assert.equal(call.gitConfigValue, undefined);
    assert.equal(call.buildxGitInfo, "false");
    assert.equal(call.buildxGitLabels, "false");
    assert.deepEqual(readFileSync(probeLog, "utf8").trim().split("\n"), ["external:aws", "external:docker"]);
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    clean(f);
    rmSync(externalBin, { recursive: true, force: true });
  }
});

test("the verified target blocks deployment Git hooks and Buildx Git discovery", async (t) => {
  const git = (process.env.PATH ?? "")
    .split(delimiter)
    .map((directory) => join(directory, "git"))
    .find((path) => existsSync(path));
  if (!git) {
    t.skip("git is unavailable");
    return;
  }
  const f = fixture(CURRENT, LATEST, "aws");
  const fsmonitorPayload = join(f.dir, "fsmonitor-payload");
  const fsmonitorLog = join(f.dir, "fsmonitor.log");
  const filterPayload = join(f.dir, "filter-payload");
  const filterLog = join(f.dir, "filter.log");
  const gitLog = join(f.dir, "git.log");
  try {
    writeFileSync(fsmonitorPayload, `#!/bin/sh\nprintf invoked >> ${JSON.stringify(fsmonitorLog)}\n`);
    chmodSync(fsmonitorPayload, 0o700);
    writeFileSync(filterPayload, `#!/bin/sh\nprintf invoked >> ${JSON.stringify(filterLog)}\ncat\n`);
    chmodSync(filterPayload, 0o700);
    assert.equal(spawnSync(git, ["init", "-q", f.dir]).status, 0);
    assert.equal(spawnSync(git, ["-C", f.dir, "config", "filter.probe.clean", filterPayload]).status, 0);
    writeFileSync(join(f.dir, ".gitattributes"), "*.txt filter=probe\n");
    writeFileSync(join(f.dir, "tracked.txt"), "before\n");
    assert.equal(spawnSync(git, ["-C", f.dir, "add", ".gitattributes", "tracked.txt"]).status, 0);
    rmSync(filterLog, { force: true });
    const tracked = join(f.dir, "tracked.txt");
    writeFileSync(tracked, "after!\n");
    const future = new Date(Date.now() + 2_000);
    utimesSync(tracked, future, future);
    spawnSync(git, ["-C", f.dir, "status"], { stdio: "ignore" });
    assert.match(readFileSync(filterLog, "utf8"), /invoked/);
    rmSync(filterLog);
    assert.equal(spawnSync(git, ["-C", f.dir, "config", "core.fsmonitor", fsmonitorPayload]).status, 0);
    spawnSync(git, ["-C", f.dir, "status"], { stdio: "ignore" });
    assert.match(readFileSync(fsmonitorLog, "utf8"), /invoked/);
    rmSync(fsmonitorLog);
    rmSync(filterLog, { force: true });
    rmSync(join(f.targetBin, "git"));
    writeFileSync(
      join(f.targetBin, "git"),
      `#!/bin/sh\nprintf '%s\\n' "$*" >> ${JSON.stringify(gitLog)}\nexec ${JSON.stringify(git)} "$@"\n`,
    );
    chmodSync(join(f.targetBin, "git"), 0o755);
    writeFileSync(join(f.targetBin, "aws"), "#!/bin/sh\ngit --version >/dev/null\n");
    chmodSync(join(f.targetBin, "aws"), 0o755);
    updateState(f, (state) => {
      state.targetGitDir = realpathSync(f.dir);
      state.targetProbeBins = ["aws"];
    });
    await runUpdate(updateOptions(f));
    assert.equal(existsSync(fsmonitorLog), false);
    assert.equal(existsSync(filterLog), false);
    assert.equal(existsSync(gitLog), false);
    const call = targetCalls(f)[0]!;
    assert.equal(call.gitConfigCount, undefined);
    assert.equal(call.gitConfigKey, undefined);
    assert.equal(call.gitConfigValue, undefined);
    assert.equal(call.buildxGitInfo, "false");
    assert.equal(call.buildxGitLabels, "false");
  } finally {
    clean(f);
  }
});

test("the verified AWS target permits only its exact GitHub remote lookup", async (t) => {
  const git = (process.env.PATH ?? "")
    .split(delimiter)
    .map((directory) => join(directory, "git"))
    .find((path) => existsSync(path));
  if (!git) {
    t.skip("git is unavailable");
    return;
  }
  const f = fixture(CURRENT, LATEST, "aws");
  const resultLog = join(f.dir, "git-config-result.json");
  const remote = "git@github.com:acme/deployment.git";
  try {
    assert.equal(spawnSync(git, ["init", "-q", f.dir]).status, 0);
    assert.equal(spawnSync(git, ["-C", f.dir, "remote", "add", "origin", remote]).status, 0);
    writeFileSync(join(f.targetBin, "git"), `#!/bin/sh\nexec ${JSON.stringify(git)} "$@"\n`);
    chmodSync(join(f.targetBin, "git"), 0o755);
    updateState(f, (state) => {
      state.targetGitConfigDir = realpathSync(f.dir);
      state.targetGitConfigLog = resultLog;
    });
    await runUpdate(updateOptions(f));
    const result = JSON.parse(readFileSync(resultLog, "utf8")) as {
      status: number | null;
      stdout: string;
      stderr: string;
    };
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), remote);
  } finally {
    clean(f);
  }
});

test("provider executables reject group-writable PATH parents", async () => {
  const f = fixture();
  try {
    chmodSync(f.targetBin, 0o775);
    await assert.rejects(runUpdate(updateOptions(f)), /requires trusted external provider commands on PATH/);
    assert.deepEqual(npmCalls(f), []);
    assert.equal(pinnedVersion(f), CURRENT);
  } finally {
    clean(f);
  }
});

test("provider helper PATH excludes individually writable executables", async () => {
  const f = fixture();
  const log = join(f.dir, "untrusted-helper.log");
  const helper = join(f.targetBin, "docker-credential-desktop");
  try {
    writeFileSync(helper, `#!/bin/sh\nprintf invoked > ${JSON.stringify(log)}\n`);
    chmodSync(helper, 0o775);
    updateState(f, (state) => void (state.targetProbeBins = ["docker-credential-desktop"]));
    await runUpdate(updateOptions(f));
    assert.equal(existsSync(log), false);
    assert.equal(pinnedVersion(f), LATEST);
  } finally {
    clean(f);
  }
});

test("automatic updates hold an exclusive project lock", async () => {
  const f = fixture();
  let releaseFetch = (): void => {};
  const fetchGate = new Promise<void>((resolve) => {
    releaseFetch = resolve;
  });
  const delayedFetcher = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    await fetchGate;
    return f.fetcher(input, init);
  }) as typeof fetch;
  try {
    const first = runUpdate(updateOptions(f, { fetcher: delayedFetcher }));
    await new Promise<void>((resolve) => setImmediate(resolve));
    await assert.rejects(runUpdate(updateOptions(f)), /another automatic QM update is already in progress/);
    assert.deepEqual(npmCalls(f), []);
    releaseFetch();
    await first;
    assert.equal(pinnedVersion(f), LATEST);
  } finally {
    releaseFetch();
    clean(f);
  }
});

test("required provider commands are checked before package mutation", async (t) => {
  for (const entry of [
    { target: "docker" as const, remove: ["docker"] },
    { target: "docker" as const, remove: ["docker-buildx"] },
    { target: "fly" as const, remove: ["fly", "flyctl"] },
    { target: "aws" as const, remove: ["aws"] },
    { target: "aws" as const, remove: ["docker"] },
  ]) {
    await t.test(entry.target + " without " + entry.remove.join(" or "), async () => {
      const f = fixture(CURRENT, LATEST, entry.target);
      try {
        for (const name of entry.remove) rmSync(join(f.targetBin, name));
        await assert.rejects(runUpdate(updateOptions(f)), /requires trusted external provider commands on PATH/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }
});

test("provider binary overrides must name external absolute executables", async (t) => {
  for (const entry of [
    { target: "aws" as const, name: "AWS_BIN" as const, value: "deployment" },
    { target: "fly" as const, name: "FLY_BIN" as const, value: "relative" },
    { target: "aws" as const, name: "DOCKER_BUILDX_BIN" as const, value: "deployment" },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture(CURRENT, LATEST, entry.target);
      const previous = process.env[entry.name];
      try {
        const value = entry.value === "relative" ? entry.name.toLowerCase() : join(f.dir, entry.name.toLowerCase());
        if (entry.value === "deployment") {
          writeFileSync(value, "#!/bin/sh\nexit 0\n");
          chmodSync(value, 0o755);
        }
        process.env[entry.name] = value;
        await assert.rejects(
          runUpdate(updateOptions(f)),
          /must name an absolute external|must name a trusted external/,
        );
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        if (previous === undefined) delete process.env[entry.name];
        else process.env[entry.name] = previous;
        clean(f);
      }
    });
  }

  await t.test("external Fly executable", async () => {
    const f = fixture(CURRENT, LATEST, "fly");
    const external = mkdtempSync(join(tmpdir(), "qm-update-fly-bin-"));
    const executable = join(external, "flyctl");
    const previous = process.env.FLY_BIN;
    try {
      writeFileSync(executable, "#!/bin/sh\nexit 0\n");
      chmodSync(executable, 0o755);
      process.env.FLY_BIN = executable;
      await runUpdate(updateOptions(f));
      assert.match(targetCalls(f)[0]!.flyBin ?? "", /qm-update-[^/]+\/target-path\/\.qm-provider-fly_bin$/);
    } finally {
      if (previous === undefined) delete process.env.FLY_BIN;
      else process.env.FLY_BIN = previous;
      clean(f);
      rmSync(external, { recursive: true, force: true });
    }
  });

  await t.test("hard-linked AWS executable", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    const external = mkdtempSync(join(tmpdir(), "qm-update-aws-bin-"));
    const deploymentExecutable = join(f.dir, "aws-payload");
    const linkedExecutable = join(external, "aws");
    const previous = process.env.AWS_BIN;
    try {
      writeFileSync(deploymentExecutable, "#!/bin/sh\nexit 0\n");
      chmodSync(deploymentExecutable, 0o755);
      linkSync(deploymentExecutable, linkedExecutable);
      process.env.AWS_BIN = linkedExecutable;
      await assert.rejects(runUpdate(updateOptions(f)), /must name a trusted external executable/);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      if (previous === undefined) delete process.env.AWS_BIN;
      else process.env.AWS_BIN = previous;
      rmSync(external, { recursive: true, force: true });
      clean(f);
    }
  });

  await t.test("external Docker Buildx executable", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    const external = mkdtempSync(join(tmpdir(), "qm-update-buildx-bin-"));
    const executable = join(external, "docker-buildx");
    const pluginDirectory = join(external, "plugins");
    const priorBuildx = process.env.DOCKER_BUILDX_BIN;
    const priorPluginDirs = process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS;
    try {
      writeFileSync(executable, "#!/bin/sh\nexit 0\n");
      chmodSync(executable, 0o755);
      mkdirSync(pluginDirectory);
      process.env.DOCKER_BUILDX_BIN = executable;
      process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS = pluginDirectory;
      await runUpdate(updateOptions(f));
      assert.match(
        targetCalls(f)[0]!.dockerBuildxBin ?? "",
        /qm-update-[^/]+\/target-path\/\.qm-provider-docker-buildx$/,
      );
      assert.equal(targetCalls(f)[0]!.dockerPluginDirs, undefined);
    } finally {
      if (priorBuildx === undefined) delete process.env.DOCKER_BUILDX_BIN;
      else process.env.DOCKER_BUILDX_BIN = priorBuildx;
      if (priorPluginDirs === undefined) delete process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS;
      else process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS = priorPluginDirs;
      clean(f);
      rmSync(external, { recursive: true, force: true });
    }
  });

  await t.test("trusted Docker Buildx plugin discovery remains available", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    const home = mkdtempSync(join(tmpdir(), "qm-update-docker-home-"));
    const external = mkdtempSync(join(tmpdir(), "qm-update-desktop-buildx-"));
    const executable = join(external, "docker-buildx");
    const pluginDirectory = join(home, ".docker", "cli-plugins");
    const priorHome = process.env.HOME;
    const priorPath = process.env.PATH;
    const priorDockerConfig = process.env.DOCKER_CONFIG;
    try {
      writeFileSync(executable, "#!/bin/sh\nexit 0\n");
      chmodSync(executable, 0o755);
      mkdirSync(pluginDirectory, { recursive: true });
      symlinkSync(executable, join(pluginDirectory, "docker-buildx"));
      process.env.HOME = home;
      process.env.PATH = f.targetBin;
      delete process.env.DOCKER_CONFIG;
      updateState(f, (state) => void (state.targetProbeBins = ["docker"]));
      await runUpdate(updateOptions(f, { testTargetPath: undefined }));
      assert.match(
        targetCalls(f)[0]!.dockerBuildxBin ?? "",
        /qm-update-[^/]+\/target-path\/\.qm-provider-docker-buildx$/,
      );
    } finally {
      if (priorHome === undefined) delete process.env.HOME;
      else process.env.HOME = priorHome;
      if (priorPath === undefined) delete process.env.PATH;
      else process.env.PATH = priorPath;
      if (priorDockerConfig === undefined) delete process.env.DOCKER_CONFIG;
      else process.env.DOCKER_CONFIG = priorDockerConfig;
      clean(f);
      rmSync(home, { recursive: true, force: true });
      rmSync(external, { recursive: true, force: true });
    }
  });

  await t.test("writable Docker Buildx plugin discovery is rejected", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    const external = mkdtempSync(join(tmpdir(), "qm-update-writable-buildx-"));
    const pluginDirectory = join(external, "plugins");
    const priorBuildx = process.env.DOCKER_BUILDX_BIN;
    const priorPluginDirs = process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS;
    try {
      mkdirSync(pluginDirectory, { mode: 0o777 });
      writeFileSync(join(pluginDirectory, "docker-buildx"), "#!/bin/sh\nexit 0\n");
      chmodSync(join(pluginDirectory, "docker-buildx"), 0o755);
      chmodSync(pluginDirectory, 0o777);
      delete process.env.DOCKER_BUILDX_BIN;
      process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS = pluginDirectory;
      await assert.rejects(runUpdate(updateOptions(f)), /Docker Buildx plugin must be a trusted external executable/);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      if (priorBuildx === undefined) delete process.env.DOCKER_BUILDX_BIN;
      else process.env.DOCKER_BUILDX_BIN = priorBuildx;
      if (priorPluginDirs === undefined) delete process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS;
      else process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS = priorPluginDirs;
      clean(f);
      rmSync(external, { recursive: true, force: true });
    }
  });

  await t.test("inactive Docker Buildx override remains available to trusted helpers", async () => {
    const f = fixture(CURRENT, LATEST, "fly");
    const prior = process.env.DOCKER_BUILDX_BIN;
    try {
      process.env.DOCKER_BUILDX_BIN = join(f.dir, "payload");
      await runUpdate(updateOptions(f));
      assert.equal(targetCalls(f)[0]!.dockerBuildxBin, process.env.DOCKER_BUILDX_BIN);
    } finally {
      if (prior === undefined) delete process.env.DOCKER_BUILDX_BIN;
      else process.env.DOCKER_BUILDX_BIN = prior;
      clean(f);
    }
  });

  await t.test("deployment Docker configuration", async () => {
    const f = fixture();
    const dockerConfig = join(f.dir, ".docker");
    const prior = process.env.DOCKER_CONFIG;
    try {
      mkdirSync(dockerConfig);
      process.env.DOCKER_CONFIG = dockerConfig;
      await assert.rejects(runUpdate(updateOptions(f)), /DOCKER_CONFIG must resolve outside/);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      if (prior === undefined) delete process.env.DOCKER_CONFIG;
      else process.env.DOCKER_CONFIG = prior;
      clean(f);
    }
  });

  await t.test("trusted external Docker configuration and helpers remain available", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    const dockerConfig = mkdtempSync(join(tmpdir(), "qm-update-docker-config-"));
    const helperLog = join(f.dir, "credential-helper.log");
    const helper = join(f.targetBin, "docker-credential-desktop");
    const priorConfig = process.env.DOCKER_CONFIG;
    const priorHooks = process.env.DOCKER_CLI_HOOKS;
    const priorHints = process.env.DOCKER_CLI_HINTS;
    const priorPluginDirs = process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS;
    const pluginDirectory = join(dockerConfig, "plugins");
    try {
      writeFileSync(
        join(dockerConfig, "config.json"),
        `${JSON.stringify({ credsStore: "desktop", features: { hooks: true }, plugins: { probe: { hooks: "build" } } })}\n`,
      );
      writeFileSync(helper, `#!/bin/sh\nprintf invoked > ${JSON.stringify(helperLog)}\n`);
      chmodSync(helper, 0o755);
      writeFileSync(join(f.targetBin, "docker"), "#!/bin/sh\ndocker-credential-desktop\n");
      chmodSync(join(f.targetBin, "docker"), 0o755);
      mkdirSync(pluginDirectory);
      process.env.DOCKER_CONFIG = dockerConfig;
      process.env.DOCKER_CLI_HOOKS = "true";
      process.env.DOCKER_CLI_HINTS = "true";
      process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS = pluginDirectory;
      updateState(f, (state) => void (state.targetProbeBins = ["docker"]));
      await runUpdate(updateOptions(f));
      const call = targetCalls(f)[0]!;
      assert.equal(readFileSync(helperLog, "utf8"), "invoked");
      assert.equal(
        call.dockerConfigBody,
        `${JSON.stringify({ credsStore: "desktop", features: { hooks: true }, plugins: { probe: { hooks: "build" } } })}\n`,
      );
      assert.equal(call.dockerConfig, realpathSync(dockerConfig));
      assert.equal(call.dockerHooks, "true");
      assert.equal(call.dockerHints, "true");
      assert.equal(call.dockerPluginDirs, undefined);
    } finally {
      if (priorConfig === undefined) delete process.env.DOCKER_CONFIG;
      else process.env.DOCKER_CONFIG = priorConfig;
      if (priorHooks === undefined) delete process.env.DOCKER_CLI_HOOKS;
      else process.env.DOCKER_CLI_HOOKS = priorHooks;
      if (priorHints === undefined) delete process.env.DOCKER_CLI_HINTS;
      else process.env.DOCKER_CLI_HINTS = priorHints;
      if (priorPluginDirs === undefined) delete process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS;
      else process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS = priorPluginDirs;
      clean(f);
      rmSync(dockerConfig, { recursive: true, force: true });
    }
  });

  await t.test("relative Docker helper paths cannot re-enter the deployment", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    const dockerConfig = mkdtempSync(join(tmpdir(), "qm-update-docker-config-"));
    const payloadDirectory = join(f.dir, "docker-credential-..");
    const payload = join(payloadDirectory, "payload");
    const payloadLog = join(f.dir, "credential-payload.log");
    const prior = process.env.DOCKER_CONFIG;
    try {
      writeFileSync(join(dockerConfig, "config.json"), `${JSON.stringify({ credsStore: "../payload" })}\n`);
      mkdirSync(payloadDirectory);
      writeFileSync(payload, `#!/bin/sh\nprintf invoked > ${JSON.stringify(payloadLog)}\n`);
      chmodSync(payload, 0o755);
      writeFileSync(join(f.targetBin, "docker"), "#!/bin/sh\ndocker-credential-../payload\n");
      chmodSync(join(f.targetBin, "docker"), 0o755);
      process.env.DOCKER_CONFIG = dockerConfig;
      updateState(f, (state) => void (state.targetProbeBins = ["docker"]));
      await runUpdate(updateOptions(f));
      assert.equal(existsSync(payloadLog), false);
      assert.equal(targetCalls(f)[0]!.dockerConfigBody, `${JSON.stringify({ credsStore: "../payload" })}\n`);
      assert.equal(pinnedVersion(f), LATEST);
    } finally {
      if (prior === undefined) delete process.env.DOCKER_CONFIG;
      else process.env.DOCKER_CONFIG = prior;
      clean(f);
      rmSync(dockerConfig, { recursive: true, force: true });
    }
  });

  await t.test("external provider PATH entries cannot alias deployment helpers", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    const payload = join(f.dir, "nested-helper-payload");
    const payloadLog = join(f.dir, "nested-helper.log");
    try {
      writeFileSync(payload, `#!/bin/sh\nprintf invoked > ${JSON.stringify(payloadLog)}\n`);
      chmodSync(payload, 0o755);
      symlinkSync(payload, join(f.targetBin, "nested-helper"));
      writeFileSync(join(f.targetBin, "docker"), "#!/bin/sh\nnested-helper\n");
      chmodSync(join(f.targetBin, "docker"), 0o755);
      updateState(f, (state) => void (state.targetProbeBins = ["docker"]));
      await assert.rejects(runUpdate(updateOptions(f)), /requires trusted external provider commands/);
      assert.equal(existsSync(payloadLog), false);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });

  await t.test("external provider PATH entries cannot hard-link deployment helpers", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    const payload = join(f.dir, "nested-helper-payload");
    const payloadLog = join(f.dir, "nested-helper.log");
    try {
      writeFileSync(payload, `#!/bin/sh\nprintf invoked > ${JSON.stringify(payloadLog)}\n`);
      chmodSync(payload, 0o755);
      linkSync(payload, join(f.targetBin, "nested-helper"));
      writeFileSync(join(f.targetBin, "docker"), "#!/bin/sh\nnested-helper\n");
      chmodSync(join(f.targetBin, "docker"), 0o755);
      updateState(f, (state) => void (state.targetProbeBins = ["docker"]));
      await assert.rejects(runUpdate(updateOptions(f)), /requires trusted external provider commands/);
      assert.equal(existsSync(payloadLog), false);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });

  await t.test("external provider PATH symlinks cannot wrap hard-linked deployment helpers", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    const externalDirectory = mkdtempSync(join(tmpdir(), "qm-update-provider-lib-"));
    const payload = join(f.dir, "nested-helper-payload");
    const externalPayload = join(externalDirectory, "payload");
    const payloadLog = join(f.dir, "nested-helper.log");
    try {
      writeFileSync(payload, `#!/bin/sh\nprintf invoked > ${JSON.stringify(payloadLog)}\n`);
      chmodSync(payload, 0o755);
      linkSync(payload, externalPayload);
      symlinkSync(relative(f.targetBin, externalPayload), join(f.targetBin, "nested-helper"));
      writeFileSync(join(f.targetBin, "docker"), "#!/bin/sh\nnested-helper\n");
      chmodSync(join(f.targetBin, "docker"), 0o755);
      updateState(f, (state) => void (state.targetProbeBins = ["docker"]));
      await assert.rejects(runUpdate(updateOptions(f)), /requires trusted external provider commands/);
      assert.equal(existsSync(payloadLog), false);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
      rmSync(externalDirectory, { recursive: true, force: true });
    }
  });

  await t.test("AWS Docker authentication may update trusted external configuration", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    const dockerConfig = mkdtempSync(join(tmpdir(), "qm-update-docker-config-"));
    const configPath = join(dockerConfig, "config.json");
    const prior = process.env.DOCKER_CONFIG;
    try {
      writeFileSync(configPath, "{}\n");
      process.env.DOCKER_CONFIG = dockerConfig;
      updateState(f, (state) => void (state.targetDockerAuth = true));
      await runUpdate(updateOptions(f));
      assert.equal(readFileSync(configPath, "utf8"), `${JSON.stringify({ auths: { "registry.example": {} } })}\n`);
      assert.equal(pinnedVersion(f), LATEST);
    } finally {
      if (prior === undefined) delete process.env.DOCKER_CONFIG;
      else process.env.DOCKER_CONFIG = prior;
      clean(f);
      rmSync(dockerConfig, { recursive: true, force: true });
    }
  });

  await t.test("trusted external Docker context remains available", async () => {
    const f = fixture();
    const dockerConfig = mkdtempSync(join(tmpdir(), "qm-update-docker-config-"));
    const contextId = createHash("sha256").update("remote").digest("hex");
    const context = join(dockerConfig, "contexts", "meta", contextId);
    const prior = process.env.DOCKER_CONFIG;
    try {
      mkdirSync(context, { recursive: true });
      writeFileSync(
        join(context, "meta.json"),
        `${JSON.stringify({ Name: "remote", Endpoints: { docker: { Host: "tcp://127.0.0.1:2375" } } })}\n`,
      );
      writeFileSync(join(dockerConfig, "config.json"), `${JSON.stringify({ currentContext: "remote" })}\n`);
      process.env.DOCKER_CONFIG = dockerConfig;
      await runUpdate(updateOptions(f));
      const call = targetCalls(f)[0]!;
      assert.equal(call.dockerConfig, realpathSync(dockerConfig));
      assert.equal(call.dockerConfigBody, `${JSON.stringify({ currentContext: "remote" })}\n`);
      assert.equal(call.dockerContexts, true);
    } finally {
      if (prior === undefined) delete process.env.DOCKER_CONFIG;
      else process.env.DOCKER_CONFIG = prior;
      clean(f);
      rmSync(dockerConfig, { recursive: true, force: true });
    }
  });

  await t.test("external Docker configuration symlinks remain available", async () => {
    const f = fixture();
    const actual = mkdtempSync(join(tmpdir(), "qm-update-docker-config-"));
    const aliases = mkdtempSync(join(tmpdir(), "qm-update-docker-alias-"));
    const body = `${JSON.stringify({ currentContext: "desktop-linux" })}\n`;
    const source = join(aliases, "config-source.json");
    const configured = join(aliases, "configured");
    const prior = process.env.DOCKER_CONFIG;
    try {
      writeFileSync(source, body);
      symlinkSync(source, join(actual, "config.json"));
      symlinkSync(actual, configured);
      process.env.DOCKER_CONFIG = configured;
      await runUpdate(updateOptions(f));
      assert.equal(targetCalls(f)[0]!.dockerConfig, realpathSync(actual));
      assert.equal(targetCalls(f)[0]!.dockerConfigBody, body);
    } finally {
      if (prior === undefined) delete process.env.DOCKER_CONFIG;
      else process.env.DOCKER_CONFIG = prior;
      clean(f);
      rmSync(actual, { recursive: true, force: true });
      rmSync(aliases, { recursive: true, force: true });
    }
  });

  await t.test("linked Docker configuration file", async () => {
    const f = fixture();
    const dockerConfig = mkdtempSync(join(tmpdir(), "qm-update-docker-config-"));
    const deploymentConfig = join(f.dir, "docker-config.json");
    const prior = process.env.DOCKER_CONFIG;
    try {
      writeFileSync(deploymentConfig, "{}\n");
      symlinkSync(deploymentConfig, join(dockerConfig, "config.json"));
      process.env.DOCKER_CONFIG = dockerConfig;
      await assert.rejects(runUpdate(updateOptions(f)), /Docker configuration file must resolve outside/);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      if (prior === undefined) delete process.env.DOCKER_CONFIG;
      else process.env.DOCKER_CONFIG = prior;
      clean(f);
      rmSync(dockerConfig, { recursive: true, force: true });
    }
  });

  await t.test("hard-linked Docker configuration file", async () => {
    const f = fixture();
    const dockerConfig = mkdtempSync(join(tmpdir(), "qm-update-docker-config-"));
    const deploymentConfig = join(f.dir, "docker-config.json");
    const prior = process.env.DOCKER_CONFIG;
    try {
      writeFileSync(deploymentConfig, "{}\n");
      linkSync(deploymentConfig, join(dockerConfig, "config.json"));
      process.env.DOCKER_CONFIG = dockerConfig;
      await assert.rejects(runUpdate(updateOptions(f)), /must not be hard-linked/);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      if (prior === undefined) delete process.env.DOCKER_CONFIG;
      else process.env.DOCKER_CONFIG = prior;
      clean(f);
      rmSync(dockerConfig, { recursive: true, force: true });
    }
  });

  await t.test("deployment home Docker configuration", async () => {
    const f = fixture();
    const priorHome = process.env.HOME;
    const priorPath = process.env.PATH;
    const priorDockerConfig = process.env.DOCKER_CONFIG;
    try {
      process.env.HOME = f.dir;
      process.env.PATH = f.targetBin;
      delete process.env.DOCKER_CONFIG;
      await assert.rejects(
        runUpdate(updateOptions(f, { testTargetPath: undefined })),
        /HOME must resolve outside the deployment/,
      );
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      if (priorHome === undefined) delete process.env.HOME;
      else process.env.HOME = priorHome;
      if (priorPath === undefined) delete process.env.PATH;
      else process.env.PATH = priorPath;
      if (priorDockerConfig === undefined) delete process.env.DOCKER_CONFIG;
      else process.env.DOCKER_CONFIG = priorDockerConfig;
      clean(f);
    }
  });
});

test("provider path lists cannot reference the deployment", async (t) => {
  for (const entry of [
    { name: "AWS_DATA_PATH", target: "aws" as const },
    { name: "SSL_CERT_DIR", target: "docker" as const },
    { name: "DOCKER_CLI_PLUGIN_EXTRA_DIRS", target: "docker" as const },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture(CURRENT, LATEST, entry.target);
      const external = mkdtempSync(join(tmpdir(), "qm-update-provider-path-"));
      const previous = process.env[entry.name];
      try {
        process.env[entry.name] = [external, f.sandboxDir].join(delimiter);
        await assert.rejects(runUpdate(updateOptions(f)), new RegExp(entry.name + ".*outside the deployment"));
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        if (previous === undefined) delete process.env[entry.name];
        else process.env[entry.name] = previous;
        clean(f);
        rmSync(external, { recursive: true, force: true });
      }
    });
  }
});

test("provider write paths and Unix endpoints cannot reference the deployment", async (t) => {
  for (const entry of [
    { name: "GITHUB_STEP_SUMMARY", value: (f: Fixture) => join(f.dir, "summary.md"), target: "fly" as const },
    {
      name: "BUILDKIT_HOST",
      value: (f: Fixture) => "unix://" + join(f.dir, "buildkit.sock"),
      target: "docker" as const,
    },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture(CURRENT, LATEST, entry.target);
      try {
        const options = updateOptions(f);
        options.testTargetEnvironment![entry.name] = entry.value(f);
        await assert.rejects(runUpdate(options), /must resolve outside the deployment/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }
});

test("automatic update rejects a relative or deployment temporary root", async (t) => {
  for (const kind of ["relative", "deployment"] as const) {
    await t.test(kind, async () => {
      const f = fixture();
      const previous = process.env.TMPDIR;
      try {
        process.env.TMPDIR = kind === "relative" ? "qm-relative-tmp" : f.sandboxDir;
        await assert.rejects(
          runUpdate(updateOptions(f)),
          /temporary directory must be an absolute external|temporary directory must resolve outside/,
        );
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        if (previous === undefined) delete process.env.TMPDIR;
        else process.env.TMPDIR = previous;
        clean(f);
      }
    });
  }
});

test(
  "automatic update rejects permission-granting macOS ACLs before npm",
  { skip: process.platform !== "darwin" },
  async (t) => {
    for (const entry of [
      { name: "deployment root", path: (f: Fixture) => f.dir },
      { name: "node_modules descendant", path: (f: Fixture) => join(f.dir, "node_modules", "@yc-software", "qm") },
    ]) {
      await t.test(entry.name, async () => {
        const f = fixture();
        const path = entry.path(f);
        addDarwinAcl(path, DARWIN_ALLOW_DIRECTORY_ACL);
        try {
          await assert.rejects(runUpdate(updateOptions(f)), /protected paths without extended ACLs/);
          assert.deepEqual(npmCalls(f), []);
          assert.equal(pinnedVersion(f), CURRENT);
        } finally {
          removeDarwinAcl(path);
          clean(f);
        }
      });
    }

    await t.test("deployment ancestor", async () => {
      const parent = mkdtempSync(join(tmpdir(), "qm-update-acl-parent-"));
      const f = fixture(CURRENT, LATEST, "docker", parent);
      addDarwinAcl(parent, DARWIN_ALLOW_DIRECTORY_ACL);
      try {
        await assert.rejects(runUpdate(updateOptions(f)), /permission-granting ancestor ACLs/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        removeDarwinAcl(parent);
        clean(f);
        rmSync(parent, { recursive: true, force: true });
      }
    });

    await t.test("temporary ancestor", async () => {
      const f = fixture();
      const transactionRoot = mkdtempSync(join(tmpdir(), "qm-update-acl-tmp-"));
      const previous = process.env.TMPDIR;
      addDarwinAcl(transactionRoot, DARWIN_ALLOW_DIRECTORY_ACL);
      try {
        process.env.TMPDIR = transactionRoot;
        await assert.rejects(runUpdate(updateOptions(f)), /permission-granting ancestor ACLs/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        if (previous === undefined) delete process.env.TMPDIR;
        else process.env.TMPDIR = previous;
        removeDarwinAcl(transactionRoot);
        rmSync(transactionRoot, { recursive: true, force: true });
        clean(f);
      }
    });
  },
);

test(
  "automatic update permits deny-only macOS ACLs on ancestors",
  { skip: process.platform !== "darwin" },
  async () => {
    const parent = mkdtempSync(join(tmpdir(), "qm-update-acl-deny-"));
    const f = fixture(CURRENT, LATEST, "docker", parent);
    addDarwinAcl(parent, DARWIN_DENY_DELETE_ACL);
    try {
      await runUpdate(updateOptions(f));
      assert.equal(pinnedVersion(f), LATEST);
    } finally {
      removeDarwinAcl(parent);
      clean(f);
      rmSync(parent, { recursive: true, force: true });
    }
  },
);

test("Linux ACL inspection fails closed before npm", async (t) => {
  await t.test("extended ACL output", async () => {
    const f = fixture();
    try {
      const inspector = join(f.targetBin, "getfacl");
      writeFileSync(inspector, "#!/bin/sh\nprintf 'user:65534:rwx\\n'\n");
      chmodSync(inspector, 0o755);
      await assert.rejects(
        runUpdate(updateOptions(f, { testPlatform: "linux" })),
        /protected paths without extended ACLs on Linux/,
      );
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });

  await t.test("ancestor ACL output", async () => {
    const f = fixture();
    const external = mkdtempSync(join(tmpdir(), "qm-update-linux-acl-parent-"));
    const environmentPath = join(external, "deployment.env");
    try {
      writeFileSync(environmentPath, "NORMAL_SECRET=value\n", { mode: 0o600 });
      const inspector = join(f.targetBin, "getfacl");
      writeFileSync(
        inspector,
        `#!/bin/sh\nfor candidate in "$@"; do\n  if [ "$candidate" = ${JSON.stringify(external)} ]; then\n    printf 'user:65534:rwx\\n'\n  fi\ndone\n`,
      );
      chmodSync(inspector, 0o755);
      await assert.rejects(
        runUpdate(updateOptions(f, { envFile: environmentPath, testPlatform: "linux" })),
        /protected paths without extended ACLs on Linux/,
      );
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
      rmSync(external, { recursive: true, force: true });
    }
  });

  await t.test("missing inspector", async () => {
    const f = fixture();
    try {
      await assert.rejects(
        runUpdate(
          updateOptions(f, {
            testPlatform: "linux",
            testGetfaclPath: join(f.targetBin, "missing-getfacl"),
          }),
        ),
        /requires trusted getfacl/,
      );
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });

  await t.test("launcher PATH selection skips a deployment candidate", async () => {
    const f = fixture();
    const deploymentBin = join(f.dir, "bin");
    const previous = process.env.PATH;
    try {
      mkdirSync(deploymentBin);
      writeFileSync(join(deploymentBin, "getfacl"), "#!/bin/sh\nprintf 'user:65534:rwx\\n'\n");
      chmodSync(join(deploymentBin, "getfacl"), 0o755);
      process.env.PATH = [deploymentBin, f.targetBin].join(delimiter);
      await runUpdate(
        updateOptions(f, {
          testPlatform: "linux",
          testGetfaclPath: undefined,
        }),
      );
      assert.equal(pinnedVersion(f), LATEST);
    } finally {
      if (previous === undefined) delete process.env.PATH;
      else process.env.PATH = previous;
      clean(f);
    }
  });
});

test("automatic mutation fails closed outside macOS and Linux", async (t) => {
  for (const platform of ["win32", "freebsd"] as const) {
    await t.test(platform, async () => {
      const f = fixture();
      try {
        await assert.rejects(
          runUpdate(updateOptions(f, { testPlatform: platform })),
          /supported only on macOS and Linux/,
        );
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }
});

test("AWS path overrides must be literal external paths", async (t) => {
  for (const [name, variable] of [
    ["AWS_CONFIG_FILE", "$QM_AWS_JUMP"],
    ["AWS_CONFIG_FILE", "${QM_AWS_JUMP}"],
    ["AWS_SHARED_CREDENTIALS_FILE", "$QM_AWS_JUMP"],
    ["AWS_SHARED_CREDENTIALS_FILE", "${QM_AWS_JUMP}"],
  ] as const) {
    await t.test(name + " " + variable, async () => {
      const f = fixture(CURRENT, LATEST, "aws");
      const previousPath = process.env[name];
      const previousJump = process.env.QM_AWS_JUMP;
      try {
        process.env.QM_AWS_JUMP = f.dir.slice(dirname(f.dir).length + 1);
        process.env[name] = join(dirname(f.dir), variable, "config");
        await assert.rejects(runUpdate(updateOptions(f)), new RegExp(name + ".*absolute external file"));
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        if (previousPath === undefined) delete process.env[name];
        else process.env[name] = previousPath;
        if (previousJump === undefined) delete process.env.QM_AWS_JUMP;
        else process.env.QM_AWS_JUMP = previousJump;
        clean(f);
      }
    });
  }
});

test("provider paths cannot exit through a deployment symlink", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const external = mkdtempSync(join(tmpdir(), "qm-update-external-config-"));
  const link = join(f.dir, "external-config");
  const previous = process.env.AWS_CONFIG_FILE;
  try {
    symlinkSync(external, link);
    process.env.AWS_CONFIG_FILE = join(link, "missing");
    await assert.rejects(runUpdate(updateOptions(f)), /AWS_CONFIG_FILE must resolve outside the deployment/);
    assert.deepEqual(npmCalls(f), []);
    assert.equal(pinnedVersion(f), CURRENT);
  } finally {
    if (previous === undefined) delete process.env.AWS_CONFIG_FILE;
    else process.env.AWS_CONFIG_FILE = previous;
    clean(f);
    rmSync(external, { recursive: true, force: true });
  }
});

test("AWS provider input files must not be writable by other users", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const external = mkdtempSync(join(tmpdir(), "qm-update-writable-aws-config-"));
  const config = join(external, "config");
  const previous = process.env.AWS_CONFIG_FILE;
  try {
    writeFileSync(config, "[default]\ncredential_process = /tmp/payload\n");
    chmodSync(config, 0o666);
    process.env.AWS_CONFIG_FILE = config;
    await assert.rejects(runUpdate(updateOptions(f)), /trusted unlinked provider input file/);
    assert.deepEqual(npmCalls(f), []);
    assert.deepEqual(targetCalls(f), []);
    assert.equal(pinnedVersion(f), CURRENT);
  } finally {
    if (previous === undefined) delete process.env.AWS_CONFIG_FILE;
    else process.env.AWS_CONFIG_FILE = previous;
    clean(f);
    rmSync(external, { recursive: true, force: true });
  }
});

test("AWS profile files cannot execute credential processes during automatic update", async (t) => {
  for (const [variable, newline] of [
    ["AWS_CONFIG_FILE", "\r"],
    ["AWS_SHARED_CREDENTIALS_FILE", "\n"],
  ] as const) {
    await t.test(variable, async () => {
      const f = fixture(CURRENT, LATEST, "aws");
      const external = mkdtempSync(join(tmpdir(), "qm-update-credential-process-"));
      const profile = join(external, "profile");
      try {
        writeFileSync(profile, ["[default]", "credential_process = /bin/echo credentials", ""].join(newline), {
          mode: 0o600,
        });
        const options = updateOptions(f);
        options.testTargetEnvironment![variable] = profile;
        await assert.rejects(runUpdate(options), /must not configure credential_process during automatic update/);
        assert.deepEqual(npmCalls(f), []);
        assert.deepEqual(targetCalls(f), []);
      } finally {
        clean(f);
        rmSync(external, { recursive: true, force: true });
      }
    });
  }
});

test("AWS profile file references require protected inputs", async (t) => {
  for (const [variable, newline] of [
    ["AWS_CONFIG_FILE", "\r"],
    ["AWS_SHARED_CREDENTIALS_FILE", "\n"],
  ] as const) {
    for (const name of ["web_identity_token_file", "ca_bundle"] as const) {
      await t.test(variable + " " + name, async () => {
        const f = fixture(CURRENT, LATEST, "aws");
        const external = mkdtempSync(join(tmpdir(), "qm-update-aws-config-reference-"));
        const writable = join(external, "writable");
        const profile = join(external, "profile");
        try {
          mkdirSync(writable);
          chmodSync(writable, 0o777);
          writeFileSync(profile, ["[default]", `${name} = ${join(writable, "missing")}`, ""].join(newline), {
            mode: 0o600,
          });
          const options = updateOptions(f);
          options.testTargetEnvironment![variable] = profile;
          await assert.rejects(
            runUpdate(options),
            /must not (?:permit other users to create an automatic update input|be writable by group or other users)/,
          );
          assert.deepEqual(npmCalls(f), []);
          assert.deepEqual(targetCalls(f), []);
        } finally {
          clean(f);
          rmSync(external, { recursive: true, force: true });
        }
      });
    }
  }
});

test("AWS profile file references remain stable until deployment", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const external = mkdtempSync(join(tmpdir(), "qm-update-aws-config-reference-stability-"));
  const token = join(external, "token");
  const config = join(external, "config");
  try {
    writeFileSync(config, `[default]\nweb_identity_token_file = ${token}\n`, { mode: 0o600 });
    updateState(f, (state) => {
      state.targetAbsentInputMutationPath = token;
    });
    const options = updateOptions(f);
    options.testTargetEnvironment!.AWS_SHARED_CREDENTIALS_FILE = config;
    await assert.rejects(
      runUpdate(options),
      (error: unknown) =>
        error instanceof Error &&
        error.cause instanceof Error &&
        new RegExp(token + " changed during automatic update").test(error.cause.message),
    );
    assert.deepEqual(targetCalls(f), []);
  } finally {
    clean(f);
    rmSync(external, { recursive: true, force: true });
  }
});

test("absent provider inputs require a protected creation directory", async (t) => {
  for (const entry of [
    { target: "aws" as const, name: "AWS_CONFIG_FILE" },
    { target: "aws" as const, name: "AWS_DATA_PATH" },
    { target: "aws" as const, name: "AWS_LOGIN_CACHE_DIRECTORY" },
    { target: "docker" as const, name: "NIX_LD_LIBRARY_PATH" },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture(CURRENT, LATEST, entry.target);
      const external = mkdtempSync(join(tmpdir(), "qm-update-writable-provider-input-"));
      try {
        chmodSync(external, 0o777);
        const options = updateOptions(f);
        options.testTargetEnvironment![entry.name] = join(external, "missing");
        await assert.rejects(runUpdate(options), /must not permit other users to create an automatic update input/);
        assert.deepEqual(npmCalls(f), []);
        assert.deepEqual(targetCalls(f), []);
      } finally {
        clean(f);
        rmSync(external, { recursive: true, force: true });
      }
    });
  }
});

test("absent AWS provider inputs must remain absent until deployment", async (t) => {
  for (const name of ["AWS_CONFIG_FILE", "AWS_DATA_PATH", "AWS_LOGIN_CACHE_DIRECTORY"] as const) {
    await t.test(name, async () => {
      const f = fixture(CURRENT, LATEST, "aws");
      const external = mkdtempSync(join(tmpdir(), "qm-update-absent-provider-input-"));
      const input = join(external, "input");
      try {
        updateState(f, (state) => {
          state.targetAbsentInputMutationPath = input;
        });
        const options = updateOptions(f);
        options.testTargetEnvironment![name] = input;
        await assert.rejects(
          runUpdate(options),
          (error: unknown) =>
            error instanceof Error &&
            error.cause instanceof Error &&
            new RegExp(input + " changed during automatic update").test(error.cause.message),
        );
        assert.deepEqual(targetCalls(f), []);
      } finally {
        clean(f);
        rmSync(external, { recursive: true, force: true });
      }
    });
  }
});

test("AWS home credential caches must be recursively trusted", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const home = mkdtempSync(join(tmpdir(), "qm-update-aws-cache-home-"));
  const token = join(home, ".aws", "sso", "cache", "token.json");
  try {
    mkdirSync(dirname(token), { recursive: true });
    writeFileSync(token, "{}\n", { mode: 0o666 });
    chmodSync(token, 0o666);
    const options = updateOptions(f);
    options.testTargetEnvironment!.HOME = home;
    await assert.rejects(runUpdate(options), /must not be writable by group or other users/);
    assert.deepEqual(npmCalls(f), []);
    assert.deepEqual(targetCalls(f), []);
  } finally {
    clean(f);
    rmSync(home, { recursive: true, force: true });
  }
});

test("AWS may create a protected default credential cache during deployment", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const home = mkdtempSync(join(tmpdir(), "qm-update-provider-created-aws-cache-"));
  const cache = join(home, ".aws", "cli", "cache");
  try {
    updateState(f, (state) => {
      state.targetAwsCacheDirectory = cache;
    });
    const options = updateOptions(f, { testTargetUmask: 0o002 });
    options.testTargetEnvironment!.HOME = home;
    await runUpdate(options);
    assert.equal(existsSync(join(cache, "credentials.json")), true);
    assert.equal(statSync(cache).mode & 0o777, 0o700);
    assert.equal(targetCalls(f).length, 1);
  } finally {
    clean(f);
    rmSync(home, { recursive: true, force: true });
  }
});

test("AWS provider data paths must be recursively trusted", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const data = mkdtempSync(join(tmpdir(), "qm-update-aws-data-"));
  const model = join(data, "service-model.json");
  try {
    writeFileSync(model, "{}\n", { mode: 0o666 });
    chmodSync(model, 0o666);
    const options = updateOptions(f);
    options.testTargetEnvironment!.AWS_DATA_PATH = data;
    await assert.rejects(runUpdate(options), /must not be writable by group or other users/);
    assert.deepEqual(npmCalls(f), []);
    assert.deepEqual(targetCalls(f), []);
  } finally {
    clean(f);
    rmSync(data, { recursive: true, force: true });
  }
});

test("canonical provider paths cannot introduce environment expansion", async (t) => {
  for (const name of ["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"] as const) {
    await t.test(name, async () => {
      const f = fixture(CURRENT, LATEST, "aws");
      const external = mkdtempSync(join(tmpdir(), "qm-update-expanded-config-"));
      const literalDirectory = join(external, "$QM_AWS_JUMP");
      const source = join(literalDirectory, "config");
      const alias = join(external, "config-link");
      const previousPath = process.env[name];
      const previousJump = process.env.QM_AWS_JUMP;
      try {
        mkdirSync(literalDirectory);
        writeFileSync(source, "[default]\nregion = us-east-1\n");
        symlinkSync(source, alias);
        process.env.QM_AWS_JUMP = "../" + f.dir.slice(dirname(f.dir).length + 1);
        process.env[name] = alias;
        await assert.rejects(runUpdate(updateOptions(f)), /must be an already-expanded external path/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        if (previousPath === undefined) delete process.env[name];
        else process.env[name] = previousPath;
        if (previousJump === undefined) delete process.env.QM_AWS_JUMP;
        else process.env.QM_AWS_JUMP = previousJump;
        clean(f);
        rmSync(external, { recursive: true, force: true });
      }
    });
  }
});

test("provider configuration files cannot be hard-linked into the deployment", async (t) => {
  for (const entry of ["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS alias"] as const) {
    await t.test(entry, async () => {
      const f = fixture(CURRENT, LATEST, "aws");
      const home = mkdtempSync(join(tmpdir(), "qm-update-aws-home-"));
      const external = mkdtempSync(join(tmpdir(), "qm-update-aws-config-"));
      const deploymentFile = join(f.dir, "aws-provider-state");
      const previousHome = process.env.HOME;
      const variable = entry === "AWS alias" ? undefined : entry;
      const previousValue = variable ? process.env[variable] : undefined;
      try {
        writeFileSync(
          deploymentFile,
          entry === "AWS alias" ? "[toplevel]\nsts = !/deployment/payload\n" : "[default]\nregion = us-east-1\n",
        );
        process.env.HOME = home;
        if (entry === "AWS alias") {
          const aliasDirectory = join(home, ".aws", "cli");
          mkdirSync(aliasDirectory, { recursive: true });
          linkSync(deploymentFile, join(aliasDirectory, "alias"));
        } else {
          const path = join(external, entry.toLowerCase());
          linkSync(deploymentFile, path);
          process.env[entry] = path;
        }
        await assert.rejects(runUpdate(updateOptions(f)), /must not be hard-linked/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        if (previousHome === undefined) delete process.env.HOME;
        else process.env.HOME = previousHome;
        if (variable) {
          if (previousValue === undefined) delete process.env[variable];
          else process.env[variable] = previousValue;
        }
        clean(f);
        rmSync(home, { recursive: true, force: true });
        rmSync(external, { recursive: true, force: true });
      }
    });
  }
});

test("default Boto configuration cannot link back into the deployment", async (t) => {
  for (const kind of ["symlink", "hardlink"] as const) {
    await t.test(kind, async () => {
      const f = fixture(CURRENT, LATEST, "aws");
      const home = mkdtempSync(join(tmpdir(), "qm-update-boto-home-"));
      const deploymentFile = join(f.dir, "boto.cfg");
      const previousHome = process.env.HOME;
      const previousBoto = process.env.BOTO_CONFIG;
      try {
        writeFileSync(deploymentFile, "[Credentials]\naws_access_key_id = deployment\n");
        if (kind === "symlink") symlinkSync(deploymentFile, join(home, ".boto"));
        else linkSync(deploymentFile, join(home, ".boto"));
        process.env.HOME = home;
        delete process.env.BOTO_CONFIG;
        await assert.rejects(
          runUpdate(updateOptions(f)),
          kind === "symlink" ? /must resolve outside the deployment/ : /must not be hard-linked/,
        );
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        if (previousHome === undefined) delete process.env.HOME;
        else process.env.HOME = previousHome;
        if (previousBoto === undefined) delete process.env.BOTO_CONFIG;
        else process.env.BOTO_CONFIG = previousBoto;
        clean(f);
        rmSync(home, { recursive: true, force: true });
      }
    });
  }
});

test("default provider state cannot link back into the deployment", async (t) => {
  for (const entry of [
    { target: "docker" as const, directory: ".docker" },
    { target: "aws" as const, directory: ".aws" },
    { target: "aws" as const, directory: ".ssh" },
    { target: "aws" as const, directory: ".kube" },
  ]) {
    await t.test(entry.directory, async () => {
      const f = fixture(CURRENT, LATEST, entry.target);
      const home = mkdtempSync(join(tmpdir(), "qm-update-provider-home-"));
      const previousHome = process.env.HOME;
      const previousDocker = process.env.DOCKER_CONFIG;
      const previousAws = process.env.AWS_CONFIG_FILE;
      try {
        symlinkSync(f.dir, join(home, entry.directory));
        process.env.HOME = home;
        delete process.env.DOCKER_CONFIG;
        delete process.env.AWS_CONFIG_FILE;
        await assert.rejects(runUpdate(updateOptions(f)), /must resolve outside the deployment/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        if (previousHome === undefined) delete process.env.HOME;
        else process.env.HOME = previousHome;
        if (previousDocker === undefined) delete process.env.DOCKER_CONFIG;
        else process.env.DOCKER_CONFIG = previousDocker;
        if (previousAws === undefined) delete process.env.AWS_CONFIG_FILE;
        else process.env.AWS_CONFIG_FILE = previousAws;
        clean(f);
        rmSync(home, { recursive: true, force: true });
      }
    });
  }
});

test("trusted external AWS configuration and aliases remain available", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const home = mkdtempSync(join(tmpdir(), "qm-update-aws-home-"));
  const config = join(home, "config");
  const credentials = join(home, "credentials");
  const alias = join(home, ".aws", "cli", "alias");
  const previousHome = process.env.HOME;
  const previousConfig = process.env.AWS_CONFIG_FILE;
  const previousCredentials = process.env.AWS_SHARED_CREDENTIALS_FILE;
  try {
    mkdirSync(dirname(alias), { recursive: true });
    writeFileSync(config, "[profile trusted]\nregion = us-east-1\n");
    writeFileSync(credentials, "[trusted]\naws_access_key_id = test\n");
    writeFileSync(alias, "[toplevel]\nwho = sts get-caller-identity\n");
    process.env.HOME = home;
    process.env.AWS_CONFIG_FILE = config;
    process.env.AWS_SHARED_CREDENTIALS_FILE = credentials;
    await runUpdate(updateOptions(f));
    const call = targetCalls(f)[0]!;
    assert.equal(call.awsConfig, realpathSync(config));
    assert.equal(call.awsConfigBody, "[profile trusted]\nregion = us-east-1\n");
    assert.equal(call.awsCredentials, realpathSync(credentials));
    assert.equal(call.awsCredentialsBody, "[trusted]\naws_access_key_id = test\n");
    assert.equal(call.awsAlias, true);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousConfig === undefined) delete process.env.AWS_CONFIG_FILE;
    else process.env.AWS_CONFIG_FILE = previousConfig;
    if (previousCredentials === undefined) delete process.env.AWS_SHARED_CREDENTIALS_FILE;
    else process.env.AWS_SHARED_CREDENTIALS_FILE = previousCredentials;
    clean(f);
    rmSync(home, { recursive: true, force: true });
  }
});

test("trusted cross-provider helper environment remains available", async () => {
  const f = fixture(CURRENT, LATEST, "docker");
  const external = mkdtempSync(join(tmpdir(), "qm-update-helper-env-"));
  const boto = join(external, "boto.cfg");
  const google = join(external, "google.json");
  const names = ["AWS_PROFILE", "BOTO_CONFIG", "GOOGLE_APPLICATION_CREDENTIALS", "PYTHONPATH", "VAULT_ADDR"] as const;
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  try {
    writeFileSync(boto, "[Credentials]\naws_access_key_id = test\n");
    writeFileSync(google, "{}\n");
    process.env.AWS_PROFILE = "trusted-profile";
    process.env.BOTO_CONFIG = boto;
    process.env.GOOGLE_APPLICATION_CREDENTIALS = google;
    process.env.PYTHONPATH = external;
    process.env.VAULT_ADDR = "https://vault.example.test";
    await runUpdate(updateOptions(f));
    const call = targetCalls(f)[0]!;
    assert.equal(call.awsProfile, "trusted-profile");
    assert.equal(call.botoConfig, boto);
    assert.equal(call.googleCredentials, google);
    assert.equal(call.pythonPath, undefined);
    assert.equal(call.vaultAddress, "https://vault.example.test");
  } finally {
    for (const name of names) {
      const value = previous[name];
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    clean(f);
    rmSync(external, { recursive: true, force: true });
  }
});

test("target process environment excludes ambient loader controls", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const nodePayload = join(f.dir, "node-loader.cjs");
  const shellPayload = join(f.dir, "shell-loader.sh");
  const log = join(f.dir, "loader.log");
  try {
    writeFileSync(nodePayload, `require("node:fs").appendFileSync(${JSON.stringify(log)}, "node\\n");\n`);
    writeFileSync(shellPayload, `printf 'shell\\n' >> ${JSON.stringify(log)}\n`);
    writeFileSync(join(f.targetBin, "aws"), "#!/bin/bash\nqm_probe 2>/dev/null || true\n");
    chmodSync(join(f.targetBin, "aws"), 0o755);
    updateState(f, (state) => void (state.targetProbeBins = ["aws"]));
    const options = updateOptions(f);
    Object.assign(options.testTargetEnvironment!, {
      NODE_OPTIONS: "--require=" + nodePayload,
      BASH_ENV: shellPayload,
      "BASH_FUNC_qm_probe%%": `() { printf 'function\\n' >> ${JSON.stringify(log)}; }`,
      LD_PRELOAD: join(f.dir, "preload.so"),
      DYLD_INSERT_LIBRARIES: join(f.dir, "insert.dylib"),
      OPENSSL_CONF: join(f.dir, "openssl.cnf"),
      GCONV_PATH: join(f.dir, "gconv"),
      SSLKEYLOGFILE: join(f.dir, "keys.log"),
      PYTHONPATH: f.dir,
      PYTHONHOME: f.dir,
      RUBYOPT: "-r" + shellPayload,
      PERL5OPT: "-Mstrict",
      JAVA_TOOL_OPTIONS: "-javaagent:" + nodePayload,
      DOTNET_STARTUP_HOOKS: nodePayload,
    });
    await runUpdate(options);
    assert.equal(existsSync(log), false);
    const call = targetCalls(f)[0]!;
    for (const value of [
      call.nodeOptions,
      call.bashEnvironment,
      call.bashFunction,
      call.ldPreload,
      call.dyldInsertLibraries,
      call.opensslConfig,
      call.gconvPath,
      call.sslKeyLogFile,
      call.pythonPath,
    ]) {
      assert.equal(value, undefined);
    }
  } finally {
    clean(f);
  }
});

test("nix-ld target loader settings preserve supported selector semantics", async () => {
  const f = fixture();
  const external = mkdtempSync(join(tmpdir(), "qm-update-nix-ld-"));
  const libraryDirectory = join(external, "libraries");
  const libraryAlias = join(external, "library-alias");
  const loaderAlias = join(external, "loader-alias");
  try {
    mkdirSync(libraryDirectory);
    symlinkSync(libraryDirectory, libraryAlias);
    symlinkSync("/bin/sh", loaderAlias);
    const options = updateOptions(f);
    Object.assign(options.testTargetEnvironment!, {
      NIX_LD: loaderAlias,
      NIX_LD_x86_64_linux: "",
      NIX_LD_i686_linux: "",
      NIX_LD_aarch64_linux: "",
      NIX_LD_riscv64_linux: "",
      NIX_LD_LIBRARY_PATH: libraryAlias,
      NIX_LD_LIBRARY_PATH_x86_64_linux: "",
      NIX_LD_LIBRARY_PATH_i686_linux: "",
      NIX_LD_LIBRARY_PATH_aarch64_linux: "",
      NIX_LD_LIBRARY_PATH_riscv64_linux: "",
      NIX_LD_LOG: "debug",
      NIX_LDFLAGS: "trusted-build-flags",
    });
    await runUpdate(options);
    const call = targetCalls(f)[0]!;
    assert.equal(call.nixLd, realpathSync("/bin/sh"));
    assert.equal(call.nixLdArch, "");
    assert.equal(call.nixLdLibraryPath, realpathSync(libraryDirectory));
    assert.equal(call.nixLdLibraryPathArch, "");
    assert.equal(call.nixLdLog, "debug");
    assert.equal(call.nixLdFlags, "trusted-build-flags");
  } finally {
    clean(f);
    rmSync(external, { recursive: true, force: true });
  }
});

test("nix-ld rejects writable library trees before provider execution", async () => {
  const f = fixture();
  const external = mkdtempSync(join(tmpdir(), "qm-update-nix-writable-library-"));
  const libraryDirectory = join(external, "libraries");
  try {
    mkdirSync(libraryDirectory);
    writeFileSync(join(libraryDirectory, "libpayload.so"), "payload", { mode: 0o666 });
    chmodSync(join(libraryDirectory, "libpayload.so"), 0o666);
    const options = updateOptions(f);
    options.testTargetEnvironment!.NIX_LD_LIBRARY_PATH = libraryDirectory;
    await assert.rejects(runUpdate(options), /must not be writable by group or other users/);
    assert.deepEqual(npmCalls(f), []);
    assert.deepEqual(targetCalls(f), []);
  } finally {
    clean(f);
    rmSync(external, { recursive: true, force: true });
  }
});

test("nix-ld library symlink targets are included in Linux ACL validation", async () => {
  const f = fixture();
  const external = mkdtempSync(join(tmpdir(), "qm-update-nix-symlink-acl-"));
  const libraryDirectory = join(external, "libraries");
  const target = join(external, "libpayload.so");
  try {
    mkdirSync(libraryDirectory);
    writeFileSync(target, "payload");
    symlinkSync(target, join(libraryDirectory, "libpayload.so"));
    const inspector = join(f.targetBin, "getfacl");
    writeFileSync(
      inspector,
      `#!/bin/sh\nfor candidate in "$@"; do\n  if [ "$candidate" = ${JSON.stringify(realpathSync(target))} ]; then\n    printf 'user:65534:rwx\\n'\n  fi\ndone\n`,
    );
    chmodSync(inspector, 0o755);
    const options = updateOptions(f, { testPlatform: "linux" });
    options.testTargetEnvironment!.NIX_LD_LIBRARY_PATH = libraryDirectory;
    await assert.rejects(runUpdate(options), /protected paths without extended ACLs on Linux/);
    assert.deepEqual(npmCalls(f), []);
    assert.deepEqual(targetCalls(f), []);
  } finally {
    clean(f);
    rmSync(external, { recursive: true, force: true });
  }
});

test("nix-ld target loader paths cannot reference the deployment", async (t) => {
  for (const name of [
    "NIX_LD",
    "NIX_LD_x86_64_linux",
    "NIX_LD_LIBRARY_PATH",
    "NIX_LD_LIBRARY_PATH_x86_64_linux",
    "NIX_LD_UNSUPPORTED",
  ] as const) {
    await t.test(name, async () => {
      const f = fixture();
      const executable = join(f.dir, "loader");
      try {
        writeFileSync(executable, "#!/bin/sh\nexit 0\n");
        chmodSync(executable, 0o700);
        const options = updateOptions(f);
        options.testTargetEnvironment![name] = executable;
        await assert.rejects(
          runUpdate(options),
          name === "NIX_LD_UNSUPPORTED" ? /not a supported target loader setting/ : /outside|external/,
        );
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }
});

test("nix-ld library paths reject semicolon smuggling and empty components", async (t) => {
  const entries = [
    {
      name: "NIX_LD_LIBRARY_PATH",
      value: (external: string, deployment: string): string => `${external};${deployment}`,
    },
    { name: "NIX_LD_LIBRARY_PATH_x86_64_linux", value: (external: string): string => `${external};` },
    { name: "NIX_LD_LIBRARY_PATH", value: (external: string): string => `;${external}` },
    { name: "NIX_LD_LIBRARY_PATH_x86_64_linux", value: (external: string): string => `${external};;${external}` },
    { name: "NIX_LD_LIBRARY_PATH", value: (external: string): string => `${external}:` },
    { name: "NIX_LD_LIBRARY_PATH_x86_64_linux", value: (external: string): string => `:${external}` },
    { name: "NIX_LD_LIBRARY_PATH", value: (external: string): string => `${external}::${external}` },
  ] as const;
  for (const [index, entry] of entries.entries()) {
    await t.test(String(index + 1), async () => {
      const f = fixture();
      const external = mkdtempSync(join(tmpdir(), "qm-update-nix-library-"));
      try {
        const options = updateOptions(f);
        options.testTargetEnvironment![entry.name] = entry.value(external, f.dir);
        await assert.rejects(runUpdate(options), /absolute external directories|outside the deployment/);
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
        rmSync(external, { recursive: true, force: true });
      }
    });
  }
});

test("nix-ld loader replacement is detected before deployment", async () => {
  const f = fixture();
  const external = mkdtempSync(join(tmpdir(), "qm-update-nix-loader-"));
  const loader = join(external, "loader");
  const replacement = join(f.dir, "replacement-loader");
  try {
    writeFileSync(loader, "#!/bin/sh\nexit 0\n");
    chmodSync(loader, 0o700);
    writeFileSync(replacement, "#!/bin/sh\nexit 0\n");
    chmodSync(replacement, 0o700);
    updateState(f, (state) => {
      state.targetExecutableMutationPath = loader;
      state.targetExecutableMutationTarget = replacement;
    });
    const options = updateOptions(f);
    Object.assign(options.testTargetEnvironment!, {
      NIX_LD: loader,
      NIX_LD_x86_64_linux: "",
      NIX_LD_i686_linux: "",
      NIX_LD_aarch64_linux: "",
      NIX_LD_riscv64_linux: "",
    });
    await assert.rejects(
      runUpdate(options),
      (error: unknown) =>
        error instanceof Error &&
        error.cause instanceof Error &&
        /loader changed during automatic update/.test(error.cause.message),
    );
    assert.deepEqual(targetCalls(f), []);
  } finally {
    clean(f);
    rmSync(external, { recursive: true, force: true });
  }
});

test("active Fly HAR output is suppressed", async () => {
  const f = fixture(CURRENT, LATEST, "fly");
  try {
    const options = updateOptions(f);
    options.testTargetEnvironment!.FLYCTL_OUTPUT_HAR = join(f.dir, "fly.har");
    await runUpdate(options);
    assert.equal(targetCalls(f)[0]!.flyHar, undefined);
  } finally {
    clean(f);
  }
});

test("Buildx source policies must be trusted external files", async (t) => {
  await t.test("external policy", async () => {
    const f = fixture();
    const external = mkdtempSync(join(tmpdir(), "qm-update-buildx-policy-"));
    const policy = join(external, "policy.json");
    try {
      writeFileSync(policy, "{}\n");
      const options = updateOptions(f);
      options.testTargetEnvironment!.EXPERIMENTAL_BUILDKIT_SOURCE_POLICY = policy;
      await runUpdate(options);
      assert.equal(targetCalls(f)[0]!.buildkitSourcePolicy, realpathSync(policy));
    } finally {
      clean(f);
      rmSync(external, { recursive: true, force: true });
    }
  });

  await t.test("deployment policy", async () => {
    const f = fixture();
    const policy = join(f.dir, "policy.json");
    try {
      writeFileSync(policy, "{}\n");
      const options = updateOptions(f);
      options.testTargetEnvironment!.EXPERIMENTAL_BUILDKIT_SOURCE_POLICY = policy;
      await assert.rejects(runUpdate(options), /EXPERIMENTAL_BUILDKIT_SOURCE_POLICY must resolve outside/);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });
});

test("AWS CLI history is isolated from deployment paths", async (t) => {
  for (const kind of ["direct", "symlink", "hardlink"] as const) {
    await t.test(kind, async () => {
      const f = fixture(CURRENT, LATEST, "aws");
      const external = mkdtempSync(join(tmpdir(), "qm-update-history-"));
      const deploymentHistory = join(f.dir, "history.db");
      const configuredHistory = kind === "direct" ? deploymentHistory : join(external, "history.db");
      const config = join(external, "aws-config");
      try {
        writeFileSync(deploymentHistory, "deployment-history\n");
        writeFileSync(config, "[default]\ncli_history = enabled\n");
        if (kind === "symlink") symlinkSync(deploymentHistory, configuredHistory);
        if (kind === "hardlink") linkSync(deploymentHistory, configuredHistory);
        const options = updateOptions(f);
        Object.assign(options.testTargetEnvironment!, {
          AWS_CONFIG_FILE: config,
          AWS_CLI_HISTORY_FILE: configuredHistory,
        });
        await runUpdate(options);
        const history = targetCalls(f)[0]!.awsHistoryFile ?? "";
        assert.match(history, /qm-update-[^/]+\/aws-cli-history\.db$/);
        assert.notEqual(history, configuredHistory);
        assert.equal(readFileSync(deploymentHistory, "utf8"), "deployment-history\n");
      } finally {
        clean(f);
        rmSync(external, { recursive: true, force: true });
      }
    });
  }
});

test("ambient provider credentials declared as workload secrets are not copied into the deployment", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const previous = process.env.AWS_SECRET_ACCESS_KEY;
  try {
    f.config.secretEnv = { core: { PLUGIN_CREDENTIAL: "AWS_SECRET_ACCESS_KEY" } };
    writeConfig(f);
    process.env.AWS_SECRET_ACCESS_KEY = "ambient-provider-credential";
    await runUpdate(updateOptions(f));
    const call = targetCalls(f)[0]!;
    assert.equal(call.deploymentEnvBody, "");
    assert.equal(call.deployEnvFileOnly, "1");
    assert.equal(call.awsSecretAccessKey, "ambient-provider-credential");
    assert.equal(existsSync(join(f.dir, ".env")), false);
  } finally {
    if (previous === undefined) delete process.env.AWS_SECRET_ACCESS_KEY;
    else process.env.AWS_SECRET_ACCESS_KEY = previous;
    clean(f);
  }
});

test("deployment-secret file-only mode covers names unknown to the current updater schema", async () => {
  const f = fixture();
  const previous = process.env.FUTURE_DEPLOYMENT_SECRET;
  try {
    process.env.FUTURE_DEPLOYMENT_SECRET = "ambient-provider-credential";
    await runUpdate(updateOptions(f));
    const call = targetCalls(f)[0]!;
    assert.equal(call.deployEnvFileOnly, "1");
    assert.equal(call.futureDeploymentSecret, "ambient-provider-credential");
    assert.doesNotMatch(call.deploymentEnvBody ?? "", /^FUTURE_DEPLOYMENT_SECRET=/m);
  } finally {
    if (previous === undefined) delete process.env.FUTURE_DEPLOYMENT_SECRET;
    else process.env.FUTURE_DEPLOYMENT_SECRET = previous;
    clean(f);
  }
});

test("the explicit deployment environment is copied byte-for-byte", async () => {
  const f = fixture();
  const environmentPath = join(f.dir, ".env");
  const body = Buffer.from("PLAIN=value\nQUOTED='abc'def\nSPACED= trailing \n");
  try {
    writeFileSync(environmentPath, body);
    await runUpdate(updateOptions(f, { envFile: environmentPath }));
    assert.deepEqual(Buffer.from(targetCalls(f)[0]!.deploymentEnvBody ?? ""), body);
  } finally {
    clean(f);
  }
});

test("the trusted target PATH excludes executable aliases into the deployment", async () => {
  const f = fixture(CURRENT, LATEST, "aws");
  const poisonedBin = mkdtempSync(join(tmpdir(), "qm-update-poisoned-bin-"));
  const externalBin = mkdtempSync(join(tmpdir(), "qm-update-external-bin-"));
  const probeLog = join(f.dir, "target-alias-probe.log");
  const previousPath = process.env.PATH;
  const commands = ["aws", "docker"];
  try {
    for (const [index, name] of commands.entries()) {
      const payload = join(f.dir, "payload-" + name);
      writeFileSync(payload, `#!/bin/sh\nprintf '%s\\n' deployment:${name} >> ${JSON.stringify(probeLog)}\n`);
      chmodSync(payload, 0o755);
      if (index % 2 === 0) symlinkSync(payload, join(poisonedBin, name));
      else linkSync(payload, join(poisonedBin, name));
      const safe = join(externalBin, name);
      writeFileSync(safe, `#!/bin/sh\nprintf '%s\\n' external:${name} >> ${JSON.stringify(probeLog)}\n`);
      chmodSync(safe, 0o755);
    }
    writeFileSync(join(externalBin, "docker-buildx"), "#!/bin/sh\nexit 0\n");
    chmodSync(join(externalBin, "docker-buildx"), 0o755);
    process.env.PATH = [poisonedBin, externalBin].join(delimiter);
    updateState(f, (state) => void (state.targetProbeBins = commands));
    await runUpdate(updateOptions(f, { testTargetPath: process.env.PATH }));
    assert.deepEqual(
      readFileSync(probeLog, "utf8").trim().split("\n"),
      commands.map((name) => "external:" + name),
    );
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    rmSync(poisonedBin, { recursive: true, force: true });
    rmSync(externalBin, { recursive: true, force: true });
    clean(f);
  }
});

test("the trusted target PATH detects executable replacement before deployment", async () => {
  const f = fixture();
  const externalBin = mkdtempSync(join(tmpdir(), "qm-update-replaced-bin-"));
  const executable = join(externalBin, "docker");
  const payload = join(f.dir, "docker-payload");
  const previousPath = process.env.PATH;
  try {
    writeFileSync(executable, "#!/bin/sh\nexit 0\n");
    chmodSync(executable, 0o755);
    writeFileSync(join(externalBin, "docker-buildx"), "#!/bin/sh\nexit 0\n");
    chmodSync(join(externalBin, "docker-buildx"), 0o755);
    writeFileSync(payload, "#!/bin/sh\nexit 0\n");
    chmodSync(payload, 0o755);
    process.env.PATH = externalBin;
    updateState(f, (state) => {
      state.targetExecutableMutationPath = executable;
      state.targetExecutableMutationTarget = payload;
    });
    await assert.rejects(
      runUpdate(updateOptions(f, { testTargetPath: process.env.PATH })),
      /deployment failed.*remains pinned and verified/,
    );
    assert.deepEqual(targetCalls(f), []);
    assert.equal(pinnedVersion(f), LATEST);
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    rmSync(externalBin, { recursive: true, force: true });
    clean(f);
  }
});

test("filesystem identity excludes alternate-case deployment aliases where supported", async (t) => {
  const f = fixture();
  const internalBin = join(f.dir, "provider-bin");
  const externalBin = mkdtempSync(join(tmpdir(), "qm-update-case-bin-"));
  const probeLog = join(f.dir, "case-probe.log");
  const previousPath = process.env.PATH;
  try {
    mkdirSync(internalBin);
    const internal = join(internalBin, "docker");
    writeFileSync(internal, `#!/bin/sh\nprintf deployment >> ${JSON.stringify(probeLog)}\n`);
    chmodSync(internal, 0o755);
    const external = join(externalBin, "docker");
    writeFileSync(external, `#!/bin/sh\nprintf external >> ${JSON.stringify(probeLog)}\n`);
    chmodSync(external, 0o755);
    writeFileSync(join(externalBin, "docker-buildx"), "#!/bin/sh\nexit 0\n");
    chmodSync(join(externalBin, "docker-buildx"), 0o755);
    let alias: string | undefined;
    for (let index = 0; index < internalBin.length; index++) {
      const character = internalBin[index]!;
      if (!/[A-Za-z]/.test(character)) continue;
      const toggled = character === character.toLowerCase() ? character.toUpperCase() : character.toLowerCase();
      const candidate = internalBin.slice(0, index) + toggled + internalBin.slice(index + 1);
      try {
        const left = statSync(candidate);
        const right = statSync(internalBin);
        if (left.dev === right.dev && left.ino === right.ino && candidate !== internalBin) {
          alias = candidate;
          break;
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    if (!alias) {
      t.skip("filesystem is case-sensitive");
      return;
    }
    process.env.PATH = [alias, externalBin].join(delimiter);
    updateState(f, (state) => void (state.targetProbeBins = ["docker"]));
    await runUpdate(updateOptions(f, { testTargetPath: process.env.PATH }));
    assert.equal(readFileSync(probeLog, "utf8"), "external");
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    clean(f);
    rmSync(externalBin, { recursive: true, force: true });
  }
});

test("trusted npm must support attestation-inclusive signature audit", async (t) => {
  for (const entry of [
    { version: "11.11.0", accepted: false },
    { version: "11.12.0", accepted: true },
    { version: "11.99.0", accepted: true },
    { version: "12.0.0", accepted: false },
  ]) {
    await t.test(entry.version, async () => {
      const f = fixture();
      const npmPackagePath = join(dirname(dirname(f.npmPath)), "package.json");
      const npmPackage = JSON.parse(readFileSync(npmPackagePath, "utf8")) as Record<string, unknown>;
      npmPackage.version = entry.version;
      writeFileSync(npmPackagePath, `${JSON.stringify(npmPackage, null, 2)}\n`);
      try {
        if (entry.accepted) {
          await runUpdate(updateOptions(f));
          assert.equal(pinnedVersion(f), LATEST);
        } else {
          await assert.rejects(runUpdate(updateOptions(f)), /npm beside Node.*11\.12\.0 or newer and below 12\.0\.0/);
          assert.deepEqual(npmCalls(f), []);
          assert.equal(pinnedVersion(f), CURRENT);
        }
      } finally {
        clean(f);
      }
    });
  }
});

test("termination reaches foreground npm process groups and waits for descendants", async (t) => {
  for (const entry of [
    {
      name: "at child startup",
      atStart: true,
      signal: "SIGTERM" as const,
      probeErrors: 0,
      forwardErrors: false,
      repeat: false,
    },
    {
      name: "after a descendant starts",
      atStart: false,
      signal: "SIGTERM" as const,
      probeErrors: 0,
      forwardErrors: false,
      repeat: false,
    },
    {
      name: "transient group probe permission errors",
      atStart: false,
      signal: "SIGTERM" as const,
      probeErrors: 3,
      forwardErrors: false,
      repeat: false,
    },
    {
      name: "persistent group probe permission errors",
      atStart: false,
      signal: "SIGTERM" as const,
      probeErrors: -1,
      forwardErrors: false,
      repeat: true,
    },
    {
      name: "persistent group signal permission errors",
      atStart: true,
      signal: "SIGTERM" as const,
      probeErrors: 0,
      forwardErrors: true,
      repeat: false,
    },
    {
      name: "SIGQUIT after a descendant starts",
      atStart: false,
      signal: "SIGQUIT" as const,
      probeErrors: 0,
      forwardErrors: false,
      repeat: false,
    },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      const ready = join(f.dir, "signal.ready");
      const signalLog = join(f.dir, "signal.log");
      const signalPid = join(f.dir, "signal.pid");
      const runner = join(f.dir, "signal-runner.mjs");
      const transactionRoot = mkdtempSync(join(tmpdir(), "qm-update-signal-tmp-"));
      updateState(f, (state) => {
        state.signalAtStart = entry.atStart;
        state.waitForSignal = !entry.atStart;
        state.signalReady = ready;
        state.signalLog = signalLog;
        state.signalPid = signalPid;
        state.forwardedSignal = entry.signal;
      });
      const updateModule = pathToFileURL(
        realpathSync(join(import.meta.dirname, "..", "src", "commands", "update.ts")),
      ).href;
      writeFileSync(
        runner,
        [
          'import { existsSync } from "node:fs";',
          `import { runUpdate } from ${JSON.stringify(updateModule)};`,
          `const config = ${JSON.stringify(f.config)};`,
          `const metadata = ${JSON.stringify(f.remote.metadata)};`,
          "const fetcher = async () => new Response(JSON.stringify(metadata), { status: 200 });",
          `const options = ${JSON.stringify({
            config: f.config,
            configDir: f.dir,
            configPath: f.configPath,
            sandboxDir: f.sandboxDir,
            target: f.config.target,
            yes: true,
            version: LATEST,
            testNpmPath: f.npmPath,
            testTargetPath: f.targetBin,
            testGetfaclPath: join(f.targetBin, "getfacl"),
            testNpmEnvironment: {
              UPDATE_STATE: f.statePath,
              UPDATE_NPM_LOG: f.npmLog,
              UPDATE_SIGSTORE_LOG: f.sigstoreLog,
              UPDATE_TARGET_LOG: f.targetLog,
            },
          })};`,
          "const originalKill = process.kill.bind(process);",
          "let groupProbes = 0;",
          "let forcedGroup = false;",
          `process.kill = (pid, signal) => { if (pid < 0 && signal === "SIGKILL") forcedGroup = true; if (pid < 0 && existsSync(${JSON.stringify(ready)}) && ((${entry.forwardErrors} && signal !== 0) || (signal === 0 && !forcedGroup && (${entry.probeErrors} < 0 || groupProbes++ < ${entry.probeErrors})))) { const error = new Error("permission denied"); error.code = "EPERM"; throw error; } return originalKill(pid, signal); };`,
          "options.fetcher = fetcher;",
          "await runUpdate(options);",
        ].join("\n"),
      );
      const child = spawn(process.execPath, [runner], {
        cwd: f.dir,
        env: { ...process.env, TMPDIR: transactionRoot },
        stdio: ["ignore", "ignore", "pipe"],
      });
      const stderr: Buffer[] = [];
      child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
      const completion = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
        (resolveCompletion, reject) => {
          child.once("error", reject);
          child.once("close", (code, signal) => resolveCompletion({ code, signal }));
        },
      );
      try {
        for (let attempt = 0; attempt < 250 && !existsSync(ready); attempt++) {
          await new Promise<void>((resolveWait) => setTimeout(resolveWait, 20));
        }
        assert.equal(existsSync(ready), true, Buffer.concat(stderr).toString("utf8"));
        const signaledAt = Date.now();
        if (!entry.atStart) child.kill(entry.signal);
        if (entry.repeat) {
          await new Promise<void>((resolveWait) => setTimeout(resolveWait, 350));
          assert.equal(child.exitCode, null);
          assert.equal(child.signalCode, null);
          child.kill(entry.signal);
        }
        const outcome = await completion;
        assert.equal(outcome.code, null, Buffer.concat(stderr).toString("utf8"));
        assert.equal(outcome.signal, entry.signal);
        if (!entry.atStart) assert.equal(Date.now() - signaledAt >= 150, true);
        assert.equal(readFileSync(signalLog, "utf8"), entry.atStart ? "installed\nsignal\ndone\n" : "signal\ndone\n");
        assert.deepEqual(targetCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
        assert.deepEqual(readdirSync(transactionRoot), []);
        assert.throws(
          () => process.kill(-Number(readFileSync(signalPid, "utf8")), 0),
          (error: unknown) => (error as NodeJS.ErrnoException).code === "ESRCH",
        );
      } finally {
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
        await completion.catch(() => undefined);
        if (existsSync(signalPid)) {
          try {
            process.kill(-Number(readFileSync(signalPid, "utf8")), "SIGKILL");
          } catch (error) {
            assert.equal((error as NodeJS.ErrnoException).code, "ESRCH");
          }
        }
        rmSync(transactionRoot, { recursive: true, force: true });
        clean(f);
      }
    });
  }
});

test("a termination signal wins a foreground spawn failure race", async () => {
  const f = fixture();
  const runner = join(f.dir, "spawn-failure-runner.mjs");
  const survived = join(f.dir, "spawn-failure-survived");
  const missingExecutable = join(f.dir, "missing-node");
  const updateModule = pathToFileURL(
    realpathSync(join(import.meta.dirname, "..", "src", "commands", "update.ts")),
  ).href;
  writeFileSync(
    runner,
    [
      'import { writeFileSync } from "node:fs";',
      `import { runUpdate } from ${JSON.stringify(updateModule)};`,
      `const config = ${JSON.stringify(f.config)};`,
      `const metadata = ${JSON.stringify(f.remote.metadata)};`,
      "let requested = false;",
      `const fetcher = async () => { if (!requested) { requested = true; process.execPath = ${JSON.stringify(missingExecutable)}; setImmediate(() => process.kill(process.pid, "SIGTERM")); } return new Response(JSON.stringify(metadata), { status: 200 }); };`,
      `const options = ${JSON.stringify({
        config: f.config,
        configDir: f.dir,
        configPath: f.configPath,
        sandboxDir: f.sandboxDir,
        target: f.config.target,
        yes: true,
        version: LATEST,
        testNpmPath: f.npmPath,
        testTargetPath: f.targetBin,
        testNpmEnvironment: {
          UPDATE_STATE: f.statePath,
          UPDATE_NPM_LOG: f.npmLog,
          UPDATE_SIGSTORE_LOG: f.sigstoreLog,
          UPDATE_TARGET_LOG: f.targetLog,
        },
      })};`,
      "options.fetcher = fetcher;",
      "try { await runUpdate(options); } catch {}",
      `writeFileSync(${JSON.stringify(survived)}, "survived");`,
    ].join("\n"),
  );
  const child = spawn(process.execPath, [runner], {
    cwd: f.dir,
    env: process.env,
    stdio: ["ignore", "ignore", "pipe"],
  });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  try {
    const outcome = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (resolveCompletion, reject) => {
        child.once("error", reject);
        child.once("close", (code, signal) => resolveCompletion({ code, signal }));
      },
    );
    assert.equal(outcome.code, null, Buffer.concat(stderr).toString("utf8"));
    assert.equal(outcome.signal, "SIGTERM");
    assert.equal(existsSync(survived), false);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    clean(f);
  }
});

test("a termination signal during release revalidation removes the private transaction", async () => {
  const f = fixture();
  const runner = join(f.dir, "fetch-signal-runner.mjs");
  const ready = join(f.dir, "fetch-signal.ready");
  const transactionRoot = mkdtempSync(join(tmpdir(), "qm-update-fetch-signal-tmp-"));
  const updateModule = pathToFileURL(
    realpathSync(join(import.meta.dirname, "..", "src", "commands", "update.ts")),
  ).href;
  writeFileSync(
    runner,
    [
      'import { writeFileSync } from "node:fs";',
      `import { runUpdate } from ${JSON.stringify(updateModule)};`,
      `const config = ${JSON.stringify(f.config)};`,
      `const metadata = ${JSON.stringify(f.remote.metadata)};`,
      "let requests = 0;",
      `const fetcher = async () => { requests += 1; if (requests === 2) { writeFileSync(${JSON.stringify(ready)}, "ready\\n"); await new Promise(() => setInterval(() => {}, 1000)); } return new Response(JSON.stringify(metadata), { status: 200 }); };`,
      `const options = ${JSON.stringify({
        config: f.config,
        configDir: f.dir,
        configPath: f.configPath,
        sandboxDir: f.sandboxDir,
        target: f.config.target,
        yes: true,
        version: LATEST,
        testNpmPath: f.npmPath,
        testTargetPath: f.targetBin,
        testGetfaclPath: join(f.targetBin, "getfacl"),
        testNpmEnvironment: {
          UPDATE_STATE: f.statePath,
          UPDATE_NPM_LOG: f.npmLog,
          UPDATE_SIGSTORE_LOG: f.sigstoreLog,
          UPDATE_TARGET_LOG: f.targetLog,
        },
      })};`,
      "options.fetcher = fetcher;",
      "await runUpdate(options);",
    ].join("\n"),
  );
  const child = spawn(process.execPath, [runner], {
    cwd: f.dir,
    env: { ...process.env, TMPDIR: transactionRoot },
    stdio: ["ignore", "ignore", "pipe"],
  });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const completion = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolveCompletion, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolveCompletion({ code, signal }));
    },
  );
  try {
    for (let attempt = 0; attempt < 250 && !existsSync(ready); attempt++) {
      await new Promise<void>((resolveWait) => setTimeout(resolveWait, 20));
    }
    assert.equal(existsSync(ready), true);
    child.kill("SIGTERM");
    const outcome = await completion;
    assert.equal(outcome.code, null, Buffer.concat(stderr).toString("utf8"));
    assert.equal(outcome.signal, "SIGTERM");
    assert.deepEqual(readdirSync(transactionRoot), []);
    assert.equal(pinnedVersion(f), CURRENT);
    assert.deepEqual(targetCalls(f), []);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await completion.catch(() => undefined);
    rmSync(transactionRoot, { recursive: true, force: true });
    clean(f);
  }
});

test("a target signal cannot be masked by deployment mutation checks", async () => {
  const f = fixture();
  const runner = join(f.dir, "target-signal-runner.mjs");
  const transactionRoot = mkdtempSync(join(tmpdir(), "qm-update-target-signal-tmp-"));
  updateState(f, (state) => {
    state.targetConfigBody = "{}\n";
    state.targetSignalAtStart = true;
  });
  const updateModule = pathToFileURL(
    realpathSync(join(import.meta.dirname, "..", "src", "commands", "update.ts")),
  ).href;
  writeFileSync(
    runner,
    [
      `import { runUpdate } from ${JSON.stringify(updateModule)};`,
      `const config = ${JSON.stringify(f.config)};`,
      `const metadata = ${JSON.stringify(f.remote.metadata)};`,
      "const fetcher = async () => new Response(JSON.stringify(metadata), { status: 200 });",
      `const options = ${JSON.stringify({
        config: f.config,
        configDir: f.dir,
        configPath: f.configPath,
        sandboxDir: f.sandboxDir,
        target: f.config.target,
        yes: true,
        version: LATEST,
        testNpmPath: f.npmPath,
        testTargetPath: f.targetBin,
        testGetfaclPath: join(f.targetBin, "getfacl"),
        testTargetEnvironment: {
          QM_TEST_UPDATE_STATE: f.statePath,
          QM_TEST_UPDATE_TARGET_LOG: f.targetLog,
        },
        testNpmEnvironment: {
          UPDATE_STATE: f.statePath,
          UPDATE_NPM_LOG: f.npmLog,
          UPDATE_SIGSTORE_LOG: f.sigstoreLog,
          UPDATE_TARGET_LOG: f.targetLog,
        },
      })};`,
      "options.fetcher = fetcher;",
      "await runUpdate(options);",
    ].join("\n"),
  );
  const child = spawn(process.execPath, [runner], {
    cwd: f.dir,
    env: { ...process.env, TMPDIR: transactionRoot },
    stdio: ["ignore", "ignore", "pipe"],
  });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const completion = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolveCompletion, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolveCompletion({ code, signal }));
    },
  );
  try {
    const outcome = await completion;
    assert.equal(outcome.code, null, Buffer.concat(stderr).toString("utf8"));
    assert.equal(outcome.signal, "SIGTERM");
    assert.deepEqual(readdirSync(transactionRoot), []);
    assert.equal(pinnedVersion(f), LATEST);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await completion.catch(() => undefined);
    rmSync(transactionRoot, { recursive: true, force: true });
    clean(f);
  }
});

test("suspension stops and resumes the foreground npm process group", async () => {
  const f = fixture();
  const ready = join(f.dir, "suspend.ready");
  const signalLog = join(f.dir, "suspend.log");
  const runner = join(f.dir, "suspend-runner.mjs");
  updateState(f, (state) => {
    state.waitForSignal = true;
    state.signalHeartbeat = true;
    state.signalReady = ready;
    state.signalLog = signalLog;
    state.forwardedSignal = "SIGTERM";
  });
  const updateModule = pathToFileURL(
    realpathSync(join(import.meta.dirname, "..", "src", "commands", "update.ts")),
  ).href;
  writeFileSync(
    runner,
    [
      `import { runUpdate } from ${JSON.stringify(updateModule)};`,
      `const config = ${JSON.stringify(f.config)};`,
      `const metadata = ${JSON.stringify(f.remote.metadata)};`,
      "const fetcher = async () => new Response(JSON.stringify(metadata), { status: 200 });",
      `const options = ${JSON.stringify({
        config: f.config,
        configDir: f.dir,
        configPath: f.configPath,
        sandboxDir: f.sandboxDir,
        target: f.config.target,
        yes: true,
        version: LATEST,
        testNpmPath: f.npmPath,
        testTargetPath: f.targetBin,
        testNpmEnvironment: {
          UPDATE_STATE: f.statePath,
          UPDATE_NPM_LOG: f.npmLog,
          UPDATE_SIGSTORE_LOG: f.sigstoreLog,
          UPDATE_TARGET_LOG: f.targetLog,
        },
      })};`,
      "options.fetcher = fetcher;",
      "await runUpdate(options);",
    ].join("\n"),
  );
  const child = spawn(process.execPath, [runner], {
    cwd: f.dir,
    env: process.env,
    stdio: ["ignore", "ignore", "pipe"],
  });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const completion = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolveCompletion, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolveCompletion({ code, signal }));
    },
  );
  try {
    for (let attempt = 0; attempt < 250 && !existsSync(ready); attempt++) {
      await new Promise<void>((resolveWait) => setTimeout(resolveWait, 20));
    }
    assert.equal(existsSync(ready), true);
    for (
      let attempt = 0;
      attempt < 100 && (!existsSync(signalLog) || !readFileSync(signalLog, "utf8").includes("tick\n"));
      attempt++
    ) {
      await new Promise<void>((resolveWait) => setTimeout(resolveWait, 20));
    }
    assert.equal(existsSync(signalLog), true);
    child.kill("SIGTSTP");
    await new Promise<void>((resolveWait) => setTimeout(resolveWait, 150));
    const stoppedSize = statSync(signalLog).size;
    await new Promise<void>((resolveWait) => setTimeout(resolveWait, 250));
    assert.equal(statSync(signalLog).size, stoppedSize);
    child.kill("SIGCONT");
    for (let attempt = 0; attempt < 100 && statSync(signalLog).size === stoppedSize; attempt++) {
      await new Promise<void>((resolveWait) => setTimeout(resolveWait, 20));
    }
    assert.equal(statSync(signalLog).size > stoppedSize, true);
    child.kill("SIGTERM");
    const outcome = await completion;
    assert.equal(outcome.code, null, Buffer.concat(stderr).toString("utf8"));
    assert.equal(outcome.signal, "SIGTERM");
    assert.match(readFileSync(signalLog, "utf8"), /signal\n(?:tick\n)*done\n/);
    assert.deepEqual(targetCalls(f), []);
    assert.equal(pinnedVersion(f), CURRENT);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGCONT");
      child.kill("SIGKILL");
    }
    await completion.catch(() => undefined);
    clean(f);
  }
});

test("npm audit binds the package to the official SLSA workflow identity", async (t) => {
  await t.test("official registry origin accepts a trailing slash", async () => {
    const f = fixture();
    updateState(f, (state) => {
      (state.audit.verified as Array<Record<string, unknown>>)[0]!.registry = REGISTRY;
    });
    try {
      await runUpdate(updateOptions(f));
      assert.equal(pinnedVersion(f), LATEST);
    } finally {
      clean(f);
    }
  });

  await t.test("invalid signature audit results are rejected", async () => {
    const f = fixture();
    updateState(f, (state) => {
      state.audit = { ...state.audit, invalid: [{ reason: "bad signature" }] };
    });
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /did not verify exactly one signed QM/);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });

  await t.test("provenance from another workflow is rejected", async () => {
    const f = fixture();
    updateState(f, (state) => {
      state.audit = audit(LATEST, ".github/workflows/not-release.yml");
    });
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /provenance does not match the official release workflow/);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });

  await t.test("the trusted verifier rejects a different certificate identity", async () => {
    const f = fixture();
    updateState(f, (state) => void (state.failIdentity = true));
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /provenance certificate does not identify/);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });

  await t.test("Fulcio repository identity extensions are required", async () => {
    const f = fixture();
    updateState(f, (state) => {
      state.audit = audit(LATEST, undefined, { "1.3.6.1.4.1.57264.1.15": "1" });
    });
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /provenance certificate does not identify/);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });
});

test("the verified package manifest contains the exact shipped service set", async (t) => {
  for (const entry of [
    { name: "a missing shipped service", mutate: (services: Record<string, unknown>) => delete services.portal },
    {
      name: "an extra service",
      mutate: (services: Record<string, unknown>) => void (services.worker = MANIFEST.services.core),
    },
  ]) {
    await t.test(`${entry.name} is rejected`, async () => {
      const f = fixture();
      updateState(f, (state) => {
        const manifest = structuredClone(MANIFEST) as { services: Record<string, unknown> };
        entry.mutate(manifest.services);
        state.manifest = manifest;
      });
      try {
        await assert.rejects(runUpdate(updateOptions(f)), /must contain exactly the shipped QM service images/);
      } finally {
        clean(f);
      }
    });
  }
});

test("native npm changes only QM package-manager state and installs the complete verified tree", async () => {
  const f = fixture();
  try {
    const unrelated = join(f.dir, "node_modules", "unrelated", "native.node");
    const lifecycle = join(f.dir, "node_modules", ".deployment-build-complete");
    const hiddenLock = join(f.dir, "node_modules", ".package-lock.json");
    mkdirSync(dirname(unrelated), { recursive: true });
    writeFileSync(unrelated, "native-artifact");
    writeFileSync(lifecycle, "lifecycle-artifact");
    const rootPackage = deploymentPackage(f);
    rootPackage.description = "deployment metadata";
    (rootPackage.dependencies as Record<string, string>).unrelated = "2.0.0";
    writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(rootPackage, null, 2)}\n`);
    const rootLock = deploymentLock(f);
    const rootPackages = rootLock.packages as Record<string, Record<string, unknown>>;
    (rootPackages[""]!.dependencies as Record<string, string>).unrelated = "2.0.0";
    rootPackages["node_modules/unrelated"] = {
      version: "2.0.0",
      resolved: "https://registry.npmjs.org/unrelated/-/unrelated-2.0.0.tgz",
      integrity: OTHER_INTEGRITY,
    };
    writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(rootLock, null, 2)}\n`);
    const hiddenBefore = structuredClone(rootLock);
    hiddenBefore.packages = Object.fromEntries(Object.entries(rootPackages).filter(([key]) => key !== ""));
    writeFileSync(hiddenLock, `${JSON.stringify(hiddenBefore, null, 2)}\n`);
    const unrelatedInode = statSync(unrelated).ino;
    const lifecycleInode = statSync(lifecycle).ino;
    await runUpdate(updateOptions(f));
    assert.equal(readFileSync(unrelated, "utf8"), "native-artifact");
    assert.equal(readFileSync(lifecycle, "utf8"), "lifecycle-artifact");
    assert.equal(statSync(unrelated).ino, unrelatedInode);
    assert.equal(statSync(lifecycle).ino, lifecycleInode);
    const hidden = JSON.parse(readFileSync(hiddenLock, "utf8")) as Record<string, unknown>;
    assert.equal(hidden.lockfileVersion, 3);
    assert.equal(pinnedVersion(f), LATEST);
    assert.equal(deploymentPackage(f).description, "deployment metadata");
    assert.equal((deploymentPackage(f).dependencies as Record<string, string>).unrelated, "2.0.0");
    assert.deepEqual(
      (deploymentLock(f).packages as Record<string, unknown>)["node_modules/unrelated"],
      rootPackages["node_modules/unrelated"],
    );
    const live = join(f.dir, "node_modules", "@yc-software", "qm");
    assert.equal(readFileSync(join(live, "templates", "target-only.txt"), "utf8"), "target-template\n");
    assert.equal(existsSync(join(live, "templates", "old-only.txt")), false);
    assert.equal(
      readFileSync(join(live, "dist", "src", "contract.js"), "utf8"),
      "export const targetContract = true;\n",
    );
    invokeInstalled(f, "probe");
    assert.deepEqual(
      targetCalls(f).map((call) => call.args[0]),
      ["up", "probe"],
    );
    assert.match(targetCalls(f)[0]!.entry, /qm-update-.*\/verifier\/node_modules/);
    assert.match(targetCalls(f)[1]!.entry, /node_modules\/@yc-software\/qm/);
  } finally {
    clean(f);
  }
});

test("an existing hidden lock must exactly cover installed unrelated packages before npm", async (t) => {
  const prepare = (f: Fixture): Record<string, Record<string, unknown>> => {
    const packagePath = join(f.dir, "node_modules", "unrelated");
    mkdirSync(packagePath, { recursive: true });
    writeFileSync(join(packagePath, "package.json"), `${JSON.stringify({ name: "unrelated", version: "1.0.0" })}\n`);
    const lock = deploymentLock(f);
    const packages = lock.packages as Record<string, Record<string, unknown>>;
    packages["node_modules/unrelated"] = {
      version: "1.0.0",
      resolved: "https://registry.npmjs.org/unrelated/-/unrelated-1.0.0.tgz",
      integrity: OTHER_INTEGRITY,
    };
    writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
    return writeHiddenLock(f, lock);
  };

  await t.test("missing record", async () => {
    const f = fixture();
    try {
      const hidden = prepare(f);
      delete hidden["node_modules/unrelated"];
      const body = deploymentLock(f);
      body.packages = hidden;
      writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /missing installed package|does not cover installed package/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("mismatched record", async () => {
    const f = fixture();
    try {
      const hidden = prepare(f);
      hidden["node_modules/unrelated"]!.license = "mismatch";
      const body = deploymentLock(f);
      body.packages = hidden;
      writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
      await assert.rejects(
        runUpdate(updateOptions(f)),
        /must match package-lock\.json exactly|does not cover installed package/,
      );
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("installed package metadata mismatch", async () => {
    const f = fixture();
    try {
      const hidden = prepare(f);
      const body = deploymentLock(f);
      body.packages = hidden;
      writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
      const manifestPath = join(f.dir, "node_modules", "unrelated", "package.json");
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
      manifest.version = "1.0.1";
      writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /metadata must match package-lock\.json/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("extraneous hidden record", async () => {
    const f = fixture();
    try {
      const rogue = join(f.dir, "node_modules", "rogue");
      mkdirSync(rogue);
      writeFileSync(join(rogue, "package.json"), `${JSON.stringify({ name: "rogue", version: "1.0.0" })}\n`);
      const hidden = writeHiddenLock(f);
      hidden["node_modules/rogue"] = {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/rogue/-/rogue-1.0.0.tgz",
        integrity: OTHER_INTEGRITY,
      };
      const body = deploymentLock(f);
      body.packages = hidden;
      writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
      await assert.rejects(
        runUpdate(updateOptions(f)),
        /must match package-lock\.json exactly|does not cover installed package/,
      );
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("extraneous physical package without a hidden lock", async () => {
    const f = fixture();
    try {
      const rogue = join(f.dir, "node_modules", "rogue");
      mkdirSync(rogue);
      writeFileSync(join(rogue, "package.json"), `${JSON.stringify({ name: "rogue", version: "1.0.0" })}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /package-lock\.json does not cover installed package/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });
});

test("existing hidden locks may omit or stale only the QM package record during recovery", async (t) => {
  for (const state of ["missing", "stale"] as const) {
    await t.test(state, async () => {
      const f = fixture();
      try {
        const hidden = writeHiddenLock(f);
        if (state === "missing") delete hidden[`node_modules/${PACKAGE_NAME}`];
        else {
          hidden[`node_modules/${PACKAGE_NAME}`] = {
            version: "0.1.5",
            resolved: "https://registry.npmjs.org/@yc-software/qm/-/qm-0.1.5.tgz",
            integrity: OTHER_INTEGRITY,
            bin: { qm: "dist/bin/qm.js" },
          };
        }
        const body = deploymentLock(f);
        body.packages = hidden;
        writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
        await runUpdate(updateOptions(f));
        assert.equal(pinnedVersion(f), LATEST);
      } finally {
        clean(f);
      }
    });
  }
});

test("an existing hidden lock may omit a physically absent optional package", async () => {
  const f = fixture();
  const recordKey = "node_modules/platform-only";
  try {
    const lock = deploymentLock(f);
    const packages = lock.packages as Record<string, Record<string, unknown>>;
    packages[recordKey] = {
      version: "1.0.0",
      resolved: "https://registry.npmjs.org/platform-only/-/platform-only-1.0.0.tgz",
      integrity: OTHER_INTEGRITY,
      optional: true,
      os: ["darwin"],
    };
    writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
    writeHiddenLock(f, lock);
    const hiddenPath = join(f.dir, "node_modules", ".package-lock.json");
    const hidden = JSON.parse(readFileSync(hiddenPath, "utf8")) as { packages: Record<string, unknown> };
    delete hidden.packages[recordKey];
    writeFileSync(hiddenPath, `${JSON.stringify(hidden, null, 2)}\n`);
    updateState(f, (state) => void (state.omitHiddenLockRecord = recordKey));
    await runUpdate(updateOptions(f));
    assert.equal(pinnedVersion(f), LATEST);
  } finally {
    clean(f);
  }
});

test("malformed package locations are rejected in root and hidden locks before npm", async (t) => {
  const locations = [
    "node_modules/../node_modules/is-number",
    "node_modules/@scope/../node_modules/is-number",
    "node_modules/foo%2fbar/node_modules/is-number",
    "node_modules/foo\\bar/node_modules/is-number",
    "node_modules/bad name/node_modules/is-number",
  ];
  for (const source of ["root", "hidden"] as const) {
    for (const [index, location] of locations.entries()) {
      await t.test(`${source} ${index + 1}`, async () => {
        const f = fixture();
        try {
          const record = {
            version: "7.0.0",
            resolved: "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
            integrity: OTHER_INTEGRITY,
          };
          const lock = deploymentLock(f);
          const packages = lock.packages as Record<string, Record<string, unknown>>;
          if (source === "root") {
            packages[location] = record;
            writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
          } else {
            const installed = join(f.dir, "node_modules", "is-number");
            mkdirSync(installed);
            writeFileSync(
              join(installed, "package.json"),
              `${JSON.stringify({ name: "is-number", version: "7.0.0" })}\n`,
            );
            packages["node_modules/is-number"] = record;
            writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
            const hidden = writeHiddenLock(f, lock);
            delete hidden["node_modules/is-number"];
            hidden[location] = record;
            const body = deploymentLock(f);
            body.packages = hidden;
            writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
          }
          await assert.rejects(runUpdate(updateOptions(f)), /invalid npm package location/);
          assert.deepEqual(npmCalls(f), []);
          assert.equal(pinnedVersion(f), CURRENT);
        } finally {
          clean(f);
        }
      });
    }
  }
});

test("a newly generated hidden lock may omit unavailable root package records", async () => {
  const f = fixture();
  try {
    const recordKey = "node_modules/platform-only";
    const lock = deploymentLock(f);
    const packages = lock.packages as Record<string, Record<string, unknown>>;
    packages[recordKey] = {
      version: "1.0.0",
      resolved: "https://registry.npmjs.org/platform-only/-/platform-only-1.0.0.tgz",
      integrity: OTHER_INTEGRITY,
      optional: true,
      os: ["darwin"],
    };
    writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
    updateState(f, (state) => void (state.omitHiddenLockRecord = recordKey));
    await runUpdate(updateOptions(f));
    assert.deepEqual((deploymentLock(f).packages as Record<string, unknown>)[recordKey], packages[recordKey]);
    const hidden = JSON.parse(readFileSync(join(f.dir, "node_modules", ".package-lock.json"), "utf8")) as {
      packages: Record<string, unknown>;
    };
    assert.equal(hidden.packages[recordKey], undefined);
    assert.equal(pinnedVersion(f), LATEST);
  } finally {
    clean(f);
  }
});

test("a successful update reminds the operator to persist npm-owned state", async () => {
  const f = fixture();
  const messages: string[] = [];
  const originalLog = console.log;
  try {
    console.log = (...values: unknown[]) => void messages.push(values.map(String).join(" "));
    await runUpdate(updateOptions(f));
    assert.match(messages.join("\n"), /Review and commit package\.json and package-lock\.json/);
  } finally {
    console.log = originalLog;
    clean(f);
  }
});

test("unexpected native npm changes fail closed before deployment", async (t) => {
  await t.test("root package metadata", async () => {
    const f = fixture();
    updateState(f, (state) => void (state.mutationPackagePatch = { name: "changed" }));
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /changed beyond the exact/);
      assert.deepEqual(targetCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("unrelated lock record", async () => {
    const f = fixture();
    const lock = deploymentLock(f);
    (lock.packages as Record<string, unknown>)["node_modules/unrelated"] = {
      version: "1.0.0",
      resolved: "https://registry.npmjs.org/unrelated/-/unrelated-1.0.0.tgz",
      integrity: OTHER_INTEGRITY,
    };
    writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
    updateState(f, (state) => void (state.deleteLockRecord = "node_modules/unrelated"));
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /changed beyond the exact QM package records/);
      assert.deepEqual(targetCalls(f), []);
    } finally {
      clean(f);
    }
  });
});

test("workspace-managed deployments are rejected before verification", async () => {
  const f = fixture();
  try {
    const pkg = deploymentPackage(f);
    pkg.workspaces = ["./workspace-qm/"];
    writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
    const packageBefore = readFileSync(join(f.dir, "package.json"));
    const lockBefore = readFileSync(join(f.dir, "package-lock.json"));
    const live = join(f.dir, "node_modules", "@yc-software", "qm");
    const liveBefore = treeDigest(live);
    await assert.rejects(runUpdate(updateOptions(f)), /declares npm workspaces/);
    assert.deepEqual(npmCalls(f), []);
    assert.deepEqual(readFileSync(join(f.dir, "package.json")), packageBefore);
    assert.deepEqual(readFileSync(join(f.dir, "package-lock.json")), lockBefore);
    assert.equal(treeDigest(live), liveBefore);
  } finally {
    clean(f);
  }
});

test("npm overrides are rejected before package mutation", async (t) => {
  for (const overrides of [{ [`${PACKAGE_NAME}@*`]: CURRENT }, { unrelated: `$${PACKAGE_NAME}` }]) {
    await t.test(JSON.stringify(overrides), async () => {
      const f = fixture();
      try {
        const pkg = deploymentPackage(f);
        pkg.overrides = overrides;
        writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
        const packageBefore = readFileSync(join(f.dir, "package.json"));
        const lockBefore = readFileSync(join(f.dir, "package-lock.json"));
        const liveBefore = treeDigest(join(f.dir, "node_modules", "@yc-software", "qm"));
        await assert.rejects(runUpdate(updateOptions(f)), /must not override/);
        assert.deepEqual(npmCalls(f), []);
        assert.deepEqual(readFileSync(join(f.dir, "package.json")), packageBefore);
        assert.deepEqual(readFileSync(join(f.dir, "package-lock.json")), lockBefore);
        assert.equal(treeDigest(join(f.dir, "node_modules", "@yc-software", "qm")), liveBefore);
      } finally {
        clean(f);
      }
    });
  }
});

test("offline native npm accepts only integrity-protected registry inputs", async (t) => {
  for (const entry of [
    { source: "manifest", field: "devDependencies", value: [] },
    { source: "root lock", field: "peerDependencies", value: 42 },
    { source: "hidden lock", field: "optionalDependencies", value: "oops" },
  ]) {
    await t.test(`invalid ${entry.source} ${entry.field} shape`, async () => {
      const f = fixture();
      try {
        if (entry.source === "manifest") {
          const pkg = deploymentPackage(f);
          pkg[entry.field] = entry.value;
          writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
        } else if (entry.source === "root lock") {
          const lock = deploymentLock(f);
          const packages = lock.packages as Record<string, Record<string, unknown>>;
          packages[`node_modules/${PACKAGE_NAME}`]![entry.field] = entry.value;
          writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
        } else {
          const hidden = writeHiddenLock(f);
          hidden[`node_modules/${PACKAGE_NAME}`]![entry.field] = entry.value;
          const body = deploymentLock(f);
          body.packages = hidden;
          writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
        }
        await assert.rejects(runUpdate(updateOptions(f)), /contains an invalid .*Dependencies object/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }

  for (const entry of [
    { name: "root bundle declaration", field: "bundleDependencies", value: [] },
    { name: "root peer metadata shape", field: "peerDependenciesMeta", value: true },
    { name: "root peer metadata entry", field: "peerDependenciesMeta", value: { peer: { optional: "yes" } } },
  ]) {
    await t.test(`invalid ${entry.name}`, async () => {
      const f = fixture();
      try {
        const pkg = deploymentPackage(f);
        pkg[entry.field] = entry.value;
        writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
        await assert.rejects(runUpdate(updateOptions(f)), /bundleDependencies|peerDependenciesMeta/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }

  for (const entry of [
    { name: "legacy bundledDependencies", field: "bundledDependencies", value: [] },
    { name: "invalid bundle package name", field: "bundleDependencies", value: ["bad name"] },
    { name: "invalid peer metadata", field: "peerDependenciesMeta", value: { peer: { optional: 1 } } },
  ]) {
    await t.test(`lock record ${entry.name}`, async () => {
      const f = fixture();
      try {
        const lock = deploymentLock(f);
        const packages = lock.packages as Record<string, Record<string, unknown>>;
        packages[`node_modules/${PACKAGE_NAME}`]![entry.field] = entry.value;
        writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
        await assert.rejects(runUpdate(updateOptions(f)), /bundleDependencies|npm package name|peerDependenciesMeta/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }

  for (const kind of ["absolute", "traversal"] as const) {
    await t.test(`hidden lock ${kind} bin key cannot delete an external file`, async () => {
      const f = fixture();
      const external = mkdtempSync(join(tmpdir(), "qm-update-bin-victim-"));
      const victim = join(external, "victim");
      try {
        writeFileSync(victim, "preserve\n");
        const hidden = writeHiddenLock(f);
        const record = hidden[`node_modules/${PACKAGE_NAME}`]!;
        record.bin = {
          qm: "dist/bin/qm.js",
          [kind === "absolute" ? victim : "../../../victim"]: "dist/bin/qm.js",
        };
        const body = deploymentLock(f);
        body.packages = hidden;
        writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
        await assert.rejects(runUpdate(updateOptions(f)), /unsafe bin declaration/);
        assert.equal(readFileSync(victim, "utf8"), "preserve\n");
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
        rmSync(external, { recursive: true, force: true });
      }
    });
  }

  await t.test("installed package bin targets must remain inside regular package files", async () => {
    const f = fixture();
    try {
      const manifestPath = join(f.dir, "node_modules", "@yc-software", "qm", "package.json");
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
      manifest.bin = { qm: "../../../../outside" };
      writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /unsafe bin declaration/);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });

  await t.test("trusted npm rejects a stale root package projection before deployment mutation", async () => {
    const f = fixture();
    try {
      const pkg = deploymentPackage(f);
      pkg.license = "Apache-2.0";
      writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      const lock = deploymentLock(f);
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      packages[""]!.license = "ISC";
      writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /would be normalized by npm/);
      assert.equal(
        npmCalls(f).filter(
          (call) => call.cwd.endsWith("/project-check") && call.args.includes("--package-lock-only=true"),
        ).length,
        1,
      );
      assert.equal(pinnedVersion(f), CURRENT);
      assert.deepEqual(targetCalls(f), []);
    } finally {
      clean(f);
    }
  });

  for (const entry of [
    { name: "hosted shorthand dependency", spec: "user/repo" },
    { name: "package-name local directory ambiguity", spec: "@scope/source" },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        const pkg = deploymentPackage(f);
        (pkg.dependencies as Record<string, string>).unrelated = entry.spec;
        writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
        await assert.rejects(runUpdate(updateOptions(f)), /valid npm registry|official npm registry/);
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }

  await t.test("nested Git override", async () => {
    const f = fixture();
    try {
      const pkg = deploymentPackage(f);
      pkg.overrides = { unrelated: { transitive: "github:user/repo" } };
      writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /must not override/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  for (const entry of [
    { name: "Git lock resolution", resolved: "git+https://github.com/user/repo.git", integrity: OTHER_INTEGRITY },
    {
      name: "noncanonical integrity",
      resolved: "https://registry.npmjs.org/unrelated/-/unrelated-1.0.0.tgz",
      integrity: "sha512-",
    },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        const pkg = deploymentPackage(f);
        (pkg.dependencies as Record<string, string>).unrelated = "1.0.0";
        writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
        const lock = deploymentLock(f);
        const packages = lock.packages as Record<string, Record<string, unknown>>;
        (packages[""]!.dependencies as Record<string, string>).unrelated = "1.0.0";
        packages["node_modules/unrelated"] = {
          version: "1.0.0",
          resolved: entry.resolved,
          integrity: entry.integrity,
        };
        writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
        await assert.rejects(runUpdate(updateOptions(f)), /integrity-protected official npm registry tarball/);
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }

  for (const entry of [
    { name: "mismatched tarball package", recordName: undefined, resolved: tarball(LATEST) },
    { name: "unbacked package-name alias", recordName: PACKAGE_NAME, resolved: tarball(LATEST) },
    {
      name: "reused verified QM integrity",
      recordName: undefined,
      resolved: `https://registry.npmjs.org/is-number/-/is-number-${LATEST}.tgz`,
    },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        const pkg = deploymentPackage(f);
        (pkg.dependencies as Record<string, string>)["is-number"] = LATEST;
        writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
        const lock = deploymentLock(f);
        const packages = lock.packages as Record<string, Record<string, unknown>>;
        (packages[""]!.dependencies as Record<string, string>)["is-number"] = LATEST;
        packages["node_modules/is-number"] = {
          ...(entry.recordName ? { name: entry.recordName } : {}),
          version: LATEST,
          resolved: entry.resolved,
          integrity: INTEGRITY,
        };
        writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
        await assert.rejects(
          runUpdate(updateOptions(f)),
          /official npm registry tarball|npm alias|reuse the verified QM package/,
        );
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }

  await t.test("nested scoped registry package", async () => {
    const f = fixture();
    try {
      const pkg = deploymentPackage(f);
      (pkg.dependencies as Record<string, string>).parent = "1.0.0";
      writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      const lock = deploymentLock(f);
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      (packages[""]!.dependencies as Record<string, string>).parent = "1.0.0";
      packages["node_modules/parent"] = {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/parent/-/parent-1.0.0.tgz",
        integrity: OTHER_INTEGRITY,
        dependencies: { "@scope/child": "2.0.0" },
      };
      packages["node_modules/parent/node_modules/@scope/child"] = {
        version: "2.0.0",
        resolved: "https://registry.npmjs.org/@scope/child/-/child-2.0.0.tgz",
        integrity: OTHER_INTEGRITY,
      };
      writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      await runUpdate(updateOptions(f));
      assert.equal(pinnedVersion(f), LATEST);
    } finally {
      clean(f);
    }
  });

  await t.test("npm-style package bundles remain bound to their parent tarball", async () => {
    const f = fixture();
    try {
      const pkg = deploymentPackage(f);
      (pkg.dependencies as Record<string, string>)["bundled-parent"] = "1.0.0";
      writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      const lock = deploymentLock(f);
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      (packages[""]!.dependencies as Record<string, string>)["bundled-parent"] = "1.0.0";
      const parentLocation = "node_modules/bundled-parent";
      packages[parentLocation] = {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/bundled-parent/-/bundled-parent-1.0.0.tgz",
        integrity: OTHER_INTEGRITY,
        bundleDependencies: ["bundle-root"],
      };
      const locations = Array.from({ length: 143 }, (_, index) =>
        index === 142
          ? parentLocation + "/node_modules/bundle-root/node_modules/nested-child"
          : parentLocation + "/node_modules/" + (index === 0 ? "bundle-root" : "bundle-child-" + index),
      );
      for (const location of [parentLocation, ...locations]) {
        const name = location.slice(location.lastIndexOf("/") + 1);
        const path = join(f.dir, location);
        mkdirSync(path, { recursive: true });
        writeFileSync(join(path, "package.json"), `${JSON.stringify({ name, version: "1.0.0" })}\n`);
        if (location !== parentLocation) packages[location] = { version: "1.0.0", inBundle: true };
      }
      writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      const hidden = structuredClone(lock);
      hidden.packages = Object.fromEntries(Object.entries(packages).filter(([location]) => location !== ""));
      writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(hidden, null, 2)}\n`);
      await runUpdate(updateOptions(f));
      assert.equal(pinnedVersion(f), LATEST);
      const finalHidden = JSON.parse(readFileSync(join(f.dir, "node_modules", ".package-lock.json"), "utf8")) as {
        packages: Record<string, unknown>;
      };
      assert.equal(
        Object.values(finalHidden.packages).filter((record) => (record as Record<string, unknown>).inBundle === true)
          .length,
        143,
      );
    } finally {
      clean(f);
    }
  });

  for (const entry of [
    { name: "unbound bundled record", patch: {} },
    { name: "bundled record with integrity", patch: { integrity: OTHER_INTEGRITY } },
    { name: "bundled package alias", patch: { name: "different-name" } },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        const lock = deploymentLock(f);
        const packages = lock.packages as Record<string, Record<string, unknown>>;
        packages["node_modules/unbound/node_modules/child"] = {
          version: "1.0.0",
          inBundle: true,
          ...entry.patch,
        };
        writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
        await assert.rejects(
          runUpdate(updateOptions(f)),
          /invalid bundled package record|not bound to an integrity|npm alias/,
        );
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }

  await t.test("invalid inBundle markers", async () => {
    const f = fixture();
    try {
      const lock = deploymentLock(f);
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      packages["node_modules/invalid-bundle"] = {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/invalid-bundle/-/invalid-bundle-1.0.0.tgz",
        integrity: OTHER_INTEGRITY,
        inBundle: false,
      };
      writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /invalid inBundle marker/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("npm alias", async () => {
    const f = fixture();
    try {
      const pkg = deploymentPackage(f);
      (pkg.dependencies as Record<string, string>).alias = "npm:is-number@^7";
      writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      const lock = deploymentLock(f);
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      (packages[""]!.dependencies as Record<string, string>).alias = "npm:is-number@^7";
      packages["node_modules/alias"] = {
        name: "is-number",
        version: "7.0.0",
        resolved: "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
        integrity: OTHER_INTEGRITY,
      };
      writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /must not use an npm alias/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("target alias without an installed lock record", async () => {
    const f = fixture();
    try {
      const pkg = deploymentPackage(f);
      (pkg.dependencies as Record<string, string>)["qm-copy"] = `npm:${PACKAGE_NAME}@${LATEST}`;
      writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      const lock = deploymentLock(f);
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      (packages[""]!.dependencies as Record<string, string>)["qm-copy"] = `npm:${PACKAGE_NAME}@${LATEST}`;
      writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /must not use an npm alias/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("target alias in a nested lock dependency", async () => {
    const f = fixture();
    try {
      const pkg = deploymentPackage(f);
      (pkg.dependencies as Record<string, string>).parent = "1.0.0";
      writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      const lock = deploymentLock(f);
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      (packages[""]!.dependencies as Record<string, string>).parent = "1.0.0";
      packages["node_modules/parent"] = {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/parent/-/parent-1.0.0.tgz",
        integrity: OTHER_INTEGRITY,
        dependencies: { "qm-copy": `npm:${PACKAGE_NAME}@${LATEST}` },
      };
      writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /must not use an npm alias/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });
});

test("automatic update rejects local QM package links before npm", async (t) => {
  await t.test("file dependency with an external source tree", async () => {
    const f = fixture();
    const sourceRoot = mkdtempSync(join(tmpdir(), "qm-update-local-source-"));
    const source = join(sourceRoot, "qm");
    const sentinel = join(source, "node_modules", "victim-sentinel");
    try {
      const live = join(f.dir, "node_modules", "@yc-software", "qm");
      renameSync(live, source);
      mkdirSync(dirname(sentinel), { recursive: true });
      writeFileSync(sentinel, "preserve\n");
      symlinkSync(source, live);
      const pkg = deploymentPackage(f);
      (pkg.dependencies as Record<string, string>)[PACKAGE_NAME] = `file:${source}`;
      writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /regular file inside node_modules/);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(readFileSync(sentinel, "utf8"), "preserve\n");
    } finally {
      clean(f);
      rmSync(sourceRoot, { recursive: true, force: true });
    }
  });

  await t.test("exact pin with an old live package link", async () => {
    const f = fixture();
    const sourceRoot = mkdtempSync(join(tmpdir(), "qm-update-old-link-"));
    try {
      const live = join(f.dir, "node_modules", "@yc-software", "qm");
      const source = join(sourceRoot, "qm");
      renameSync(live, source);
      symlinkSync(source, live);
      await assert.rejects(runUpdate(updateOptions(f)), /regular file inside node_modules/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
      rmSync(sourceRoot, { recursive: true, force: true });
    }
  });

  for (const lock of ["package-lock.json", "node_modules/.package-lock.json"] as const) {
    await t.test("local target record in " + lock, async () => {
      const f = fixture();
      try {
        const path = join(f.dir, lock);
        const body =
          lock === "package-lock.json"
            ? deploymentLock(f)
            : { lockfileVersion: 3, packages: {} as Record<string, unknown> };
        const packages = body.packages as Record<string, unknown>;
        packages[`node_modules/${PACKAGE_NAME}`] = { resolved: "../local-qm", link: true };
        writeFileSync(path, `${JSON.stringify(body, null, 2)}\n`);
        await assert.rejects(runUpdate(updateOptions(f)), /must contain an exact registry package record/);
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }

  await t.test("local resolved target record", async () => {
    const f = fixture();
    try {
      const lock = deploymentLock(f);
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      packages[`node_modules/${PACKAGE_NAME}`] = {
        version: CURRENT,
        resolved: "file:../local-qm",
        integrity: INTEGRITY,
      };
      writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /official npm registry tarball/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });
});

test("automatic update requires a reviewed npm lockfile version 3", async (t) => {
  for (const lockfileVersion of [1, 2]) {
    await t.test(`lockfile version ${lockfileVersion}`, async () => {
      const f = fixture();
      try {
        const lock = deploymentLock(f);
        lock.lockfileVersion = lockfileVersion;
        if (lockfileVersion === 1) delete lock.packages;
        lock.dependencies = { [PACKAGE_NAME]: { version: CURRENT } };
        writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
        await assert.rejects(runUpdate(updateOptions(f)), /reviewed and upgraded to npm lockfile version 3/);
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }
});

test("native npm converges ordinary interrupted package-manager states", async (t) => {
  const cases: Array<{ name: string; arrange: (f: Fixture) => void }> = [
    {
      name: "new pin with old installation",
      arrange: (f) => {
        const pkg = deploymentPackage(f);
        (pkg.dependencies as Record<string, string>)[PACKAGE_NAME] = LATEST;
        writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      },
    },
    {
      name: "old pin with new installation",
      arrange: (f) => {
        const installedPath = join(f.dir, "node_modules", "@yc-software", "qm", "package.json");
        const installed = JSON.parse(readFileSync(installedPath, "utf8")) as Record<string, unknown>;
        installed.version = LATEST;
        writeFileSync(installedPath, `${JSON.stringify(installed, null, 2)}\n`);
      },
    },
    {
      name: "missing installation",
      arrange: (f) => rmSync(join(f.dir, "node_modules", "@yc-software"), { recursive: true }),
    },
  ];
  for (const entry of cases) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        entry.arrange(f);
        await runUpdate(updateOptions(f));
        assert.equal(pinnedVersion(f), LATEST);
        assert.equal(
          npmCalls(f).filter((call) => call.cwd === realpathSync(f.dir) && call.args[0] === "install").length,
          1,
        );
        assert.equal(targetCalls(f).length, 1);
      } finally {
        clean(f);
      }
    });
  }
});

test("a same-version tree mismatch requires npm ci or tracked restore", async () => {
  const f = fixture(LATEST, LATEST);
  updateState(f, (state) => void (state.tamperMutationTree = true));
  try {
    await assert.rejects(runUpdate(updateOptions(f)), /restore tracked package files and run npm ci/);
    assert.equal(
      npmCalls(f).filter((call) => call.cwd === realpathSync(f.dir) && call.args[0] === "install").length,
      1,
    );
    assert.deepEqual(targetCalls(f), []);
  } finally {
    clean(f);
  }
});

test("a hard-linked file in the installed registry package is rejected before deployment", async () => {
  const f = fixture(LATEST, LATEST);
  const linkedPath = `node_modules/${PACKAGE_NAME}/dist/src/contract.js`;
  updateState(f, (state) => void (state.hardlinkMutationPath = linkedPath));
  try {
    await assert.rejects(runUpdate(updateOptions(f)), /must not have hard links outside node_modules/);
    assert.equal(statSync(join(f.dir, linkedPath)).nlink, 2);
    assert.deepEqual(targetCalls(f), []);
  } finally {
    clean(f);
  }
});

test("npm latest metadata is revalidated immediately before package mutation", async () => {
  const f = fixture();
  let latestRequests = 0;
  const fetcher = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = requestUrl(input);
    if (url === "https://registry.npmjs.org/@yc-software%2fqm/latest") {
      latestRequests++;
      const body = structuredClone(f.remote.metadata);
      if (latestRequests === 2) body.gitHead = "b".repeat(40);
      return new Response(JSON.stringify(body), { status: 200 });
    }
    return f.fetcher(input, init);
  }) as typeof fetch;
  try {
    await assert.rejects(runUpdate(updateOptions(f, { fetcher })), /metadata changed during verification/);
    assert.equal(latestRequests, 2);
    assert.equal(
      npmCalls(f).some((call) => call.cwd === realpathSync(f.dir) && call.args[0] === "install"),
      false,
    );
    assert.equal(pinnedVersion(f), CURRENT);
  } finally {
    clean(f);
  }
});

test("post-deployment checks reject guarded input and installed-tree drift", async (t) => {
  for (const entry of [
    { name: "configuration", mutation: "config" as const, exit: false, error: /config.*changed during the QM update/ },
    {
      name: "installed package",
      mutation: "package" as const,
      exit: true,
      error: /does not match the independently verified/,
    },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      updateState(f, (state) => {
        state.targetMutation = entry.mutation;
        if (entry.exit) state.targetExit = 17;
      });
      try {
        await assert.rejects(runUpdate(updateOptions(f)), entry.error);
        assert.equal(targetCalls(f).length, 1);
      } finally {
        clean(f);
      }
    });
  }
});

test("AWS deployment may persist only its complete validated image pin", async (t) => {
  const updates = {
    AWS_DEPLOY_IMAGE_VERSION: "8",
    AWS_DEPLOY_EXEC_ROLE_ARN: "arn:aws:iam::123456789012:role/acme-qm-microvm-exec",
    AWS_DEPLOY_IMAGE_SOURCE_SHA256: "b".repeat(64),
  };
  await t.test("complete provider-owned pin", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    try {
      const original = readFileSync(f.configPath, "utf8");
      const expected = updateConfigCoreEnv(original, updates);
      updateState(f, (state) => void (state.targetConfigBody = expected));
      await runUpdate(updateOptions(f));
      assert.equal(readFileSync(f.configPath, "utf8"), expected);
    } finally {
      clean(f);
    }
  });

  for (const entry of [
    {
      name: "partial pin",
      body: (original: string) =>
        updateConfigCoreEnv(original, { AWS_DEPLOY_IMAGE_VERSION: updates.AWS_DEPLOY_IMAGE_VERSION }),
    },
    {
      name: "invalid pin",
      body: (original: string) =>
        updateConfigCoreEnv(original, { ...updates, AWS_DEPLOY_IMAGE_SOURCE_SHA256: "not-a-digest" }),
    },
    {
      name: "unrelated configuration change",
      body: (original: string) =>
        updateConfigCoreEnv(original, updates).replace("https://qm.example.com", "https://changed.example.com"),
    },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture(CURRENT, LATEST, "aws");
      try {
        updateState(f, (state) => void (state.targetConfigBody = entry.body(readFileSync(f.configPath, "utf8"))));
        await assert.rejects(runUpdate(updateOptions(f)), /changed unexpectedly during the AWS deployment/);
      } finally {
        clean(f);
      }
    });
  }

  await t.test("configuration mode change", async () => {
    const f = fixture(CURRENT, LATEST, "aws");
    try {
      updateState(f, (state) => void (state.targetConfigMode = 0o400));
      await assert.rejects(runUpdate(updateOptions(f)), /changed mode during the QM update/);
    } finally {
      clean(f);
    }
  });
});

test("pre-activation failures leave deployment files and installation unchanged", async (t) => {
  const cases: Array<{
    name: string;
    configure: (f: Fixture) => void;
    error: RegExp;
  }> = [
    {
      name: "isolated install failure",
      configure: (f) => updateState(f, (state) => void (state.failInstall = true)),
      error: /isolated QM package install failed/,
    },
    {
      name: "signature audit failure",
      configure: (f) => updateState(f, (state) => void (state.failAudit = true)),
      error: /QM package signature verification failed/,
    },
    {
      name: "native npm interruption",
      configure: (f) => updateState(f, (state) => void (state.failMutation = true)),
      error: /confirm no npm child remains/,
    },
    {
      name: "unsafe installed package metadata",
      configure: (f) => updateState(f, (state) => void (state.packagePatch = { scripts: { postinstall: "evil" } })),
      error: /package metadata is not safe for deployment/,
    },
    {
      name: "extra package executable",
      configure: (f) =>
        updateState(
          f,
          (state) => void (state.packagePatch = { bin: { qm: "dist/bin/qm.js", other: "dist/bin/qm.js" } }),
        ),
      error: /package metadata is not safe for deployment/,
    },
    {
      name: "unsupported deployment lockfile",
      configure: (f) => {
        const lock = deploymentLock(f);
        lock.lockfileVersion = 4;
        writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      },
      error: /reviewed and upgraded to npm lockfile version 3/,
    },
  ];
  for (const entry of cases) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        entry.configure(f);
        const packageBefore = readFileSync(join(f.dir, "package.json"));
        const lockBefore = readFileSync(join(f.dir, "package-lock.json"));
        const installedBefore = readFileSync(join(f.dir, "node_modules", "@yc-software", "qm", "package.json"));
        await assert.rejects(runUpdate(updateOptions(f)), entry.error);
        assert.deepEqual(readFileSync(join(f.dir, "package.json")), packageBefore);
        assert.deepEqual(readFileSync(join(f.dir, "package-lock.json")), lockBefore);
        assert.deepEqual(
          readFileSync(join(f.dir, "node_modules", "@yc-software", "qm", "package.json")),
          installedBefore,
        );
      } finally {
        clean(f);
      }
    });
  }
});

test("automatic update protects every local deployment input tree", async (t) => {
  for (const entry of ["sandbox", "plugins", "skills"] as const) {
    await t.test(entry, async () => {
      const f = fixture();
      const external = mkdtempSync(join(tmpdir(), "qm-update-skill-input-"));
      try {
        let path: string;
        if (entry === "sandbox") {
          path = join(f.sandboxDir, "input.txt");
        } else if (entry === "plugins") {
          path = join(f.dir, "plugins", "example", "Dockerfile");
          mkdirSync(dirname(path), { recursive: true });
        } else {
          path = join(external, "input.txt");
          f.config.skills = [external];
          writeConfig(f);
        }
        writeFileSync(path, entry === "plugins" ? "FROM scratch\n" : "input\n");
        chmodSync(path, 0o666);
        await assert.rejects(runUpdate(updateOptions(f)), /must not be writable by group or other users/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
        rmSync(external, { recursive: true, force: true });
      }
    });
  }

  await t.test("environment file", async () => {
    const f = fixture();
    const environmentPath = join(f.dir, ".env");
    try {
      writeFileSync(environmentPath, "SECRET=value\n");
      chmodSync(environmentPath, 0o666);
      await assert.rejects(runUpdate(updateOptions(f)), /must not be writable by group or other users/);
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });

  await t.test("target mutation", async () => {
    const f = fixture();
    try {
      updateState(f, (state) => void (state.targetSandboxMutationPath = join(f.sandboxDir, "changed.txt")));
      await assert.rejects(runUpdate(updateOptions(f)), /sandbox changed during the QM update/);
      assert.equal(pinnedVersion(f), LATEST);
      assert.equal(targetCalls(f).length, 1);
    } finally {
      clean(f);
    }
  });

  await t.test("environment mutation", async () => {
    const f = fixture();
    const environmentPath = join(f.dir, ".env");
    try {
      writeFileSync(environmentPath, "SECRET=value\n");
      updateState(f, (state) => void (state.targetEnvironmentMutationPath = environmentPath));
      await assert.rejects(runUpdate(updateOptions(f)), /\.env changed during the QM update/);
      assert.equal(pinnedVersion(f), LATEST);
      assert.equal(targetCalls(f).length, 1);
    } finally {
      clean(f);
    }
  });
});

test("a target deployment failure retains the verified pin for normal qm up reconciliation", async () => {
  const f = fixture();
  updateState(f, (state) => void (state.targetExit = 17));
  try {
    await assert.rejects(
      runUpdate(updateOptions(f)),
      /remains pinned and verified;.*review and commit package\.json and package-lock\.json/,
    );
    assert.equal(pinnedVersion(f), LATEST);
    const installed = JSON.parse(
      readFileSync(join(f.dir, "node_modules", "@yc-software", "qm", "package.json"), "utf8"),
    ) as Record<string, unknown>;
    assert.equal(installed.version, LATEST);
    assert.equal(targetCalls(f).length, 1);
  } finally {
    clean(f);
  }
});

test("deployment configuration must remain an unlinked file in the project root", async (t) => {
  await t.test("symbolic link", async () => {
    const f = fixture();
    try {
      const target = join(f.dir, "actual.config.jsonc");
      renameSync(f.configPath, target);
      symlinkSync(target, f.configPath);
      await assert.rejects(runUpdate(updateOptions(f)), /must be an unlinked current-user configuration file/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("hard link", async () => {
    const f = fixture();
    try {
      linkSync(f.configPath, join(f.dir, "config-alias.jsonc"));
      await assert.rejects(runUpdate(updateOptions(f)), /must be an unlinked current-user configuration file/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("different project directory", async () => {
    const f = fixture();
    const outsideRoot = mkdtempSync(join(tmpdir(), "qm-update-config-"));
    try {
      const outside = join(outsideRoot, "qm.config.jsonc");
      writeFileSync(outside, readFileSync(f.configPath));
      await assert.rejects(
        runUpdate(updateOptions(f, { configPath: outside })),
        /regular configuration file directly inside/,
      );
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
      rmSync(outsideRoot, { recursive: true, force: true });
    }
  });

  await t.test("hard link created by the target", async () => {
    const f = fixture();
    try {
      const alias = join(f.dir, "target-config-alias.jsonc");
      writeFileSync(alias, readFileSync(f.configPath));
      updateState(f, (state) => void (state.targetConfigHardlinkPath = alias));
      await assert.rejects(runUpdate(updateOptions(f)), /must not be hard-linked/);
    } finally {
      clean(f);
    }
  });
});

test("node_modules cannot redirect npm into external directories or hard links", async (t) => {
  for (const kind of ["nested directory link", "scope link", "external hard link"] as const) {
    await t.test(kind, async () => {
      const f = fixture();
      const external = mkdtempSync(join(tmpdir(), "qm-update-node-modules-victim-"));
      const sentinel = join(external, "sentinel");
      try {
        writeFileSync(sentinel, "preserve\n");
        if (kind === "nested directory link") {
          const packageDir = join(f.dir, "node_modules", "ansi-regex");
          mkdirSync(packageDir);
          symlinkSync(external, join(packageDir, "node_modules"));
        } else if (kind === "scope link") {
          symlinkSync(external, join(f.dir, "node_modules", "@colors"));
        } else {
          linkSync(sentinel, join(f.dir, "node_modules", "external-hardlink"));
        }
        await assert.rejects(
          runUpdate(updateOptions(f)),
          kind === "external hard link" ? /hard links outside node_modules/ : /regular file inside node_modules/,
        );
        assert.deepEqual(npmCalls(f), []);
        assert.equal(readFileSync(sentinel, "utf8"), "preserve\n");
      } finally {
        clean(f);
        rmSync(external, { recursive: true, force: true });
      }
    });
  }

  await t.test("external hard-linked symlink", async () => {
    const f = fixture();
    const external = mkdtempSync(join(tmpdir(), "qm-update-node-modules-symlink-victim-"));
    try {
      const binDirectory = join(f.dir, "node_modules", ".bin");
      const bin = join(binDirectory, "qm");
      const alias = join(external, "qm-link");
      mkdirSync(binDirectory);
      symlinkSync("../@yc-software/qm/dist/bin/qm.js", bin);
      const linked = spawnSync("/bin/ln", ["-P", bin, alias], { encoding: "utf8" });
      assert.equal(linked.status, 0, linked.stderr);
      await assert.rejects(runUpdate(updateOptions(f)), /hard links outside node_modules/);
      assert.equal(lstatSync(alias).nlink, 2);
      assert.equal(readlinkSync(alias), "../@yc-software/qm/dist/bin/qm.js");
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
      rmSync(external, { recursive: true, force: true });
    }
  });
});

test("the current QM package cannot claim another package executable", async (t) => {
  for (const source of ["root lock", "hidden lock", "installed manifest"] as const) {
    await t.test(source, async () => {
      const f = fixture();
      try {
        const binDirectory = join(f.dir, "node_modules", ".bin");
        const unrelatedBin = join(binDirectory, "unrelated");
        mkdirSync(binDirectory);
        symlinkSync("../@yc-software/qm/dist/bin/qm.js", unrelatedBin);
        if (source === "root lock") {
          const lock = deploymentLock(f);
          const packages = lock.packages as Record<string, Record<string, unknown>>;
          packages[`node_modules/${PACKAGE_NAME}`]!.bin = { unrelated: "dist/bin/qm.js" };
          writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
        } else if (source === "hidden lock") {
          const hidden = writeHiddenLock(f);
          hidden[`node_modules/${PACKAGE_NAME}`]!.bin = { unrelated: "dist/bin/qm.js" };
          const body = deploymentLock(f);
          body.packages = hidden;
          writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
        } else {
          const manifestPath = join(f.dir, "node_modules", "@yc-software", "qm", "package.json");
          const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
          manifest.bin = { unrelated: "dist/bin/qm.js" };
          writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
        }
        await assert.rejects(runUpdate(updateOptions(f)), /must declare only the qm executable/);
        assert.equal(readlinkSync(unrelatedBin), "../@yc-software/qm/dist/bin/qm.js");
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }

  await t.test("hidden string bin", async () => {
    const f = fixture();
    try {
      const binDirectory = join(f.dir, "node_modules", ".bin");
      const numberedBin = join(binDirectory, "0");
      mkdirSync(binDirectory);
      symlinkSync("../@yc-software/qm/dist/bin/qm.js", numberedBin);
      const hidden = writeHiddenLock(f);
      hidden[`node_modules/${PACKAGE_NAME}`]!.bin = "dist/bin/qm.js";
      const body = deploymentLock(f);
      body.packages = hidden;
      writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /must use an object bin declaration/);
      assert.equal(readlinkSync(numberedBin), "../@yc-software/qm/dist/bin/qm.js");
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });
});

test("the current QM package cannot reach unrelated installed packages", async (t) => {
  for (const source of ["root lock", "hidden lock", "installed manifest"] as const) {
    await t.test(source, async () => {
      const f = fixture();
      try {
        const unrelated = join(f.dir, "node_modules", "unrelated");
        const sentinel = join(unrelated, "sentinel");
        mkdirSync(unrelated);
        writeFileSync(join(unrelated, "package.json"), `${JSON.stringify({ name: "unrelated", version: "1.0.0" })}\n`);
        writeFileSync(sentinel, "preserve\n");
        const lock = deploymentLock(f);
        const packages = lock.packages as Record<string, Record<string, unknown>>;
        packages["node_modules/unrelated"] = {
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/unrelated/-/unrelated-1.0.0.tgz",
          integrity: OTHER_INTEGRITY,
        };
        if (source === "root lock") {
          packages[`node_modules/${PACKAGE_NAME}`]!.dependencies = { unrelated: "1.0.0" };
        }
        writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
        if (source === "hidden lock") {
          const hidden = writeHiddenLock(f, lock);
          hidden[`node_modules/${PACKAGE_NAME}`]!.dependencies = { unrelated: "1.0.0" };
          const body = structuredClone(lock);
          body.packages = hidden;
          writeFileSync(join(f.dir, "node_modules", ".package-lock.json"), `${JSON.stringify(body, null, 2)}\n`);
        } else if (source === "installed manifest") {
          const manifestPath = join(f.dir, "node_modules", "@yc-software", "qm", "package.json");
          const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
          manifest.dependencies = { unrelated: "1.0.0" };
          writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
        }
        await assert.rejects(
          runUpdate(updateOptions(f)),
          /must not declare runtime package dependencies|must declare only/,
        );
        assert.equal(readFileSync(sentinel, "utf8"), "preserve\n");
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }
});

test("nested package locks cannot delegate npm mutations", async (t) => {
  const prepare = (f: Fixture): { packageDir: string; lock: Record<string, unknown> } => {
    const packageDir = join(f.dir, "node_modules", "unrelated");
    mkdirSync(packageDir);
    writeFileSync(join(packageDir, "package.json"), `${JSON.stringify({ name: "unrelated", version: "1.0.0" })}\n`);
    const lock = deploymentLock(f);
    const packages = lock.packages as Record<string, Record<string, unknown>>;
    packages["node_modules/unrelated"] = {
      version: "1.0.0",
      resolved: "https://registry.npmjs.org/unrelated/-/unrelated-1.0.0.tgz",
      integrity: OTHER_INTEGRITY,
    };
    return { packageDir, lock };
  };

  await t.test("lock record marker", async () => {
    const f = fixture();
    try {
      const { lock } = prepare(f);
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      packages["node_modules/unrelated"]!.hasShrinkwrap = true;
      writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /must not delegate to a nested package lock/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("physical nested lock", async () => {
    const f = fixture();
    const external = mkdtempSync(join(tmpdir(), "qm-update-nested-lock-victim-"));
    const victim = join(external, "victim.sh");
    try {
      const { packageDir, lock } = prepare(f);
      writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
      writeFileSync(victim, "preserve\n", { mode: 0o600 });
      writeFileSync(
        join(packageDir, "package-lock.json"),
        `${JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { name: "unrelated", version: "1.0.0" },
            "node_modules/evil": { link: true, resolved: external, bin: { evil: "victim.sh" } },
          },
        })}\n`,
      );
      await assert.rejects(runUpdate(updateOptions(f)), /must not delegate to a nested package lock/);
      assert.equal(readFileSync(victim, "utf8"), "preserve\n");
      assert.equal(statSync(victim).mode & 0o777, 0o600);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
      rmSync(external, { recursive: true, force: true });
    }
  });
});

test("an unrelated package cannot claim the qm executable", async (t) => {
  for (const command of ["qm", "QM"] as const) {
    await t.test(command, async () => {
      const f = fixture();
      try {
        const packageDir = join(f.dir, "node_modules", "unrelated");
        const binDirectory = join(f.dir, "node_modules", ".bin");
        mkdirSync(packageDir);
        mkdirSync(binDirectory);
        writeFileSync(join(packageDir, "index.js"), "export {};\n");
        writeFileSync(
          join(packageDir, "package.json"),
          `${JSON.stringify({ name: "unrelated", version: "1.0.0", bin: { [command]: "index.js" } }, null, 2)}\n`,
        );
        symlinkSync("../unrelated/index.js", join(binDirectory, command));
        const lock = deploymentLock(f);
        const packages = lock.packages as Record<string, Record<string, unknown>>;
        packages["node_modules/unrelated"] = {
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/unrelated/-/unrelated-1.0.0.tgz",
          integrity: OTHER_INTEGRITY,
          bin: { [command]: "index.js" },
        };
        writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
        writeHiddenLock(f, lock);
        await assert.rejects(runUpdate(updateOptions(f)), /must not claim the qm executable/);
        assert.equal(readlinkSync(join(binDirectory, command)), "../unrelated/index.js");
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }
});

test("installed package bin targets may use npm-equivalent relative spelling", async () => {
  const f = fixture();
  try {
    const packageDir = join(f.dir, "node_modules", "unrelated");
    const binDirectory = join(f.dir, "node_modules", ".bin");
    mkdirSync(join(packageDir, "bin"), { recursive: true });
    mkdirSync(binDirectory);
    writeFileSync(join(packageDir, "bin", "tool.js"), "export {};\n");
    writeFileSync(
      join(packageDir, "package.json"),
      `${JSON.stringify({ name: "unrelated", version: "1.0.0", bin: { unrelated: "./bin/tool.js" } }, null, 2)}\n`,
    );
    symlinkSync("../unrelated/bin/tool.js", join(binDirectory, "unrelated"));
    const lock = deploymentLock(f);
    const packages = lock.packages as Record<string, Record<string, unknown>>;
    packages["node_modules/unrelated"] = {
      version: "1.0.0",
      resolved: "https://registry.npmjs.org/unrelated/-/unrelated-1.0.0.tgz",
      integrity: OTHER_INTEGRITY,
      bin: { unrelated: "bin/tool.js" },
    };
    writeFileSync(join(f.dir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
    writeHiddenLock(f, lock);
    await runUpdate(updateOptions(f));
    assert.equal(pinnedVersion(f), LATEST);
  } finally {
    clean(f);
  }
});

test("node_modules permits contained executable symlinks and internal hard links", async () => {
  const f = fixture();
  try {
    const packageDir = join(f.dir, "node_modules", "@yc-software", "qm");
    const binDirectory = join(f.dir, "node_modules", ".bin");
    mkdirSync(binDirectory);
    symlinkSync("../@yc-software/qm/dist/bin/qm.js", join(binDirectory, "qm"));
    linkSync(join(packageDir, "templates", "old-only.txt"), join(packageDir, "templates", "old-only-alias.txt"));
    await runUpdate(updateOptions(f));
    assert.equal(pinnedVersion(f), LATEST);
  } finally {
    clean(f);
  }
});

test("an interrupted exact-pin install accepts only the canonical dangling QM bin", async (t) => {
  await t.test("canonical bin converges", async () => {
    const f = fixture();
    try {
      const scope = join(f.dir, "node_modules", "@yc-software");
      const binDirectory = join(f.dir, "node_modules", ".bin");
      mkdirSync(binDirectory);
      symlinkSync("../@yc-software/qm/dist/bin/qm.js", join(binDirectory, "qm"));
      rmSync(scope, { recursive: true, force: true });
      await runUpdate(updateOptions(f));
      assert.equal(pinnedVersion(f), LATEST);
      assert.equal(realpathSync(join(binDirectory, "qm")), realpathSync(join(scope, "qm", "dist", "bin", "qm.js")));
      assert.equal(
        npmCalls(f).some((call) => call.cwd === realpathSync(f.dir) && call.args[0] === "install"),
        true,
      );
    } finally {
      clean(f);
    }
  });

  for (const entry of [
    { name: "lexical alias", bin: "qm", target: "../@yc-software/qm/dist/bin/../bin/qm.js" },
    { name: "bin alias", bin: "qm-alias", target: "../@yc-software/qm/dist/bin/qm.js" },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        const binDirectory = join(f.dir, "node_modules", ".bin");
        mkdirSync(binDirectory);
        symlinkSync(entry.target, join(binDirectory, entry.bin));
        rmSync(join(f.dir, "node_modules", "@yc-software"), { recursive: true, force: true });
        await assert.rejects(runUpdate(updateOptions(f)), /regular file inside node_modules/);
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }
});

test("unsupported package-manager layouts are rejected before mutation", async (t) => {
  for (const entry of [
    { name: "project npm configuration", file: ".npmrc", error: /removing deployment \.npmrc/ },
    { name: "npm shrinkwrap", file: "npm-shrinkwrap.json", error: /does not support npm-shrinkwrap/ },
    { name: "pnpm lock", file: "pnpm-lock.yaml", error: /standalone npm package-lock/ },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        writeFileSync(join(f.dir, entry.file), "invalid\n");
        await assert.rejects(runUpdate(updateOptions(f)), entry.error);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }

  await t.test("non-npm packageManager", async () => {
    const f = fixture();
    try {
      const pkg = deploymentPackage(f);
      pkg.packageManager = "pnpm@10.0.0";
      writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /incompatible packageManager/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  for (const npmVersion of ["11.12.0", "11.16.0"]) {
    await t.test(`directories.bin with npm ${npmVersion}`, async () => {
      const f = fixture();
      try {
        const pkg = deploymentPackage(f);
        pkg.directories = { bin: "external-bin" };
        writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
        const victim = join(f.dir, "external-bin-target");
        const binDirectory = join(f.dir, "node_modules", ".bin");
        writeFileSync(victim, "unchanged\n");
        mkdirSync(binDirectory);
        symlinkSync("../../external-bin-target", join(binDirectory, "external-tool"));
        const npmPackagePath = join(dirname(dirname(f.npmPath)), "package.json");
        const npmPackage = JSON.parse(readFileSync(npmPackagePath, "utf8")) as Record<string, unknown>;
        npmPackage.version = npmVersion;
        writeFileSync(npmPackagePath, `${JSON.stringify(npmPackage, null, 2)}\n`);
        await assert.rejects(runUpdate(updateOptions(f)), /must not declare directories\.bin/);
        assert.deepEqual(npmCalls(f), []);
        assert.deepEqual(targetCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
        assert.equal(readFileSync(victim, "utf8"), "unchanged\n");
      } finally {
        clean(f);
      }
    });
  }

  await t.test("duplicate optional QM dependency", async () => {
    const f = fixture();
    try {
      const pkg = deploymentPackage(f);
      pkg.optionalDependencies = { [PACKAGE_NAME]: CURRENT };
      writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      await assert.rejects(runUpdate(updateOptions(f)), /only in dependencies, not optionalDependencies/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("symlinked package scope", async () => {
    const f = fixture();
    try {
      const scope = join(f.dir, "node_modules", "@yc-software");
      const outside = join(f.dir, "outside-scope");
      renameSync(scope, outside);
      symlinkSync(outside, scope);
      await assert.rejects(runUpdate(updateOptions(f)), /must resolve to a regular file inside node_modules/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  await t.test("symlinked hidden package lock", async () => {
    const f = fixture();
    try {
      const outside = join(f.dir, "outside-hidden-lock");
      const hidden = join(f.dir, "node_modules", ".package-lock.json");
      writeFileSync(outside, "outside\n");
      symlinkSync(outside, hidden);
      await assert.rejects(runUpdate(updateOptions(f)), /must resolve to a regular file inside node_modules/);
      assert.equal(readFileSync(outside, "utf8"), "outside\n");
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
    }
  });

  for (const entry of [
    { name: "hard-linked root package", path: "package.json" },
    { name: "hard-linked root package lock", path: "package-lock.json" },
    { name: "hard-linked hidden package lock", path: "node_modules/.package-lock.json" },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        const path = join(f.dir, entry.path);
        if (!existsSync(path)) writeFileSync(path, "{}\n");
        const outside = join(f.dir, "outside-hardlink");
        linkSync(path, outside);
        const before = readFileSync(outside);
        await assert.rejects(
          runUpdate(updateOptions(f)),
          /must not (?:be hard-linked|have hard links outside node_modules)/,
        );
        assert.equal(statSync(path).nlink, 2);
        assert.deepEqual(readFileSync(outside), before);
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }

  for (const entry of [
    { name: "root package hard link created during install", path: "package.json" },
    { name: "root package-lock hard link created during install", path: "package-lock.json" },
    { name: "hidden package-lock hard link created during install", path: "node_modules/.package-lock.json" },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      updateState(f, (state) => void (state.hardlinkMutationPath = entry.path));
      try {
        await assert.rejects(
          runUpdate(updateOptions(f)),
          /must not (?:be hard-linked|have hard links outside node_modules)/,
        );
        assert.equal(statSync(join(f.dir, entry.path)).nlink, 2);
        assert.equal(
          npmCalls(f).some((call) => call.cwd === realpathSync(f.dir) && call.args[0] === "install"),
          true,
        );
        assert.deepEqual(targetCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }

  await t.test("ancestor workspace", async () => {
    const parent = mkdtempSync(join(tmpdir(), "qm-update-workspace-"));
    writeFileSync(join(parent, "package.json"), `${JSON.stringify({ private: true, workspaces: ["*"] })}\n`);
    const f = fixture(CURRENT, LATEST, "docker", parent);
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /outside any ancestor workspace/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
      rmSync(parent, { recursive: true, force: true });
    }
  });

  await t.test("ancestor pnpm workspace", async () => {
    const parent = mkdtempSync(join(tmpdir(), "qm-update-pnpm-workspace-"));
    writeFileSync(join(parent, "pnpm-workspace.yaml"), "packages: []\n");
    const f = fixture(CURRENT, LATEST, "docker", parent);
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /outside any ancestor pnpm workspace/);
      assert.deepEqual(npmCalls(f), []);
    } finally {
      clean(f);
      rmSync(parent, { recursive: true, force: true });
    }
  });

  await t.test("npm-discovered ancestor project", async () => {
    const f = fixture();
    updateState(f, (state) => void (state.npmPrefix = dirname(f.dir)));
    try {
      await assert.rejects(runUpdate(updateOptions(f)), /standalone npm project outside any ancestor workspace/);
      assert.equal(pinnedVersion(f), CURRENT);
      assert.equal(
        npmCalls(f).some((call) => call.cwd === realpathSync(f.dir) && call.args[0] === "install"),
        false,
      );
    } finally {
      clean(f);
    }
  });
});

test("custom image and recipe configurations block automatic rollout", async (t) => {
  const cases: Array<{ name: string; target: Target; configure: (f: Fixture) => void; expected: RegExp }> = [
    {
      name: "service image override",
      target: "docker",
      configure: (f) => void (f.config.imageOverrides = { core: "" }),
      expected: /core/,
    },
    {
      name: "local sandbox image",
      target: "docker",
      configure: (f) => void (f.config.sandbox = { backend: "local", image: "" }),
      expected: /sandbox\.image/,
    },
    {
      name: "default local sandbox image",
      target: "docker",
      configure: (f) => void (f.config.sandbox = { image: "" }),
      expected: /sandbox\.image/,
    },
    {
      name: "Fly image source",
      target: "fly",
      configure: (f) => void (f.config.imageFrom = ""),
      expected: /imageFrom/,
    },
    {
      name: "Fly sandbox recipe",
      target: "fly",
      configure: (f) => writeFileSync(join(f.sandboxDir, "Dockerfile"), "FROM scratch\n"),
      expected: /retired Sprites sandbox recipe.*archive or remove/,
    },
    {
      name: "Docker Sprites sandbox recipe",
      target: "docker",
      configure: (f) => {
        f.config.sandbox = { backend: "sprites", app: "acme-sandboxes" };
        writeFileSync(join(f.sandboxDir, "Dockerfile"), "FROM scratch\n");
      },
      expected: /retired Sprites sandbox recipe.*archive or remove/,
    },
    {
      name: "AWS Sprites sandbox recipe",
      target: "aws",
      configure: (f) => writeFileSync(join(f.sandboxDir, "Dockerfile"), "FROM scratch\n"),
      expected: /retired Sprites sandbox recipe.*archive or remove/,
    },
  ];
  for (const entry of cases) {
    await t.test(entry.name, async () => {
      const f = fixture(CURRENT, LATEST, entry.target);
      try {
        entry.configure(f);
        writeConfig(f);
        await assert.rejects(runUpdate(updateOptions(f)), entry.expected);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }

  await t.test("Sprites sandbox recipe is reported without mutating preview", async () => {
    const f = fixture(CURRENT, LATEST, "fly");
    try {
      writeFileSync(join(f.sandboxDir, "Dockerfile"), "FROM scratch\n");
      await runUpdate(updateOptions(f, { yes: false }));
      assert.deepEqual(npmCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
    }
  });
});

test("Docker, Fly, and AWS Sprites invoke the private verified qm up entrypoint", async (t) => {
  for (const target of ["docker", "fly", "aws"] as const) {
    await t.test(target, async () => {
      const f = fixture(CURRENT, LATEST, target);
      try {
        writeFileSync(join(f.dir, ".env"), "QM_TEST=1\n");
        await runUpdate(updateOptions(f, { envFile: join(f.dir, ".env") }));
        assert.deepEqual(
          npmCalls(f).map((call) => call.args[0]),
          ["install", "audit", "prefix", "root", "install", "install"],
        );
        const calls = targetCalls(f);
        assert.equal(calls.length, 1);
        assert.notEqual(calls[0]!.cwd, realpathSync(f.dir));
        assert.match(calls[0]!.cwd, /qm-update-/);
        assert.match(calls[0]!.entry, /qm-update-.*\/verifier\/node_modules/);
        const privateEnvironment = calls[0]!.args[calls[0]!.args.indexOf("--env-file") + 1]!;
        assert.match(privateEnvironment, /qm-update-[^/]+\/deployment\.env$/);
        assert.notEqual(privateEnvironment, join(f.dir, ".env"));
        assert.equal(calls[0]!.deploymentEnvBody, "QM_TEST=1\n");
        assert.deepEqual(calls[0]!.args, [
          "up",
          "--config",
          realpathSync(f.configPath),
          "--sandbox-dir",
          realpathSync(f.sandboxDir),
          "--env-file",
          privateEnvironment,
          "--target",
          target,
          ...(target === "aws" ? ["--yes"] : []),
        ]);
        if (target === "aws") {
          assert.equal(calls[0]!.awsPager, "");
          assert.equal(calls[0]!.awsAutoPrompt, "off");
        }
        assert.equal(pinnedVersion(f), LATEST);
      } finally {
        clean(f);
      }
    });
  }
});

test("preview and deployment accept an absent sandbox directory", async () => {
  const f = fixture();
  try {
    rmSync(f.sandboxDir, { recursive: true });
    updateState(f, (state) => void (state.requireAbsentSandbox = true));
    await runUpdate(updateOptions(f, { yes: false }));
    assert.deepEqual(npmCalls(f), []);
    await runUpdate(updateOptions(f));
    const call = targetCalls(f)[0]!;
    assert.equal(targetCalls(f).length, 1);
    assert.equal(call.args[call.args.indexOf("--sandbox-dir") + 1], join(call.cwd, "absent-sandbox"));
    assert.equal(existsSync(f.sandboxDir), false);
  } finally {
    clean(f);
  }
});

test("an explicit environment path is validated before npm", async (t) => {
  for (const entry of [
    { name: "missing file", value: (f: Fixture) => join(f.dir, "missing.env"), error: /--env-file not found/ },
    {
      name: "missing parent",
      value: (f: Fixture) => join(f.dir, "missing", "deployment.env"),
      error: /--env-file not found/,
    },
    { name: "empty", value: () => "", error: /--env-file needs a non-empty path/ },
    { name: "blank", value: () => " \t ", error: /--env-file needs a non-empty path/ },
    { name: "NUL", value: () => "bad\0path", error: /--env-file needs a non-empty path/ },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        await assert.rejects(runUpdate(updateOptions(f, { envFile: entry.value(f) })), entry.error);
        assert.deepEqual(npmCalls(f), []);
        assert.deepEqual(targetCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }
});

test("the deployment environment source must be a bounded unlinked regular file", async (t) => {
  for (const kind of ["symlink", "hard link", "directory", "fifo", "oversized"] as const) {
    await t.test(kind, async () => {
      const f = fixture();
      const environmentPath = join(f.dir, "deployment.env");
      const source = join(f.dir, "environment-source");
      try {
        if (kind === "directory") mkdirSync(environmentPath);
        else if (kind === "fifo") {
          const result = spawnSync("/usr/bin/mkfifo", [environmentPath], { encoding: "utf8" });
          assert.equal(result.status, 0, result.stderr);
        } else if (kind === "oversized") {
          writeFileSync(environmentPath, Buffer.alloc(1_048_577), { mode: 0o600 });
        } else {
          writeFileSync(source, "SECRET=value\n", { mode: 0o600 });
          if (kind === "symlink") symlinkSync(source, environmentPath);
          else linkSync(source, environmentPath);
        }
        await assert.rejects(
          runUpdate(updateOptions(f, { envFile: environmentPath })),
          kind === "oversized"
            ? /exceeds the 1048576-byte limit/
            : /unlinked.*deployment environment file|unlinked current-user file/,
        );
        assert.deepEqual(npmCalls(f), []);
        assert.deepEqual(targetCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }
});

test("the deployment environment is captured once before update mutation", async () => {
  const f = fixture();
  const environmentPath = join(f.dir, ".env");
  const savedPath = join(f.dir, ".env.saved");
  const markerPath = join(f.dir, "environment-swapped");
  const getfaclPath = join(f.targetBin, "getfacl");
  try {
    writeFileSync(environmentPath, "NORMAL_SECRET=normal\n", { mode: 0o600 });
    writeFileSync(
      getfaclPath,
      [
        "#!/bin/sh",
        `environment=${JSON.stringify(environmentPath)}`,
        `saved=${JSON.stringify(savedPath)}`,
        `config=${JSON.stringify(f.configPath)}`,
        `marker=${JSON.stringify(markerPath)}`,
        'for candidate in "$@"; do',
        '  case "$candidate" in',
        "    */qm-update-secure-*|*/qm-update-provider-bin-*) ;;",
        "    */qm-update-*)",
        '      if [ ! -e "$marker" ]; then',
        '        : > "$marker"',
        '        /bin/mv "$environment" "$saved"',
        '        /bin/ln -s "$config" "$environment"',
        "        (",
        "          attempts=0",
        '          while [ ! -f "$candidate/deployment.env" ] && [ "$attempts" -lt 50 ]; do',
        "            /bin/sleep 0.01",
        "            attempts=$((attempts + 1))",
        "          done",
        '          /bin/rm -f "$environment"',
        '          /bin/mv "$saved" "$environment"',
        "        ) >/dev/null 2>&1 &",
        "      fi",
        "      ;;",
        "  esac",
        "done",
        "exit 0",
      ].join("\n") + "\n",
    );
    chmodSync(getfaclPath, 0o755);
    await assert.rejects(
      runUpdate(updateOptions(f, { envFile: environmentPath, testPlatform: "linux" })),
      /\.env changed during the QM update/,
    );
    for (let attempt = 0; attempt < 100 && existsSync(savedPath); attempt++) {
      await new Promise<void>((resolveWait) => setTimeout(resolveWait, 10));
    }
    assert.equal(readFileSync(environmentPath, "utf8"), "NORMAL_SECRET=normal\n");
    assert.deepEqual(npmCalls(f), []);
    assert.deepEqual(targetCalls(f), []);
    assert.equal(pinnedVersion(f), CURRENT);
  } finally {
    clean(f);
  }
});

test("the configuration descriptor is trusted before parsing", async (t) => {
  for (const entry of ["symlink", "writable replacement"] as const) {
    await t.test(entry, async () => {
      const f = fixture();
      const original = join(f.dir, "trusted.config.jsonc");
      try {
        await assert.rejects(
          runUpdate(
            updateOptions(f, {
              testBeforeConfigSnapshot: () => {
                renameSync(f.configPath, original);
                if (entry === "symlink") symlinkSync(original, f.configPath);
                else {
                  writeFileSync(f.configPath, readFileSync(original));
                  chmodSync(f.configPath, 0o666);
                }
              },
            }),
          ),
          /must be an unlinked current-user configuration file/,
        );
        assert.deepEqual(npmCalls(f), []);
        assert.deepEqual(targetCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }

  await t.test("retargeted parent alias", async () => {
    const f = fixture();
    const aliasRoot = mkdtempSync(join(tmpdir(), "qm-update-config-alias-"));
    const external = mkdtempSync(join(tmpdir(), "qm-update-external-config-"));
    const alias = join(aliasRoot, "deployment");
    const externalConfig = { ...f.config, target: "fly", appPrefix: "external" } as QmConfig;
    try {
      symlinkSync(f.dir, alias);
      writeFileSync(join(external, "qm.config.jsonc"), `${JSON.stringify(externalConfig, null, 2)}\n`);
      await runUpdate(
        updateOptions(f, {
          yes: false,
          configPath: join(alias, "qm.config.jsonc"),
          testBeforeConfigSnapshot: () => {
            rmSync(alias);
            symlinkSync(external, alias);
          },
        }),
      );
      assert.deepEqual(npmCalls(f), []);
      assert.deepEqual(targetCalls(f), []);
      assert.equal(pinnedVersion(f), CURRENT);
    } finally {
      clean(f);
      rmSync(aliasRoot, { recursive: true, force: true });
      rmSync(external, { recursive: true, force: true });
    }
  });
});

test("deployment inputs cannot overlap node_modules mutation paths", async (t) => {
  for (const kind of [
    "environment",
    "skill",
    "sandbox",
    "skill root",
    "sandbox root",
    "skill symlink",
    "plugins symlink",
    "skill symlink ancestor",
    "sandbox symlink ancestor",
  ] as const) {
    await t.test(kind, async () => {
      const f = fixture();
      const live = join(f.dir, "node_modules", "@yc-software", "qm");
      try {
        const options = updateOptions(f);
        if (kind === "environment") {
          const envFile = join(live, "deployment.env");
          writeFileSync(envFile, "QM_TEST=1\n");
          options.envFile = envFile;
        } else {
          if (
            kind === "skill" ||
            kind === "skill root" ||
            kind === "skill symlink" ||
            kind === "skill symlink ancestor"
          ) {
            let skill = ".";
            if (kind === "skill") skill = live;
            else if (kind.includes("symlink")) skill = join(f.dir, "skill-alias");
            if (kind.includes("symlink")) symlinkSync(live, skill);
            const configuredSkill = kind === "skill symlink ancestor" ? join(skill, "missing") : skill;
            f.config.skills = [configuredSkill];
            writeConfig(f);
            options.config = f.config;
          } else if (kind === "plugins symlink") {
            symlinkSync(live, join(f.dir, "plugins"));
          } else if (kind === "sandbox symlink ancestor") {
            const alias = join(f.dir, "sandbox-alias");
            symlinkSync(live, alias);
            options.sandboxDir = join(alias, "missing");
          } else {
            options.sandboxDir = kind === "sandbox" ? live : f.dir;
          }
        }
        if (kind.endsWith("root")) {
          const pkg = deploymentPackage(f);
          (pkg.dependencies as Record<string, string>)[PACKAGE_NAME] = LATEST;
          writeFileSync(join(f.dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
        }
        const pinnedBefore = pinnedVersion(f);
        await assert.rejects(runUpdate(options), /physically disjoint from deployment node_modules/);
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), pinnedBefore);
        assert.equal(existsSync(join(live, "package.json")), true);
      } finally {
        clean(f);
      }
    });
  }
});

test("the deployment environment cannot alias updater-mutable files", async (t) => {
  for (const name of ["configuration", "package", "package lock"] as const) {
    await t.test(name, async () => {
      const f = fixture();
      try {
        const envFile =
          name === "configuration"
            ? f.configPath
            : join(f.dir, name === "package" ? "package.json" : "package-lock.json");
        await assert.rejects(
          runUpdate(updateOptions(f, { envFile })),
          /(?:unlinked current-user file separate from the deployment config|physically disjoint from an automatic update mutable file)/,
        );
        assert.deepEqual(npmCalls(f), []);
        assert.equal(pinnedVersion(f), CURRENT);
      } finally {
        clean(f);
      }
    });
  }
});

test("retired browser updater workflows are blocked by filename or signature", async (t) => {
  for (const entry of [
    { name: "default filename", file: "qm-update.yml", body: "name: anything\n" },
    {
      name: "renamed signed workflow",
      file: "deploy-update.yaml",
      body: [
        "name: QM browser update",
        "concurrency:",
        "  group: qm-browser-update",
        "inputs:",
        "  request_id:",
        "  requested_by:",
      ].join("\n"),
    },
  ]) {
    await t.test(entry.name, async () => {
      const f = fixture();
      try {
        const workflows = join(f.dir, ".github", "workflows");
        mkdirSync(workflows, { recursive: true });
        writeFileSync(join(workflows, entry.file), `${entry.body}\n`);
        await assert.rejects(
          runUpdate(updateOptions(f)),
          /QM_DEPLOY_ENV.*FLY_SANDBOX_API_TOKEN.*QM_UPDATE_GITHUB_TOKEN/,
        );
        assert.deepEqual(npmCalls(f), []);
      } finally {
        clean(f);
      }
    });
  }
});
