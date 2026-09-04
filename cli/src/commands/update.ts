import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  chmodSync,
  cpSync,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  readlinkSync,
  realpathSync,
  readdirSync,
  rmdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir, userInfo } from "node:os";
import { createRequire } from "node:module";
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { loadConfigAt, localSandboxActive, sandboxBackend, updateConfigCoreEnv, type QmConfig } from "../config.ts";
import { runChecks } from "./check.ts";
import { CliError, errMessage, note, ok } from "../log.ts";
import { cliPackageName } from "../manifest.ts";
import type { Target } from "../providers.ts";
import { canonicalJson, MAX_DEPLOYMENT_INPUT_BYTES, type RegularFileSnapshot } from "../util.ts";

const STABLE_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const SHA = /^[a-f0-9]{40}$/;
const SHA512 = /^[a-f0-9]{128}$/;
const NPM_REGISTRY = "https://registry.npmjs.org/";
const NPM_REGISTRY_ORIGIN = "https://registry.npmjs.org";
const NPM_LATEST = "https://registry.npmjs.org/@yc-software%2fqm/latest";
const GITHUB_REPOSITORY = "https://github.com/yc-software/qm";
const GITHUB_REPOSITORY_ID = "1316527318";
const GITHUB_REPOSITORY_OWNER_ID = "153323858";
const IMAGE_SERVICE_NAMES = ["admin", "auth", "core", "egress-proxy", "portal", "web-ui"];
const FOREIGN_PACKAGE_MANAGER_FILES = ["yarn.lock", "pnpm-lock.yaml", "pnpm-workspace.yaml", "bun.lock", "bun.lockb"];
const PACKAGE_DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const NPM_FETCH_ONLINE = [
  "--offline=false",
  "--prefer-online=true",
  "--min-release-age=0",
  "--fetch-timeout=10000",
  "--fetch-retries=2",
  "--fetch-retry-mintimeout=1000",
  "--fetch-retry-maxtimeout=2000",
];
const NPM_FETCH_OFFLINE = ["--offline=true", "--prefer-offline=true"];

interface ReleaseMetadata {
  version: string;
  gitHead: string;
  tarball: string;
  integrity: string;
  integrityHex: string;
  attestationUrl: string;
}

interface VerifiedPackage {
  packageDir: string;
  packageRecord: Record<string, unknown>;
}

interface VerifiedProvenance {
  bundle: Record<string, unknown>;
}

class ForwardedSignal extends Error {
  readonly signal: NodeJS.Signals;

  constructor(signal: NodeJS.Signals) {
    super(signal);
    this.signal = signal;
  }
}

interface UpdateInterruption {
  controller: AbortController;
  signal?: NodeJS.Signals;
}

function forwardedSignal(error: unknown): NodeJS.Signals | undefined {
  const seen = new Set<unknown>();
  let current = error;
  while (current instanceof Error && !seen.has(current)) {
    if (current instanceof ForwardedSignal) return current.signal;
    seen.add(current);
    current = (current as Error & { cause?: unknown }).cause;
  }
  return undefined;
}

function throwIfInterrupted(interruption: UpdateInterruption): void {
  if (interruption.signal) throw new ForwardedSignal(interruption.signal);
}

function versionParts(version: string): [bigint, bigint, bigint] | null {
  const match = STABLE_VERSION.exec(version);
  if (!match) return null;
  return [BigInt(match[1]!), BigInt(match[2]!), BigInt(match[3]!)];
}

export function compareVersions(a: string, b: string): number {
  const left = versionParts(a);
  const right = versionParts(b);
  if (!left || !right) throw new CliError(`invalid QM version: ${!left ? a : b}`);
  for (const index of [0, 1, 2] as const) {
    if (left[index] < right[index]) return -1;
    if (left[index] > right[index]) return 1;
  }
  return 0;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function jsonObject(raw: string | Buffer, path: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString());
  } catch (error) {
    throw new CliError(`${path} is not valid JSON`, { cause: error });
  }
  const object = objectValue(parsed);
  if (!object) throw new CliError(`${path} must contain a JSON object`);
  return object;
}

function hasPath(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

interface FilesystemIdentity {
  dev: bigint;
  ino: bigint;
}

function filesystemIdentity(path: string): FilesystemIdentity {
  const identity = lstatSync(path, { bigint: true });
  return { dev: identity.dev, ino: identity.ino };
}

function sameFilesystemIdentity(left: FilesystemIdentity, right: FilesystemIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function samePathIdentity(left: string, right: string): boolean {
  return sameFilesystemIdentity(filesystemIdentity(canonicalPath(left)), filesystemIdentity(canonicalPath(right)));
}

function canonicalPath(path: string): string {
  return realpathSync.native(path);
}

function pathHasAncestorIdentity(path: string, ancestor: string | FilesystemIdentity): boolean {
  const ancestorIdentity = typeof ancestor === "string" ? filesystemIdentity(canonicalPath(ancestor)) : ancestor;
  let current = canonicalPath(path);
  for (;;) {
    if (sameFilesystemIdentity(filesystemIdentity(current), ancestorIdentity)) return true;
    const parent = dirname(current);
    if (parent === current) return false;
    current = parent;
  }
}

function lexicalPathHasAncestorIdentity(path: string, ancestor: FilesystemIdentity): boolean {
  let current = resolve(path);
  for (;;) {
    if (hasPath(current) && sameFilesystemIdentity(filesystemIdentity(current), ancestor)) return true;
    const parent = dirname(current);
    if (parent === current) return false;
    current = parent;
  }
}

function packageDirectory(dir: string, packageName: string): string {
  return join(dir, "node_modules", ...packageName.split("/"));
}

function packageVersionAt(packageDir: string, packageName: string): string {
  const path = join(packageDir, "package.json");
  assertRegularFile(path);
  const installed = jsonObject(readFileSync(path), path);
  if (installed.name !== packageName || typeof installed.version !== "string" || !versionParts(installed.version)) {
    throw new CliError(`${path} must identify ${packageName} at an exact stable version`);
  }
  return installed.version;
}

function installedVersion(dir: string, packageName: string): string | undefined {
  const packageDir = packageDirectory(dir, packageName);
  if (!hasPath(packageDir)) return undefined;
  for (const path of [join(dir, "node_modules"), dirname(packageDir)]) assertRegularDirectory(path);
  assertPackageEntry(packageDir);
  if (!hasPath(join(packageDir, "package.json"))) return undefined;
  return packageVersionAt(packageDir, packageName);
}

function currentVersion(dir: string, packageName: string): string {
  const path = join(dir, "package.json");
  if (!existsSync(path)) throw new CliError(`update requires ${path}`);
  const parsed = jsonObject(readFileSync(path), path);
  const dependency = objectValue(parsed.dependencies)?.[packageName];
  if (typeof dependency !== "string" || !dependency.trim()) {
    throw new CliError(`${path} must depend on ${packageName} before it can be updated`);
  }
  if (!versionParts(dependency)) {
    throw new CliError(
      `${path} must pin ${packageName} to an exact registry version; normalize local source links through the trusted source and package-manager workflow first`,
    );
  }
  return dependency;
}

function assertSupportedPackageEntry(dir: string, packageName: string, allowIncomplete = false): void {
  const rootPackagePath = join(dir, "package.json");
  const rootPackage = jsonObject(readFileSync(rootPackagePath), rootPackagePath);
  if (rootPackage.workspaces !== undefined) {
    throw new CliError(
      `${rootPackagePath} declares npm workspaces; update ${packageName} through the workspace's normal source and package-manager workflow`,
    );
  }
  const live = packageDirectory(dir, packageName);
  const dependency = objectValue(rootPackage.dependencies)?.[packageName];
  if (typeof dependency !== "string") return;
  if (versionParts(dependency)) {
    if (!hasPath(live) && !allowIncomplete) throw new CliError(live + " is missing");
    if (hasPath(live) && lstatSync(live).isSymbolicLink()) {
      throw new CliError(live + " must not be linked when " + rootPackagePath + " uses an exact registry version");
    }
  } else {
    throw new CliError(
      `${rootPackagePath} must pin ${packageName} to an exact registry version; normalize local source links through the trusted source and package-manager workflow first`,
    );
  }
  for (const lockPath of [join(dir, "package-lock.json"), join(dir, "node_modules", ".package-lock.json")]) {
    if (!hasPath(lockPath)) continue;
    const lock = jsonObject(readFileSync(lockPath), lockPath);
    const record = objectValue(objectValue(lock.packages)?.["node_modules/" + packageName]);
    if (!record) continue;
    if (record.link !== undefined || typeof record.version !== "string" || !versionParts(record.version)) {
      throw new CliError(lockPath + " must contain an exact registry package record for " + packageName);
    }
    assertOfficialLockTarball(record, packageName, record.version, lockPath + " package node_modules/" + packageName);
  }
}

function repositoryMatches(value: unknown): boolean {
  const repository = objectValue(value);
  return (
    repository?.type === "git" &&
    repository.url === "git+https://github.com/yc-software/qm.git" &&
    repository.directory === "cli"
  );
}

function hasRuntimeDependencies(value: Record<string, unknown>): boolean {
  for (const field of ["dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta"]) {
    const dependencies = value[field];
    const dependencyObject = objectValue(dependencies);
    if (dependencies !== undefined && (!dependencyObject || Object.keys(dependencyObject).length !== 0)) return true;
  }
  for (const field of ["bundleDependencies", "bundledDependencies"]) {
    const dependencies = value[field];
    if (dependencies !== undefined && (!Array.isArray(dependencies) || dependencies.length !== 0)) return true;
  }
  return false;
}

async function responseJson(
  fetcher: typeof fetch,
  url: string,
  label: string,
  interruption: UpdateInterruption,
): Promise<unknown> {
  let response: Response;
  try {
    const interrupted = new Promise<never>((_resolve, reject) => {
      const stop = (): void => reject(interruption.controller.signal.reason);
      if (interruption.controller.signal.aborted) stop();
      else interruption.controller.signal.addEventListener("abort", stop, { once: true });
    });
    response = await Promise.race([
      fetcher(url, {
        headers: {
          Accept: "application/json",
          "Cache-Control": "no-cache",
          "User-Agent": "yc-software-qm-updater",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        signal: AbortSignal.any([AbortSignal.timeout(15_000), interruption.controller.signal]),
      }),
      interrupted,
    ]);
  } catch (error) {
    throw new CliError(`${label} lookup failed: ${errMessage(error)}`, { cause: error });
  }
  if (!response.ok) throw new CliError(`${label} lookup failed with HTTP ${response.status}`);
  try {
    return await response.json();
  } catch (error) {
    throw new CliError(`${label} returned invalid JSON`, { cause: error });
  }
}

function canonicalBase64(value: string, bytes: number): Buffer | undefined {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return undefined;
  const decoded = Buffer.from(value, "base64");
  return decoded.length === bytes && decoded.toString("base64") === value ? decoded : undefined;
}

async function releaseMetadata(
  fetcher: typeof fetch,
  requested: string | undefined,
  interruption: UpdateInterruption,
): Promise<ReleaseMetadata> {
  if (requested !== undefined && !versionParts(requested)) {
    throw new CliError(`QM version ${JSON.stringify(requested)} is not an exact stable version`);
  }
  const raw = await responseJson(fetcher, NPM_LATEST, "npm latest QM release", interruption);
  const metadata = objectValue(raw);
  if (!metadata || metadata.name !== cliPackageName() || typeof metadata.version !== "string") {
    throw new CliError("npm returned invalid latest QM release metadata");
  }
  const version = metadata.version;
  if (!versionParts(version)) throw new CliError(`npm latest points to non-stable QM ${version}`);
  if (requested !== undefined && requested !== version) {
    throw new CliError(`QM ${requested} is not the promoted latest release; npm latest is QM ${version}`);
  }
  if (Object.hasOwn(metadata, "deprecated")) throw new CliError(`QM ${version} is deprecated`);
  if (hasRuntimeDependencies(metadata)) {
    throw new CliError(`QM ${version} unexpectedly declares runtime dependencies`);
  }
  if (!repositoryMatches(metadata.repository)) throw new CliError(`QM ${version} has unexpected repository metadata`);
  if (typeof metadata.gitHead !== "string" || !SHA.test(metadata.gitHead)) {
    throw new CliError(`QM ${version} has an invalid source commit`);
  }
  const dist = objectValue(metadata.dist);
  const tarball = dist?.tarball;
  const integrity = dist?.integrity;
  const attestations = objectValue(dist?.attestations);
  const provenance = objectValue(attestations?.provenance);
  const attestationUrl = attestations?.url;
  const expectedTarball = `${NPM_REGISTRY}@yc-software/qm/-/qm-${version}.tgz`;
  const expectedAttestation = `${NPM_REGISTRY}-/npm/v1/attestations/@yc-software%2fqm@${version}`;
  if (tarball !== expectedTarball) throw new CliError(`QM ${version} has an unexpected npm tarball URL`);
  if (typeof integrity !== "string" || !integrity.startsWith("sha512-")) {
    throw new CliError(`QM ${version} has invalid npm integrity metadata`);
  }
  const digest = canonicalBase64(integrity.slice("sha512-".length), 64);
  if (!digest) throw new CliError(`QM ${version} has invalid npm integrity metadata`);
  if (attestationUrl !== expectedAttestation || provenance?.predicateType !== "https://slsa.dev/provenance/v1") {
    throw new CliError(`QM ${version} has unexpected npm provenance metadata`);
  }
  return {
    version,
    gitHead: metadata.gitHead,
    tarball,
    integrity,
    integrityHex: digest.toString("hex"),
    attestationUrl,
  };
}

function prepareNpmEnvironment(transaction: string): void {
  for (const path of [
    join(transaction, "home"),
    join(transaction, "tmp"),
    join(transaction, "npm-cache"),
    join(transaction, "path"),
  ]) {
    mkdirSync(path, { mode: 0o700 });
  }
  writeFileSync(join(transaction, "user.npmrc"), "", { flag: "wx", mode: 0o600 });
  writeFileSync(join(transaction, "global.npmrc"), "", { flag: "wx", mode: 0o600 });
}

function npmEnvironment(transaction: string, testEnvironment?: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const name of ["SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "LC_CTYPE"]) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  const home = join(transaction, "home");
  const temporary = join(transaction, "tmp");
  env.HOME = home;
  env.USERPROFILE = home;
  env.TMPDIR = temporary;
  env.TMP = temporary;
  env.TEMP = temporary;
  if (testEnvironment) Object.assign(env, testEnvironment);
  env.PATH = join(transaction, "path");
  return env;
}

function npmBinary(testNpmPath?: string): string {
  if (testNpmPath !== undefined) return canonicalPath(resolve(testNpmPath));
  const packageEntry = join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  if (existsSync(packageEntry)) return canonicalPath(packageEntry);
  const sibling = join(dirname(process.execPath), process.platform === "win32" ? "npm.cmd" : "npm");
  if (existsSync(sibling)) return canonicalPath(sibling);
  throw new CliError(`could not find npm beside ${process.execPath}`);
}

function npmArgs(transaction: string, network?: "online" | "offline"): string[] {
  const userConfig = join(transaction, "user.npmrc");
  const globalConfig = join(transaction, "global.npmrc");
  const cache = join(transaction, "npm-cache");
  let networkArgs: string[] = [];
  if (network === "online") networkArgs = NPM_FETCH_ONLINE;
  if (network === "offline") networkArgs = NPM_FETCH_OFFLINE;
  return [
    "--global=false",
    "--location=project",
    `--registry=${NPM_REGISTRY}`,
    `--@yc-software:registry=${NPM_REGISTRY}`,
    `--userconfig=${userConfig}`,
    `--globalconfig=${globalConfig}`,
    `--cache=${cache}`,
    ...networkArgs,
  ];
}

async function assertNpmProject(
  npm: string,
  transaction: string,
  dir: string,
  testEnvironment?: NodeJS.ProcessEnv,
): Promise<void> {
  const environment = npmEnvironment(transaction, testEnvironment);
  const prefix = (
    await runForeground(
      process.execPath,
      [npm, "prefix", ...npmArgs(transaction)],
      dir,
      environment,
      "npm project lookup",
      true,
    )
  ).trim();
  const root = (
    await runForeground(
      process.execPath,
      [npm, "root", ...npmArgs(transaction)],
      dir,
      environment,
      "npm root lookup",
      true,
    )
  ).trim();
  if (!hasPath(prefix) || !samePathIdentity(prefix, dir)) {
    throw new CliError(dir + " must be a standalone npm project outside any ancestor workspace");
  }
  if (!hasPath(root) || !samePathIdentity(root, join(dir, "node_modules"))) {
    throw new CliError(dir + " must use its own regular node_modules directory");
  }
}

async function assertCanonicalPackageManagerProjection(
  npm: string,
  transaction: string,
  dir: string,
  packageName: string,
  testEnvironment?: NodeJS.ProcessEnv,
): Promise<void> {
  const projection = join(transaction, "project-check");
  mkdirSync(projection, { mode: 0o700 });
  const files = ["package.json", "package-lock.json"];
  const expected = new Map<string, Record<string, unknown>>();
  for (const name of files) {
    const source = join(dir, name);
    expected.set(name, jsonObject(readFileSync(source), source));
    writeFileSync(join(projection, name), readFileSync(source), { flag: "wx", mode: 0o600 });
  }
  await runForeground(
    process.execPath,
    [
      npm,
      "install",
      "--package-lock-only=true",
      "--dry-run=false",
      "--ignore-scripts=true",
      "--foreground-scripts=false",
      "--audit=false",
      "--fund=false",
      "--bin-links=true",
      "--lockfile-version=3",
      "--workspaces=false",
      "--install-links=false",
      "--strict-peer-deps=true",
      "--engine-strict=true",
      ...npmArgs(transaction, "offline"),
    ],
    projection,
    npmEnvironment(transaction, testEnvironment),
    "npm package projection verification",
  );
  const comparable = (name: string, value: Record<string, unknown>): string => {
    if (name === "package.json") return canonicalJson(value);
    const lock = structuredClone(value);
    const packages = objectValue(lock.packages);
    const root = objectValue(packages?.[""]);
    const dependencies = objectValue(root?.dependencies);
    if (dependencies) delete dependencies[packageName];
    if (packages) delete packages["node_modules/" + packageName];
    return canonicalJson(lock);
  };
  for (const name of files) {
    const path = join(projection, name);
    const before = expected.get(name)!;
    if (!hasPath(path) || comparable(name, jsonObject(readFileSync(path), path)) !== comparable(name, before)) {
      throw new CliError(
        join(dir, name) +
          " would be normalized by npm; repair it with the trusted package-manager workflow before updating",
      );
    }
  }
}

function npmPackageRoot(npm: string): string {
  const resolvedNpm = canonicalPath(npm);
  let candidate = dirname(resolvedNpm);
  for (;;) {
    const packagePath = join(candidate, "package.json");
    if (hasPath(packagePath)) {
      assertRegularFile(packagePath);
      const pkg = jsonObject(readFileSync(packagePath), packagePath);
      const npmEntry = objectValue(pkg.bin)?.npm;
      if (
        pkg.name === "npm" &&
        typeof npmEntry === "string" &&
        hasPath(join(candidate, npmEntry)) &&
        samePathIdentity(join(candidate, npmEntry), resolvedNpm)
      ) {
        if (
          typeof pkg.version !== "string" ||
          !versionParts(pkg.version) ||
          compareVersions(pkg.version, "11.12.0") < 0 ||
          compareVersions(pkg.version, "12.0.0") >= 0
        ) {
          throw new CliError(
            "automatic update requires the trusted npm beside Node to be version 11.12.0 or newer and below 12.0.0",
          );
        }
        return candidate;
      }
    }
    const parent = dirname(candidate);
    if (parent === candidate) break;
    candidate = parent;
  }
  throw new CliError(`could not locate the trusted npm package behind ${npm}`);
}

interface PackageArgument {
  type?: string;
  name?: string;
}

interface PackageArgumentParser {
  (spec: string, where?: string): PackageArgument;
  resolve(name: string, spec: string, where?: string): PackageArgument;
}

function npmPackageArgumentParser(npmRoot: string): PackageArgumentParser {
  const loaded: unknown = createRequire(join(npmRoot, "package.json"))("npm-package-arg");
  if (typeof loaded !== "function" || typeof (loaded as Partial<PackageArgumentParser>).resolve !== "function") {
    throw new CliError("the trusted npm package argument parser is unavailable");
  }
  return loaded as PackageArgumentParser;
}

function registryPackageArgument(
  parser: PackageArgumentParser,
  name: string,
  spec: string,
  where: string,
  label: string,
): void {
  let argument: PackageArgument;
  try {
    argument = parser.resolve(name, spec, where);
  } catch (error) {
    throw new CliError(label + " is not a valid npm registry package specification", { cause: error });
  }
  if (argument.type === "alias") {
    throw new CliError(label + " must not use an npm alias during automatic update");
  }
  if (argument.type !== "version" && argument.type !== "range" && argument.type !== "tag") {
    throw new CliError(label + " must resolve only through the official npm registry during automatic update");
  }
}

function assertNpmPackageName(parser: PackageArgumentParser, name: string, where: string, label: string): void {
  let argument: PackageArgument;
  try {
    argument = parser.resolve(name, "0.0.0", where);
  } catch (error) {
    throw new CliError(label + " has an invalid npm package name", { cause: error });
  }
  if (argument.type !== "version" || argument.name !== name) {
    throw new CliError(label + " has an invalid npm package name");
  }
}

function lockLocationPackageNames(location: string, label: string): string[] {
  const parts = location.split("/");
  const packageNames: string[] = [];
  for (let index = 0; index < parts.length;) {
    if (parts[index] !== "node_modules") throw new CliError(label + " has an invalid npm package location");
    const first = parts[index + 1];
    if (!first) throw new CliError(label + " has an invalid npm package location");
    if (first.startsWith("@")) {
      const second = parts[index + 2];
      if (first === "@" || !second) throw new CliError(label + " has an invalid npm package location");
      packageNames.push(first + "/" + second);
      index += 3;
    } else {
      packageNames.push(first);
      index += 2;
    }
  }
  return packageNames;
}

function lockLocationPackageName(location: string, label: string): string {
  return lockLocationPackageNames(location, label).at(-1)!;
}

function lockRecordPackageName(location: string, record: Record<string, unknown>, label: string): string {
  const locationName = lockLocationPackageName(location, label);
  if (record.name === undefined || record.name === locationName) return locationName;
  throw new CliError(label + " must not use an npm alias during automatic update");
}

function assertSafePackageBin(
  value: unknown,
  packageName: string,
  packageDir: string,
  requireTargets: boolean,
  label: string,
): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  const entries =
    typeof value === "string" ? [[basename(packageName), value] as const] : Object.entries(objectValue(value) ?? {});
  if ((typeof value !== "string" && !objectValue(value)) || !entries.length) {
    throw new CliError(label + " contains an invalid bin declaration");
  }
  const root = resolve(packageDir);
  const normalized: Record<string, string> = {};
  for (const [command, target] of entries) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(command) || typeof target !== "string" || !target) {
      throw new CliError(label + " contains an unsafe bin declaration");
    }
    const parts = target.split("/");
    if (parts[0] === ".") parts.shift();
    if (isAbsolute(target) || target.includes("\\") || parts.some((part) => !part || part === "." || part === "..")) {
      throw new CliError(label + " contains an unsafe bin declaration");
    }
    const targetPath = resolve(root, target);
    const contained = relative(root, targetPath);
    if (!contained || contained === ".." || contained.startsWith(".." + sep) || isAbsolute(contained)) {
      throw new CliError(label + " contains an unsafe bin declaration");
    }
    if (requireTargets) {
      if (!hasPath(targetPath)) throw new CliError(label + " identifies a missing bin target");
      const identity = lstatSync(targetPath);
      if (!identity.isFile() || identity.isSymbolicLink()) {
        throw new CliError(label + " bin targets must be regular package files");
      }
      if (!pathHasAncestorIdentity(targetPath, filesystemIdentity(canonicalPath(root)))) {
        throw new CliError(label + " contains an unsafe bin declaration");
      }
    }
    normalized[command] = parts.join("/");
  }
  return normalized;
}

function assertOfficialLockTarball(
  record: Record<string, unknown>,
  packageName: string,
  version: string,
  label: string,
): void {
  if (typeof record.resolved !== "string" || typeof record.integrity !== "string") {
    throw new CliError(label + " must contain an integrity-protected official npm registry tarball");
  }
  let resolved: URL;
  try {
    resolved = new URL(record.resolved);
  } catch (error) {
    throw new CliError(label + " must resolve through the official npm registry", { cause: error });
  }
  let pathname: string;
  try {
    pathname = decodeURIComponent(resolved.pathname);
  } catch (error) {
    throw new CliError(label + " must resolve through the official npm registry", { cause: error });
  }
  const tarballName = packageName.slice(packageName.lastIndexOf("/") + 1);
  if (
    resolved.origin !== NPM_REGISTRY_ORIGIN ||
    resolved.username ||
    resolved.password ||
    resolved.search ||
    resolved.hash ||
    pathname !== `/${packageName}/-/${tarballName}-${version}.tgz` ||
    !record.integrity.startsWith("sha512-") ||
    !canonicalBase64(record.integrity.slice("sha512-".length), 64)
  ) {
    throw new CliError(label + " must contain an integrity-protected official npm registry tarball");
  }
}

function assertOfflinePackageManagerInputs(
  dir: string,
  packageName: string,
  npmRoot: string,
  targetIntegrity: string,
): void {
  const parser = npmPackageArgumentParser(npmRoot);
  const packagePath = join(dir, "package.json");
  const pkg = jsonObject(readFileSync(packagePath), packagePath);
  const assertPeerDependenciesMeta = (record: Record<string, unknown>, label: string): void => {
    const value = record.peerDependenciesMeta;
    if (value === undefined) return;
    const metadata = objectValue(value);
    if (!metadata) throw new CliError(label + " contains an invalid peerDependenciesMeta object");
    for (const [name, entryValue] of Object.entries(metadata)) {
      assertNpmPackageName(parser, name, dir, label + " peerDependenciesMeta");
      const entry = objectValue(entryValue);
      if (
        !entry ||
        Object.keys(entry).some((key) => key !== "optional") ||
        (entry.optional !== undefined && typeof entry.optional !== "boolean")
      ) {
        throw new CliError(label + " contains invalid peerDependenciesMeta for " + name);
      }
    }
  };
  for (const field of PACKAGE_DEPENDENCY_FIELDS) {
    const value = pkg[field];
    const dependencies = objectValue(value);
    if (value !== undefined && !dependencies) {
      throw new CliError(packagePath + " contains an invalid " + field + " object");
    }
    if (!dependencies) continue;
    for (const [name, spec] of Object.entries(dependencies)) {
      if (typeof spec !== "string") {
        throw new CliError(packagePath + " contains a non-string " + field + " specification for " + name);
      }
      registryPackageArgument(parser, name, spec, dir, packagePath + " " + field + "." + name);
    }
  }
  assertPeerDependenciesMeta(pkg, packagePath);
  for (const field of ["bundleDependencies", "bundledDependencies"]) {
    if (pkg[field] !== undefined) {
      throw new CliError(packagePath + " must not declare " + field + " during automatic update");
    }
  }

  const lockPath = join(dir, "package-lock.json");
  const lock = jsonObject(readFileSync(lockPath), lockPath);
  if (lock.lockfileVersion !== 3 || lock.dependencies !== undefined) {
    throw new CliError(
      lockPath +
        " must be reviewed and upgraded to npm lockfile version 3 with npm install --package-lock-only --ignore-scripts",
    );
  }
  const packages = objectValue(lock.packages);
  if (!packages) throw new CliError(lockPath + " must contain npm package records");
  const rootRecord = objectValue(packages[""]);
  if (!rootRecord) throw new CliError(lockPath + " must contain the root npm package record");
  for (const field of [...PACKAGE_DEPENDENCY_FIELDS, "peerDependenciesMeta"]) {
    const comparable = (value: unknown): unknown => {
      if (field !== "dependencies") return value;
      const dependencies = structuredClone(objectValue(value) ?? {});
      delete dependencies[packageName];
      return dependencies;
    };
    if (canonicalJson({ value: comparable(pkg[field]) }) !== canonicalJson({ value: comparable(rootRecord[field]) })) {
      throw new CliError(lockPath + " root " + field + " must match package.json exactly");
    }
  }
  const packageKey = "node_modules/" + packageName;
  const expectedPackageBin = canonicalJson({ value: { qm: "dist/bin/qm.js" } });
  const assertDependencySpecs = (record: Record<string, unknown>, label: string): void => {
    for (const field of PACKAGE_DEPENDENCY_FIELDS) {
      const value = record[field];
      const dependencies = objectValue(value);
      if (value !== undefined && !dependencies) {
        throw new CliError(label + " contains an invalid " + field + " object");
      }
      if (!dependencies) continue;
      for (const [name, spec] of Object.entries(dependencies)) {
        if (typeof spec !== "string") throw new CliError(label + " contains an invalid " + field + " specification");
        registryPackageArgument(parser, name, spec, dir, label + " " + field + "." + name);
      }
    }
  };
  const assertBundleDeclaration = (record: Record<string, unknown>, label: string): void => {
    if (record.bundledDependencies !== undefined) {
      throw new CliError(label + " must use bundleDependencies instead of bundledDependencies");
    }
    if (record.bundleDependencies === undefined) return;
    if (!Array.isArray(record.bundleDependencies)) {
      throw new CliError(label + " contains an invalid bundleDependencies array");
    }
    for (const name of record.bundleDependencies) {
      if (typeof name !== "string") throw new CliError(label + " contains an invalid bundleDependencies array");
      assertNpmPackageName(parser, name, dir, label + " bundleDependencies");
    }
  };
  const assertRecords = (records: Record<string, unknown>, path: string): void => {
    const assertRegistryRecord = (location: string, record: Record<string, unknown>): void => {
      if (typeof record.version !== "string") {
        throw new CliError(path + " package " + location + " is missing an exact registry version");
      }
      const recordPackageName = lockRecordPackageName(location, record, path + " package " + location);
      let versionArgument: PackageArgument;
      try {
        versionArgument = parser.resolve(recordPackageName, record.version, dir);
      } catch (error) {
        throw new CliError(path + " package " + location + " has an invalid version", { cause: error });
      }
      if (versionArgument.type !== "version") {
        throw new CliError(path + " package " + location + " must have an exact registry version");
      }
      assertOfficialLockTarball(record, recordPackageName, record.version, path + " package " + location);
    };
    const assertBundledRecord = (location: string, record: Record<string, unknown>): void => {
      if (
        typeof record.version !== "string" ||
        record.name !== undefined ||
        record.resolved !== undefined ||
        record.integrity !== undefined
      ) {
        throw new CliError(path + " package " + location + " contains an invalid bundled package record");
      }
      let versionArgument: PackageArgument;
      try {
        versionArgument = parser.resolve(
          lockRecordPackageName(location, record, path + " package " + location),
          record.version,
          dir,
        );
      } catch (error) {
        throw new CliError(path + " package " + location + " has an invalid bundled version", { cause: error });
      }
      if (versionArgument.type !== "version") {
        throw new CliError(path + " package " + location + " must have an exact bundled version");
      }
      let ancestor = location;
      for (;;) {
        const marker = ancestor.lastIndexOf("/node_modules/");
        if (marker < 0) break;
        ancestor = ancestor.slice(0, marker);
        const value = objectValue(records[ancestor]);
        if (!value || value.inBundle === true) continue;
        const bundled = value.bundleDependencies;
        if (!Array.isArray(bundled) || !bundled.length) break;
        assertRegistryRecord(ancestor, value);
        return;
      }
      throw new CliError(path + " package " + location + " is not bound to an integrity-protected package bundle");
    };
    for (const [location, value] of Object.entries(records)) {
      const record = objectValue(value);
      if (!record) throw new CliError(path + " contains an invalid package record at " + location);
      if (typeof record.bin === "string") {
        throw new CliError(path + " package " + location + " must use an object bin declaration");
      }
      if (record.hasShrinkwrap !== undefined || record._hasShrinkwrap !== undefined) {
        throw new CliError(path + " package " + location + " must not delegate to a nested package lock");
      }
      assertDependencySpecs(record, path + " package " + location);
      assertPeerDependenciesMeta(record, path + " package " + location);
      assertBundleDeclaration(record, path + " package " + location);
      if (location === "") {
        assertSafePackageBin(
          record.bin,
          typeof pkg.name === "string" ? pkg.name : "deployment",
          dir,
          true,
          path + " root package",
        );
        continue;
      }
      for (const name of lockLocationPackageNames(location, path + " package " + location)) {
        try {
          assertNpmPackageName(parser, name, dir, path + " package " + location);
        } catch (error) {
          throw new CliError(path + " package " + location + " has an invalid npm package location", {
            cause: error,
          });
        }
      }
      if (record.link !== undefined) {
        throw new CliError(path + " contains an unrelated local package link at " + location);
      }
      if (record.inBundle !== undefined && record.inBundle !== true) {
        throw new CliError(path + " package " + location + " has an invalid inBundle marker");
      }
      if (record.extraneous === true) {
        throw new CliError(path + " package " + location + " must not be extraneous");
      }
      const recordPackageName = lockRecordPackageName(location, record, path + " package " + location);
      const installed = join(dir, location);
      const normalizedBin = assertSafePackageBin(
        record.bin,
        recordPackageName,
        installed,
        hasPath(installed),
        path + " package " + location,
      );
      if (
        location === packageKey &&
        (canonicalJson({ value: record.bin }) !== expectedPackageBin ||
          canonicalJson({ value: normalizedBin }) !== expectedPackageBin)
      ) {
        throw new CliError(path + " package " + location + " must declare only the qm executable");
      }
      if (location === packageKey && hasRuntimeDependencies(record)) {
        throw new CliError(path + " package " + location + " must not declare runtime package dependencies");
      }
      if (location !== packageKey && Object.keys(normalizedBin ?? {}).some((name) => name.toLowerCase() === "qm")) {
        throw new CliError(path + " package " + location + " must not claim the qm executable");
      }
      if (location !== packageKey && (recordPackageName === packageName || record.integrity === targetIntegrity)) {
        throw new CliError(path + " package " + location + " must not alias or reuse the verified QM package");
      }
      if (record.inBundle === true) assertBundledRecord(location, record);
      else assertRegistryRecord(location, record);
    }
  };
  assertRecords(packages, lockPath);
  const installedSlots = new Map<string, { path: string; manifest: Record<string, unknown> }>();
  const collectInstalledSlots = (nodeModules: string, prefix: string): void => {
    for (const name of readdirSync(nodeModules)) {
      if (name === ".bin" || name.startsWith(".")) continue;
      const path = join(nodeModules, name);
      if (!lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink()) continue;
      const slots = name.startsWith("@")
        ? readdirSync(path)
            .map((child) => ({ location: prefix + "/" + name + "/" + child, path: join(path, child) }))
            .filter((slot) => lstatSync(slot.path).isDirectory() && !lstatSync(slot.path).isSymbolicLink())
        : [{ location: prefix + "/" + name, path }];
      for (const slot of slots) {
        const manifestPath = join(slot.path, "package.json");
        for (const name of ["package-lock.json", "npm-shrinkwrap.json"]) {
          if (hasPath(join(slot.path, name))) {
            throw new CliError(slot.path + " must not delegate to a nested package lock");
          }
        }
        if (hasPath(manifestPath)) {
          const manifest = jsonObject(readFileSync(manifestPath), manifestPath);
          const manifestName = manifest.name;
          if (typeof manifestName !== "string") throw new CliError(manifestPath + " must contain a package name");
          assertNpmPackageName(parser, manifestName, dir, manifestPath);
          assertSafePackageBin(manifest.bin, manifestName, slot.path, true, manifestPath);
          installedSlots.set(slot.location, { path: slot.path, manifest });
        }
        const nested = join(slot.path, "node_modules");
        if (hasPath(nested)) collectInstalledSlots(nested, slot.location + "/node_modules");
      }
    }
  };
  collectInstalledSlots(join(dir, "node_modules"), "node_modules");
  for (const [location, installed] of installedSlots) {
    if (location === packageKey) {
      if (
        installed.manifest.name !== packageName ||
        hasRuntimeDependencies(installed.manifest) ||
        installed.manifest.hasShrinkwrap !== undefined ||
        installed.manifest._hasShrinkwrap !== undefined ||
        hasPath(join(installed.path, "node_modules"))
      ) {
        throw new CliError(installed.path + " must not declare runtime package dependencies or nested package state");
      }
      if (
        canonicalJson({ value: installed.manifest.bin }) !== expectedPackageBin ||
        canonicalJson({
          value: assertSafePackageBin(installed.manifest.bin, packageName, installed.path, true, installed.path),
        }) !== expectedPackageBin
      ) {
        throw new CliError(installed.path + " must declare only the qm executable");
      }
      continue;
    }
    const record = objectValue(packages[location]);
    if (!record) {
      throw new CliError(lockPath + " does not cover installed package " + location);
    }
    const packageLabel = lockPath + " package " + location;
    const packageRecordName = lockRecordPackageName(location, record, packageLabel);
    if (
      installed.manifest.name !== packageRecordName ||
      installed.manifest.version !== record.version ||
      canonicalJson({
        value: assertSafePackageBin(installed.manifest.bin, packageRecordName, installed.path, true, packageLabel),
      }) !==
        canonicalJson({
          value: assertSafePackageBin(record.bin, packageRecordName, installed.path, true, packageLabel),
        })
    ) {
      throw new CliError(installed.path + " metadata must match package-lock.json before automatic update");
    }
  }
  const hiddenPath = join(dir, "node_modules", ".package-lock.json");
  if (hasPath(hiddenPath)) {
    const hidden = jsonObject(readFileSync(hiddenPath), hiddenPath);
    if (hidden.lockfileVersion !== 3 || hidden.dependencies !== undefined) {
      throw new CliError(hiddenPath + " must use npm lockfile version 3 without legacy dependency records");
    }
    const hiddenPackages = objectValue(hidden.packages);
    if (!hiddenPackages || hiddenPackages[""] !== undefined) {
      throw new CliError(hiddenPath + " must contain only installed npm package records");
    }
    assertRecords(hiddenPackages, hiddenPath);
    const rootMetadata = structuredClone(lock);
    const hiddenMetadata = structuredClone(hidden);
    delete rootMetadata.packages;
    delete hiddenMetadata.packages;
    if (canonicalJson(rootMetadata) !== canonicalJson(hiddenMetadata)) {
      throw new CliError(hiddenPath + " metadata must match package-lock.json before automatic update");
    }
    for (const [location, record] of Object.entries(hiddenPackages)) {
      if (location === packageKey) continue;
      if (!objectValue(packages[location]) || canonicalJson(record) !== canonicalJson(packages[location])) {
        throw new CliError(hiddenPath + " package " + location + " must match package-lock.json exactly");
      }
      const installed = join(dir, location);
      if (!hasPath(installed) || !lstatSync(installed).isDirectory() || lstatSync(installed).isSymbolicLink()) {
        throw new CliError(hiddenPath + " package " + location + " must identify an installed package directory");
      }
    }
    for (const [location, record] of Object.entries(packages)) {
      if (location === "" || location === packageKey || !hasPath(join(dir, location))) continue;
      if (!objectValue(hiddenPackages[location]) || canonicalJson(record) !== canonicalJson(hiddenPackages[location])) {
        throw new CliError(hiddenPath + " is missing installed package " + location + " from package-lock.json");
      }
    }
    for (const location of installedSlots.keys()) {
      if (location === packageKey) continue;
      const rootRecord = objectValue(packages[location]);
      const hiddenRecord = objectValue(hiddenPackages[location]);
      if (!rootRecord || !hiddenRecord || canonicalJson(rootRecord) !== canonicalJson(hiddenRecord)) {
        throw new CliError(hiddenPath + " does not cover installed package " + location);
      }
    }
  }
}

async function verifyCertificateIdentity(
  transaction: string,
  npm: string,
  bundle: Record<string, unknown>,
  metadata: ReleaseMetadata,
  testEnvironment?: NodeJS.ProcessEnv,
): Promise<void> {
  const npmRoot = npmPackageRoot(npm);
  const packagePath = join(npmRoot, "package.json");
  const bundlePath = join(transaction, "provenance-bundle.json");
  const verifierPath = join(transaction, "verify-provenance.mjs");
  const cachePath = join(transaction, "sigstore-cache");
  mkdirSync(cachePath, { mode: 0o700 });
  writeFileSync(bundlePath, `${JSON.stringify(bundle)}\n`, { flag: "wx", mode: 0o600 });
  writeFileSync(
    verifierPath,
    [
      'import { readFileSync } from "node:fs";',
      'import { createRequire } from "node:module";',
      'import { pathToFileURL } from "node:url";',
      `const require = createRequire(${JSON.stringify(packagePath)});`,
      'const imported = await import(pathToFileURL(require.resolve("sigstore")).href);',
      'const core = await import(pathToFileURL(require.resolve("@sigstore/core")).href);',
      "const verify = imported.verify ?? imported.default?.verify;",
      'if (typeof verify !== "function") throw new Error("trusted npm sigstore verifier is unavailable");',
      'const bundle = JSON.parse(readFileSync(process.argv[2], "utf8"));',
      "const rawCertificate = bundle.verificationMaterial?.certificate?.rawBytes;",
      'if (typeof rawCertificate !== "string") throw new Error("provenance certificate is unavailable");',
      "const Certificate = core.X509Certificate ?? core.default?.X509Certificate;",
      'if (typeof Certificate?.parse !== "function") throw new Error("trusted npm certificate parser is unavailable");',
      'const certificate = Certificate.parse(Buffer.from(rawCertificate, "base64"));',
      "const extension = (oid) => {",
      "  const value = certificate.extension(oid);",
      "  const body = value?.valueObj?.subs?.[0]?.value ?? value?.value;",
      '  return Buffer.isBuffer(body) ? body.toString("utf8") : undefined;',
      "};",
      `const expected = ${JSON.stringify({
        "1.3.6.1.4.1.57264.1.11": "github-hosted",
        "1.3.6.1.4.1.57264.1.12": GITHUB_REPOSITORY,
        "1.3.6.1.4.1.57264.1.13": metadata.gitHead,
        "1.3.6.1.4.1.57264.1.14": "refs/heads/main",
        "1.3.6.1.4.1.57264.1.15": GITHUB_REPOSITORY_ID,
        "1.3.6.1.4.1.57264.1.16": "https://github.com/yc-software",
        "1.3.6.1.4.1.57264.1.17": GITHUB_REPOSITORY_OWNER_ID,
        "1.3.6.1.4.1.57264.1.18": `${GITHUB_REPOSITORY}/.github/workflows/release.yml@refs/heads/main`,
        "1.3.6.1.4.1.57264.1.19": metadata.gitHead,
        "1.3.6.1.4.1.57264.1.20": "workflow_dispatch",
        "1.3.6.1.4.1.57264.1.22": "public",
      })};`,
      "for (const [oid, value] of Object.entries(expected)) if (extension(oid) !== value) throw new Error(`unexpected certificate extension ${oid}`);",
      "await verify(bundle, {",
      "  certificateIdentityURI: /^https:\\/\\/github\\.com\\/yc-software\\/qm\\/\\.github\\/workflows\\/publish-cli\\.yml@refs\\/heads\\/main$/u,",
      '  certificateIssuer: "https://token.actions.githubusercontent.com",',
      "  tufCachePath: process.argv[3],",
      "});",
    ].join("\n"),
    { flag: "wx", mode: 0o600 },
  );
  try {
    await runForeground(
      process.execPath,
      [verifierPath, bundlePath, cachePath],
      transaction,
      npmEnvironment(transaction, testEnvironment),
      "QM provenance certificate verification",
    );
  } catch (error) {
    throw new CliError(
      `QM ${metadata.version} provenance certificate does not identify the official publish workflow`,
      {
        cause: error,
      },
    );
  }
}

function imageManifest(value: unknown, label: string): Record<string, unknown> {
  const manifest = objectValue(value);
  if (!manifest || Object.keys(manifest).sort().join(",") !== "sandboxBase,services") {
    throw new CliError(`${label} must contain only sandboxBase and services`);
  }
  if (
    typeof manifest.sandboxBase !== "string" ||
    !/^ghcr\.io\/yc-software\/qm\/sandbox-base@sha256:[a-f0-9]{64}$/.test(manifest.sandboxBase)
  ) {
    throw new CliError(`${label} has an invalid sandbox base image`);
  }
  const services = objectValue(manifest.services);
  if (!services || Object.keys(services).sort().join(",") !== IMAGE_SERVICE_NAMES.join(",")) {
    throw new CliError(`${label} must contain exactly the shipped QM service images`);
  }
  for (const [name, reference] of Object.entries(services)) {
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name) || typeof reference !== "string") {
      throw new CliError(`${label} has an invalid service image entry`);
    }
    const pattern = new RegExp(
      `^ghcr\\.io/yc-software/qm/${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}@sha256:[a-f0-9]{64}$`,
    );
    if (!pattern.test(reference)) throw new CliError(`${label} has an invalid ${name} image`);
  }
  return manifest;
}

function provenanceStatement(raw: string, metadata: ReleaseMetadata): VerifiedProvenance {
  const audit = jsonObject(raw, "npm signature audit output");
  const invalid = Array.isArray(audit.invalid) ? audit.invalid : undefined;
  const missing = Array.isArray(audit.missing) ? audit.missing : undefined;
  const verified = Array.isArray(audit.verified) ? audit.verified : undefined;
  if (!invalid || !missing || !verified || invalid.length || missing.length || verified.length !== 1) {
    throw new CliError(`npm did not verify exactly one signed QM ${metadata.version} package`);
  }
  const entry = objectValue(verified[0]);
  const attestations = objectValue(entry?.attestations);
  const provenance = objectValue(attestations?.provenance);
  if (
    entry?.name !== cliPackageName() ||
    entry.version !== metadata.version ||
    entry.location !== `node_modules/${cliPackageName()}` ||
    typeof entry.registry !== "string" ||
    entry.registry.replace(/\/+$/, "") !== NPM_REGISTRY_ORIGIN ||
    attestations?.url !== metadata.attestationUrl ||
    provenance?.predicateType !== "https://slsa.dev/provenance/v1"
  ) {
    throw new CliError(`npm verified unexpected package identity for QM ${metadata.version}`);
  }
  const bundles = Array.isArray(entry.attestationBundles) ? entry.attestationBundles : [];
  const matching = bundles.filter((bundle) => objectValue(bundle)?.predicateType === "https://slsa.dev/provenance/v1");
  if (matching.length !== 1) throw new CliError(`QM ${metadata.version} must have exactly one SLSA provenance bundle`);
  const bundle = objectValue(objectValue(matching[0])?.bundle);
  const envelope = objectValue(bundle?.dsseEnvelope);
  const encoded = envelope?.payload;
  if (envelope?.payloadType !== "application/vnd.in-toto+json" || typeof encoded !== "string") {
    throw new CliError(`QM ${metadata.version} has an invalid SLSA envelope`);
  }
  const decoded = canonicalBase64(encoded, Buffer.from(encoded, "base64").length);
  if (!decoded) throw new CliError(`QM ${metadata.version} has a non-canonical SLSA payload`);
  const statement = jsonObject(decoded, `QM ${metadata.version} SLSA statement`);
  const subjects = Array.isArray(statement.subject) ? statement.subject : [];
  const subject = objectValue(subjects[0]);
  const digest = objectValue(subject?.digest);
  const predicate = objectValue(statement.predicate);
  const definition = objectValue(predicate?.buildDefinition);
  const parameters = objectValue(definition?.externalParameters);
  const workflow = objectValue(parameters?.workflow);
  const internal = objectValue(objectValue(definition?.internalParameters)?.github);
  const dependencies = Array.isArray(definition?.resolvedDependencies) ? definition.resolvedDependencies : [];
  const runDetails = objectValue(predicate?.runDetails);
  const invocationId = objectValue(runDetails?.metadata)?.invocationId;
  if (
    statement._type !== "https://in-toto.io/Statement/v1" ||
    statement.predicateType !== "https://slsa.dev/provenance/v1" ||
    subjects.length !== 1 ||
    subject?.name !== `pkg:npm/%40yc-software/qm@${metadata.version}` ||
    !digest ||
    Object.keys(digest).join(",") !== "sha512" ||
    digest.sha512 !== metadata.integrityHex ||
    !SHA512.test(String(digest.sha512)) ||
    definition?.buildType !== "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1" ||
    workflow?.ref !== "refs/heads/main" ||
    workflow.repository !== GITHUB_REPOSITORY ||
    workflow.path !== ".github/workflows/release.yml" ||
    internal?.event_name !== "workflow_dispatch" ||
    internal.repository_id !== GITHUB_REPOSITORY_ID ||
    internal.repository_owner_id !== GITHUB_REPOSITORY_OWNER_ID ||
    !dependencies.some((dependency) => {
      const item = objectValue(dependency);
      return (
        item?.uri === `git+${GITHUB_REPOSITORY}@refs/heads/main` &&
        objectValue(item.digest)?.gitCommit === metadata.gitHead
      );
    }) ||
    objectValue(runDetails?.builder)?.id !== "https://github.com/actions/runner/github-hosted" ||
    typeof invocationId !== "string" ||
    !/^https:\/\/github\.com\/yc-software\/qm\/actions\/runs\/[1-9]\d*\/attempts\/[1-9]\d*$/.test(invocationId)
  ) {
    throw new CliError(`QM ${metadata.version} provenance does not match the official release workflow`);
  }
  return { bundle: structuredClone(bundle!) };
}

async function verifyPackage(
  transaction: string,
  metadata: ReleaseMetadata,
  npm: string,
  testEnvironment?: NodeJS.ProcessEnv,
): Promise<VerifiedPackage> {
  const verifier = join(transaction, "verifier");
  mkdirSync(verifier, { mode: 0o700 });
  writeFileSync(join(verifier, ".npmrc"), "", { flag: "wx", mode: 0o600 });
  writeFileSync(
    join(verifier, "package.json"),
    `${JSON.stringify({ private: true, dependencies: { [cliPackageName()]: metadata.version } }, null, 2)}\n`,
    { flag: "wx", mode: 0o600 },
  );
  await runForeground(
    process.execPath,
    [
      npm,
      "install",
      "--dry-run=false",
      "--ignore-scripts=true",
      "--foreground-scripts=false",
      "--audit=false",
      "--fund=false",
      "--bin-links=true",
      "--package-lock=true",
      "--package-lock-only=false",
      "--lockfile-version=3",
      "--workspaces=false",
      "--install-links=false",
      "--strict-peer-deps=true",
      "--engine-strict=true",
      "--omit=dev",
      "--omit=optional",
      ...npmArgs(transaction, "online"),
    ],
    verifier,
    npmEnvironment(transaction, testEnvironment),
    "isolated QM package install",
  );
  const packageDir = packageDirectory(verifier, cliPackageName());
  const packagePath = join(packageDir, "package.json");
  const manifestPath = join(packageDir, "manifest.json");
  const lockPath = join(verifier, "package-lock.json");
  const entryPath = join(packageDir, "dist", "bin", "qm.js");
  const binPath = join(verifier, "node_modules", ".bin", "qm");
  if (!hasPath(packageDir) || !existsSync(packagePath) || !existsSync(manifestPath) || !existsSync(entryPath)) {
    throw new CliError(`QM ${metadata.version} is missing required package files`);
  }
  if (!lstatSync(entryPath).isFile() || (lstatSync(entryPath).mode & 0o111) === 0) {
    throw new CliError(`QM ${metadata.version} has an invalid qm executable`);
  }
  if (!hasPath(binPath) || !lstatSync(binPath).isSymbolicLink() || !samePathIdentity(binPath, entryPath)) {
    throw new CliError(`QM ${metadata.version} has an invalid npm executable link`);
  }
  assertOwnedPackageTree(packageDir, true);
  imageManifest(jsonObject(readFileSync(manifestPath), manifestPath), manifestPath);
  const pkg = jsonObject(readFileSync(packagePath), packagePath);
  const scripts = objectValue(pkg.scripts);
  if (
    pkg.name !== cliPackageName() ||
    pkg.version !== metadata.version ||
    pkg.type !== "module" ||
    !repositoryMatches(pkg.repository) ||
    canonicalJson(objectValue(pkg.bin) ?? {}) !== canonicalJson({ qm: "dist/bin/qm.js" }) ||
    hasRuntimeDependencies(pkg) ||
    ["preinstall", "install", "postinstall"].some((name) => scripts?.[name] !== undefined)
  ) {
    throw new CliError(`QM ${metadata.version} package metadata is not safe for deployment`);
  }
  const lock = jsonObject(readFileSync(lockPath), lockPath);
  const packageRecord = objectValue(objectValue(lock.packages)?.[`node_modules/${cliPackageName()}`]);
  if (
    lock.lockfileVersion !== 3 ||
    lock.dependencies !== undefined ||
    !packageRecord ||
    packageRecord.version !== metadata.version ||
    packageRecord.resolved !== metadata.tarball ||
    packageRecord.integrity !== metadata.integrity ||
    packageRecord.link !== undefined
  ) {
    throw new CliError(`QM ${metadata.version} isolated lock record does not match npm release metadata`);
  }
  const audit = await runForeground(
    process.execPath,
    [npm, "audit", "signatures", "--json", "--include-attestations=true", ...npmArgs(transaction, "online")],
    verifier,
    npmEnvironment(transaction, testEnvironment),
    "QM package signature verification",
    true,
  );
  const provenance = provenanceStatement(audit, metadata);
  await verifyCertificateIdentity(transaction, npm, provenance.bundle, metadata, testEnvironment);
  return {
    packageDir,
    packageRecord: structuredClone(packageRecord),
  };
}

function digestRecord(digest: ReturnType<typeof createHash>, ...values: Array<string | Buffer>): void {
  for (const value of values) {
    const bytes = typeof value === "string" ? Buffer.from(value) : value;
    digest.update(String(bytes.length) + ":");
    digest.update(bytes);
  }
}

function packageTreeDigest(root: string): string {
  const digest = createHash("sha256");
  const visit = (path: string, relativePath: string): void => {
    const identity = lstatSync(path);
    if (identity.isDirectory() && !identity.isSymbolicLink()) {
      digestRecord(digest, "d", relativePath, String(identity.mode & 0o7777));
      for (const name of readdirSync(path).sort()) {
        visit(join(path, name), relativePath ? relativePath + "/" + name : name);
      }
    } else if (identity.isFile()) {
      digestRecord(digest, "f", relativePath, String(identity.mode & 0o7777), readFileSync(path));
    } else if (identity.isSymbolicLink()) {
      digestRecord(digest, "l", relativePath, readlinkSync(path));
    } else {
      throw new CliError(path + " has an unsupported filesystem type");
    }
  };
  visit(root, "");
  return digest.digest("hex");
}

function assertRegularDirectory(path: string): void {
  const identity = lstatSync(path);
  if (!identity.isDirectory() || identity.isSymbolicLink()) {
    throw new CliError(path + " must be a regular directory");
  }
}

function assertRegularFile(path: string): void {
  const identity = lstatSync(path);
  if (!identity.isFile() || identity.isSymbolicLink()) {
    throw new CliError(path + " must be a regular file");
  }
}

function assertUnlinkedRegularFile(path: string): void {
  const identity = lstatSync(path);
  if (!identity.isFile() || identity.isSymbolicLink()) {
    throw new CliError(path + " must be a regular file");
  }
  if (identity.nlink !== 1) {
    throw new CliError(path + " must not be hard-linked");
  }
}

function assertPackageEntry(path: string): void {
  const identity = lstatSync(path);
  if (!identity.isDirectory() && !identity.isSymbolicLink()) {
    throw new CliError(path + " must be a package directory or directory link");
  }
}

function effectiveUid(): number {
  if (typeof process.geteuid !== "function") {
    throw new CliError("automatic update requires POSIX filesystem ownership checks");
  }
  return process.geteuid();
}

function assertOwnedPath(path: string): void {
  const identity = lstatSync(path);
  if (identity.uid !== effectiveUid()) throw new CliError(path + " must be owned by the current user");
  if (!identity.isSymbolicLink() && (identity.mode & 0o022) !== 0) {
    throw new CliError(path + " must not be writable by group or other users");
  }
}

async function aclCommand(executable: string, args: string[], label: string): Promise<string> {
  return runForeground(executable, args, "/", { LANG: "C", LC_ALL: "C" }, "ACL verification for " + label, true);
}

function nearestExistingPath(path: string): string {
  let current = resolve(path);
  while (!hasPath(current)) {
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return current;
}

async function assertDarwinAclSafeAncestors(starts: string[]): Promise<void> {
  const ancestors = new Set<string>();
  for (const start of starts) {
    let current = resolve(start);
    for (;;) {
      ancestors.add(current);
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  if (ancestors.size) {
    const body = await aclCommand("/bin/ls", ["-lden", "--", ...ancestors], [...ancestors][0]!);
    if (body.split("\n").some((line) => /^\s*\d+:\s.*\sallow(?:\s|$)/u.test(line))) {
      throw new CliError("automatic update paths must not have permission-granting ancestor ACLs on macOS");
    }
  }
}

async function assertDarwinAclSafeRoots(roots: string[]): Promise<void> {
  const lexical = roots.map((root) => resolve(root));
  const existing = lexical.filter(hasPath);
  const unique = [...new Set([...existing, ...existing.map(canonicalPath)])];
  if (unique.length) {
    const acl = await aclCommand("/usr/bin/find", ["-P", "--", ...unique, "-acl", "-print", "-quit"], unique[0]!);
    if (acl !== "") throw new CliError("automatic update requires protected paths without extended ACLs on macOS");
  }
  const starts: string[] = [];
  for (const root of lexical) {
    if (hasPath(root)) {
      starts.push(dirname(root), dirname(canonicalPath(root)));
    } else {
      const nearest = nearestExistingPath(root);
      starts.push(nearest, canonicalPath(nearest));
    }
  }
  await assertDarwinAclSafeAncestors(starts);
}

function protectedUpdatePaths(
  configDir: string,
  sandboxDir: string,
  config: QmConfig,
  environmentPath: string,
): string[] {
  return [
    configDir,
    sandboxDir,
    join(configDir, "plugins"),
    ...config.skills.map((path) => resolve(configDir, path)),
    environmentPath,
  ];
}

function assertInputsDisjointFromRoot(inputs: string[], root: string, label: string): void {
  const rootIdentity = filesystemIdentity(canonicalPath(root));
  for (const input of inputs) {
    if (
      lexicalPathHasAncestorIdentity(input, rootIdentity) ||
      pathHasAncestorIdentity(canonicalPath(nearestExistingPath(input)), rootIdentity)
    ) {
      throw new CliError(input + " must be physically disjoint from " + label + " during automatic update");
    }
    if (hasPath(input) && pathHasAncestorIdentity(root, filesystemIdentity(canonicalPath(input)))) {
      throw new CliError(input + " must be physically disjoint from " + label + " during automatic update");
    }
  }
}

async function linuxAclInspector(
  configured: string | undefined,
  deploymentIdentity: FilesystemIdentity,
  allowTestExecutable: boolean,
): Promise<string> {
  const search = (process.env.PATH ?? "")
    .split(delimiter)
    .filter((path) => path !== "" && isAbsolute(path))
    .map((path) => join(path, "getfacl"));
  const candidates = configured === undefined ? search : [configured];
  let rejected: unknown;
  for (const candidate of candidates) {
    if (!candidate || !isAbsolute(candidate) || !hasPath(candidate)) continue;
    let executable: ProjectedExecutable;
    try {
      executable = trustedExecutable(candidate, deploymentIdentity);
      if (!allowTestExecutable) {
        let current = executable.source;
        for (;;) {
          if (lstatSync(current).uid !== 0) throw new CliError(current + " must be owned by root");
          const parent = dirname(current);
          if (parent === current) break;
          current = parent;
        }
      }
    } catch (error) {
      rejected ??= error;
      continue;
    }
    const source = canonicalPath(executable.source);
    const identity = lstatSync(source);
    if (
      source !== executable.source ||
      !sameFilesystemIdentity(filesystemIdentity(source), executable.identity) ||
      identity.nlink !== executable.nlink ||
      (identity.mode & 0o7777) !== executable.mode ||
      identity.size !== executable.size ||
      identity.mtimeMs !== executable.mtimeMs ||
      identity.ctimeMs !== executable.ctimeMs
    ) {
      throw new CliError(executable.source + " changed during ACL verification");
    }
    return executable.source;
  }
  if (configured !== undefined && rejected) {
    throw new CliError("automatic update on Linux requires a trusted external getfacl executable", {
      cause: rejected,
    });
  }
  throw new CliError("automatic update on Linux requires trusted getfacl from the acl package on PATH");
}

async function assertLinuxAclFree(executable: string, roots: string[], recursive: boolean): Promise<void> {
  if (!roots.length) return;
  const args = ["-P", ...(recursive ? ["-R"] : []), "-s", "-c", "-n", "--absolute-names", "--", ...roots];
  const body = await aclCommand(executable, args, roots[0]!);
  if (body.trim() !== "") {
    throw new CliError("automatic update requires protected paths without extended ACLs on Linux");
  }
}

async function assertLinuxAclSafeAncestors(executable: string, starts: string[]): Promise<void> {
  const ancestors = new Set<string>();
  for (const start of starts) {
    let current = resolve(start);
    for (;;) {
      ancestors.add(current);
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  await assertLinuxAclFree(executable, [...ancestors], false);
}

async function assertLinuxAclSafeRoots(executable: string, roots: string[]): Promise<void> {
  const lexical = roots.map((root) => resolve(root));
  const existing = lexical.filter(hasPath);
  await assertLinuxAclFree(executable, [...new Set([...existing, ...existing.map(canonicalPath)])], true);
  const starts = lexical.flatMap((root) => {
    if (hasPath(root)) return [dirname(root), dirname(canonicalPath(root))];
    const nearest = nearestExistingPath(root);
    return [nearest, canonicalPath(nearest)];
  });
  await assertLinuxAclSafeAncestors(executable, starts);
}

function assertTrustedPathAncestors(path: string): void {
  const uid = effectiveUid();
  let current = canonicalPath(path);
  for (;;) {
    const identity = lstatSync(current);
    if (identity.uid !== 0 && identity.uid !== uid) {
      throw new CliError(current + " must be owned by root or the current user");
    }
    const trustedStickyDirectory = identity.uid === 0 && identity.isDirectory() && (identity.mode & 0o1000) !== 0;
    if ((identity.mode & 0o022) !== 0 && !trustedStickyDirectory) {
      throw new CliError(current + " must not be writable by group or other users");
    }
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function assertTrustedLexicalPathAncestors(path: string): void {
  const uid = effectiveUid();
  let current = nearestExistingPath(resolve(path));
  for (;;) {
    const identity = lstatSync(current);
    if (identity.uid !== 0 && identity.uid !== uid) {
      throw new CliError(current + " must be owned by root or the current user");
    }
    const trustedStickyDirectory = identity.uid === 0 && identity.isDirectory() && (identity.mode & 0o1000) !== 0;
    if (!identity.isSymbolicLink() && (identity.mode & 0o022) !== 0 && !trustedStickyDirectory) {
      throw new CliError(current + " must not be writable by group or other users");
    }
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function assertTrustedAbsentPath(path: string): string {
  const absent = resolve(path);
  if (hasPath(absent)) throw new CliError(absent + " changed during automatic update");
  const nearest = canonicalPath(nearestExistingPath(absent));
  const identity = lstatSync(nearest);
  if (!identity.isDirectory() || identity.isSymbolicLink()) {
    throw new CliError(nearest + " must be a trusted directory for an absent automatic update input");
  }
  if ((identity.uid !== 0 && identity.uid !== effectiveUid()) || (identity.mode & 0o022) !== 0) {
    throw new CliError(nearest + " must not permit other users to create an automatic update input");
  }
  assertTrustedPathAncestors(nearest);
  return nearest;
}

function assertOwnedPackageTree(root: string, requireUnlinkedFiles = false): void {
  const visit = (path: string): void => {
    assertOwnedPath(path);
    const identity = lstatSync(path);
    if (identity.isDirectory() && !identity.isSymbolicLink()) {
      for (const name of readdirSync(path)) visit(join(path, name));
      return;
    }
    if (identity.isFile()) {
      if (requireUnlinkedFiles && identity.nlink !== 1) {
        throw new CliError(path + " must not be hard-linked");
      }
      return;
    }
    if (identity.isSymbolicLink()) {
      throw new CliError(path + " must not be a symbolic link");
    }
    throw new CliError(path + " has an unsupported filesystem type");
  };
  visit(root);
}

function assertTrustedDirectoryTree(root: string): string[] {
  const uid = effectiveUid();
  const roots = new Set<string>();
  const visitedDirectories = new Set<string>();
  const visit = (path: string): void => {
    const identity = lstatSync(path);
    if (identity.uid !== 0 && identity.uid !== uid) {
      throw new CliError(path + " must be owned by root or the current user");
    }
    if (!identity.isSymbolicLink() && (identity.mode & 0o022) !== 0) {
      throw new CliError(path + " must not be writable by group or other users");
    }
    if (identity.isSymbolicLink()) {
      const target = canonicalPath(path);
      roots.add(target);
      assertTrustedPathAncestors(target);
      visit(target);
      return;
    }
    if (identity.isDirectory()) {
      const key = `${identity.dev}:${identity.ino}`;
      if (visitedDirectories.has(key)) return;
      visitedDirectories.add(key);
      for (const name of readdirSync(path)) visit(join(path, name));
      return;
    }
    if (!identity.isFile()) throw new CliError(path + " has an unsupported filesystem type");
  };
  const source = canonicalPath(root);
  roots.add(source);
  assertTrustedPathAncestors(source);
  visit(source);
  return [...roots];
}

function trustedPackageTreeDigest(root: string): string {
  const uid = effectiveUid();
  const digest = createHash("sha256");
  assertTrustedPathAncestors(root);
  const visit = (path: string, relativePath: string): void => {
    const identity = lstatSync(path);
    if (identity.uid !== 0 && identity.uid !== uid) {
      throw new CliError(path + " must be owned by root or the current user");
    }
    if ((identity.mode & 0o022) !== 0) {
      throw new CliError(path + " must not be writable by group or other users");
    }
    if (identity.isDirectory() && !identity.isSymbolicLink()) {
      digestRecord(digest, "d", relativePath, String(identity.mode & 0o7777));
      for (const name of readdirSync(path).sort())
        visit(join(path, name), relativePath ? relativePath + "/" + name : name);
      return;
    }
    if (identity.isFile()) {
      const trustedRootLinks = identity.uid === 0 && (identity.mode & 0o022) === 0;
      if (identity.nlink !== 1 && !trustedRootLinks) throw new CliError(path + " must not be hard-linked");
      digestRecord(digest, "f", relativePath, String(identity.mode & 0o7777), readFileSync(path));
      return;
    }
    throw new CliError(path + " has an unsupported filesystem type");
  };
  visit(root, "");
  return digest.digest("hex");
}

function trustedNpmProjection(transaction: string, npm: string, npmRoot: string): { npm: string; npmRoot: string } {
  const sourceDigest = trustedPackageTreeDigest(npmRoot);
  const projectedRoot = join(transaction, "trusted-npm");
  cpSync(npmRoot, projectedRoot, { recursive: true, errorOnExist: true });
  const projectedDigest = packageTreeDigest(projectedRoot);
  if (projectedDigest !== sourceDigest || trustedPackageTreeDigest(npmRoot) !== sourceDigest) {
    throw new CliError("the trusted npm installation changed while preparing automatic update");
  }
  const npmRelativePath = relative(npmRoot, npm);
  if (!npmRelativePath || npmRelativePath.startsWith(".." + sep) || isAbsolute(npmRelativePath)) {
    throw new CliError("the trusted npm executable must be inside its package");
  }
  const projectedNpm = join(projectedRoot, npmRelativePath);
  if (!hasPath(projectedNpm)) {
    throw new CliError("the trusted npm projection is incomplete");
  }
  assertRegularFile(projectedNpm);
  return { npm: projectedNpm, npmRoot: projectedRoot };
}

function projectUpdateLock(configDir: string): () => void {
  const project = canonicalPath(resolve(configDir));
  assertRegularDirectory(project);
  assertOwnedPath(project);
  const path = join(project, ".qm-update.lock");
  try {
    mkdirSync(path, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new CliError(
        "another automatic QM update is already in progress for " +
          project +
          "; if no updater is running, remove the stale lock directory " +
          path,
      );
    }
    throw error;
  }
  const lockIdentity = filesystemIdentity(path);
  return (): void => {
    if (!sameFilesystemIdentity(filesystemIdentity(path), lockIdentity)) {
      throw new CliError(path + " changed during automatic update");
    }
    rmdirSync(path);
  };
}

function retiredWorkflowMarkers(body: string): number {
  return [
    /^name:\s*QM browser update\s*$/m,
    /^\s*group:\s*qm-browser-update\s*$/m,
    /^\s*request_id:\s*$/m,
    /^\s*requested_by:\s*$/m,
    /npm exec qm -- update/,
  ].filter((pattern) => pattern.test(body)).length;
}

function assertNoRetiredUpdateWorkflow(dir: string): void {
  const workflows = join(dir, ".github", "workflows");
  if (!existsSync(workflows)) return;
  assertRegularDirectory(workflows);
  for (const name of readdirSync(workflows).filter((entry) => /\.ya?ml$/i.test(entry))) {
    const path = join(workflows, name);
    assertRegularFile(path);
    const retired = name === "qm-update.yml" || retiredWorkflowMarkers(readFileSync(path, "utf8")) >= 3;
    if (!retired) continue;
    throw new CliError(
      path +
        " is a retired browser update workflow; cancel its queued or running jobs, wait for every job to reach a terminal status, remove the workflow, delete the QM_DEPLOY_ENV repository secret, delete or rotate FLY_SANDBOX_API_TOKEN, and revoke and remove every repository, app, host, and CI copy of QM_UPDATE_GITHUB_TOKEN and the other QM_UPDATE_GITHUB_* settings before updating",
    );
  }
}

function customImageConfiguration(config: QmConfig, target: Target): string[] {
  const names = Object.keys(config.imageOverrides);
  if (target === "docker" && localSandboxActive(config) && config.sandbox?.image !== undefined) {
    names.push("sandbox.image");
  }
  if (target === "fly") {
    if (config.imageFrom !== undefined) names.push("imageFrom");
  }
  return [...new Set(names)];
}

function assertSafeNodeModulesTree(root: string, packageName: string, allowIncomplete: boolean): void {
  const rootIdentity = filesystemIdentity(canonicalPath(root));
  const links = new Map<string, { count: bigint; nlink: bigint; path: string }>();
  const visit = (path: string): void => {
    assertOwnedPath(path);
    const identity = lstatSync(path, { bigint: true });
    if (identity.dev !== rootIdentity.dev) throw new CliError(path + " must be on the node_modules filesystem");
    if (identity.isDirectory() && !identity.isSymbolicLink()) {
      for (const name of readdirSync(path)) visit(join(path, name));
      return;
    }
    if (identity.isFile()) {
      const key = identity.dev + ":" + identity.ino;
      const current = links.get(key);
      if (current) current.count += 1n;
      else links.set(key, { count: 1n, nlink: identity.nlink, path });
      return;
    }
    if (identity.isSymbolicLink()) {
      if (identity.nlink !== 1n) throw new CliError(path + " must not have hard links outside node_modules");
      let target: string;
      try {
        target = canonicalPath(path);
      } catch (error) {
        const expectedBin = join(root, ".bin", "qm");
        const expectedTarget = join(root, ...packageName.split("/"), "dist", "bin", "qm.js");
        if (
          allowIncomplete &&
          path === expectedBin &&
          (error as NodeJS.ErrnoException).code === "ENOENT" &&
          readlinkSync(path) === relative(dirname(path), expectedTarget)
        ) {
          return;
        }
        throw new CliError(path + " must resolve to a regular file inside node_modules", { cause: error });
      }
      if (!pathHasAncestorIdentity(target, rootIdentity) || !lstatSync(target).isFile()) {
        throw new CliError(path + " must resolve to a regular file inside node_modules");
      }
      return;
    }
    throw new CliError(path + " has an unsupported filesystem type");
  };
  visit(root);
  for (const link of links.values()) {
    if (link.count !== link.nlink) throw new CliError(link.path + " must not have hard links outside node_modules");
  }
}

function assertPackageManagerLayout(dir: string, packageName: string, allowIncomplete = false): void {
  const packagePath = join(dir, "package.json");
  const lockPath = join(dir, "package-lock.json");
  const hiddenLockPath = join(dir, "node_modules", ".package-lock.json");
  const npmrcPath = join(dir, ".npmrc");
  const shrinkwrapPath = join(dir, "npm-shrinkwrap.json");
  if (hasPath(npmrcPath)) {
    throw new CliError("automatic update requires removing deployment .npmrc configuration");
  }
  if (hasPath(shrinkwrapPath)) {
    throw new CliError("automatic update does not support npm-shrinkwrap.json deployments");
  }
  for (const name of FOREIGN_PACKAGE_MANAGER_FILES) {
    if (hasPath(join(dir, name))) {
      throw new CliError("automatic update requires a standalone npm package-lock deployment, not " + name);
    }
  }
  for (const path of [dir, join(dir, "node_modules")]) {
    assertRegularDirectory(path);
    assertOwnedPath(path);
  }
  if (!hasPath(packagePath)) throw new CliError("update requires " + packagePath);
  assertUnlinkedRegularFile(packagePath);
  assertOwnedPath(packagePath);
  const pkg = jsonObject(readFileSync(packagePath), packagePath);
  if (Object.hasOwn(objectValue(pkg.directories) ?? {}, "bin")) {
    throw new CliError(packagePath + " must not declare directories.bin during automatic update");
  }
  assertSafeNodeModulesTree(join(dir, "node_modules"), packageName, allowIncomplete);
  const scopeDirectory = dirname(packageDirectory(dir, packageName));
  if (hasPath(scopeDirectory)) {
    assertRegularDirectory(scopeDirectory);
    assertOwnedPath(scopeDirectory);
  } else if (!allowIncomplete) {
    throw new CliError(scopeDirectory + " is missing");
  }
  if (!hasPath(lockPath)) throw new CliError("update requires " + lockPath);
  assertUnlinkedRegularFile(lockPath);
  assertOwnedPath(lockPath);
  if (hasPath(hiddenLockPath)) {
    assertUnlinkedRegularFile(hiddenLockPath);
    assertOwnedPath(hiddenLockPath);
  }
  if (pkg.workspaces !== undefined) {
    throw new CliError(
      packagePath +
        " declares npm workspaces; update " +
        packageName +
        " through the workspace's normal source and package-manager workflow",
    );
  }
  if (
    pkg.packageManager !== undefined &&
    (typeof pkg.packageManager !== "string" ||
      !/^npm@[1-9]\d*\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(pkg.packageManager))
  ) {
    throw new CliError(packagePath + " declares an incompatible packageManager");
  }
  for (const field of ["devDependencies", "optionalDependencies", "peerDependencies"]) {
    if (objectValue(pkg[field])?.[packageName] !== undefined) {
      throw new CliError(packagePath + " must declare " + packageName + " only in dependencies, not " + field);
    }
  }
  for (const field of ["bundleDependencies", "bundledDependencies"]) {
    if (Array.isArray(pkg[field]) && pkg[field].includes(packageName)) {
      throw new CliError(packagePath + " must not bundle " + packageName);
    }
  }
  if (pkg.overrides !== undefined) {
    throw new CliError(packagePath + " must not override packages during automatic update");
  }
  const lock = jsonObject(readFileSync(lockPath), lockPath);
  if (lock.lockfileVersion !== 3 || lock.dependencies !== undefined) {
    throw new CliError(
      lockPath +
        " must be reviewed and upgraded to npm lockfile version 3 with npm install --package-lock-only --ignore-scripts",
    );
  }
  const live = packageDirectory(dir, packageName);
  if (hasPath(live)) {
    assertPackageEntry(live);
    assertOwnedPath(live);
    if (!lstatSync(live).isSymbolicLink()) assertOwnedPackageTree(live);
  } else if (!allowIncomplete) {
    throw new CliError(live + " is missing");
  }
}

function assertNoAncestorWorkspace(dir: string): void {
  let current = dirname(dir);
  for (;;) {
    const packagePath = join(current, "package.json");
    if (hasPath(packagePath)) {
      assertRegularFile(packagePath);
      if (jsonObject(readFileSync(packagePath), packagePath).workspaces !== undefined) {
        throw new CliError(dir + " must be a standalone npm project outside any ancestor workspace");
      }
    }
    if (hasPath(join(current, "pnpm-workspace.yaml"))) {
      throw new CliError(dir + " must be outside any ancestor pnpm workspace");
    }
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function deploymentConfig(path: string, target: Target): QmConfig {
  const config = loadConfigAt(path).config;
  if (config.target !== target) {
    throw new CliError(
      "automatic update requires the configured " +
        config.target +
        " target; remove the --target " +
        target +
        " override",
    );
  }
  return config;
}

function assertDeploymentReady(
  config: QmConfig,
  configDir: string,
  sandboxDir: string,
  target: Target,
  packageName: string,
  expectedCurrent?: string,
  allowCustomImages = false,
  allowIncomplete = false,
): string {
  assertNoRetiredUpdateWorkflow(configDir);
  assertNoAncestorWorkspace(configDir);
  if (!allowCustomImages && sandboxBackend(config) === "sprites" && hasPath(join(sandboxDir, "Dockerfile"))) {
    throw new CliError(
      join(sandboxDir, "Dockerfile") +
        " is a retired Sprites sandbox recipe that no longer applies; review and archive or remove it before updating",
    );
  }
  const customImages = customImageConfiguration(config, target);
  if (customImages.length && !allowCustomImages) {
    throw new CliError(
      "automatic update is unavailable while custom image " +
        (customImages.length === 1 ? "configuration is" : "configurations are") +
        " set (" +
        customImages.join(", ") +
        "); use the release details and the deployment's normal image rollout process",
    );
  }
  runChecks(config, configDir, sandboxDir, { report: false });
  assertPackageManagerLayout(configDir, packageName, allowIncomplete);
  assertSupportedPackageEntry(configDir, packageName, allowIncomplete);
  const current = currentVersion(configDir, packageName);
  if (expectedCurrent !== undefined && current !== expectedCurrent) {
    throw new CliError(
      "the deployment's QM pin changed from " + expectedCurrent + " to " + current + " during update verification",
    );
  }
  const installed = installedVersion(configDir, packageName);
  if (!allowIncomplete && installed !== current) {
    throw new CliError(
      packageDirectory(configDir, packageName) +
        " contains QM " +
        (installed ?? "without a version") +
        ", not the deployment's current QM " +
        current,
    );
  }
  return current;
}

interface DeploymentFingerprint {
  files: Array<{ path: string; digest: string }>;
  packageDigest: string;
  workflowsDigest: string;
  localInputs: LocalInputFingerprint[];
}

interface DeploymentEnvironmentSnapshot {
  path: string;
  content: Buffer;
  digest: string;
  identity?: {
    dev: bigint;
    ino: bigint;
    size: bigint;
    mode: bigint;
    uid: bigint;
    nlink: bigint;
    mtimeNs: bigint;
    ctimeNs: bigint;
  };
}

function trustedConfigurationSnapshot(path: string): RegularFileSnapshot {
  assertTrustedPathAncestors(dirname(path));
  let descriptor: number;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    throw new CliError(path + " must be an unlinked current-user configuration file", { cause: error });
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    const uid = BigInt(effectiveUid());
    if (!before.isFile() || before.nlink !== 1n || before.uid !== uid || (before.mode & 0o022n) !== 0n) {
      throw new CliError(path + " must be an unlinked current-user configuration file");
    }
    if (before.size > BigInt(MAX_DEPLOYMENT_INPUT_BYTES)) {
      throw new CliError(path + ` exceeds the ${MAX_DEPLOYMENT_INPUT_BYTES}-byte limit`);
    }
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let length = 0;
    while (length < buffer.length) {
      const bytes = readSync(descriptor, buffer, length, buffer.length - length, length);
      if (bytes === 0) break;
      length += bytes;
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (
      !after.isFile() ||
      after.nlink !== 1n ||
      after.uid !== uid ||
      (after.mode & 0o022n) !== 0n ||
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.mode !== before.mode ||
      after.uid !== before.uid ||
      after.nlink !== before.nlink ||
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs ||
      after.ctimeNs !== before.ctimeNs ||
      BigInt(length) !== after.size
    ) {
      throw new CliError(path + " changed while it was being read");
    }
    return {
      content: buffer.subarray(0, length),
      identity: { dev: after.dev, ino: after.ino },
    };
  } finally {
    closeSync(descriptor);
  }
}

interface GuardedDeploymentFingerprint {
  files: Array<{ path: string; digest: string }>;
  workflowsDigest: string;
  configPath: string;
  configBody: string;
  configMode: number;
  localInputs: LocalInputFingerprint[];
}

interface LocalInputFingerprint {
  path: string;
  resolved?: string;
  identity?: FilesystemIdentity;
  digest: string;
}

function localInputFingerprints(configDir: string, sandboxDir: string, config: QmConfig): LocalInputFingerprint[] {
  const inputs = [
    { path: sandboxDir, required: false },
    { path: join(configDir, "plugins"), required: false },
    ...config.skills.map((path) => ({ path: resolve(configDir, path), required: true })),
  ];
  return inputs.map((input) => {
    if (!hasPath(input.path)) {
      if (input.required) throw new CliError(input.path + " is required by the deployment skills configuration");
      return { path: input.path, digest: "absent" };
    }
    const resolved = canonicalPath(input.path);
    assertRegularDirectory(resolved);
    assertTrustedPathAncestors(resolved);
    assertOwnedPackageTree(resolved, true);
    return {
      path: input.path,
      resolved,
      identity: filesystemIdentity(resolved),
      digest: packageTreeDigest(resolved),
    };
  });
}

function assertLocalInputFingerprints(expected: LocalInputFingerprint[]): void {
  for (const input of expected) {
    if (input.digest === "absent") {
      if (hasPath(input.path)) throw new CliError(input.path + " changed during the QM update");
      continue;
    }
    let resolved: string;
    try {
      resolved = canonicalPath(input.path);
    } catch (error) {
      throw new CliError(input.path + " changed during the QM update", { cause: error });
    }
    if (
      resolved !== input.resolved ||
      !input.identity ||
      !sameFilesystemIdentity(filesystemIdentity(resolved), input.identity)
    ) {
      throw new CliError(input.path + " changed during the QM update");
    }
    assertTrustedPathAncestors(resolved);
    assertOwnedPackageTree(resolved, true);
    if (packageTreeDigest(resolved) !== input.digest) {
      throw new CliError(input.path + " changed during the QM update");
    }
  }
}

function fileFingerprint(path: string): string {
  if (!hasPath(path)) return "absent";
  assertUnlinkedRegularFile(path);
  assertOwnedPath(path);
  assertTrustedPathAncestors(path);
  const identity = lstatSync(path);
  return createHash("sha256")
    .update(String(identity.mode & 0o7777) + "\0")
    .update(readFileSync(path))
    .digest("hex");
}

function deploymentEnvironmentSnapshot(
  path: string,
  required: boolean,
  configIdentity: FilesystemIdentity,
): DeploymentEnvironmentSnapshot {
  let descriptor: number;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" && !required) {
      return { path, content: Buffer.alloc(0), digest: "absent" };
    }
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new CliError("--env-file not found: " + path, { cause: error });
    }
    throw new CliError(path + " must be an unlinked regular deployment environment file", { cause: error });
  }
  try {
    assertTrustedPathAncestors(dirname(path));
    const before = fstatSync(descriptor, { bigint: true });
    const uid = BigInt(effectiveUid());
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.uid !== uid ||
      sameFilesystemIdentity({ dev: before.dev, ino: before.ino }, configIdentity)
    ) {
      throw new CliError(path + " must be an unlinked current-user file separate from the deployment config");
    }
    if ((before.mode & 0o022n) !== 0n) {
      throw new CliError(path + " must not be writable by group or other users");
    }
    if (before.size > BigInt(MAX_DEPLOYMENT_INPUT_BYTES)) {
      throw new CliError(path + ` exceeds the ${MAX_DEPLOYMENT_INPUT_BYTES}-byte limit`);
    }
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let length = 0;
    while (length < buffer.length) {
      const bytes = readSync(descriptor, buffer, length, buffer.length - length, length);
      if (bytes === 0) break;
      length += bytes;
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (
      !after.isFile() ||
      after.nlink !== 1n ||
      after.uid !== uid ||
      (after.mode & 0o022n) !== 0n ||
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.mode !== before.mode ||
      after.uid !== before.uid ||
      after.nlink !== before.nlink ||
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs ||
      after.ctimeNs !== before.ctimeNs ||
      BigInt(length) !== after.size
    ) {
      throw new CliError(path + " changed while it was being read");
    }
    const content = buffer.subarray(0, length);
    const digest = createHash("sha256")
      .update(String(Number(after.mode & 0o7777n)) + "\0")
      .update(content)
      .digest("hex");
    return {
      path,
      content,
      digest,
      identity: {
        dev: after.dev,
        ino: after.ino,
        size: after.size,
        mode: after.mode,
        uid: after.uid,
        nlink: after.nlink,
        mtimeNs: after.mtimeNs,
        ctimeNs: after.ctimeNs,
      },
    };
  } finally {
    closeSync(descriptor);
  }
}

function assertDeploymentEnvironmentSnapshotCurrent(snapshot: DeploymentEnvironmentSnapshot): void {
  let descriptor: number;
  try {
    descriptor = openSync(snapshot.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" && snapshot.identity === undefined) return;
    throw new CliError(snapshot.path + " changed during the QM update", { cause: error });
  }
  try {
    const current = fstatSync(descriptor, { bigint: true });
    const expected = snapshot.identity;
    if (
      !expected ||
      !current.isFile() ||
      current.dev !== expected.dev ||
      current.ino !== expected.ino ||
      current.size !== expected.size ||
      current.mode !== expected.mode ||
      current.uid !== expected.uid ||
      current.nlink !== expected.nlink ||
      current.mtimeNs !== expected.mtimeNs ||
      current.ctimeNs !== expected.ctimeNs
    ) {
      throw new CliError(snapshot.path + " changed during the QM update");
    }
  } finally {
    closeSync(descriptor);
  }
}

function guardedConfigBody(path: string): string {
  assertUnlinkedRegularFile(path);
  assertOwnedPath(path);
  return readFileSync(path, "utf8");
}

function workflowsFingerprint(dir: string): string {
  const workflows = join(dir, ".github", "workflows");
  if (!hasPath(workflows)) return "absent";
  assertRegularDirectory(workflows);
  assertOwnedPath(workflows);
  const digest = createHash("sha256");
  for (const name of readdirSync(workflows).sort()) {
    const path = join(workflows, name);
    if (!lstatSync(path).isFile()) continue;
    digestRecord(digest, name, fileFingerprint(path));
  }
  return digest.digest("hex");
}

function deploymentFingerprint(
  configDir: string,
  configPath: string,
  sandboxDir: string,
  packageName: string,
  config: QmConfig,
  environment: DeploymentEnvironmentSnapshot,
): DeploymentFingerprint {
  const paths = [
    configPath,
    join(configDir, "package.json"),
    join(configDir, "package-lock.json"),
    join(configDir, ".npmrc"),
    join(configDir, "npm-shrinkwrap.json"),
    ...FOREIGN_PACKAGE_MANAGER_FILES.map((name) => join(configDir, name)),
    environment.path,
  ];
  return {
    files: paths.map((path) => ({
      path,
      digest: path === environment.path ? environment.digest : fileFingerprint(path),
    })),
    packageDigest: hasPath(packageDirectory(configDir, packageName))
      ? packageTreeDigest(packageDirectory(configDir, packageName))
      : "absent",
    workflowsDigest: workflowsFingerprint(configDir),
    localInputs: localInputFingerprints(configDir, sandboxDir, config),
  };
}

function guardedDeploymentFingerprint(
  configDir: string,
  configPath: string,
  sandboxDir: string,
  config: QmConfig,
  environment: DeploymentEnvironmentSnapshot,
): GuardedDeploymentFingerprint {
  const paths = [
    join(configDir, ".npmrc"),
    join(configDir, "npm-shrinkwrap.json"),
    ...FOREIGN_PACKAGE_MANAGER_FILES.map((name) => join(configDir, name)),
    environment.path,
  ];
  return {
    files: paths.map((path) => ({
      path,
      digest: path === environment.path ? environment.digest : fileFingerprint(path),
    })),
    workflowsDigest: workflowsFingerprint(configDir),
    configPath,
    configBody: guardedConfigBody(configPath),
    configMode: lstatSync(configPath).mode & 0o7777,
    localInputs: localInputFingerprints(configDir, sandboxDir, config),
  };
}

function assertAwsConfigPinMutation(expected: GuardedDeploymentFingerprint): void {
  const currentBody = guardedConfigBody(expected.configPath);
  if (currentBody === expected.configBody) return;
  const config = deploymentConfig(expected.configPath, "aws");
  const version = config.env.core?.AWS_DEPLOY_IMAGE_VERSION;
  const role = config.env.core?.AWS_DEPLOY_EXEC_ROLE_ARN;
  const source = config.env.core?.AWS_DEPLOY_IMAGE_SOURCE_SHA256;
  const accountId = config.aws?.accountId;
  if (
    typeof version !== "string" ||
    !/^[1-9]\d*$/.test(version) ||
    typeof role !== "string" ||
    typeof accountId !== "string" ||
    !new RegExp(`^arn:aws[a-z-]*:iam::${accountId}:role/[A-Za-z0-9_+=,.@/-]+$`).test(role) ||
    typeof source !== "string" ||
    !/^[a-f0-9]{64}$/.test(source) ||
    currentBody !==
      updateConfigCoreEnv(expected.configBody, {
        AWS_DEPLOY_IMAGE_VERSION: version,
        AWS_DEPLOY_EXEC_ROLE_ARN: role,
        AWS_DEPLOY_IMAGE_SOURCE_SHA256: source,
      })
  ) {
    throw new CliError(expected.configPath + " changed unexpectedly during the AWS deployment");
  }
}

function assertGuardedFingerprint(
  expected: GuardedDeploymentFingerprint,
  configDir: string,
  target: Target,
  allowAwsPinMutation = false,
): void {
  if ((lstatSync(expected.configPath).mode & 0o7777) !== expected.configMode) {
    throw new CliError(expected.configPath + " changed mode during the QM update");
  }
  if (allowAwsPinMutation && target === "aws") assertAwsConfigPinMutation(expected);
  else if (guardedConfigBody(expected.configPath) !== expected.configBody) {
    throw new CliError(
      expected.configPath + " changed during the QM update; reconcile it and retry from the current state",
    );
  }
  for (const file of expected.files) {
    if (fileFingerprint(file.path) !== file.digest) {
      throw new CliError(file.path + " changed during the QM update; reconcile it and retry from the current state");
    }
  }
  if (workflowsFingerprint(configDir) !== expected.workflowsDigest) {
    throw new CliError("the deployment workflows changed during the QM update; reconcile them before retrying");
  }
  assertLocalInputFingerprints(expected.localInputs);
}

function assertFingerprint(expected: DeploymentFingerprint, configDir: string, packageName: string): void {
  for (const file of expected.files) {
    if (fileFingerprint(file.path) !== file.digest) {
      throw new CliError(file.path + " changed while the QM update was being verified; retry from the current state");
    }
  }
  if (
    (hasPath(packageDirectory(configDir, packageName))
      ? packageTreeDigest(packageDirectory(configDir, packageName))
      : "absent") !== expected.packageDigest ||
    workflowsFingerprint(configDir) !== expected.workflowsDigest
  ) {
    throw new CliError("the deployment changed while the QM update was being verified; retry from the current state");
  }
  assertLocalInputFingerprints(expected.localInputs);
}

function packageRecordMatches(record: unknown, verified: Record<string, unknown>): boolean {
  const value = objectValue(record);
  return value !== undefined && canonicalJson(value) === canonicalJson(verified);
}

interface PackageManagerBaseline {
  packageJson: Record<string, unknown>;
  lockProjection: Record<string, unknown>;
  hiddenLockProjection?: Record<string, unknown>;
}

function lockProjection(lock: Record<string, unknown>, packageName: string, hidden = false): Record<string, unknown> {
  const projection = structuredClone(lock);
  const packages = objectValue(projection.packages);
  if (!packages) return projection;
  const packageKey = "node_modules/" + packageName;
  delete packages[packageKey];
  if (!hidden) {
    const rootDependencies = objectValue(objectValue(packages[""])?.dependencies);
    if (rootDependencies) delete rootDependencies[packageName];
  }
  return projection;
}

function packageManagerBaseline(dir: string, packageName: string): PackageManagerBaseline {
  const packagePath = join(dir, "package.json");
  const lockPath = join(dir, "package-lock.json");
  const packageJson = jsonObject(readFileSync(packagePath), packagePath);
  const lock = jsonObject(readFileSync(lockPath), lockPath);
  const packages = objectValue(lock.packages);
  if (!packages) throw new CliError(lockPath + " must contain npm package records");
  const hiddenPath = join(dir, "node_modules", ".package-lock.json");
  const baseline: PackageManagerBaseline = {
    packageJson: structuredClone(packageJson),
    lockProjection: lockProjection(lock, packageName),
  };
  if (hasPath(hiddenPath)) {
    const hidden = jsonObject(readFileSync(hiddenPath), hiddenPath);
    const hiddenPackages = objectValue(hidden.packages);
    if (!hiddenPackages) throw new CliError(hiddenPath + " must contain npm package records");
    baseline.hiddenLockProjection = lockProjection(hidden, packageName, true);
  }
  return baseline;
}

function assertPackageManagerMutation(
  baseline: PackageManagerBaseline,
  dir: string,
  packageName: string,
  version: string,
): void {
  const packagePath = join(dir, "package.json");
  const expectedPackage = structuredClone(baseline.packageJson);
  const expectedDependencies = objectValue(expectedPackage.dependencies);
  if (!expectedDependencies) throw new CliError(packagePath + " lost its dependencies object");
  expectedDependencies[packageName] = version;
  if (canonicalJson(jsonObject(readFileSync(packagePath), packagePath)) !== canonicalJson(expectedPackage)) {
    throw new CliError(packagePath + " changed beyond the exact " + packageName + " dependency pin");
  }
  const lockPath = join(dir, "package-lock.json");
  const lock = jsonObject(readFileSync(lockPath), lockPath);
  if (canonicalJson(lockProjection(lock, packageName)) !== canonicalJson(baseline.lockProjection)) {
    throw new CliError(lockPath + " changed beyond the exact QM package records");
  }
  const hiddenPath = join(dir, "node_modules", ".package-lock.json");
  const hidden = jsonObject(readFileSync(hiddenPath), hiddenPath);
  if (baseline.hiddenLockProjection) {
    if (canonicalJson(lockProjection(hidden, packageName, true)) !== canonicalJson(baseline.hiddenLockProjection)) {
      throw new CliError(hiddenPath + " changed unrelated package-manager state");
    }
  } else {
    const rootPackages = objectValue(lock.packages);
    const hiddenMetadata = structuredClone(hidden);
    const hiddenPackages = objectValue(hiddenMetadata.packages);
    delete hiddenMetadata.packages;
    const rootMetadata = structuredClone(lock);
    delete rootMetadata.packages;
    if (
      !rootPackages ||
      !hiddenPackages ||
      canonicalJson(hiddenMetadata) !== canonicalJson(rootMetadata) ||
      Object.entries(hiddenPackages).some(
        ([key, record]) => key === "" || canonicalJson(record) !== canonicalJson(rootPackages[key]),
      )
    ) {
      throw new CliError(hiddenPath + " does not match the final root lock state");
    }
  }
}

function assertInstalledPackage(
  dir: string,
  packageName: string,
  metadata: ReleaseMetadata,
  verified: VerifiedPackage,
  verifiedDigest: string,
): string {
  assertPackageManagerLayout(dir, packageName);
  const packagePath = join(dir, "package.json");
  const pkg = jsonObject(readFileSync(packagePath), packagePath);
  if (objectValue(pkg.dependencies)?.[packageName] !== metadata.version) {
    throw new CliError(packagePath + " does not pin " + packageName + "@" + metadata.version + " exactly");
  }
  const lockPath = join(dir, "package-lock.json");
  const lock = jsonObject(readFileSync(lockPath), lockPath);
  const packages = objectValue(lock.packages);
  const rootDependencies = objectValue(objectValue(packages?.[""])?.dependencies);
  const packageKey = "node_modules/" + packageName;
  if (
    lock.lockfileVersion !== 3 ||
    lock.dependencies !== undefined ||
    rootDependencies?.[packageName] !== metadata.version ||
    !packageRecordMatches(packages?.[packageKey], verified.packageRecord)
  ) {
    throw new CliError(lockPath + " does not record the exact verified " + packageName + " package");
  }
  const hiddenPath = join(dir, "node_modules", ".package-lock.json");
  if (!hasPath(hiddenPath)) throw new CliError(hiddenPath + " is missing after npm install");
  assertRegularFile(hiddenPath);
  assertOwnedPath(hiddenPath);
  const hidden = jsonObject(readFileSync(hiddenPath), hiddenPath);
  if (
    hidden.lockfileVersion !== 3 ||
    hidden.dependencies !== undefined ||
    !packageRecordMatches(objectValue(hidden.packages)?.[packageKey], verified.packageRecord)
  ) {
    throw new CliError(hiddenPath + " does not record the exact verified " + packageName + " package");
  }
  const live = packageDirectory(dir, packageName);
  assertRegularDirectory(live);
  assertOwnedPackageTree(live, true);
  if (packageTreeDigest(live) !== verifiedDigest) {
    throw new CliError(
      live +
        " does not match the independently verified " +
        packageName +
        " package; restore tracked package files and run npm ci --ignore-scripts before retrying",
    );
  }
  const entry = join(live, "dist", "bin", "qm.js");
  assertRegularFile(entry);
  if ((lstatSync(entry).mode & 0o111) === 0) throw new CliError(entry + " must be executable");
  const bin = join(dir, "node_modules", ".bin", "qm");
  if (!hasPath(bin) || !lstatSync(bin).isSymbolicLink() || !samePathIdentity(bin, entry)) {
    throw new CliError(bin + " does not resolve to the verified QM executable");
  }
  return entry;
}

async function runForeground(
  executable: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  operation: string,
  captureOutput = false,
): Promise<string> {
  const detached = process.platform !== "win32";
  const output: Buffer[] = [];
  let child: ReturnType<typeof spawn> | undefined;
  let forwarded: NodeJS.Signals | undefined;
  let forceForwarded = false;
  let forceTimer: NodeJS.Timeout | undefined;
  let forwardingError: unknown;
  const forwardSignal = (signal: NodeJS.Signals): void => {
    if (child?.pid === undefined) return;
    try {
      process.kill(detached ? -child.pid : child.pid, signal);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return;
      forwardingError = error;
      if (!detached) return;
      try {
        process.kill(child.pid, signal);
      } catch (fallbackError) {
        if ((fallbackError as NodeJS.ErrnoException).code !== "ESRCH") forwardingError = fallbackError;
      }
    }
  };
  const forceSignal = (): void => {
    forceForwarded = true;
    forwardSignal("SIGKILL");
  };
  const signals: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"];
  const handlers = new Map<NodeJS.Signals, () => void>();
  for (const signal of signals) {
    const handler = (): void => {
      if (forwarded) {
        forceSignal();
        return;
      }
      forwarded ??= signal;
      forwardSignal(signal);
      forceTimer = setTimeout(forceSignal, 5_000);
      forceTimer.unref();
    };
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
  if (detached) {
    const suspend = (): void => {
      forwardSignal("SIGSTOP");
      process.kill(process.pid, "SIGSTOP");
    };
    const resume = (): void => forwardSignal("SIGCONT");
    handlers.set("SIGTSTP", suspend);
    handlers.set("SIGCONT", resume);
    process.on("SIGTSTP", suspend);
    process.on("SIGCONT", resume);
  }
  let outcome: { code: number | null; signal: NodeJS.Signals | null } | undefined;
  let childError: unknown;
  try {
    const running = spawn(executable, args, {
      cwd,
      env,
      stdio: captureOutput ? ["inherit", "pipe", "inherit"] : "inherit",
      detached,
    });
    child = running;
    running.stdout?.on("data", (chunk: Buffer) => output.push(chunk));
    if (forceForwarded) forwardSignal("SIGKILL");
    else if (forwarded) forwardSignal(forwarded);
    const closed = new Promise<void>((resolveClosed) => {
      running.once("error", (error) => {
        childError ??= error;
      });
      running.once("close", (code, signal) => {
        outcome = { code, signal };
        resolveClosed();
      });
    });
    await closed;
    if (childError && !forwarded) {
      await new Promise<void>((resolveWait) => setTimeout(resolveWait, 25));
    }
    if (outcome && detached && running.pid !== undefined) {
      const permissionDeadline = Date.now() + 5_000;
      for (;;) {
        try {
          process.kill(-running.pid, 0);
        } catch (error) {
          const code = (error as NodeJS.ErrnoException).code;
          if (code === "ESRCH") break;
          if (code === "EPERM") {
            if (Date.now() >= permissionDeadline) throw error;
            await new Promise<void>((resolveWait) => setTimeout(resolveWait, 25));
            continue;
          }
          throw error;
        }
        if (forceForwarded) forwardSignal("SIGKILL");
        await new Promise<void>((resolveWait) => setTimeout(resolveWait, 25));
      }
    }
  } catch (error) {
    childError = error;
  } finally {
    if (forceTimer) clearTimeout(forceTimer);
    for (const [signal, handler] of handlers) process.off(signal, handler);
  }
  if (forwarded) {
    throw new ForwardedSignal(forwarded);
  }
  if (forwardingError) {
    throw new CliError(operation + " signal forwarding failed: " + errMessage(forwardingError), {
      cause: forwardingError,
    });
  }
  if (childError) throw new CliError(operation + " failed: " + errMessage(childError), { cause: childError });
  if (!outcome || outcome.code !== 0) {
    const reason = outcome?.signal ?? "exit " + String(outcome?.code);
    throw new CliError(operation + " failed (" + reason + ")");
  }
  return Buffer.concat(output).toString("utf8");
}

async function installVerifiedPackage(
  npm: string,
  transaction: string,
  dir: string,
  packageName: string,
  version: string,
  testEnvironment?: NodeJS.ProcessEnv,
): Promise<void> {
  const args = [
    npm,
    "install",
    "--save=true",
    "--save-exact=true",
    "--save-prod=true",
    "--dry-run=false",
    "--ignore-scripts=true",
    "--foreground-scripts=false",
    "--audit=false",
    "--fund=false",
    "--bin-links=true",
    "--package-lock=true",
    "--package-lock-only=false",
    "--lockfile-version=3",
    "--workspaces=false",
    "--install-links=false",
    "--install-strategy=hoisted",
    "--strict-peer-deps=true",
    "--engine-strict=true",
    ...npmArgs(transaction, "offline"),
    packageName + "@" + version,
  ];
  try {
    await runForeground(
      process.execPath,
      args,
      dir,
      npmEnvironment(transaction, testEnvironment),
      "QM package install",
    );
  } catch (error) {
    throw new CliError(
      "QM package install failed; confirm no npm child remains, then rerun this exact update, or restore package.json and package-lock.json and run npm ci",
      { cause: error },
    );
  }
}

async function runTargetPackage(
  dir: string,
  entry: string,
  options: { configPath: string; sandboxDir: string; envFile?: string; target: Target },
  environment: TargetEnvironment,
): Promise<void> {
  const args = [
    entry,
    "up",
    "--config",
    options.configPath,
    "--sandbox-dir",
    options.sandboxDir,
    ...(options.envFile ? ["--env-file", resolve(options.envFile)] : []),
    "--target",
    options.target,
    ...(options.target === "aws" ? ["--yes"] : []),
  ];
  environment.assertStable();
  try {
    await runForeground(process.execPath, [environment.runner, ...args], dir, environment.env, "QM deployment");
  } finally {
    environment.assertStable();
  }
}

interface ProjectedExecutable {
  source: string;
  projected: string;
  identity: FilesystemIdentity;
  mode: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  nlink: number;
}

interface ProjectedFile {
  path: string;
  body: string;
  identity: FilesystemIdentity;
}

interface TrustedInputFile {
  path: string;
  identity: FilesystemIdentity;
  mode: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  nlink: number;
}

interface TargetEnvironment {
  env: NodeJS.ProcessEnv;
  assertStable: () => void;
  runner: string;
  trustedPaths: string[];
  trustedAncestors: string[];
}

function hasPathExpansion(value: string): boolean {
  return /[~$]|%[^%]+%/.test(value);
}

function externalPath(path: string, deploymentIdentity: FilesystemIdentity, label: string): string {
  if (lexicalPathHasAncestorIdentity(path, deploymentIdentity)) {
    throw new CliError(label + " must resolve outside the deployment during automatic update");
  }
  let existing = path;
  let complete = true;
  while (!hasPath(existing)) {
    complete = false;
    const parent = dirname(existing);
    if (parent === existing) break;
    existing = parent;
  }
  const resolved = canonicalPath(existing);
  if (pathHasAncestorIdentity(resolved, deploymentIdentity)) {
    throw new CliError(label + " must resolve outside the deployment during automatic update");
  }
  const output = complete ? resolved : resolve(resolved, relative(existing, path));
  if (hasPathExpansion(output)) {
    throw new CliError(label + " must be an already-expanded external path during automatic update");
  }
  return output;
}

function targetBaseEnvironment(testEnvironment?: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, ...testEnvironment };
  const blocked = [
    /^(?:BASH_ENV|BASHOPTS|ENV|GCONV_PATH|KSH_ENV|PS4|SHELLOPTS|SSLKEYLOGFILE)$/iu,
    /^BASH_FUNC_/iu,
    /^(?:NODE_COMPILE_CACHE|NODE_OPTIONS|NODE_PATH|NODE_REDIRECT_WARNINGS|NODE_V8_COVERAGE)$/iu,
    /^OPENSSL_/iu,
    /^(?:LD_|DYLD_)/iu,
    /^(?:BUNDLE_|CLASSPATH$|CORECLR_|DOTNET_STARTUP_HOOKS$|GEM_|JAVA_TOOL_OPTIONS$|JDK_JAVA_OPTIONS$|LUA_CPATH$|LUA_PATH$|PERL5|PHP_INI|PYTHON|RUBYLIB$|RUBYOPT$|_JAVA_OPTIONS$)/iu,
    /^GIT_/iu,
    /^(?:INIT_CWD|OLDPWD|PWD)$/u,
  ];
  for (const name of Object.keys(env)) {
    if (blocked.some((pattern) => pattern.test(name))) delete env[name];
  }
  return env;
}

function privateDeploymentEnvironment(transaction: string, source: DeploymentEnvironmentSnapshot): string {
  assertDeploymentEnvironmentSnapshotCurrent(source);
  const path = join(transaction, "deployment.env");
  writeFileSync(path, source.content, { flag: "wx", mode: 0o600 });
  return path;
}

function trustedExecutable(path: string, deploymentIdentity: FilesystemIdentity): ProjectedExecutable {
  const source = canonicalPath(path);
  if (pathHasAncestorIdentity(source, deploymentIdentity)) {
    throw new CliError(source + " resolves inside the deployment");
  }
  const identity = lstatSync(source);
  const trustedRootLinks = identity.uid === 0 && (identity.mode & 0o022) === 0;
  if (
    !identity.isFile() ||
    identity.isSymbolicLink() ||
    (identity.nlink !== 1 && !trustedRootLinks) ||
    (identity.mode & 0o111) === 0
  ) {
    throw new CliError(source + " must be an unlinked executable file");
  }
  assertTrustedPathAncestors(source);
  return {
    source,
    projected: "",
    identity: filesystemIdentity(source),
    mode: identity.mode & 0o7777,
    size: identity.size,
    mtimeMs: identity.mtimeMs,
    ctimeMs: identity.ctimeMs,
    nlink: identity.nlink,
  };
}

function targetEnvironment(
  transaction: string,
  dir: string,
  target: Target,
  sourcePath?: string,
  testEnvironment?: NodeJS.ProcessEnv,
  testInheritedUmask?: number,
): TargetEnvironment {
  const deploymentDirectory = canonicalPath(dir);
  const deploymentIdentity = filesystemIdentity(deploymentDirectory);
  const deploymentHardlinks = new Set<string>();
  const collectDeploymentHardlinks = (path: string): void => {
    const identity = lstatSync(path, { bigint: true });
    if (identity.isDirectory() && !identity.isSymbolicLink()) {
      for (const name of readdirSync(path)) collectDeploymentHardlinks(join(path, name));
      return;
    }
    if (identity.isFile() && identity.nlink > 1n) {
      deploymentHardlinks.add(identity.dev + ":" + identity.ino);
    }
  };
  collectDeploymentHardlinks(deploymentDirectory);
  const localBin = (path: string): boolean => {
    const parts = path.split(sep);
    return parts.at(-1) === ".bin" && parts.at(-2) === "node_modules";
  };
  const projection = join(transaction, "target-path");
  mkdirSync(projection, { mode: 0o700 });
  const projectionIdentity = filesystemIdentity(projection);
  const executables: ProjectedExecutable[] = [];
  const projectedFiles: ProjectedFile[] = [];
  const projectedNames = new Set<string>();
  const directories: string[] = [];
  const trustedTrees: string[] = [];
  const additionalTrustedPaths: string[] = [];
  const absentTrustedPaths = new Set<string>();
  const providerWritableDirectories = new Set<string>();
  const trustedInputFiles = new Map<string, TrustedInputFile>();
  const dockerPluginDirectories: string[] = [];
  let dockerConfigDirectory: string | undefined;
  const inputPath = sourcePath ?? process.env.PATH;
  if (!inputPath) throw new CliError("PATH must contain absolute external directories during automatic update");
  for (const entry of inputPath.split(delimiter)) {
    if (!entry || !isAbsolute(entry)) {
      throw new CliError("PATH must contain only absolute external directories during automatic update");
    }
    if (localBin(entry)) continue;
    try {
      const directory = canonicalPath(entry);
      const identity = lstatSync(directory);
      if (
        !identity.isDirectory() ||
        identity.isSymbolicLink() ||
        pathHasAncestorIdentity(directory, deploymentIdentity) ||
        localBin(directory)
      ) {
        continue;
      }
      const aliasesDeployment = readdirSync(directory).some((name) => {
        const candidate = join(directory, name);
        const candidateIdentity = lstatSync(candidate, { bigint: true });
        if (
          candidateIdentity.isFile() &&
          candidateIdentity.nlink > 1n &&
          deploymentHardlinks.has(candidateIdentity.dev + ":" + candidateIdentity.ino)
        ) {
          return true;
        }
        if (!candidateIdentity.isSymbolicLink()) return false;
        const target = resolve(dirname(candidate), readlinkSync(candidate));
        if (lexicalPathHasAncestorIdentity(target, deploymentIdentity)) return true;
        try {
          const resolvedCandidate = canonicalPath(candidate);
          const resolvedIdentity = lstatSync(resolvedCandidate, { bigint: true });
          if (
            resolvedIdentity.isFile() &&
            resolvedIdentity.nlink > 1n &&
            deploymentHardlinks.has(resolvedIdentity.dev + ":" + resolvedIdentity.ino)
          ) {
            return true;
          }
          return pathHasAncestorIdentity(resolvedCandidate, deploymentIdentity);
        } catch {
          return false;
        }
      });
      if (aliasesDeployment) continue;
      assertTrustedPathAncestors(directory);
      if (!directories.includes(directory)) directories.push(directory);
    } catch {
      continue;
    }
  }
  const shellQuote = (value: string): string => `'${value.replaceAll("'", `'"'"'`)}'`;
  const writeProjected = (name: string, body: string): string => {
    const path = join(projection, name);
    writeFileSync(path, body, { flag: "wx", mode: 0o700 });
    projectedFiles.push({ path, body, identity: filesystemIdentity(path) });
    return path;
  };
  const runner = writeProjected(
    ".qm-target-runner.mjs",
    'import { pathToFileURL } from "node:url";\n' +
      "const entry = process.argv[2];\n" +
      "if (!entry) process.exit(1);\n" +
      "process.argv = [process.execPath, entry, ...process.argv.slice(3)];\n" +
      (testInheritedUmask === undefined ? "" : `process.umask(${testInheritedUmask});\n`) +
      "process.umask(0o077);\n" +
      "await import(pathToFileURL(entry).href);\n",
  );
  const projectExecutable = (executable: ProjectedExecutable, name: string): void => {
    const path = writeProjected(
      name,
      `#!/bin/sh\nPATH=${shellQuote(projection)}\nexport PATH\nexec ${shellQuote(executable.source)} "$@"\n`,
    );
    executable.projected = path;
    executables.push(executable);
    projectedNames.add(name);
  };
  const project = (name: string, candidates = directories.map((directory) => join(directory, name))): boolean => {
    if (projectedNames.has(name)) return true;
    for (const candidate of candidates) {
      if (!hasPath(candidate)) continue;
      let executable: ProjectedExecutable;
      try {
        executable = trustedExecutable(candidate, deploymentIdentity);
      } catch {
        continue;
      }
      projectExecutable(executable, name);
      return true;
    }
    return false;
  };
  const rememberTrustedInputFile = (path: string): void => {
    const source = canonicalPath(path);
    if (trustedInputFiles.has(source)) return;
    const identity = lstatSync(source);
    if (!identity.isFile() || identity.isSymbolicLink()) {
      throw new CliError(source + " must be a trusted unlinked provider input file");
    }
    if (identity.nlink !== 1) throw new CliError(source + " must not be hard-linked");
    if ((identity.uid !== 0 && identity.uid !== effectiveUid()) || (identity.mode & 0o022) !== 0) {
      throw new CliError(source + " must be a trusted unlinked provider input file");
    }
    assertTrustedPathAncestors(source);
    trustedInputFiles.set(source, {
      path: source,
      identity: filesystemIdentity(source),
      mode: identity.mode & 0o7777,
      size: identity.size,
      mtimeMs: identity.mtimeMs,
      ctimeMs: identity.ctimeMs,
      nlink: identity.nlink,
    });
  };
  const rememberAbsentTrustedPath = (path: string): void => {
    const absent = resolve(path);
    const nearest = assertTrustedAbsentPath(absent);
    absentTrustedPaths.add(absent);
    if (!additionalTrustedPaths.includes(nearest)) additionalTrustedPaths.push(nearest);
  };
  const rememberTrustedInputDirectory = (path: string): void => {
    if (hasPath(path)) {
      assertRegularDirectory(path);
      trustedTrees.push(...assertTrustedDirectoryTree(path));
    } else {
      rememberAbsentTrustedPath(path);
    }
  };
  const rememberProviderWritableDirectory = (path: string): void => {
    const directory = resolve(path);
    providerWritableDirectories.add(directory);
    if (hasPath(directory)) {
      assertRegularDirectory(directory);
      trustedTrees.push(...assertTrustedDirectoryTree(directory));
    } else {
      const nearest = assertTrustedAbsentPath(directory);
      if (!additionalTrustedPaths.includes(nearest)) additionalTrustedPaths.push(nearest);
    }
  };
  const parsedAwsProfileFiles = new Set<string>();
  const rememberTrustedAwsProfileFile = (path: string): void => {
    rememberTrustedInputFile(path);
    const source = canonicalPath(path);
    if (parsedAwsProfileFiles.has(source)) return;
    parsedAwsProfileFiles.add(source);
    for (const line of readFileSync(source, "utf8").split(/\r\n?|\n/u)) {
      const assignment = /^\s*([A-Za-z0-9_]+)\s*(?:=|:)\s*(.*?)\s*$/u.exec(line);
      if (!assignment) continue;
      const name = assignment[1]!.toLowerCase();
      const value = assignment[2]!;
      if (name === "credential_process") {
        throw new CliError(source + " must not configure credential_process during automatic update");
      }
      if (name !== "web_identity_token_file" && name !== "ca_bundle") continue;
      if (!value || !isAbsolute(value) || hasPathExpansion(value)) {
        throw new CliError(source + " must configure " + name + " as an absolute external file");
      }
      assertTrustedLexicalPathAncestors(value);
      const referenced = externalPath(value, deploymentIdentity, name + " in " + source);
      if (hasPath(referenced)) rememberTrustedInputFile(referenced);
      else rememberAbsentTrustedPath(referenced);
    }
  };
  for (const directory of directories) {
    for (const name of readdirSync(directory)) {
      if (name !== "git" && !name.startsWith(".qm-provider-")) project(name);
    }
  }
  let git: ProjectedExecutable | undefined;
  for (const candidate of directories.map((directory) => join(directory, "git"))) {
    if (!hasPath(candidate)) continue;
    try {
      git = trustedExecutable(candidate, deploymentIdentity);
      break;
    } catch {
      continue;
    }
  }
  if (git) {
    const body =
      "#!/bin/sh\n" +
      `if [ "$#" -eq 5 ] && [ "$1" = "-C" ] && [ "$2" = ${shellQuote(deploymentDirectory)} ] && [ "$3" = "config" ] && [ "$4" = "--get" ] && [ "$5" = "remote.origin.url" ]; then\n` +
      `  PATH=${shellQuote(projection)}\n` +
      "  export PATH\n" +
      `  exec ${shellQuote(git.source)} -C ${shellQuote(deploymentDirectory)} config --get remote.origin.url\n` +
      "fi\n" +
      "exit 1\n";
    git.projected = writeProjected("git", body);
    executables.push(git);
  } else {
    writeProjected("git", "#!/bin/sh\nexit 1\n");
  }
  const env = targetBaseEnvironment(testEnvironment);
  env.QM_DEPLOY_ENV_FILE_ONLY = "1";
  env.PATH = projection;
  if (target === "docker" || target === "aws") {
    env.BUILDX_GIT_INFO = "false";
    env.BUILDX_GIT_LABELS = "false";
    delete env.BUILDX_CPU_PROFILE;
    delete env.BUILDX_MEM_PROFILE;
    for (const name of Object.keys(env)) {
      if (/^DOCKER_CLI_PLUGIN_(?!EXTRA_DIRS$)/iu.test(name)) delete env[name];
    }
  }
  if (target === "aws") {
    env.AWS_CLI_HISTORY_FILE = join(transaction, "aws-cli-history.db");
    env.AWS_PAGER = "";
    env.AWS_CLI_AUTO_PROMPT = "off";
  }
  if (target === "fly") delete env.FLYCTL_OUTPUT_HAR;
  env.HOME = env.HOME || homedir();
  env.TMPDIR = transaction;
  env.TMP = transaction;
  env.TEMP = transaction;
  const externalPaths: Array<[string, "file" | "directory"]> = [
    ["HOME", "directory"],
    ["XDG_CONFIG_HOME", "directory"],
    ["SSL_CERT_FILE", "file"],
    ["NODE_EXTRA_CA_CERTS", "file"],
    ["REQUESTS_CA_BUNDLE", "file"],
    ["CURL_CA_BUNDLE", "file"],
  ];
  if (target === "docker" || target === "aws") {
    externalPaths.push(
      ["DOCKER_CONFIG", "directory"],
      ["DOCKER_CERT_PATH", "directory"],
      ["BUILDX_CONFIG", "directory"],
      ["EXPERIMENTAL_BUILDKIT_SOURCE_POLICY", "file"],
    );
  }
  if (target === "fly") {
    externalPaths.push(["FLY_CONFIG_DIR", "directory"], ["GITHUB_STEP_SUMMARY", "file"]);
  }
  if (target === "aws") {
    externalPaths.push(
      ["AWS_LOGIN_CACHE_DIRECTORY", "directory"],
      ["AWS_CONFIG_FILE", "file"],
      ["AWS_SHARED_CREDENTIALS_FILE", "file"],
      ["AWS_WEB_IDENTITY_TOKEN_FILE", "file"],
      ["AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "file"],
      ["AWS_CREDENTIAL_FILE", "file"],
      ["AWS_CA_BUNDLE", "file"],
      ["AWS_CLI_HISTORY_FILE", "file"],
      ["BOTO_CONFIG", "file"],
    );
  }
  const stableAwsFiles = new Set([
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_CREDENTIAL_FILE",
    "AWS_CA_BUNDLE",
    "BOTO_CONFIG",
  ]);
  const stableAwsDirectories = new Set(["AWS_LOGIN_CACHE_DIRECTORY"]);
  for (const [name, type] of externalPaths) {
    const value = env[name];
    if (value === undefined) continue;
    if (!value || !isAbsolute(value) || hasPathExpansion(value)) {
      throw new CliError(name + " must name an absolute external " + type + " during automatic update");
    }
    const resolved = externalPath(value, deploymentIdentity, name);
    if (hasPath(resolved)) {
      if (type === "directory") assertRegularDirectory(resolved);
      else assertUnlinkedRegularFile(resolved);
    }
    env[name] = resolved;
    if (target === "aws" && stableAwsFiles.has(name)) {
      if (hasPath(resolved) && (name === "AWS_CONFIG_FILE" || name === "AWS_SHARED_CREDENTIALS_FILE")) {
        rememberTrustedAwsProfileFile(resolved);
      } else if (hasPath(resolved)) rememberTrustedInputFile(resolved);
      else rememberAbsentTrustedPath(resolved);
    }
    if (target === "aws" && stableAwsDirectories.has(name)) rememberTrustedInputDirectory(resolved);
  }
  const externalPathLists = ["SSL_CERT_DIR"];
  if (target === "docker" || target === "aws") {
    externalPathLists.push("KUBECONFIG", "DOCKER_CLI_PLUGIN_EXTRA_DIRS");
  }
  if (target === "aws") externalPathLists.push("AWS_DATA_PATH");
  for (const name of externalPathLists) {
    const value = env[name];
    if (value === undefined) continue;
    const resolved: string[] = [];
    for (const path of value.split(delimiter)) {
      if (!path || !isAbsolute(path) || hasPathExpansion(path)) {
        throw new CliError(name + " must contain only absolute external paths during automatic update");
      }
      const external = externalPath(path, deploymentIdentity, name);
      if (hasPath(external)) {
        if (name === "KUBECONFIG") assertUnlinkedRegularFile(external);
        else assertRegularDirectory(external);
        resolved.push(external);
      } else {
        resolved.push(external);
      }
      if (name === "AWS_DATA_PATH") rememberTrustedInputDirectory(external);
    }
    env[name] = resolved.join(delimiter);
    if (name === "DOCKER_CLI_PLUGIN_EXTRA_DIRS") {
      dockerPluginDirectories.push(...resolved);
      delete env[name];
    }
  }
  const nixLdSuffixes = ["", "_x86_64_linux", "_i686_linux", "_aarch64_linux", "_riscv64_linux"];
  const nixLdLoaders = nixLdSuffixes.map((suffix) => "NIX_LD" + suffix);
  const nixLdLibraries = nixLdSuffixes.map((suffix) => "NIX_LD_LIBRARY_PATH" + suffix);
  const supportedNixLd = new Set([...nixLdLoaders, ...nixLdLibraries, "NIX_LD_LOG"]);
  const unsupportedNixLd = Object.keys(env).find(
    (name) => (name === "NIX_LD" || name.startsWith("NIX_LD_")) && !supportedNixLd.has(name),
  );
  if (unsupportedNixLd) {
    throw new CliError(unsupportedNixLd + " is not a supported target loader setting during automatic update");
  }
  for (const name of nixLdLoaders) {
    const value = env[name];
    if (value === undefined) continue;
    if (value === "") continue;
    if (!isAbsolute(value) || hasPathExpansion(value)) {
      throw new CliError(name + " must name an absolute external executable during automatic update");
    }
    try {
      const executable = trustedExecutable(value, deploymentIdentity);
      env[name] = executable.source;
      executables.push(executable);
    } catch (error) {
      throw new CliError(name + " must name a trusted external executable during automatic update", { cause: error });
    }
  }
  for (const name of nixLdLibraries) {
    const value = env[name];
    if (value === undefined) continue;
    if (value === "") continue;
    const resolved: string[] = [];
    for (const path of value.split(/[:;]/u)) {
      if (!path || !isAbsolute(path) || hasPathExpansion(path)) {
        throw new CliError(name + " must contain only absolute external directories during automatic update");
      }
      const external = externalPath(path, deploymentIdentity, name);
      rememberTrustedInputDirectory(external);
      resolved.push(external);
    }
    env[name] = resolved.join(":");
  }
  if (target === "docker" || target === "aws") {
    const dockerConfig = env.DOCKER_CONFIG ?? join(env.HOME, ".docker");
    const resolvedDockerConfig = externalPath(dockerConfig, deploymentIdentity, "DOCKER_CONFIG");
    dockerConfigDirectory = resolvedDockerConfig;
    if (hasPath(resolvedDockerConfig)) assertRegularDirectory(resolvedDockerConfig);
    const configPath = externalPath(
      join(resolvedDockerConfig, "config.json"),
      deploymentIdentity,
      "the Docker configuration file",
    );
    if (hasPath(configPath)) assertUnlinkedRegularFile(configPath);
    for (const name of ["buildx", "cli-plugins"]) {
      const path = externalPath(
        join(resolvedDockerConfig, name),
        deploymentIdentity,
        "the Docker " + name + " directory",
      );
      if (hasPath(path)) assertRegularDirectory(path);
    }
  }
  if (target === "aws") {
    const awsHome = externalPath(join(env.HOME!, ".aws"), deploymentIdentity, "the AWS home directory");
    rememberProviderWritableDirectory(awsHome);
    const awsFiles: Array<[string, string]> = [
      ["AWS_CONFIG_FILE", env.AWS_CONFIG_FILE ?? join(env.HOME!, ".aws", "config")],
      ["AWS_SHARED_CREDENTIALS_FILE", env.AWS_SHARED_CREDENTIALS_FILE ?? join(env.HOME!, ".aws", "credentials")],
      ["the AWS CLI alias file", join(env.HOME!, ".aws", "cli", "alias")],
    ];
    if (!env.BOTO_CONFIG) {
      awsFiles.push(
        ["the system Boto configuration file", "/etc/boto.cfg"],
        ["the user Boto configuration file", join(env.HOME!, ".boto")],
      );
    }
    for (const [name, path] of awsFiles) {
      const resolved = externalPath(path, deploymentIdentity, name);
      if (hasPath(resolved) && (name === "AWS_CONFIG_FILE" || name === "AWS_SHARED_CREDENTIALS_FILE")) {
        rememberTrustedAwsProfileFile(resolved);
      } else if (hasPath(resolved)) rememberTrustedInputFile(resolved);
      else rememberAbsentTrustedPath(resolved);
    }
  }
  if (target === "fly") {
    const flyConfig = externalPath(
      env.FLY_CONFIG_DIR ?? join(env.HOME!, ".fly"),
      deploymentIdentity,
      "the Fly configuration directory",
    );
    if (hasPath(flyConfig)) assertRegularDirectory(flyConfig);
  }
  if (target === "docker" || target === "aws") {
    const accountHome = userInfo().homedir;
    const directories = [
      ["the SSH configuration directory", join(env.HOME!, ".ssh")],
      ["the native SSH configuration directory", join(accountHome, ".ssh")],
      ["the Kubernetes configuration directory", join(env.HOME!, ".kube")],
    ] as const;
    for (const [name, path] of directories) {
      const resolved = externalPath(path, deploymentIdentity, name);
      if (hasPath(resolved)) assertRegularDirectory(resolved);
    }
    const files = [
      ["the SSH configuration file", join(env.HOME!, ".ssh", "config")],
      ["the native SSH configuration file", join(accountHome, ".ssh", "config")],
      ["the Kubernetes configuration file", join(env.HOME!, ".kube", "config")],
    ] as const;
    for (const [name, path] of files) {
      const resolved = externalPath(path, deploymentIdentity, name);
      if (hasPath(resolved)) assertUnlinkedRegularFile(resolved);
    }
  }
  if (target === "docker" || target === "aws") {
    for (const name of ["DOCKER_HOST", "BUILDKIT_HOST"] as const) {
      const host = env[name]?.trim();
      if (!host?.startsWith("unix://")) continue;
      const socket = host.slice("unix://".length);
      if (!isAbsolute(socket)) throw new CliError(name + " must name an absolute external Unix socket");
      const resolved = externalPath(socket, deploymentIdentity, name);
      if (hasPath(resolved)) env[name] = "unix://" + resolved;
    }
  }
  let activeOverride: "AWS_BIN" | "FLY_BIN" | undefined;
  if (target === "aws") activeOverride = "AWS_BIN";
  if (target === "fly") activeOverride = "FLY_BIN";
  let projectedOverride = false;
  for (const name of ["AWS_BIN", "FLY_BIN"] as const) {
    if (name !== activeOverride) continue;
    const configured = env[name];
    if (configured === undefined) continue;
    if (!configured || configured !== configured.trim() || !isAbsolute(configured)) {
      throw new CliError(name + " must name an absolute external executable during automatic update");
    }
    let executable: ProjectedExecutable;
    try {
      executable = trustedExecutable(configured, deploymentIdentity);
    } catch (error) {
      throw new CliError(name + " must name a trusted external executable during automatic update", {
        cause: error,
      });
    }
    projectExecutable(executable, ".qm-provider-" + name.toLowerCase());
    env[name] = executable.projected;
    projectedOverride = true;
  }
  const missing: string[] = [];
  if (target === "docker") {
    if (!project("docker")) missing.push("docker");
  }
  if (target === "fly") {
    if (!projectedOverride && !project("flyctl") && !project("fly")) missing.push("flyctl or fly");
  }
  if (target === "aws") {
    if (!projectedOverride && !project("aws")) missing.push("aws");
    if (!project("docker")) missing.push("docker");
  }
  if (target === "docker" || target === "aws") {
    const buildx = env.DOCKER_BUILDX_BIN;
    if (buildx !== undefined && (!buildx || buildx !== buildx.trim() || !isAbsolute(buildx))) {
      throw new CliError("DOCKER_BUILDX_BIN must name an absolute external executable during automatic update");
    }
    if (buildx) {
      let executable: ProjectedExecutable;
      try {
        executable = trustedExecutable(buildx, deploymentIdentity);
      } catch (error) {
        throw new CliError("DOCKER_BUILDX_BIN must name a trusted external executable during automatic update", {
          cause: error,
        });
      }
      projectExecutable(executable, ".qm-provider-docker-buildx");
      env.DOCKER_BUILDX_BIN = executable.projected;
    } else {
      const candidates = [
        ...dockerPluginDirectories.map((directory) => join(directory, "docker-buildx")),
        ...(dockerConfigDirectory ? [join(dockerConfigDirectory, "cli-plugins", "docker-buildx")] : []),
        ...directories.map((directory) => join(directory, "docker-buildx")),
        "/usr/local/lib/docker/cli-plugins/docker-buildx",
        "/usr/local/libexec/docker/cli-plugins/docker-buildx",
        "/usr/lib/docker/cli-plugins/docker-buildx",
        "/usr/libexec/docker/cli-plugins/docker-buildx",
      ];
      const discovered = candidates.find(hasPath);
      if (discovered) {
        let executable: ProjectedExecutable;
        try {
          executable = trustedExecutable(discovered, deploymentIdentity);
        } catch (error) {
          throw new CliError("the discovered Docker Buildx plugin must be a trusted external executable", {
            cause: error,
          });
        }
        projectExecutable(executable, ".qm-provider-docker-buildx");
        env.DOCKER_BUILDX_BIN = executable.projected;
      } else {
        missing.push("docker-buildx");
      }
    }
  }
  if (missing.length) {
    throw new CliError("automatic update requires trusted external provider commands on PATH: " + missing.join(", "));
  }
  env.PATH = projection;
  const assertStable = (): void => {
    if (!sameFilesystemIdentity(filesystemIdentity(projection), projectionIdentity)) {
      throw new CliError("the trusted executable projection changed during automatic update");
    }
    for (const projected of projectedFiles) {
      const identity = lstatSync(projected.path);
      if (
        !identity.isFile() ||
        identity.isSymbolicLink() ||
        identity.nlink !== 1 ||
        !sameFilesystemIdentity(filesystemIdentity(projected.path), projected.identity) ||
        (identity.mode & 0o7777) !== 0o700 ||
        readFileSync(projected.path, "utf8") !== projected.body
      ) {
        throw new CliError(projected.path + " changed during automatic update");
      }
    }
    for (const executable of executables) {
      let source: string;
      try {
        source = canonicalPath(executable.source);
      } catch (error) {
        throw new CliError(executable.source + " changed during automatic update", { cause: error });
      }
      const identity = lstatSync(source);
      assertTrustedPathAncestors(source);
      if (
        source !== executable.source ||
        !sameFilesystemIdentity(filesystemIdentity(source), executable.identity) ||
        identity.nlink !== executable.nlink ||
        (identity.mode & 0o7777) !== executable.mode ||
        identity.size !== executable.size ||
        identity.mtimeMs !== executable.mtimeMs ||
        identity.ctimeMs !== executable.ctimeMs ||
        pathHasAncestorIdentity(source, deploymentIdentity)
      ) {
        throw new CliError(executable.source + " changed during automatic update");
      }
    }
    for (const tree of trustedTrees) assertTrustedDirectoryTree(tree);
    for (const directory of providerWritableDirectories) {
      if (hasPath(directory)) {
        assertRegularDirectory(directory);
        assertTrustedDirectoryTree(directory);
      } else {
        assertTrustedAbsentPath(directory);
      }
    }
    for (const path of absentTrustedPaths) assertTrustedAbsentPath(path);
    for (const file of trustedInputFiles.values()) {
      const source = canonicalPath(file.path);
      const identity = lstatSync(source);
      assertTrustedPathAncestors(source);
      if (
        source !== file.path ||
        !identity.isFile() ||
        identity.isSymbolicLink() ||
        !sameFilesystemIdentity(filesystemIdentity(source), file.identity) ||
        identity.nlink !== file.nlink ||
        (identity.mode & 0o7777) !== file.mode ||
        identity.size !== file.size ||
        identity.mtimeMs !== file.mtimeMs ||
        identity.ctimeMs !== file.ctimeMs
      ) {
        throw new CliError(file.path + " changed during automatic update");
      }
    }
  };
  return {
    env,
    assertStable,
    runner,
    trustedPaths: [
      ...directories,
      ...executables.map((executable) => executable.source),
      ...trustedTrees,
      ...trustedInputFiles.keys(),
    ],
    trustedAncestors: additionalTrustedPaths,
  };
}

interface RunUpdateOptions {
  config: QmConfig;
  configDir: string;
  configPath: string;
  sandboxDir: string;
  envFile?: string;
  target: Target;
  yes: boolean;
  version?: string;
  fetcher?: typeof fetch;
  testNpmPath?: string;
  testNpmEnvironment?: NodeJS.ProcessEnv;
  testTargetPath?: string;
  testTargetEnvironment?: NodeJS.ProcessEnv;
  testTargetUmask?: number;
  testPlatform?: NodeJS.Platform;
  testGetfaclPath?: string;
  testBeforeConfigSnapshot?: () => void;
}

async function runUpdateInner(options: RunUpdateOptions, interruption: UpdateInterruption): Promise<void> {
  const platform = options.testPlatform ?? process.platform;
  if (options.envFile !== undefined && (!options.envFile.trim() || options.envFile.includes("\0"))) {
    throw new CliError("--env-file needs a non-empty path");
  }
  if (options.yes && !["darwin", "linux"].includes(platform)) {
    throw new CliError("automatic QM update is supported only on macOS and Linux");
  }
  if (options.yes && options.version === undefined) {
    throw new CliError("update --yes requires --version with the exact reviewed stable release");
  }
  const configDir = canonicalPath(resolve(options.configDir));
  const requestedConfigPath = resolve(options.configPath);
  if (!samePathIdentity(dirname(requestedConfigPath), configDir)) {
    throw new CliError(requestedConfigPath + " must be a regular configuration file directly inside " + configDir);
  }
  const configPath = join(configDir, basename(requestedConfigPath));
  options.testBeforeConfigSnapshot?.();
  const configSnapshot = trustedConfigurationSnapshot(configPath);
  const requestedSandboxDir = resolve(options.sandboxDir);
  const sandboxDir = hasPath(requestedSandboxDir) ? canonicalPath(requestedSandboxDir) : requestedSandboxDir;
  for (const path of [configDir, ...(hasPath(sandboxDir) ? [sandboxDir] : [])]) {
    assertRegularDirectory(path);
    assertOwnedPath(path);
  }
  const packageName = cliPackageName();
  const loadedConfig = loadConfigAt(configPath, { snapshot: configSnapshot });
  const currentConfig = loadedConfig.config;
  if (currentConfig.target !== options.target) {
    throw new CliError(
      "automatic update requires the configured " +
        currentConfig.target +
        " target; remove the --target " +
        options.target +
        " override",
    );
  }
  const environmentPath = options.envFile !== undefined ? resolve(options.envFile) : join(configDir, ".env");
  const environment = deploymentEnvironmentSnapshot(
    environmentPath,
    options.envFile !== undefined,
    loadedConfig.configIdentity,
  );
  const protectedPaths = protectedUpdatePaths(configDir, sandboxDir, currentConfig, environmentPath);
  const mutableInputPaths = [
    sandboxDir,
    join(configDir, "plugins"),
    ...currentConfig.skills.map((path) => resolve(configDir, path)),
    environmentPath,
  ];
  assertInputsDisjointFromRoot(mutableInputPaths, join(configDir, "node_modules"), "deployment node_modules");
  for (const path of [configPath, join(configDir, "package.json"), join(configDir, "package-lock.json")]) {
    assertInputsDisjointFromRoot(mutableInputPaths, path, "an automatic update mutable file");
  }
  for (const skill of currentConfig.skills.map((path) => resolve(configDir, path))) {
    if (!hasPath(skill)) throw new CliError(skill + " is required by the deployment skills configuration");
  }
  let getfacl: string | undefined;
  if (options.yes && platform === "darwin") {
    await assertDarwinAclSafeRoots(protectedPaths);
  } else if (options.yes && platform === "linux") {
    getfacl = await linuxAclInspector(
      options.testGetfaclPath,
      filesystemIdentity(configDir),
      options.testPlatform !== undefined,
    );
    await assertLinuxAclSafeRoots(getfacl, protectedPaths);
  }
  const metadata = await releaseMetadata(options.fetcher ?? fetch, options.version, interruption);
  throwIfInterrupted(interruption);
  const current = assertDeploymentReady(
    currentConfig,
    configDir,
    sandboxDir,
    options.target,
    packageName,
    undefined,
    !options.yes,
    options.yes,
  );
  if (compareVersions(current, metadata.version) > 0) {
    throw new CliError("QM " + metadata.version + " is older than the deployment's current " + current + " pin");
  }
  const updateAvailable = compareVersions(current, metadata.version) < 0;
  const customImages = customImageConfiguration(currentConfig, options.target);
  const retiredSpritesRecipe = sandboxBackend(currentConfig) === "sprites" && hasPath(join(sandboxDir, "Dockerfile"));
  if (!options.yes) {
    if (!updateAvailable) {
      ok("QM " + current + " is already current");
      return;
    }
    note("QM " + current + " → " + metadata.version);
    if (customImages.length) {
      note(
        "This deployment uses custom image " +
          (customImages.length === 1 ? "configuration" : "configurations") +
          " (" +
          customImages.join(", ") +
          "); update those images through their normal rollout process before changing the QM package pin.",
      );
    }
    if (retiredSpritesRecipe) {
      note(
        join(sandboxDir, "Dockerfile") +
          " is a retired Sprites sandbox recipe; review and archive or remove it before automatic update.",
      );
    }
    if (!customImages.length && !retiredSpritesRecipe) {
      note(
        "Rerun this command with --yes --version " + metadata.version + " to install and deploy the reviewed release.",
      );
    }
    return;
  }
  const fingerprint = deploymentFingerprint(configDir, configPath, sandboxDir, packageName, currentConfig, environment);
  const guardedFingerprint = guardedDeploymentFingerprint(
    configDir,
    configPath,
    sandboxDir,
    currentConfig,
    environment,
  );
  const sourceNpm = npmBinary(options.testNpmPath);
  assertTrustedPathAncestors(sourceNpm);
  const sourceNpmRoot = npmPackageRoot(sourceNpm);
  if (platform === "darwin") await assertDarwinAclSafeRoots([sourceNpmRoot]);
  if (getfacl) await assertLinuxAclSafeRoots(getfacl, [sourceNpmRoot]);
  const temporaryDirectory = tmpdir();
  if (!isAbsolute(temporaryDirectory)) {
    throw new CliError("the automatic update temporary directory must be an absolute external directory");
  }
  const transactionRoot = externalPath(
    temporaryDirectory,
    filesystemIdentity(configDir),
    "the automatic update temporary directory",
  );
  assertRegularDirectory(transactionRoot);
  assertTrustedPathAncestors(transactionRoot);
  if (platform === "darwin") {
    await assertDarwinAclSafeAncestors([resolve(temporaryDirectory), transactionRoot]);
  }
  if (getfacl) await assertLinuxAclSafeAncestors(getfacl, [transactionRoot]);
  const transaction = canonicalPath(mkdtempSync(join(transactionRoot, "qm-update-")));
  try {
    chmodSync(transaction, 0o700);
    assertInputsDisjointFromRoot(mutableInputPaths, transaction, "the automatic update transaction");
    if (platform === "darwin") await assertDarwinAclSafeRoots([transaction]);
    if (getfacl) await assertLinuxAclSafeRoots(getfacl, [transaction]);
    prepareNpmEnvironment(transaction);
    const projectedNpm = trustedNpmProjection(transaction, sourceNpm, sourceNpmRoot);
    const npm = projectedNpm.npm;
    const npmRoot = projectedNpm.npmRoot;
    assertOfflinePackageManagerInputs(configDir, packageName, npmRoot, metadata.integrity);
    const targetSandboxDir = hasPath(sandboxDir) ? sandboxDir : join(transaction, "absent-sandbox");
    const targetEnvFile = privateDeploymentEnvironment(transaction, environment);
    const deploymentEnvironment = targetEnvironment(
      transaction,
      configDir,
      options.target,
      options.testTargetPath,
      options.testTargetEnvironment,
      options.testTargetUmask,
    );
    if (platform === "darwin") await assertDarwinAclSafeRoots(deploymentEnvironment.trustedPaths);
    if (getfacl) await assertLinuxAclSafeRoots(getfacl, deploymentEnvironment.trustedPaths);
    if (platform === "darwin") await assertDarwinAclSafeAncestors(deploymentEnvironment.trustedAncestors);
    if (getfacl) await assertLinuxAclSafeAncestors(getfacl, deploymentEnvironment.trustedAncestors);
    note(
      updateAvailable
        ? "QM " + current + " → " + metadata.version
        : "QM " + current + " is already pinned; reconciling the deployment",
    );
    note("Exclusive maintenance is required: finish other QM and npm commands before continuing.");
    note("After a forced kill, confirm the npm or deployment child has exited before rerunning this exact update.");
    const verified = await verifyPackage(transaction, metadata, npm, options.testNpmEnvironment);
    throwIfInterrupted(interruption);
    const verifiedDigest = packageTreeDigest(verified.packageDir);
    assertDeploymentReady(
      deploymentConfig(configPath, options.target),
      configDir,
      sandboxDir,
      options.target,
      packageName,
      current,
      false,
      true,
    );
    assertFingerprint(fingerprint, configDir, packageName);
    if (packageTreeDigest(verified.packageDir) !== verifiedDigest) {
      throw new CliError("the independently verified QM package changed before installation");
    }
    await assertNpmProject(npm, transaction, configDir, options.testNpmEnvironment);
    const refreshedMetadata = await releaseMetadata(options.fetcher ?? fetch, metadata.version, interruption);
    throwIfInterrupted(interruption);
    if (canonicalJson(refreshedMetadata) !== canonicalJson(metadata)) {
      throw new CliError("npm latest QM release metadata changed during verification; retry from the current state");
    }
    assertDeploymentReady(
      deploymentConfig(configPath, options.target),
      configDir,
      sandboxDir,
      options.target,
      packageName,
      current,
      false,
      true,
    );
    assertFingerprint(fingerprint, configDir, packageName);
    assertOfflinePackageManagerInputs(configDir, packageName, npmRoot, metadata.integrity);
    await assertCanonicalPackageManagerProjection(npm, transaction, configDir, packageName, options.testNpmEnvironment);
    throwIfInterrupted(interruption);
    const packageManagerState = packageManagerBaseline(configDir, packageName);
    throwIfInterrupted(interruption);
    await installVerifiedPackage(
      npm,
      transaction,
      configDir,
      packageName,
      metadata.version,
      options.testNpmEnvironment,
    );
    assertPackageManagerMutation(packageManagerState, configDir, packageName, metadata.version);
    assertInstalledPackage(configDir, packageName, metadata, verified, verifiedDigest);
    assertDeploymentReady(
      deploymentConfig(configPath, options.target),
      configDir,
      sandboxDir,
      options.target,
      packageName,
      metadata.version,
    );
    assertGuardedFingerprint(guardedFingerprint, configDir, options.target);
    ok("pinned verified " + packageName + "@" + metadata.version);
    const verifiedEntry = join(verified.packageDir, "dist", "bin", "qm.js");
    assertOwnedPackageTree(verified.packageDir, true);
    if (packageTreeDigest(verified.packageDir) !== verifiedDigest) {
      throw new CliError("the independently verified QM package changed before deployment");
    }
    let deploymentError: unknown;
    try {
      throwIfInterrupted(interruption);
      await runTargetPackage(
        transaction,
        verifiedEntry,
        {
          configPath,
          sandboxDir: targetSandboxDir,
          envFile: targetEnvFile,
          target: options.target,
        },
        deploymentEnvironment,
      );
    } catch (error) {
      if (forwardedSignal(error)) throw error;
      deploymentError = error;
    }
    assertOwnedPackageTree(verified.packageDir, true);
    if (packageTreeDigest(verified.packageDir) !== verifiedDigest) {
      throw new CliError("the independently verified QM package changed during deployment");
    }
    assertInstalledPackage(configDir, packageName, metadata, verified, verifiedDigest);
    assertPackageManagerMutation(packageManagerState, configDir, packageName, metadata.version);
    assertGuardedFingerprint(guardedFingerprint, configDir, options.target, true);
    assertDeploymentReady(
      deploymentConfig(configPath, options.target),
      configDir,
      sandboxDir,
      options.target,
      packageName,
      metadata.version,
    );
    if (deploymentError) {
      throw new CliError(
        "QM deployment failed; " +
          packageName +
          "@" +
          metadata.version +
          " remains pinned and verified; reconcile it with " +
          (options.target === "aws" ? "qm up --yes" : "qm up") +
          ", then review and commit package.json and package-lock.json" +
          (options.target === "aws" ? ", and " + configPath : "") +
          " before reviewing a newer promoted release",
        { cause: deploymentError },
      );
    }
    ok("deployment reconciled with " + packageName + "@" + metadata.version);
    note(
      "Review and commit package.json and package-lock.json" +
        (options.target === "aws" ? ", and " + configPath : "") +
        " before another deployment can roll back this update.",
    );
  } finally {
    rmSync(transaction, { recursive: true, force: true });
  }
}

export async function runUpdate(options: RunUpdateOptions): Promise<void> {
  const interruption: UpdateInterruption = { controller: new AbortController() };
  const signals: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"];
  const handlers = new Map<NodeJS.Signals, () => void>();
  for (const signal of signals) {
    const handler = (): void => {
      interruption.signal ??= signal;
      if (!interruption.controller.signal.aborted) {
        interruption.controller.abort(new ForwardedSignal(interruption.signal));
      }
    };
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
  let failure: unknown;
  let releaseLock: (() => void) | undefined;
  try {
    if (options.yes) releaseLock = projectUpdateLock(options.configDir);
    await runUpdateInner(options, interruption);
  } catch (error) {
    failure = error;
  } finally {
    try {
      releaseLock?.();
    } catch (error) {
      failure ??= error;
    }
    for (const [signal, handler] of handlers) process.off(signal, handler);
  }
  const signal = interruption.signal ?? forwardedSignal(failure);
  if (signal) {
    process.kill(process.pid, signal);
    await new Promise<never>(() => setInterval(() => {}, 1_000));
  }
  if (failure) throw failure;
}
