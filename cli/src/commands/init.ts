import { randomBytes } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import {
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  readSync,
  realpathSync,
  rmSync,
  type BigIntStats,
  unlinkSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import {
  CONFIG_FILENAME,
  loadConfigAt,
  validOrgId,
  type EmailTransport,
  type ModelProvider,
  type Target,
  type QmConfig,
} from "../config.ts";
import { die, note, ok, warn } from "../log.ts";
import { assertNodeEngine } from "../preflight.ts";
import { cliPackageName, cliVersion } from "../manifest.ts";
import { computedSecrets, renderEnvExample } from "../secrets.ts";
import { renderSlackManifests, usesSlackOidc } from "../slack-manifests.ts";
import { hostingProvider } from "../backends/registry.ts";
import { updateRenderedFile } from "../safe-write.ts";
import { decodeUtf8, gitSubprocessEnvironment } from "../util.ts";

const AGENTS_TEMPLATE = `# QM deployment

This directory is one QM deployment: a config, a secret contract, and a
sandbox layer that customizes the agent without forking the core images. Commit
everything here except \`.env\`, which holds the secret values and is covered by
the scaffolded \`.gitignore\`.

## Where the documentation lives

- \`package.json\` pins the exact CLI version this directory is interpreted by,
  so every checkout resolves the same \`qm\`. \`contract\` in the config is only
  the coarse compatibility floor; this pin is the reproducible one. Upgrade it
  deliberately and re-run \`qm check\` afterwards.
- \`qm.config.jsonc\` describes what to run. Every field carries a comment
  explaining it, including the full list of services, so read the file itself
  before changing it. It is JSON with comments (the \`tsconfig.json\` dialect).
  That applies only to the config: \`tool.json\` files must stay strict JSON.
- \`.env.example\` is the secret catalog. It lists every secret the platform
  knows, what each one is for, what enables it, and the command that produces a
  value when one exists. The secrets the current config needs appear uncommented.
  \`qm init\` creates a gitignored \`.env\`, generates its local signing
  keys, and leaves provider credentials blank for you to fill in. Never write a
  secret value into any other file.
- \`slack-app-manifest.yml\` creates the optional qm bot app. Slack OIDC
  deployments also get \`slack-sso-manifest.yml\`. Run
  \`npm exec --yes=false -- qm slack render\` after changing \`publicUrl\`, then
  \`npm exec --yes=false -- qm outputs\` for creation links.

## Customizing the sandbox

\`sandbox/\` defines what the agent gets in its execution environment:

- A skill is \`sandbox/skills/<id>/SKILL.md\`: markdown with \`name\` and
  \`description\` frontmatter that teaches the agent a workflow and when to use it.
- A tool is \`sandbox/tools/<id>/tool.json\`: a descriptor whose minimal form is
  \`{ "id": ..., "advertise": ..., "install": { "binary": ... } }\`, with the
  executable next to it when the binary is not already in the base image.
- \`sandbox/Dockerfile\` is optional and only needed for system packages or
  runtimes.

The scaffold ships a working example, the \`greet\` skill and \`example-tool\`.
Copy its shape, then replace or delete it.

## The workflow

Run every command from this directory.

1. \`npm exec --yes=false -- qm check\` validates the config and the sandbox layer and prints the
   secret names the config currently requires. It builds nothing, and when
   credential values are already present in \`.env\` it also verifies them
   against their providers, so run it after every edit.
2. \`npm exec --yes=false -- qm plan\` reports what deployment would do
   without changing anything.
3. After the target prerequisites are complete, \`npm exec --yes=false -- qm up\` brings the
   deployment up and prints the URLs. An AWS directory must first complete the
   edge and authenticated-portal steps in its AWS bootstrap section below.
   \`--build-from <path to a QM checkout>\` is reserved for contributors
   testing unreleased runtime code.
4. \`npm exec --yes=false -- qm status\`, \`npm exec --yes=false -- qm logs [service]\`, and
   \`npm exec --yes=false -- qm down\` show
   what is running, tail logs, and stop the deployment.
5. \`npm exec --yes=false -- qm secrets push\` uploads the \`.env\` values to the deploy target.
   The docker target reads \`.env\` directly and does not need it.

\`npm exec --yes=false -- qm help\` lists everything else, including \`sandbox build\` and
\`rollback\`.
`;

const GREET_SKILL = `---
name: greet
description: Greet a teammate by name. Use whenever asked to say hello to someone.
---
Run \`example-tool <name>\` to greet someone, e.g. \`example-tool Ada\`.
`;

const EXAMPLE_TOOL_DESCRIPTOR =
  JSON.stringify({ id: "example-tool", advertise: "example-tool", install: { binary: "example-tool" } }, null, 2) +
  "\n";

const EXAMPLE_TOOL_BIN = `#!/usr/bin/env bash
echo "Hello, \${1:-world}!"
`;

const MAX_MUTABLE_SCAFFOLD_BYTES = 1024 * 1024;
const MAX_GIT_INDEX_BYTES = 16 * 1024 * 1024;

const DEPLOYMENT_SCAFFOLD_PATHS = [
  ["deployment.md"],
  [".codex", "skills", "deploy-qm", "SKILL.md"],
  [".codex", "skills", "deploy-qm", "agents", "openai.yaml"],
  ...["fly", "aws", "slack", "email"].map((name) => [".codex", "skills", "deploy-qm", "references", `${name}.md`]),
];

const SANDBOX_SCAFFOLD_PATHS = [
  ["sandbox", "skills", "greet", "SKILL.md"],
  ["sandbox", "tools", "example-tool", "tool.json"],
  ["sandbox", "tools", "example-tool", "example-tool"],
];

interface FileIdentity {
  dev: bigint;
  ino: bigint;
}

interface ExistingFileSnapshot {
  byteLength: number;
  content: string;
  identity: FileIdentity;
}

interface ScaffoldRoot {
  descriptor: number;
  identity: FileIdentity;
  path: string;
}

interface ScaffoldPath {
  abs: string;
  assertCurrent(): void;
  rel: string;
}

interface GitIndexLock {
  descriptor: number;
  identity: FileIdentity;
  path: string;
}

const currentUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : undefined;

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function ownedByCurrentUser(uid: bigint): boolean {
  return currentUid === undefined || uid === currentUid;
}

function safeDirectory(entry: BigIntStats, expected?: FileIdentity): boolean {
  return (
    entry.isDirectory() &&
    !entry.isSymbolicLink() &&
    ownedByCurrentUser(entry.uid) &&
    (entry.mode & 0o022n) === 0n &&
    (expected === undefined || sameIdentity(entry, expected))
  );
}

function directoryAncestors(path: string): string[] {
  const paths: string[] = [];
  let current = resolve(path);
  for (;;) {
    paths.push(current);
    const parent = dirname(current);
    if (parent === current) return paths;
    current = parent;
  }
}

function trustedPlatformRootAlias(path: string, entry: BigIntStats): boolean {
  if (process.platform !== "darwin" || entry.uid !== 0n || !entry.isSymbolicLink()) return false;
  const target = new Map([
    ["/etc", "/private/etc"],
    ["/tmp", "/private/tmp"],
    ["/var", "/private/var"],
  ]).get(path);
  return target !== undefined && realpathSync(path) === target;
}

function assertTrustedDirectoryAncestors(path: string, allowPlatformRootAliases = false): void {
  for (const current of directoryAncestors(path)) {
    const entry = lstatSync(current, { bigint: true });
    if (allowPlatformRootAliases && trustedPlatformRootAlias(current, entry)) continue;
    const trustedSticky = entry.uid === 0n && entry.isDirectory() && (entry.mode & 0o1000n) !== 0n;
    if (
      !entry.isDirectory() ||
      entry.isSymbolicLink() ||
      (currentUid !== undefined && entry.uid !== 0n && entry.uid !== currentUid) ||
      ((entry.mode & 0o022n) !== 0n && !trustedSticky)
    ) {
      die(`${current} is not a trusted init directory ancestor`);
    }
  }
}

function assertDarwinDirectoryAcls(paths: readonly string[]): void {
  if (process.platform !== "darwin") return;
  let output: string;
  try {
    output = execFileSync("/bin/ls", ["-lden", "--", ...paths], {
      encoding: "utf8",
      env: { ...process.env, LANG: "C", LC_ALL: "C" },
    });
  } catch {
    die("could not verify init directory ACLs");
  }
  if (output.split("\n").some((line) => /^\s*\d+:\s.*\sallow(?:\s|$)/u.test(line))) {
    die("init directories must not have permission-granting ACLs");
  }
}

function assertDarwinMutationAclSafe(path: string, label: string): void {
  if (process.platform !== "darwin") return;
  let output: string;
  try {
    output = execFileSync("/bin/ls", ["-lde", "--", path], {
      encoding: "utf8",
      env: { ...process.env, LANG: "C", LC_ALL: "C" },
    });
  } catch {
    die(`could not verify ${label} ACLs`);
  }
  const mutationPermissions = new Set([
    "append",
    "chown",
    "delete",
    "delete_child",
    "write",
    "writeattr",
    "writeextattr",
    "writesecurity",
  ]);
  const unsafe = output.split("\n").some((line) => {
    const permissions = /\sallow\s+([a-z_,]+)/u.exec(line)?.[1];
    return permissions?.split(",").some((permission) => mutationPermissions.has(permission)) ?? false;
  });
  if (unsafe) die(`${label} must not have a mutation-granting ACL`);
}

function assertDarwinFileAclSafe(path: ScaffoldPath, descriptor: number, identity: FileIdentity): void {
  assertDarwinMutationAclSafe(path.abs, path.rel);
  safeFileIdentity(path, descriptor, identity);
}

function normalizeDescriptorPermissions(descriptor: number, mode: number): void {
  if (process.platform === "darwin") {
    try {
      execFileSync("/bin/chmod", ["-N", "/dev/fd/3"], {
        stdio: ["ignore", "ignore", "ignore", descriptor],
      });
    } catch {
      die("could not remove inherited ACLs from an init scaffold file");
    }
  }
  fchmodSync(descriptor, mode);
}

function nearestExistingPath(path: string): string {
  let current = resolve(path);
  for (;;) {
    try {
      lstatSync(current);
      return current;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const parent = dirname(current);
    if (parent === current) return current;
    current = parent;
  }
}

function openScaffoldRoot(dir: string): ScaffoldRoot {
  const requested = resolve(dir);
  const lexicalExistingAncestor = nearestExistingPath(requested);
  assertTrustedDirectoryAncestors(lexicalExistingAncestor, true);
  assertDarwinDirectoryAcls(directoryAncestors(lexicalExistingAncestor));
  const existingAncestor = realpathSync(lexicalExistingAncestor);
  assertTrustedDirectoryAncestors(existingAncestor);
  assertDarwinDirectoryAcls(directoryAncestors(existingAncestor));
  mkdirSync(requested, { recursive: true, mode: 0o700 });
  const requestedEntry = lstatSync(requested, { bigint: true });
  if (!safeDirectory(requestedEntry)) die(`${requested} is not a safe init directory`);
  const path = realpathSync(requested);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor, { bigint: true });
    const current = lstatSync(path, { bigint: true });
    if (
      !safeDirectory(opened) ||
      !safeDirectory(current) ||
      !sameIdentity(requestedEntry, opened) ||
      !sameIdentity(opened, current)
    ) {
      die(`${requested} is not a safe init directory`);
    }
    assertTrustedDirectoryAncestors(path);
    assertDarwinDirectoryAcls(directoryAncestors(path));
    return { descriptor, identity: { dev: opened.dev, ino: opened.ino }, path };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    throw error;
  }
}

function assertScaffoldRoot(root: ScaffoldRoot): void {
  const opened = fstatSync(root.descriptor, { bigint: true });
  const current = lstatSync(root.path, { bigint: true });
  if (!safeDirectory(opened, root.identity) || !safeDirectory(current, root.identity)) {
    die(`${root.path} changed while init was writing the scaffold`);
  }
}

function scaffoldRelativePath(segments: readonly string[]): string {
  if (
    segments.length === 0 ||
    segments.some(
      (segment) =>
        segment === "" || segment === "." || segment === ".." || isAbsolute(segment) || /[\\/\0]/u.test(segment),
    )
  ) {
    die("invalid init scaffold path");
  }
  return segments.join("/");
}

function assertInternalDirectoryAncestors(root: ScaffoldRoot, path: string, rel: string): void {
  const paths: string[] = [];
  let current = path;
  for (;;) {
    const fromRoot = relative(root.path, current);
    if (fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
      die(`${rel} escapes the init directory`);
    }
    const entry = lstatSync(current, { bigint: true });
    if (!safeDirectory(entry)) die(`${rel} has an unsafe parent directory`);
    paths.push(current);
    if (current === root.path) break;
    current = dirname(current);
  }
  assertDarwinDirectoryAcls(paths);
}

function preflightScaffoldPath(root: ScaffoldRoot, segments: readonly string[]): void {
  const rel = scaffoldRelativePath(segments);
  const abs = join(root.path, ...segments);
  assertScaffoldRoot(root);
  const nearest = nearestExistingPath(abs);
  const finalExists = nearest === abs;
  assertInternalDirectoryAncestors(root, finalExists ? dirname(abs) : nearest, rel);
  if (finalExists) existingScaffoldFile(root, segments);
}

function withScaffoldPath<T>(root: ScaffoldRoot, segments: readonly string[], fn: (path: ScaffoldPath) => T): T {
  const rel = scaffoldRelativePath(segments);
  const held: { descriptor: number; identity: FileIdentity; path: string }[] = [];
  let parent = root.path;
  try {
    assertScaffoldRoot(root);
    for (const segment of segments.slice(0, -1)) {
      parent = join(parent, segment);
      try {
        mkdirSync(parent, { mode: 0o755 });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      let descriptor: number;
      try {
        descriptor = openSync(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      } catch {
        die(`${rel} has an unsafe parent directory`);
      }
      const opened = fstatSync(descriptor, { bigint: true });
      let current: BigIntStats;
      try {
        current = lstatSync(parent, { bigint: true });
      } catch (error) {
        closeSync(descriptor);
        throw error;
      }
      if (!safeDirectory(opened) || !safeDirectory(current) || !sameIdentity(opened, current)) {
        closeSync(descriptor);
        die(`${rel} has an unsafe parent directory`);
      }
      held.push({ descriptor, identity: { dev: opened.dev, ino: opened.ino }, path: parent });
    }
    assertTrustedDirectoryAncestors(root.path);
    assertDarwinDirectoryAcls([...directoryAncestors(root.path), ...held.map((directory) => directory.path)]);
    const assertCurrent = (): void => {
      assertScaffoldRoot(root);
      for (const directory of held) {
        const opened = fstatSync(directory.descriptor, { bigint: true });
        const current = lstatSync(directory.path, { bigint: true });
        if (!safeDirectory(opened, directory.identity) || !safeDirectory(current, directory.identity)) {
          die(`${rel} changed parent directories while init was writing it`);
        }
      }
    };
    return fn({ abs: join(parent, segments.at(-1)!), assertCurrent, rel });
  } finally {
    for (const directory of held.reverse()) closeSync(directory.descriptor);
  }
}

function safeFileIdentity(
  path: ScaffoldPath,
  descriptor: number,
  expected?: FileIdentity,
  writable = false,
): FileIdentity {
  path.assertCurrent();
  const opened = fstatSync(descriptor, { bigint: true });
  const current = lstatSync(path.abs, { bigint: true });
  if (
    !opened.isFile() ||
    opened.nlink !== 1n ||
    !current.isFile() ||
    current.isSymbolicLink() ||
    current.nlink !== 1n ||
    !ownedByCurrentUser(opened.uid) ||
    !ownedByCurrentUser(current.uid) ||
    (opened.mode & 0o022n) !== 0n ||
    (current.mode & 0o022n) !== 0n ||
    (writable && ((opened.mode & 0o200n) === 0n || (current.mode & 0o200n) === 0n)) ||
    !sameIdentity(opened, current) ||
    (expected !== undefined && !sameIdentity(opened, expected))
  ) {
    die(`${path.rel} is not a safe regular file owned by the current user`);
  }
  return { dev: opened.dev, ino: opened.ino };
}

function readDescriptorBytes(path: ScaffoldPath, descriptor: number, maxBytes: number): Buffer {
  const size = fstatSync(descriptor, { bigint: true }).size;
  if (size > BigInt(maxBytes)) die(`${path.rel} exceeds the ${maxBytes}-byte init limit`);
  const byteLength = Number(size);
  const content = Buffer.allocUnsafe(byteLength);
  let offset = 0;
  while (offset < byteLength) {
    const received = readSync(descriptor, content, offset, byteLength - offset, offset);
    if (received === 0) die(`${path.rel} changed while init was reading it`);
    offset += received;
  }
  if (readSync(descriptor, Buffer.allocUnsafe(1), 0, 1, byteLength) !== 0) {
    die(`${path.rel} changed while init was reading it`);
  }
  return content;
}

function writeDescriptor(descriptor: number, content: string): void {
  const bytes = Buffer.from(content, "utf8");
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (written === 0) die("could not write the init scaffold");
    offset += written;
  }
}

function withExistingScaffoldFile<T>(
  root: ScaffoldRoot,
  segments: readonly string[],
  writable: boolean,
  fn: (path: ScaffoldPath, descriptor: number, identity: FileIdentity) => T,
): T | undefined {
  return withScaffoldPath(root, segments, (path) => {
    let descriptor: number;
    try {
      descriptor = openSync(
        path.abs,
        (writable ? constants.O_RDWR : constants.O_RDONLY) | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        try {
          lstatSync(path.abs);
        } catch (lstatError) {
          if ((lstatError as NodeJS.ErrnoException).code === "ENOENT") return undefined;
        }
      }
      die(`${path.rel} is not a safe regular file owned by the current user`);
    }
    try {
      const identity = safeFileIdentity(path, descriptor, undefined, writable);
      assertDarwinFileAclSafe(path, descriptor, identity);
      const result = fn(path, descriptor, identity);
      safeFileIdentity(path, descriptor, identity, writable);
      return result;
    } finally {
      closeSync(descriptor);
    }
  });
}

function existingScaffoldFile(root: ScaffoldRoot, segments: readonly string[]): boolean {
  return withExistingScaffoldFile(root, segments, false, () => true) ?? false;
}

function readExistingFile(
  root: ScaffoldRoot,
  segments: readonly string[],
  maxBytes: number,
): ExistingFileSnapshot | undefined {
  return withExistingScaffoldFile(root, segments, true, (path, descriptor, identity) => {
    const bytes = readDescriptorBytes(path, descriptor, maxBytes);
    return { byteLength: bytes.byteLength, content: decodeUtf8(bytes), identity };
  });
}

function unlinkOpenedScaffoldFile(path: ScaffoldPath, descriptor: number, identity: FileIdentity): void {
  path.assertCurrent();
  const opened = fstatSync(descriptor, { bigint: true });
  const current = lstatSync(path.abs, { bigint: true });
  if (!opened.isFile() || !sameIdentity(identity, opened) || !sameIdentity(identity, current)) {
    die(`${path.rel} changed before init could remove it`);
  }
  unlinkSync(path.abs);
  try {
    lstatSync(path.abs);
    die(`${path.rel} still exists after init removed it`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  path.assertCurrent();
}

function createScaffoldFile(
  root: ScaffoldRoot,
  segments: readonly string[],
  content: string,
  mode?: number,
  beforeWrite?: () => void,
): boolean {
  return withScaffoldPath(root, segments, (path) => {
    const fileMode = mode ?? 0o644;
    let descriptor: number;
    try {
      descriptor = openSync(
        path.abs,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        fileMode,
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (existingScaffoldFile(root, segments)) return false;
      die(`${path.rel} cannot be safely created`);
    }
    let identity: FileIdentity | undefined;
    try {
      identity = safeFileIdentity(path, descriptor);
      normalizeDescriptorPermissions(descriptor, fileMode);
      safeFileIdentity(path, descriptor, identity);
      beforeWrite?.();
      writeDescriptor(descriptor, content);
      fsyncSync(descriptor);
      safeFileIdentity(path, descriptor, identity);
      return true;
    } catch (error) {
      if (identity) unlinkOpenedScaffoldFile(path, descriptor, identity);
      throw error;
    } finally {
      closeSync(descriptor);
    }
  });
}

function replaceExistingFile(
  root: ScaffoldRoot,
  segments: readonly string[],
  snapshot: ExistingFileSnapshot,
  content: string,
): void {
  withScaffoldPath(root, segments, (path) => {
    let descriptor: number;
    try {
      descriptor = openSync(path.abs, constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch {
      die(`${path.rel} changed while init was preparing it`);
    }
    try {
      const identity = safeFileIdentity(path, descriptor, snapshot.identity, true);
      const current = decodeUtf8(readDescriptorBytes(path, descriptor, snapshot.byteLength));
      if (current !== snapshot.content) die(`${path.rel} changed while init was preparing it`);
      const mode = Number(fstatSync(descriptor, { bigint: true }).mode & 0o777n);
      normalizeDescriptorPermissions(descriptor, mode);
      safeFileIdentity(path, descriptor, identity, true);
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
  });
  const updated = updateRenderedFile(root.path, segments, (existing) => {
    assertScaffoldRoot(root);
    if (existing !== snapshot.content) die(`${segments.join("/")} changed while init was preparing it`);
    return content;
  });
  if (!updated) die(`${segments.join("/")} changed while init was preparing it`);
  assertScaffoldRoot(root);
}

function validateRenderedConfig(content: string): QmConfig {
  const temporary = mkdtempSync(join(tmpdir(), "qm-init-config-"));
  let root: ScaffoldRoot | undefined;
  try {
    root = openScaffoldRoot(temporary);
    if (!createScaffoldFile(root, [CONFIG_FILENAME], content)) die("could not validate the init config scaffold");
    return loadConfigAt(join(root.path, CONFIG_FILENAME)).config;
  } finally {
    if (root) closeSync(root.descriptor);
    rmSync(temporary, { recursive: true, force: true });
  }
}

function writeIfAbsent(root: ScaffoldRoot, segments: readonly string[], content: string, mode?: number): void {
  const rel = segments.join("/");
  if (!createScaffoldFile(root, segments, content, mode)) {
    warn(`${rel} already exists — left it untouched`);
    return;
  }
  ok(`wrote ${rel}`);
}

function scaffoldSandbox(root: ScaffoldRoot): void {
  writeIfAbsent(root, SANDBOX_SCAFFOLD_PATHS[0]!, GREET_SKILL);
  writeIfAbsent(root, SANDBOX_SCAFFOLD_PATHS[1]!, EXAMPLE_TOOL_DESCRIPTOR);
  writeIfAbsent(root, SANDBOX_SCAFFOLD_PATHS[2]!, EXAMPLE_TOOL_BIN, 0o755);
}

function ensureGitignore(
  root: ScaffoldRoot,
  rules: readonly string[],
  snapshot: ExistingFileSnapshot | undefined,
): void {
  const scaffold = `${rules.join("\n")}\n`;
  if (!snapshot) {
    if (!createScaffoldFile(root, [".gitignore"], scaffold)) {
      die(".gitignore appeared while init was preparing the scaffold");
    }
    ok("wrote .gitignore");
    return;
  }
  const current = snapshot.content;
  const existing = new Set(current.split(/\r?\n/));
  const missing = rules.filter((rule) => rule !== ".env" && !existing.has(rule));
  const lastRule = current.split(/\r?\n/).filter(Boolean).at(-1);
  if (lastRule !== ".env") missing.push(".env");
  if (!missing.length) {
    replaceExistingFile(root, [".gitignore"], snapshot, current);
    ok(".gitignore already covers generated and secret state");
    return;
  }
  replaceExistingFile(
    root,
    [".gitignore"],
    snapshot,
    `${current}${current && !current.endsWith("\n") ? "\n" : ""}${missing.join("\n")}\n`,
  );
  ok("updated .gitignore");
}

function bareGitRepositoryAt(path: string): boolean {
  const configPath = join(path, "config");
  const entry = (name: string): BigIntStats | undefined => {
    try {
      return lstatSync(join(path, name), { bigint: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  };
  const head = entry("HEAD");
  const objects = entry("objects");
  const refs = entry("refs");
  const repositoryState = entry("config") !== undefined || entry("index") !== undefined;
  if (!head || !objects || !refs) {
    if (repositoryState && [head, objects, refs].some(Boolean)) {
      assertTrustedGitDirectory(path, "bare Git candidate");
      die("could not determine whether an init ancestor is a bare Git repository");
    }
    return false;
  }
  assertTrustedGitDirectory(path, "bare Git candidate");
  if (!(head.isFile() || head.isSymbolicLink())) {
    if (repositoryState) die("could not determine whether an init ancestor is a bare Git repository");
    return false;
  }
  if (!assertTrustedBareHead(path)) {
    if (repositoryState) die("could not determine whether an init ancestor is a bare Git repository");
    return false;
  }
  assertTrustedGitDirectory(join(path, "objects"), "bare Git candidate object directory");
  assertTrustedGitDirectory(join(path, "refs"), "bare Git candidate ref directory");
  assertTrustedGitFile(configPath, "bare Git candidate config");
  const result = spawnSync(
    "git",
    [
      "--no-pager",
      "--no-optional-locks",
      "-c",
      "core.fsmonitor=false",
      "-C",
      path,
      "rev-parse",
      "--is-bare-repository",
      "--absolute-git-dir",
    ],
    {
      env: gitSubprocessEnvironment(),
      maxBuffer: 4096,
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  if (result.error || result.status === null || result.signal !== null || !Buffer.isBuffer(result.stdout)) {
    die("could not determine whether an init ancestor is a bare Git repository");
  }
  if (result.status !== 0) die("could not determine whether an init ancestor is a bare Git repository");
  const lines = decodeUtf8(result.stdout).replace(/\n$/u, "").split("\n");
  if (lines.length !== 2 || (lines[0] !== "true" && lines[0] !== "false")) {
    die("could not determine whether an init ancestor is a bare Git repository");
  }
  const candidate = lstatSync(realpathSync(path), { bigint: true });
  const gitDirectory = lstatSync(realpathSync(lines[1]!), { bigint: true });
  return candidate.isDirectory() && gitDirectory.isDirectory() && sameIdentity(candidate, gitDirectory);
}

function assertTrustedBareHead(repository: string): boolean {
  const path = join(repository, "HEAD");
  const initial = lstatSync(path, { bigint: true });
  if (initial.isFile()) {
    const identity = assertTrustedGitFile(path, "bare Git candidate HEAD", true)!;
    let descriptor: number;
    try {
      descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch {
      die("bare Git candidate HEAD changed while init was inspecting Git metadata");
    }
    try {
      const opened = fstatSync(descriptor, { bigint: true });
      const current = lstatSync(path, { bigint: true });
      if (!sameIdentity(identity, opened) || !sameIdentity(identity, current) || opened.size > 1024n) {
        die("bare Git candidate HEAD changed while init was inspecting Git metadata");
      }
      const content = Buffer.alloc(Number(opened.size));
      let offset = 0;
      while (offset < content.length) {
        const received = readSync(descriptor, content, offset, content.length - offset, offset);
        if (received === 0) die("bare Git candidate HEAD changed while init was inspecting Git metadata");
        offset += received;
      }
      if (readSync(descriptor, Buffer.allocUnsafe(1), 0, 1, content.length) !== 0) {
        die("bare Git candidate HEAD changed while init was inspecting Git metadata");
      }
      const verified = fstatSync(descriptor, { bigint: true });
      const verifiedPath = lstatSync(path, { bigint: true });
      if (!sameIdentity(identity, verified) || !sameIdentity(identity, verifiedPath)) {
        die("bare Git candidate HEAD changed while init was inspecting Git metadata");
      }
      const value = decodeUtf8(content).replace(/\n$/u, "");
      if (/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/iu.test(value)) return true;
      const ref = /^ref: (refs\/heads\/.+)$/u.exec(value)?.[1];
      if (!ref) return false;
      const components = ref.split("/");
      return components.slice(2).every((component) => component !== "" && component !== "." && component !== "..");
    } finally {
      closeSync(descriptor);
    }
  }
  const target = readlinkSync(path);
  const components = target.split("/");
  if (
    !initial.isSymbolicLink() ||
    initial.nlink !== 1n ||
    !ownedByCurrentUser(initial.uid) ||
    isAbsolute(target) ||
    components.length < 3 ||
    components[0] !== "refs" ||
    components[1] !== "heads" ||
    components.slice(2).some((component) => component === "" || component === "." || component === "..")
  ) {
    die("bare Git candidate HEAD is not trusted Git metadata");
  }
  const resolvedTarget = resolve(repository, ...components);
  const targetParent = nearestExistingPath(dirname(resolvedTarget));
  const fromRepository = relative(repository, targetParent);
  if (fromRepository === ".." || fromRepository.startsWith(`..${sep}`) || isAbsolute(fromRepository)) {
    die("bare Git candidate HEAD is not trusted Git metadata");
  }
  assertTrustedGitDirectory(targetParent, "bare Git candidate HEAD target directory");
  assertDarwinMutationAclSafe(path, "bare Git candidate HEAD");
  const verified = lstatSync(path, { bigint: true });
  if (
    !verified.isSymbolicLink() ||
    verified.nlink !== 1n ||
    !ownedByCurrentUser(verified.uid) ||
    !sameIdentity(initial, verified) ||
    readlinkSync(path) !== target
  ) {
    die("bare Git candidate HEAD changed while init was inspecting Git metadata");
  }
  return true;
}

function assertTrustedGitFile(path: string, label: string, required = false): FileIdentity | undefined {
  let descriptor: number;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (!required && (error as NodeJS.ErrnoException).code === "ENOENT") {
      try {
        lstatSync(path);
      } catch (lstatError) {
        if ((lstatError as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      }
    }
    die(`${label} is not trusted Git metadata`);
  }
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    const current = lstatSync(path, { bigint: true });
    if (
      !opened.isFile() ||
      opened.nlink !== 1n ||
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.nlink !== 1n ||
      !ownedByCurrentUser(opened.uid) ||
      !ownedByCurrentUser(current.uid) ||
      (opened.mode & 0o022n) !== 0n ||
      (current.mode & 0o022n) !== 0n ||
      !sameIdentity(opened, current)
    ) {
      die(`${label} is not trusted Git metadata`);
    }
    const identity = { dev: opened.dev, ino: opened.ino };
    assertDarwinMutationAclSafe(path, label);
    const verified = fstatSync(descriptor, { bigint: true });
    const verifiedPath = lstatSync(path, { bigint: true });
    if (!sameIdentity(identity, verified) || !sameIdentity(identity, verifiedPath)) {
      die(`${label} changed while init was inspecting Git metadata`);
    }
    return identity;
  } finally {
    closeSync(descriptor);
  }
}

function assertTrustedGitDirectory(path: string, label: string): string {
  if (!isAbsolute(path)) die(`${label} is not trusted Git metadata`);
  const lexical = resolve(path);
  assertTrustedDirectoryAncestors(lexical, true);
  assertDarwinDirectoryAcls(directoryAncestors(lexical));
  const canonical = realpathSync(lexical);
  assertTrustedDirectoryAncestors(canonical);
  assertDarwinDirectoryAcls(directoryAncestors(canonical));
  const lexicalEntry = lstatSync(lexical, { bigint: true });
  const canonicalEntry = lstatSync(canonical, { bigint: true });
  if (!safeDirectory(lexicalEntry) || !safeDirectory(canonicalEntry) || !sameIdentity(lexicalEntry, canonicalEntry)) {
    die(`${label} is not trusted Git metadata`);
  }
  return canonical;
}

function gitMetadataPaths(root: string): { commonDirectory: string; gitDirectory: string; index: string } {
  const result = spawnSync(
    "git",
    [
      "--no-pager",
      "--no-optional-locks",
      "-c",
      "core.fsmonitor=false",
      "-C",
      root,
      "rev-parse",
      "--path-format=absolute",
      "--absolute-git-dir",
      "--git-common-dir",
      "--git-path",
      "index",
    ],
    {
      env: gitSubprocessEnvironment(),
      maxBuffer: 16 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  if (
    result.error ||
    result.status !== 0 ||
    result.signal !== null ||
    !Buffer.isBuffer(result.stdout) ||
    result.stdout.length === 0
  ) {
    die("could not determine whether .env is tracked by Git");
  }
  const lines = decodeUtf8(result.stdout).replace(/\n$/u, "").split("\n");
  if (lines.length !== 3 || lines.some((path) => !isAbsolute(path))) {
    die("could not determine whether .env is tracked by Git");
  }
  return { gitDirectory: lines[0]!, commonDirectory: lines[1]!, index: lines[2]! };
}

function assertTrustedGitMetadata(root: string): { index: string } {
  const paths = gitMetadataPaths(root);
  const gitDirectory = assertTrustedGitDirectory(paths.gitDirectory, "Git directory");
  const commonDirectory = assertTrustedGitDirectory(paths.commonDirectory, "Git common directory");
  const markerPath = join(root, ".git");
  try {
    const marker = lstatSync(markerPath, { bigint: true });
    if (marker.isDirectory() && !marker.isSymbolicLink()) {
      const markerDirectory = assertTrustedGitDirectory(markerPath, "Git worktree marker");
      if (!sameIdentity(lstatSync(markerDirectory, { bigint: true }), lstatSync(gitDirectory, { bigint: true }))) {
        die("Git worktree marker does not match its Git directory");
      }
    } else {
      assertTrustedGitFile(markerPath, "Git worktree marker", true);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const indexDirectory = assertTrustedGitDirectory(dirname(paths.index), "Git index directory");
  const index = join(indexDirectory, basename(paths.index));
  assertTrustedGitFile(index, "Git index");
  assertTrustedGitFile(join(commonDirectory, "config"), "Git config");
  assertTrustedGitFile(join(gitDirectory, "config.worktree"), "Git worktree config");
  assertTrustedGitFile(join(gitDirectory, "commondir"), "Git common-directory pointer");
  for (const directory of new Set([gitDirectory, commonDirectory])) {
    for (const name of readdirSync(directory)) {
      if (name.startsWith("sharedindex.")) {
        assertTrustedGitFile(join(directory, name), `Git shared index ${name}`, true);
      }
    }
  }
  return { index };
}

function releaseGitIndexLocks(locks: readonly GitIndexLock[]): void {
  let firstError: unknown;
  for (const lock of [...locks].reverse()) {
    try {
      const opened = fstatSync(lock.descriptor, { bigint: true });
      const current = lstatSync(lock.path, { bigint: true });
      if (
        !opened.isFile() ||
        opened.nlink !== 1n ||
        !current.isFile() ||
        current.isSymbolicLink() ||
        current.nlink !== 1n ||
        !sameIdentity(lock.identity, opened) ||
        !sameIdentity(lock.identity, current)
      ) {
        die(`${lock.path} changed while init held the Git index lock`);
      }
      unlinkSync(lock.path);
      try {
        lstatSync(lock.path);
        die(`${lock.path} still exists after init released the Git index lock`);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    } catch (error) {
      firstError ??= error;
    } finally {
      try {
        closeSync(lock.descriptor);
      } catch (error) {
        firstError ??= error;
      }
    }
  }
  if (firstError) throw firstError;
}

function acquireGitIndexLocks(dir: string): GitIndexLock[] {
  const indexes = [...new Set(enclosingGitRoots(dir).map((root) => assertTrustedGitMetadata(root).index))].sort();
  const locks: GitIndexLock[] = [];
  try {
    for (const index of indexes) {
      const path = `${index}.lock`;
      let descriptor: number;
      try {
        descriptor = openSync(
          path,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
          0o600,
        );
      } catch {
        die(`${path} is busy or unsafe — refusing to initialize while Git may be updating its index`);
      }
      let opened: BigIntStats;
      try {
        opened = fstatSync(descriptor, { bigint: true });
      } catch (error) {
        closeSync(descriptor);
        throw error;
      }
      const identity = { dev: opened.dev, ino: opened.ino };
      locks.push({ descriptor, identity, path });
      const current = lstatSync(path, { bigint: true });
      if (
        !opened.isFile() ||
        opened.nlink !== 1n ||
        !current.isFile() ||
        current.isSymbolicLink() ||
        current.nlink !== 1n ||
        !ownedByCurrentUser(opened.uid) ||
        !ownedByCurrentUser(current.uid) ||
        !sameIdentity(opened, current)
      ) {
        die(`${path} is not a safe Git index lock`);
      }
      normalizeDescriptorPermissions(descriptor, 0o600);
      fsyncSync(descriptor);
      const verified = fstatSync(descriptor, { bigint: true });
      const verifiedPath = lstatSync(path, { bigint: true });
      if (!sameIdentity(identity, verified) || !sameIdentity(identity, verifiedPath)) {
        die(`${path} changed while init acquired the Git index lock`);
      }
    }
    return locks;
  } catch (error) {
    releaseGitIndexLocks(locks);
    throw error;
  }
}

function enclosingGitRoots(dir: string): string[] {
  const roots: string[] = [];
  let current = resolve(dir);
  for (;;) {
    let worktree = false;
    try {
      lstatSync(join(current, ".git"));
      worktree = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (worktree || bareGitRepositoryAt(current)) roots.push(current);
    const parent = dirname(current);
    if (parent === current) return roots;
    current = parent;
  }
}

function normalizedFilesystemPath(path: string): string {
  return path.normalize("NFD").toLocaleLowerCase("und");
}

function indexEntryTargetsPath(root: string, target: string, entry: string): boolean {
  const entrySeparator = entry.lastIndexOf("/");
  const name = entry.slice(entrySeparator + 1);
  if (name.toLowerCase() !== ".env") return false;
  const entryParent = entrySeparator < 0 ? "" : entry.slice(0, entrySeparator);
  const targetSeparator = target.lastIndexOf("/");
  const targetParent = targetSeparator < 0 ? "" : target.slice(0, targetSeparator);
  const components = entryParent ? entryParent.split("/") : [];
  if (components.some((component) => component === "" || component === "." || component === "..")) {
    die("could not determine whether .env is tracked by Git");
  }
  const indexedDirectory = resolve(root, ...components);
  const targetDirectory = resolve(root, ...(targetParent ? targetParent.split("/") : []));
  const fromRoot = relative(root, indexedDirectory);
  if (fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
    die("could not determine whether .env is tracked by Git");
  }
  try {
    const indexed = lstatSync(realpathSync(indexedDirectory), { bigint: true });
    const requested = lstatSync(realpathSync(targetDirectory), { bigint: true });
    if (!indexed.isDirectory() || !requested.isDirectory()) {
      die("could not determine whether .env is tracked by Git");
    }
    return sameIdentity(indexed, requested);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      die("could not determine whether .env is tracked by Git");
    }
    return normalizedFilesystemPath(entry) === normalizedFilesystemPath(target);
  }
}

function gitIndexTracksPath(root: string, target: string): boolean {
  assertTrustedGitMetadata(root);
  const result = spawnSync(
    "git",
    [
      "--no-pager",
      "--no-optional-locks",
      "-c",
      "core.fsmonitor=false",
      "-C",
      root,
      "ls-files",
      "--full-name",
      "-z",
      "--",
      ":(top,glob,icase).env",
      ":(top,glob,icase)**/.env",
    ],
    {
      env: gitSubprocessEnvironment(),
      maxBuffer: MAX_GIT_INDEX_BYTES,
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  if (result.error || result.status === null || result.signal !== null) {
    die("could not determine whether .env is tracked by Git");
  }
  if (result.status !== 0) die("could not determine whether .env is tracked by Git");
  if (!Buffer.isBuffer(result.stdout)) die("could not determine whether .env is tracked by Git");
  if (result.stdout.length > 0 && result.stdout.at(-1) !== 0) {
    die("could not determine whether .env is tracked by Git");
  }
  const entries = decodeUtf8(result.stdout).split("\0").filter(Boolean);
  const tracked = entries.some((entry) => indexEntryTargetsPath(root, target, entry));
  assertTrustedGitMetadata(root);
  return tracked;
}

function envPathIsTracked(dir: string): boolean {
  const roots = enclosingGitRoots(dir);
  return roots.some((root) => {
    const prefix = relative(root, dir);
    const target = join(prefix, ".env").split(sep).join("/");
    return gitIndexTracksPath(root, target);
  });
}

function initialEnv(config: QmConfig): string {
  const generated = new Map(
    computedSecrets(config)
      .filter((secret) => secret.generate === "openssl rand -hex 32")
      .map((secret) => [secret.name, randomBytes(32).toString("hex")]),
  );
  return renderEnvExample(config)
    .replace(
      "# Secret values for this deployment. This file holds names only; copy it to .env and fill in",
      "# Secret values for this deployment. Local signing keys were generated; fill in the blanks",
    )
    .replace(/^([A-Z][A-Z0-9_]*)=$/gm, (line, name: string) => {
      const value = generated.get(name);
      return value ? `${name}=${value}` : line;
    });
}

function template(rel: string): string {
  const source = new URL(`../../templates/${rel}`, import.meta.url);
  const packaged = new URL(`../../../templates/${rel}`, import.meta.url);
  return readFileSync(existsSync(source) ? source : packaged, "utf8");
}

function packageContent(root: ScaffoldRoot, orgId: string): { content: string; snapshot?: ExistingFileSnapshot } {
  const packagePath = join(root.path, "package.json");
  let existing: Record<string, unknown> = {};
  const snapshot = readExistingFile(root, ["package.json"], MAX_MUTABLE_SCAFFOLD_BYTES);
  if (snapshot) {
    try {
      const parsed = JSON.parse(snapshot.content) as unknown;
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
        die(`${packagePath} must contain a JSON object`);
      existing = parsed as Record<string, unknown>;
    } catch (error) {
      if (error instanceof SyntaxError) die(`${packagePath} is not valid JSON: ${error.message}`);
      throw error;
    }
  }
  const objectField = (name: string): Record<string, unknown> => {
    const value = existing[name];
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  };
  const scripts = {
    qm: "qm",
    check: "qm check",
    plan: "qm plan",
    deploy: "qm up",
    status: "qm status",
    conformance: "qm conformance --static",
    ...objectField("scripts"),
  };
  const engines = { ...objectField("engines"), node: ">=24.0.0" };
  const packageName = cliPackageName();
  const dependencies = objectField("dependencies");
  const installedPackage = typeof dependencies[packageName] === "string" ? dependencies[packageName] : cliVersion();
  delete dependencies["qm-cli"];
  delete dependencies[packageName];
  for (const group of ["devDependencies", "optionalDependencies"] as const) {
    const groupDependencies = objectField(group);
    if ("qm-cli" in groupDependencies || packageName in groupDependencies) {
      delete groupDependencies["qm-cli"];
      delete groupDependencies[packageName];
      existing[group] = groupDependencies;
    }
  }
  existing["dependencies"] = {
    ...dependencies,
    [packageName]: installedPackage,
  };
  const packageJson = {
    ...(snapshot ? {} : { name: `${orgId}-qm-deployment`, version: "0.0.0" }),
    ...existing,
    private: true,
    engines,
    scripts,
  };
  return { content: `${JSON.stringify(packageJson, null, 2)}\n`, ...(snapshot ? { snapshot } : {}) };
}

function writePackage(root: ScaffoldRoot, prepared: { content: string; snapshot?: ExistingFileSnapshot }): void {
  if (!prepared.snapshot) {
    if (!createScaffoldFile(root, ["package.json"], prepared.content)) {
      die("package.json appeared while init was preparing the scaffold");
    }
    ok("wrote package.json");
    return;
  }
  replaceExistingFile(root, ["package.json"], prepared.snapshot, prepared.content);
  ok("updated package.json");
}

function scaffoldDeploymentSkill(root: ScaffoldRoot): void {
  for (const segments of DEPLOYMENT_SCAFFOLD_PATHS) {
    const source =
      segments[segments.length - 1] === "deployment.md"
        ? "deployment/deployment.md"
        : `deployment/${segments.slice(3).join("/")}`;
    writeIfAbsent(root, segments, template(source));
  }
}

export function runInit(opts: {
  org?: string;
  target?: Target;
  modelProvider?: ModelProvider;
  emailTransport?: EmailTransport;
  dir?: string;
}): void {
  assertNodeEngine();
  const orgId = opts.org ?? "default-org";
  if (!validOrgId(orgId)) die(`--org must be a lowercase DNS label (a-z, 0-9, and hyphens between)`);
  const root = openScaffoldRoot(opts.dir ?? process.cwd());
  try {
    const dir = root.path;
    const configPath = join(dir, CONFIG_FILENAME);
    const target: Target = opts.target ?? "docker";
    const modelProvider: ModelProvider = opts.modelProvider ?? "anthropic";
    const emailTransport: EmailTransport = opts.emailTransport ?? "resend";
    const provider = hostingProvider(target);
    const configContent = provider.scaffold.renderConfig(orgId, modelProvider, emailTransport);
    const config = validateRenderedConfig(configContent);
    const manifests = renderSlackManifests(config);
    const providerFiles = provider.scaffold.files(config);
    const plannedPaths = [
      [CONFIG_FILENAME],
      ["package.json"],
      [".env.example"],
      [".gitignore"],
      [".env"],
      ["AGENTS.md"],
      ["CLAUDE.md"],
      ...DEPLOYMENT_SCAFFOLD_PATHS,
      ["slack-app-manifest.yml"],
      ...(usesSlackOidc(config) ? [["slack-sso-manifest.yml"]] : []),
      ...SANDBOX_SCAFFOLD_PATHS,
      ...providerFiles.map((file) => file.segments),
    ];
    for (const segments of plannedPaths) preflightScaffoldPath(root, segments);
    if (existingScaffoldFile(root, [CONFIG_FILENAME])) {
      die(`${configPath} already exists — refusing to overwrite.`);
    }
    const preparedPackage = packageContent(root, orgId);
    const gitignoreSnapshot = readExistingFile(root, [".gitignore"], MAX_MUTABLE_SCAFFOLD_BYTES);
    if (envPathIsTracked(dir)) {
      die(`${join(dir, ".env")} is tracked by Git — refusing to generate signing keys into it`);
    }

    const indexLocks = acquireGitIndexLocks(dir);
    try {
      if (envPathIsTracked(dir)) {
        die(`${join(dir, ".env")} became tracked by Git before init could lock the repository index`);
      }
      writePackage(root, preparedPackage);
      writeIfAbsent(root, [".env.example"], renderEnvExample(config));
      ensureGitignore(root, provider.scaffold.ignores, gitignoreSnapshot);
      const envCreated = createScaffoldFile(root, [".env"], initialEnv(config), 0o600, () => {
        if (envPathIsTracked(dir)) {
          die(`${join(dir, ".env")} became tracked by Git while init was generating the scaffold`);
        }
      });
      if (envCreated) ok("wrote .env");
      else warn(".env already exists — left it untouched");
    } finally {
      releaseGitIndexLocks(indexLocks);
    }
    writeIfAbsent(root, ["AGENTS.md"], AGENTS_TEMPLATE + provider.scaffold.agentsAppendix);
    scaffoldDeploymentSkill(root);
    writeIfAbsent(root, ["slack-app-manifest.yml"], manifests.bot);
    if (usesSlackOidc(config)) writeIfAbsent(root, ["slack-sso-manifest.yml"], manifests.sso);
    scaffoldSandbox(root);
    for (const file of providerFiles) writeIfAbsent(root, file.segments, file.content);
    if (!createScaffoldFile(root, [CONFIG_FILENAME], configContent)) {
      die(`${configPath} appeared while init was preparing the scaffold`);
    }
    ok(`wrote ${CONFIG_FILENAME} (orgId=${orgId}, target=${target}, modelProvider=${modelProvider})`);

    note("");
    note(`CLI ${cliVersion()} selects immutable runtime image digests from its release manifest.`);
    note(`AGENTS.md explains this directory and how to customize the deployment.`);
    note("");
    note("Next:");
    const rel = relative(realpathSync(process.cwd()), dir);
    if (rel) note(`  cd ${rel.startsWith("..") || isAbsolute(rel) ? dir : rel}`);
    const step = (n: number, cmd: string, why: string): void => note(`  ${n}. ${cmd.padEnd(38)} # ${why}`);
    step(1, `npm install`, `install the exact package dependency and write the lockfile`);
    step(2, `$EDITOR ${CONFIG_FILENAME}`, `confirm provider, identity, services; optionally pin a model`);
    note(`     (${provider.scaffold.configurationHint})`);
    step(3, `npm exec --yes=false -- qm setup`, `guided: walk the configured secrets interactively`);
    note(`     (or $EDITOR .env to fill them by hand; local signing keys are generated)`);
    step(4, `npm exec --yes=false -- qm check`, `validate the config and sandbox/`);
    step(5, provider.scaffold.finalCommand, provider.scaffold.finalWhy);
  } finally {
    closeSync(root.descriptor);
  }
}
