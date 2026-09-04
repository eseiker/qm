import { createHash, createHmac, randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  opendirSync,
  openSync,
  readSync,
  realpathSync,
  statSync,
  type BigIntStats,
} from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
import type { QmConfig } from "./config.ts";
import { CliError, errMessage, step, warn } from "./log.ts";
import { deploymentSecretValue, isInvalidSecret, readEnvFile, type FileIdentity } from "./util.ts";

interface DeploymentLayerFile {
  path: string;
  content: string;
  executable?: boolean;
}

export const MAX_DEPLOYMENT_LAYER_BODY_BYTES = 1_000_000;
const MAX_DEPLOYMENT_LAYER_ENTRIES = 30_000;

interface DeploymentLayerBudget {
  remaining: number;
  entries: number;
  serializedEntries: Record<"tools" | "skills", number>;
}

export interface DeploymentLayerBundle {
  contract: 1;
  tools: DeploymentLayerFile[];
  skills: DeploymentLayerFile[];
}

export interface DeploymentLayerState {
  body: string;
  contentHash: string;
  status: "applied" | "degraded";
  runtimeContentHash: string | null;
  bootstrapped: boolean;
  precondition: DeploymentLayerPrecondition;
}

export interface DeploymentLayerPrecondition {
  generation: number;
  contentHash: string | null;
  source: "durable" | "filesystem" | "none";
  operationId: string | null;
}

export interface DeploymentLayerSyncResult {
  version: number;
  contentHash: string;
  durable: boolean;
  operationId: string | null;
  changed: boolean;
  status?: "applied" | "degraded";
  message?: string;
}

function validateDeploymentLayerPrecondition(precondition: DeploymentLayerPrecondition): void {
  if (!Number.isSafeInteger(precondition.generation) || precondition.generation < 0) {
    throw new CliError("deployment-layer precondition requires a non-negative generation");
  }
  if (precondition.source === "durable") {
    if (
      precondition.generation < 1 ||
      typeof precondition.contentHash !== "string" ||
      !/^[a-f0-9]{64}$/.test(precondition.contentHash)
    ) {
      throw new CliError("deployment-layer durable precondition requires a lowercase SHA-256 hash");
    }
  } else if (
    (precondition.source !== "none" && precondition.source !== "filesystem") ||
    precondition.contentHash !== null
  ) {
    throw new CliError("deployment-layer absent precondition requires source none or filesystem");
  }
  if (precondition.operationId !== null && !/^[a-f0-9]{32}$/.test(precondition.operationId)) {
    throw new CliError("deployment-layer precondition requires a valid operation ID");
  }
}

function validateDeploymentLayerOperationId(operationId: string): void {
  if (!/^[a-f0-9]{32}$/.test(operationId)) {
    throw new CliError("deployment-layer mutation requires a valid operation ID");
  }
}

function isWithinDeploymentLayerRoot(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function reserveDeploymentLayerBytes(budget: DeploymentLayerBudget, bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > budget.remaining) {
    throw new CliError("deployment layer exceeds the core API's 1 MB request limit");
  }
  budget.remaining -= bytes;
}

function trackDeploymentLayerEntry(budget: DeploymentLayerBudget): void {
  budget.entries++;
  if (budget.entries > MAX_DEPLOYMENT_LAYER_ENTRIES) {
    throw new CliError(`deployment layer contains too many filesystem entries`);
  }
}

function serializedTextByteLength(value: string): number {
  let bytes = 0;
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (
      code === 0x22 ||
      code === 0x5c ||
      code === 0x08 ||
      code === 0x09 ||
      code === 0x0a ||
      code === 0x0c ||
      code === 0x0d
    ) {
      bytes += 2;
    } else if (code < 0x20) {
      bytes += 6;
    } else {
      bytes += Buffer.byteLength(character);
    }
  }
  return bytes;
}

function readBoundedDeploymentLayerFile(fd: number, path: string, initial: BigIntStats, limit: number): Buffer {
  if (initial.size < 0n || initial.size > BigInt(limit)) {
    throw new CliError("deployment layer exceeds the core API's 1 MB request limit");
  }
  const size = Number(initial.size);
  const snapshot = (): Buffer => {
    const buffer = Buffer.allocUnsafe(size + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(fd, buffer, length, buffer.length - length, length);
      if (count === 0) break;
      length += count;
    }
    return buffer.subarray(0, length);
  };
  const before = fstatSync(fd, { bigint: true });
  const first = snapshot();
  const between = fstatSync(fd, { bigint: true });
  const second = snapshot();
  const after = fstatSync(fd, { bigint: true });
  if (
    !sameDeploymentLayerStat(initial, before) ||
    !sameDeploymentLayerStat(before, between) ||
    !sameDeploymentLayerStat(between, after) ||
    first.length !== size ||
    second.length !== size ||
    !first.equals(second)
  ) {
    throw new CliError(`deployment layer file changed while it was being read: ${path}`);
  }
  return first;
}

interface OpenedDeploymentLayerFile {
  fd: number;
  stat: BigIntStats;
  entry: BigIntStats;
  resolvedPath: string;
}

interface DeploymentLayerMemberSnapshot {
  path: string;
  stat: BigIntStats;
  entry: BigIntStats;
  resolvedPath: string;
  content: Buffer;
}

type DeploymentLayerDirectorySnapshot = Omit<DeploymentLayerDirectory, "fd">;

function sameDeploymentLayerStat(a: BigIntStats, b: BigIntStats): boolean {
  return (
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.mode === b.mode &&
    a.nlink === b.nlink &&
    a.size === b.size &&
    a.mtimeNs === b.mtimeNs &&
    a.ctimeNs === b.ctimeNs
  );
}

function openDeploymentLayerRegularFile(
  path: string,
  deploymentRoot: DeploymentLayerDirectory,
): OpenedDeploymentLayerFile {
  let fd: number | undefined;
  try {
    requireDeploymentLayerDirectory(deploymentRoot.sourcePath, deploymentRoot);
    const initial = lstatSync(path, { bigint: true });
    const resolved = realpathSync(path);
    if (
      !initial.isFile() ||
      initial.isSymbolicLink() ||
      initial.nlink !== 1n ||
      !isWithinDeploymentLayerRoot(deploymentRoot.resolvedPath, resolved)
    ) {
      throw new CliError(`deployment layer file must be a regular file within its root: ${path}`);
    }
    fd = openSync(resolved, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const opened = fstatSync(fd, { bigint: true });
    const currentLink = lstatSync(path, { bigint: true });
    const currentPath = realpathSync(path);
    const current = statSync(path, { bigint: true });
    if (
      !opened.isFile() ||
      !currentLink.isFile() ||
      currentLink.isSymbolicLink() ||
      !current.isFile() ||
      opened.nlink !== 1n ||
      !sameDeploymentLayerStat(initial, currentLink) ||
      !sameDeploymentLayerStat(opened, current) ||
      !isWithinDeploymentLayerRoot(deploymentRoot.resolvedPath, currentPath)
    ) {
      throw new CliError(`deployment layer file changed while it was being read: ${path}`);
    }
    requireDeploymentLayerDirectory(deploymentRoot.sourcePath, deploymentRoot);
    return { fd, stat: opened, entry: currentLink, resolvedPath: currentPath };
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (error instanceof CliError) throw error;
    throw new CliError(`deployment layer file must be a stable regular file within its root: ${path}`);
  }
}

function requireDeploymentLayerRegularFile(
  path: string,
  opened: OpenedDeploymentLayerFile,
  deploymentRoot: DeploymentLayerDirectory,
): void {
  try {
    requireDeploymentLayerDirectory(deploymentRoot.sourcePath, deploymentRoot);
    const descriptor = fstatSync(opened.fd, { bigint: true });
    const entry = lstatSync(path, { bigint: true });
    const resolvedPath = realpathSync(path);
    const current = statSync(path, { bigint: true });
    if (
      descriptor.isFile() &&
      entry.isFile() &&
      !entry.isSymbolicLink() &&
      current.isFile() &&
      descriptor.nlink === 1n &&
      sameDeploymentLayerStat(opened.stat, descriptor) &&
      sameDeploymentLayerStat(opened.entry, entry) &&
      sameDeploymentLayerStat(descriptor, current) &&
      resolvedPath === opened.resolvedPath &&
      isWithinDeploymentLayerRoot(deploymentRoot.resolvedPath, resolvedPath)
    )
      return;
  } catch {
    void 0;
  }
  throw new CliError(`deployment layer file changed while it was being read: ${path}`);
}

function requireDeploymentLayerMemberSnapshots(
  snapshots: readonly DeploymentLayerMemberSnapshot[],
  deploymentRoot: DeploymentLayerDirectory,
): void {
  for (const snapshot of snapshots) {
    const opened = openDeploymentLayerRegularFile(snapshot.path, deploymentRoot);
    try {
      if (
        !sameDeploymentLayerStat(snapshot.stat, opened.stat) ||
        !sameDeploymentLayerStat(snapshot.entry, opened.entry) ||
        snapshot.resolvedPath !== opened.resolvedPath
      ) {
        throw new CliError(`deployment layer file changed while it was being read: ${snapshot.path}`);
      }
      const content = readBoundedDeploymentLayerFile(
        opened.fd,
        snapshot.path,
        opened.stat,
        MAX_DEPLOYMENT_LAYER_BODY_BYTES,
      );
      requireDeploymentLayerRegularFile(snapshot.path, opened, deploymentRoot);
      if (!content.equals(snapshot.content)) {
        throw new CliError(`deployment layer file changed while it was being read: ${snapshot.path}`);
      }
    } finally {
      closeSync(opened.fd);
    }
  }
}

function deploymentLayerDirectorySnapshot(directory: DeploymentLayerDirectory): DeploymentLayerDirectorySnapshot {
  return {
    stat: directory.stat,
    entry: directory.entry,
    resolvedPath: directory.resolvedPath,
    sourcePath: directory.sourcePath,
  };
}

function requireDeploymentLayerDirectorySnapshots(
  snapshots: readonly DeploymentLayerDirectorySnapshot[],
  deploymentRoot: DeploymentLayerDirectory,
): void {
  for (const snapshot of snapshots) {
    const opened = openNestedDeploymentLayerDirectory(snapshot.sourcePath, deploymentRoot);
    try {
      if (
        !sameDeploymentLayerStat(snapshot.stat, opened.stat) ||
        !sameDeploymentLayerStat(snapshot.entry, opened.entry) ||
        snapshot.resolvedPath !== opened.resolvedPath
      ) {
        throw new CliError(`deployment layer directory changed while it was being read: ${snapshot.sourcePath}`);
      }
      requireDeploymentLayerDirectory(snapshot.sourcePath, opened);
    } finally {
      closeSync(opened.fd);
    }
  }
}

function textFile(
  root: string,
  path: string,
  prefix: "tools" | "skills",
  deploymentRoot: DeploymentLayerDirectory,
  budget: DeploymentLayerBudget,
  snapshots: DeploymentLayerMemberSnapshot[],
): DeploymentLayerFile {
  let openedFile: OpenedDeploymentLayerFile | undefined;
  try {
    openedFile = openDeploymentLayerRegularFile(path, deploymentRoot);
    const { fd, stat: opened } = openedFile;
    const rel = relative(root, path).split(sep).join("/");
    const bundlePath = `${prefix}/${rel}`;
    const executable = (opened.mode & 0o111n) !== 0n;
    const separatorBytes = budget.serializedEntries[prefix] === 0 ? 0 : 1;
    budget.serializedEntries[prefix]++;
    reserveDeploymentLayerBytes(
      budget,
      Buffer.byteLength(
        JSON.stringify({ path: bundlePath, content: "", ...(executable ? { executable: true } : {}) }),
      ) + separatorBytes,
    );
    const bytes = readBoundedDeploymentLayerFile(fd, path, opened, budget.remaining);
    requireDeploymentLayerRegularFile(path, openedFile, deploymentRoot);
    const content = bytes.toString("utf8");
    if (bytes.includes(0) || !Buffer.from(content, "utf8").equals(bytes)) {
      throw new CliError(`deployment layer API only accepts text skill assets: ${path}`);
    }
    snapshots.push({
      path,
      stat: openedFile.stat,
      entry: openedFile.entry,
      resolvedPath: openedFile.resolvedPath,
      content: bytes,
    });
    reserveDeploymentLayerBytes(budget, serializedTextByteLength(content));
    return {
      path: bundlePath,
      content,
      ...(executable ? { executable: true } : {}),
    };
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(`deployment layer file must be a stable regular file within its root: ${path}`);
  } finally {
    if (openedFile !== undefined) closeSync(openedFile.fd);
  }
}

const pathOrder = (a: DeploymentLayerFile, b: DeploymentLayerFile): number => {
  if (a.path < b.path) return -1;
  if (a.path > b.path) return 1;
  return 0;
};

export const JUNK_FILE = /^(?:\.DS_Store|Thumbs\.db|\._.*)$/;

interface DeploymentLayerDirectory {
  fd: number;
  stat: BigIntStats;
  entry: BigIntStats;
  resolvedPath: string;
  sourcePath: string;
}

function openDeploymentLayerDirectory(path: string): DeploymentLayerDirectory {
  let fd: number | undefined;
  try {
    const entry = lstatSync(path, { bigint: true });
    fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
    const stat = fstatSync(fd, { bigint: true });
    const resolvedPath = realpathSync(path);
    const resolved = statSync(resolvedPath, { bigint: true });
    if (
      (entry.isDirectory() || entry.isSymbolicLink()) &&
      stat.isDirectory() &&
      sameDeploymentLayerStat(stat, resolved)
    ) {
      return { fd, stat, entry, resolvedPath, sourcePath: path };
    }
  } catch {
    void 0;
  }
  if (fd !== undefined) closeSync(fd);
  throw new CliError(`deployment layer root must be an existing directory: ${path}`);
}

function requireDeploymentLayerDirectory(path: string, opened: DeploymentLayerDirectory): void {
  try {
    const descriptor = fstatSync(opened.fd, { bigint: true });
    const entry = lstatSync(path, { bigint: true });
    const resolvedPath = realpathSync(path);
    const stat = statSync(path, { bigint: true });
    if (
      descriptor.isDirectory() &&
      (entry.isDirectory() || entry.isSymbolicLink()) &&
      stat.isDirectory() &&
      sameDeploymentLayerStat(opened.stat, descriptor) &&
      sameDeploymentLayerStat(opened.entry, entry) &&
      sameDeploymentLayerStat(descriptor, stat) &&
      resolvedPath === opened.resolvedPath
    )
      return;
  } catch {
    void 0;
  }
  throw new CliError(`deployment layer root changed while it was being read: ${path}`);
}

function openNestedDeploymentLayerDirectory(path: string, root: DeploymentLayerDirectory): DeploymentLayerDirectory {
  let fd: number | undefined;
  try {
    requireDeploymentLayerDirectory(root.sourcePath, root);
    const link = lstatSync(path, { bigint: true });
    const resolvedPath = realpathSync(path);
    if (link.isSymbolicLink() || !link.isDirectory() || !isWithinDeploymentLayerRoot(root.resolvedPath, resolvedPath)) {
      throw new CliError(`deployment layer directory must be within its root: ${path}`);
    }
    fd = openSync(resolvedPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const descriptor = fstatSync(fd, { bigint: true });
    const currentLink = lstatSync(path, { bigint: true });
    const currentPath = realpathSync(path);
    const current = statSync(path, { bigint: true });
    if (
      !descriptor.isDirectory() ||
      !currentLink.isDirectory() ||
      currentLink.isSymbolicLink() ||
      !current.isDirectory() ||
      !sameDeploymentLayerStat(link, currentLink) ||
      !sameDeploymentLayerStat(descriptor, current) ||
      !isWithinDeploymentLayerRoot(root.resolvedPath, currentPath)
    ) {
      throw new CliError(`deployment layer directory changed while it was being read: ${path}`);
    }
    requireDeploymentLayerDirectory(root.sourcePath, root);
    return { fd, stat: descriptor, entry: currentLink, resolvedPath: currentPath, sourcePath: path };
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (error instanceof CliError) throw error;
    throw new CliError(`deployment layer directory must be stable within its root: ${path}`);
  }
}

function walkText(
  root: string,
  prefix: "skills",
  deploymentRoot: DeploymentLayerDirectory,
  budget: DeploymentLayerBudget,
  snapshots: DeploymentLayerMemberSnapshot[],
  directorySnapshots: DeploymentLayerDirectorySnapshot[],
): DeploymentLayerFile[] {
  if (!existsSync(root)) return [];
  const out: DeploymentLayerFile[] = [];
  const walk = (dir: string): void => {
    const opened = openNestedDeploymentLayerDirectory(dir, deploymentRoot);
    directorySnapshots.push(deploymentLayerDirectorySnapshot(opened));
    const entries = opendirSync(dir);
    try {
      requireDeploymentLayerDirectory(deploymentRoot.sourcePath, deploymentRoot);
      requireDeploymentLayerDirectory(dir, opened);
      for (let entry = entries.readSync(); entry !== null; entry = entries.readSync()) {
        trackDeploymentLayerEntry(budget);
        if (JUNK_FILE.test(entry.name)) continue;
        const path = join(dir, entry.name);
        if (entry.isDirectory()) walk(path);
        else out.push(textFile(root, path, prefix, deploymentRoot, budget, snapshots));
      }
    } finally {
      entries.closeSync();
      try {
        requireDeploymentLayerDirectory(dir, opened);
      } finally {
        closeSync(opened.fd);
      }
    }
  };
  walk(root);
  return out.sort(pathOrder);
}

function validateToolDescendants(
  dir: string,
  deploymentRoot: DeploymentLayerDirectory,
  budget: DeploymentLayerBudget,
  directorySnapshots: DeploymentLayerDirectorySnapshot[],
): void {
  const openedDirectory = openNestedDeploymentLayerDirectory(dir, deploymentRoot);
  directorySnapshots.push(deploymentLayerDirectorySnapshot(openedDirectory));
  const entries = opendirSync(dir);
  try {
    requireDeploymentLayerDirectory(deploymentRoot.sourcePath, deploymentRoot);
    requireDeploymentLayerDirectory(dir, openedDirectory);
    for (let entry = entries.readSync(); entry !== null; entry = entries.readSync()) {
      trackDeploymentLayerEntry(budget);
      if (JUNK_FILE.test(entry.name)) continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        validateToolDescendants(path, deploymentRoot, budget, directorySnapshots);
      } else {
        const opened = openDeploymentLayerRegularFile(path, deploymentRoot);
        closeSync(opened.fd);
      }
    }
  } finally {
    entries.closeSync();
    try {
      requireDeploymentLayerDirectory(dir, openedDirectory);
    } finally {
      closeSync(openedDirectory.fd);
    }
  }
}

export function deploymentLayerBundle(sandboxDir: string): DeploymentLayerBundle {
  const root = openDeploymentLayerDirectory(sandboxDir);
  const sandboxPath = root.resolvedPath;
  const budget: DeploymentLayerBudget = {
    remaining:
      MAX_DEPLOYMENT_LAYER_BODY_BYTES - Buffer.byteLength(JSON.stringify({ contract: 1, tools: [], skills: [] })),
    entries: 0,
    serializedEntries: { tools: 0, skills: 0 },
  };
  const snapshots: DeploymentLayerMemberSnapshot[] = [];
  const directorySnapshots: DeploymentLayerDirectorySnapshot[] = [];
  try {
    requireDeploymentLayerDirectory(sandboxDir, root);
    const toolsDir = join(sandboxPath, "tools");
    const tools: DeploymentLayerFile[] = [];
    if (existsSync(toolsDir)) {
      const openedTools = openNestedDeploymentLayerDirectory(toolsDir, root);
      directorySnapshots.push(deploymentLayerDirectorySnapshot(openedTools));
      const entries = opendirSync(toolsDir);
      try {
        requireDeploymentLayerDirectory(root.sourcePath, root);
        requireDeploymentLayerDirectory(toolsDir, openedTools);
        for (let entry = entries.readSync(); entry !== null; entry = entries.readSync()) {
          trackDeploymentLayerEntry(budget);
          if (JUNK_FILE.test(entry.name)) continue;
          const path = join(toolsDir, entry.name);
          if (!entry.isDirectory())
            throw new CliError(`deployment layer tools entry must be a directory containing tool.json: ${path}`);
          validateToolDescendants(path, root, budget, directorySnapshots);
          const descriptor = join(path, "tool.json");
          if (!existsSync(descriptor))
            throw new CliError(`deployment layer tool directory is missing tool.json: ${path}`);
          tools.push(textFile(toolsDir, descriptor, "tools", root, budget, snapshots));
        }
      } finally {
        entries.closeSync();
        try {
          requireDeploymentLayerDirectory(toolsDir, openedTools);
        } finally {
          closeSync(openedTools.fd);
        }
      }
      tools.sort(pathOrder);
    }
    requireDeploymentLayerDirectory(sandboxDir, root);
    const skills = walkText(join(sandboxPath, "skills"), "skills", root, budget, snapshots, directorySnapshots);
    requireDeploymentLayerDirectorySnapshots(directorySnapshots, root);
    requireDeploymentLayerMemberSnapshots(snapshots, root);
    requireDeploymentLayerDirectory(sandboxDir, root);
    return { contract: 1, tools, skills };
  } finally {
    closeSync(root.fd);
  }
}

export function deploymentLayerRootTextFile(sandboxDir: string, name: string): string | undefined {
  const root = openDeploymentLayerDirectory(sandboxDir);
  let opened: OpenedDeploymentLayerFile | undefined;
  try {
    requireDeploymentLayerDirectory(sandboxDir, root);
    const path = join(root.resolvedPath, name);
    try {
      lstatSync(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
    opened = openDeploymentLayerRegularFile(path, root);
    const bytes = readBoundedDeploymentLayerFile(opened.fd, path, opened.stat, MAX_DEPLOYMENT_LAYER_BODY_BYTES);
    requireDeploymentLayerRegularFile(path, opened, root);
    const content = bytes.toString("utf8");
    if (bytes.includes(0) || !Buffer.from(content, "utf8").equals(bytes)) {
      throw new CliError(`deployment layer API only accepts text files: ${path}`);
    }
    requireDeploymentLayerDirectory(sandboxDir, root);
    return content;
  } finally {
    if (opened) closeSync(opened.fd);
    closeSync(root.fd);
  }
}

export function deploymentLayerTopLevelDirectories(sandboxDir: string, name: "skills"): string[] {
  const root = openDeploymentLayerDirectory(sandboxDir);
  try {
    const path = join(root.resolvedPath, name);
    if (!existsSync(path)) return [];
    const opened = openNestedDeploymentLayerDirectory(path, root);
    const directories: string[] = [];
    const entries = opendirSync(path);
    let count = 0;
    try {
      requireDeploymentLayerDirectory(root.sourcePath, root);
      requireDeploymentLayerDirectory(path, opened);
      for (let entry = entries.readSync(); entry !== null; entry = entries.readSync()) {
        if (++count > MAX_DEPLOYMENT_LAYER_ENTRIES) {
          throw new CliError(`deployment layer contains too many filesystem entries`);
        }
        if (JUNK_FILE.test(entry.name) || !entry.isDirectory()) continue;
        const child = openNestedDeploymentLayerDirectory(join(path, entry.name), root);
        try {
          requireDeploymentLayerDirectory(join(path, entry.name), child);
        } finally {
          closeSync(child.fd);
        }
        directories.push(entry.name);
      }
    } finally {
      entries.closeSync();
      try {
        requireDeploymentLayerDirectory(path, opened);
      } finally {
        closeSync(opened.fd);
      }
    }
    requireDeploymentLayerDirectory(sandboxDir, root);
    return directories.sort();
  } finally {
    closeSync(root.fd);
  }
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function deploymentLayerPath(path: string, kind: "tools" | "skills"): string {
  const parts = path.split("/");
  if (
    path.startsWith("/") ||
    path.endsWith("/") ||
    path.includes("\\") ||
    path.includes("\0") ||
    hasLoneSurrogate(path) ||
    parts.some((part) => part === "" || part === "." || part === "..") ||
    parts[0] !== kind
  ) {
    throw new CliError(`deployment layer ${kind} entry has an unsafe path: ${JSON.stringify(path)}`);
  }
  return path;
}

function normalizedLayerBundle(value: unknown): DeploymentLayerBundle {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new CliError("deployment layer bundle must be an object");
  const bundle = value as Record<string, unknown>;
  if (bundle.contract !== 1 || !Array.isArray(bundle.tools) || !Array.isArray(bundle.skills)) {
    throw new CliError("deployment layer bundle requires contract: 1, tools[], and skills[]");
  }
  const files = (kind: "tools" | "skills", entries: unknown[]): DeploymentLayerFile[] => {
    const seen = new Set<string>();
    return entries
      .map((entry) => {
        if (!entry || typeof entry !== "object" || Array.isArray(entry))
          throw new CliError(`deployment layer ${kind} entry must be an object`);
        const file = entry as Record<string, unknown>;
        if (typeof file.path !== "string" || typeof file.content !== "string") {
          throw new CliError(`deployment layer ${kind} entries require string path and content`);
        }
        const path = deploymentLayerPath(file.path, kind);
        if (file.content.includes("\0") || hasLoneSurrogate(file.content)) {
          throw new CliError(`deployment layer ${kind} entry contains invalid text: ${path}`);
        }
        if (file.executable !== undefined && file.executable !== true) {
          throw new CliError(`deployment layer ${kind} entry has an invalid executable field: ${path}`);
        }
        if (seen.has(path)) throw new CliError(`deployment layer contains a duplicate path: ${path}`);
        seen.add(path);
        return { path, content: file.content, ...(file.executable === true ? { executable: true } : {}) };
      })
      .sort(pathOrder);
  };
  return { contract: 1, tools: files("tools", bundle.tools), skills: files("skills", bundle.skills) };
}

function normalizedLayerBody(value: unknown): string {
  return JSON.stringify(normalizedLayerBundle(value));
}

export function deploymentLayerBody(sandboxDir: string): string {
  const bundle = deploymentLayerBundle(sandboxDir);
  const body = normalizedLayerBody(bundle);
  if (Buffer.byteLength(body) > MAX_DEPLOYMENT_LAYER_BODY_BYTES)
    throw new CliError("deployment layer exceeds the core API's 1 MB request limit");
  return body;
}

function signingHeaders(secret: string, method: string, path: string, body: string): Record<string, string> {
  const timestamp = Math.floor(Date.now() / 1000);
  const canonical = `${method}\n${path}\n${body}`;
  const signature = createHmac("sha256", secret).update(`v0:${timestamp}:${canonical}`).digest("hex");
  return {
    "content-type": "application/json",
    "x-timestamp": String(timestamp),
    "x-signature": `v0=${signature}`,
  };
}

function defaultCoreUrl(config: QmConfig): URL {
  const url = new URL(config.publicUrl);
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/v1/deployment-layer`;
  return url;
}

export class CoreUnreachableError extends CliError {}

export const CONNECTIVITY_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ENOTFOUND",
  "EAI_AGAIN",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "EPERM",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_SOCKET",
]);

const DEFAULT_HTTP_DEPLOYMENT_LAYER_TIMEOUT_MS = 30_000;
export const MAX_DEPLOYMENT_LAYER_GET_RESPONSE_BYTES = MAX_DEPLOYMENT_LAYER_BODY_BYTES + 100_000;
export const MAX_DEPLOYMENT_LAYER_SMALL_RESPONSE_BYTES = 65_536;

function isCoreUnreachable(error: unknown): boolean {
  if (error instanceof CoreUnreachableError) return true;
  const seen = new Set<Error>();
  let unreachable = false;
  for (let e: unknown = error; e instanceof Error && !seen.has(e); e = e.cause) {
    seen.add(e);
    if (e instanceof CliError) return false;
    if (e instanceof DOMException && e.name === "TimeoutError" && e.code === DOMException.TIMEOUT_ERR) {
      unreachable = true;
    }
    const code = (e as { code?: unknown }).code;
    if (typeof code === "string" && CONNECTIVITY_CODES.has(code)) unreachable = true;
  }
  return unreachable;
}

interface DeploymentLayerTransportOpts {
  config: QmConfig;
  configIdentity: FileIdentity;
  configDir: string;
  method: "GET" | "PUT" | "DELETE";
  body: string;
  envFile?: string;
  precondition?: DeploymentLayerPrecondition;
  operationId?: string;
}

/**
 * How a hosting target reaches its core's /v1/deployment-layer endpoint.
 * Each HostingProvider supplies one; nothing in this file knows about targets.
 */
export type DeploymentLayerTransport = (
  opts: DeploymentLayerTransportOpts,
) => Promise<{ status: number; body: string }>;

export function validateDeploymentLayerRequestBody(method: "GET" | "PUT" | "DELETE", body: string): void {
  if (method !== "PUT" && body !== "") {
    throw new CliError(`deployment-layer ${method} requests must have an empty body`);
  }
  if (method === "PUT" && Buffer.byteLength(body) > MAX_DEPLOYMENT_LAYER_BODY_BYTES) {
    throw new CliError("deployment layer exceeds the core API's 1 MB request limit");
  }
}

function deploymentLayerResponseLimit(method: "GET" | "PUT" | "DELETE", status: number): number {
  return method === "GET" && status === 200
    ? MAX_DEPLOYMENT_LAYER_GET_RESPONSE_BYTES
    : MAX_DEPLOYMENT_LAYER_SMALL_RESPONSE_BYTES;
}

async function readDeploymentLayerResponse(response: Response, method: "GET" | "PUT" | "DELETE"): Promise<string> {
  const limit = deploymentLayerResponseLimit(method, response.status);
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const length = Number(contentLength);
    if (!/^\d+$/.test(contentLength) || !Number.isSafeInteger(length) || length > limit) {
      await response.body?.cancel().catch(() => undefined);
      throw new CliError(`deployment-layer response exceeds the ${limit}-byte limit`);
    }
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  let received = 0;
  const bytes = new Uint8Array(limit);
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      if (chunk.value.byteLength > limit - received) {
        await reader.cancel().catch(() => undefined);
        throw new CliError(`deployment-layer response exceeds the ${limit}-byte limit`);
      }
      bytes.set(chunk.value, received);
      received += chunk.value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, received));
  } catch (error) {
    throw new CliError(`deployment-layer response is not valid UTF-8`, { cause: error });
  }
}

/** Signed-HTTP transport used by providers whose core is reachable over plain HTTPS. */
export function httpDeploymentLayerTransport(
  o: {
    urlOf?: (config: QmConfig) => URL;
    secretFallback?: (config: QmConfig) => string | undefined;
    timeoutMs?: number;
  } = {},
): DeploymentLayerTransport {
  return async (opts) => {
    validateDeploymentLayerRequestBody(opts.method, opts.body);
    if (opts.envFile !== undefined && !opts.envFile.trim()) {
      throw new CliError("--env-file needs a non-empty path", { clause: "cli.invocation" });
    }
    const envPath = opts.envFile ?? join(opts.configDir, ".env");
    const env = readEnvFile(envPath, {
      required: opts.envFile !== undefined,
      protectedIdentity: opts.configIdentity,
    });
    let secret = deploymentSecretValue("CORE_SIGNING_SECRET", env.get("CORE_SIGNING_SECRET"));
    if (!secret && o.secretFallback) secret = o.secretFallback(opts.config);
    if (!secret) throw new CliError(`CORE_SIGNING_SECRET is required locally to access the deployment layer`);
    if (isInvalidSecret("CORE_SIGNING_SECRET", secret)) {
      throw new CliError("CORE_SIGNING_SECRET is missing, placeholder, or insecure");
    }
    const url = (o.urlOf ?? defaultCoreUrl)(opts.config);
    if (opts.precondition !== undefined) {
      validateDeploymentLayerPrecondition(opts.precondition);
      url.searchParams.set("generation", String(opts.precondition.generation));
      url.searchParams.set("source", opts.precondition.source);
      if (opts.precondition.contentHash !== null) url.searchParams.set("contentHash", opts.precondition.contentHash);
      if (opts.precondition.operationId !== null) {
        url.searchParams.set("currentOperationId", opts.precondition.operationId);
      }
    }
    if (opts.operationId !== undefined) {
      validateDeploymentLayerOperationId(opts.operationId);
      url.searchParams.set("operationId", opts.operationId);
    }
    const response = await fetch(url, {
      method: opts.method,
      headers: signingHeaders(secret, opts.method, url.pathname + url.search, opts.body),
      ...(opts.method === "PUT" ? { body: opts.body } : {}),
      signal: AbortSignal.timeout(o.timeoutMs ?? DEFAULT_HTTP_DEPLOYMENT_LAYER_TIMEOUT_MS),
      redirect: "error",
    });
    return { status: response.status, body: await readDeploymentLayerResponse(response, opts.method) };
  };
}

export async function deploymentLayerRequest(opts: {
  config: QmConfig;
  configIdentity: FileIdentity;
  configDir: string;
  method: "GET" | "PUT" | "DELETE";
  body?: string;
  envFile?: string;
  precondition?: DeploymentLayerPrecondition;
  operationId?: string;
  transport: DeploymentLayerTransport;
}): Promise<{ status: number; body: string }> {
  const body = opts.body ?? "";
  validateDeploymentLayerRequestBody(opts.method, body);
  if (opts.precondition !== undefined) validateDeploymentLayerPrecondition(opts.precondition);
  if (opts.operationId !== undefined) validateDeploymentLayerOperationId(opts.operationId);
  const response = await opts.transport({
    config: opts.config,
    configIdentity: opts.configIdentity,
    configDir: opts.configDir,
    method: opts.method,
    body,
    ...(opts.envFile !== undefined ? { envFile: opts.envFile } : {}),
    ...(opts.precondition !== undefined ? { precondition: opts.precondition } : {}),
    ...(opts.operationId !== undefined ? { operationId: opts.operationId } : {}),
  });
  const limit = deploymentLayerResponseLimit(opts.method, response.status);
  if (Buffer.byteLength(response.body) > limit) {
    throw new CliError(`deployment-layer response exceeds the ${limit}-byte limit`);
  }
  return response;
}

export async function syncDeploymentLayer(opts: {
  config: QmConfig;
  configIdentity: FileIdentity;
  transport: DeploymentLayerTransport;
  configDir: string;
  sandboxDir: string;
  envFile?: string;
  allowUnavailable?: boolean;
  operationId?: string;
}): Promise<void> {
  if (!existsSync(opts.sandboxDir)) {
    step(`deployment layer: skipped (no sandbox directory at ${opts.sandboxDir})`);
    return;
  }
  const body = deploymentLayerBody(opts.sandboxDir);
  let current: DeploymentLayerState;
  try {
    current = await currentDeploymentLayerState(opts);
  } catch (error) {
    if (opts.allowUnavailable && isCoreUnreachable(error)) {
      step(`deployment layer: core is not reachable; deployment succeeded and sync is deferred until the next up`);
      return;
    }
    throw new CliError(`could not sync deployment layer: ${errMessage(error)}`, { cause: error });
  }
  await syncDeploymentLayerBody({ ...opts, precondition: current.precondition }, body);
}

export async function currentDeploymentLayerState(opts: {
  config: QmConfig;
  configIdentity: FileIdentity;
  transport: DeploymentLayerTransport;
  configDir: string;
  envFile?: string;
}): Promise<DeploymentLayerState> {
  const response = await deploymentLayerRequest({ ...opts, method: "GET" });
  if (response.status !== 200)
    throw new CliError(`deployment layer read failed (${response.status}): ${response.body.slice(0, 200)}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(response.body);
  } catch {
    throw new CliError("deployment layer read returned unparseable JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new CliError("deployment layer read returned invalid JSON");
  const result = parsed as Record<string, unknown>;
  if (result.contract !== 1) throw new CliError("deployment layer read returned an invalid contract");
  const version = result.version;
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 0) {
    throw new CliError("deployment layer read returned an invalid version");
  }
  const generation = result.generation;
  if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 0) {
    throw new CliError("deployment layer read returned an invalid generation");
  }
  const storedHash = result.contentHash;
  if (storedHash !== null && (typeof storedHash !== "string" || !/^[a-f0-9]{64}$/.test(storedHash))) {
    throw new CliError("deployment layer read returned an invalid contentHash");
  }
  const source = result.source;
  if (source !== "none" && source !== "filesystem" && source !== "durable") {
    throw new CliError("deployment layer read returned an invalid source");
  }
  const operationId = result.operationId;
  if (operationId !== null && (typeof operationId !== "string" || !/^[a-f0-9]{32}$/.test(operationId))) {
    throw new CliError("deployment layer read returned an invalid operationId");
  }
  const bootstrapped = version === 0 && storedHash === null;
  if ((version === 0) !== (storedHash === null)) {
    throw new CliError("deployment layer read returned inconsistent version and contentHash fields");
  }
  if (bootstrapped) {
    if (
      source === "durable" ||
      result.bundle !== undefined ||
      result.status !== undefined ||
      result.runtimeContentHash !== undefined
    ) {
      throw new CliError("deployment layer read returned an invalid version-0 state");
    }
    const body = normalizedLayerBody({ contract: 1, tools: [], skills: [] });
    const contentHash = createHash("sha256").update(body).digest("hex");
    return {
      body,
      contentHash,
      status: "applied",
      runtimeContentHash: source === "none" ? contentHash : null,
      bootstrapped: true,
      precondition: { generation, contentHash: null, source, operationId },
    };
  }
  const storedBundle = result.bundle;
  if (!storedBundle || typeof storedBundle !== "object" || Array.isArray(storedBundle))
    throw new CliError("deployment layer read did not return a restorable bundle");
  const status = result.status;
  if (status !== "applied" && status !== "degraded") {
    throw new CliError("deployment layer read returned an invalid status");
  }
  const runtimeContentHash = result.runtimeContentHash;
  if (
    runtimeContentHash !== null &&
    (typeof runtimeContentHash !== "string" || !/^[a-f0-9]{64}$/.test(runtimeContentHash))
  ) {
    throw new CliError("deployment layer read returned an invalid runtimeContentHash");
  }
  const bundle = normalizedLayerBundle(storedBundle);
  try {
    const { assertRestorableDeploymentLayerBundle } = await import("./sandbox-layer.ts");
    assertRestorableDeploymentLayerBundle(bundle);
  } catch (error) {
    throw new CliError(`deployment layer read returned an unrestorable bundle: ${errMessage(error)}`, {
      cause: error,
    });
  }
  const body = JSON.stringify(bundle);
  if (Buffer.byteLength(body) > MAX_DEPLOYMENT_LAYER_BODY_BYTES)
    throw new CliError("deployment layer exceeds the core API's 1 MB request limit");
  const contentHash = createHash("sha256").update(body).digest("hex");
  if (storedHash !== contentHash) {
    throw new CliError("deployment layer read returned a bundle that does not match its contentHash");
  }
  if (status === "applied" && (source !== "durable" || runtimeContentHash !== contentHash)) {
    throw new CliError("deployment layer read returned an inconsistent applied state");
  }
  if (generation !== version) throw new CliError("deployment layer read returned an inconsistent generation");
  return {
    body,
    contentHash,
    status,
    runtimeContentHash,
    bootstrapped: false,
    precondition: { generation, contentHash, source: "durable", operationId },
  };
}

function deploymentLayerMutationResult(
  response: { status: number; body: string },
  expectedHash: string,
  expectedDescription: string,
  precondition: DeploymentLayerPrecondition,
  requestOperationId: string,
  allowUnchanged: boolean,
): DeploymentLayerSyncResult {
  if (response.status !== 200 && response.status !== 202)
    throw new CliError(`deployment layer sync failed (${response.status}): ${response.body.slice(0, 200)}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(response.body);
  } catch {
    throw new CliError(
      `deployment layer sync returned a ${response.status} but unparseable JSON: ${response.body.slice(0, 200)}`,
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new CliError(`deployment layer sync returned invalid JSON: expected an object`);
  }
  const result = parsed as Record<string, unknown>;
  if (result.ok !== true) {
    throw new CliError(`deployment layer sync returned invalid JSON: ok must be true`);
  }
  const version = result.version;
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) {
    throw new CliError(`deployment layer sync returned invalid JSON: version must be a positive integer`);
  }
  const contentHash = result.contentHash;
  if (typeof contentHash !== "string") {
    throw new CliError(`deployment layer sync returned invalid JSON: contentHash must be a string`);
  }
  if (contentHash !== expectedHash) {
    throw new CliError(`deployment layer sync returned a contentHash that does not match ${expectedDescription}`);
  }
  const operationId = result.operationId;
  if (operationId !== null && (typeof operationId !== "string" || !/^[a-f0-9]{32}$/.test(operationId))) {
    throw new CliError(`deployment layer sync returned invalid JSON: operationId must be null or a valid operation ID`);
  }
  const changed = result.changed;
  if (typeof changed !== "boolean") {
    throw new CliError(`deployment layer sync returned invalid JSON: changed must be a boolean`);
  }
  const ownedTransition = changed && version === precondition.generation + 1 && operationId === requestOperationId;
  const unchangedCurrent =
    !changed &&
    allowUnchanged &&
    precondition.source === "durable" &&
    precondition.contentHash === expectedHash &&
    version === precondition.generation &&
    operationId === precondition.operationId;
  if (!ownedTransition && !unchangedCurrent) {
    throw new CliError(`deployment layer sync returned an inconsistent mutation revision`);
  }
  const durable = result.durable;
  if (typeof durable !== "boolean") {
    throw new CliError(`deployment layer sync returned invalid JSON: durable must be a boolean`);
  }
  const status = result.status;
  if (status !== undefined && status !== "applied" && status !== "degraded") {
    throw new CliError(`deployment layer sync returned invalid JSON: status must be applied or degraded`);
  }
  const message = result.message;
  if (message !== undefined && typeof message !== "string") {
    throw new CliError(`deployment layer sync returned invalid JSON: message must be a string`);
  }
  if (response.status === 202 && (status !== "degraded" || typeof message !== "string")) {
    throw new CliError(`deployment layer sync returned invalid JSON: 202 requires degraded status and a message`);
  }
  if (response.status === 200 && status === "degraded") {
    throw new CliError(`deployment layer sync returned invalid JSON: 200 cannot report degraded status`);
  }
  step(`deployment layer: v${version} ${contentHash.slice(0, 12)}`);
  if (status === "degraded") {
    warn(
      `deployment layer persisted but only partially applied: ${message ?? "the core is serving its previous resolved layer"}`,
    );
  }
  if (!durable) {
    warn(
      "deployment layer is memory-backed and will not survive a core restart; configure DATABASE_URL for durable storage",
    );
  }
  return {
    version,
    contentHash,
    durable,
    operationId,
    changed,
    ...(status !== undefined ? { status } : {}),
    ...(message !== undefined ? { message } : {}),
  };
}

export async function syncDeploymentLayerBody(
  opts: {
    config: QmConfig;
    configIdentity: FileIdentity;
    transport: DeploymentLayerTransport;
    configDir: string;
    envFile?: string;
    allowUnavailable?: boolean;
    precondition: DeploymentLayerPrecondition;
    operationId?: string;
  },
  body: string,
): Promise<DeploymentLayerSyncResult | undefined> {
  const operationId = opts.operationId ?? randomBytes(16).toString("hex");
  validateDeploymentLayerOperationId(operationId);
  let response: { status: number; body: string };
  try {
    response = await deploymentLayerRequest({
      config: opts.config,
      configIdentity: opts.configIdentity,
      configDir: opts.configDir,
      method: "PUT",
      body,
      transport: opts.transport,
      ...(opts.envFile !== undefined ? { envFile: opts.envFile } : {}),
      precondition: opts.precondition,
      operationId,
    });
  } catch (error) {
    if (opts.allowUnavailable && isCoreUnreachable(error)) {
      step(`deployment layer: core is not reachable; deployment succeeded and sync is deferred until the next up`);
      return;
    }
    throw new CliError(`could not sync deployment layer: ${errMessage(error)}`);
  }
  return deploymentLayerMutationResult(
    response,
    createHash("sha256").update(body).digest("hex"),
    "the request body",
    opts.precondition,
    operationId,
    true,
  );
}

export async function clearDeploymentLayer(opts: {
  config: QmConfig;
  configIdentity: FileIdentity;
  transport: DeploymentLayerTransport;
  configDir: string;
  precondition: DeploymentLayerPrecondition;
  envFile?: string;
  operationId?: string;
}): Promise<DeploymentLayerSyncResult> {
  validateDeploymentLayerPrecondition(opts.precondition);
  if (opts.precondition.contentHash === null) {
    throw new CliError("deployment-layer clear requires a durable precondition");
  }
  const operationId = opts.operationId ?? randomBytes(16).toString("hex");
  validateDeploymentLayerOperationId(operationId);
  let response: { status: number; body: string };
  try {
    response = await deploymentLayerRequest({
      config: opts.config,
      configIdentity: opts.configIdentity,
      configDir: opts.configDir,
      method: "DELETE",
      transport: opts.transport,
      precondition: opts.precondition,
      operationId,
      ...(opts.envFile !== undefined ? { envFile: opts.envFile } : {}),
    });
  } catch (error) {
    throw new CliError(`could not clear deployment layer: ${errMessage(error)}`);
  }
  return deploymentLayerMutationResult(
    response,
    opts.precondition.contentHash,
    "the rollback precondition",
    opts.precondition,
    operationId,
    false,
  );
}
