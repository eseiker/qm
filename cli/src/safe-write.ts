import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readlinkSync,
  readSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  type BigIntStats,
} from "node:fs";
import { basename, dirname, isAbsolute, join, parse, resolve, sep } from "node:path";
import { CliError } from "./log.ts";

interface FileIdentity {
  dev: bigint;
  ino: bigint;
}

interface HeldDirectory {
  childUid?: bigint;
  descriptor: number;
  identity: FileIdentity;
  kind: "ancestor" | "output";
  path: string;
}

interface HeldSymlink extends FileIdentity {
  path: string;
  target: string;
  uid: bigint;
}

interface RenderedRoot {
  basePath: string;
  directories: HeldDirectory[];
  rootDescriptor: number;
  symlinks: HeldSymlink[];
}

interface SymlinkResolution {
  canonical: string;
  symlinks: HeldSymlink[];
}

interface RenderedPath {
  abs: string;
  assertCurrent(): void;
  parentDescriptor: number;
  rel: string;
}

interface FileSnapshot extends FileIdentity {
  content: string;
  extendedMetadata: string;
  gid: number;
  inodeMetadata: string;
  mode: number;
  uid: number;
}

interface SecureRenderedWriteCapabilities {
  directory: number | undefined;
  noFollow: number | undefined;
  nonblock: number | undefined;
  platform: string;
  effectiveUid: bigint | undefined;
}

export function renderedWriteEffectiveUid(
  geteuid: (() => number) | undefined,
  getuid: (() => number) | undefined,
): bigint | undefined {
  const uid = geteuid ?? getuid;
  return uid ? BigInt(uid()) : undefined;
}

const currentUid = renderedWriteEffectiveUid(process.geteuid, process.getuid);
const MAX_RENDERED_FILE_BYTES = 1_048_576;

export function secureRenderedWritesSupported(capabilities: SecureRenderedWriteCapabilities): boolean {
  return (
    (capabilities.platform === "darwin" || capabilities.platform === "linux") &&
    capabilities.effectiveUid !== undefined &&
    Number.isInteger(capabilities.directory) &&
    capabilities.directory! > 0 &&
    Number.isInteger(capabilities.noFollow) &&
    capabilities.noFollow! > 0 &&
    Number.isInteger(capabilities.nonblock) &&
    capabilities.nonblock! > 0
  );
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function ownedByCurrentUser(entry: BigIntStats): boolean {
  return currentUid !== undefined && entry.uid === currentUid;
}

function ownedByTrustedUser(entry: BigIntStats): boolean {
  return entry.uid === 0n || ownedByCurrentUser(entry);
}

function safeDirectory(entry: BigIntStats, expected?: FileIdentity): boolean {
  return (
    entry.isDirectory() &&
    !entry.isSymbolicLink() &&
    ownedByCurrentUser(entry) &&
    (entry.mode & 0o022n) === 0n &&
    (entry.mode & 0o300n) === 0o300n &&
    (expected === undefined || sameIdentity(entry, expected))
  );
}

function safeAncestor(entry: BigIntStats, childUid: bigint | undefined, expected?: FileIdentity): boolean {
  if (
    !entry.isDirectory() ||
    entry.isSymbolicLink() ||
    !ownedByTrustedUser(entry) ||
    (expected !== undefined && !sameIdentity(entry, expected))
  ) {
    return false;
  }
  if ((entry.mode & 0o022n) === 0n) return true;
  return (entry.mode & 0o1000n) !== 0n && currentUid !== undefined && childUid === currentUid;
}

function safeFile(entry: BigIntStats, expected?: FileIdentity): boolean {
  return (
    entry.isFile() &&
    !entry.isSymbolicLink() &&
    entry.nlink === 1n &&
    ownedByCurrentUser(entry) &&
    (entry.mode & 0o200n) !== 0n &&
    (entry.mode & 0o7022n) === 0n &&
    (expected === undefined || sameIdentity(entry, expected))
  );
}

function safeSymlink(entry: BigIntStats, expected?: HeldSymlink): boolean {
  return (
    entry.isSymbolicLink() &&
    ownedByTrustedUser(entry) &&
    (expected === undefined ||
      (sameIdentity(entry, expected) && entry.uid === expected.uid && readlinkSync(expected.path) === expected.target))
  );
}

function trustedSystemExecutable(candidates: readonly string[], requirement: string): string {
  for (const candidate of candidates) {
    try {
      const source = realpathSync(candidate);
      const executable = lstatSync(source, { bigint: true });
      if (
        !executable.isFile() ||
        executable.isSymbolicLink() ||
        executable.uid !== 0n ||
        (executable.mode & 0o111n) === 0n ||
        (executable.mode & 0o022n) !== 0n
      ) {
        continue;
      }
      const paths = ancestorPaths(dirname(source));
      if (
        paths.some((path) => {
          const entry = lstatSync(path, { bigint: true });
          return !entry.isDirectory() || entry.isSymbolicLink() || entry.uid !== 0n || (entry.mode & 0o022n) !== 0n;
        })
      ) {
        continue;
      }
      return source;
    } catch {
      continue;
    }
  }
  throw new CliError(requirement);
}

function trustedLinuxAclInspector(): string {
  return trustedSystemExecutable(
    ["/usr/bin/getfacl", "/bin/getfacl"],
    "secure rendered output writes on Linux require trusted getfacl from the acl package",
  );
}

function assertFilesystemAcls(paths: readonly string[], subject: string): void {
  if (paths.length === 0) return;
  if (process.platform === "linux") {
    let output: string;
    try {
      output = execFileSync(
        trustedLinuxAclInspector(),
        ["-P", "-s", "-c", "-n", "--absolute-names", "--", ...new Set(paths)],
        {
          encoding: "utf8",
          env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
        },
      );
    } catch (error) {
      if (error instanceof CliError) throw error;
      throw new CliError(`could not verify ${subject} ACLs`, { cause: error });
    }
    if (output.trim() !== "") throw new CliError(`${subject} must not have ACLs`);
    return;
  }
  if (process.platform !== "darwin") return;
  let output: string;
  try {
    output = execFileSync("/bin/ls", ["-lden", "--", ...new Set(paths)], {
      encoding: "utf8",
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    });
  } catch (error) {
    throw new CliError(`could not verify ${subject} ACLs`, { cause: error });
  }
  if (output.split("\n").some((line) => /^\s*\d+:/u.test(line))) {
    throw new CliError(`${subject} must not have ACLs`);
  }
}

function extendedMetadata(path: string, rel: string): string {
  let executable: string;
  let args: string[];
  if (process.platform === "darwin") {
    executable = trustedSystemExecutable(
      ["/usr/bin/xattr"],
      "secure rendered output writes on macOS require trusted /usr/bin/xattr",
    );
    args = ["-lx", "--", path];
  } else if (process.platform === "linux") {
    executable = trustedSystemExecutable(
      ["/usr/bin/getfattr", "/bin/getfattr"],
      "secure rendered output writes on Linux require trusted getfattr from the attr package",
    );
    args = ["-h", "-d", "-m", "-", "-e", "hex", "--absolute-names", "--", path];
  } else {
    throw new CliError("secure rendered output writes require supported extended-metadata inspection");
  }
  try {
    const output = execFileSync(executable, args, {
      encoding: "utf8",
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    });
    return process.platform === "linux"
      ? output
          .split("\n")
          .filter((line) => !line.startsWith("# file:"))
          .join("\n")
          .trim()
      : output.trimEnd();
  } catch (error) {
    throw new CliError(`could not verify ${rel} extended metadata`, { cause: error });
  }
}

function inodeMetadata(path: string, rel: string): string {
  let executable: string;
  let args: string[];
  if (process.platform === "darwin") {
    executable = trustedSystemExecutable(
      ["/usr/bin/stat"],
      "secure rendered output writes on macOS require trusted /usr/bin/stat",
    );
    args = ["-f", "%f", "--", path];
  } else if (process.platform === "linux") {
    executable = trustedSystemExecutable(
      ["/usr/bin/lsattr", "/bin/lsattr"],
      "secure rendered output writes on Linux require trusted lsattr from the e2fsprogs package",
    );
    args = ["-p", "-d", "--", path];
  } else {
    throw new CliError("secure rendered output writes require supported file-flag inspection");
  }
  try {
    const output = execFileSync(executable, args, {
      encoding: "utf8",
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    }).trim();
    if (process.platform !== "linux") return output;
    const [projectId, flags] = output.split(/\s+/u);
    if (!/^\d+$/u.test(projectId ?? "") || !/^[A-Za-z-]+$/u.test(flags ?? "")) {
      throw new Error("unexpected lsattr output");
    }
    return `${projectId}:${flags}`;
  } catch (error) {
    throw new CliError(`could not verify ${rel} inode metadata`, { cause: error });
  }
}

function assertSupportedPlatform(): void {
  if (
    !secureRenderedWritesSupported({
      directory: constants.O_DIRECTORY,
      noFollow: constants.O_NOFOLLOW,
      nonblock: constants.O_NONBLOCK,
      platform: process.platform,
      effectiveUid: currentUid,
    })
  ) {
    throw new CliError("secure rendered output writes require POSIX no-follow filesystem operations");
  }
}

function ancestorPaths(path: string): string[] {
  const paths: string[] = [];
  let current = path;
  for (;;) {
    paths.push(current);
    const parent = dirname(current);
    if (parent === current) return paths.reverse();
    current = parent;
  }
}

function absolutePathParts(path: string): { root: string; segments: string[] } {
  const root = parse(path).root;
  return { root, segments: path.slice(root.length).split(sep).filter(Boolean) };
}

function resolveSymlinkChain(path: string): SymlinkResolution {
  const initial = absolutePathParts(path);
  let current = initial.root;
  const pending = initial.segments;
  const symlinks: HeldSymlink[] = [];
  while (pending.length > 0) {
    const segment = pending.shift()!;
    const candidate = join(current, segment);
    const entry = lstatSync(candidate, { bigint: true });
    if (!entry.isSymbolicLink()) {
      current = candidate;
      continue;
    }
    if (symlinks.length === 40) throw new CliError(`${path} has an unsafe mutation-controlling ancestor`);
    const target = readlinkSync(candidate);
    symlinks.push({ dev: entry.dev, ino: entry.ino, path: candidate, target, uid: entry.uid });
    const expanded = absolutePathParts(isAbsolute(target) ? resolve(target) : resolve(current, target));
    current = expanded.root;
    pending.unshift(...expanded.segments);
  }
  return { canonical: current, symlinks };
}

function closeDirectories(directories: readonly HeldDirectory[]): void {
  for (const directory of directories.toReversed()) closeSync(directory.descriptor);
}

function holdSymlinkController(root: RenderedRoot, symlink: HeldSymlink, requested: string): void {
  const paths = ancestorPaths(dirname(symlink.path));
  for (const [index, currentPath] of paths.entries()) {
    const descriptor = openSync(currentPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    let retained = false;
    try {
      const opened = fstatSync(descriptor, { bigint: true });
      const current = lstatSync(currentPath, { bigint: true });
      const childPath = index === paths.length - 1 ? symlink.path : paths[index + 1]!;
      const child = lstatSync(childPath, { bigint: true });
      if (
        !(child.isDirectory() || child.isSymbolicLink()) ||
        !safeAncestor(opened, child.uid) ||
        !safeAncestor(current, child.uid) ||
        !sameIdentity(opened, current)
      ) {
        throw new CliError(`${requested} has an unsafe mutation-controlling ancestor`);
      }
      root.directories.push({
        childUid: child.uid,
        descriptor,
        identity: { dev: opened.dev, ino: opened.ino },
        kind: "ancestor",
        path: currentPath,
      });
      retained = true;
    } finally {
      if (!retained) closeSync(descriptor);
    }
  }
  const current = lstatSync(symlink.path, { bigint: true });
  if (!safeSymlink(current, symlink)) {
    throw new CliError(`${requested} has an unsafe mutation-controlling ancestor`);
  }
  root.symlinks.push(symlink);
}

function appendPathChain(
  root: RenderedRoot,
  paths: readonly string[],
  requested: string,
  requestedEntry: BigIntStats,
): HeldDirectory {
  let outputDirectory: HeldDirectory | undefined;
  for (const [index, currentPath] of paths.entries()) {
    const current = lstatSync(currentPath, { bigint: true });
    const output = index === paths.length - 1;
    if (current.isSymbolicLink()) {
      if (output || !safeSymlink(current)) {
        throw new CliError(`${requested} has an unsafe mutation-controlling ancestor`);
      }
      root.symlinks.push({
        dev: current.dev,
        ino: current.ino,
        path: currentPath,
        target: readlinkSync(currentPath),
        uid: current.uid,
      });
      continue;
    }
    const descriptor = openSync(currentPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    let retained = false;
    try {
      const opened = fstatSync(descriptor, { bigint: true });
      const verified = lstatSync(currentPath, { bigint: true });
      const child = output ? undefined : lstatSync(paths[index + 1]!, { bigint: true });
      const childIsTraversable = child !== undefined && (child.isDirectory() || child.isSymbolicLink());
      const safe = output
        ? safeDirectory(opened) &&
          safeDirectory(verified) &&
          sameIdentity(requestedEntry, opened) &&
          sameIdentity(opened, verified)
        : childIsTraversable &&
          safeAncestor(opened, child?.uid) &&
          safeAncestor(verified, child?.uid) &&
          sameIdentity(opened, verified);
      if (!safe) throw new CliError(`${requested} has an unsafe mutation-controlling ancestor`);
      const held: HeldDirectory = {
        ...(child ? { childUid: child.uid } : {}),
        descriptor,
        identity: { dev: opened.dev, ino: opened.ino },
        kind: output ? "output" : "ancestor",
        path: currentPath,
      };
      root.directories.push(held);
      if (output) outputDirectory = held;
      retained = true;
    } finally {
      if (!retained) closeSync(descriptor);
    }
  }
  if (!outputDirectory) throw new CliError(`${requested} has an unsafe mutation-controlling ancestor`);
  return outputDirectory;
}

function assertDirectoriesCurrent(directories: readonly HeldDirectory[], rel: string): void {
  try {
    for (const directory of directories) {
      const opened = fstatSync(directory.descriptor, { bigint: true });
      const current = lstatSync(directory.path, { bigint: true });
      const safe =
        directory.kind === "output"
          ? safeDirectory(opened, directory.identity) && safeDirectory(current, directory.identity)
          : safeAncestor(opened, directory.childUid, directory.identity) &&
            safeAncestor(current, directory.childUid, directory.identity);
      if (!safe) throw new CliError(`${rel} changed parent directories while it was being rendered`);
    }
    assertFilesystemAcls(
      directories.map((directory) => directory.path),
      "rendered output directories",
    );
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(`${rel} changed parent directories while it was being rendered`, { cause: error });
  }
}

function assertSymlinksCurrent(symlinks: readonly HeldSymlink[], rel: string): void {
  try {
    for (const symlink of symlinks) {
      const current = lstatSync(symlink.path, { bigint: true });
      if (!safeSymlink(current, symlink)) {
        throw new CliError(`${rel} changed parent directories while it was being rendered`);
      }
    }
    assertFilesystemAcls(
      symlinks.map((symlink) => symlink.path),
      "rendered output mutation-controlling symlinks",
    );
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(`${rel} changed parent directories while it was being rendered`, { cause: error });
  }
}

function assertRootCurrent(root: RenderedRoot, rel: string): void {
  assertDirectoriesCurrent(root.directories, rel);
  assertSymlinksCurrent(root.symlinks, rel);
}

function openRoot(configDir: string): RenderedRoot {
  assertSupportedPlatform();
  const requested = resolve(configDir);
  let requestedEntry: BigIntStats;
  try {
    requestedEntry = lstatSync(requested, { bigint: true });
  } catch (error) {
    throw new CliError(`${requested} is not a safe rendered output directory`, { cause: error });
  }
  if (!safeDirectory(requestedEntry)) {
    throw new CliError(`${requested} is not a safe rendered output directory`);
  }
  const root: RenderedRoot = { basePath: requested, directories: [], rootDescriptor: -1, symlinks: [] };
  try {
    const resolution = resolveSymlinkChain(requested);
    for (const symlink of resolution.symlinks) holdSymlinkController(root, symlink, requested);
    const lexicalRoot = appendPathChain(root, ancestorPaths(requested), requested, requestedEntry);
    const canonical = realpathSync(requested);
    const resolvedEntry = lstatSync(resolution.canonical, { bigint: true });
    const canonicalEntry = lstatSync(canonical, { bigint: true });
    if (!sameIdentity(resolvedEntry, canonicalEntry)) {
      throw new CliError(`${requested} changed while its symlink chain was being resolved`);
    }
    const canonicalRoot =
      canonical === requested
        ? lexicalRoot
        : appendPathChain(root, ancestorPaths(canonical), requested, requestedEntry);
    root.basePath = canonical;
    root.rootDescriptor = canonicalRoot.descriptor;
    assertRootCurrent(root, requested);
    return root;
  } catch (error) {
    closeDirectories(root.directories);
    if (error instanceof CliError) throw error;
    throw new CliError(`${requested} has an unsafe mutation-controlling ancestor`, { cause: error });
  }
}

function openChildDirectory(parent: string, segment: string, rel: string): HeldDirectory {
  const path = join(parent, segment);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor, { bigint: true });
    const current = lstatSync(path, { bigint: true });
    if (!safeDirectory(opened) || !safeDirectory(current) || !sameIdentity(opened, current)) {
      throw new CliError(`${rel} has an unsafe parent directory`);
    }
    assertFilesystemAcls([path], "rendered output directories");
    return { descriptor, identity: { dev: opened.dev, ino: opened.ino }, kind: "output", path };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error instanceof CliError) throw error;
    throw new CliError(`${rel} has an unsafe parent directory`, { cause: error });
  }
}

function validSegments(segments: readonly string[]): boolean {
  return (
    segments.length > 0 &&
    segments.every(
      (segment) =>
        segment !== "" &&
        segment !== "." &&
        segment !== ".." &&
        !isAbsolute(segment) &&
        !segment.includes("/") &&
        !segment.includes("\\"),
    )
  );
}

function withRenderedPaths<T>(
  configDir: string,
  segmentSets: readonly (readonly string[])[],
  fn: (paths: readonly RenderedPath[]) => T,
): T {
  if (segmentSets.length === 0 || segmentSets.some((segments) => !validSegments(segments))) {
    throw new CliError("invalid rendered output path");
  }
  const root = openRoot(configDir);
  const descendants = new Map<string, HeldDirectory>();
  try {
    const paths = segmentSets.map((segments) => {
      const rel = segments.join("/");
      let parentPath = root.basePath;
      let parentDescriptor = root.rootDescriptor;
      for (const segment of segments.slice(0, -1)) {
        const childPath = join(parentPath, segment);
        let child = descendants.get(childPath);
        if (!child) {
          child = openChildDirectory(parentPath, segment, rel);
          descendants.set(childPath, child);
          root.directories.push(child);
        }
        parentPath = child.path;
        parentDescriptor = child.descriptor;
      }
      const assertCurrent = (): void => assertRootCurrent(root, rel);
      return {
        abs: join(parentPath, segments.at(-1)!),
        assertCurrent,
        parentDescriptor,
        rel,
      };
    });
    for (const path of paths) path.assertCurrent();
    return fn(paths);
  } finally {
    closeDirectories(root.directories);
  }
}

function withRenderedPath<T>(configDir: string, segments: readonly string[], fn: (path: RenderedPath) => T): T {
  return withRenderedPaths(configDir, [segments], ([path]) => fn(path!));
}

function assertFileCurrent(path: string, descriptor: number, identity: FileIdentity, rel: string): BigIntStats {
  let opened: BigIntStats;
  let current: BigIntStats;
  try {
    opened = fstatSync(descriptor, { bigint: true });
    current = lstatSync(path, { bigint: true });
  } catch (error) {
    throw new CliError(`${rel} is not a safe rendered output file`, { cause: error });
  }
  if (!safeFile(opened, identity) || !safeFile(current, identity) || !sameIdentity(opened, current)) {
    throw new CliError(`${rel} is not a safe rendered output file`);
  }
  return opened;
}

function readBoundedContent(descriptor: number, size: bigint, rel: string): string {
  if (size > BigInt(MAX_RENDERED_FILE_BYTES)) {
    throw new CliError(`${rel} exceeds the ${MAX_RENDERED_FILE_BYTES}-byte rendered file limit`);
  }
  const bytes = Buffer.allocUnsafe(MAX_RENDERED_FILE_BYTES + 1);
  let length = 0;
  for (;;) {
    const read = readSync(descriptor, bytes, length, bytes.length - length, length);
    if (read === 0) break;
    length += read;
    if (length > MAX_RENDERED_FILE_BYTES) {
      throw new CliError(`${rel} exceeds the ${MAX_RENDERED_FILE_BYTES}-byte rendered file limit`);
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length));
  } catch (error) {
    throw new CliError(`${rel} must contain valid UTF-8 text`, { cause: error });
  }
}

function sameFileMetadata(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.size === right.size &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function readSnapshot(path: RenderedPath): FileSnapshot | undefined {
  path.assertCurrent();
  let descriptor: number;
  try {
    descriptor = openSync(path.abs, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      path.assertCurrent();
      return undefined;
    }
    throw new CliError(`${path.rel} is not a safe rendered output file`, { cause: error });
  }
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    const identity = { dev: opened.dev, ino: opened.ino };
    const current = assertFileCurrent(path.abs, descriptor, identity, path.rel);
    assertFilesystemAcls([path.abs], "rendered output files");
    const metadata = extendedMetadata(path.abs, path.rel);
    const inode = inodeMetadata(path.abs, path.rel);
    const content = readBoundedContent(descriptor, current.size, path.rel);
    const verified = assertFileCurrent(path.abs, descriptor, identity, path.rel);
    if (
      !sameFileMetadata(current, verified) ||
      extendedMetadata(path.abs, path.rel) !== metadata ||
      inodeMetadata(path.abs, path.rel) !== inode
    ) {
      throw new CliError(`${path.rel} changed while it was being read`);
    }
    assertFilesystemAcls([path.abs], "rendered output files");
    return {
      ...identity,
      content,
      extendedMetadata: metadata,
      gid: Number(current.gid),
      inodeMetadata: inode,
      mode: Number(current.mode & 0o7777n),
      uid: Number(current.uid),
    };
  } finally {
    closeSync(descriptor);
  }
}

function assertSnapshotCurrent(path: RenderedPath, snapshot: FileSnapshot | undefined): void {
  path.assertCurrent();
  if (!snapshot) {
    try {
      lstatSync(path.abs);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw new CliError(`${path.rel} changed while it was being rendered`, { cause: error });
    }
    throw new CliError(`${path.rel} changed while it was being rendered`);
  }
  const current = readSnapshot(path);
  if (
    !current ||
    !sameIdentity(current, snapshot) ||
    current.uid !== snapshot.uid ||
    current.gid !== snapshot.gid ||
    current.mode !== snapshot.mode ||
    current.extendedMetadata !== snapshot.extendedMetadata ||
    current.inodeMetadata !== snapshot.inodeMetadata ||
    current.content !== snapshot.content
  ) {
    throw new CliError(`${path.rel} changed while it was being rendered`);
  }
}

function normalizePermissions(descriptor: number, mode: number): void {
  if (process.platform === "darwin") {
    execFileSync("/bin/chmod", ["-N", "/dev/fd/3"], {
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
      stdio: ["ignore", "ignore", "ignore", descriptor],
    });
  }
  fchmodSync(descriptor, mode);
}

function encodedContent(content: string, rel: string): Buffer {
  if (!content.isWellFormed()) throw new CliError(`${rel} must contain valid UTF-8 text`);
  const encoded = Buffer.from(content, "utf8");
  if (encoded.length > MAX_RENDERED_FILE_BYTES) {
    throw new CliError(`${rel} exceeds the ${MAX_RENDERED_FILE_BYTES}-byte rendered file limit`);
  }
  return encoded;
}

function removeTemporary(path: string, identity: FileIdentity | undefined): void {
  if (!identity) return;
  let current: BigIntStats;
  try {
    current = lstatSync(path, { bigint: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (
    !current.isFile() ||
    current.isSymbolicLink() ||
    current.nlink !== 1n ||
    !ownedByCurrentUser(current) ||
    !sameIdentity(current, identity)
  ) {
    throw new CliError("rendered output temporary file changed before cleanup");
  }
  unlinkSync(path);
}

function install(
  path: RenderedPath,
  snapshot: FileSnapshot | undefined,
  content: string,
  newMode: number,
  validateDependencies?: () => void,
): void {
  path.assertCurrent();
  const bytes = encodedContent(content, path.rel);
  const mode = snapshot?.mode ?? newMode;
  const temporary = join(dirname(path.abs), `.${basename(path.abs)}.${randomUUID()}.tmp`);
  let committed = false;
  let descriptor: number | undefined;
  let identity: FileIdentity | undefined;
  try {
    descriptor = openSync(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      mode,
    );
    const opened = fstatSync(descriptor, { bigint: true });
    identity = { dev: opened.dev, ino: opened.ino };
    if (snapshot) fchownSync(descriptor, snapshot.uid, snapshot.gid);
    normalizePermissions(descriptor, mode);
    assertFilesystemAcls([temporary], "rendered output temporary files");
    if (snapshot && extendedMetadata(temporary, `${path.rel} temporary file`) !== snapshot.extendedMetadata) {
      throw new CliError(`${path.rel} extended metadata could not be preserved`);
    }
    if (snapshot && inodeMetadata(temporary, `${path.rel} temporary file`) !== snapshot.inodeMetadata) {
      throw new CliError(`${path.rel} inode metadata could not be preserved`);
    }
    const prepared = assertFileCurrent(temporary, descriptor, identity, `${path.rel} temporary file`);
    if (
      Number(prepared.uid) !== (snapshot?.uid ?? Number(opened.uid)) ||
      Number(prepared.gid) !== (snapshot?.gid ?? Number(opened.gid)) ||
      Number(prepared.mode & 0o7777n) !== mode
    ) {
      throw new CliError(`${path.rel} temporary file metadata could not be preserved`);
    }
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
    assertFileCurrent(temporary, descriptor, identity, `${path.rel} temporary file`);
    if (validateDependencies) validateDependencies();
    assertSnapshotCurrent(path, snapshot);
    path.assertCurrent();
    renameSync(temporary, path.abs);
    committed = true;
    assertFileCurrent(path.abs, descriptor, identity, path.rel);
    path.assertCurrent();
    fsyncSync(path.parentDescriptor);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (!committed) removeTemporary(temporary, identity);
  }
}

export function readRenderedFile(configDir: string, segments: readonly string[]): string | undefined {
  return withRenderedPath(configDir, segments, (path) => readSnapshot(path)?.content);
}

export function writeRenderedFile(configDir: string, segments: readonly string[], content: string, mode = 0o644): void {
  withRenderedPath(configDir, segments, (path) => install(path, readSnapshot(path), content, mode));
}

export function updateRenderedFile(
  configDir: string,
  segments: readonly string[],
  update: (existing: string, dependencies: ReadonlyMap<string, string | undefined>) => string,
  dependencySegments: readonly (readonly string[])[] = [],
): boolean {
  return withRenderedPaths(configDir, [segments, ...dependencySegments], ([path, ...dependencies]) => {
    const snapshot = readSnapshot(path!);
    if (!snapshot) return false;
    const dependencySnapshots = dependencies.map((dependency) => [dependency, readSnapshot(dependency)] as const);
    const dependencyContents = new Map(
      dependencySnapshots.map(([dependency, dependencySnapshot]) => [dependency.rel, dependencySnapshot?.content]),
    );
    install(path!, snapshot, update(snapshot.content, dependencyContents), snapshot.mode, () => {
      for (const [dependency, dependencySnapshot] of dependencySnapshots) {
        assertSnapshotCurrent(dependency, dependencySnapshot);
      }
    });
    return true;
  });
}

export function removeRenderedFile(configDir: string, segments: readonly string[]): boolean {
  return withRenderedPath(configDir, segments, (path) => {
    const snapshot = readSnapshot(path);
    if (!snapshot) return false;
    assertSnapshotCurrent(path, snapshot);
    path.assertCurrent();
    unlinkSync(path.abs);
    path.assertCurrent();
    fsyncSync(path.parentDescriptor);
    return true;
  });
}
