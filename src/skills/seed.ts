import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  type BigIntStats,
} from "node:fs";
import { join, relative, sep } from "node:path";
import type { ScopeId } from "../types.ts";
import { createKeyedQueue } from "../util/async.ts";
import { parseSeedSkillFrontmatter } from "./frontmatter.ts";
import { safeSkillFilePath, type Skill, type SkillFile, type SkillManifest, type SkillStore } from "./skill-store.ts";

export interface SeedInstallResult {
  installed: string[];
  updated: string[];
  skipped: string[];
}

export function isProbablyBinary(bytes: Buffer): boolean {
  if (bytes.includes(0)) return true;
  return !Buffer.from(bytes.toString("utf8"), "utf8").equals(bytes);
}

function canonicalFilesKey(files: SkillFile[] | undefined): string {
  return [...(files ?? [])]
    .map((f) => `${f.path}\0${f.content}\0${f.executable === true ? "1" : "0"}`)
    .sort()
    .join("");
}

interface OpenPath {
  fd: number;
  path: string;
  stat: BigIntStats;
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertOpenPath(opened: OpenPath, kind: "directory" | "file"): void {
  const current = lstatSync(opened.path, { bigint: true, throwIfNoEntry: false });
  const correctKind = kind === "directory" ? current?.isDirectory() : current?.isFile();
  if (!current || !correctKind || !sameFile(current, opened.stat)) {
    throw new Error(`skills-seed: ${opened.path} changed while it was being read`);
  }
}

function openPath(path: string, kind: "directory" | "file"): OpenPath | undefined {
  const before = lstatSync(path, { bigint: true, throwIfNoEntry: false });
  const correctKind = kind === "directory" ? before?.isDirectory() : before?.isFile();
  if (!before || !correctKind) return undefined;
  const flags = constants.O_RDONLY | constants.O_NOFOLLOW | (kind === "directory" ? constants.O_DIRECTORY : 0);
  const fd = openSync(path, flags);
  try {
    const opened = fstatSync(fd, { bigint: true });
    const openedKind = kind === "directory" ? opened.isDirectory() : opened.isFile();
    if (!openedKind || !sameFile(before, opened)) {
      throw new Error(`skills-seed: ${path} changed while it was being opened`);
    }
    return { fd, path, stat: opened };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function directoryEntries(dir: OpenPath): string[] {
  assertOpenPath(dir, "directory");
  const entries = readdirSync(dir.path).sort();
  assertOpenPath(dir, "directory");
  return entries;
}

function readOpenFile(file: OpenPath, parent: OpenPath): Buffer {
  assertOpenPath(parent, "directory");
  assertOpenPath(file, "file");
  const bytes = readFileSync(file.fd);
  assertOpenPath(file, "file");
  assertOpenPath(parent, "directory");
  return bytes;
}

export function sameManifest(a: SkillManifest, b: SkillManifest): boolean {
  return (
    a.description === b.description &&
    a.body === b.body &&
    [...a.requiredCapabilities].sort().join("\0") === [...b.requiredCapabilities].sort().join("\0") &&
    canonicalFilesKey(a.files) === canonicalFilesKey(b.files)
  );
}

function readSkillFiles(skillDir: OpenPath): SkillFile[] {
  const out: SkillFile[] = [];
  const walk = (dir: OpenPath): void => {
    for (const name of directoryEntries(dir)) {
      const child = join(dir.path, name);
      const st = lstatSync(child, { bigint: true });
      if (st.isSymbolicLink()) {
        console.warn(`skills-seed: skipping symlink asset ${relative(skillDir.path, child)} (not materialized)`);
        continue;
      }
      if (st.isDirectory()) {
        const childDir = openPath(child, "directory");
        if (!childDir) throw new Error(`skills-seed: ${child} changed while it was being opened`);
        try {
          assertOpenPath(dir, "directory");
          walk(childDir);
        } finally {
          closeSync(childDir.fd);
        }
        assertOpenPath(dir, "directory");
        continue;
      }
      if (!st.isFile()) continue;
      const rel = relative(skillDir.path, child).split(sep).join("/");
      if (rel === "SKILL.md") continue;
      const safe = safeSkillFilePath(rel);
      const file = openPath(child, "file");
      if (!file) throw new Error(`skills-seed: ${child} changed while it was being opened`);
      let bytes: Buffer;
      try {
        assertOpenPath(dir, "directory");
        bytes = readOpenFile(file, dir);
      } finally {
        closeSync(file.fd);
      }
      if (isProbablyBinary(bytes)) {
        console.warn(`skills-seed: skipping binary asset ${safe} (v1 stores text only)`);
        continue;
      }
      out.push({ path: safe, content: bytes.toString("utf8"), executable: (file.stat.mode & 0o111n) !== 0n });
    }
  };
  walk(skillDir);
  return out.sort((a, b) => {
    if (a.path < b.path) return -1;
    if (a.path > b.path) return 1;
    return 0;
  });
}

function readSeedSkill(skillDir: OpenPath): SkillManifest | undefined {
  const skillPath = join(skillDir.path, "SKILL.md");
  const skillFile = openPath(skillPath, "file");
  if (!skillFile) return undefined;
  let raw: Buffer;
  try {
    raw = readOpenFile(skillFile, skillDir);
  } finally {
    closeSync(skillFile.fd);
  }
  const manifest = parseSeedSkill(raw.toString("utf8"));
  manifest.files = readSkillFiles(skillDir);
  assertOpenPath(skillDir, "directory");
  return manifest;
}

export function parseSeedSkill(raw: string): SkillManifest {
  return parseSeedSkillFrontmatter(raw);
}

export type UpsertOutcome = "installed" | "updated" | "skipped" | "foreign";

function foreignSkillCollision(all: Skill[], scopeId: ScopeId, name: string, createdBy: string): Skill | undefined {
  return all.find(
    (s) => s.scopeId === scopeId && s.manifest.name === name && s.createdBy !== createdBy && s.status !== "archived",
  );
}

const upsertQueue = createKeyedQueue<string>();

export function upsertSeedSkill(
  skills: SkillStore,
  input: { scopeId: ScopeId; manifest: SkillManifest; createdBy: string; reviewer: string; pack?: Skill["pack"] },
): Promise<UpsertOutcome> {
  return upsertQueue(`${input.scopeId}\0${input.manifest.name}`, () => upsertSeedSkillUnsafe(skills, input));
}

async function upsertSeedSkillUnsafe(
  skills: SkillStore,
  input: { scopeId: ScopeId; manifest: SkillManifest; createdBy: string; reviewer: string; pack?: Skill["pack"] },
): Promise<UpsertOutcome> {
  const { scopeId, manifest, createdBy, reviewer, pack } = input;
  const all = await skills.list();
  const existing = all.find(
    (s) => s.scopeId === scopeId && s.manifest.name === manifest.name && s.createdBy === createdBy,
  );
  if (!existing && foreignSkillCollision(all, scopeId, manifest.name, createdBy)) return "foreign";
  if (existing) {
    const changed = !sameManifest(existing.manifest, manifest);
    if (!changed && existing.status === "published") return "skipped";
    if (changed) await skills.update(existing.id, manifest);
    await skills.review(existing.id, reviewer, manifest.requiredCapabilities);
    await skills.publish(existing.id);
    return "updated";
  }
  const skill = await skills.create({ scopeId, manifest, createdBy, ...(pack ? { pack } : {}) });
  await skills.review(skill.id, reviewer, manifest.requiredCapabilities);
  await skills.publish(skill.id);
  return "installed";
}

export async function installSeedSkills(
  skills: SkillStore,
  opts: { dir: string; scopeId: ScopeId; createdBy?: string; reviewer?: string },
): Promise<SeedInstallResult> {
  const createdBy = opts.createdBy ?? "system:skills-seed";
  const reviewer = opts.reviewer ?? "system:skills-reviewer";
  const result: SeedInstallResult = { installed: [], updated: [], skipped: [] };
  const seedDir = openPath(opts.dir, "directory");
  if (!seedDir) return result;

  try {
    for (const entry of directoryEntries(seedDir)) {
      const skillDir = openPath(join(seedDir.path, entry), "directory");
      if (!skillDir) continue;
      let manifest: SkillManifest | undefined;
      try {
        assertOpenPath(seedDir, "directory");
        manifest = readSeedSkill(skillDir);
        assertOpenPath(seedDir, "directory");
      } finally {
        closeSync(skillDir.fd);
      }
      if (!manifest) continue;
      const outcome = await upsertSeedSkill(skills, { scopeId: opts.scopeId, manifest, createdBy, reviewer });
      result[outcome === "foreign" ? "skipped" : outcome].push(manifest.name);
    }
  } finally {
    closeSync(seedDir.fd);
  }

  return result;
}
