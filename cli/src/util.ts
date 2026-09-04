import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createECDH, createPrivateKey, randomUUID, type JsonWebKey } from "node:crypto";
import {
  accessSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  linkSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { isIP } from "node:net";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { CliError, errMessage } from "./log.ts";

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export async function settleAll(tasks: Promise<unknown>[]): Promise<void> {
  const failures = (await Promise.allSettled(tasks)).filter((r): r is PromiseRejectedResult => r.status === "rejected");
  if (failures.length) throw new CliError(failures.map((f) => errMessage(f.reason)).join("\n\n"));
}

export function envNum(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

const procOpts = (o: { cwd?: string; env?: NodeJS.ProcessEnv }) => ({
  ...(o.cwd ? { cwd: o.cwd } : {}),
  ...(o.env ? { env: o.env } : {}),
});

async function pollUntil(cond: () => boolean, tries: number): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    if (cond()) return true;
    await sleep(1000);
  }
  return false;
}

export function capture(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv; allow?: RegExp } = {},
): string {
  try {
    return execFileSync(cmd, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      ...procOpts(opts),
    });
  } catch (e: unknown) {
    const err = e as { stdout?: string; stderr?: string; message?: string };
    const out = `${err.stdout ?? ""}${err.stderr ?? ""}`;
    if (opts.allow?.test(out)) return out;
    throw new Error(`${cmd} ${args.join(" ")} failed:\n${out || err.message}`, { cause: e });
  }
}

export function captureBoth(cmd: string, args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}): string {
  const r = spawnSync(cmd, args, {
    encoding: "utf8",
    ...procOpts(opts),
  });
  return `${r.stdout ?? ""}${r.stderr ?? ""}`;
}

export function processErrorOutput(error: unknown): string {
  const output: string[] = [];
  const seen = new Set<object>();
  let current: unknown = error;
  while (current && typeof current === "object" && !seen.has(current)) {
    seen.add(current);
    const record = current as { stdout?: unknown; stderr?: unknown; cause?: unknown };
    for (const value of [record.stdout, record.stderr]) {
      if (typeof value === "string") output.push(value);
      else if (Buffer.isBuffer(value)) output.push(value.toString("utf8"));
    }
    current = record.cause;
  }
  return output.join("\n");
}

export function processErrorMatches(error: unknown, pattern: RegExp): boolean {
  pattern.lastIndex = 0;
  const matches = pattern.test(processErrorOutput(error));
  pattern.lastIndex = 0;
  return matches;
}

export function runInherit(cmd: string, args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}): void {
  execFileSync(cmd, args, {
    stdio: "inherit",
    ...procOpts(opts),
  });
}

export function spawnBackground(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv; logFile: string },
): number {
  const fd = openSync(opts.logFile, "a");
  const child = spawn(cmd, args, {
    detached: true,
    stdio: ["ignore", fd, fd],
    ...procOpts(opts),
  });
  child.unref();
  if (child.pid === undefined) throw new Error(`failed to spawn ${cmd}`);
  return child.pid;
}

export function streamLabeled(
  procs: { label: string; command: string; args: string[]; env?: NodeJS.ProcessEnv }[],
  emit: (paddedLabel: string, line: string) => void,
): Promise<void> {
  const width = Math.max(0, ...procs.map((p) => p.label.length));
  return new Promise((resolveAll) => {
    let pending = procs.length;
    if (pending === 0) return resolveAll();
    const done = (): void => {
      if (--pending === 0) resolveAll();
    };
    for (const { label, command, args, env } of procs) {
      const tag = label.padEnd(width);
      const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], ...(env ? { env } : {}) });
      const sink = (): { push: (buf: Buffer) => void; flush: () => void } => {
        let carry = "";
        return {
          push(buf: Buffer): void {
            carry += buf.toString("utf8");
            const lines = carry.split("\n");
            carry = lines.pop() ?? "";
            for (const line of lines) emit(tag, line);
          },
          flush(): void {
            if (carry) emit(tag, carry);
            carry = "";
          },
        };
      };
      const out = sink();
      const err = sink();
      child.stdout?.on("data", (b: Buffer) => out.push(b));
      child.stderr?.on("data", (b: Buffer) => err.push(b));
      let ended = false;
      const finish = (): void => {
        if (ended) return;
        ended = true;
        out.flush();
        err.flush();
        done();
      };
      child.on("close", finish);
      child.on("error", finish);
    }
  });
}

const pidAlive = (pid: number | undefined): boolean => {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

function killTree(pid: number, sig: NodeJS.Signals): void {
  for (const target of [-pid, pid]) {
    try {
      process.kill(target, sig);
    } catch {
      void 0;
    }
  }
}

export async function stopPid(pid: number | undefined, graceSec = 5): Promise<void> {
  if (!pidAlive(pid)) return;
  killTree(pid!, "SIGTERM");
  if (await pollUntil(() => !pidAlive(pid), graceSec)) return;
  killTree(pid!, "SIGKILL");
}

export function waitForLog(file: string, pattern: RegExp, timeoutSec: number): Promise<boolean> {
  return pollUntil(() => {
    if (!existsSync(file)) return false;
    try {
      return pattern.test(readFileSync(file, "utf8"));
    } catch {
      return false;
    }
  }, timeoutSec);
}

export const tailString = (s: string, lines: number): string => s.split("\n").slice(-lines).join("\n");

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value))
    return `[${value.map((element) => (element === undefined ? "null" : canonicalJson(element))).join(",")}]`;
  if (typeof value !== "object" || value === null) return JSON.stringify(value);
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .filter((key) => object[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(",")}}`;
}

export function tail(file: string, lines = 20): string {
  if (!existsSync(file)) return "";
  return tailString(readFileSync(file, "utf8"), lines);
}

export const isEnvVarName = (name: string): boolean => /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);

export function isMissingOrPlaceholder(value: string | undefined): boolean {
  const candidate = value?.trim();
  return !candidate || /^(replace-me|placeholder|changeme|todo)$/i.test(candidate);
}

export function canonicalHttpOrigin(value: string): string | undefined {
  const match = /^(https?):\/\/([^/?#\\\s%@]+)\/?$/iu.exec(value);
  if (!match || match[2]!.endsWith(":")) return undefined;
  try {
    const parsed = new URL(value);
    if (
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash ||
      parsed.username ||
      parsed.password ||
      parsed.hostname.endsWith(".")
    ) {
      return undefined;
    }
    return parsed.origin;
  } catch {
    return undefined;
  }
}

export function isInvalidSecret(name: string, value: string | undefined): boolean {
  if (value?.includes("\0")) return true;
  if (isMissingOrPlaceholder(value)) return true;
  const candidate = value!.trim();
  if (name === "PUBLIC_API_URL") return canonicalHttpOrigin(value!) === undefined;
  if (name === "AUTH_ALLOWED_EMAILS") {
    const emails = candidate
      .split(",")
      .map((email) => email.trim())
      .filter(Boolean);
    return emails.length === 0 || emails.some((email) => isMissingOrPlaceholder(email) || !validEmail(email));
  }
  if (name === "AUTH_EMAIL_FROM") {
    return /[\p{Cc}\p{Cf}]/u.test(value!) || !validEmail(senderAddress(candidate));
  }
  if (name === "AUTH_SIGNING_JWK") {
    try {
      const key: unknown = JSON.parse(candidate);
      if (
        typeof key !== "object" ||
        key === null ||
        Array.isArray(key) ||
        (key as Record<string, unknown>).kty !== "EC" ||
        (key as Record<string, unknown>).crv !== "P-256" ||
        typeof (key as Record<string, unknown>).d !== "string" ||
        typeof (key as Record<string, unknown>).x !== "string" ||
        typeof (key as Record<string, unknown>).y !== "string"
      ) {
        return true;
      }
      const allowed = new Set(["kty", "crv", "d", "x", "y", "key_ops"]);
      if (Object.keys(key).some((name) => !allowed.has(name))) return true;
      const operations = (key as Record<string, unknown>).key_ops;
      if (
        operations !== undefined &&
        (!Array.isArray(operations) || operations.length !== 1 || operations[0] !== "sign")
      ) {
        return true;
      }
      const component = (name: "d" | "x" | "y"): Buffer => {
        const raw = (key as Record<string, string>)[name]!;
        const decoded = Buffer.from(raw, "base64url");
        if (decoded.length !== 32) throw new Error(name);
        return decoded;
      };
      const d = component("d");
      const x = component("x");
      const y = component("y");
      const ecdh = createECDH("prime256v1");
      ecdh.setPrivateKey(d);
      const point = ecdh.getPublicKey(undefined, "uncompressed");
      if (!x.equals(point.subarray(1, 33)) || !y.equals(point.subarray(33))) return true;
      const privateKey = createPrivateKey({ key: key as JsonWebKey, format: "jwk" });
      return (
        privateKey.type !== "private" ||
        privateKey.asymmetricKeyType !== "ec" ||
        privateKey.asymmetricKeyDetails?.namedCurve !== "prime256v1"
      );
    } catch {
      return true;
    }
  }
  if (name === "ADMIN_GRANTS") {
    const entries = candidate
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
    return entries.length === 0 || !entries.every((entry) => adminGrantEmail(entry) !== undefined);
  }
  return (
    (name === "CONNECTOR_SECRET_KEY" ||
      name === "CORE_SIGNING_SECRET" ||
      name === "SKILL_SIGNING_SECRET" ||
      name === "CAPABILITY_SECRET" ||
      name === "PORTAL_IDENTITY_SECRET" ||
      name === "PORTAL_SESSION_SECRET" ||
      name === "DEPLOY_APPS_SESSION_SECRET" ||
      name === "AWS_DEPLOY_GATE_SECRET" ||
      name === "AUTH_TOKEN_SECRET" ||
      name === "AUTH_CLIENT_SECRET") &&
    Buffer.byteLength(candidate, "utf8") < 32
  );
}

export function invalidSecretNames(values: ReadonlyMap<string, string | undefined>): Set<string> {
  const invalid = new Set<string>();
  for (const [name, value] of values) {
    if (isInvalidSecret(name, value)) invalid.add(name);
  }
  const distinct: readonly (readonly [string, string])[] = [
    ["CORE_SIGNING_SECRET", "CAPABILITY_SECRET"],
    ["CORE_SIGNING_SECRET", "PORTAL_IDENTITY_SECRET"],
    ["CAPABILITY_SECRET", "PORTAL_IDENTITY_SECRET"],
    ["CONNECTOR_SECRET_KEY", "CORE_SIGNING_SECRET"],
    ["CONNECTOR_SECRET_KEY", "CAPABILITY_SECRET"],
    ["CONNECTOR_SECRET_KEY", "PORTAL_IDENTITY_SECRET"],
    ["PORTAL_SESSION_SECRET", "CORE_SIGNING_SECRET"],
    ["AUTH_CLIENT_SECRET", "AUTH_TOKEN_SECRET"],
  ];
  for (const [left, right] of distinct) {
    const leftValue = values.get(left);
    const rightValue = values.get(right);
    if (leftValue && rightValue && leftValue === rightValue) {
      invalid.add(left);
      invalid.add(right);
    }
  }
  return invalid;
}

export function validEmailDomain(value: string): boolean {
  if (value.length > 252 || !value.includes(".") || isIP(value) !== 0) return false;
  return value
    .split(".")
    .every(
      (label) => label.length > 0 && label.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label),
    );
}

export function validEmail(value: string): boolean {
  const separator = value.indexOf("@");
  if (value.length > 254 || separator < 1 || separator !== value.lastIndexOf("@")) return false;
  const local = value.slice(0, separator);
  const domain = value.slice(separator + 1);
  return (
    local.length <= 64 &&
    /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/.test(local) &&
    validEmailDomain(domain)
  );
}

export function adminGrantEmail(entry: string): string | undefined {
  const normalized = entry.trim();
  const suffix = ":org_admin";
  if (!normalized.endsWith(suffix)) return undefined;
  const email = normalized.slice(0, -suffix.length);
  if (!email || /[\p{Cc}\p{Cf}:]/u.test(email) || !validEmail(email)) return undefined;
  return email;
}

export function senderAddress(from: string): string {
  const normalized = from.trim();
  if (/\p{Cc}|\p{Cf}/u.test(normalized)) return "";
  if (validEmail(normalized)) return normalized;
  const angled = /^([^<>,]+)<([^<>]+)>$/u.exec(normalized);
  if (!angled) return "";
  const display = (angled[1] ?? "").trim();
  const address = (angled[2] ?? "").trim();
  if (!display) return "";
  return validEmail(address) ? address : "";
}

export function assertNoNulSecret(name: string, value: string | undefined): void {
  if (value?.includes("\0")) throw new CliError(`${name} contains a NUL byte`);
}

export const MAX_SECRET_BYTES = 65_536;

export function assertSecretByteLength(name: string, value: string, max = MAX_SECRET_BYTES): void {
  if (Buffer.byteLength(value, "utf8") > max) {
    throw new CliError(`${name} exceeds the ${max}-byte provider limit`);
  }
}

const trimEnvSpace = (value: string): string => value.replace(/^[ \t\r]+|[ \t\r]+$/g, "");
const trimEnvSpaceStart = (value: string): string => value.replace(/^[ \t\r]+/g, "");
const trimEnvSpaceEnd = (value: string): string => value.replace(/[ \t\r]+$/g, "");
const stripEnvExport = (value: string): string => value.replace(/^export /, "");

function parseEnvLine(raw: string): [key: string, value: string] | undefined {
  let line = trimEnvSpace(raw);
  if (!line || line.startsWith("#")) return undefined;
  line = trimEnvSpaceStart(stripEnvExport(line));
  const eq = line.indexOf("=");
  if (eq <= 0) return undefined;
  const key = trimEnvSpace(line.slice(0, eq));
  let value = trimEnvSpace(line.slice(eq + 1));
  const quote = value[0];
  if (quote === '"' || quote === "'" || quote === "`") {
    const end = value.indexOf(quote, 1);
    if (end > 0) {
      value = value.slice(1, end);
      if (quote === '"') value = value.replaceAll("\\n", "\n");
    }
  } else value = trimEnvSpaceEnd(value.split("#", 1)[0]!);
  return [key, value];
}

function assertEnvFileQuotesAreSingleLine(content: string): void {
  if (content.includes("\ufeff")) {
    throw new CliError("deployment environment file must not contain a UTF-8 byte-order mark");
  }
  if (/\r(?!\n)/u.test(content)) {
    throw new CliError("deployment environment file must not contain lone carriage returns");
  }
  for (const raw of content.split("\n")) {
    const physical = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    let line = trimEnvSpace(physical);
    if (!line || line.startsWith("#")) continue;
    const exported = trimEnvSpaceStart(physical).startsWith("export ");
    line = trimEnvSpaceStart(stripEnvExport(line));
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const assignment = trimEnvSpaceStart(stripEnvExport(trimEnvSpaceStart(physical)));
    const rawValue = assignment.slice(assignment.indexOf("=") + 1);
    if ((exported && trimEnvSpace(rawValue) === "") || (rawValue !== "" && trimEnvSpace(rawValue) === "")) {
      throw new CliError("deployment environment file must not contain ambiguous empty assignments");
    }
    const value = trimEnvSpace(line.slice(eq + 1));
    const quote = value[0];
    if ((quote === '"' || quote === "'" || quote === "`") && value.indexOf(quote, 1) < 0) {
      throw new CliError("deployment environment file must not contain multiline or unclosed quoted values");
    }
  }
}

export function readEnvFile(
  path: string,
  options: { protectedIdentity?: FileIdentity; required?: boolean } = {},
): Map<string, string> {
  let descriptor: number;
  try {
    descriptor = openSync(resolve(path), constants.O_RDONLY | constants.O_NONBLOCK);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      if (options.required) throw new CliError(`--env-file not found: ${path}`, { cause: error });
      return new Map();
    }
    throw error;
  }
  let content: string;
  try {
    const snapshot = readStableDescriptor(descriptor, "deployment environment path");
    const stat = snapshot.stat;
    if (!stat.isFile()) throw new CliError("the deployment environment path must be a regular file");
    if (
      options.protectedIdentity !== undefined &&
      stat.dev === options.protectedIdentity.dev &&
      stat.ino === options.protectedIdentity.ino
    ) {
      throw new CliError("deployment environment file must be separate from the deployment config");
    }
    content = decodeEnvFileText(snapshot.content);
  } finally {
    closeSync(descriptor);
  }
  return parseEnvFileText(content);
}

function parseEnvFileText(content: string): Map<string, string> {
  const out = new Map<string, string>();
  assertEnvFileQuotesAreSingleLine(content);
  for (const raw of content.split("\n")) {
    const entry = parseEnvLine(raw);
    if (entry && isEnvVarName(entry[0])) out.set(entry[0], entry[1]);
  }
  return out;
}

export function parseEnvFile(content: Uint8Array): Map<string, string> {
  return parseEnvFileText(decodeEnvFileText(content));
}

function envAssignmentName(line: string): string | undefined {
  const match = /^(?:#[ \t\r]*)?(?:export [ \t\r]*)?([A-Za-z_][A-Za-z0-9_]*)[ \t\r]*=/.exec(trimEnvSpace(line));
  return match?.[1];
}

export function updateEnvContent(content: string, entries: ReadonlyMap<string, string>): string {
  assertEnvFileQuotesAreSingleLine(content);
  for (const [name, value] of entries) {
    if (!isEnvVarName(name)) throw new CliError(`${JSON.stringify(name)} is not a valid environment variable name`);
    if (!value.isWellFormed()) throw new CliError(`the value for ${name} must be valid UTF-8 text`);
    if (value.includes("\ufeff")) throw new CliError(`the value for ${name} must not contain a byte-order mark`);
    if (/[\0\r\n]/.test(value)) throw new CliError(`the value for ${name} must be a single line without NUL bytes`);
  }
  const remaining = new Map(entries);
  const lines = content.split("\n").flatMap((line) => {
    const name = envAssignmentName(line);
    if (!name || !entries.has(name)) return [line];
    if (!remaining.has(name)) return [];
    const value = remaining.get(name)!;
    remaining.delete(name);
    return [`${name}=${serializeEnvValue(name, value)}`];
  });
  let out = lines.join("\n");
  if (remaining.size > 0) {
    if (out !== "" && !out.endsWith("\n")) out += "\n";
    for (const [name, value] of remaining) out += `${name}=${serializeEnvValue(name, value)}\n`;
  }
  return out;
}

function serializeEnvValue(name: string, value: string): string {
  if (value === value.trim() && !value.includes("#") && !['"', "'", "`"].includes(value[0] ?? "")) return value;
  for (const quote of ["'", "`", '"'] as const) {
    if (!value.includes(quote) && (quote !== '"' || !value.includes("\\n"))) return `${quote}${value}${quote}`;
  }
  throw new CliError(`the value for ${name} cannot be represented losslessly in a deployment environment file`);
}

interface EnvFileSnapshot {
  content: string;
  mode: number;
  identity?: { dev: number; ino: number };
  ownership?: { uid: number; gid: number };
}

function decodeUtf8Text(content: Uint8Array, label: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(content);
  } catch (error) {
    throw new CliError(`${label} must contain valid UTF-8 text`, { cause: error });
  }
}

function decodeEnvFileText(content: Uint8Array): string {
  return decodeUtf8Text(content, "deployment environment file");
}

export function decodeUtf8(content: Uint8Array): string {
  return decodeUtf8Text(content, "input");
}

export interface FileIdentity {
  dev: bigint;
  ino: bigint;
}

export interface RegularFileSnapshot {
  content: Buffer;
  identity: FileIdentity;
}

export const MAX_DEPLOYMENT_INPUT_BYTES = 1_048_576;

function readStableDescriptor(descriptor: number, label: string, maxBytes = MAX_DEPLOYMENT_INPUT_BYTES) {
  const before = fstatSync(descriptor, { bigint: true });
  if (!before.isFile()) throw new CliError(`${label} must be a regular file`);
  if (before.size > BigInt(maxBytes)) throw new CliError(`${label} exceeds the ${maxBytes}-byte limit`);
  const buffer = Buffer.alloc(Number(before.size) + 1);
  let length = 0;
  for (;;) {
    const bytes = readSync(descriptor, buffer, length, buffer.length - length, length);
    if (bytes === 0) break;
    length += bytes;
    if (length === buffer.length) break;
  }
  const content = buffer.subarray(0, length);
  const after = fstatSync(descriptor, { bigint: true });
  if (
    !after.isFile() ||
    after.dev !== before.dev ||
    after.ino !== before.ino ||
    after.size !== before.size ||
    after.mtimeNs !== before.mtimeNs ||
    after.ctimeNs !== before.ctimeNs ||
    BigInt(content.byteLength) !== after.size
  ) {
    throw new CliError(`${label} changed while it was being read`);
  }
  return { content, stat: after };
}

export function readRegularFileSnapshot(path: string, maxBytes = MAX_DEPLOYMENT_INPUT_BYTES): RegularFileSnapshot {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const snapshot = readStableDescriptor(descriptor, "input path", maxBytes);
    return { content: snapshot.content, identity: { dev: snapshot.stat.dev, ino: snapshot.stat.ino } };
  } finally {
    closeSync(descriptor);
  }
}

export function readRegularFile(path: string, maxBytes = MAX_DEPLOYMENT_INPUT_BYTES): Buffer {
  return readRegularFileSnapshot(path, maxBytes).content;
}

export function readUtf8File(path: string): string {
  return decodeUtf8(readRegularFile(path));
}

function readEnvFileText(descriptor: number): string {
  return decodeEnvFileText(readStableDescriptor(descriptor, "deployment environment file").content);
}

function envFileSnapshot(path: string, protectedPath?: string): EnvFileSnapshot {
  assertEnvFileTargetSafe(path, protectedPath);
  const target = resolve(path);
  let descriptor: number;
  try {
    descriptor = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { content: "", mode: 0o600 };
    throw new CliError("deployment environment file must be an unlinked regular file", { cause: error });
  }
  try {
    const snapshot = readStableDescriptor(descriptor, "deployment environment file");
    const identity = snapshot.stat;
    if (identity.nlink !== 1n) {
      throw new CliError("deployment environment file must be an unlinked regular file");
    }
    if (typeof process.getuid === "function" && identity.uid !== BigInt(process.getuid())) {
      throw new CliError("deployment environment file must be owned by the current user");
    }
    if (protectedPath) {
      const protectedIdentity = statSync(resolve(protectedPath), { bigint: true });
      if (identity.dev === protectedIdentity.dev && identity.ino === protectedIdentity.ino) {
        throw new CliError("deployment environment file must be separate from the deployment config");
      }
    }
    return {
      content: decodeEnvFileText(snapshot.content),
      mode: Number(identity.mode & 0o777n),
      identity: { dev: Number(identity.dev), ino: Number(identity.ino) },
      ownership: { uid: Number(identity.uid), gid: Number(identity.gid) },
    };
  } finally {
    closeSync(descriptor);
  }
}

interface EnvFileLock {
  descriptor: number;
  path: string;
  ownerPath: string;
  identity: { dev: number; ino: number };
  token: string;
}

const envFileLockWait = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));

function envFileLockOwner(path: string):
  | {
      descriptor: number;
      pid: number;
      token: string;
      ownerPath: string;
      identity: { dev: number; ino: number };
    }
  | undefined {
  let descriptor: number;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new CliError("deployment environment file lock is unsafe", { cause: error });
  }
  let transferred = false;
  try {
    let snapshot: ReturnType<typeof readStableDescriptor>;
    try {
      snapshot = readStableDescriptor(descriptor, "deployment environment file lock", 4096);
    } catch (error) {
      const opened = fstatSync(descriptor);
      if (!opened.isFile()) throw new CliError("deployment environment file lock is unsafe", { cause: error });
      const openedIdentity = { dev: opened.dev, ino: opened.ino };
      if (!envFilePathMatchesIdentity(path, openedIdentity)) return undefined;
      throw new CliError("deployment environment file lock is unsafe", { cause: error });
    }
    const identity = snapshot.stat;
    const fileIdentity = { dev: Number(identity.dev), ino: Number(identity.ino) };
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (
      (uid !== undefined && identity.uid !== BigInt(uid)) ||
      Number(identity.mode & 0o777n) !== 0o600 ||
      identity.nlink !== 2n
    ) {
      if (!envFilePathMatchesIdentity(path, fileIdentity)) return undefined;
      throw new CliError("deployment environment file lock is unsafe");
    }
    let content: string;
    try {
      content = decodeUtf8Text(snapshot.content, "deployment environment file lock");
    } catch (error) {
      throw new CliError("deployment environment file lock is unsafe", { cause: error });
    }
    const owner = /^([1-9]\d*):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([^/]+)\n$/u.exec(
      content,
    );
    const pid = Number(owner?.[1]);
    const expectedOwner = owner ? `${basename(path)}.${owner[1]}.${owner[2]}.owner` : undefined;
    const ownerPath = expectedOwner ? join(dirname(path), expectedOwner) : undefined;
    let ownerIdentity: ReturnType<typeof lstatSync> | undefined;
    try {
      if (ownerPath) ownerIdentity = lstatSync(ownerPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw new CliError("deployment environment file lock is unsafe", { cause: error });
      }
    }
    if (
      !Number.isSafeInteger(pid) ||
      pid < 1 ||
      pid > 2_147_483_647 ||
      owner?.[3] !== expectedOwner ||
      !ownerPath ||
      !ownerIdentity?.isFile() ||
      ownerIdentity.nlink !== 2 ||
      BigInt(ownerIdentity.dev) !== identity.dev ||
      BigInt(ownerIdentity.ino) !== identity.ino ||
      (uid !== undefined && ownerIdentity.uid !== uid) ||
      (Number(ownerIdentity.mode) & 0o777) !== 0o600 ||
      !envFileLockPathMatches(path, fileIdentity, 2, 0o600) ||
      !envFileLockPathMatches(ownerPath, fileIdentity, 2, 0o600)
    ) {
      if (!envFilePathMatchesIdentity(path, fileIdentity)) return undefined;
      throw new CliError("deployment environment file lock is unsafe");
    }
    transferred = true;
    return {
      descriptor,
      pid,
      token: owner![2]!,
      ownerPath,
      identity: fileIdentity,
    };
  } finally {
    if (!transferred) closeSync(descriptor);
  }
}

function envFilePathMatchesIdentity(path: string, identity: { dev: number; ino: number }): boolean {
  try {
    const current = lstatSync(path);
    return current.dev === identity.dev && current.ino === identity.ino;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function envFileLockPathMatches(
  path: string,
  identity: { dev: number; ino: number },
  links: number,
  exactMode?: number,
): boolean {
  let current: ReturnType<typeof lstatSync>;
  try {
    current = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  const mode = current.mode & 0o777;
  return (
    current.isFile() &&
    current.nlink === links &&
    current.dev === identity.dev &&
    current.ino === identity.ino &&
    (uid === undefined || current.uid === uid) &&
    (exactMode === undefined ? (mode & 0o077) === 0 : mode === exactMode)
  );
}

function removeOwnedEnvFileLock(
  path: string,
  identity: { dev: number; ino: number },
  links: number,
  exactMode?: number,
): boolean {
  if (!envFileLockPathMatches(path, identity, links, exactMode)) {
    return false;
  }
  unlinkSync(path);
  return true;
}

function envFileTemporaryPath(target: string, pid: number, token: string): string {
  return join(dirname(target), `.${basename(target)}.${pid}.${token}.tmp`);
}

function removeStaleEnvFileTemporary(path: string, pid: number, token: string): void {
  const target = path.slice(0, -".qm-lock".length);
  const temporary = envFileTemporaryPath(target, pid, token);
  let identity: ReturnType<typeof lstatSync>;
  try {
    identity = lstatSync(temporary);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  const safe = (entry: typeof identity): boolean =>
    entry.isFile() && entry.nlink === 1 && (entry.mode & 0o777) === 0o600 && (uid === undefined || entry.uid === uid);
  if (!safe(identity)) {
    throw new CliError("deployment environment file temporary state is unsafe");
  }
  let current: typeof identity;
  try {
    current = lstatSync(temporary);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!safe(current) || current.dev !== identity.dev || current.ino !== identity.ino) {
    throw new CliError("deployment environment file temporary state is unsafe");
  }
  if (!removeOwnedEnvFileLock(temporary, { dev: identity.dev, ino: identity.ino }, 1, 0o600)) {
    throw new CliError("deployment environment file temporary state is unsafe");
  }
}

function removeStaleEnvFileLock(path: string): boolean {
  const owner = envFileLockOwner(path);
  if (!owner) return true;
  try {
    try {
      process.kill(owner.pid, 0);
      return false;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") return false;
    }
    if (
      !envFileLockPathMatches(path, owner.identity, 2, 0o600) ||
      !envFileLockPathMatches(owner.ownerPath, owner.identity, 2, 0o600)
    ) {
      return true;
    }
    removeStaleEnvFileTemporary(path, owner.pid, owner.token);
    if (!removeOwnedEnvFileLock(path, owner.identity, 2, 0o600)) {
      throw new CliError("deployment environment file lock changed during stale-lock cleanup");
    }
    if (!removeOwnedEnvFileLock(owner.ownerPath, owner.identity, 1, 0o600)) {
      throw new CliError("deployment environment file owner changed during stale-lock cleanup");
    }
    return true;
  } finally {
    closeSync(owner.descriptor);
  }
}

function acquireEnvFileLock(path: string): EnvFileLock {
  const lockPath = `${resolve(path)}.qm-lock`;
  const deadline = Date.now() + 30_000;
  for (;;) {
    const token = randomUUID();
    const ownerPath = `${lockPath}.${process.pid}.${token}.owner`;
    let descriptor: number;
    try {
      descriptor = openSync(
        ownerPath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      throw new CliError("could not prepare the deployment environment file lock", { cause: error });
    }
    const opened = fstatSync(descriptor);
    const openedIdentity = { dev: opened.dev, ino: opened.ino };
    let descriptorOpen = true;
    try {
      fchmodSync(descriptor, 0o600);
      writeFileSync(descriptor, `${process.pid}:${token}:${basename(ownerPath)}\n`, "utf8");
      fsyncSync(descriptor);
      const identity = fstatSync(descriptor);
      if (!identity.isFile() || identity.nlink !== 1) throw new CliError("deployment environment file lock is unsafe");
      try {
        linkSync(ownerPath, lockPath);
      } catch (error) {
        closeSync(descriptor);
        descriptorOpen = false;
        removeOwnedEnvFileLock(ownerPath, openedIdentity, 1);
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
          throw new CliError("could not lock the deployment environment file", { cause: error });
        }
        if (removeStaleEnvFileLock(lockPath)) continue;
        if (Date.now() >= deadline) {
          throw new CliError("deployment environment file is locked by another qm process");
        }
        Atomics.wait(envFileLockWait, 0, 0, 25);
        continue;
      }
      const linked = fstatSync(descriptor);
      if (linked.nlink !== 2) throw new CliError("deployment environment file lock is unsafe");
      return { descriptor, path: lockPath, ownerPath, identity: { dev: linked.dev, ino: linked.ino }, token };
    } catch (error) {
      let closeError: unknown;
      if (descriptorOpen) {
        try {
          closeSync(descriptor);
        } catch (failure) {
          closeError = failure;
        }
      }
      try {
        removeOwnedEnvFileLock(lockPath, openedIdentity, 2);
        removeOwnedEnvFileLock(ownerPath, openedIdentity, 1);
      } catch (cleanupError) {
        throw new CliError("could not clean up the deployment environment file lock", {
          cause: new AggregateError([error, ...(closeError ? [closeError] : []), cleanupError]),
        });
      }
      if (closeError) {
        throw new CliError("could not close the deployment environment file lock", {
          cause: new AggregateError([error, closeError]),
        });
      }
      throw error;
    }
  }
}

function assertEnvFileLockHeld(lock: EnvFileLock): void {
  if (
    !envFileLockPathMatches(lock.path, lock.identity, 2, 0o600) ||
    !envFileLockPathMatches(lock.ownerPath, lock.identity, 2, 0o600)
  ) {
    throw new CliError("deployment environment file lock changed during the update");
  }
}

function releaseEnvFileLock(lock: EnvFileLock): void {
  try {
    assertEnvFileLockHeld(lock);
    if (!removeOwnedEnvFileLock(lock.path, lock.identity, 2, 0o600)) {
      throw new CliError("deployment environment file lock changed during release");
    }
    if (!removeOwnedEnvFileLock(lock.ownerPath, lock.identity, 1, 0o600)) {
      throw new CliError("deployment environment file owner changed during release");
    }
  } finally {
    closeSync(lock.descriptor);
  }
}

function assertEnvFileSnapshotCurrent(path: string, snapshot: EnvFileSnapshot): void {
  let descriptor: number;
  try {
    descriptor = openSync(resolve(path), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" && !snapshot.identity) return;
    throw new CliError("deployment environment file changed during the update", { cause: error });
  }
  try {
    const identity = fstatSync(descriptor);
    if (
      !snapshot.identity ||
      !identity.isFile() ||
      identity.nlink !== 1 ||
      identity.dev !== snapshot.identity.dev ||
      identity.ino !== snapshot.identity.ino ||
      (snapshot.ownership !== undefined &&
        (identity.uid !== snapshot.ownership.uid || identity.gid !== snapshot.ownership.gid)) ||
      (identity.mode & 0o777) !== snapshot.mode ||
      readEnvFileText(descriptor) !== snapshot.content
    ) {
      throw new CliError("deployment environment file changed during the update");
    }
  } finally {
    closeSync(descriptor);
  }
}

function assertEnvFileTemporaryCurrent(path: string, descriptor: number, identity: { dev: number; ino: number }): void {
  const opened = fstatSync(descriptor);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (
    !opened.isFile() ||
    opened.nlink !== 1 ||
    opened.dev !== identity.dev ||
    opened.ino !== identity.ino ||
    (uid !== undefined && opened.uid !== uid) ||
    (opened.mode & 0o777) !== 0o600 ||
    !envFileLockPathMatches(path, identity, 1, 0o600)
  ) {
    throw new CliError("deployment environment file temporary state changed during the update");
  }
}

interface EnvFileDirectory {
  descriptor: number;
  path: string;
  identity: { dev: number; ino: number };
}

function assertDarwinEnvFileDirectoryAclSafe(path: string): void {
  if (process.platform !== "darwin") return;
  const ancestors = new Set<string>();
  for (const start of [resolve(path), realpathSync(path)]) {
    let current = start;
    for (;;) {
      ancestors.add(current);
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  assertDarwinPathsHaveNoGrantingAcl(ancestors, "deployment environment file directory");
}

function assertDarwinPathsHaveNoGrantingAcl(paths: Iterable<string>, label: string): void {
  if (process.platform !== "darwin") return;
  const output = execFileSync("/bin/ls", ["-lden", "--", ...paths], {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C" },
  });
  if (output.split("\n").some((line) => /^\s*\d+:\s.*\sallow(?:\s|$)/u.test(line))) {
    throw new CliError(`${label} has an unsafe access control list`);
  }
}

function assertEnvFileDirectoryAncestrySafe(path: string): void {
  const ancestors = new Set<string>();
  for (const start of [resolve(path), realpathSync(path)]) {
    let current = start;
    for (;;) {
      ancestors.add(current);
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  for (const ancestor of ancestors) {
    const entry = lstatSync(ancestor);
    if (entry.isSymbolicLink() && entry.uid === 0) continue;
    const mode = entry.mode & 0o7777;
    const rootSticky = entry.uid === 0 && (mode & 0o1000) !== 0;
    if (
      !entry.isDirectory() ||
      (uid !== undefined && entry.uid !== uid && entry.uid !== 0) ||
      ((mode & 0o022) !== 0 && !rootSticky)
    ) {
      throw new CliError("deployment environment file directory ancestry is unsafe");
    }
  }
}

function openEnvFileDirectory(target: string): EnvFileDirectory {
  const path = dirname(target);
  assertEnvFileDirectoryAncestrySafe(path);
  assertDarwinEnvFileDirectoryAclSafe(path);
  let descriptor: number;
  try {
    descriptor = openSync(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_DIRECTORY,
    );
  } catch (error) {
    throw new CliError("deployment environment file directory is unsafe", { cause: error });
  }
  const entry = fstatSync(descriptor);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (!entry.isDirectory() || (uid !== undefined && entry.uid !== uid) || (entry.mode & 0o022) !== 0) {
    closeSync(descriptor);
    throw new CliError("deployment environment file directory is unsafe");
  }
  return { descriptor, path, identity: { dev: entry.dev, ino: entry.ino } };
}

function assertEnvFileDirectoryCurrent(directory: EnvFileDirectory): void {
  assertEnvFileDirectoryAncestrySafe(directory.path);
  assertDarwinEnvFileDirectoryAclSafe(directory.path);
  const opened = fstatSync(directory.descriptor);
  const current = lstatSync(directory.path);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  for (const entry of [opened, current]) {
    if (
      !entry.isDirectory() ||
      entry.dev !== directory.identity.dev ||
      entry.ino !== directory.identity.ino ||
      (uid !== undefined && entry.uid !== uid) ||
      (entry.mode & 0o022) !== 0
    ) {
      throw new CliError("deployment environment file directory changed during the update");
    }
  }
}

export function writeEnvValues(path: string, entries: ReadonlyMap<string, string>, protectedPath?: string): void {
  const target = resolve(path);
  const directory = openEnvFileDirectory(target);
  try {
    const lock = acquireEnvFileLock(path);
    try {
      const snapshot = envFileSnapshot(path, protectedPath);
      const temporary = envFileTemporaryPath(target, process.pid, lock.token);
      let descriptor: number | undefined;
      let installed = false;
      try {
        descriptor = openSync(
          temporary,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
          0o600,
        );
        const created = fstatSync(descriptor);
        const temporaryIdentity = { dev: created.dev, ino: created.ino };
        fchmodSync(descriptor, 0o600);
        if (snapshot.ownership && typeof process.getuid === "function") {
          fchownSync(descriptor, snapshot.ownership.uid, snapshot.ownership.gid);
        }
        if (process.platform === "darwin") {
          execFileSync("/bin/chmod", ["-N", "/dev/fd/3"], {
            stdio: ["ignore", "ignore", "ignore", descriptor],
          });
        }
        fchmodSync(descriptor, 0o600);
        const updated = updateEnvContent(snapshot.content, entries);
        if (Buffer.byteLength(updated, "utf8") > MAX_DEPLOYMENT_INPUT_BYTES) {
          throw new CliError(`deployment environment file exceeds the ${MAX_DEPLOYMENT_INPUT_BYTES}-byte limit`);
        }
        writeFileSync(descriptor, updated, "utf8");
        fsyncSync(descriptor);
        assertEnvFileTemporaryCurrent(temporary, descriptor, temporaryIdentity);
        assertEnvFileLockHeld(lock);
        assertEnvFileTargetSafe(target, protectedPath);
        assertEnvFileSnapshotCurrent(target, snapshot);
        assertEnvFileDirectoryCurrent(directory);
        assertEnvFileTemporaryCurrent(temporary, descriptor, temporaryIdentity);
        renameSync(temporary, target);
        installed = true;
        assertEnvFileTemporaryCurrent(target, descriptor, temporaryIdentity);
        assertEnvFileDirectoryCurrent(directory);
        closeSync(descriptor);
        descriptor = undefined;
        fsyncSync(directory.descriptor);
      } finally {
        if (descriptor !== undefined) {
          if (!installed) {
            ftruncateSync(descriptor, 0);
            fsyncSync(descriptor);
          }
          closeSync(descriptor);
        }
        removeStaleEnvFileTemporary(lock.path, process.pid, lock.token);
      }
    } finally {
      releaseEnvFileLock(lock);
    }
  } finally {
    closeSync(directory.descriptor);
  }
}

export function writeEnvValue(path: string, key: string, value: string, protectedPath?: string): void {
  writeEnvValues(path, new Map([[key, value]]), protectedPath);
}

function canonicalMutationPath(path: string): string {
  let current = resolve(path);
  const suffix: string[] = [];
  while (!existsSync(current)) {
    const parent = dirname(current);
    if (parent === current) return current;
    suffix.unshift(basename(current));
    current = parent;
  }
  return resolve(realpathSync(current), ...suffix);
}

function assertEnvFileTargetSafe(path: string, protectedPath?: string): void {
  const target = resolve(path);
  const protectedTarget = protectedPath ? resolve(protectedPath) : undefined;
  if (protectedTarget && target === protectedTarget) {
    throw new CliError("deployment environment file must be separate from the deployment config");
  }
  let entry: ReturnType<typeof lstatSync> | undefined;
  try {
    entry = lstatSync(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  if (entry && (!entry.isFile() || entry.nlink !== 1)) {
    throw new CliError("deployment environment file must be an unlinked regular file");
  }
  if (protectedTarget && canonicalMutationPath(target) === canonicalMutationPath(protectedTarget)) {
    throw new CliError("deployment environment file must be separate from the deployment config");
  }
  if (!entry || !protectedTarget) return;
  const protectedEntry = statSync(protectedTarget);
  if (entry.dev === protectedEntry.dev && entry.ino === protectedEntry.ino) {
    throw new CliError("deployment environment file must be separate from the deployment config");
  }
}

export function assertEnvFileMutationSafe(path: string, protectedPath: string): void {
  assertEnvFileTargetSafe(path, protectedPath);
}

export function deploymentSecretValue(name: string, fileValue: string | undefined): string | undefined {
  if (process.env.QM_DEPLOY_ENV_FILE_ONLY === "1") {
    return fileValue === undefined || fileValue.trim() === "" ? undefined : fileValue;
  }
  return fileValue === undefined || fileValue.trim() === "" ? process.env[name] : fileValue;
}

export function which(bin: string): boolean {
  if (!bin || bin.includes("\0")) return false;
  const candidates = /[\\/]/.test(bin)
    ? [resolve(bin)]
    : (process.env.PATH ?? "").split(delimiter).map((entry) => join(entry || ".", bin));
  for (const path of candidates) {
    try {
      accessSync(path, constants.X_OK);
      if (statSync(path).isFile()) return true;
    } catch {
      continue;
    }
  }
  return false;
}

export const flyBin = (): string => process.env.FLY_BIN ?? (which("flyctl") ? "flyctl" : "fly");

export function gitSubprocessEnvironment(baseEnv: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return {
    ...Object.fromEntries(Object.entries(baseEnv).filter(([name]) => !name.startsWith("GIT_"))),
    GIT_OPTIONAL_LOCKS: "0",
  };
}

export function gitTopLevel(baseEnv: NodeJS.ProcessEnv = process.env, cwd?: string): string {
  try {
    const output = capture("git", ["--no-optional-locks", "rev-parse", "--show-toplevel"], {
      env: gitSubprocessEnvironment(baseEnv),
      ...(cwd === undefined ? {} : { cwd }),
    });
    return output.endsWith("\n") ? output.slice(0, -1) : output;
  } catch {
    throw new CliError("not inside a git worktree (run this from a QM checkout)");
  }
}

export function resolveBuildRepoRoot(
  explicit?: string,
  requiredServices: readonly string[] = ["core"],
  baseEnv: NodeJS.ProcessEnv = process.env,
): string {
  let root: string;
  if (explicit !== undefined) root = resolve(explicit);
  else {
    try {
      root = gitTopLevel(baseEnv);
    } catch {
      throw new CliError(
        "--build-from requires running inside the QM source repo, or pass a path: --build-from <repo>",
      );
    }
  }
  const missing = requiredServices.filter((service) => !existsSync(join(root, "deploy", service, "Dockerfile")));
  if (missing.length) {
    const source = explicit === undefined ? root : explicit;
    throw new CliError(
      `--build-from ${source}: not a QM checkout (missing ${missing.map((service) => `deploy/${service}/Dockerfile`).join(", ")})`,
    );
  }
  return root;
}

export function promptHidden(name: string, prompt = `${name}: `): Promise<string> {
  if (!process.stdin.isTTY || !process.stdin.setRawMode) {
    throw new CliError(`missing ${name} in .env; an interactive terminal is required to prompt`);
  }
  return new Promise((resolve, reject) => {
    const bytes: number[] = [];
    const stdin = process.stdin;
    const finish = (error?: Error): void => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.off("data", onData);
      process.stdout.write("\n");
      if (error) reject(error);
      else {
        try {
          resolve(decodeUtf8(Buffer.from(bytes)));
        } catch (failure) {
          reject(failure);
        }
      }
    };
    const onData = (chunk: Buffer): void => {
      for (const byte of chunk) {
        if (byte === 3) return finish(new CliError("secret entry cancelled"));
        if (byte === 4) return bytes.length ? finish() : finish(new CliError("secret entry cancelled"));
        if (byte === 13 || byte === 10) return finish();
        if (byte === 127 || byte === 8) {
          let dropped = bytes.pop();
          while (dropped !== undefined && (dropped & 0b1100_0000) === 0b1000_0000) dropped = bytes.pop();
        } else if (bytes.length >= MAX_SECRET_BYTES) {
          return finish(new CliError(`${name} exceeds the ${MAX_SECRET_BYTES}-byte provider limit`));
        } else bytes.push(byte);
      }
    };
    process.stdout.write(prompt);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on("data", onData);
  });
}
