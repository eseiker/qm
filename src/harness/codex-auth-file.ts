import { closeSync, constants, fstatSync, openSync, readSync, type BigIntStats } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export type JsonObject = Record<string, unknown>;

const CODEX_OAUTH_MODES = new Set(["chatgpt", "chatgptAuthTokens"]);
const MAX_CODEX_AUTH_FILE_BYTES = 1024 * 1024;
export const CODEX_OAUTH_ISSUER = "https://auth.openai.com";

export function asObject(value: unknown): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonObject) : null;
}

export function codexOAuthJwtAccountIdFromToken(value: unknown): string | undefined {
  if (typeof value !== "string" || value.split(".").length !== 3) return undefined;
  try {
    const payload = asObject(JSON.parse(Buffer.from(value.split(".")[1] ?? "", "base64url").toString("utf8")));
    const claims = payload ? asObject(payload["https://api.openai.com/auth"]) : null;
    return typeof claims?.chatgpt_account_id === "string" && claims.chatgpt_account_id
      ? claims.chatgpt_account_id
      : undefined;
  } catch {
    return undefined;
  }
}

export function codexOAuthJwtAccountId(value: unknown): string | undefined {
  const auth = asObject(value);
  const tokens = auth ? asObject(auth.tokens) : null;
  return codexOAuthJwtAccountIdFromToken(tokens?.id_token);
}

function sameCodexAuthFileStat(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function readJsonFile(descriptor: number, initial: BigIntStats): JsonObject | null {
  if (initial.size < 0n || initial.size > BigInt(MAX_CODEX_AUTH_FILE_BYTES)) return null;
  const size = Number(initial.size);
  const snapshot = (): Buffer => {
    const bytes = Buffer.allocUnsafe(size + 1);
    let length = 0;
    while (length < bytes.length) {
      const read = readSync(descriptor, bytes, length, bytes.length - length, length);
      if (read === 0) break;
      length += read;
    }
    return bytes.subarray(0, length);
  };
  try {
    const first = snapshot();
    const between = fstatSync(descriptor, { bigint: true });
    const second = snapshot();
    const after = fstatSync(descriptor, { bigint: true });
    if (
      !sameCodexAuthFileStat(initial, between) ||
      !sameCodexAuthFileStat(between, after) ||
      first.length !== size ||
      second.length !== size ||
      !first.equals(second)
    ) {
      return null;
    }
    return asObject(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(first)));
  } catch {
    return null;
  }
}

function expandPath(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return resolve(path);
}

export function codexAuthFileForEnv(env: NodeJS.ProcessEnv, includeDefault = false): string | undefined {
  const explicit = env.CODEX_AUTH_FILE?.trim();
  if (explicit) return expandPath(explicit);
  if (!includeDefault) return undefined;
  const codexHome = env.CODEX_HOME?.trim();
  if (codexHome) return join(expandPath(codexHome), "auth.json");
  const home = env.HOME?.trim();
  return home ? join(expandPath(home), ".codex", "auth.json") : undefined;
}

function isCodexOAuthAuth(value: unknown): value is JsonObject {
  const auth = asObject(value);
  if (!auth || typeof auth.auth_mode !== "string" || !CODEX_OAUTH_MODES.has(auth.auth_mode)) return false;
  const tokens = asObject(auth.tokens);
  return Boolean(
    tokens &&
    typeof tokens.access_token === "string" &&
    tokens.access_token &&
    typeof tokens.refresh_token === "string" &&
    tokens.refresh_token &&
    codexOAuthJwtAccountId(auth),
  );
}

export function readCodexOAuthAuthFile(path: string): JsonObject | null {
  let descriptor: number;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch {
    return null;
  }
  let auth: JsonObject | null;
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    const currentUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : undefined;
    if (
      !opened.isFile() ||
      opened.nlink !== 1n ||
      (opened.mode & 0o7777n) !== 0o600n ||
      currentUid === undefined ||
      opened.uid !== currentUid
    ) {
      auth = null;
    } else {
      const parsed = readJsonFile(descriptor, opened);
      auth = isCodexOAuthAuth(parsed) ? parsed : null;
    }
  } catch {
    auth = null;
  }
  try {
    closeSync(descriptor);
  } catch {
    return null;
  }
  return auth;
}

export function sanitizedCodexOAuthAuth(auth: JsonObject): JsonObject {
  const copy: JsonObject = {};
  for (const key of ["auth_mode", "last_refresh", "tokens"] as const) {
    if (key === "tokens") {
      const tokens = asObject(auth.tokens);
      if (tokens) {
        copy.tokens = Object.fromEntries(
          ["access_token", "refresh_token", "id_token", "account_id"].flatMap((token) =>
            typeof tokens[token] === "string" ? [[token, tokens[token]]] : [],
          ),
        );
      }
    } else if (key in auth) copy[key] = auth[key];
  }
  return copy;
}

export function codexOAuthRefreshToken(value: unknown): string | undefined {
  const auth = asObject(value);
  const tokens = auth ? asObject(auth.tokens) : null;
  return typeof tokens?.refresh_token === "string" && tokens.refresh_token ? tokens.refresh_token : undefined;
}
