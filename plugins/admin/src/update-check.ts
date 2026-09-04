import { readFileSync } from "node:fs";
import { errMessage } from "../../chassis/src/errors.ts";

const REGISTRY_URL = "https://registry.npmjs.org/@yc-software%2fqm/latest";
const STABLE_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
export const SUCCESS_TTL_MS = 5 * 60_000;
export const FAILURE_TTL_MS = 30_000;

type VersionParts = [bigint, bigint, bigint];

class RegistryUnavailableError extends Error {}

function versionParts(version: string): VersionParts | null {
  const match = STABLE_VERSION.exec(version);
  if (!match) return null;
  return [BigInt(match[1]!), BigInt(match[2]!), BigInt(match[3]!)];
}

export function resolveCurrentQmVersion(
  envVersion = process.env.QM_VERSION,
  packageUrl = new URL("../qm-package.json", import.meta.url),
  nodeEnv = process.env.NODE_ENV,
): string | undefined {
  if (nodeEnv !== "production" && envVersion) return versionParts(envVersion) ? envVersion : undefined;
  try {
    const value = JSON.parse(readFileSync(packageUrl, "utf8")) as { name?: unknown; version?: unknown };
    return value.name === "@yc-software/qm" && typeof value.version === "string" && versionParts(value.version)
      ? value.version
      : undefined;
  } catch {
    return undefined;
  }
}

export function compareVersions(a: string, b: string): number {
  const left = versionParts(a);
  const right = versionParts(b);
  if (!left || !right) throw new Error(`invalid stable QM version: ${!left ? a : b}`);
  for (const i of [0, 1, 2] as const) {
    if (left[i] < right[i]) return -1;
    if (left[i] > right[i]) return 1;
  }
  return 0;
}

export interface UpdateStatus {
  currentVersion: string;
  latestVersion: string;
  updateAvailable: boolean;
  updateCommand: string;
  releaseUrl: string;
}

function promotedVersion(metadata: unknown): string {
  if (!metadata || typeof metadata !== "object") {
    throw new Error("npm registry returned invalid latest QM metadata");
  }
  const { version, deprecated } = metadata as { version?: unknown; deprecated?: unknown };
  if (typeof version !== "string" || !versionParts(version)) {
    throw new Error("npm registry returned an invalid stable latest QM version");
  }
  if (deprecated !== undefined) throw new Error(`npm registry returned deprecated QM ${version}`);
  return version;
}

export async function fetchUpdateStatus(currentVersion: string, fetcher: typeof fetch = fetch): Promise<UpdateStatus> {
  if (!versionParts(currentVersion)) throw new Error(`invalid current stable QM version: ${currentVersion}`);
  let response: Response;
  try {
    response = await fetcher(REGISTRY_URL, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(3_000),
    });
  } catch (error) {
    throw new RegistryUnavailableError(`npm registry request failed: ${errMessage(error)}`, { cause: error });
  }
  if (!response.ok) {
    const message = `npm registry returned ${response.status}`;
    if (response.status === 408 || response.status === 429 || (response.status >= 500 && response.status < 600)) {
      throw new RegistryUnavailableError(message);
    }
    throw new Error(message);
  }
  let metadata: unknown;
  try {
    metadata = await response.json();
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error("npm registry returned invalid latest QM metadata", { cause: error });
    }
    throw new RegistryUnavailableError(`npm registry response failed: ${errMessage(error)}`, { cause: error });
  }
  const latestVersion = promotedVersion(metadata);
  return {
    currentVersion,
    latestVersion,
    updateAvailable: compareVersions(currentVersion, latestVersion) < 0,
    updateCommand: `node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version ${latestVersion}`,
    releaseUrl: `https://github.com/yc-software/qm/releases/tag/v${latestVersion}`,
  };
}

export function createUpdateChecker(
  currentVersion: string | undefined,
  options: { fetcher?: typeof fetch; now?: () => number } = {},
): () => Promise<UpdateStatus | null> {
  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? Date.now;
  let cached: { expiresAt: number; status: UpdateStatus } | null = null;
  let failed: { error: unknown; retryAt: number; staleAvailable: boolean } | null = null;
  let pending: Promise<UpdateStatus> | null = null;

  return async (): Promise<UpdateStatus | null> => {
    if (!currentVersion || !versionParts(currentVersion)) return null;
    if (cached && cached.expiresAt > now()) return cached.status;
    if (failed && failed.retryAt > now()) {
      if (cached && failed.staleAvailable) return cached.status;
      throw failed.error;
    }
    if (!pending) {
      pending = fetchUpdateStatus(currentVersion, fetcher)
        .then((status) => {
          cached = { expiresAt: now() + SUCCESS_TTL_MS, status };
          failed = null;
          return status;
        })
        .catch((error: unknown) => {
          console.warn(`[admin] update check failed: ${errMessage(error)}`);
          const staleAvailable = error instanceof RegistryUnavailableError && cached?.status.updateAvailable === false;
          failed = { error, retryAt: now() + FAILURE_TTL_MS, staleAvailable };
          if (!staleAvailable) cached = null;
          if (cached) return cached.status;
          throw error;
        })
        .finally(() => {
          pending = null;
        });
    }
    return pending;
  };
}
