import { AsyncLocalStorage } from "node:async_hooks";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { Worker } from "node:worker_threads";
import type { AwsConfig } from "./config.ts";
import { CliError, errMessage, warn } from "./log.ts";
import { capture, envNum, processErrorMatches, runInherit } from "./util.ts";

const DEFAULT_LEASE_SECONDS = 60 * 60;
const LEASE_HELD = 0;
const LEASE_LOST = 1;
const LEASE_RENEWAL_FAILED = 2;
const LEASE_STOPPING = 3;
const STOP_REQUESTED = 1;
const RENEWER_SOURCE = String.raw`
const { execFileSync } = require("node:child_process");
const { parentPort, workerData } = require("node:worker_threads");
const state = new Int32Array(workerData.state);
const confirmedExpiry = new BigInt64Array(workerData.confirmedExpiry);
const conditional = /(?:^|\n)[ \t]*(?:An error occurred \(ConditionalCheckFailedException\) when calling\b|ConditionalCheckFailedException(?=[:\r\n]|$))/;
const output = (error) => [error && error.stdout, error && error.stderr]
  .map((value) => Buffer.isBuffer(value) ? value.toString("utf8") : typeof value === "string" ? value : "")
  .join("\n");
let renewalAttempted = false;
while (Atomics.load(state, 1) === 0) {
  const deadline = Number(Atomics.load(confirmedExpiry, 0)) - workerData.safetyMs;
  const latestStart = deadline - workerData.commandTimeoutMs;
  const nowMs = Date.now();
  if (nowMs >= latestStart) {
    Atomics.compareExchange(state, 0, 0, 2);
    break;
  }
  if (renewalAttempted) {
    const wait = Atomics.wait(state, 1, 0, Math.min(workerData.intervalMs, latestStart - nowMs));
    if (wait !== "timed-out" || Atomics.load(state, 1) !== 0) break;
  }
  renewalAttempted = true;
  const now = Math.floor(Date.now() / 1000);
  const nextExpiry = Math.ceil(Date.now() / 1000) + workerData.leaseSeconds;
  try {
    execFileSync(workerData.awsBin, [
      "dynamodb",
      "update-item",
      "--table-name",
      workerData.table,
      "--key",
      JSON.stringify({ lockKey: { S: workerData.key } }),
      "--update-expression",
      "SET expiresAt = :expiresAt",
      "--condition-expression",
      "holder = :holder AND expiresAt >= :now",
      "--expression-attribute-values",
      JSON.stringify({ ":expiresAt": { N: String(nextExpiry) }, ":holder": { S: workerData.holder }, ":now": { N: String(now) } }),
      "--region",
      workerData.region,
      "--output",
      "text",
    ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: workerData.commandTimeoutMs });
    if (Date.now() >= deadline) {
      Atomics.compareExchange(state, 0, 0, 2);
      break;
    }
    Atomics.store(confirmedExpiry, 0, BigInt(nextExpiry * 1000));
  } catch (error) {
    if (conditional.test(output(error))) {
      Atomics.compareExchange(state, 0, 0, 1);
      break;
    }
    if (Date.now() >= latestStart) {
      Atomics.compareExchange(state, 0, 0, 2);
      break;
    }
    parentPort.postMessage("warning");
  }
}
`;

const activeAwsLease = new AsyncLocalStorage<AwsLease>();

export interface AwsLease {
  table: string;
  key: string;
  holder: string;
  state: Int32Array;
  confirmedExpiry: BigInt64Array;
  safetyMs: number;
  renewWorker?: Worker;
  renewStopped?: Promise<void>;
  releaseOnSignal?: () => void;
  releasePromise?: Promise<void>;
  operationDone?: Promise<void>;
  signalPromise?: Promise<void>;
  signalRequested?: boolean;
  operationStarted?: boolean;
  cleanupComplete?: boolean;
}

function leaseSeconds(): number {
  return Math.max(1, Math.floor(envNum("QM_AWS_LEASE_SECONDS", DEFAULT_LEASE_SECONDS)));
}

function assertLeaseHeld(lease: AwsLease): void {
  let status = Atomics.load(lease.state, 0);
  if (status === LEASE_HELD && Date.now() >= Number(Atomics.load(lease.confirmedExpiry, 0)) - lease.safetyMs) {
    const previous = Atomics.compareExchange(lease.state, 0, LEASE_HELD, LEASE_RENEWAL_FAILED);
    status = previous === LEASE_HELD ? LEASE_RENEWAL_FAILED : previous;
  }
  if (status === LEASE_LOST) {
    throw new CliError(`the ${JSON.stringify(lease.key)} AWS deployment lease was lost to another operation`);
  }
  if (status === LEASE_RENEWAL_FAILED) {
    throw new CliError(`the ${JSON.stringify(lease.key)} AWS deployment lease crossed its safe renewal deadline`);
  }
  if (status === LEASE_STOPPING) {
    throw new CliError(`the ${JSON.stringify(lease.key)} AWS deployment lease is stopping`);
  }
}

function markLeaseStopping(lease: AwsLease): void {
  Atomics.compareExchange(lease.state, 0, LEASE_HELD, LEASE_STOPPING);
}

export function assertAwsLeaseHeld(): void {
  const lease = activeAwsLease.getStore();
  if (lease) assertLeaseHeld(lease);
}

function nextEventLoopTurn(): Promise<void> {
  return new Promise((resolve) => setTimeout(() => setImmediate(resolve), 0));
}

export async function awsLeaseBoundary(): Promise<void> {
  const lease = activeAwsLease.getStore();
  if (!lease) return;
  assertLeaseHeld(lease);
  await nextEventLoopTurn();
  assertLeaseHeld(lease);
}

export async function awsLeaseOperation<T>(operation: () => T): Promise<T> {
  await awsLeaseBoundary();
  try {
    const result = operation();
    await awsLeaseBoundary();
    return result;
  } catch (error) {
    await awsLeaseBoundary();
    throw error;
  }
}

export function awsCaptureAsync(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; allow?: RegExp } = {},
): Promise<string> {
  return awsLeaseOperation(() => capture(command, args, options));
}

export function awsRunInheritAsync(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv } = {},
): Promise<void> {
  return awsLeaseOperation(() => runInherit(command, args, options));
}

export function awsCapture(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; allow?: RegExp } = {},
): string {
  assertAwsLeaseHeld();
  try {
    const result = capture(command, args, options);
    assertAwsLeaseHeld();
    return result;
  } catch (error) {
    assertAwsLeaseHeld();
    throw error;
  }
}

export function awsRunInherit(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv } = {},
): void {
  assertAwsLeaseHeld();
  try {
    runInherit(command, args, options);
    assertAwsLeaseHeld();
  } catch (error) {
    assertAwsLeaseHeld();
    throw error;
  }
}

function awsTextUnchecked(aws: AwsConfig, args: string[], input?: string): string {
  const command = process.env.AWS_BIN ?? "aws";
  const fullArgs = [...args, "--region", aws.region, "--output", "text"];
  if (input === undefined) return capture(command, fullArgs).trim();
  try {
    return execFileSync(command, fullArgs, {
      encoding: "utf8",
      input,
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    const processError = error as { stdout?: string; stderr?: string; message?: string };
    const output = `${processError.stdout ?? ""}${processError.stderr ?? ""}`;
    throw new Error(`${command} ${fullArgs.join(" ")} failed:\n${output || processError.message}`, { cause: error });
  }
}

export function awsText(aws: AwsConfig, args: string[], options: { input?: string } = {}): string {
  assertAwsLeaseHeld();
  try {
    const result = awsTextUnchecked(aws, args, options.input);
    assertAwsLeaseHeld();
    return result;
  } catch (error) {
    assertAwsLeaseHeld();
    throw error;
  }
}

export function awsTextAsync(aws: AwsConfig, args: string[], options: { input?: string } = {}): Promise<string> {
  return awsLeaseOperation(() => awsTextUnchecked(aws, args, options.input));
}

export function deployLocksTable(aws: AwsConfig): string {
  return `${aws.cluster}-deploy-locks`;
}

export function awsCliErrorMatches(error: unknown, code: string): boolean {
  const escaped = code.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return processErrorMatches(
    error,
    new RegExp(`(?:^|\\n)[ \\t]*(?:An error occurred \\(${escaped}\\) when calling\\b|${escaped}(?=[:\\r\\n]|$))`),
  );
}

function deleteLeaseItem(aws: AwsConfig, table: string, key: string, holder: string): void {
  awsTextUnchecked(aws, [
    "dynamodb",
    "delete-item",
    "--table-name",
    table,
    "--key",
    JSON.stringify({ lockKey: { S: key } }),
    "--condition-expression",
    "holder = :holder",
    "--expression-attribute-values",
    JSON.stringify({ ":holder": { S: holder } }),
  ]);
}

function startAwsLeaseRenewal(aws: AwsConfig, lease: AwsLease, seconds: number): void {
  const requestedInterval = envNum("QM_AWS_LEASE_RENEW_MS", (seconds / 3) * 1000);
  const leaseMs = seconds * 1000;
  const commandTimeoutMs = Math.max(
    1,
    Math.min(envNum("QM_AWS_LEASE_RENEW_TIMEOUT_MS", 30_000), Math.floor(leaseMs / 3)),
  );
  const safetyMs = Math.max(1, Math.min(Math.floor(leaseMs / 6), commandTimeoutMs + 5_000));
  const intervalMs = Math.max(1, Math.min(requestedInterval, leaseMs - safetyMs - commandTimeoutMs));
  lease.safetyMs = safetyMs;
  const worker = new Worker(RENEWER_SOURCE, {
    eval: true,
    execArgv: [],
    workerData: {
      awsBin: process.env.AWS_BIN ?? "aws",
      table: lease.table,
      key: lease.key,
      holder: lease.holder,
      region: aws.region,
      leaseSeconds: seconds,
      intervalMs,
      commandTimeoutMs,
      safetyMs,
      state: lease.state.buffer,
      confirmedExpiry: lease.confirmedExpiry.buffer,
    },
  });
  worker.unref();
  lease.renewWorker = worker;
  lease.renewStopped = new Promise((resolve) => {
    worker.once("exit", () => {
      if (
        Atomics.load(lease.state, 1) === 0 &&
        Atomics.compareExchange(lease.state, 0, LEASE_HELD, LEASE_RENEWAL_FAILED) === LEASE_HELD
      ) {
        warn(`the ${JSON.stringify(lease.key)} AWS deployment lease renewer stopped unexpectedly`);
      }
      resolve();
    });
  });
  worker.on("message", (message) => {
    if (message === "warning" && Atomics.load(lease.state, 1) === 0) {
      warn(`could not renew the ${JSON.stringify(lease.key)} AWS deployment lease; retrying before expiry`);
    }
  });
  worker.on("error", () => {
    if (
      Atomics.load(lease.state, 1) === 0 &&
      Atomics.compareExchange(lease.state, 0, LEASE_HELD, LEASE_RENEWAL_FAILED) === LEASE_HELD
    ) {
      warn(`the ${JSON.stringify(lease.key)} AWS deployment lease renewer stopped unexpectedly`);
    }
  });
}

async function stopAwsLeaseRenewal(lease: AwsLease): Promise<void> {
  const worker = lease.renewWorker;
  const stopped = lease.renewStopped;
  lease.renewWorker = undefined;
  lease.renewStopped = undefined;
  if (!worker || !stopped) return;
  worker.ref();
  markLeaseStopping(lease);
  Atomics.store(lease.state, 1, STOP_REQUESTED);
  Atomics.notify(lease.state, 1);
  const timeoutMs = Math.max(1, envNum("QM_AWS_LEASE_RENEW_STOP_TIMEOUT_MS", 35_000));
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<"timeout">((resolve) => {
    timeout = setTimeout(() => resolve("timeout"), timeoutMs);
  });
  const outcome = await Promise.race([stopped.then(() => "stopped" as const), timedOut]);
  if (timeout) clearTimeout(timeout);
  if (outcome === "timeout") {
    await worker.terminate();
    throw new CliError("could not stop the AWS deployment lease renewer cleanly");
  }
}

async function acquireAwsLeaseWithDrain(aws: AwsConfig, key: string, operationDone?: Promise<void>): Promise<AwsLease> {
  assertAwsLeaseHeld();
  const table = deployLocksTable(aws);
  const holder = randomUUID();
  const seconds = leaseSeconds();
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = Math.ceil(Date.now() / 1000) + seconds;
  const lease: AwsLease = {
    table,
    key,
    holder,
    state: new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2)),
    confirmedExpiry: new BigInt64Array(new SharedArrayBuffer(BigInt64Array.BYTES_PER_ELEMENT)),
    safetyMs: 1,
    ...(operationDone ? { operationDone } : {}),
  };
  Atomics.store(lease.confirmedExpiry, 0, BigInt(expiresAt * 1000));
  const onSignal = (): void => {
    lease.signalRequested = true;
    markLeaseStopping(lease);
    lease.renewWorker?.ref();
    lease.signalPromise ??= (lease.operationStarted ? (lease.operationDone ?? Promise.resolve()) : Promise.resolve())
      .then(() => (lease.cleanupComplete ? undefined : releaseAwsLease(aws, lease)))
      .catch((error) => warn(errMessage(error)))
      .then(() => process.exit(130));
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  lease.releaseOnSignal = () => {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
  };
  try {
    awsTextUnchecked(aws, [
      "dynamodb",
      "put-item",
      "--table-name",
      table,
      "--item",
      JSON.stringify({ lockKey: { S: key }, holder: { S: holder }, expiresAt: { N: String(expiresAt) } }),
      "--condition-expression",
      "attribute_not_exists(lockKey) OR expiresAt < :now",
      "--expression-attribute-values",
      JSON.stringify({ ":now": { N: String(now) } }),
    ]);
  } catch (error) {
    let failure: unknown = error;
    if (awsCliErrorMatches(error, "ConditionalCheckFailedException")) {
      failure = new CliError(
        `another QM operation holds the ${JSON.stringify(key)} lease in ${table}; it expires within ${Math.ceil(seconds / 60)} minutes, or delete that item to release it manually`,
      );
    } else {
      try {
        deleteLeaseItem(aws, table, key, holder);
      } catch (cleanupError) {
        if (!awsCliErrorMatches(cleanupError, "ConditionalCheckFailedException")) {
          failure = new CliError(
            `${errMessage(error)}; could not clean up an ambiguously acquired AWS deployment lease`,
            {
              cause: new AggregateError([error, cleanupError]),
            },
          );
        }
      }
    }
    lease.cleanupComplete = true;
    await nextEventLoopTurn();
    lease.releaseOnSignal?.();
    lease.releaseOnSignal = undefined;
    throw failure;
  }
  try {
    startAwsLeaseRenewal(aws, lease, seconds);
  } catch (error) {
    let failure: unknown = new CliError("could not start the AWS deployment lease renewer", { cause: error });
    try {
      deleteLeaseItem(aws, table, key, holder);
    } catch (cleanupError) {
      failure = new CliError("could not start the AWS deployment lease renewer or clean up its acquired lease", {
        cause: new AggregateError([error, cleanupError]),
      });
    }
    lease.cleanupComplete = true;
    await nextEventLoopTurn();
    lease.releaseOnSignal?.();
    lease.releaseOnSignal = undefined;
    throw failure;
  }
  try {
    await nextEventLoopTurn();
    assertLeaseHeld(lease);
  } catch (error) {
    let failure: unknown = error;
    try {
      await releaseAwsLease(aws, lease);
    } catch (cleanupError) {
      failure = new CliError(`${errMessage(error)}; could not clean up the acquired AWS deployment lease`, {
        cause: new AggregateError([error, cleanupError]),
      });
    }
    throw failure;
  }
  return lease;
}

export function acquireAwsLease(aws: AwsConfig, key = "deploy"): Promise<AwsLease> {
  return acquireAwsLeaseWithDrain(aws, key);
}

async function releaseAwsLeaseOnce(aws: AwsConfig, lease: AwsLease): Promise<void> {
  try {
    let stopError: unknown;
    try {
      await stopAwsLeaseRenewal(lease);
    } catch (error) {
      stopError = error;
    }
    let deleteError: unknown;
    try {
      deleteLeaseItem(aws, lease.table, lease.key, lease.holder);
    } catch (error) {
      deleteError = error;
    }
    await nextEventLoopTurn();
    if (deleteError) {
      const error = deleteError;
      const releaseError = new CliError("could not release the AWS deployment lease", { cause: error });
      if (stopError) {
        throw new CliError("could not stop or release the AWS deployment lease", {
          cause: new AggregateError([stopError, releaseError]),
        });
      }
      throw releaseError;
    }
    if (stopError) throw stopError;
  } finally {
    lease.cleanupComplete = true;
    lease.releaseOnSignal?.();
    lease.releaseOnSignal = undefined;
  }
}

export function releaseAwsLease(aws: AwsConfig, lease: AwsLease): Promise<void> {
  markLeaseStopping(lease);
  lease.releasePromise ??= releaseAwsLeaseOnce(aws, lease);
  return lease.releasePromise;
}

export async function withAwsLease<T>(aws: AwsConfig, operation: (lease: AwsLease) => Promise<T>): Promise<T> {
  let settleOperation!: () => void;
  const operationDone = new Promise<void>((resolve) => {
    settleOperation = resolve;
  });
  let lease: AwsLease;
  try {
    lease = await acquireAwsLeaseWithDrain(aws, "deploy", operationDone);
  } catch (error) {
    settleOperation();
    throw error;
  }
  lease.operationStarted = true;
  let result: T | undefined;
  let operationError: unknown;
  let operationFailed = false;
  try {
    result = await activeAwsLease.run(lease, async () => {
      await awsLeaseBoundary();
      try {
        return await operation(lease);
      } finally {
        await awsLeaseBoundary();
      }
    });
  } catch (error) {
    operationError = error;
    operationFailed = true;
  } finally {
    settleOperation();
  }
  try {
    await releaseAwsLease(aws, lease);
  } catch (releaseError) {
    if (operationFailed) {
      throw new CliError(`${errMessage(operationError)}; the AWS deployment lease could not be released`, {
        cause: new AggregateError([operationError, releaseError]),
      });
    }
    throw releaseError;
  }
  if (lease.signalRequested) {
    throw new CliError(`the ${JSON.stringify(lease.key)} AWS deployment lease stopped after a termination signal`);
  }
  if (operationFailed) throw operationError;
  return result as T;
}
