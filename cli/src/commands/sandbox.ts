import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildxInvocation, sourceBuildEnvironment, type BuildxInvocation } from "../buildx.ts";
import { CliError, bold, die, header, note, ok, warn } from "../log.ts";
import type { QmConfig } from "../config.ts";
import { sandboxBaseRef } from "../manifest.ts";
import { validateSandboxLayer, type SandboxValidation } from "../sandbox-layer.ts";
import { computedSecrets, deploymentStoreSecretValue } from "../secrets.ts";
import { readEnvFile, type FileIdentity } from "../util.ts";

const SANDBOX_RUNTIME_PLATFORM = "linux/amd64";

export interface SandboxBuildOpts {
  sandboxDir: string;
  config: QmConfig;
  configDir: string;
  configPath: string;
  configIdentity: FileIdentity;
  envFile?: string;
  from?: string;
  tag?: string;
  dryRun?: boolean;
}

interface PreparedBuild {
  sandboxDir: string;
  dockerfilePath: string;
  dockerfileBody: string;
  base: string;
  layer: SandboxValidation;
  binaries: string[];
  hasCustom: boolean;
  temporaryDirectories: string[];
}

interface DockerfileLogicalLine {
  text: string;
  start: number;
  end: number;
}

interface DockerfileFrom extends DockerfileLogicalLine {
  ref: string;
  alias?: string;
}

const FROM_RE = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?(?:\s+#.*)?\s*$/i;

interface DockerfileHeredoc {
  delimiter: string;
  stripTabs: boolean;
}

function dockerfileHeredocs(instruction: string): DockerfileHeredoc[] {
  const body = instruction.match(/^\s*(?:ONBUILD\s+)?(?:RUN|COPY|ADD)\b([\s\S]*)$/i)?.[1];
  if (body === undefined) return [];
  const out: DockerfileHeredoc[] = [];
  let quote: "'" | '"' | undefined;
  for (let i = 0; i < body.length; i++) {
    const char = body[i]!;
    if (quote) {
      if (char === quote) quote = undefined;
      else if (char === "\\" && quote === '"') i++;
      continue;
    }
    if (char === "\\") {
      i++;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "#" && (i === 0 || /\s/.test(body[i - 1]!))) break;
    if (char !== "<" || body[i + 1] !== "<" || body[i + 2] === "<") continue;
    i += 2;
    const stripTabs = body[i] === "-";
    if (stripTabs) i++;
    let delimiter = "";
    let delimiterQuote: "'" | '"' | undefined;
    let consumed = false;
    for (; i < body.length; i++) {
      const delimiterChar = body[i]!;
      if (delimiterQuote) {
        consumed = true;
        if (delimiterChar === delimiterQuote) {
          delimiterQuote = undefined;
        } else if (delimiterChar === "\\" && delimiterQuote === '"') {
          const next = body[i + 1];
          if (next === undefined) throw new CliError(`sandbox/Dockerfile has a malformed heredoc delimiter`);
          if ('$`"\\\n'.includes(next)) {
            delimiter += next;
            i++;
          } else {
            delimiter += delimiterChar;
          }
        } else {
          delimiter += delimiterChar;
        }
        continue;
      }
      if (/\s|[;&|<>]/.test(delimiterChar)) break;
      consumed = true;
      if (delimiterChar === "'" || delimiterChar === '"') {
        delimiterQuote = delimiterChar;
      } else if (delimiterChar === "\\") {
        const next = body[++i];
        if (next === undefined) throw new CliError(`sandbox/Dockerfile has a malformed heredoc delimiter`);
        delimiter += next;
      } else {
        delimiter += delimiterChar;
      }
    }
    if (!consumed || delimiterQuote || !delimiter)
      throw new CliError(`sandbox/Dockerfile has a malformed heredoc delimiter`);
    i--;
    out.push({ delimiter, stripTabs });
  }
  return out;
}

function dockerfileLogicalLines(body: string): DockerfileLogicalLine[] {
  const physical = body.match(/[^\n]*(?:\n|$)/g)?.filter((line) => line.length > 0) ?? [];
  let escape = "\\";
  let offset = 0;
  let pending = "";
  let pendingStart = 0;
  const out: DockerfileLogicalLine[] = [];
  let sawInstruction = false;

  for (let physicalIndex = 0; physicalIndex < physical.length; physicalIndex++) {
    const raw = physical[physicalIndex]!;
    const start = offset;
    offset += raw.length;
    const line = raw.endsWith("\n") ? raw.slice(0, -1).replace(/\r$/, "") : raw.replace(/\r$/, "");
    if (!pending && !sawInstruction) {
      const directive = line.match(/^#\s*escape=(\\|`)\s*$/i);
      if (directive) escape = directive[1]!;
      if (line.trim() && !line.trimStart().startsWith("#")) sawInstruction = true;
    }
    let escapes = 0;
    for (let i = line.length - 1; i >= 0 && line[i] === escape; i--) escapes++;
    const continued = escapes % 2 === 1;
    if (!pending) pendingStart = start;
    pending += continued ? `${line.slice(0, -1)} ` : line;
    if (continued) continue;
    const instruction = { text: pending, start: pendingStart, end: offset };
    out.push(instruction);
    pending = "";
    for (const heredoc of dockerfileHeredocs(instruction.text)) {
      let terminated = false;
      while (++physicalIndex < physical.length) {
        const heredocRaw = physical[physicalIndex]!;
        offset += heredocRaw.length;
        const heredocLine = heredocRaw.endsWith("\n")
          ? heredocRaw.slice(0, -1).replace(/\r$/, "")
          : heredocRaw.replace(/\r$/, "");
        const terminator = heredoc.stripTabs ? heredocLine.replace(/^\t+/, "") : heredocLine;
        if (terminator === heredoc.delimiter) {
          terminated = true;
          break;
        }
      }
      if (!terminated)
        throw new CliError(`sandbox/Dockerfile has an unterminated heredoc ${JSON.stringify(heredoc.delimiter)}`);
    }
  }
  if (pending) throw new CliError("sandbox/Dockerfile has an unterminated line continuation");
  return out;
}

function dockerfileFroms(body: string): DockerfileFrom[] {
  const froms: DockerfileFrom[] = [];
  for (const line of dockerfileLogicalLines(body)) {
    if (!/^\s*FROM(?:\s|$)/i.test(line.text)) continue;
    const match = line.text.match(FROM_RE);
    if (!match)
      throw new CliError(`sandbox/Dockerfile has an unsupported or malformed FROM instruction: ${line.text.trim()}`);
    froms.push({
      ...line,
      ref: match[1]!,
      ...(match[2] ? { alias: match[2] } : {}),
    });
  }
  if (!froms.length) throw new CliError("sandbox/Dockerfile must contain a FROM instruction");
  return froms;
}

function externalDockerfileBases(body: string): string[] {
  const stages = new Set<string>();
  const bases: string[] = [];
  for (const { ref, alias } of dockerfileFroms(body)) {
    if (ref.toLowerCase() !== "scratch" && !stages.has(ref.toLowerCase())) bases.push(ref);
    if (alias) stages.add(alias.toLowerCase());
  }
  return bases;
}

function prepare(opts: SandboxBuildOpts): PreparedBuild {
  const requestedSandboxDir = resolve(opts.sandboxDir);
  const layer = validateSandboxLayer(requestedSandboxDir);
  if (layer.errors.length) {
    throw new CliError(`sandbox check failed:\n${layer.errors.map((error) => `  - ${error}`).join("\n")}`);
  }
  const temporaryDirectories: string[] = [];
  try {
    let sandboxDir = requestedSandboxDir;
    if (!layer.exists) {
      sandboxDir = mkdtempSync(join(tmpdir(), "qm-sandbox-empty-"));
      temporaryDirectories.push(sandboxDir);
    }
    const hasCustom = layer.dockerfile !== undefined;
    const binaries = layer.tools.map((tool) => tool.binary);
    const presenceCheck = binaries.length
      ? `RUN for b in ${binaries.map((binary) => `'${binary}'`).join(" ")}; do command -v "$b" >/dev/null 2>&1 || { echo "sandbox build: tool binary $b is not on PATH" >&2; exit 1; }; done\n`
      : "";
    let base = opts.from ?? sandboxBaseRef();
    let dockerfileBody: string;
    if (hasCustom) {
      if (opts.from) warn("--from is ignored: sandbox/Dockerfile sets its own base image.");
      dockerfileBody = layer.dockerfile!.replace(/\n*$/, "\n") + presenceCheck;
      const declared = externalDockerfileBases(dockerfileBody);
      if (declared.some((ref) => ref.includes("$")))
        throw new CliError(
          "sandbox/Dockerfile FROM variables cannot be provenance-pinned; use an explicit image reference",
        );
      const mutable = [...new Set(declared.filter((ref) => !ref.includes("@sha256:")))];
      if (mutable.length > 1)
        throw new CliError("sandbox/Dockerfile has multiple mutable external base images; pin all but one by digest");
      if (mutable[0]) {
        base = mutable[0];
      } else if (declared[0]) base = declared[0];
      else base = "scratch";
    } else {
      const copies = layer.tools
        .filter((tool) => tool.executablePath)
        .map((tool) => `COPY tools/${tool.dir}/${tool.binary} /usr/local/bin/${tool.binary}`)
        .join("\n");
      const permissions = copies ? "\nRUN chmod -R a+rx /usr/local/bin" : "";
      dockerfileBody = `FROM ${base}\n${copies}${permissions}\n${presenceCheck}`;
    }
    const dockerfileDir = mkdtempSync(join(tmpdir(), "qm-sandbox-"));
    temporaryDirectories.push(dockerfileDir);
    const dockerfilePath = join(dockerfileDir, "Dockerfile");
    writeFileSync(dockerfilePath, dockerfileBody);
    return {
      sandboxDir,
      dockerfilePath,
      dockerfileBody,
      base,
      layer,
      binaries,
      hasCustom,
      temporaryDirectories,
    };
  } catch (error) {
    for (const directory of temporaryDirectories) rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

function cleanupPrepared(prepared: PreparedBuild): void {
  for (const directory of new Set(prepared.temporaryDirectories)) {
    rmSync(directory, { recursive: true, force: true });
  }
}

function runDocker(invocation: BuildxInvocation, failure: string): void {
  try {
    execFileSync(invocation.command, invocation.args, { stdio: "inherit", env: invocation.env });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      if (invocation.command === "docker") die("docker not found — install Docker with Buildx.");
      die("DOCKER_BUILDX_BIN executable not found — verify the configured standalone Buildx path.");
    }
    throw new CliError(failure);
  }
}

function sandboxBuildEnvironment(opts: SandboxBuildOpts, ambientEnv: Readonly<NodeJS.ProcessEnv>): NodeJS.ProcessEnv {
  if (opts.envFile !== undefined && !opts.envFile.trim()) {
    throw new CliError("--env-file needs a non-empty path", { clause: "cli.invocation" });
  }
  const environmentPath = resolve(opts.envFile ?? join(opts.configDir, ".env"));
  const fileValues = readEnvFile(environmentPath, {
    required: Boolean(opts.envFile),
    protectedIdentity: opts.configIdentity,
  });
  const secrets = computedSecrets(opts.config);
  return sourceBuildEnvironment(ambientEnv, {
    sensitiveNames: [...secrets.map((secret) => secret.name), "POSTGRES_PASSWORD"],
    sensitiveValues: [
      ...secrets.map((secret) => deploymentStoreSecretValue(secret.name, fileValues.get(secret.name), ambientEnv)),
      ambientEnv.POSTGRES_PASSWORD,
    ],
  });
}

function printBuild(prepared: PreparedBuild): void {
  note(`base:    ${prepared.hasCustom ? `${join(prepared.sandboxDir, "Dockerfile")} (custom)` : prepared.base}`);
  note(`context: ${prepared.sandboxDir}`);
  note(`tools:   ${prepared.binaries.length ? prepared.binaries.join(", ") : "(none)"}`);
}

export function runSandboxBuild(opts: SandboxBuildOpts): void {
  const environment = sandboxBuildEnvironment(opts, { ...process.env });
  const prepared = prepare(opts);
  try {
    const tag = opts.tag ?? `${opts.config.orgId}-sandbox:local`;
    const args = [
      "build",
      "--platform",
      SANDBOX_RUNTIME_PLATFORM,
      "--load",
      "--provenance=false",
      "-t",
      tag,
      "--file",
      prepared.dockerfilePath,
      prepared.sandboxDir,
    ];
    const invocation = buildxInvocation(args, environment);
    header(`qm sandbox build → ${tag}`);
    printBuild(prepared);
    if (opts.dryRun) {
      note(bold("\nDRY RUN — nothing built."));
      note(`\nDockerfile:\n${prepared.dockerfileBody}`);
      note(`${invocation.command} ${invocation.args.join(" ")}`);
      return;
    }
    runDocker(invocation, "sandbox build failed — a declared tool binary may be missing from PATH.");
    ok(`built local image ${tag}`);
  } finally {
    cleanupPrepared(prepared);
  }
}
