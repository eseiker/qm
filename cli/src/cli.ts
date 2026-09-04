import { spawnSync } from "node:child_process";
import { statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { CliError, bold, dim, errMessage, note, ok, red } from "./log.ts";
import {
  findConfigPath,
  isEmailTransport,
  isModelProvider,
  loadConfigAt,
  loadConfigInDir,
  readConfigOrgId,
  EMAIL_TRANSPORTS,
  MODEL_PROVIDERS,
  type EmailTransport,
  type ModelProvider,
} from "./config.ts";
import { HOSTING_PROVIDER_IDS, hostingProviderChoices, isTarget, type Target } from "./providers.ts";
import { type LogOpts } from "./services.ts";
import { runInit } from "./commands/init.ts";
import { runSetup } from "./commands/setup.ts";
import { runUpdate } from "./commands/update.ts";
import { runSandboxBuild } from "./commands/sandbox.ts";
import { runChecks, runCheckCommand } from "./commands/check.ts";
import { assertNodeEngine } from "./preflight.ts";
import { devCiDown, devCiUp } from "./backends/dev-ci.ts";
import {
  assertDeploymentEnvironmentDisjoint,
  hostingProvider,
  hostingProviderUpFlags,
  prepareUpSubstrate,
  type DeployContext,
} from "./backends/registry.ts";
import { runConformance } from "./commands/conformance.ts";
import { renderSlackFiles, runOutputs } from "./commands/outputs.ts";
import { cliVersion } from "./manifest.ts";
import {
  assertSecretByteLength,
  decodeUtf8,
  gitTopLevel,
  parseEnvFile,
  promptHidden,
  readEnvFile,
  readRegularFile,
  readRegularFileSnapshot,
  writeEnvValue,
} from "./util.ts";
import { scopeStorageKey } from "./scope-storage-key.ts";

interface Parsed {
  positionals: string[];
  flags: Record<string, string | boolean>;
}

type Flags = Parsed["flags"];

const BOOLEAN_FLAGS = new Set(["build-only", "ci", "dry-run", "f", "follow", "json", "live", "purge", "static", "yes"]);

function parse(args: string[]): Parsed {
  const positionals: string[] = [];
  const flags = Object.create(null) as Record<string, string | boolean>;
  let options = true;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (options && a === "--") {
      options = false;
    } else if (options && a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = a.slice(2, eq === -1 ? undefined : eq);
      if (Object.hasOwn(flags, name)) {
        throw new CliError(`--${name} may be specified only once`, { clause: "cli.invocation" });
      }
      if (BOOLEAN_FLAGS.has(name)) {
        if (eq !== -1) {
          if (name !== "ci") throw new CliError(`--${name} does not take a value`, { clause: "cli.invocation" });
          flags[name] = a.slice(eq + 1);
        } else flags[name] = true;
      } else if (eq !== -1) flags[name] = a.slice(eq + 1);
      else {
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith("-")) {
          flags[name] = next;
          i++;
        } else flags[name] = true;
      }
    } else if (options && a.startsWith("-") && a.length > 1) {
      const name = a.slice(1);
      if (Object.hasOwn(flags, name)) {
        throw new CliError(`-${name} may be specified only once`, { clause: "cli.invocation" });
      }
      flags[name] = true;
    } else positionals.push(a);
  }
  return { positionals, flags };
}

function strFlag(flags: Flags, name: string): string | undefined {
  const v = flags[name];
  if (v === undefined) return undefined;
  if (typeof v !== "string") throw new CliError(`--${name} needs a value`, { clause: "cli.invocation" });
  if (!v.trim()) throw new CliError(`--${name} needs a non-empty value`, { clause: "cli.invocation" });
  return v;
}

function pathOperand(value: string | undefined, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (!value.trim()) throw new CliError(`${label} needs a non-empty path`, { clause: "cli.invocation" });
  if (value.includes("\0"))
    throw new CliError(`${label} path must not contain a NUL byte`, { clause: "cli.invocation" });
  return value;
}

function pathFlag(flags: Flags, name: string): string | undefined {
  const value = flags[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new CliError(`--${name} needs a value`, { clause: "cli.invocation" });
  return pathOperand(value, `--${name}`);
}

function existingDirectoryPath(path: string, label: string): string {
  try {
    if (!statSync(path).isDirectory()) throw new Error("not a directory");
  } catch (error) {
    throw new CliError(`${label} must point to an existing directory`, {
      cause: error,
      clause: "cli.invocation",
    });
  }
  return path;
}

function readableFileContents(path: string, label: string): Buffer {
  try {
    return readRegularFile(path);
  } catch (error) {
    throw new CliError(`${label} must point to an existing readable regular file`, {
      cause: error,
      clause: "cli.invocation",
    });
  }
}

const boolFlag = (flags: Flags, name: string): boolean => flags[name] === true;

function targetFlag(flags: Flags): Target | undefined {
  const target = strFlag(flags, "target");
  if (target !== undefined && !isTarget(target)) throw new CliError(`--target must be ${hostingProviderChoices()}`);
  return target;
}

function modelProviderFlag(flags: Flags): ModelProvider | undefined {
  const provider = strFlag(flags, "model-provider");
  if (provider !== undefined && !isModelProvider(provider)) {
    throw new CliError(`--model-provider must be ${MODEL_PROVIDERS.join(" | ")}`, { clause: "cli.invocation" });
  }
  return provider;
}

function emailTransportFlag(flags: Flags): EmailTransport | undefined {
  const transport = strFlag(flags, "email-transport");
  if (transport !== undefined && !isEmailTransport(transport)) {
    throw new CliError(`--email-transport must be ${EMAIL_TRANSPORTS.join(" | ")}`, { clause: "cli.invocation" });
  }
  return transport;
}

function version(): string {
  return cliVersion();
}

const CLI_NAME = "qm";

const HELP = `${bold(CLI_NAME)} — control-plane CLI for a QM deployment

${bold("USAGE")}
  ${CLI_NAME} <command> [options]
  ${CLI_NAME} help | version

${bold("DEPLOY (operator)")} ${dim("— runs in the deployment directory")}
  init [path] [--org <id>] [--target ${HOSTING_PROVIDER_IDS.join("|")}]
       [--model-provider ${MODEL_PROVIDERS.join("|")}]
       [--email-transport ${EMAIL_TRANSPORTS.join("|")}]
                                           scaffold a deployment directory (the base model
                                           provider defaults to anthropic; its API key is a
                                           required secret; sign-in emails default to resend,
                                           and only the chosen transport's keys are scaffolded)
  setup [path]                             interactive wizard: scaffold if needed, then walk the
                                           missing secrets with per-provider instructions
  update [--yes] [--version <version>]     check npm's current stable QM release; --yes requires
                                           the exact version, updates its substrate, and deploys
  up                                       build images and bring the deployment up
     --build-from[=<qm-repo>]              build from local Dockerfiles instead of pulling
     --dry-run                             resolve the config + report the plan, change nothing
  plan                                     an alias for up --dry-run
  check                                    validate config + sandbox/ (skills & tools); no build; verifies
                                           provider credentials whose values are present locally
    --json                                 machine-readable results keyed by contract clause
    --live                                 verify running identity, rendered config, and health
  doctor                                   verify deployment prerequisites read-only
  config get <dot.path>                    print one config value (raw scalar, JSON otherwise)
  slack render                             render the bot manifest (+ SSO manifest for Slack OIDC)
  outputs [--json]                         print the Web UI, health, and Slack app creation links
  proof scope-key <scope-id>               derive the provider snapshot key for an exact scope
  infra render                             re-derive infra/terraform.tfvars from config
  infra build-image                        build the AWS deploy MicroVM image and record its pin
  infra delete-image --yes                 terminate its MicroVMs and delete the AWS deploy image
  infra delete-task-definitions --yes      delete the stack's AWS ECS task definition revisions
  conformance [dir] [--static]             run static gates and compare the live resolved layer
  secrets push [--from <env-file>]         upload the computed secret set to the target store
  secrets set <KEY> [<value>]              write one .env value in place (dedupes the key, keeps
     [--from-file <path>]                  order and file mode); reads stdin or prompts when no
                                           value is given, so the secret never hits shell history
  status                                   show what's running
  logs [<service>] [-f] [--tail <n>]       tail service logs (omit <service> for all, interleaved)
  down [--purge]                           stop the deployment (--purge drops docker volumes)
  rollback [--to <target>]                 roll back AWS workloads to a prior deployment manifest
                                           or manifest id/release label
  sandbox build [--from <img>] [--tag <t>] [--dry-run]
                                           build and validate the sandbox image locally

  ${dim("Options (apply to all deploy commands):")}
    --config <path>                        path to deploy config (default: qm.config.jsonc in deploy dir)
    --env-file <path>                      path to .env (default: .env in the deploy dir)
    --sandbox-dir <path>                   path to the sandbox layer dir (default: sandbox/ in the deploy dir)

${bold("DEVELOP (contributor)")} ${dim("— runs in the QM repo")}
  dev up [--org <id>] · dev down · dev status · dev restart · dev canary · dev logs · dev doctor [options]
                                           run the supervised contributor engine in scripts/dev/
  dev --ci [up|down]                       CI mode: core only (Slack in-process), no pool lease (live-e2e)

  help · version

${dim("target is set in the config: docker runs local containers, fly deploys Fly apps, and aws deploys ECS.")}
${dim("status/logs/down act on the configured target; agent computers use the sandbox backend selected in config.")}
`;

const deploymentBackend = (ctx: DeployContext) => hostingProvider(ctx.target).createBackend(ctx);

function deployContext(flags: Flags, dir?: string, opts: { allowMissingEnvFile?: boolean } = {}): DeployContext {
  const explicit = pathFlag(flags, "config");
  const envFile = pathFlag(flags, "env-file");
  const explicitSandboxDir = pathFlag(flags, "sandbox-dir");
  const resolvedSandboxDir =
    explicitSandboxDir === undefined ? undefined : existingDirectoryPath(resolve(explicitSandboxDir), "--sandbox-dir");
  const target = targetFlag(flags);
  const loaded =
    explicit !== undefined
      ? loadConfigAt(explicit, target ? { target } : undefined)
      : loadConfigInDir(resolve(dir ?? process.cwd()), target ? { target } : undefined);
  const configDir = dirname(loaded.path);
  const sandboxDir = resolvedSandboxDir ?? resolve(join(configDir, "sandbox"));
  const ctx: DeployContext = {
    config: loaded.config,
    configPath: loaded.path,
    configIdentity: loaded.configIdentity,
    configDir,
    sandboxDir,
    target: loaded.config.target,
    ...(envFile !== undefined ? { envFile } : {}),
  };
  assertDeploymentEnvironmentDisjoint(ctx, opts.allowMissingEnvFile);
  return ctx;
}

function rejectUnknownFlags(flags: Flags, allowed: readonly string[]): void {
  const unknown = Object.keys(flags).filter((name) => !allowed.includes(name));
  if (unknown.length)
    throw new CliError(
      `unknown option${unknown.length === 1 ? "" : "s"}: ${unknown.map((name) => `--${name}`).join(", ")}`,
      { clause: "cli.invocation" },
    );
}

function rejectExtraPositionals(positionals: readonly string[], maximum: number): void {
  if (positionals.length <= maximum) return;
  throw new CliError(
    `unexpected argument${positionals.length - maximum === 1 ? "" : "s"}: ${positionals
      .slice(maximum)
      .map((value) => JSON.stringify(value))
      .join(", ")}`,
    { clause: "cli.invocation" },
  );
}

function intFlag(flags: Flags, name: string): number | undefined {
  const s = strFlag(flags, name);
  if (s === undefined) return undefined;
  if (!/^\d+$/.test(s)) throw new CliError(`--${name} must be a non-negative integer`, { clause: "cli.invocation" });
  return Number(s);
}

const followFlag = (flags: Flags): boolean => boolFlag(flags, "f") || boolFlag(flags, "follow");

function logOpts(flags: Flags): LogOpts {
  const tail = intFlag(flags, "tail");
  return { follow: followFlag(flags), ...(tail !== undefined ? { tail } : {}) };
}

async function dispatch(argv: string[]): Promise<void> {
  const cmd = argv[0];
  const { positionals, flags } = parse(argv.slice(1));

  switch (cmd) {
    case undefined:
      rejectUnknownFlags(flags, []);
      rejectExtraPositionals(positionals, 0);
      note(HELP);
      return;

    case "help":
    case "--help":
    case "-h": {
      rejectUnknownFlags(flags, []);
      rejectExtraPositionals(positionals, 0);
      note(HELP);
      return;
    }

    case "version":
    case "--version":
    case "-v": {
      rejectUnknownFlags(flags, []);
      rejectExtraPositionals(positionals, 0);
      note(version());
      return;
    }

    case "init": {
      rejectUnknownFlags(flags, ["org", "target", "model-provider", "email-transport"]);
      rejectExtraPositionals(positionals, 1);
      const target = targetFlag(flags);
      const modelProvider = modelProviderFlag(flags);
      const emailTransport = emailTransportFlag(flags);
      const org = strFlag(flags, "org");
      const dir = resolve(pathOperand(positionals[0], "init path") ?? process.cwd());
      runInit({
        dir,
        ...(org !== undefined ? { org } : {}),
        ...(target ? { target } : {}),
        ...(modelProvider ? { modelProvider } : {}),
        ...(emailTransport ? { emailTransport } : {}),
      });
      return;
    }

    case "setup": {
      rejectUnknownFlags(flags, []);
      rejectExtraPositionals(positionals, 1);
      await runSetup({ dir: resolve(pathOperand(positionals[0], "setup path") ?? process.cwd()) });
      return;
    }

    case "update": {
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target", "yes", "version"]);
      rejectExtraPositionals(positionals, 0);
      const requestedVersion = strFlag(flags, "version");
      const ctx = deployContext(flags);
      await runUpdate({
        config: ctx.config,
        configDir: ctx.configDir,
        configPath: ctx.configPath,
        sandboxDir: ctx.sandboxDir,
        ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
        target: ctx.target,
        yes: boolFlag(flags, "yes"),
        ...(requestedVersion !== undefined ? { version: requestedVersion } : {}),
      });
      return;
    }

    case "dev": {
      if (flags.ci !== undefined) {
        rejectUnknownFlags(flags, ["ci"]);
        const explicitCiSub = typeof flags.ci === "string" ? flags.ci : undefined;
        rejectExtraPositionals(positionals, explicitCiSub === undefined ? 1 : 0);
        const sub = explicitCiSub ?? positionals[0] ?? "up";
        if (sub === "up") return devCiUp();
        if (sub === "down") return devCiDown();
        throw new CliError(`'dev --ci' supports up|down (got: ${sub})`);
      }
      rejectUnknownFlags(flags, [
        "json",
        "force",
        "strict",
        "rotate",
        "f",
        "follow",
        "fix",
        "sandbox",
        "no-watch",
        "org",
      ]);
      if (!["up", "down", "status", "restart", "canary", "logs", "doctor"].includes(positionals[0] ?? "up"))
        rejectExtraPositionals(positionals, 1);
      const root = gitTopLevel();
      const configPath = findConfigPath(root);
      const orgId = strFlag(flags, "org") ?? (configPath && readConfigOrgId(configPath)) ?? "acme";
      const result = spawnSync(process.execPath, [join(root, "scripts/dev/cli.ts"), ...argv.slice(1)], {
        cwd: root,
        stdio: "inherit",
        env: { ...process.env, DEV_INSTANCE_ORG_ID: orgId },
      });
      if (result.error) throw result.error;
      process.exitCode = result.status ?? 1;
      return;
    }

    case "check": {
      if (boolFlag(flags, "json")) {
        try {
          rejectUnknownFlags(flags, ["json", "live", "config", "env-file", "sandbox-dir", "target"]);
          rejectExtraPositionals(positionals, 0);
          const ctx = deployContext(flags);
          assertNodeEngine(ctx.configDir);
          const result = runChecks(ctx.config, ctx.configDir, ctx.sandboxDir, { report: false });
          if (boolFlag(flags, "live")) {
            const checkLive = deploymentBackend(ctx).checkLive;
            if (!checkLive)
              throw new CliError(`check --live is not implemented for target ${ctx.target}`, {
                clause: "cli.invocation",
              });
            await checkLive({ report: false });
          }
          const live = boolFlag(flags, "live");
          note(
            JSON.stringify({
              contract: 1,
              valid: true,
              clauses: {
                "config.v1": { status: "pass" },
                "sandbox.descriptors": { status: "pass", warnings: result.layer.warnings },
                "plugins.resolved": { status: "pass", count: result.plugins.length },
                "secrets.computed-set": { status: "pass", names: result.secrets.map((secret) => secret.name) },
                ...(live
                  ? {
                      [ctx.target === "fly" ? "fly.live-readiness" : `${ctx.target}.live-drift`]: { status: "pass" },
                    }
                  : {}),
              },
            }),
          );
        } catch (error) {
          if (error instanceof CliError) {
            const problems = error.problems ?? [{ clause: error.clause ?? "config.v1", message: error.message }];
            const clauses: Record<string, { status: "fail" | "error"; errors: string[] }> = {};
            for (const problem of problems) {
              const entry = (clauses[problem.clause] ??= {
                status: problem.clause === "cli.invocation" ? "error" : "fail",
                errors: [],
              });
              entry.errors.push(...problem.message.split("\n").filter(Boolean));
            }
            note(JSON.stringify({ contract: 1, valid: false, clauses }));
            process.exit(clauses["cli.invocation"] ? 2 : 1);
          } else {
            note(
              JSON.stringify({
                contract: 1,
                valid: false,
                clauses: { "cli.internal": { status: "error", errors: [errMessage(error)] } },
              }),
            );
            process.exit(2);
          }
        }
        return;
      }
      rejectUnknownFlags(flags, ["json", "live", "config", "env-file", "sandbox-dir", "target"]);
      rejectExtraPositionals(positionals, 0);
      const ctx = deployContext(flags);
      if (boolFlag(flags, "live")) {
        const checkLive = deploymentBackend(ctx).checkLive;
        if (!checkLive)
          throw new CliError(`check --live is not implemented for target ${ctx.target}`, { clause: "cli.invocation" });
        await runCheckCommand(ctx.config, ctx.configDir, ctx.sandboxDir, ctx.envFile, ctx.configIdentity);
        await checkLive();
        return;
      }
      await runCheckCommand(ctx.config, ctx.configDir, ctx.sandboxDir, ctx.envFile, ctx.configIdentity);
      return;
    }

    case "config": {
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target"]);
      rejectExtraPositionals(positionals, 2);
      const path = positionals[1];
      if (positionals[0] !== "get" || path === undefined) {
        throw new CliError(`usage: ${CLI_NAME} config get <dot.path>`, { clause: "cli.invocation" });
      }
      const ctx = deployContext(flags);
      let value: unknown = ctx.config;
      for (const key of path.split(".")) {
        value =
          value !== null && typeof value === "object" && Object.hasOwn(value, key)
            ? (value as Record<string, unknown>)[key]
            : undefined;
        if (value === undefined) throw new CliError(`config get: "${path}" is not set in ${ctx.configPath}`);
      }
      note(typeof value === "object" ? JSON.stringify(value) : String(value));
      return;
    }

    case "slack": {
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target"]);
      rejectExtraPositionals(positionals, 1);
      if (positionals[0] !== "render") throw new CliError(`usage: ${CLI_NAME} slack render`);
      const ctx = deployContext(flags);
      renderSlackFiles(ctx.config, ctx.configDir);
      return;
    }

    case "outputs": {
      rejectUnknownFlags(flags, ["json", "config", "env-file", "sandbox-dir", "target"]);
      rejectExtraPositionals(positionals, 0);
      const ctx = deployContext(flags);
      runOutputs(ctx.config, ctx.configDir, boolFlag(flags, "json"));
      return;
    }

    case "conformance": {
      rejectUnknownFlags(flags, ["static", "config", "env-file", "sandbox-dir", "target"]);
      rejectExtraPositionals(positionals, 1);
      const ctx = deployContext(flags, pathOperand(positionals[0], "conformance directory"));
      await runConformance(ctx, { runtime: !boolFlag(flags, "static") });
      return;
    }

    case "infra": {
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target", "yes"]);
      rejectExtraPositionals(positionals, 1);
      const operation = positionals[0];
      if (
        operation !== "render" &&
        operation !== "build-image" &&
        operation !== "delete-image" &&
        operation !== "delete-task-definitions"
      ) {
        throw new CliError(`usage: ${CLI_NAME} infra render|build-image|delete-image|delete-task-definitions`);
      }
      const ctx = deployContext(flags);
      const run = hostingProvider(ctx.target).infra?.[operation];
      if (!run) throw new CliError(`infra ${operation} is not available for target ${ctx.target}`);
      if (operation === "delete-image" || operation === "delete-task-definitions") {
        if (!boolFlag(flags, "yes"))
          throw new CliError(`infra ${operation} requires --yes`, { clause: "cli.invocation" });
      }
      if (operation === "render") runChecks(ctx.config, ctx.configDir, ctx.sandboxDir, { report: false });
      await run(ctx);
      return;
    }

    case "up":
    case "plan": {
      const common = ["config", "env-file", "sandbox-dir", "target", "dry-run"];
      rejectUnknownFlags(flags, [...common, ...hostingProviderUpFlags()]);
      rejectExtraPositionals(positionals, 0);
      if (typeof flags["build-from"] === "string") pathOperand(flags["build-from"], "--build-from");
      const dryRun = cmd === "plan" || boolFlag(flags, "dry-run");
      let ctx = deployContext(flags);
      const provider = hostingProvider(ctx.target);
      rejectUnknownFlags(flags, [...common, ...provider.upFlags]);
      const upOptions = provider.upOptions(ctx, flags, dryRun);
      runChecks(ctx.config, ctx.configDir, ctx.sandboxDir, { report: false });
      ctx = await provider.preflightUp(ctx, upOptions);
      ctx = await prepareUpSubstrate(ctx, upOptions);
      await provider.createBackend(ctx).up(upOptions);
      return;
    }

    case "sandbox": {
      const sub = positionals[0];
      if (sub === "publish") {
        throw new CliError(
          "sandbox publish is unavailable because the supported sandbox backends do not consume OCI layer images",
        );
      }
      if (sub !== "build") {
        throw new CliError(`usage: ${CLI_NAME} sandbox build [--from <image>] [--tag <label>] [--dry-run]`);
      }
      rejectExtraPositionals(positionals, 1);
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target", "from", "tag", "dry-run"]);
      const ctx = deployContext(flags);
      runChecks(ctx.config, ctx.configDir, ctx.sandboxDir, { report: false });
      const from = strFlag(flags, "from");
      const tag = strFlag(flags, "tag");
      const common = {
        sandboxDir: ctx.sandboxDir,
        config: ctx.config,
        configDir: ctx.configDir,
        configPath: ctx.configPath,
        configIdentity: ctx.configIdentity,
        ...(ctx.envFile !== undefined ? { envFile: ctx.envFile } : {}),
        ...(from !== undefined ? { from } : {}),
        ...(tag !== undefined ? { tag } : {}),
        dryRun: boolFlag(flags, "dry-run"),
      };
      runSandboxBuild(common);
      return;
    }

    case "status": {
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target"]);
      rejectExtraPositionals(positionals, 0);
      const ctx = deployContext(flags);
      return deploymentBackend(ctx).status();
    }

    case "logs": {
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target", "f", "follow", "tail"]);
      rejectExtraPositionals(positionals, 1);
      const ctx = deployContext(flags);
      const service = positionals[0];
      const opts = logOpts(flags);
      return deploymentBackend(ctx).logs(service, opts);
    }

    case "down": {
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target", "purge"]);
      rejectExtraPositionals(positionals, 0);
      const ctx = deployContext(flags);
      return deploymentBackend(ctx).down({ purge: boolFlag(flags, "purge") });
    }

    case "rollback": {
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target", "to"]);
      rejectExtraPositionals(positionals, 0);
      const ctx = deployContext(flags);
      return deploymentBackend(ctx).rollback(strFlag(flags, "to"));
    }

    case "doctor": {
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target"]);
      rejectExtraPositionals(positionals, 0);
      const ctx = deployContext(flags);
      runChecks(ctx.config, ctx.configDir, ctx.sandboxDir, { report: false });
      await deploymentBackend(ctx).doctor();
      note(`doctor: ${ctx.target} prerequisites are ready`);
      return;
    }

    case "proof": {
      if (positionals[0] !== "scope-key") throw new CliError(`usage: ${CLI_NAME} proof scope-key <scope-id>`);
      rejectUnknownFlags(flags, []);
      rejectExtraPositionals(positionals, 2);
      const scope = positionals[1];
      if (!scope) throw new CliError(`usage: ${CLI_NAME} proof scope-key <scope-id>`);
      note(scopeStorageKey(scope));
      return;
    }

    case "secrets": {
      if (positionals[0] === "set") {
        rejectExtraPositionals(positionals, 3);
        rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target", "from-file"]);
        const key = positionals[1];
        if (!key) {
          throw new CliError(`usage: ${CLI_NAME} secrets set <KEY> [<value>] [--from-file <path>]`, {
            clause: "cli.invocation",
          });
        }
        const requestedFromFile = pathFlag(flags, "from-file");
        if (positionals[2] !== undefined && requestedFromFile !== undefined) {
          throw new CliError(`secrets set takes a value argument or --from-file, not both`, {
            clause: "cli.invocation",
          });
        }
        let fromFileValue: string | undefined;
        if (requestedFromFile !== undefined) {
          try {
            fromFileValue = decodeUtf8(readableFileContents(requestedFromFile, "--from-file"));
          } catch (error) {
            if (error instanceof CliError && error.clause === "cli.invocation") throw error;
            throw new CliError(errMessage(error), { cause: error, clause: "cli.invocation" });
          }
        }
        const ctx = deployContext(flags, undefined, { allowMissingEnvFile: true });
        let value = positionals[2] ?? fromFileValue;
        if (value === undefined) value = process.stdin.isTTY ? await promptHidden(key) : await readStdin();
        value = value.replace(/\r?\n$/, "");
        if (!value) throw new CliError(`secrets set: no value provided for ${key}`, { clause: "cli.invocation" });
        assertSecretByteLength(key, value);
        const envPath = ctx.envFile ?? join(ctx.configDir, ".env");
        writeEnvValue(envPath, key, value, ctx.configPath);
        ok(`set ${key} in ${envPath}`);
        return;
      }
      if (positionals[0] !== "push") {
        throw new CliError(
          `usage: ${CLI_NAME} secrets push [--from <env-file>] | secrets set <KEY> [<value>] [--from-file <path>]`,
        );
      }
      rejectExtraPositionals(positionals, 1);
      rejectUnknownFlags(flags, ["config", "env-file", "sandbox-dir", "target", "from"]);
      const source = pathFlag(flags, "from");
      let sourceValues: Map<string, string> | undefined;
      let sourceIdentity: { dev: bigint; ino: bigint } | undefined;
      if (source !== undefined) {
        try {
          const snapshot = readRegularFileSnapshot(source);
          sourceIdentity = snapshot.identity;
          sourceValues = parseEnvFile(snapshot.content);
        } catch (error) {
          throw new CliError(
            `--from must point to an existing readable regular file containing a UTF-8 deployment environment: ${errMessage(error)}`,
            {
              cause: error,
              clause: "cli.invocation",
            },
          );
        }
      }
      const ctx = deployContext(flags);
      if (
        sourceIdentity !== undefined &&
        sourceIdentity.dev === ctx.configIdentity.dev &&
        sourceIdentity.ino === ctx.configIdentity.ino
      ) {
        throw new CliError("deployment environment file must be separate from the deployment config");
      }
      const values =
        sourceValues ??
        readEnvFile(ctx.envFile ?? join(ctx.configDir, ".env"), {
          required: ctx.envFile !== undefined,
          protectedIdentity: ctx.configIdentity,
        });
      await deploymentBackend(ctx).secretsPush(values);
      return;
    }

    default:
      throw new CliError(`unknown command: ${cmd}\n\n${HELP}`);
  }
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  try {
    return decodeUtf8(Buffer.concat(chunks));
  } catch (error) {
    throw new CliError(errMessage(error), { cause: error, clause: "cli.invocation" });
  }
}

export async function main(argv: string[]): Promise<void> {
  try {
    await dispatch(argv);
  } catch (e) {
    if (e instanceof CliError) {
      console.error(`${red("error")}: ${e.message}`);
      process.exit(e.clause === "cli.invocation" ? 2 : 1);
    }
    throw e;
  }
}
