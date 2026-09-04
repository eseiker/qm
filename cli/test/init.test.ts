import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInit } from "../src/commands/init.ts";
import { CONFIG_FILENAME, loadConfigInDir } from "../src/config.ts";
import { cliVersion } from "../src/manifest.ts";
import { parseToolDescriptor, validateSandboxLayer } from "../src/sandbox-layer.ts";
import { SERVICE_NAMES, VIRTUAL_SERVICE_NAMES } from "../src/services.ts";
import { renderEnvExample } from "../src/secrets.ts";
import { runChecks } from "../src/commands/check.ts";
import { renderTerraformVars } from "../src/terraform.ts";
import { requiredSlackScopes, slackManifestBotScopes } from "../src/backends/doctor.ts";

function quiet<T>(fn: () => T): T {
  const log = console.log,
    warn = console.warn;
  console.log = (): void => {};
  console.warn = (): void => {};
  try {
    return fn();
  } finally {
    console.log = log;
    console.warn = warn;
  }
}

function captureInit(opts: Parameters<typeof runInit>[0]): string {
  const lines: string[] = [];
  const log = console.log,
    warn = console.warn;
  console.log = (...args: unknown[]): void => void lines.push(args.join(" "));
  console.warn = (...args: unknown[]): void => void lines.push(args.join(" "));
  try {
    runInit(opts);
    return lines.join("\n");
  } finally {
    console.log = log;
    console.warn = warn;
  }
}

function withProcessEnv(values: Record<string, string>, fn: () => void): void {
  const previous = new Map(Object.keys(values).map((name) => [name, process.env[name]]));
  try {
    Object.assign(process.env, values);
    fn();
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

function assertNoScaffoldFiles(dir: string): void {
  assert.deepEqual(
    readdirSync(dir).filter((name) => name !== ".git"),
    [],
  );
}

test("init scaffolds a loadable config, generated local secrets, and a valid sandbox/ layer", () => {
  const base = mkdtempSync(join(tmpdir(), "qm-init-"));
  try {
    const dir = join(base, "nested", "acme");
    quiet(() => runInit({ dir, org: "acme", target: "docker" }));

    const configRaw = readFileSync(join(dir, CONFIG_FILENAME), "utf8");
    assert.match(configRaw, /^\s*\/\//m, "the scaffolded config carries field comments");
    for (const service of [...SERVICE_NAMES, ...VIRTUAL_SERVICE_NAMES]) {
      assert.ok(configRaw.includes(`"${service}"`), `the config's services comment should describe ${service}`);
    }
    const { config } = loadConfigInDir(dir);
    assert.equal(config.orgId, "acme");
    assert.equal(config.target, "docker");
    assert.equal(config.publicUrl, "http://localhost:8082");
    assert.equal(config.env.core?.HARNESS, "pi");
    assert.equal(config.modelProvider, "anthropic", "init names a base model provider by default");
    assert.deepEqual(config.sandbox, { backend: "local" });

    const env = readFileSync(join(dir, ".env.example"), "utf8");
    assert.equal(env, renderEnvExample(config), ".env.example is exactly renderEnvExample output");
    // The scaffold names anthropic as the base model provider, so its key is required
    // rather than deferred to Admin; the providers not selected stay optional.
    for (const line of ["CORE_SIGNING_SECRET=", "SKILL_SIGNING_SECRET=", "ANTHROPIC_API_KEY="]) {
      assert.ok(env.split("\n").includes(line), `.env.example should require ${line}`);
    }
    for (const line of ["# OPENROUTER_API_KEY=  # optional"]) {
      assert.ok(env.split("\n").includes(line), `.env.example should offer ${line}`);
    }
    // OPENAI_API_KEY answers to two independent rules; the catalog lists both so neither
    // route to requiring it is hidden behind the other.
    assert.match(env, /# Needed when env\.core\.HARNESS is "codex" or modelProvider is "openai"/);
    assert.ok(env.split("\n").includes("# OPENAI_API_KEY="));
    assert.ok(env.includes("# Generate with: openssl rand -hex 32"), "mintable secrets carry their generation command");
    const localEnv = readFileSync(join(dir, ".env"), "utf8");
    const coreSecret = localEnv.match(/^CORE_SIGNING_SECRET=([a-f0-9]{64})$/m)?.[1];
    const skillSecret = localEnv.match(/^SKILL_SIGNING_SECRET=([a-f0-9]{64})$/m)?.[1];
    assert.ok(coreSecret, "init generates a strong core signing key");
    assert.ok(skillSecret, "init generates a strong skill signing key");
    assert.notEqual(coreSecret, skillSecret, "generated keys are independent");
    assert.equal(statSync(join(dir, ".env")).mode & 0o777, 0o600, ".env is owner-readable only");
    for (const stale of ["HARNESS=", "ORG_ID=", "PORT=", "SESSION_STORE"]) {
      assert.ok(!env.includes(stale), `.env.example should not offer ${stale} as a value to fill in`);
    }

    const gitignore = readFileSync(join(dir, ".gitignore"), "utf8").split("\n");
    assert.ok(gitignore.includes(".env"), ".gitignore should cover .env");

    const agentsMd = readFileSync(join(dir, "AGENTS.md"), "utf8");
    for (const piece of [
      CONFIG_FILENAME,
      ".env.example",
      "sandbox/",
      "npm exec --yes=false -- qm check",
      "npm exec --yes=false -- qm up",
    ]) {
      assert.ok(agentsMd.includes(piece), `AGENTS.md should mention ${piece}`);
    }
    assert.doesNotMatch(env, /ORG_ID=|PORT=|HARNESS=/);
    const manifest = readFileSync(join(dir, "slack-app-manifest.yml"), "utf8");
    assert.match(manifest, /^ {2}name: qm$/m);
    assert.match(manifest, /^ {4}display_name: qm$/m);
    assert.equal(existsSync(join(dir, "slack-sso-manifest.yml")), false);

    const skill = readFileSync(join(dir, "sandbox", "skills", "greet", "SKILL.md"), "utf8");
    assert.match(skill, /name: greet/);
    assert.match(skill, /description: Greet a teammate by name/);
    assert.match(skill, /example-tool/);

    const tj = parseToolDescriptor(
      readFileSync(join(dir, "sandbox", "tools", "example-tool", "tool.json"), "utf8"),
      "tool.json",
    );
    assert.equal(tj.id, "example-tool");
    assert.equal(tj.advertise, "example-tool");
    assert.equal(tj.install?.binary, "example-tool");

    const exe = join(dir, "sandbox", "tools", "example-tool", "example-tool");
    assert.ok(existsSync(exe));
    assert.ok(statSync(exe).mode & 0o111, "executable bit set on the tool binary");
    assert.match(readFileSync(exe, "utf8"), /Hello/);

    const layer = validateSandboxLayer(join(dir, "sandbox"));
    assert.deepEqual(layer.errors, [], "scaffolded sandbox layer must validate clean");
    assert.equal(layer.tools.length, 1);
    assert.equal(layer.skills.length, 1);
    assert.ok(layer.tools[0]!.executablePath, "the example tool ships an executable");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("init --target fly scaffolds the full hosted topology and both Slack apps", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-fly-"));
  try {
    quiet(() => runInit({ dir, org: "acme", target: "fly" }));
    const { config } = loadConfigInDir(dir);
    assert.equal(config.target, "fly");
    assert.deepEqual(config.services, ["core", "slack", "web-ui", "admin", "portal", "auth"]);
    assert.equal(config.publicUrl, "https://acme-portal.fly.dev");
    assert.equal(config.flyOrg, "personal");
    assert.ok(config.region, "region is scaffolded");
    assert.equal(config.appPrefix, "acme");
    assert.deepEqual(
      {
        SNAPSHOT_STORE: config.env.core?.SNAPSHOT_STORE,
        TRANSFER_STORE: config.env.core?.TRANSFER_STORE,
        S3_BUCKET: config.env.core?.S3_BUCKET,
        S3_REGION: config.env.core?.S3_REGION,
      },
      { SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" },
    );
    assert.deepEqual(config.secretEnv?.core, { ADMIN_GRANTS: "ADMIN_GRANTS" });
    assert.equal(config.env.slack?.SLACK_IDENTITY_EMAIL, "1");
    assert.equal(config.env.auth?.AUTH_EMAIL_TRANSPORT, "resend");
    assert.equal(config.env.portal?.OIDC_PRINCIPAL_CLAIM, undefined, "the broker derives every OIDC_* value");
    const env = readFileSync(join(dir, ".env.example"), "utf8");
    for (const line of [
      "ADMIN_GRANTS=",
      "AUTH_ALLOWED_EMAILS=",
      "AUTH_EMAIL_FROM=",
      "RESEND_API_KEY=",
      "PORTAL_SESSION_SECRET=",
      "ANTHROPIC_API_KEY=",
    ]) {
      assert.ok(env.split("\n").includes(line), `.env.example should require ${line} for the fly scaffold`);
    }
    for (const line of [
      "# OPENROUTER_API_KEY=  # optional",
      "# SLACK_APP_TOKEN=  # optional",
      "# SLACK_BOT_TOKEN=  # optional",
    ]) {
      assert.ok(env.split("\n").includes(line), `.env.example should offer ${line}`);
    }
    assert.ok(existsSync(join(dir, "slack-app-manifest.yml")), "Slack manifest is scaffolded on fly too");
    assert.equal(existsSync(join(dir, ".github")), false);
    assert.equal(existsSync(join(dir, "slack-sso-manifest.yml")), false);
    for (const line of ["# OIDC_CLIENT_ID=", "# OIDC_CLIENT_SECRET=", "# PORTAL_EXPECTED_TEAM_ID="]) {
      assert.ok(env.split("\n").includes(line), `external-IdP secret ${line} stays documented but unrequired`);
    }
    assert.ok(!env.includes("SMTP_"), "the unselected smtp transport's keys stay out of .env.example");
    assert.ok(!readFileSync(join(dir, ".env"), "utf8").includes("SMTP_"), "and out of .env");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init --email-transport smtp scaffolds smtp keys only and a matching config", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-smtp-"));
  try {
    quiet(() => runInit({ dir, org: "acme", target: "fly", emailTransport: "smtp" }));
    const { config } = loadConfigInDir(dir);
    assert.equal(config.env.auth?.AUTH_EMAIL_TRANSPORT, "smtp");
    const env = readFileSync(join(dir, ".env.example"), "utf8");
    assert.equal(env, renderEnvExample(config));
    for (const line of ["SMTP_HOST=", "SMTP_USERNAME=", "SMTP_PASSWORD="]) {
      assert.ok(env.split("\n").includes(line), `.env.example should require ${line}`);
    }
    assert.ok(!env.includes("RESEND_API_KEY"), "the unselected resend transport's key stays out of .env.example");
    assert.ok(!readFileSync(join(dir, ".env"), "utf8").includes("RESEND_API_KEY"), "and out of .env");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init keeps stable qm Slack branding for long org ids", () => {
  for (const org of ["a".repeat(34), `${"a".repeat(28)}-bcd`]) {
    const dir = mkdtempSync(join(tmpdir(), "qm-init-"));
    try {
      quiet(() => runInit({ dir, org }));
      const manifest = readFileSync(join(dir, "slack-app-manifest.yml"), "utf8");
      assert.match(manifest, /^ {2}name: qm$/m);
      assert.match(manifest, /^ {4}display_name: qm$/m);
      assert.ok(manifest.includes(`qm workspace agent for ${org}`));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("init defaults Docker to the local sandbox", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-"));
  try {
    quiet(() => runInit({ dir, org: "globex" }));
    assert.deepEqual(loadConfigInDir(dir).config.sandbox, { backend: "local" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init --target aws scaffolds the full hosted topology, Terraform, and the optional Slack bot manifest", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-"));
  try {
    quiet(() => runInit({ dir, org: "acme", target: "aws" }));
    const { config } = loadConfigInDir(dir);
    assert.equal(config.target, "aws");
    assert.equal(config.publicUrl, "https://acme.example.com");
    assert.deepEqual(config.services, ["core", "slack", "web-ui", "admin", "portal", "auth"]);
    assert.equal(config.env.core?.HARNESS, "pi");
    assert.equal(config.env.core?.AWS_DEPLOY_IMAGE, "acme-qm-sandbox");
    assert.equal(config.env.core?.AWS_PUBLIC_ORIGIN_URL, "http://replace-with-alb-hostname");
    assert.equal(config.env.slack?.SLACK_IDENTITY_EMAIL, "1");
    assert.equal(config.sandbox, undefined);
    assert.equal(config.aws?.cluster, "acme-qm");
    assert.equal(config.aws?.imageLabel, "latest");
    assert.deepEqual(config.aws?.services.core, {
      ecrRepository: "acme-qm-core",
      ecsService: "acme-qm-core",
      cpu: 2048,
      memory: 4096,
    });
    assert.deepEqual(Object.keys(config.aws?.services ?? {}), ["core", "web-ui", "admin", "portal", "auth"]);
    for (const name of ["main.tf", "outputs.tf", "variables.tf", "versions.tf", "terraform.tfvars"]) {
      assert.ok(existsSync(join(dir, "infra", name)), `infra/${name} is scaffolded`);
    }
    const tfvars = readFileSync(join(dir, "infra", "terraform.tfvars"), "utf8");
    assert.match(tfvars, /cluster_name\s*= "acme-qm"/);
    assert.match(tfvars, /github_repository\s*= "replace-me\/repository"/);
    assert.match(tfvars, /deploy_microvm_image\s*= "acme-qm-sandbox"/);
    assert.match(tfvars, /certificate_arn\s*= ""/);
    assert.match(readFileSync(join(dir, "infra", "main.tf"), "utf8"), /desired_count\s*= 0/);
    const env = readFileSync(join(dir, ".env.example"), "utf8").split("\n");
    for (const name of [
      "ADMIN_GRANTS=",
      "PUBLIC_API_URL=",
      "AUTH_ALLOWED_EMAILS=",
      "AUTH_EMAIL_FROM=",
      "RESEND_API_KEY=",
      "ANTHROPIC_API_KEY=",
    ]) {
      assert.ok(env.includes(name), `hosted AWS scaffold requires ${name}`);
    }
    for (const name of [
      "# OPENROUTER_API_KEY=  # optional",
      "# SLACK_BOT_TOKEN=  # optional",
      "# SLACK_APP_TOKEN=  # optional",
    ]) {
      assert.ok(env.includes(name), `hosted AWS scaffold offers deferred ${name}`);
    }
    const manifest = readFileSync(join(dir, "slack-app-manifest.yml"), "utf8");
    assert.match(manifest, /^ {2}name: qm$/m);
    assert.equal(existsSync(join(dir, "slack-sso-manifest.yml")), false);
    const agents = readFileSync(join(dir, "AGENTS.md"), "utf8");
    assert.match(agents, /CloudFront/);
    assert.match(agents, /AWS_DEPLOY_IMAGE.*always-required Lambda MicroVM image for the AWS deployment\s+publisher/);
    assert.match(agents, /Agent computers reuse the same image when the sandbox backend is `aws`/);
    for (const command of [
      "aws iam get-open-id-connect-provider",
      "aws iam create-open-id-connect-provider",
      "cloudfront_hostname",
      "alb_hostname",
      "npm exec --yes=false -- qm infra render",
      "terraform -chdir=infra apply",
      "npm exec --yes=false -- qm infra build-image",
      "npm exec --yes=false -- qm secrets push",
      "npm exec --yes=false -- qm up --yes",
      "npm exec --yes=false -- qm check --live",
      "npm exec --yes=false -- qm infra delete-task-definitions --yes",
      "secret_recovery_window_days=0",
    ]) {
      assert.match(agents, new RegExp(command.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    }
    assert.doesNotMatch(agents, /fly apps|sandbox publish|Fly app/);
    const destructiveApply = agents.indexOf("terraform -chdir=infra apply\n-var='ecr_force_delete=true'");
    const destructiveDestroy = agents.indexOf("terraform -chdir=infra destroy\n-var='ecr_force_delete=true'");
    assert.ok(destructiveApply >= 0, "destructive lifecycle settings are applied before teardown");
    const taskDefinitionCleanup = agents.indexOf("npm exec --yes=false -- qm infra delete-task-definitions --yes");
    assert.ok(
      taskDefinitionCleanup > destructiveApply,
      "task definitions are cleaned after the lifecycle apply recreates its bootstrap revision",
    );
    assert.ok(destructiveDestroy > destructiveApply, "destroy follows the state-persisting apply");
    assert.ok(destructiveDestroy > taskDefinitionCleanup, "destroy follows task-definition cleanup");
    for (const setting of [
      "ecr_force_delete=true",
      "object_store_force_destroy=true",
      "db_skip_final_snapshot=true",
      "secret_recovery_window_days=0",
    ]) {
      assert.equal(agents.split(setting).length - 1, 2, `${setting} is passed to both apply and destroy`);
    }
    const gitignore = readFileSync(join(dir, ".gitignore"), "utf8");
    assert.match(gitignore, /infra\/\.terraform\//);
    assert.match(gitignore, /infra\/\*\.tfstate/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init keeps long next-step commands separate from their explanations", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-"));
  try {
    const output = captureInit({ dir, org: "acme", target: "aws" });
    assert.match(output, /terraform -chdir=infra apply # create inert infrastructure/);
    assert.doesNotMatch(output, /apply#/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init --target aws derives stable valid AWS names for a maximum-length org id", () => {
  const org = `a${"b".repeat(62)}`;
  const first = mkdtempSync(join(tmpdir(), "qm-init-long-"));
  const second = mkdtempSync(join(tmpdir(), "qm-init-long-"));
  try {
    quiet(() => runInit({ dir: first, org, target: "aws" }));
    quiet(() => runInit({ dir: second, org, target: "aws" }));
    const one = loadConfigInDir(first).config.aws!;
    const two = loadConfigInDir(second).config.aws!;
    assert.equal(one.cluster, two.cluster);
    assert.equal(one.cluster.length, 49);
    assert.match(one.cluster, /^[a-z][a-z0-9-]*[a-z0-9]$/);
    assert.equal(one.deployRoleArn, `arn:aws:iam::000000000000:role/${one.cluster}-github-deploy`);
    assert.equal(one.services.core?.ecsService, `${one.cluster}-core`);
  } finally {
    rmSync(first, { recursive: true, force: true });
    rmSync(second, { recursive: true, force: true });
  }
});

test("init refuses to clobber an existing config, and leaves present scaffold files untouched", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-"));
  try {
    quiet(() => runInit({ dir, org: "acme" }));
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /already exists/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init rejects symlink and hardlink aliases for every root scaffold file", () => {
  for (const name of [CONFIG_FILENAME, ".env", "package.json", ".gitignore"]) {
    for (const kind of ["symlink", "hardlink"] as const) {
      const base = mkdtempSync(join(tmpdir(), "qm-init-alias-"));
      const dir = join(base, "deployment");
      const external = join(base, "external");
      const target = join(dir, name);
      mkdirSync(dir);
      try {
        if (kind === "symlink") {
          symlinkSync(external, target);
        } else {
          writeFileSync(external, name === "package.json" ? '{"external":true}\n' : "external\n");
          linkSync(external, target);
        }
        assert.throws(
          () => quiet(() => runInit({ dir, org: "acme" })),
          /not a safe regular file owned by the current user/,
          `${kind} ${name}`,
        );
        if (kind === "symlink") assert.equal(existsSync(external), false, `${name} symlink target stays absent`);
        else {
          assert.equal(
            readFileSync(external, "utf8"),
            name === "package.json" ? '{"external":true}\n' : "external\n",
            `${name} hardlink target stays unchanged`,
          );
        }
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
    }
  }
});

test("init preflights late root and nested scaffold aliases before writing any files", () => {
  for (const [segments, target] of [
    [[".env.example"], "docker"],
    [["AGENTS.md"], "docker"],
    [["CLAUDE.md"], "docker"],
    [["sandbox", "skills", "greet", "SKILL.md"], "docker"],
    [["infra", "main.tf"], "aws"],
  ] as const) {
    const base = mkdtempSync(join(tmpdir(), "qm-init-late-alias-"));
    const dir = join(base, "deployment");
    const external = join(base, "external");
    const path = join(dir, ...segments);
    mkdirSync(join(path, ".."), { recursive: true });
    symlinkSync(external, path);
    try {
      assert.throws(() => quiet(() => runInit({ dir, org: "acme", target })), /safe regular file/);
      assert.equal(existsSync(external), false);
      for (const name of [CONFIG_FILENAME, ".env", ".env.example", ".gitignore", "package.json"]) {
        if (segments.length === 1 && segments[0] === name) continue;
        assert.equal(existsSync(join(dir, name)), false, `${segments.join("/")} must fail before creating ${name}`);
      }
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  }
});

test("init rejects a symlink used as its requested root", () => {
  const base = mkdtempSync(join(tmpdir(), "qm-init-root-alias-"));
  const victim = join(base, "victim");
  const requested = join(base, "requested");
  mkdirSync(victim);
  symlinkSync(victim, requested);
  try {
    assert.throws(() => quiet(() => runInit({ dir: requested, org: "acme" })), /init directory/);
    assert.deepEqual(readdirSync(victim), []);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("init rejects writable lexical ancestors hidden by an intermediate symlink", () => {
  const base = mkdtempSync(join(tmpdir(), "qm-init-lexical-alias-"));
  const untrusted = join(base, "untrusted");
  const victim = join(base, "victim");
  const alias = join(untrusted, "alias");
  const requested = join(alias, "deployment");
  mkdirSync(untrusted);
  mkdirSync(victim);
  chmodSync(untrusted, 0o777);
  symlinkSync(victim, alias);
  try {
    assert.throws(() => quiet(() => runInit({ dir: requested, org: "acme" })), /trusted init directory ancestor/);
    assert.deepEqual(readdirSync(victim), []);
  } finally {
    chmodSync(untrusted, 0o700);
    rmSync(base, { recursive: true, force: true });
  }
});

test("init rejects group-writable roots, nested directories, and mutable files", () => {
  const root = mkdtempSync(join(tmpdir(), "qm-init-writable-root-"));
  try {
    chmodSync(root, 0o777);
    assert.throws(() => quiet(() => runInit({ dir: root, org: "acme" })), /not a trusted init directory ancestor/);
    assert.equal(existsSync(join(root, CONFIG_FILENAME)), false);
  } finally {
    chmodSync(root, 0o700);
    rmSync(root, { recursive: true, force: true });
  }

  const outer = mkdtempSync(join(tmpdir(), "qm-init-writable-ancestor-"));
  const controlling = join(outer, "controlling");
  const requested = join(controlling, "deployment");
  try {
    mkdirSync(controlling);
    chmodSync(controlling, 0o777);
    assert.throws(() => quiet(() => runInit({ dir: requested, org: "acme" })), /trusted init directory ancestor/);
    assert.equal(existsSync(join(requested, CONFIG_FILENAME)), false);
  } finally {
    chmodSync(controlling, 0o700);
    rmSync(outer, { recursive: true, force: true });
  }

  const nested = mkdtempSync(join(tmpdir(), "qm-init-writable-parent-"));
  try {
    mkdirSync(join(nested, "sandbox"), { mode: 0o777 });
    chmodSync(join(nested, "sandbox"), 0o777);
    assert.throws(() => quiet(() => runInit({ dir: nested, org: "acme" })), /unsafe parent directory/);
  } finally {
    chmodSync(join(nested, "sandbox"), 0o700);
    rmSync(nested, { recursive: true, force: true });
  }

  for (const name of ["package.json", ".gitignore"]) {
    const dir = mkdtempSync(join(tmpdir(), "qm-init-writable-file-"));
    const path = join(dir, name);
    const content = name === "package.json" ? "{}\n" : "external\n";
    try {
      writeFileSync(path, content);
      chmodSync(path, 0o666);
      assert.throws(
        () => quiet(() => runInit({ dir, org: "acme" })),
        /not a safe regular file owned by the current user/,
      );
      assert.equal(readFileSync(path, "utf8"), content);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("init rejects read-only mutable files before writing the scaffold", () => {
  for (const name of ["package.json", ".gitignore"]) {
    const dir = mkdtempSync(join(tmpdir(), "qm-init-readonly-file-"));
    const path = join(dir, name);
    const content = name === "package.json" ? "{}\n" : "node_modules/\n";
    try {
      writeFileSync(path, content, { mode: 0o444 });
      assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /safe regular file/);
      assert.equal(readFileSync(path, "utf8"), content);
      assert.equal(existsSync(join(dir, CONFIG_FILENAME)), false);
      assert.equal(existsSync(join(dir, ".env")), false);
    } finally {
      chmodSync(path, 0o600);
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("init rejects oversized sparse mutable files before reading or writing", () => {
  for (const name of ["package.json", ".gitignore"]) {
    const dir = mkdtempSync(join(tmpdir(), "qm-init-oversized-file-"));
    const path = join(dir, name);
    try {
      writeFileSync(path, name === "package.json" ? "{}\n" : ".env\n");
      truncateSync(path, 2 * 1024 * 1024);
      assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /exceeds the .* init limit/);
      assert.equal(statSync(path).size, 2 * 1024 * 1024);
      assert.equal(existsSync(join(dir, CONFIG_FILENAME)), false);
      assert.equal(existsSync(join(dir, ".env")), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("init creates safe modes even under a permissive umask", () => {
  const base = mkdtempSync(join(tmpdir(), "qm-init-umask-"));
  const dir = join(base, "deployment");
  const previous = process.umask(0);
  try {
    try {
      quiet(() => runInit({ dir, org: "acme" }));
    } finally {
      process.umask(previous);
    }
    assert.equal(statSync(dir).mode & 0o022, 0);
    assert.equal(statSync(join(dir, CONFIG_FILENAME)).mode & 0o022, 0);
    assert.equal(statSync(join(dir, ".gitignore")).mode & 0o022, 0);
    assert.equal(statSync(join(dir, ".env")).mode & 0o777, 0o600);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("init rejects permission-granting directory ACLs and strips file ACLs on macOS", (t) => {
  if (process.platform !== "darwin") return t.skip("macOS ACL semantics");
  const inherited = mkdtempSync(join(tmpdir(), "qm-init-inherited-acl-"));
  try {
    execFileSync("/bin/chmod", ["+a", "everyone allow read,file_inherit", inherited]);
    assert.throws(() => quiet(() => runInit({ dir: inherited, org: "acme" })), /permission-granting ACLs/);
    assert.equal(existsSync(join(inherited, CONFIG_FILENAME)), false);
  } finally {
    execFileSync("/bin/chmod", ["-N", inherited]);
    rmSync(inherited, { recursive: true, force: true });
  }

  const existing = mkdtempSync(join(tmpdir(), "qm-init-file-acl-"));
  const packagePath = join(existing, "package.json");
  try {
    writeFileSync(packagePath, "{}\n");
    execFileSync("/bin/chmod", ["+a", "everyone allow read", packagePath]);
    quiet(() => runInit({ dir: existing, org: "acme" }));
    assert.doesNotMatch(execFileSync("/bin/ls", ["-lde", packagePath], { encoding: "utf8" }), / allow /);
  } finally {
    rmSync(existing, { recursive: true, force: true });
  }

  for (const name of ["package.json", ".gitignore"]) {
    const unsafe = mkdtempSync(join(tmpdir(), "qm-init-unsafe-file-acl-"));
    const path = join(unsafe, name);
    const content = name === "package.json" ? '{"scripts":{"postinstall":"external"}}\n' : ".env\n";
    try {
      writeFileSync(path, content);
      execFileSync("/bin/chmod", ["+a", "everyone allow write", path]);
      assert.throws(() => quiet(() => runInit({ dir: unsafe, org: "acme" })), /mutation-granting ACL/);
      assert.equal(readFileSync(path, "utf8"), content);
      assert.equal(existsSync(join(unsafe, CONFIG_FILENAME)), false);
      assert.equal(existsSync(join(unsafe, ".env")), false);
    } finally {
      if (existsSync(path)) execFileSync("/bin/chmod", ["-N", path]);
      rmSync(unsafe, { recursive: true, force: true });
    }
  }

  const repository = mkdtempSync(join(tmpdir(), "qm-init-unsafe-git-acl-"));
  const indexPath = join(repository, ".git", "index");
  try {
    execFileSync("git", ["init"], { cwd: repository, stdio: "ignore" });
    writeFileSync(join(repository, "seed"), "seed\n");
    execFileSync("git", ["add", "seed"], { cwd: repository, stdio: "ignore" });
    rmSync(join(repository, "seed"));
    execFileSync("/bin/chmod", ["+a", "everyone allow write", indexPath]);
    assert.throws(() => quiet(() => runInit({ dir: repository, org: "acme" })), /mutation-granting ACL/);
    assertNoScaffoldFiles(repository);
  } finally {
    if (existsSync(indexPath)) execFileSync("/bin/chmod", ["-N", indexPath]);
    rmSync(repository, { recursive: true, force: true });
  }
});

test("init rejects symlinked scaffold ancestor directories without escaping its root", () => {
  for (const [ancestor, target] of [
    ["sandbox", "docker"],
    [".codex", "docker"],
    ["infra", "aws"],
  ] as const) {
    const base = mkdtempSync(join(tmpdir(), "qm-init-parent-alias-"));
    const dir = join(base, "deployment");
    const external = join(base, "external");
    mkdirSync(dir);
    mkdirSync(external);
    symlinkSync(external, join(dir, ancestor));
    try {
      assert.throws(() => quiet(() => runInit({ dir, org: "acme", target })), /unsafe parent directory/, ancestor);
      assert.deepEqual(readdirSync(external), [], `${ancestor} cannot redirect scaffold writes outside the root`);
      assert.equal(existsSync(join(dir, CONFIG_FILENAME)), false);
      assert.equal(existsSync(join(dir, ".env")), false);
      assert.equal(existsSync(join(dir, "package.json")), false);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  }
});

test("init makes .env the final matching gitignore rule before generating signing keys", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-existing-ignore-"));
  try {
    writeFileSync(join(dir, ".gitignore"), "node_modules/\n.env\n!.env\n");
    quiet(() => runInit({ dir, org: "acme" }));
    assert.equal(readFileSync(join(dir, ".gitignore"), "utf8"), "node_modules/\n.env\n!.env\n.generated/\n.env\n");
    assert.match(readFileSync(join(dir, ".env"), "utf8"), /^CORE_SIGNING_SECRET=[a-f0-9]{64}$/m);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init does not mistake a leading-space gitignore pattern for .env", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-leading-space-ignore-"));
  try {
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    writeFileSync(join(dir, ".gitignore"), "node_modules/\n.generated/\n .env\n");
    quiet(() => runInit({ dir, org: "acme" }));
    assert.equal(readFileSync(join(dir, ".gitignore"), "utf8"), "node_modules/\n.generated/\n .env\n.env\n");
    assert.equal(execFileSync("git", ["check-ignore", ".env"], { cwd: dir, encoding: "utf8" }).trim(), ".env");
    assert.doesNotMatch(
      execFileSync("git", ["status", "--short", "--untracked-files=all"], { cwd: dir, encoding: "utf8" }),
      /^\?\? \.env$/m,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init refuses to generate keys into an absent but Git-tracked .env", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-tracked-env-"));
  try {
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    writeFileSync(join(dir, ".env"), "previous=value\n");
    execFileSync("git", ["add", ".env"], { cwd: dir, stdio: "ignore" });
    rmSync(join(dir, ".env"));
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /tracked by Git/);
    assert.ok(!existsSync(join(dir, CONFIG_FILENAME)), "init refuses before writing the scaffold");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init refuses a present tracked .env before writing the scaffold", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-present-tracked-env-"));
  try {
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    writeFileSync(join(dir, ".env"), "previous=value\n");
    execFileSync("git", ["add", ".env"], { cwd: dir, stdio: "ignore" });
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /tracked by Git/);
    assert.ok(!existsSync(join(dir, CONFIG_FILENAME)), "init refuses before writing the scaffold");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init ignores hostile Git routing variables when checking an absent tracked .env", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-hostile-git-env-"));
  const decoy = mkdtempSync(join(tmpdir(), "qm-init-hostile-git-decoy-"));
  try {
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    execFileSync("git", ["init"], { cwd: decoy, stdio: "ignore" });
    writeFileSync(join(dir, ".env"), "previous=value\n");
    execFileSync("git", ["add", "-f", ".env"], { cwd: dir, stdio: "ignore" });
    rmSync(join(dir, ".env"));
    withProcessEnv(
      {
        GIT_DIR: join(decoy, ".git"),
        GIT_INDEX_FILE: join(decoy, ".git", "index"),
        GIT_WORK_TREE: decoy,
      },
      () => assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /tracked by Git/),
    );
    assertNoScaffoldFiles(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(decoy, { recursive: true, force: true });
  }
});

test("init rejects writable Git directories and indexes before writing the scaffold", () => {
  for (const [relative, mode] of [
    [[".git"], 0o777],
    [[".git", "index"], 0o666],
  ] as const) {
    const dir = mkdtempSync(join(tmpdir(), "qm-init-writable-git-metadata-"));
    const path = join(dir, ...relative);
    try {
      execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
      writeFileSync(join(dir, "seed"), "seed\n");
      execFileSync("git", ["add", "seed"], { cwd: dir, stdio: "ignore" });
      rmSync(join(dir, "seed"));
      chmodSync(path, mode);
      assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /trusted/);
      assertNoScaffoldFiles(dir);
    } finally {
      if (existsSync(path)) chmodSync(path, relative.length === 1 ? 0o700 : 0o600);
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("init refuses an existing Git index lock before writing the scaffold", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-busy-git-index-"));
  const lock = join(dir, ".git", "index.lock");
  try {
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    writeFileSync(lock, "active\n", { mode: 0o600 });
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /busy or unsafe/);
    assert.equal(readFileSync(lock, "utf8"), "active\n");
    assertNoScaffoldFiles(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init holds the Git index lock while installing generated secrets", () => {
  const base = mkdtempSync(join(tmpdir(), "qm-init-git-race-"));
  const dir = join(base, "deployment");
  const bin = join(base, "bin");
  const wrapper = join(bin, "git");
  const counter = join(base, "ls-files-counter");
  const result = join(base, "git-add-result");
  const realGit = execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
  mkdirSync(dir);
  mkdirSync(bin);
  try {
    execFileSync(realGit, ["init"], { cwd: dir, stdio: "ignore" });
    writeFileSync(
      wrapper,
      `#!/bin/sh
is_ls_files=
for argument in "$@"; do
  if [ "$argument" = "ls-files" ]; then is_ls_files=1; fi
done
if [ "$is_ls_files" = "1" ]; then
  if [ -e "$QM_INIT_GIT_RACE_COUNTER" ]; then
    if "$QM_INIT_REAL_GIT" -C "$QM_INIT_GIT_RACE_REPO" add -f .env >/dev/null 2>&1; then
      echo staged > "$QM_INIT_GIT_RACE_RESULT"
    else
      echo blocked > "$QM_INIT_GIT_RACE_RESULT"
    fi
  else
    : > "$QM_INIT_GIT_RACE_COUNTER"
  fi
fi
exec "$QM_INIT_REAL_GIT" "$@"
`,
      { mode: 0o755 },
    );
    withProcessEnv(
      {
        PATH: `${bin}:${process.env.PATH ?? ""}`,
        QM_INIT_GIT_RACE_COUNTER: counter,
        QM_INIT_GIT_RACE_REPO: dir,
        QM_INIT_GIT_RACE_RESULT: result,
        QM_INIT_REAL_GIT: realGit,
      },
      () => quiet(() => runInit({ dir, org: "acme" })),
    );
    assert.equal(readFileSync(result, "utf8").trim(), "blocked");
    assert.match(readFileSync(join(dir, ".env"), "utf8"), /^CORE_SIGNING_SECRET=[a-f0-9]{64}$/m);
    assert.ok(existsSync(join(dir, CONFIG_FILENAME)));
    assert.equal(execFileSync(realGit, ["ls-files", ".env"], { cwd: dir, encoding: "utf8" }).trim(), "");
    assert.throws(() => execFileSync(realGit, ["show", ":.env"], { cwd: dir, stdio: "ignore" }));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("init releases every enclosing Git index lock after a cleanup failure", () => {
  const base = mkdtempSync(join(tmpdir(), "qm-init-git-lock-cleanup-"));
  const dir = join(base, "deployment");
  const bin = join(base, "bin");
  const wrapper = join(bin, "git");
  const outerLock = join(base, ".git", "index.lock");
  const innerLock = join(dir, ".git", "index.lock");
  const realGit = execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
  mkdirSync(dir);
  mkdirSync(bin);
  try {
    execFileSync(realGit, ["init"], { cwd: base, stdio: "ignore" });
    execFileSync(realGit, ["init"], { cwd: dir, stdio: "ignore" });
    writeFileSync(
      wrapper,
      `#!/bin/sh
is_ls_files=
for argument in "$@"; do
  if [ "$argument" = "ls-files" ]; then is_ls_files=1; fi
done
if [ "$is_ls_files" = "1" ] && [ -e "$QM_INIT_OUTER_LOCK" ] && [ -e "$QM_INIT_INNER_LOCK" ]; then
  rm -f -- "$QM_INIT_INNER_LOCK"
fi
exec "$QM_INIT_REAL_GIT" "$@"
`,
      { mode: 0o755 },
    );
    assert.throws(
      () =>
        withProcessEnv(
          {
            PATH: `${bin}:${process.env.PATH ?? ""}`,
            QM_INIT_INNER_LOCK: innerLock,
            QM_INIT_OUTER_LOCK: outerLock,
            QM_INIT_REAL_GIT: realGit,
          },
          () => quiet(() => runInit({ dir, org: "acme" })),
        ),
      /index\.lock/,
    );
    assert.equal(existsSync(innerLock), false);
    assert.equal(existsSync(outerLock), false);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("init does not execute a repository fsmonitor while checking .env", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-fsmonitor-"));
  const hook = join(dir, "fsmonitor");
  const marker = join(dir, "fsmonitor-ran");
  try {
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    writeFileSync(hook, '#!/bin/sh\n: > "$QM_INIT_FSMONITOR_MARKER"\n', { mode: 0o755 });
    execFileSync("git", ["config", "core.fsmonitor", hook], { cwd: dir, stdio: "ignore" });
    withProcessEnv({ QM_INIT_FSMONITOR_MARKER: marker }, () => quiet(() => runInit({ dir, org: "acme" })));
    assert.equal(existsSync(marker), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init fails closed before writing when Git cannot execute", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-git-unavailable-"));
  try {
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    writeFileSync(join(dir, ".env"), "previous=value\n");
    execFileSync("git", ["add", "-f", ".env"], { cwd: dir, stdio: "ignore" });
    rmSync(join(dir, ".env"));
    withProcessEnv({ PATH: join(dir, "missing-bin") }, () => {
      assert.throws(
        () => quiet(() => runInit({ dir, org: "acme" })),
        /could not determine whether \.env is tracked by Git/,
      );
    });
    assertNoScaffoldFiles(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init treats case-folded .env index entries as tracked", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-casefolded-env-"));
  try {
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    writeFileSync(join(dir, ".ENV"), "previous=value\n");
    execFileSync("git", ["add", "-f", ".ENV"], { cwd: dir, stdio: "ignore" });
    rmSync(join(dir, ".ENV"));
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /tracked by Git/);
    assertNoScaffoldFiles(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init treats Unicode-case-folded ancestor components of a tracked .env as equivalent", (t) => {
  const repo = mkdtempSync(join(tmpdir(), "qm-init-casefolded-ancestors-"));
  const requested = join(repo, "déploy", "äcme");
  const indexed = join(repo, "DÉPLOY", "ÄCME");
  try {
    execFileSync("git", ["init"], { cwd: repo, stdio: "ignore" });
    mkdirSync(requested, { recursive: true });
    if (!existsSync(indexed)) return t.skip("case-sensitive filesystem");
    writeFileSync(join(requested, ".env"), "previous=value\n");
    execFileSync("git", ["add", "-f", "DÉPLOY/ÄCME/.env"], { cwd: repo, stdio: "ignore" });
    assert.equal(
      execFileSync("git", ["ls-files", "-z"], { cwd: repo, encoding: "utf8" }).replace(/\0$/u, "").normalize("NFC"),
      "DÉPLOY/ÄCME/.env".normalize("NFC"),
    );
    rmSync(join(requested, ".env"));
    assert.throws(() => quiet(() => runInit({ dir: requested, org: "acme" })), /tracked by Git/);
    assert.equal(existsSync(join(requested, CONFIG_FILENAME)), false);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("init rejects an .env tracked by an enclosing repository", () => {
  const repo = mkdtempSync(join(tmpdir(), "qm-init-enclosing-repo-"));
  const dir = join(repo, "deploy");
  try {
    execFileSync("git", ["init"], { cwd: repo, stdio: "ignore" });
    mkdirSync(dir);
    writeFileSync(join(dir, ".env"), "previous=value\n");
    execFileSync("git", ["add", "-f", "deploy/.env"], { cwd: repo, stdio: "ignore" });
    rmSync(join(dir, ".env"));
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /tracked by Git/);
    assertNoScaffoldFiles(dir);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("init discovers bare repositories and fails closed on an unreadable bare index", () => {
  const repo = mkdtempSync(join(tmpdir(), "qm-init-bare-repo-"));
  const dir = join(repo, "deploy");
  const indexPath = join(repo, "index");
  try {
    execFileSync("git", ["init", "--bare"], { cwd: repo, stdio: "ignore" });
    mkdirSync(dir);
    const blob = execFileSync("git", ["hash-object", "-w", "--stdin"], {
      cwd: repo,
      encoding: "utf8",
      input: "previous=value\n",
    }).trim();
    execFileSync("git", ["update-index", "--add", "--cacheinfo", `100644,${blob},deploy/.env`], {
      cwd: repo,
      stdio: "ignore",
    });
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /tracked by Git/);
    assertNoScaffoldFiles(dir);

    rmSync(join(repo, "config"));
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /tracked by Git/);
    assertNoScaffoldFiles(dir);

    rmSync(join(repo, "HEAD"), { recursive: true });
    symlinkSync("refs/heads/main", join(repo, "HEAD"));
    assert.equal(
      execFileSync("git", ["rev-parse", "--is-bare-repository"], { cwd: repo, encoding: "utf8" }).trim(),
      "true",
    );
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /tracked by Git/);
    assertNoScaffoldFiles(dir);

    writeFileSync(join(repo, "config"), "[core\n", { mode: 0o644 });
    assert.throws(
      () => quiet(() => runInit({ dir, org: "acme" })),
      /could not determine whether an init ancestor is a bare Git repository/,
    );
    assertNoScaffoldFiles(dir);
    rmSync(join(repo, "config"));

    rmSync(join(repo, "HEAD"));
    writeFileSync(join(repo, "HEAD"), "not a repository\n", { mode: 0o644 });
    assert.throws(
      () => quiet(() => runInit({ dir, org: "acme" })),
      /could not determine whether an init ancestor is a bare Git repository/,
    );
    assertNoScaffoldFiles(dir);
    rmSync(join(repo, "HEAD"));

    mkdirSync(join(repo, "HEAD"));
    assert.throws(
      () => quiet(() => runInit({ dir, org: "acme" })),
      /could not determine whether an init ancestor is a bare Git repository/,
    );
    assertNoScaffoldFiles(dir);
    rmSync(join(repo, "HEAD"), { recursive: true });
    symlinkSync("refs/heads/main", join(repo, "HEAD"));

    execFileSync("git", ["--git-dir", repo, "config", "core.bare", "false"], { stdio: "ignore" });
    execFileSync("git", ["--git-dir", repo, "config", "core.worktree", repo], { stdio: "ignore" });
    assert.equal(
      execFileSync("git", ["rev-parse", "--is-bare-repository"], { cwd: repo, encoding: "utf8" }).trim(),
      "false",
    );
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /tracked by Git/);
    assertNoScaffoldFiles(dir);
    rmSync(join(repo, "config"));

    rmSync(join(repo, "refs"), { recursive: true });
    assert.throws(
      () => quiet(() => runInit({ dir, org: "acme" })),
      /could not determine whether an init ancestor is a bare Git repository/,
    );
    assertNoScaffoldFiles(dir);
    mkdirSync(join(repo, "refs", "heads"), { recursive: true });

    const index = readFileSync(indexPath);
    writeFileSync(indexPath, index.subarray(0, 8));
    assert.throws(
      () => quiet(() => runInit({ dir, org: "acme" })),
      /could not determine whether \.env is tracked by Git/,
    );
    assertNoScaffoldFiles(dir);
    writeFileSync(indexPath, index);
    assert.equal(execFileSync("git", ["ls-files"], { cwd: repo, encoding: "utf8" }).trim(), "deploy/.env");
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("init fails closed on aliased bare repository metadata", () => {
  const base = mkdtempSync(join(tmpdir(), "qm-init-aliased-bare-repo-"));
  const repo = join(base, "repo");
  const dir = join(repo, "deploy");
  const objects = join(base, "objects");
  try {
    execFileSync("git", ["init", "--bare", repo], { stdio: "ignore" });
    mkdirSync(dir);
    const blob = execFileSync("git", ["hash-object", "-w", "--stdin"], {
      cwd: repo,
      encoding: "utf8",
      input: "previous=value\n",
    }).trim();
    execFileSync("git", ["update-index", "--add", "--cacheinfo", `100644,${blob},deploy/.env`], {
      cwd: repo,
      stdio: "ignore",
    });
    renameSync(join(repo, "objects"), objects);
    symlinkSync("../objects", join(repo, "objects"));
    assert.equal(
      execFileSync("git", ["rev-parse", "--is-bare-repository"], { cwd: repo, encoding: "utf8" }).trim(),
      "true",
    );
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /trusted/);
    assertNoScaffoldFiles(dir);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("init does not mistake an ordinary Git-shaped ancestor for a bare repository", () => {
  const base = mkdtempSync(join(tmpdir(), "qm-init-git-lookalike-"));
  const dir = join(base, "deploy");
  try {
    writeFileSync(join(base, "HEAD"), "not a repository\n");
    mkdirSync(join(base, "objects"));
    mkdirSync(join(base, "refs"));
    mkdirSync(dir);
    quiet(() => runInit({ dir, org: "acme" }));
    assert.ok(existsSync(join(dir, CONFIG_FILENAME)));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("init checks .env without enumerating a large unrelated Git index", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-large-index-"));
  try {
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    const blob = execFileSync("git", ["hash-object", "-w", "--stdin"], {
      cwd: dir,
      encoding: "utf8",
      input: "",
    }).trim();
    const entries = Array.from(
      { length: 240_000 },
      (_, index) => `100644 ${blob}\t${"indexed-path-".repeat(6)}${index.toString().padStart(5, "0")}\n`,
    ).join("");
    execFileSync("git", ["update-index", "--index-info"], { cwd: dir, input: entries });
    const listing = execFileSync("git", ["ls-files", "-z"], { cwd: dir, maxBuffer: 32 * 1024 * 1024 });
    assert.ok(listing.byteLength > 16 * 1024 * 1024);
    quiet(() => runInit({ dir, org: "acme" }));
    assert.ok(existsSync(join(dir, CONFIG_FILENAME)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init merges every AWS secret and generated-state ignore into an existing file", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-aws-ignore-"));
  try {
    writeFileSync(join(dir, ".gitignore"), ".DS_Store\n");
    quiet(() => runInit({ dir, org: "acme", target: "aws" }));
    const rules = readFileSync(join(dir, ".gitignore"), "utf8").split(/\r?\n/);
    for (const rule of [
      "node_modules/",
      ".generated/",
      "infra/.terraform/",
      "infra/*.tfstate",
      "infra/*.tfstate.*",
      "infra/crash.log",
      "infra/*.tfplan",
    ])
      assert.ok(rules.includes(rule), `${rule} is ignored`);
    assert.equal(rules.filter(Boolean).at(-1), ".env", ".env is the final matching rule");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init preflights package.json and completes an install-first package manifest", () => {
  const invalid = mkdtempSync(join(tmpdir(), "qm-init-invalid-package-"));
  const existing = mkdtempSync(join(tmpdir(), "qm-init-existing-package-"));
  try {
    writeFileSync(join(invalid, "package.json"), "{ broken");
    assert.throws(() => quiet(() => runInit({ dir: invalid, org: "acme" })), /package\.json is not valid JSON/);
    assert.ok(
      !existsSync(join(invalid, CONFIG_FILENAME)),
      "invalid package metadata cannot strand a partial deployment",
    );

    writeFileSync(
      join(existing, "package.json"),
      JSON.stringify({
        dependencies: { "qm-cli": "0.1.0", other: "1.0.0" },
      }),
    );
    quiet(() => runInit({ dir: existing, org: "acme" }));
    const manifest = JSON.parse(readFileSync(join(existing, "package.json"), "utf8")) as {
      private?: boolean;
      engines?: Record<string, string>;
      scripts?: Record<string, string>;
      dependencies?: Record<string, string>;
    };
    assert.equal(manifest.private, true);
    assert.equal(manifest.engines?.node, ">=24.0.0");
    assert.equal(manifest.scripts?.deploy, "qm up");
    assert.equal(manifest.dependencies?.["@yc-software/qm"], cliVersion());
    assert.equal(manifest.dependencies?.["qm-cli"], undefined);
    assert.equal(manifest.dependencies?.other, "1.0.0");
  } finally {
    rmSync(invalid, { recursive: true, force: true });
    rmSync(existing, { recursive: true, force: true });
  }
});

test("init rejects malformed UTF-8 in mutable files without changing them", () => {
  for (const [name, content] of [
    ["package.json", Buffer.concat([Buffer.from('{"description":"'), Buffer.from([0xc3, 0x28]), Buffer.from('"}\n')])],
    [".gitignore", Buffer.concat([Buffer.from("node_modules/\n"), Buffer.from([0xc3, 0x28]), Buffer.from("\n")])],
  ] as const) {
    const dir = mkdtempSync(join(tmpdir(), "qm-init-malformed-utf8-"));
    const path = join(dir, name);
    try {
      writeFileSync(path, content);
      assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /valid UTF-8 text/);
      assert.deepEqual(readFileSync(path), content);
      assert.equal(existsSync(join(dir, CONFIG_FILENAME)), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("init preserves an existing package if its atomic replacement cannot be prepared", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-atomic-package-"));
  const path = join(dir, "package.json");
  const content = `${JSON.stringify({ description: "x".repeat(1_048_500) })}\n`;
  try {
    assert.ok(Buffer.byteLength(content) < 1024 * 1024);
    writeFileSync(path, content);
    assert.throws(() => quiet(() => runInit({ dir, org: "acme" })), /rendered file limit/);
    assert.equal(readFileSync(path, "utf8"), content);
    assert.equal(existsSync(join(dir, CONFIG_FILENAME)), false);
    assert.equal(existsSync(join(dir, ".env")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init preserves an installed local package artifact", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-local-package-"));
  try {
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({
        private: true,
        dependencies: { "@yc-software/qm": "file:../packages/yc-software-qm-0.1.0.tgz" },
      }),
    );

    quiet(() => runInit({ dir, org: "acme", target: "fly" }));

    const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
    };
    assert.equal(manifest.dependencies?.["@yc-software/qm"], "file:../packages/yc-software-qm-0.1.0.tgz");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init --target aws vendors a contract-valid Terraform deployment", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-aws-"));
  try {
    quiet(() => runInit({ dir, org: "globex", target: "aws" }));
    const { config } = loadConfigInDir(dir);
    assert.equal(config.aws?.cluster, "globex-qm");
    assert.equal(config.aws?.services.core?.cpu, 2048);
    for (const path of [
      ["infra", "versions.tf"],
      ["infra", "variables.tf"],
      ["infra", "main.tf"],
      ["infra", "outputs.tf"],
      ["infra", "terraform.tfvars"],
    ])
      assert.ok(existsSync(join(dir, ...path)), `${path.join("/")} exists`);
    assert.doesNotThrow(() => runChecks(config, dir, join(dir, "sandbox"), { report: false }));
    const main = readFileSync(join(dir, "infra", "main.tf"), "utf8");
    assert.match(main, /aws_ecs_cluster/);
    assert.match(main, /aws_db_instance/);
    assert.match(main, /aws_lb_listener/);
    assert.match(main, /aws_iam_openid_connect_provider/);
    assert.match(main, /aws_dynamodb_table/);
    assert.match(main, /ec2:DescribeSecurityGroups/);
    assert.match(main, /elasticloadbalancing:Describe\*/);
    assert.match(main, /servicediscovery:ListServices/);
    const tfvarsPath = join(dir, "infra", "terraform.tfvars");
    writeFileSync(
      tfvarsPath,
      readFileSync(tfvarsPath, "utf8").replace(
        /github_repository\s*= "replace-me\/repository"/,
        'github_repository   = "globex/deploy"',
      ),
    );
    config.publicUrl = "https://agents.globex.example";
    renderTerraformVars(config, dir);
    const tfvars = readFileSync(tfvarsPath, "utf8");
    assert.match(tfvars, /public_url\s*= "https:\/\/agents\.globex\.example"/);
    assert.match(tfvars, /github_repository\s*= "globex\/deploy"/);
    assert.equal(existsSync(join(dir, ".github")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the scaffold is an npm-backed deployment repository with no CI coupling and valid Slack YAML", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-init-"));
  try {
    quiet(() => runInit({ dir, org: "acme" }));
    const packageJson = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as {
      private?: boolean;
      dependencies?: Record<string, string>;
      scripts?: Record<string, string>;
    };
    assert.equal(packageJson.private, true);
    assert.equal(packageJson.dependencies?.["@yc-software/qm"], cliVersion());
    assert.equal(packageJson.scripts?.check, "qm check");
    assert.ok(existsSync(join(dir, "deployment.md")));
    assert.ok(existsSync(join(dir, ".codex", "skills", "deploy-qm", "SKILL.md")));
    for (const provider of ["fly", "aws", "slack", "email"]) {
      assert.ok(existsSync(join(dir, ".codex", "skills", "deploy-qm", "references", `${provider}.md`)));
    }
    assert.match(readFileSync(join(dir, ".gitignore"), "utf8"), /^node_modules\/$/m);
    assert.match(readFileSync(join(dir, "AGENTS.md"), "utf8"), /package\.json.*pins the exact CLI version/s);
    assert.ok(!existsSync(join(dir, ".github")));
    assert.ok(!existsSync(join(dir, "test")));

    const manifest = readFileSync(join(dir, "slack-app-manifest.yml"), "utf8");
    assert.ok(!manifest.trimStart().startsWith("{"), "the .yml manifest holds YAML, not a JSON blob");
    assert.match(manifest, /^display_information:/m);
    assert.match(manifest, /^ {2}name: qm$/m);
    assert.match(manifest, /^ {6}- chat:write$/m);
    assert.match(manifest, /background_color: "#1f2937"/, "values YAML would misread are quoted");
    assert.deepEqual(
      slackManifestBotScopes(manifest),
      requiredSlackScopes(dir),
      "doctor parses the scaffolded YAML scopes",
    );
    assert.equal(existsSync(join(dir, "slack-sso-manifest.yml")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
