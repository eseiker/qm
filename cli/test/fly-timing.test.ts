import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const cliDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(cliDir, "..");
const bin = join(cliDir, "bin", "qm.ts");

function fakeFlyBin(dir: string): string {
  const binPath = join(dir, "fake-fly.cjs");
  writeFileSync(
    binPath,
    `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
const cmd = args.join(" ");
if (process.env.FAKE_FLY_LOG) fs.appendFileSync(process.env.FAKE_FLY_LOG, JSON.stringify(args) + "\\n");
if (args[0] === "deploy" && process.env.FAKE_FLY_DEPLOY_CWD_LOG) {
  fs.appendFileSync(process.env.FAKE_FLY_DEPLOY_CWD_LOG, process.cwd() + "\\n");
}
if (args[0] === "apps" && args[1] === "list") {
  console.log(JSON.stringify([{ Name: "qm-core" }, { Name: "beta-core" }]));
} else if (args[0] === "apps" && args[1] === "create") {
  console.log("created");
} else if (args[0] === "secrets" && args[1] === "set") {
  console.log("staged");
} else if (args[0] === "secrets" && args[1] === "unset") {
  console.log("staged");
} else if (args[0] === "secrets" && args[1] === "list") {
  const app = args[args.indexOf("-a") + 1];
  const prefix = app === "qm-core" ? "qm" : "beta";
  const org = prefix === "qm" ? "acme" : "beta";
  const owner = "QM_OWNER_" + require("node:crypto").createHash("sha256").update("qm-v2:personal:" + org + ":" + prefix).digest("hex").slice(0, 16).toUpperCase();
  const names = process.env.FAKE_FLY_OWNER_ONLY ? [owner] : [owner, "ADMIN_GRANTS", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_ENDPOINT_URL_S3", "AWS_SECRET_ACCESS_KEY", "CAPABILITY_SECRET", "CONNECTOR_SECRET_KEY", "CORE_SIGNING_SECRET", "PORTAL_IDENTITY_SECRET", "SKILL_SIGNING_SECRET", "FLY_API_TOKEN", "PUBLIC_API_URL", "SPRITES_TOKEN", ...(process.env.FAKE_FLY_FRESH_PG ? [] : ["DATABASE_URL"]), "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"];
  console.log(JSON.stringify(names.map((Name) => ({ Name }))));
} else if (args[0] === "mpg" && args[1] === "list") {
  console.log(process.env.FAKE_FLY_FRESH_PG ? "" : "pg-1 test-pg");
} else if (args[0] === "mpg" && args[1] === "create") {
  console.log("ID: pg-1");
} else if (args[0] === "mpg" && args[1] === "status") {
  if (process.env.FAKE_FLY_STATUS_FAIL) {
    console.log("postgresql://fly-user:secret@direct.pg-1.flympg.net/fly-db");
    console.error("postgresql://fly-user:secret@direct.pg-1.flympg.net/fly-db");
    process.exit(1);
  }
  console.log(JSON.stringify({ credentials: { pgbouncer_uri: "postgresql://fly-user:secret@pgbouncer.pg-1.flympg.net/fly-db" } }));
} else if (args[0] === "status" && args.includes("--json")) {
  console.log(JSON.stringify({ Machines: [{ id: "machine-core", config: { image: "registry.fly.io/source-core:v1" } }] }));
} else if (args[0] === "image" && args[1] === "show") {
  console.log(process.env.FAKE_FLY_NO_IMAGE_DIGEST ? "[]" : JSON.stringify([
    ...(process.env.FAKE_FLY_MIXED_IMAGES ? [{ MachineID: "machine-other", Registry: "registry.fly.io", Repository: "source-core", Tag: "v1", Digest: "sha256:${"b".repeat(64)}" }] : []),
    { MachineID: "machine-core", Registry: "registry.fly.io", Repository: "source-core", Tag: "v1", Digest: "sha256:${"a".repeat(64)}" },
  ]));
} else if (args[0] === "deploy") {
  console.log("deployed");
} else if (args[0] === "ssh" && args[1] === "console") {
  console.log('QM_LAYER_RESPONSE=' + JSON.stringify({ status: 200, body: JSON.stringify({ version: 1, contentHash: "0123456789abcdef" }) }));
} else {
  console.error("unexpected fake fly command: " + cmd);
  process.exit(42);
}
`,
  );
  chmodSync(binPath, 0o755);
  return binPath;
}

test("fly up emits phase timings and appends a GitHub step summary", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-timing-"));
  const summaryPath = join(dir, "summary.md");
  const stdout = execFileSync(
    process.execPath,
    [
      bin,
      "up",
      "--config",
      join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"),
      "--only",
      "core",
      "--image-from",
      "source",
    ],
    {
      encoding: "utf8",
      cwd: repoRoot,
      env: {
        ...process.env,
        FLY_BIN: fakeFlyBin(dir),
        GITHUB_STEP_SUMMARY: summaryPath,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  assert.match(stdout, /timing qm\/core: app ensure \d+(?:ms|\.\d+s)/);
  assert.match(stdout, /timing qm\/core: secret checks \d+(?:ms|\.\d+s)/);
  assert.match(stdout, /timing qm\/core: Postgres ensure \d+(?:ms|\.\d+s)/);
  assert.match(stdout, /timing qm\/core: current image lookup \d+(?:ms|\.\d+s)/);
  assert.match(stdout, /timing qm\/core: fly deploy \d+(?:ms|\.\d+s)/);

  const summary = readFileSync(summaryPath, "utf8");
  assert.match(summary, /### Fly deploy timings \(qm\)/);
  assert.match(summary, /\| Stack \| Service \| Phase \| Duration \|/);
  assert.match(summary, /\| qm \| core \| app ensure \| \d+(?:ms|\.\d+s) \|/);
  assert.match(summary, /\| qm \| core \| secret checks \| \d+(?:ms|\.\d+s) \|/);
  assert.match(summary, /\| qm \| core \| Postgres ensure \| \d+(?:ms|\.\d+s) \|/);
  assert.match(summary, /\| qm \| core \| current image lookup \| \d+(?:ms|\.\d+s) \|/);
  assert.match(summary, /\| qm \| core \| fly deploy \| \d+(?:ms|\.\d+s) \|/);
});

test("fly up can deploy a tagged image without consulting the source stack's running image", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-tagged-"));
  const logPath = join(dir, "fly.log");
  const stdout = execFileSync(
    process.execPath,
    [
      bin,
      "up",
      "--config",
      join(repoRoot, "cli", "test", "fixtures", "imagefrom-stack.json"),
      "--only",
      "core",
      "--image-label",
      "sha123",
      "--image-repo-prefix",
      "qm",
    ],
    {
      encoding: "utf8",
      cwd: repoRoot,
      env: {
        ...process.env,
        FLY_BIN: fakeFlyBin(dir),
        FAKE_FLY_LOG: logPath,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  assert.match(stdout, /--image registry\.fly\.io\/qm-core:sha123/);
  assert.doesNotMatch(stdout, /current image lookup/);
  const commands = readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as string[]);
  assert.equal(
    commands.some((args) => args[0] === "status"),
    false,
  );
  assert.equal(
    commands.some(
      (args) => args[0] === "deploy" && args.includes("--image") && args.includes("registry.fly.io/qm-core:sha123"),
    ),
    true,
  );
});

test("fly image-from fails closed when Fly cannot resolve the running tag to a digest", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-no-digest-"));
  const result = spawnSync(
    process.execPath,
    [
      bin,
      "up",
      "--config",
      join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"),
      "--only",
      "core",
      "--image-from",
      "source",
    ],
    {
      encoding: "utf8",
      cwd: repoRoot,
      env: {
        ...process.env,
        FLY_BIN: fakeFlyBin(dir),
        FAKE_FLY_NO_IMAGE_DIGEST: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /source-core did not report an immutable image digest/);
  assert.doesNotMatch(result.stdout, /fly deploy/);
});

test("fly image-from resolves by machine id during a mixed rollout", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-mixed-images-"));
  const logPath = join(dir, "fly.log");
  execFileSync(
    process.execPath,
    [
      bin,
      "up",
      "--config",
      join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"),
      "--only",
      "core",
      "--image-from",
      "source",
    ],
    {
      encoding: "utf8",
      cwd: repoRoot,
      env: {
        ...process.env,
        FLY_BIN: fakeFlyBin(dir),
        FAKE_FLY_LOG: logPath,
        FAKE_FLY_MIXED_IMAGES: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  const commands = readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as string[]);
  const deploy = commands.find((args) => args[0] === "deploy");
  assert.ok(deploy?.includes(`registry.fly.io/source-core@sha256:${"a".repeat(64)}`));
  assert.equal(deploy?.includes(`registry.fly.io/source-core@sha256:${"b".repeat(64)}`), false);
});

test("a fresh Fly deploy stages the direct Managed Postgres URL without attaching the pooled URL", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-fresh-pg-"));
  const logPath = join(dir, "fly.log");
  execFileSync(
    process.execPath,
    [
      bin,
      "up",
      "--config",
      join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"),
      "--only",
      "core",
      "--image-from",
      "source",
    ],
    {
      encoding: "utf8",
      cwd: repoRoot,
      env: {
        ...process.env,
        FLY_BIN: fakeFlyBin(dir),
        FAKE_FLY_LOG: logPath,
        FAKE_FLY_FRESH_PG: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  const commands = readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as string[]);
  const directSecret = commands.findIndex(
    (args) => args[0] === "secrets" && args[1] === "set" && args.includes("DATABASE_URL=-"),
  );
  const deploy = commands.findIndex((args) => args[0] === "deploy");
  assert.ok(directSecret >= 0, "the direct DATABASE_URL is staged");
  assert.ok(deploy > directSecret, "the direct DATABASE_URL is staged before the first deploy");
  assert.equal(
    commands.some((args) => args[0] === "mpg" && args[1] === "attach"),
    false,
  );
});

test("Fly preserves an existing DATABASE_URL even when a same-name Managed Postgres cluster exists", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-existing-db-"));
  const logPath = join(dir, "fly.log");
  execFileSync(
    process.execPath,
    [
      bin,
      "up",
      "--config",
      join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"),
      "--only",
      "core",
      "--image-from",
      "source",
    ],
    {
      encoding: "utf8",
      cwd: repoRoot,
      env: {
        ...process.env,
        FLY_BIN: fakeFlyBin(dir),
        FAKE_FLY_LOG: logPath,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  const commands = readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as string[]);
  assert.equal(
    commands.some((args) => args[0] === "mpg"),
    false,
  );
  assert.equal(
    commands.some((args) => args[0] === "secrets" && args[1] === "set" && args.includes("DATABASE_URL=-")),
    false,
  );
});

test("Fly redacts credential-bearing Managed Postgres status failures", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-pg-error-"));
  const result = spawnSync(
    process.execPath,
    [
      bin,
      "up",
      "--config",
      join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"),
      "--only",
      "core",
      "--image-from",
      "source",
    ],
    {
      encoding: "utf8",
      cwd: repoRoot,
      env: {
        ...process.env,
        FLY_BIN: fakeFlyBin(dir),
        FAKE_FLY_FRESH_PG: "1",
        FAKE_FLY_STATUS_FAIL: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /failed to read Managed Postgres connection details/);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /fly-user|secret@|flympg\.net/);
});

test("fly up build-only runs from the caller cwd and preflights ownership without runtime deploy secrets", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-build-only-"));
  const logPath = join(dir, "fly.log");
  const cwdLogPath = join(dir, "fly-cwd.log");
  const stdout = execFileSync(
    process.execPath,
    [
      bin,
      "up",
      "--config",
      join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"),
      "--only",
      "core",
      "--build-only",
      "--image-label",
      "sha123",
    ],
    {
      encoding: "utf8",
      cwd: repoRoot,
      env: {
        ...process.env,
        FLY_BIN: fakeFlyBin(dir),
        FAKE_FLY_LOG: logPath,
        FAKE_FLY_DEPLOY_CWD_LOG: cwdLogPath,
        FAKE_FLY_OWNER_ONLY: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  assert.match(stdout, /--build-only --push --image-label sha123/);
  assert.match(stdout, /image: qm-core -> registry\.fly\.io\/qm-core:sha123/);
  const deployCwd = readFileSync(cwdLogPath, "utf8").trim();
  assert.equal(deployCwd, repoRoot);
  assert.notEqual(deployCwd, join(repoRoot, "deploy", "stacks", "acme"));
  const commands = readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as string[]);
  assert.equal(
    commands.some((args) => args[0] === "secrets" && args[1] === "list"),
    true,
  );
  assert.equal(
    commands.some((args) => args[0] === "secrets" && args[1] === "set"),
    true,
    "new apps receive only the ownership marker",
  );
  assert.equal(
    commands.some(
      (args) =>
        args[0] === "deploy" &&
        args.includes("--build-only") &&
        args.includes("--push") &&
        args.includes("--image-label"),
    ),
    true,
  );
});

test("fly up build-only dry-run plans without pushing an image", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-build-only-dry-run-"));
  const logPath = join(dir, "fly.log");
  const stdout = execFileSync(
    process.execPath,
    [
      bin,
      "up",
      "--config",
      join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"),
      "--only",
      "core",
      "--build-only",
      "--image-label",
      "sha123",
      "--dry-run",
    ],
    {
      encoding: "utf8",
      cwd: repoRoot,
      env: {
        ...process.env,
        FLY_BIN: fakeFlyBin(dir),
        FAKE_FLY_LOG: logPath,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  assert.match(stdout, /sandbox substrate: sprites; no OCI sandbox image publish/);
  assert.match(stdout, /Plan only\. Re-run without --dry-run to build images\./);
  const commands = readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as string[]);
  assert.equal(
    commands.some(
      (args) =>
        (args[0] === "apps" && args[1] === "create") ||
        (args[0] === "secrets" && (args[1] === "set" || args[1] === "unset")) ||
        args[0] === "deploy" ||
        (args[0] === "mpg" && args[1] === "create"),
    ),
    false,
  );
});

test("fly dry-run reports external sandbox backends", () => {
  for (const backend of ["porter", "smolmachines"]) {
    const dir = mkdtempSync(join(tmpdir(), `qm-fly-${backend}-dry-run-`));
    const logPath = join(dir, "fly.log");
    const configPath = join(dir, "qm.config.jsonc");
    try {
      writeFileSync(
        configPath,
        JSON.stringify({
          contract: 1,
          orgId: "acme",
          publicUrl: "https://agent.example.com",
          target: "fly",
          appPrefix: "qm",
          region: "sjc",
          flyOrg: "personal",
          services: ["core"],
          env: {
            core: {
              HARNESS: "mock",
              SANDBOX_BACKEND: backend,
              SNAPSHOT_STORE: "s3",
              TRANSFER_STORE: "s3",
              S3_BUCKET: "acme-data",
              S3_REGION: "auto",
            },
          },
        }),
      );
      const stdout = execFileSync(
        process.execPath,
        [bin, "up", "--config", configPath, "--only", "core", "--dry-run"],
        {
          encoding: "utf8",
          cwd: repoRoot,
          env: {
            ...process.env,
            FLY_BIN: fakeFlyBin(dir),
            FAKE_FLY_LOG: logPath,
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      assert.match(stdout, new RegExp(`sandbox substrate: ${backend}; no OCI sandbox image publish`));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
