import { test } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runSandboxBuild, type SandboxBuildOpts } from "../src/commands/sandbox.ts";
import { CONFIG_FILENAME, loadConfigAt, type QmConfig } from "../src/config.ts";

const CONFIG: QmConfig = {
  contract: 1,
  orgId: "acme",
  publicUrl: "http://localhost:8080",
  target: "docker",
  services: ["core"],
  plugins: [],
  skills: [],
  env: {},
  imageOverrides: {},
};

function sandboxDir(setup: (sb: string) => void): string {
  const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-"));
  const sb = join(dir, "sandbox");
  mkdirSync(sb, { recursive: true });
  setup(sb);
  return sb;
}

function tool(sb: string, id: string, descriptor: object, withExe = true): void {
  const td = join(sb, "tools", id);
  mkdirSync(td, { recursive: true });
  writeFileSync(join(td, "tool.json"), JSON.stringify(descriptor));
  if (withExe) {
    writeFileSync(join(td, id), "#!/usr/bin/env bash\necho hi\n");
    chmodSync(join(td, id), 0o755);
  }
}

function sandboxDeployment(
  configDir: string,
  config: QmConfig = CONFIG,
): {
  config: QmConfig;
  configDir: string;
  configPath: string;
  configIdentity: ReturnType<typeof loadConfigAt>["configIdentity"];
} {
  const configPath = join(configDir, CONFIG_FILENAME);
  writeFileSync(configPath, JSON.stringify(config));
  const loaded = loadConfigAt(configPath);
  return {
    config: loaded.config,
    configDir,
    configPath: loaded.path,
    configIdentity: loaded.configIdentity,
  };
}

function dryRun(
  opts: Omit<SandboxBuildOpts, "dryRun" | "config" | "configDir" | "configPath" | "configIdentity"> & {
    config?: QmConfig;
    configDir?: string;
  },
): string {
  const lines: string[] = [];
  const log = console.log,
    warn = console.warn;
  console.log = (...a: unknown[]): void => void lines.push(a.join(" "));
  console.warn = (...a: unknown[]): void => void lines.push(a.join(" "));
  try {
    const deployment = sandboxDeployment(opts.configDir ?? dirname(opts.sandboxDir), opts.config);
    runSandboxBuild({
      ...opts,
      ...deployment,
      dryRun: true,
    });
  } finally {
    console.log = log;
    console.warn = warn;
  }
  return lines.join("\n").replace(/\x1b\[[0-9;]*m/g, "");
}

interface RecordedBuild {
  args: string[];
  env: NodeJS.ProcessEnv;
}

function buildProbe(dir: string, name: string, logPath: string): string {
  const path = join(dir, name);
  writeFileSync(
    path,
    `#!${process.execPath}\nrequire("node:fs").writeFileSync(${JSON.stringify(logPath)}, JSON.stringify({ args: process.argv.slice(2), env: process.env }));\n`,
  );
  chmodSync(path, 0o755);
  return path;
}

function recordedBuild(path: string): RecordedBuild {
  return JSON.parse(readFileSync(path, "utf8")) as RecordedBuild;
}

function withEnvironment<T>(values: Readonly<Record<string, string | undefined>>, run: () => T): T {
  const previous = new Map(Object.keys(values).map((name) => [name, process.env[name]]));
  try {
    for (const [name, value] of Object.entries(values)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    return run();
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

test("generates a Dockerfile that COPYs each tool executable onto PATH + bakes the presence check", () => {
  const sb = sandboxDir((s) => tool(s, "example-tool", { id: "example-tool", install: { binary: "example-tool" } }));
  try {
    const out = dryRun({ sandboxDir: sb });
    assert.match(out, /FROM registry\.invalid\/qm\/qm-sandbox-base@sha256:a{64}/);
    assert.match(out, /COPY tools\/example-tool\/example-tool \/usr\/local\/bin\/example-tool/);
    assert.match(out, /command -v "\$b"/);
    assert.match(out, /'example-tool'/);
    assert.match(out, /acme-sandbox:local/);
  } finally {
    rmSync(sb, { recursive: true, force: true });
  }
});

test("--from overrides the base image for the generated Dockerfile", () => {
  const sb = sandboxDir((s) => tool(s, "t", { id: "t" }));
  try {
    const out = dryRun({ sandboxDir: sb, from: "registry.fly.io/custom-base:v1" });
    assert.match(out, /FROM registry\.fly\.io\/custom-base:v1/);
  } finally {
    rmSync(sb, { recursive: true, force: true });
  }
});

test("a missing sandbox directory builds the package base without tool instructions", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-missing-"));
  try {
    const out = dryRun({ sandboxDir: join(dir, "sandbox") });
    assert.match(out, /FROM registry\.invalid\/qm\/qm-sandbox-base@sha256:a{64}/);
    assert.match(out, /tools:\s+\(none\)/);
    assert.doesNotMatch(out, /COPY tools\/|RUN chmod/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a skills-only sandbox builds the package base without tool instructions", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-skills-"));
  const skillDir = join(dir, "sandbox", "skills", "example");
  mkdirSync(skillDir, { recursive: true });
  writeFileSync(
    join(skillDir, "SKILL.md"),
    "---\nname: example\ndescription: Example skill\n---\nUse the example skill.\n",
  );
  try {
    const out = dryRun({ sandboxDir: join(dir, "sandbox") });
    assert.match(out, /FROM registry\.invalid\/qm\/qm-sandbox-base@sha256:a{64}/);
    assert.match(out, /tools:\s+\(none\)/);
    assert.doesNotMatch(out, /COPY tools\/|RUN chmod/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a custom sandbox/Dockerfile owns the recipe; --from is warned-ignored; presence check appended", () => {
  const sb = sandboxDir((s) => {
    tool(s, "apt-tool", { id: "apt-tool", install: { binary: "apt-tool" } }, false);
    writeFileSync(join(s, "Dockerfile"), "FROM my/base:1\nRUN apt-get install -y apt-tool\n");
  });
  try {
    const out = dryRun({ sandboxDir: sb, from: "registry.fly.io/ignored:1" });
    assert.match(out, /FROM my\/base:1/);
    assert.match(out, /--from is ignored/);
    assert.match(out, /command -v "\$b"/);
    assert.match(out, /'apt-tool'/);
  } finally {
    rmSync(sb, { recursive: true, force: true });
  }
});

test("sandbox build rejects an external Dockerfile symlink before invoking Buildx", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-linked-dockerfile-"));
  const sb = join(dir, "sandbox");
  mkdirSync(sb);
  writeFileSync(join(dir, "external.Dockerfile"), "FROM external\n");
  symlinkSync(join(dir, "external.Dockerfile"), join(sb, "Dockerfile"));
  try {
    assert.throws(() => dryRun({ sandboxDir: sb }), /regular file within its root/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("custom Dockerfile provenance recognizes platform flags, aliases, lowercase, and stage reuse", () => {
  const sb = sandboxDir((s) => {
    writeFileSync(
      join(s, "Dockerfile"),
      "from --platform=linux/arm64 my/base:1 AS build\nRUN true\nFROM build AS final\n",
    );
  });
  try {
    const out = dryRun({ sandboxDir: sb });
    assert.match(out, /base:\s+.*Dockerfile \(custom\)/);
    assert.match(out, /from --platform=linux\/arm64 my\/base:1 AS build/);
  } finally {
    rmSync(sb, { recursive: true, force: true });
  }
});

test("custom Dockerfiles must pin all but one distinct external base", () => {
  const sb = sandboxDir((s) => {
    writeFileSync(join(s, "Dockerfile"), "FROM first/base:1 AS build\nFROM second/base:2\n");
  });
  try {
    assert.throws(() => dryRun({ sandboxDir: sb }), /multiple mutable external base images/);
  } finally {
    rmSync(sb, { recursive: true, force: true });
  }
});

test("--tag sets the image tag", () => {
  const sb = sandboxDir((s) => tool(s, "t", { id: "t" }));
  try {
    const out = dryRun({ sandboxDir: sb, tag: "acme-sandbox:v2" });
    assert.match(out, /acme-sandbox:v2/);
  } finally {
    rmSync(sb, { recursive: true, force: true });
  }
});

test("sandbox build cleans generated Dockerfile and empty-context directories", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-cleanup-"));
  try {
    const out = dryRun({ sandboxDir: join(dir, "missing") });
    const command = out.split("\n").find((line) => line.startsWith("docker buildx build"));
    assert.ok(command);
    const dockerfile = command.match(/--file (\S+)/)?.[1];
    const context = command.split(" ").at(-1);
    assert.ok(dockerfile && context);
    assert.equal(existsSync(dirname(dockerfile)), false);
    assert.equal(existsSync(context), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a broken layer (tool with no executable and no Dockerfile) fails before building", () => {
  const sb = sandboxDir((s) => tool(s, "x", { id: "x", install: { binary: "x" } }, false));
  try {
    assert.throws(() => dryRun({ sandboxDir: sb }), /sandbox check failed/);
  } finally {
    rmSync(sb, { recursive: true, force: true });
  }
});

test("sandbox build uses one sanitized deployment and source-build environment snapshot", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-env-"));
  const sb = join(dir, "sandbox");
  const logPath = join(dir, "build.json");
  const selectedEnv = join(dir, "selected.env");
  mkdirSync(sb);
  const buildx = buildProbe(dir, "buildx-probe", logPath);
  writeFileSync(
    selectedEnv,
    "CORE_SIGNING_SECRET=selected-core-secret\nSANDBOX_STORE_SECRET=selected-store-secret\nSANDBOX_HOST_SECRET=selected-host-secret\n",
  );
  const config: QmConfig = {
    ...CONFIG,
    secretEnv: {
      core: {
        WORKLOAD_ALIAS: "SANDBOX_STORE_SECRET",
        FUTURE_WORKLOAD_ALIAS: "SANDBOX_HOST_SECRET",
      },
    },
  };
  const deployment = sandboxDeployment(dir, config);
  const originalLog = console.log;
  try {
    withEnvironment(
      {
        DOCKER_BUILDX_BIN: buildx,
        DOCKER_HOST: "unix:///early-docker.sock",
        DOCKER_CLI_PLUGIN_EXTRA_DIRS: join(dir, "plugins"),
        DOCKER_CLI_HINTS: "enabled",
        BUILDX_CPU_PROFILE: join(dir, "cpu.pprof"),
        BUILDX_MEM_PROFILE: join(dir, "mem.pprof"),
        BUILDX_GIT_INFO: "true",
        BUILDX_GIT_LABELS: "true",
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "credential.helper",
        NODE_OPTIONS: `--import=${join(dir, "payload.mjs")}`,
        AWS_SECRET_ACCESS_KEY: "ambient-aws-secret",
        CORE_SIGNING_SECRET: "ambient-core-secret",
        SANDBOX_STORE_SECRET: "ambient-store-secret",
        SANDBOX_HOST_SECRET: "ambient-host-secret",
        WORKLOAD_ALIAS: "ambient-runtime-alias",
        FUTURE_WORKLOAD_ALIAS: "ambient-future-runtime-alias",
        UNRELATED_DUPLICATE: "selected-core-secret",
        QM_DEPLOY_ENV_FILE_ONLY: undefined,
      },
      () => {
        let mutated = false;
        console.log = (): void => {
          if (mutated) return;
          mutated = true;
          process.env.DOCKER_BUILDX_BIN = join(dir, "late-buildx");
          process.env.DOCKER_HOST = "selected-core-secret";
          process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS = join(dir, "late-plugins");
          process.env.CORE_SIGNING_SECRET = "late-core-secret";
        };
        try {
          runSandboxBuild({
            sandboxDir: sb,
            ...deployment,
            envFile: selectedEnv,
          });
        } finally {
          console.log = originalLog;
        }
      },
    );

    const call = recordedBuild(logPath);
    assert.deepEqual(call.args.slice(0, 5), ["build", "--platform", "linux/amd64", "--load", "--provenance=false"]);
    assert.equal(call.env.DOCKER_BUILDX_BIN, buildx);
    assert.equal(call.env.DOCKER_HOST, "unix:///early-docker.sock");
    assert.equal(call.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS, join(dir, "plugins"));
    assert.equal(call.env.BUILDX_GIT_INFO, "false");
    assert.equal(call.env.BUILDX_GIT_LABELS, "false");
    for (const name of [
      "DOCKER_CLI_HINTS",
      "BUILDX_CPU_PROFILE",
      "BUILDX_MEM_PROFILE",
      "GIT_CONFIG_COUNT",
      "GIT_CONFIG_KEY_0",
      "NODE_OPTIONS",
      "AWS_SECRET_ACCESS_KEY",
      "CORE_SIGNING_SECRET",
      "SANDBOX_STORE_SECRET",
      "SANDBOX_HOST_SECRET",
      "WORKLOAD_ALIAS",
      "FUTURE_WORKLOAD_ALIAS",
      "UNRELATED_DUPLICATE",
      "QM_DEPLOY_ENV_FILE_ONLY",
    ]) {
      assert.equal(call.env[name], undefined, name);
    }
    for (const value of ["selected-core-secret", "selected-store-secret", "selected-host-secret"]) {
      assert.equal(Object.values(call.env).includes(value), false, value);
    }
  } finally {
    console.log = originalLog;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sandbox build uses Docker Buildx fallback with the captured file-only environment", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-fallback-"));
  const sb = join(dir, "sandbox");
  const logPath = join(dir, "build.json");
  mkdirSync(sb);
  buildProbe(dir, "docker", logPath);
  writeFileSync(join(dir, ".env"), "CORE_SIGNING_SECRET=default-file-secret\n");
  const deployment = sandboxDeployment(dir);
  const originalLog = console.log;
  try {
    withEnvironment(
      {
        PATH: dir,
        DOCKER_BUILDX_BIN: undefined,
        DOCKER_HOST: "ambient-file-only-value",
        CORE_SIGNING_SECRET: "ambient-overridden-secret",
        CAPABILITY_SECRET: "ambient-file-only-value",
        QM_DEPLOY_ENV_FILE_ONLY: "1",
        BUILDX_GIT_INFO: "true",
        BUILDX_GIT_LABELS: "true",
      },
      () => {
        console.log = (): void => undefined;
        try {
          runSandboxBuild({ sandboxDir: sb, ...deployment });
        } finally {
          console.log = originalLog;
        }
      },
    );
    const call = recordedBuild(logPath);
    assert.deepEqual(call.args.slice(0, 6), [
      "buildx",
      "build",
      "--platform",
      "linux/amd64",
      "--load",
      "--provenance=false",
    ]);
    assert.equal(call.env.PATH, dir);
    assert.equal(call.env.DOCKER_HOST, "ambient-file-only-value");
    assert.equal(call.env.CORE_SIGNING_SECRET, undefined);
    assert.equal(call.env.CAPABILITY_SECRET, undefined);
    assert.equal(Object.values(call.env).includes("default-file-secret"), false);
    assert.equal(call.env.QM_DEPLOY_ENV_FILE_ONLY, undefined);
    assert.equal(call.env.BUILDX_GIT_INFO, "false");
    assert.equal(call.env.BUILDX_GIT_LABELS, "false");
  } finally {
    console.log = originalLog;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sandbox build rejects secret-store and provider-control collisions", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-collision-"));
  const sb = join(dir, "sandbox");
  const selectedEnv = join(dir, "selected.env");
  mkdirSync(sb);
  try {
    const deployment = sandboxDeployment(dir);
    writeFileSync(selectedEnv, "CORE_SIGNING_SECRET=selected-secret\n");
    withEnvironment({ DOCKER_HOST: "selected-secret" }, () => {
      assert.throws(
        () =>
          runSandboxBuild({
            sandboxDir: sb,
            ...deployment,
            envFile: selectedEnv,
            dryRun: true,
          }),
        /source-build provider control DOCKER_HOST conflicts with a deployment secret/,
      );
    });

    withEnvironment(
      {
        DOCKER_HOST: "ambient-postgres-password",
        POSTGRES_PASSWORD: "ambient-postgres-password",
      },
      () => {
        assert.throws(
          () =>
            runSandboxBuild({
              sandboxDir: sb,
              ...deployment,
              dryRun: true,
            }),
          /source-build provider control DOCKER_HOST conflicts with a deployment secret/,
        );
      },
    );

    withEnvironment(
      {
        DOCKER_HOST: "ambient-catalog-secret",
        CORE_SIGNING_SECRET: "ambient-catalog-secret",
      },
      () => {
        assert.throws(
          () =>
            runSandboxBuild({
              sandboxDir: sb,
              ...sandboxDeployment(dir),
              dryRun: true,
            }),
          /source-build provider control DOCKER_HOST conflicts with a deployment secret/,
        );
      },
    );

    const customSourceConfig: QmConfig = {
      ...CONFIG,
      secretEnv: { core: { WORKLOAD_ALIAS: "CUSTOM_STORE_TOKEN" } },
    };
    withEnvironment(
      {
        DOCKER_HOST: "ambient-custom-secret",
        CUSTOM_STORE_TOKEN: "ambient-custom-secret",
      },
      () => {
        assert.doesNotThrow(() => dryRun({ sandboxDir: sb, configDir: dir, config: customSourceConfig }));
        writeFileSync(selectedEnv, "CUSTOM_STORE_TOKEN=ambient-custom-secret\n");
        assert.throws(
          () =>
            runSandboxBuild({
              sandboxDir: sb,
              ...sandboxDeployment(dir, customSourceConfig),
              envFile: selectedEnv,
              dryRun: true,
            }),
          /source-build provider control DOCKER_HOST conflicts with a deployment secret/,
        );
      },
    );

    const providerSourceConfig: QmConfig = {
      ...CONFIG,
      secretEnv: { core: { WORKLOAD_ALIAS: "DOCKER_HOST" } },
    };
    withEnvironment({ DOCKER_HOST: "unix:///safe.sock" }, () => {
      assert.throws(
        () =>
          runSandboxBuild({
            sandboxDir: sb,
            ...sandboxDeployment(dir, providerSourceConfig),
            dryRun: true,
          }),
        /source-build provider control DOCKER_HOST conflicts with a deployment secret/,
      );
    });

    writeFileSync(selectedEnv, "CORE_SIGNING_SECRET=false\n");
    assert.throws(
      () =>
        runSandboxBuild({
          sandboxDir: sb,
          ...sandboxDeployment(dir),
          envFile: selectedEnv,
          dryRun: true,
        }),
      /source-build metadata controls conflict with a deployment secret/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sandbox build rejects missing and blank explicit deployment environment paths", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-env-path-"));
  const sb = join(dir, "sandbox");
  mkdirSync(sb);
  try {
    const deployment = sandboxDeployment(dir);
    assert.throws(
      () =>
        runSandboxBuild({
          sandboxDir: sb,
          ...deployment,
          envFile: join(dir, "missing.env"),
          dryRun: true,
        }),
      /--env-file not found/,
    );
    assert.throws(
      () => runSandboxBuild({ sandboxDir: sb, ...deployment, envFile: "", dryRun: true }),
      /--env-file needs a non-empty path/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sandbox build accepts disjoint deployment environment symlink and hardlink aliases", async (t) => {
  for (const kind of ["symlink", "hardlink"] as const) {
    await t.test(kind, () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-env-alias-"));
      const sb = join(dir, "sandbox");
      const storedEnvironment = join(dir, "stored.env");
      const selectedEnvironment = join(dir, "selected.env");
      mkdirSync(sb);
      writeFileSync(storedEnvironment, "CORE_SIGNING_SECRET=selected-secret\n");
      if (kind === "symlink") symlinkSync(storedEnvironment, selectedEnvironment);
      else linkSync(storedEnvironment, selectedEnvironment);
      try {
        assert.match(dryRun({ sandboxDir: sb, envFile: selectedEnvironment }), /DRY RUN/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("sandbox build rejects an environment swapped to the loaded config identity", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-sbx-build-env-config-swap-"));
  const sb = join(dir, "sandbox");
  const selectedEnvironment = join(dir, "selected.env");
  const loadedConfig = join(dir, "loaded-config.jsonc");
  mkdirSync(sb);
  writeFileSync(selectedEnvironment, "CORE_SIGNING_SECRET=selected-secret\n");
  try {
    const deployment = sandboxDeployment(dir);
    renameSync(deployment.configPath, loadedConfig);
    writeFileSync(deployment.configPath, readFileSync(loadedConfig));
    rmSync(selectedEnvironment);
    symlinkSync(loadedConfig, selectedEnvironment);
    assert.throws(
      () =>
        runSandboxBuild({
          sandboxDir: sb,
          ...deployment,
          envFile: selectedEnvironment,
          dryRun: true,
        }),
      /deployment environment file must be separate from the deployment config/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
