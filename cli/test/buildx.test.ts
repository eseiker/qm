import assert from "node:assert/strict";
import { test } from "node:test";
import { buildxInvocation, sourceBuildEnvironment } from "../src/buildx.ts";

test("source build environments retain only explicit neutral capabilities", () => {
  const sensitive = "private-value";
  const env = sourceBuildEnvironment(
    {
      PATH: "/trusted/bin",
      HOME: "/trusted/home",
      DOCKER_CONFIG: "/trusted/docker",
      NODE_EXTRA_CA_CERTS: "/trusted/ca.pem",
      HTTPS_PROXY: "https://proxy.example.com",
      LC_ALL: "C",
      LC_UNKNOWN: "payload",
      AWS_SECRET_ACCESS_KEY: "aws-secret",
      GIT_CONFIG_COUNT: "1",
      NODE_OPTIONS: "--import=/payload.mjs",
      LD_PRELOAD: "/payload.so",
      BASH_ENV: "/payload.sh",
      PYTHONPATH: "/payload",
      BUILDX_CPU_PROFILE: "/leak/cpu.pprof",
      BUILDX_MEM_PROFILE: "/leak/mem.pprof",
      DOCKER_CLI_PLUGIN_ORIGINAL_CLI_COMMAND: "payload",
      DOCKER_CLI_PLUGIN_EXTRA_DIRS: "/trusted/plugins",
      DOCKER_UNKNOWN_FUTURE_CONTROL: "unknown",
      UNKNOWN_CONTROL: "unknown",
    },
    { sensitiveNames: ["WORKLOAD_SECRET"], sensitiveValues: [sensitive] },
  );
  assert.deepEqual(
    { ...env },
    {
      PATH: "/trusted/bin",
      HOME: "/trusted/home",
      DOCKER_CONFIG: "/trusted/docker",
      NODE_EXTRA_CA_CERTS: "/trusted/ca.pem",
      HTTPS_PROXY: "https://proxy.example.com",
      LC_ALL: "C",
      DOCKER_CLI_PLUGIN_EXTRA_DIRS: "/trusted/plugins",
      BUILDX_GIT_INFO: "false",
      BUILDX_GIT_LABELS: "false",
    },
  );
});

test("source build environments reject provider controls that disclose selected secrets", () => {
  for (const [base, options] of [
    [{ DOCKER_HOST: "unix:///safe.sock" }, { sensitiveNames: ["DOCKER_HOST"], sensitiveValues: [] }],
    [{ DOCKER_HOST: "private-value" }, { sensitiveNames: [], sensitiveValues: ["private-value"] }],
    [{ DOCKER_BUILDX_BIN: " /private/buildx " }, { sensitiveNames: [], sensitiveValues: ["/private/buildx"] }],
    [{ DOCKER_BUILDX_BIN: " /private/buildx " }, { sensitiveNames: [], sensitiveValues: [" /private/buildx "] }],
    [{}, { sensitiveNames: [], sensitiveValues: ["false"] }],
  ] as const) {
    assert.throws(() => sourceBuildEnvironment(base, options), /conflict.*deployment secret/);
  }
});

test("source build environments ignore semantically absent selected secrets", () => {
  const env = sourceBuildEnvironment(
    { DOCKER_TLS_VERIFY: "", PATH: "/trusted/bin" },
    { sensitiveNames: [], sensitiveValues: [undefined, "", "   "] },
  );
  assert.deepEqual(
    { ...env },
    {
      DOCKER_TLS_VERIFY: "",
      PATH: "/trusted/bin",
      BUILDX_GIT_INFO: "false",
      BUILDX_GIT_LABELS: "false",
    },
  );
});

test("buildx invocation ignores inherited executable overrides", () => {
  const inherited = Object.getOwnPropertyDescriptor(Object.prototype, "DOCKER_BUILDX_BIN");
  Object.defineProperty(Object.prototype, "DOCKER_BUILDX_BIN", {
    configurable: true,
    enumerable: true,
    value: "/payload/buildx",
  });
  try {
    const invocation = buildxInvocation(["inspect"], {});
    assert.equal(invocation.command, "docker");
    assert.deepEqual(invocation.args, ["buildx", "inspect"]);
    assert.equal(Object.getPrototypeOf(invocation.env), null);
    assert.equal(Object.hasOwn(invocation.env, "DOCKER_BUILDX_BIN"), false);
  } finally {
    if (inherited) Object.defineProperty(Object.prototype, "DOCKER_BUILDX_BIN", inherited);
    else delete (Object.prototype as Record<string, unknown>).DOCKER_BUILDX_BIN;
  }
});

test("buildx invocation uses one explicit environment snapshot", () => {
  const base = sourceBuildEnvironment(
    { DOCKER_BUILDX_BIN: " /trusted/buildx ", PROVIDER_TOKEN: "first" },
    { sensitiveNames: [], sensitiveValues: [] },
  );
  const direct = buildxInvocation(["inspect"], base);
  base.DOCKER_BUILDX_BIN = "/changed/buildx";
  base.PROVIDER_TOKEN = "changed";
  assert.deepEqual(
    { ...direct, env: { ...direct.env } },
    {
      command: "/trusted/buildx",
      args: ["inspect"],
      env: { DOCKER_BUILDX_BIN: "/trusted/buildx", BUILDX_GIT_INFO: "false", BUILDX_GIT_LABELS: "false" },
    },
  );

  const blank = sourceBuildEnvironment({ DOCKER_BUILDX_BIN: "   " }, { sensitiveNames: [], sensitiveValues: [] });
  assert.equal(blank.DOCKER_BUILDX_BIN, undefined);

  const fallback = buildxInvocation(["inspect"], {}, ["build", "fallback"]);
  assert.deepEqual(
    { ...fallback, env: { ...fallback.env } },
    {
      command: "docker",
      args: ["build", "fallback"],
      env: {},
    },
  );
  const defaultFallback = buildxInvocation(["inspect"], {});
  assert.deepEqual(
    { ...defaultFallback, env: { ...defaultFallback.env } },
    {
      command: "docker",
      args: ["buildx", "inspect"],
      env: {},
    },
  );
});
