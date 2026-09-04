import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
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
  truncateSync,
  writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONFIG_FILENAME, loadConfigInDir, type QmConfig } from "../src/config.ts";
import {
  clearDeploymentLayer as clearDeploymentLayerRaw,
  currentDeploymentLayerState as currentDeploymentLayerStateRaw,
  deploymentLayerBody,
  deploymentLayerBundle,
  deploymentLayerRequest as deploymentLayerRequestRaw,
  httpDeploymentLayerTransport as httpDeploymentLayerTransportRaw,
  syncDeploymentLayer as syncDeploymentLayerRaw,
  syncDeploymentLayerBody as syncDeploymentLayerBodyRaw,
  type DeploymentLayerPrecondition,
  type DeploymentLayerTransport,
} from "../src/deployment-layer.ts";
import { dockerDeploymentLayerTransport as dockerDeploymentLayerTransportRaw } from "../src/backends/docker.ts";
import { flyDeploymentLayerTransport as flyDeploymentLayerTransportRaw } from "../src/backends/fly.ts";
import { awsDeploymentLayerTransport as awsDeploymentLayerTransportRaw } from "../src/backends/aws.ts";
import { expectedDescriptors, runConformance as runConformanceRaw } from "../src/commands/conformance.ts";
import { CliError } from "../src/log.ts";
import type { FileIdentity } from "../src/util.ts";

const SECRET = "conformance-test-secret".repeat(2);
const TEST_OPERATION_ID = "a".repeat(32);
const TEST_CONFIG_IDENTITY: FileIdentity = { dev: -1n, ino: -1n };
const EMPTY_PRECONDITION = {
  generation: 0,
  contentHash: null,
  source: "none" as const,
  operationId: null,
};

const PINNED_SANDBOX_IMAGE = `registry.fly.io/acme-sandboxes@sha256:${"b".repeat(64)}`;

type TransportOptions = Parameters<DeploymentLayerTransport>[0];
type TestTransportOptions = Omit<TransportOptions, "configIdentity"> & { configIdentity?: FileIdentity };

function testTransport(
  transport: DeploymentLayerTransport,
): (opts: TestTransportOptions) => ReturnType<DeploymentLayerTransport> {
  return (opts) => transport({ ...opts, configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY });
}

const dockerDeploymentLayerTransport = testTransport(dockerDeploymentLayerTransportRaw);
const flyDeploymentLayerTransport = testTransport(flyDeploymentLayerTransportRaw);
const awsDeploymentLayerTransport = testTransport(awsDeploymentLayerTransportRaw);

function httpDeploymentLayerTransport(
  ...args: Parameters<typeof httpDeploymentLayerTransportRaw>
): ReturnType<typeof testTransport> {
  return testTransport(httpDeploymentLayerTransportRaw(...args));
}

type SyncOptions = Parameters<typeof syncDeploymentLayerRaw>[0];
type TestSyncOptions = Omit<SyncOptions, "configIdentity"> & { configIdentity?: FileIdentity };

const syncDeploymentLayer = (opts: TestSyncOptions): ReturnType<typeof syncDeploymentLayerRaw> =>
  syncDeploymentLayerRaw({ ...opts, configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY });

type StateOptions = Parameters<typeof currentDeploymentLayerStateRaw>[0];
type TestStateOptions = Omit<StateOptions, "configIdentity"> & { configIdentity?: FileIdentity };

const currentDeploymentLayerState = (opts: TestStateOptions): ReturnType<typeof currentDeploymentLayerStateRaw> =>
  currentDeploymentLayerStateRaw({ ...opts, configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY });

type RequestOptions = Parameters<typeof deploymentLayerRequestRaw>[0];
type TestRequestOptions = Omit<RequestOptions, "configIdentity"> & { configIdentity?: FileIdentity };

const deploymentLayerRequest = (opts: TestRequestOptions): ReturnType<typeof deploymentLayerRequestRaw> =>
  deploymentLayerRequestRaw({ ...opts, configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY });

type BodyOptions = Parameters<typeof syncDeploymentLayerBodyRaw>[0];
type TestBodyOptions = Omit<BodyOptions, "configIdentity"> & { configIdentity?: FileIdentity };

const syncDeploymentLayerBody = (opts: TestBodyOptions, body: string): ReturnType<typeof syncDeploymentLayerBodyRaw> =>
  syncDeploymentLayerBodyRaw({ ...opts, configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY }, body);

type ClearOptions = Parameters<typeof clearDeploymentLayerRaw>[0];
type TestClearOptions = Omit<ClearOptions, "configIdentity"> & { configIdentity?: FileIdentity };

const clearDeploymentLayer = (opts: TestClearOptions): ReturnType<typeof clearDeploymentLayerRaw> =>
  clearDeploymentLayerRaw({ ...opts, configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY });

type ConformanceOptions = Parameters<typeof runConformanceRaw>[0];
type TestConformanceOptions = Omit<ConformanceOptions, "configIdentity"> & { configIdentity?: FileIdentity };

const runConformance = (
  deployment: TestConformanceOptions,
  opts?: Parameters<typeof runConformanceRaw>[1],
): ReturnType<typeof runConformanceRaw> =>
  runConformanceRaw({ ...deployment, configIdentity: deployment.configIdentity ?? TEST_CONFIG_IDENTITY }, opts);

function writeLayer(dir: string): void {
  mkdirSync(join(dir, "sandbox", "skills", "a"), { recursive: true });
  mkdirSync(join(dir, "sandbox", "skills", "a-b"), { recursive: true });
  writeFileSync(join(dir, "sandbox", "skills", "a", "SKILL.md"), "---\nname: a\ndescription: skill a\n---\nbody a\n");
  writeFileSync(
    join(dir, "sandbox", "skills", "a-b", "SKILL.md"),
    "---\nname: a-b\ndescription: skill a-b\n---\nbody a-b\n",
  );
  mkdirSync(join(dir, "sandbox", "tools", "t"), { recursive: true });
  writeFileSync(
    join(dir, "sandbox", "tools", "t", "tool.json"),
    JSON.stringify({ install: { binary: "t" }, advertise: "runs t", id: "t" }),
  );
  writeFileSync(join(dir, "sandbox", "tools", "t", "t"), "#!/usr/bin/env bash\necho hi\n");
  chmodSync(join(dir, "sandbox", "tools", "t", "t"), 0o755);
}

function coreNormalizedHash(dir: string): string {
  const skillFiles = [
    { path: "skills/a/SKILL.md", content: readFileSync(join(dir, "sandbox", "skills", "a", "SKILL.md"), "utf8") },
    { path: "skills/a-b/SKILL.md", content: readFileSync(join(dir, "sandbox", "skills", "a-b", "SKILL.md"), "utf8") },
  ].reverse();
  const tools = [
    { path: "tools/t/tool.json", content: readFileSync(join(dir, "sandbox", "tools", "t", "tool.json"), "utf8") },
  ];
  const order = (a: { path: string }, b: { path: string }): number => a.path.localeCompare(b.path);
  const bundle = { contract: 1, tools: tools.sort(order), skills: skillFiles.sort(order) };
  return createHash("sha256").update(JSON.stringify(bundle)).digest("hex");
}

test("the CLI bundle hashes byte-identically to the core's full-path normalization (a vs a-b siblings)", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-"));
  try {
    writeLayer(dir);
    const bundle = deploymentLayerBundle(join(dir, "sandbox"));
    assert.deepEqual(
      bundle.skills.map((file) => file.path),
      ["skills/a-b/SKILL.md", "skills/a/SKILL.md"],
      "full-path order, not per-directory walk order",
    );
    const cliHash = createHash("sha256").update(JSON.stringify(bundle)).digest("hex");
    assert.equal(cliHash, coreNormalizedHash(dir));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("expectedDescriptors canonicalizes tool.json through the parser (key order never matters)", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-"));
  try {
    writeLayer(dir);
    const descriptors = expectedDescriptors(deploymentLayerBundle(join(dir, "sandbox")));
    assert.deepEqual(descriptors, [{ id: "t", advertise: "runs t", install: { binary: "t" } }]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer readers reject missing, regular-file, FIFO, and device roots", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-root-"));
  try {
    const file = join(dir, "file");
    const fifo = join(dir, "fifo");
    writeFileSync(file, "not a directory\n");
    execFileSync("mkfifo", [fifo]);
    for (const path of [join(dir, "missing"), file, "/dev/null"]) {
      assert.throws(() => deploymentLayerBundle(path), /root must be an existing directory/);
      assert.throws(() => deploymentLayerBody(path), /root must be an existing directory/);
    }
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const layer=await import(process.argv[1]);for(const name of ["deploymentLayerBundle","deploymentLayerBody"]){try{layer[name](process.argv[2]);process.exit(1)}catch(error){if(!String(error).includes("root must be an existing directory")){console.error(error);process.exit(2)}}}`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        fifo,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer readers accept an intentional symlink to a directory", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-root-"));
  try {
    const actual = join(dir, "actual");
    const linked = join(dir, "linked");
    mkdirSync(join(actual, "skills", "linked"), { recursive: true });
    writeFileSync(join(actual, "skills", "linked", "SKILL.md"), "linked skill\n");
    symlinkSync(actual, linked, "dir");
    assert.deepEqual(deploymentLayerBundle(linked), deploymentLayerBundle(actual));
    assert.equal(deploymentLayerBody(linked), deploymentLayerBody(actual));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer rejects a root-symlink swap-away-and-back during enumeration", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-root-aba-"));
  try {
    const actual = join(dir, "actual");
    const alternate = join(dir, "alternate");
    const linked = join(dir, "linked");
    mkdirSync(join(actual, "skills", "safe"), { recursive: true });
    mkdirSync(join(alternate, "skills", "external"), { recursive: true });
    writeFileSync(join(actual, "skills", "safe", "SKILL.md"), "safe content\n");
    writeFileSync(join(alternate, "skills", "external", "SKILL.md"), "external secret\n");
    symlinkSync(actual, linked, "dir");
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const layer=await import(process.argv[1]);const fs=(await import("node:fs")).default;const {syncBuiltinESMExports}=await import("node:module");const original=fs.opendirSync,target=fs.realpathSync(process.argv[5]+"/skills");let swapped=false;fs.opendirSync=function(path,...args){if(!swapped&&path===target){swapped=true;fs.renameSync(process.argv[3],process.argv[3]+".held");fs.symlinkSync(process.argv[4],process.argv[3],"dir");const opened=original.call(this,path,...args);fs.unlinkSync(process.argv[3]);fs.renameSync(process.argv[3]+".held",process.argv[3]);return opened}return original.call(this,path,...args)};syncBuiltinESMExports();try{layer.deploymentLayerBundle(process.argv[2]);process.exit(1)}catch(error){if(!swapped||!String(error).includes("changed while it was being read"))throw error}`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        linked,
        linked,
        alternate,
        actual,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer traversal remains bound when a root ancestor symlink is swapped", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-ancestor-aba-"));
  try {
    const actualParent = join(dir, "actual-parent");
    const alternateParent = join(dir, "alternate-parent");
    const linkedParent = join(dir, "linked-parent");
    const sandbox = join(linkedParent, "sandbox");
    mkdirSync(join(actualParent, "sandbox", "skills", "safe"), { recursive: true });
    mkdirSync(join(alternateParent, "sandbox", "skills"), { recursive: true });
    writeFileSync(join(actualParent, "sandbox", "skills", "safe", "SKILL.md"), "safe content\n");
    symlinkSync(actualParent, linkedParent, "dir");
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const layer=await import(process.argv[1]);const fs=(await import("node:fs")).default;const {syncBuiltinESMExports}=await import("node:module");const original=fs.opendirSync;let swapped=false;fs.opendirSync=function(path,...args){if(!swapped&&String(path).endsWith("/sandbox/skills")){swapped=true;fs.renameSync(process.argv[3],process.argv[3]+".held");fs.symlinkSync(process.argv[4],process.argv[3],"dir");const opened=original.call(this,path,...args);fs.unlinkSync(process.argv[3]);fs.renameSync(process.argv[3]+".held",process.argv[3]);return opened}return original.call(this,path,...args)};syncBuiltinESMExports();const bundle=layer.deploymentLayerBundle(process.argv[2]);if(!swapped||bundle.skills.length!==1||bundle.skills[0].content.trim()!=="safe content")process.exit(1)`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        sandbox,
        linkedParent,
        alternateParent,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer readers reject nested skills and tools roots that escape through symlinks", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-nested-root-"));
  try {
    const sandbox = join(dir, "sandbox");
    const externalSkills = join(dir, "external-skills");
    const externalTools = join(dir, "external-tools");
    mkdirSync(join(externalSkills, "secret"), { recursive: true });
    writeFileSync(join(externalSkills, "secret", "SKILL.md"), "external secret\n");
    mkdirSync(join(externalTools, "secret"), { recursive: true });
    writeFileSync(join(externalTools, "secret", "tool.json"), JSON.stringify({ id: "external-secret" }));
    mkdirSync(sandbox);
    symlinkSync(externalSkills, join(sandbox, "skills"), "dir");
    assert.throws(() => deploymentLayerBundle(sandbox), /directory must be within its root/);
    rmSync(join(sandbox, "skills"));
    mkdirSync(join(sandbox, "skills"));
    symlinkSync(externalTools, join(sandbox, "tools"), "dir");
    assert.throws(() => deploymentLayerBundle(sandbox), /directory must be within its root/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer readers reject files hardlinked to content outside the root", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-hardlink-"));
  try {
    const sandbox = join(dir, "sandbox");
    const external = join(dir, "outside-secret");
    const target = join(sandbox, "skills", "linked", "SKILL.md");
    mkdirSync(join(sandbox, "skills", "linked"), { recursive: true });
    writeFileSync(external, "TOP-SECRET\n", { mode: 0o600 });
    linkSync(external, target);
    assert.throws(() => deploymentLayerBundle(sandbox), /regular file within its root/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer rejects pathname replacement after opening the validated descriptor", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-file-race-"));
  try {
    const sandbox = join(dir, "sandbox");
    const target = join(sandbox, "skills", "safe", "SKILL.md");
    const external = join(dir, "external-secret");
    mkdirSync(join(sandbox, "skills", "safe"), { recursive: true });
    writeFileSync(target, "safe content\n");
    writeFileSync(external, "external secret\n");
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const layer=await import(process.argv[1]);const fs=(await import("node:fs")).default;const {syncBuiltinESMExports}=await import("node:module");const original=fs.readSync;let replaced=false;fs.readSync=function(fd,...args){if(!replaced){replaced=true;fs.renameSync(process.argv[3],process.argv[3]+".safe");fs.symlinkSync(process.argv[4],process.argv[3])}return original.call(this,fd,...args)};syncBuiltinESMExports();try{layer.deploymentLayerBundle(process.argv[2]);process.exit(1)}catch(error){if(!replaced||!String(error).includes("changed while it was being read"))throw error}`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        sandbox,
        target,
        external,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer nested FIFOs are rejected without blocking", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-file-fifo-"));
  try {
    const sandbox = join(dir, "sandbox");
    const target = join(sandbox, "skills", "fifo", "SKILL.md");
    mkdirSync(join(sandbox, "skills", "fifo"), { recursive: true });
    execFileSync("mkfifo", [target]);
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const {deploymentLayerBundle}=await import(process.argv[1]);try{deploymentLayerBundle(process.argv[2]);process.exit(1)}catch(error){if(!String(error).includes("regular file"))throw error}`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        sandbox,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer regular-to-FIFO replacement is rejected without blocking", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-file-fifo-race-"));
  try {
    const sandbox = join(dir, "sandbox");
    const target = join(sandbox, "skills", "fifo", "SKILL.md");
    mkdirSync(join(sandbox, "skills", "fifo"), { recursive: true });
    writeFileSync(target, "safe content\n");
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const layer=await import(process.argv[1]);const fs=(await import("node:fs")).default;const {execFileSync}=await import("node:child_process");const {syncBuiltinESMExports}=await import("node:module");const original=fs.realpathSync,target=fs.realpathSync(process.argv[3]);let replaced=false;fs.realpathSync=function(path,...args){const resolved=original.call(this,path,...args);if(!replaced&&path===target){replaced=true;fs.renameSync(path,path+".regular");execFileSync("mkfifo",[path])}return resolved};syncBuiltinESMExports();try{layer.deploymentLayerBundle(process.argv[2]);process.exit(1)}catch(error){if(!replaced||!String(error).includes("changed while it was being read"))throw error}`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        sandbox,
        target,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer rejects a nested directory swap-away-and-back during enumeration", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-directory-aba-"));
  try {
    const sandbox = join(dir, "sandbox");
    const target = join(sandbox, "skills", "safe");
    const external = join(dir, "external");
    mkdirSync(target, { recursive: true });
    mkdirSync(external);
    writeFileSync(join(target, "SKILL.md"), "safe content\n");
    writeFileSync(join(external, "SKILL.md"), "external secret\n");
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const layer=await import(process.argv[1]);const fs=(await import("node:fs")).default;const {syncBuiltinESMExports}=await import("node:module");const original=fs.opendirSync,target=fs.realpathSync(process.argv[3]);let swapped=false;fs.opendirSync=function(path,...args){if(!swapped&&path===target){swapped=true;fs.renameSync(path,path+".held");fs.renameSync(process.argv[4],path);const opened=original.call(this,path,...args);fs.renameSync(path,process.argv[4]+".read");fs.renameSync(path+".held",path);return opened}return original.call(this,path,...args)};syncBuiltinESMExports();try{layer.deploymentLayerBundle(process.argv[2]);process.exit(1)}catch(error){if(!swapped||!String(error).includes("changed while it was being read"))throw error}`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        sandbox,
        target,
        external,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the deployment layer sync rejects a bundle over the core's 1 MB limit before any request", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-big-"));
  try {
    mkdirSync(join(dir, "sandbox", "skills", "big"), { recursive: true });
    writeFileSync(
      join(dir, "sandbox", "skills", "big", "SKILL.md"),
      `---\nname: big\ndescription: big\n---\n${"x".repeat(1_100_000)}\n`,
    );
    const config: QmConfig = {
      contract: 1,
      orgId: "acme",
      publicUrl: "http://localhost:8080",
      target: "docker",
      services: ["core"],
      plugins: [],
      skills: [],
      env: {},
      imageOverrides: {},
      sandbox: { backend: "local", image: PINNED_SANDBOX_IMAGE },
    };
    process.env.CORE_SIGNING_SECRET = SECRET;
    try {
      await assert.rejects(
        () =>
          syncDeploymentLayer({
            config,
            transport: dockerDeploymentLayerTransport,
            configDir: dir,
            sandboxDir: join(dir, "sandbox"),
            operationId: TEST_OPERATION_ID,
          }),
        /1 MB/,
      );
    } finally {
      delete process.env.CORE_SIGNING_SECRET;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer size accounting rejects sparse, cumulative, and serialization-expanded assets", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-bounded-size-"));
  try {
    const sandbox = join(dir, "sandbox");
    const skills = join(sandbox, "skills");
    mkdirSync(join(skills, "sparse"), { recursive: true });
    writeFileSync(join(skills, "sparse", "SKILL.md"), "");
    truncateSync(join(skills, "sparse", "SKILL.md"), 100_000_000);
    assert.throws(() => deploymentLayerBundle(sandbox), /1 MB request limit/);
    rmSync(join(skills, "sparse"), { recursive: true });
    mkdirSync(join(skills, "first"), { recursive: true });
    mkdirSync(join(skills, "second"), { recursive: true });
    writeFileSync(join(skills, "first", "SKILL.md"), "a".repeat(600_000));
    writeFileSync(join(skills, "second", "SKILL.md"), "b".repeat(600_000));
    assert.throws(() => deploymentLayerBundle(sandbox), /1 MB request limit/);
    rmSync(join(skills, "first"), { recursive: true });
    rmSync(join(skills, "second"), { recursive: true });
    mkdirSync(join(skills, "escaped"), { recursive: true });
    writeFileSync(join(skills, "escaped", "SKILL.md"), '"'.repeat(600_000));
    assert.throws(() => deploymentLayerBundle(sandbox), /1 MB request limit/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer size accounting admits exactly 1 MB and rejects the next byte", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-size-boundary-"));
  try {
    const target = join(dir, "sandbox", "skills", "a", "SKILL.md");
    mkdirSync(join(dir, "sandbox", "skills", "a"), { recursive: true });
    writeFileSync(target, "x".repeat(999_922));
    assert.equal(Buffer.byteLength(deploymentLayerBody(join(dir, "sandbox"))), 1_000_000);
    writeFileSync(target, "x".repeat(999_923));
    assert.throws(() => deploymentLayerBody(join(dir, "sandbox")), /1 MB request limit/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer bounded reads reject a file that grows after descriptor validation", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-file-growth-"));
  try {
    const sandbox = join(dir, "sandbox");
    const target = join(sandbox, "skills", "growing", "SKILL.md");
    mkdirSync(join(sandbox, "skills", "growing"), { recursive: true });
    writeFileSync(target, "initial content\n");
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const layer=await import(process.argv[1]);const fs=(await import("node:fs")).default;const {syncBuiltinESMExports}=await import("node:module");const original=fs.readSync;let grew=false;fs.readSync=function(fd,...args){if(!grew){grew=true;fs.appendFileSync(process.argv[3],"growth")}return original.call(this,fd,...args)};syncBuiltinESMExports();try{layer.deploymentLayerBundle(process.argv[2]);process.exit(1)}catch(error){if(!grew||!String(error).includes("changed while it was being read"))throw error}`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        sandbox,
        target,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer bounded reads reject same-inode torn content", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-file-torn-"));
  try {
    const sandbox = join(dir, "sandbox");
    const target = join(sandbox, "skills", "torn", "SKILL.md");
    mkdirSync(join(sandbox, "skills", "torn"), { recursive: true });
    writeFileSync(target, "a".repeat(8_192));
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const layer=await import(process.argv[1]);const fs=(await import("node:fs")).default;const {syncBuiltinESMExports}=await import("node:module");const original=fs.readSync;let torn=false;fs.readSync=function(fd,buffer,offset,length,position){if(!torn&&length>2){const count=original.call(this,fd,buffer,offset,Math.floor(length/2),position);torn=true;const writer=fs.openSync(process.argv[3],"r+");try{fs.writeSync(writer,Buffer.alloc(4096,0x62),0,4096,4096)}finally{fs.closeSync(writer)}return count}return original.call(this,fd,buffer,offset,length,position)};syncBuiltinESMExports();try{layer.deploymentLayerBundle(process.argv[2]);process.exit(1)}catch(error){if(!torn||!String(error).includes("changed while it was being read"))throw error}`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        sandbox,
        target,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer rejects a multi-file snapshot assembled across a mutation", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-multi-file-torn-"));
  try {
    const sandbox = join(dir, "sandbox");
    const descriptor = join(sandbox, "tools", "example", "tool.json");
    const skill = join(sandbox, "skills", "example", "SKILL.md");
    mkdirSync(join(sandbox, "tools", "example"), { recursive: true });
    mkdirSync(join(sandbox, "skills", "example"), { recursive: true });
    writeFileSync(descriptor, JSON.stringify({ id: "old-tool" }));
    writeFileSync(skill, "---\nname: example\ndescription: example\n---\n");
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const layer=await import(process.argv[1]);const fs=(await import("node:fs")).default;const {syncBuiltinESMExports}=await import("node:module");const original=fs.openSync,trigger=fs.realpathSync(process.argv[4]);let mutated=false;fs.openSync=function(path,...args){if(!mutated&&path===trigger){mutated=true;fs.writeFileSync(process.argv[3],JSON.stringify({id:"new-tool"}))}return original.call(this,path,...args)};syncBuiltinESMExports();try{layer.deploymentLayerBundle(process.argv[2]);process.exit(1)}catch(error){if(!mutated||!String(error).includes("changed while it was being read"))throw error}`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        sandbox,
        descriptor,
        skill,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer rejects membership changes after directory enumeration", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-directory-snapshot-"));
  try {
    const sandbox = join(dir, "sandbox");
    const toolDir = join(sandbox, "tools", "example");
    const skill = join(sandbox, "skills", "example", "SKILL.md");
    mkdirSync(toolDir, { recursive: true });
    mkdirSync(join(sandbox, "skills", "example"), { recursive: true });
    writeFileSync(join(toolDir, "tool.json"), JSON.stringify({ id: "example" }));
    writeFileSync(skill, "---\nname: example\ndescription: example\n---\n");
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const layer=await import(process.argv[1]);const fs=(await import("node:fs")).default;const {syncBuiltinESMExports}=await import("node:module");const original=fs.openSync,trigger=fs.realpathSync(process.argv[4]);let mutated=false;fs.openSync=function(path,...args){if(!mutated&&path===trigger){mutated=true;fs.writeFileSync(process.argv[3],"late member")}return original.call(this,path,...args)};syncBuiltinESMExports();try{layer.deploymentLayerBundle(process.argv[2]);process.exit(1)}catch(error){if(!mutated||!String(error).includes("directory changed while it was being read"))throw error}`,
        new URL("../src/deployment-layer.ts", import.meta.url).href,
        sandbox,
        join(toolDir, "late.txt"),
        skill,
      ],
      { timeout: 2_000 },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a missing sandbox directory skips sync instead of replacing the deployed layer with empty", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-missing-"));
  const lines: string[] = [];
  t.mock.method(console, "log", (...parts: unknown[]) => void lines.push(parts.join(" ")));
  try {
    await syncDeploymentLayer({
      config: makeConfig("http://example.invalid"),
      transport: dockerDeploymentLayerTransport,
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
    });
    assert.ok(lines.some((line) => /skipped \(no sandbox directory/.test(line)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

interface CapturedRequest {
  method: string;
  url: string;
  timestamp: string;
  signature: string;
  body: string;
}

interface StubServer {
  close(done: () => void): void;
}

function startCoreStub(
  response: (request: CapturedRequest) => { status?: number; body: string },
  captured: CapturedRequest[],
): Promise<{ server: StubServer; port: number }> {
  const previous = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    const headers = new Headers(init?.headers);
    const request = {
      method: init?.method ?? "GET",
      url: url.pathname + url.search,
      timestamp: headers.get("x-timestamp") ?? "",
      signature: headers.get("x-signature") ?? "",
      body: typeof init?.body === "string" ? init.body : "",
    };
    captured.push(request);
    const result = response(request);
    return new Response(result.body, { status: result.status ?? 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return Promise.resolve({
    port: 43119,
    server: {
      close(done): void {
        globalThis.fetch = previous;
        done();
      },
    },
  });
}

function makeConfig(publicUrl: string): QmConfig {
  return {
    contract: 1,
    orgId: "acme",
    publicUrl,
    target: "docker",
    services: ["core"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
    sandbox: { backend: "local", image: PINNED_SANDBOX_IMAGE },
  };
}

function syncResponseBody(dir: string, values: Record<string, unknown> = {}): string {
  const body = deploymentLayerBody(join(dir, "sandbox"));
  return JSON.stringify({
    ok: true,
    version: 1,
    contentHash: createHash("sha256").update(body).digest("hex"),
    operationId: TEST_OPERATION_ID,
    changed: true,
    durable: true,
    ...values,
  });
}

function emptyStateBody(source: "none" | "filesystem" = "none"): string {
  return JSON.stringify({
    contract: 1,
    version: 0,
    generation: 0,
    contentHash: null,
    source,
    operationId: null,
  });
}

function syncProtocolResponse(
  dir: string,
  request: CapturedRequest,
  values: Record<string, unknown> = {},
): { status?: number; body: string } {
  if (request.method === "GET") return { body: emptyStateBody() };
  const requestOperationId = new URL(request.url, "http://core.invalid").searchParams.get("operationId");
  assert.match(requestOperationId ?? "", /^[a-f0-9]{32}$/);
  return { body: syncResponseBody(dir, { operationId: requestOperationId, ...values }) };
}

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const saved = Object.fromEntries(Object.keys(vars).map((name) => [name, process.env[name]]));
  for (const [name, value] of Object.entries(vars)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  try {
    return await fn();
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

async function freeUnboundPort(): Promise<number> {
  const { server, port } = await startCoreStub(() => ({ body: "{}" }), []);
  await new Promise<void>((resolve) => server.close(resolve));
  return port;
}

async function listenLocal(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => server.once("error", reject).listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

async function closeLocal(server: Server): Promise<void> {
  const closed = new Promise<void>((resolve, reject) =>
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    }),
  );
  server.closeAllConnections();
  await closed;
}

test("the docker sync PUTs the bundle to the base port with verifiable v0 HMAC signing headers", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-sync-"));
  const captured: CapturedRequest[] = [];
  const { server, port } = await startCoreStub((request) => syncProtocolResponse(dir, request), captured);
  try {
    writeLayer(dir);
    writeFileSync(join(dir, ".env"), `CORE_SIGNING_SECRET=${SECRET}\n`);
    await withEnv({ CORE_SIGNING_SECRET: "wrong-ambient-secret", QM_BASE_PORT: String(port) }, () =>
      syncDeploymentLayer({
        config: makeConfig("http://example.invalid"),
        transport: dockerDeploymentLayerTransport,
        configDir: dir,
        sandboxDir: join(dir, "sandbox"),
      }),
    );
    assert.equal(captured.length, 2);
    const request = captured[1]!;
    assert.equal(request.method, "PUT");
    const requestUrl = new URL(request.url, "http://core.invalid");
    assert.equal(requestUrl.pathname, "/v1/deployment-layer");
    assert.equal(requestUrl.searchParams.get("generation"), "0");
    assert.equal(requestUrl.searchParams.get("source"), "none");
    assert.match(requestUrl.searchParams.get("operationId") ?? "", /^[a-f0-9]{32}$/);
    assert.equal(request.body, JSON.stringify(deploymentLayerBundle(join(dir, "sandbox"))));
    const expected = createHmac("sha256", SECRET)
      .update(`v0:${request.timestamp}:PUT\n${request.url}\n${request.body}`)
      .digest("hex");
    assert.equal(request.signature, `v0=${expected}`);
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the shared HTTP transport rejects invalid signing secrets before making a request", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-secret-"));
  let requests = 0;
  t.mock.method(globalThis, "fetch", async () => {
    requests++;
    return new Response("{}");
  });
  try {
    await withEnv({ CORE_SIGNING_SECRET: undefined }, async () => {
      const envFile = join(dir, ".env");
      const transport = httpDeploymentLayerTransport({
        urlOf: () => new URL("https://example.invalid/v1/deployment-layer"),
      });
      for (const value of ["short", "replace-me", `private\0value`]) {
        writeFileSync(envFile, `CORE_SIGNING_SECRET=${value}\n`);
        await assert.rejects(
          () =>
            transport({
              config: makeConfig("https://example.invalid"),
              configDir: dir,
              method: "GET",
              body: "",
            }),
          /CORE_SIGNING_SECRET is missing, placeholder, or insecure/,
        );
      }
      rmSync(envFile);
      await assert.rejects(
        () =>
          transport({
            config: makeConfig("https://example.invalid"),
            configDir: dir,
            envFile,
            method: "GET",
            body: "",
          }),
        /--env-file not found/,
      );
      await assert.rejects(
        () =>
          transport({
            config: makeConfig("https://example.invalid"),
            configDir: dir,
            envFile: "",
            method: "GET",
            body: "",
          }),
        /--env-file needs a non-empty path/,
      );
      const fallback = httpDeploymentLayerTransport({
        urlOf: () => new URL("https://example.invalid/v1/deployment-layer"),
        secretFallback: () => `fallback\0private`,
      });
      await assert.rejects(
        () => fallback({ config: makeConfig("https://example.invalid"), configDir: dir, method: "GET", body: "" }),
        /CORE_SIGNING_SECRET is missing, placeholder, or insecure/,
      );
      assert.equal(requests, 0);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the HTTP transport rejects an env alias to the loaded config after the config path is replaced", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-config-identity-"));
  const configPath = join(dir, CONFIG_FILENAME);
  const originalConfig = join(dir, "loaded.config.jsonc");
  const envFile = join(dir, "deployment.env");
  let requests = 0;
  t.mock.method(globalThis, "fetch", async () => {
    requests++;
    return new Response("{}");
  });
  try {
    writeFileSync(configPath, JSON.stringify(makeConfig("https://example.invalid")));
    const loaded = loadConfigInDir(dir);
    renameSync(configPath, originalConfig);
    writeFileSync(configPath, JSON.stringify(makeConfig("https://replacement.invalid")));
    symlinkSync(originalConfig, envFile);
    await withEnv({ CORE_SIGNING_SECRET: SECRET }, () =>
      assert.rejects(
        () =>
          httpDeploymentLayerTransport()({
            config: loaded.config,
            configIdentity: loaded.configIdentity,
            configDir: dir,
            envFile,
            method: "GET",
            body: "",
          }),
        /deployment environment file must be separate from the deployment config/,
      ),
    );
    assert.equal(requests, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the HTTP transport uses one environment snapshot when the file changes before the request", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-env-race-"));
  try {
    const envFile = join(dir, "deployment.env");
    for (const mode of ["delete", "swap"]) {
      writeFileSync(envFile, `CORE_SIGNING_SECRET=${SECRET}\n`);
      execFileSync(
        process.execPath,
        [
          "--input-type=module",
          "--eval",
          `const fs=(await import("node:fs")).default;const {createHmac}=await import("node:crypto");const {httpDeploymentLayerTransport}=await import(process.argv[1]);const target=process.argv[2],mode=process.argv[3];process.env.CORE_SIGNING_SECRET="ambient-secret-that-must-not-be-used";globalThis.fetch=async(input,init)=>{if(mode==="delete")fs.unlinkSync(target);else{fs.renameSync(target,target+".original");fs.writeFileSync(target,"CORE_SIGNING_SECRET=changed-secret-that-must-not-be-used\\n")}const headers=new Headers(init.headers),timestamp=headers.get("x-timestamp"),body=String(init.body??""),path=new URL(input).pathname,expected=createHmac("sha256",${JSON.stringify(SECRET)}).update("v0:"+timestamp+":"+init.method+"\\n"+path+"\\n"+body).digest("hex");if(headers.get("x-signature")!=="v0="+expected)process.exit(1);return new Response("{}");};await httpDeploymentLayerTransport()({config:{publicUrl:"https://example.invalid"},configIdentity:{dev:-1n,ino:-1n},configDir:process.cwd(),envFile:target,method:"GET",body:""})`,
          new URL("../src/deployment-layer.ts", import.meta.url).href,
          envFile,
          mode,
        ],
        { timeout: 2_000 },
      );
      rmSync(`${envFile}.original`, { force: true });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the HTTP mutation identity and precondition are carried in the signed request target", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-replace-signature-"));
  const contentHash = "a".repeat(64);
  const currentOperationId = "b".repeat(32);
  const operationId = "c".repeat(32);
  const precondition = { generation: 3, source: "durable" as const, contentHash, operationId: currentOperationId };
  try {
    writeFileSync(join(dir, ".env"), `CORE_SIGNING_SECRET=${SECRET}\n`);
    t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(String(input));
      const headers = new Headers(init?.headers);
      const timestamp = headers.get("x-timestamp")!;
      const expected = createHmac("sha256", SECRET)
        .update(`v0:${timestamp}:PUT\n${url.pathname}${url.search}\n{}`)
        .digest("hex");
      assert.equal(
        url.search,
        `?generation=3&source=durable&contentHash=${contentHash}&currentOperationId=${currentOperationId}&operationId=${operationId}`,
      );
      assert.equal(headers.get("x-signature"), `v0=${expected}`);
      return new Response("{}");
    });
    await httpDeploymentLayerTransport({
      urlOf: () => new URL("https://example.invalid/v1/deployment-layer"),
    })({
      config: makeConfig("https://example.invalid"),
      configDir: dir,
      method: "PUT",
      body: "{}",
      precondition,
      operationId,
    });
    await assert.rejects(
      () =>
        deploymentLayerRequest({
          config: makeConfig("https://example.invalid"),
          configDir: dir,
          method: "PUT",
          body: "{}",
          precondition: { ...precondition, contentHash: "not-a-hash" },
          operationId,
          transport: async () => ({ status: 200, body: "{}" }),
        }),
      /durable precondition requires a lowercase SHA-256 hash/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the conditional clear uses DELETE and validates the exact cleared hash", async () => {
  const contentHash = "b".repeat(64);
  const operationId = "c".repeat(32);
  const precondition = { generation: 3, source: "durable" as const, contentHash, operationId: null };
  const requests: Array<{
    method: string;
    body: string;
    precondition?: DeploymentLayerPrecondition;
    operationId?: string;
    config: QmConfig;
    configDir: string;
  }> = [];
  const result = await clearDeploymentLayer({
    config: makeConfig("https://example.invalid"),
    configDir: "/unused",
    precondition,
    operationId,
    transport: async (request) => {
      requests.push(request);
      return {
        status: 200,
        body: JSON.stringify({
          ok: true,
          status: "applied",
          version: 4,
          contentHash,
          operationId,
          changed: true,
          durable: true,
        }),
      };
    },
  });
  assert.equal(result.contentHash, contentHash);
  assert.deepEqual(requests, [
    {
      config: makeConfig("https://example.invalid"),
      configIdentity: TEST_CONFIG_IDENTITY,
      configDir: "/unused",
      method: "DELETE",
      body: "",
      precondition,
      operationId,
    },
  ]);
  await assert.rejects(
    () =>
      clearDeploymentLayer({
        config: makeConfig("https://example.invalid"),
        configDir: "/unused",
        precondition,
        operationId,
        transport: async () => ({
          status: 200,
          body: JSON.stringify({
            ok: true,
            version: 4,
            contentHash: "c".repeat(64),
            operationId,
            changed: true,
            durable: true,
          }),
        }),
      }),
    /does not match the rollback precondition/,
  );
});

test("the Docker HTTP transport applies a bounded default timeout and honors an explicit timeout", async (t) => {
  const timeouts: number[] = [];
  const timeoutSignals: AbortSignal[] = [];
  const fetchSignals: Array<AbortSignal | null | undefined> = [];
  t.mock.method(AbortSignal, "timeout", (milliseconds: number) => {
    timeouts.push(milliseconds);
    const signal = new AbortController().signal;
    timeoutSignals.push(signal);
    return signal;
  });
  t.mock.method(globalThis, "fetch", async (_input: string | URL | Request, init?: RequestInit) => {
    fetchSignals.push(init?.signal);
    return new Response("{}");
  });
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-timeout-"));
  try {
    await withEnv({ CORE_SIGNING_SECRET: SECRET }, async () => {
      await dockerDeploymentLayerTransport({
        config: makeConfig("http://example.invalid"),
        configDir: dir,
        method: "GET",
        body: "",
      });
      await httpDeploymentLayerTransport({
        urlOf: () => new URL("https://example.invalid/v1/deployment-layer"),
        timeoutMs: 17,
      })({
        config: makeConfig("https://example.invalid"),
        configDir: dir,
        method: "GET",
        body: "",
      });
    });
    assert.deepEqual(timeouts, [30_000, 17]);
    assert.deepEqual(fetchSignals, timeoutSignals);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the HTTP transport rejects fixed, chunked, and falsely-small oversized responses", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-response-limit-"));
  const transport = httpDeploymentLayerTransport({
    urlOf: () => new URL("https://example.invalid/v1/deployment-layer"),
  });
  let cancelled = 0;
  let reads = 0;
  try {
    writeFileSync(join(dir, ".env"), `CORE_SIGNING_SECRET=${SECRET}\n`);
    for (const contentLength of ["2000000", undefined, "1"] as const) {
      cancelled = 0;
      reads = 0;
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          reads++;
          controller.enqueue(Buffer.alloc(80_000, 0x78));
        },
        cancel() {
          cancelled++;
        },
      });
      t.mock.method(globalThis, "fetch", async () => {
        const headers = new Headers();
        if (contentLength !== undefined) headers.set("content-length", contentLength);
        return new Response(stream, { status: 500, headers });
      });
      await assert.rejects(
        () => transport({ config: makeConfig("https://example.invalid"), configDir: dir, method: "GET", body: "" }),
        (error) => {
          assert.match(String(error), /deployment-layer response exceeds the 65536-byte limit/);
          assert.doesNotMatch(String(error), /response-private-tail/);
          return true;
        },
      );
      assert.equal(cancelled, 1);
      if (contentLength === "2000000") assert.ok(reads <= 1);
      else assert.ok(reads >= 1);
      t.mock.restoreAll();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the shared transport boundary rejects an oversized custom error before diagnostics", async () => {
  const body = JSON.stringify({ contract: 1, tools: [], skills: [] });
  const privateTail = "response-private-tail";
  await assert.rejects(
    () =>
      syncDeploymentLayerBody(
        {
          config: makeConfig("https://example.invalid"),
          configDir: "/unused",
          precondition: EMPTY_PRECONDITION,
          operationId: TEST_OPERATION_ID,
          transport: async () => ({ status: 500, body: "x".repeat(2_000_000) + privateTail }),
        },
        body,
      ),
    (error) => {
      assert.match(String(error), /deployment-layer response exceeds the 65536-byte limit/);
      assert.doesNotMatch(String(error), new RegExp(privateTail));
      return true;
    },
  );
});

test("deployment-layer requests enforce the exact 1 MB PUT boundary before custom transport access", async () => {
  let calls = 0;
  const transport: DeploymentLayerTransport = async () => {
    calls += 1;
    return { status: 200, body: "" };
  };
  const exact = "x".repeat(1_000_000);
  await deploymentLayerRequest({
    config: makeConfig("https://example.invalid"),
    configDir: "/unused",
    method: "PUT",
    body: exact,
    transport,
  });
  assert.equal(calls, 1);
  await assert.rejects(
    () =>
      syncDeploymentLayerBody(
        {
          config: makeConfig("https://example.invalid"),
          configDir: "/unused",
          precondition: EMPTY_PRECONDITION,
          operationId: TEST_OPERATION_ID,
          transport,
        },
        `${exact}x`,
      ),
    /deployment layer exceeds the core API's 1 MB request limit/,
  );
  assert.equal(calls, 1);
});

test("GET and DELETE reject nonempty bodies before custom or HTTP transport access", async () => {
  for (const method of ["GET", "DELETE"] as const) {
    let calls = 0;
    await assert.rejects(
      () =>
        deploymentLayerRequest({
          config: makeConfig("https://example.invalid"),
          configDir: "/unused",
          method,
          body: "signed-but-not-sent",
          transport: async () => {
            calls += 1;
            return { status: 200, body: "" };
          },
        }),
      new RegExp(`deployment-layer ${method} requests must have an empty body`),
    );
    assert.equal(calls, 0);
    await assert.rejects(
      () =>
        httpDeploymentLayerTransport()({
          config: makeConfig("https://example.invalid"),
          configDir: "/unused",
          method,
          body: "signed-but-not-sent",
        }),
      new RegExp(`deployment-layer ${method} requests must have an empty body`),
    );
  }
});

test("a compact GET accepts an exactly 1 MB restorable bundle", async () => {
  const manifest = "---\nname: a\ndescription: Exact boundary.\n---\nbody\n";
  const base = { contract: 1 as const, tools: [], skills: [{ path: "skills/a/SKILL.md", content: manifest }] };
  const padding = 1_000_000 - Buffer.byteLength(JSON.stringify(base));
  const bundle = {
    ...base,
    skills: [{ path: "skills/a/SKILL.md", content: manifest + "x".repeat(padding) }],
  };
  const body = JSON.stringify(bundle);
  assert.equal(Buffer.byteLength(body), 1_000_000);
  const contentHash = createHash("sha256").update(body).digest("hex");
  const state = await currentDeploymentLayerState({
    config: makeConfig("https://example.invalid"),
    configDir: "/unused",
    transport: async () => ({
      status: 200,
      body: JSON.stringify({
        contract: 1,
        version: 1,
        generation: 1,
        contentHash,
        source: "durable",
        operationId: null,
        status: "applied",
        runtimeContentHash: contentHash,
        bundle,
      }),
    }),
  });
  assert.equal(state.body, body);
  assert.equal(state.contentHash, contentHash);
});

test("the default HTTP timeout does not keep a completed transport process alive", () => {
  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `process.env.CORE_SIGNING_SECRET=${JSON.stringify(SECRET)};globalThis.fetch=async()=>new Response("{}");const {httpDeploymentLayerTransport}=await import(process.argv[1]);await httpDeploymentLayerTransport({urlOf:()=>new URL("https://example.invalid/v1/deployment-layer")})({config:{publicUrl:"https://example.invalid"},configDir:process.cwd(),method:"GET",body:""})`,
      new URL("../src/deployment-layer.ts", import.meta.url).href,
    ],
    { timeout: 2_000 },
  );
});

test("the shared HTTP transport never sends signed headers or bodies across redirects", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-redirect-"));
  const sourceRequests: Array<{ status: number; signature: string; timestamp: string; body: string }> = [];
  const sinkRequests: Array<{ signature: string; timestamp: string; body: string }> = [];
  const sink = createServer((request, response) => {
    void (async () => {
      const body = Buffer.concat(await Array.fromAsync(request)).toString("utf8");
      sinkRequests.push({
        signature: String(request.headers["x-signature"] ?? ""),
        timestamp: String(request.headers["x-timestamp"] ?? ""),
        body,
      });
      response.end("{}");
    })();
  });
  let sinkUrl = "";
  const source = createServer((request, response) => {
    void (async () => {
      const body = Buffer.concat(await Array.fromAsync(request)).toString("utf8");
      const status = Number(request.url?.slice(1));
      sourceRequests.push({
        status,
        signature: String(request.headers["x-signature"] ?? ""),
        timestamp: String(request.headers["x-timestamp"] ?? ""),
        body,
      });
      response.writeHead(status, { location: `${sinkUrl}/capture` });
      response.end();
    })();
  });
  try {
    const sinkPort = await listenLocal(sink);
    sinkUrl = `http://127.0.0.1:${sinkPort}`;
    const sourcePort = await listenLocal(source);
    writeFileSync(join(dir, ".env"), `CORE_SIGNING_SECRET=${SECRET}\n`);
    for (const status of [301, 302, 303, 307, 308]) {
      const body = JSON.stringify({ status });
      const transport = httpDeploymentLayerTransport({
        urlOf: () => new URL(`http://127.0.0.1:${sourcePort}/${status}`),
      });
      await assert.rejects(() =>
        transport({ config: makeConfig("http://example.invalid"), configDir: dir, method: "PUT", body }),
      );
    }
    assert.deepEqual(
      sourceRequests.map((request) => request.status),
      [301, 302, 303, 307, 308],
    );
    assert.ok(sourceRequests.every((request) => request.signature.startsWith("v0=")));
    assert.ok(sourceRequests.every((request) => /^\d+$/.test(request.timestamp)));
    assert.deepEqual(
      sourceRequests.map((request) => request.body),
      [301, 302, 303, 307, 308].map((status) => JSON.stringify({ status })),
    );
    assert.deepEqual(sinkRequests, []);
  } finally {
    await Promise.all([closeLocal(source), closeLocal(sink)]);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("conformance passes against a live core: base-port override, signed request, canonical hash + descriptors", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-conf-"));
  const captured: CapturedRequest[] = [];
  const bundle = (() => {
    writeLayer(dir);
    return deploymentLayerBundle(join(dir, "sandbox"));
  })();
  const contentHash = createHash("sha256").update(JSON.stringify(bundle)).digest("hex");
  const { server, port } = await startCoreStub(
    () => ({
      body: JSON.stringify({
        contract: 1,
        version: 1,
        generation: 1,
        contentHash,
        source: "durable",
        operationId: null,
        status: "applied",
        runtimeContentHash: contentHash,
        bundle,
      }),
    }),
    captured,
  );
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "acme",
        publicUrl: "http://localhost:8080",
        target: "docker",
        services: ["core"],
        basePort: 1,
        sandbox: { backend: "local", image: PINNED_SANDBOX_IMAGE },
      }),
    );
    await withEnv({ CORE_SIGNING_SECRET: SECRET, QM_BASE_PORT: String(port) }, async () => {
      const log = console.log;
      console.log = (): void => {};
      try {
        await runConformance(
          { config: loadConfigInDir(dir).config, configDir: dir, sandboxDir: join(dir, "sandbox"), target: "docker" },
          { runtime: true },
        );
      } finally {
        console.log = log;
      }
    });
    assert.equal(captured.length, 1);
    const request = captured[0]!;
    assert.equal(request.method, "GET");
    assert.equal(request.url, "/v1/deployment-layer");
    assert.match(request.timestamp, /^\d+$/, "x-timestamp is unix seconds");
    const expected = createHmac("sha256", SECRET)
      .update(`v0:${request.timestamp}:GET\n/v1/deployment-layer\n`)
      .digest("hex");
    assert.equal(request.signature, `v0=${expected}`, "v0 HMAC over METHOD\\npath\\nbody");
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("conformance fails when the stored layer matches but the core still serves a previous resolved layer", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-conf-"));
  const bundle = (() => {
    writeLayer(dir);
    return deploymentLayerBundle(join(dir, "sandbox"));
  })();
  const contentHash = createHash("sha256").update(JSON.stringify(bundle)).digest("hex");
  const { server, port } = await startCoreStub(
    () => ({
      body: JSON.stringify({
        contract: 1,
        version: 1,
        generation: 1,
        contentHash,
        source: "durable",
        operationId: null,
        status: "degraded",
        runtimeContentHash: "0000000000000000000000000000000000000000000000000000000000000000",
        bundle,
      }),
    }),
    [],
  );
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "acme",
        publicUrl: "http://localhost:8080",
        target: "docker",
        services: ["core"],
        basePort: 1,
        sandbox: { backend: "local", image: PINNED_SANDBOX_IMAGE },
      }),
    );
    await withEnv({ CORE_SIGNING_SECRET: SECRET, QM_BASE_PORT: String(port) }, async () => {
      const log = console.log;
      console.log = (): void => {};
      try {
        await assert.rejects(
          () =>
            runConformance(
              {
                config: loadConfigInDir(dir).config,
                configDir: dir,
                sandboxDir: join(dir, "sandbox"),
                target: "docker",
              },
              { runtime: true },
            ),
          /runtime\.layer-resolved: .*serving a previous resolved layer/,
        );
      } finally {
        console.log = log;
      }
    });
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("conformance reports a non-JSON layer response as a contract failure, not a raw SyntaxError", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-conf-"));
  writeLayer(dir);
  const { server, port } = await startCoreStub(() => ({ body: "<html>bad gateway</html>" }), []);
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "acme",
        publicUrl: "http://localhost:8080",
        target: "docker",
        services: ["core"],
        basePort: 1,
        sandbox: { backend: "local", image: PINNED_SANDBOX_IMAGE },
      }),
    );
    await withEnv({ CORE_SIGNING_SECRET: SECRET, QM_BASE_PORT: String(port) }, async () => {
      const log = console.log;
      console.log = (): void => {};
      try {
        await assert.rejects(
          () =>
            runConformance(
              {
                config: loadConfigInDir(dir).config,
                configDir: dir,
                sandboxDir: join(dir, "sandbox"),
                target: "docker",
              },
              { runtime: true },
            ),
          /runtime\.layer-resolved: .*unparseable JSON/,
        );
      } finally {
        console.log = log;
      }
    });
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a successful memory-backed sync warns that the layer will not survive restart", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-sync-"));
  const warnings: string[] = [];
  t.mock.method(console, "warn", (...parts: unknown[]) => warnings.push(parts.join(" ")));
  const { server, port } = await startCoreStub((request) => syncProtocolResponse(dir, request, { durable: false }), []);
  try {
    writeLayer(dir);
    await withEnv({ CORE_SIGNING_SECRET: SECRET, QM_BASE_PORT: String(port) }, () =>
      syncDeploymentLayer({
        config: makeConfig("http://example.invalid"),
        transport: dockerDeploymentLayerTransport,
        configDir: dir,
        sandboxDir: join(dir, "sandbox"),
      }),
    );
    assert.ok(warnings.some((line) => /memory-backed.*will not survive a core restart/.test(line)));
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a publicUrl with a base path keeps it in the request path and the signed canonical string", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-sync-"));
  const captured: CapturedRequest[] = [];
  const { server, port } = await startCoreStub((request) => syncProtocolResponse(dir, request), captured);
  try {
    writeLayer(dir);
    await withEnv({ CORE_SIGNING_SECRET: SECRET }, () =>
      syncDeploymentLayer({
        config: makeConfig(`http://127.0.0.1:${port}/base`),
        transport: awsDeploymentLayerTransport,
        configDir: dir,
        sandboxDir: join(dir, "sandbox"),
      }),
    );
    const request = captured[1]!;
    assert.match(request.url, /^\/base\/v1\/deployment-layer\?generation=0&source=none&operationId=[a-f0-9]{32}$/);
    const expected = createHmac("sha256", SECRET)
      .update(`v0:${request.timestamp}:PUT\n${request.url}\n${request.body}`)
      .digest("hex");
    assert.equal(request.signature, `v0=${expected}`);
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the AWS signing-secret fallback preserves leading and trailing whitespace", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-aws-secret-"));
  const captured: CapturedRequest[] = [];
  const { server, port } = await startCoreStub((request) => syncProtocolResponse(dir, request), captured);
  const secret = `  ${SECRET}  `;
  const bin = join(dir, "aws");
  const argsLog = join(dir, "aws-args.json");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const fs = require("node:fs");
fs.writeFileSync(${JSON.stringify(argsLog)}, JSON.stringify(process.argv.slice(2)));
process.stdout.write(JSON.stringify({ SecretString: ${JSON.stringify(secret)} }));
`,
  );
  chmodSync(bin, 0o755);
  const config: QmConfig = {
    ...makeConfig(`http://127.0.0.1:${port}`),
    target: "aws",
    aws: {
      accountId: "123456789012",
      region: "us-west-2",
      cluster: "acme-qm",
      deployRoleArn: "arn:aws:iam::123456789012:role/acme-deploy",
      secretsPrefix: "acme/qm/",
      imageLabel: "release",
      networking: { cloudMapNamespace: "acme.internal" },
      services: {},
    },
  };
  try {
    writeLayer(dir);
    await withEnv({ AWS_BIN: bin, CORE_SIGNING_SECRET: undefined }, () =>
      syncDeploymentLayer({
        config,
        transport: awsDeploymentLayerTransport,
        configDir: dir,
        sandboxDir: join(dir, "sandbox"),
      }),
    );
    const request = captured[1]!;
    const expected = createHmac("sha256", secret)
      .update(`v0:${request.timestamp}:PUT\n${request.url}\n${request.body}`)
      .digest("hex");
    assert.equal(request.signature, `v0=${expected}`);
    const args = JSON.parse(readFileSync(argsLog, "utf8")) as string[];
    assert.ok(args.includes("--output"));
    assert.ok(args.includes("json"));
    assert.ok(!args.includes("--query"));
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a non-2xx sync response is a CliError carrying the status and body", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-sync-"));
  const { server, port } = await startCoreStub(
    (request) => (request.method === "GET" ? { body: emptyStateBody() } : { status: 503, body: "core warming up" }),
    [],
  );
  try {
    writeLayer(dir);
    await withEnv({ CORE_SIGNING_SECRET: SECRET, QM_BASE_PORT: String(port) }, () =>
      assert.rejects(
        () =>
          syncDeploymentLayer({
            config: makeConfig("http://example.invalid"),
            transport: dockerDeploymentLayerTransport,
            configDir: dir,
            sandboxDir: join(dir, "sandbox"),
            operationId: TEST_OPERATION_ID,
          }),
        /deployment layer sync failed \(503\): core warming up/,
      ),
    );
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sync accepts only contract statuses, required fields, and the exact request body hash", async () => {
  const body = JSON.stringify({ contract: 1, tools: [], skills: [] });
  const contentHash = createHash("sha256").update(body).digest("hex");
  const valid = {
    ok: true,
    version: 1,
    contentHash,
    operationId: TEST_OPERATION_ID,
    changed: true,
    durable: true,
  };
  const opts = {
    config: makeConfig("http://example.invalid"),
    configDir: "/unused",
    precondition: EMPTY_PRECONDITION,
    operationId: TEST_OPERATION_ID,
    transport: async (): Promise<{ status: number; body: string }> => ({ status: 200, body: "" }),
  };
  for (const [name, status, responseBody, pattern] of [
    ["partial content", 206, JSON.stringify(valid), /sync failed \(206\)/],
    ["arbitrary success", 201, JSON.stringify(valid), /sync failed \(201\)/],
    ["empty object", 200, "{}", /ok must be true/],
    ["wrong hash", 200, JSON.stringify({ ...valid, contentHash: "0".repeat(64) }), /does not match/],
    ["malformed version", 200, JSON.stringify({ ...valid, version: "1" }), /positive integer/],
    ["version zero", 200, JSON.stringify({ ...valid, version: 0 }), /positive integer/],
    ["wrong generation", 200, JSON.stringify({ ...valid, version: 2 }), /inconsistent mutation revision/],
    [
      "wrong operation",
      200,
      JSON.stringify({ ...valid, operationId: "b".repeat(32) }),
      /inconsistent mutation revision/,
    ],
    ["missing changed", 200, JSON.stringify({ ...valid, changed: undefined }), /changed must be a boolean/],
    ["false changed", 200, JSON.stringify({ ...valid, changed: false }), /inconsistent mutation revision/],
  ] as const) {
    await assert.rejects(
      () =>
        syncDeploymentLayerBody(
          {
            ...opts,
            transport: async () => ({ status, body: responseBody }),
          },
          body,
        ),
      pattern,
      name,
    );
  }
  await assert.doesNotReject(() =>
    syncDeploymentLayerBody(
      {
        ...opts,
        transport: async () => ({
          status: 202,
          body: JSON.stringify({ ...valid, status: "degraded", message: "persisted but not applied" }),
        }),
      },
      body,
    ),
  );
  const currentOperationId = "b".repeat(32);
  await assert.doesNotReject(() =>
    syncDeploymentLayerBody(
      {
        ...opts,
        precondition: {
          generation: 4,
          contentHash,
          source: "durable",
          operationId: currentOperationId,
        },
        transport: async () => ({
          status: 200,
          body: JSON.stringify({
            ...valid,
            version: 4,
            operationId: currentOperationId,
            changed: false,
          }),
        }),
      },
      body,
    ),
  );
});

test("a caller-supplied operation ID stays stable across a lost response retry", async () => {
  const body = JSON.stringify({ contract: 1, tools: [], skills: [] });
  const contentHash = createHash("sha256").update(body).digest("hex");
  const seen: Array<string | undefined> = [];
  let attempt = 0;
  const transport = async (request: { operationId?: string }): Promise<{ status: number; body: string }> => {
    seen.push(request.operationId);
    attempt++;
    if (attempt === 1) throw new Error("response lost");
    return {
      status: 200,
      body: JSON.stringify({
        ok: true,
        version: 1,
        contentHash,
        operationId: TEST_OPERATION_ID,
        changed: true,
        durable: true,
      }),
    };
  };
  const opts = {
    config: makeConfig("https://example.invalid"),
    configDir: "/unused",
    precondition: EMPTY_PRECONDITION,
    operationId: TEST_OPERATION_ID,
    transport,
  };
  await assert.rejects(() => syncDeploymentLayerBody(opts, body), /response lost/);
  await assert.doesNotReject(() => syncDeploymentLayerBody(opts, body));
  assert.deepEqual(seen, [TEST_OPERATION_ID, TEST_OPERATION_ID]);
});

test("a 2xx response with unparseable JSON is a CliError with a body snippet, not a stack trace", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-sync-"));
  const { server, port } = await startCoreStub(
    (request) => (request.method === "GET" ? { body: emptyStateBody() } : { body: "<html>gateway</html>" }),
    [],
  );
  try {
    writeLayer(dir);
    await withEnv({ CORE_SIGNING_SECRET: SECRET, QM_BASE_PORT: String(port) }, () =>
      assert.rejects(
        () =>
          syncDeploymentLayer({
            config: makeConfig("http://example.invalid"),
            transport: dockerDeploymentLayerTransport,
            configDir: dir,
            sandboxDir: join(dir, "sandbox"),
            operationId: TEST_OPERATION_ID,
          }),
        /unparseable JSON: <html>gateway<\/html>/,
      ),
    );
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a 2xx response with an invalid durability shape fails instead of suppressing the warning", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-sync-"));
  let body = "";
  const { server, port } = await startCoreStub(
    (request) => (request.method === "GET" ? { body: emptyStateBody() } : { body }),
    [],
  );
  try {
    writeLayer(dir);
    body = syncResponseBody(dir, { version: 1, durable: "false" });
    await withEnv({ CORE_SIGNING_SECRET: SECRET, QM_BASE_PORT: String(port) }, () =>
      assert.rejects(
        () =>
          syncDeploymentLayer({
            config: makeConfig("http://example.invalid"),
            transport: dockerDeploymentLayerTransport,
            configDir: dir,
            sandboxDir: join(dir, "sandbox"),
            operationId: TEST_OPERATION_ID,
          }),
        /invalid JSON: durable must be a boolean/,
      ),
    );
    body = "null";
    await withEnv({ CORE_SIGNING_SECRET: SECRET, QM_BASE_PORT: String(port) }, () =>
      assert.rejects(
        () =>
          syncDeploymentLayer({
            config: makeConfig("http://example.invalid"),
            transport: dockerDeploymentLayerTransport,
            configDir: dir,
            sandboxDir: join(dir, "sandbox"),
          }),
        /invalid JSON: expected an object/,
      ),
    );
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("allowUnavailable defers an AbortSignal timeout from a hanging core and closes every server handle", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-hanging-"));
  const server = createServer(() => undefined);
  try {
    writeLayer(dir);
    writeFileSync(join(dir, ".env"), `CORE_SIGNING_SECRET=${SECRET}\n`);
    const port = await listenLocal(server);
    await syncDeploymentLayer({
      config: makeConfig("http://example.invalid"),
      transport: httpDeploymentLayerTransport({
        urlOf: () => new URL(`http://127.0.0.1:${port}/v1/deployment-layer`),
        timeoutMs: 25,
      }),
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      allowUnavailable: true,
    });
  } finally {
    if (server.listening) await closeLocal(server);
    assert.equal(server.listening, false);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("allowUnavailable fails closed for non-timeout aborts, arbitrary errors, spoofed timeouts, and CliErrors", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-timeout-classification-"));
  try {
    writeLayer(dir);
    const timeout = new DOMException("timed out", "TimeoutError");
    assert.equal(timeout.code, DOMException.TIMEOUT_ERR);
    await syncDeploymentLayer({
      config: makeConfig("http://example.invalid"),
      transport: async () => {
        throw timeout;
      },
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      allowUnavailable: true,
    });
    const spoofed = new Error("spoofed timeout") as Error & { code: number };
    spoofed.name = "TimeoutError";
    spoofed.code = DOMException.TIMEOUT_ERR;
    const cyclic = new Error("cyclic cause") as Error & { cause?: unknown };
    cyclic.cause = cyclic;
    const misleadingConnectivity = new Error("wrapped local configuration failure", {
      cause: new CliError("local configuration failed"),
    }) as Error & { code: string };
    misleadingConnectivity.code = "ECONNREFUSED";
    for (const error of [
      new DOMException("cancelled", "AbortError"),
      new Error("arbitrary failure"),
      spoofed,
      new CliError("local configuration failed", { cause: timeout }),
      new Error("wrapped local configuration failure", {
        cause: new CliError("local configuration failed", { cause: timeout }),
      }),
      misleadingConnectivity,
      cyclic,
    ]) {
      await assert.rejects(
        () =>
          syncDeploymentLayer({
            config: makeConfig("http://example.invalid"),
            transport: async () => {
              throw error;
            },
            configDir: dir,
            sandboxDir: join(dir, "sandbox"),
            allowUnavailable: true,
          }),
        /could not sync deployment layer/,
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("allowUnavailable swallows an unreachable core but NOT a local config error", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-sync-"));
  try {
    writeLayer(dir);
    const port = await freeUnboundPort();
    await withEnv({ CORE_SIGNING_SECRET: SECRET, QM_BASE_PORT: String(port) }, () =>
      syncDeploymentLayer({
        config: makeConfig("http://example.invalid"),
        transport: dockerDeploymentLayerTransport,
        configDir: dir,
        sandboxDir: join(dir, "sandbox"),
        allowUnavailable: true,
      }),
    );
    await withEnv({ CORE_SIGNING_SECRET: SECRET, QM_BASE_PORT: String(port) }, () =>
      assert.rejects(
        () =>
          syncDeploymentLayer({
            config: makeConfig("http://example.invalid"),
            transport: dockerDeploymentLayerTransport,
            configDir: dir,
            sandboxDir: join(dir, "sandbox"),
          }),
        /could not sync deployment layer/,
      ),
    );
    await withEnv({ CORE_SIGNING_SECRET: undefined, QM_BASE_PORT: String(port) }, () =>
      assert.rejects(
        () =>
          syncDeploymentLayer({
            config: makeConfig("http://example.invalid"),
            transport: dockerDeploymentLayerTransport,
            configDir: dir,
            sandboxDir: join(dir, "sandbox"),
            allowUnavailable: true,
          }),
        /CORE_SIGNING_SECRET is required/,
      ),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function fakeFly(dir: string, body: string): string {
  const bin = join(dir, "fake-fly.cjs");
  writeFileSync(bin, `#!/usr/bin/env node\nconst fs = require("node:fs");\n${body}\n`);
  chmodSync(bin, 0o755);
  return bin;
}

function fakeFlyProtocol(getBody: string, putStatus: number, putBody: string): string {
  return `const command=process.argv[process.argv.indexOf("-C")+1],source=Buffer.from(command.split("'")[1],"base64").toString(),response=source.includes('const method="GET"')?{status:200,body:${JSON.stringify(getBody)}}:{status:${putStatus},body:${JSON.stringify(putBody)}};console.log("QM_LAYER_RESPONSE="+JSON.stringify(response));`;
}

function flySyncOpts(dir: string, allowUnavailable?: boolean): Parameters<typeof syncDeploymentLayer>[0] {
  return {
    config: makeConfig("http://example.invalid"),
    transport: flyDeploymentLayerTransport,
    configDir: dir,
    sandboxDir: join(dir, "sandbox"),
    operationId: TEST_OPERATION_ID,
    ...(allowUnavailable !== undefined ? { allowUnavailable } : {}),
  };
}

test("fly sync succeeds on the response marker, piping the exact bundle over stdin", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-fly-"));
  try {
    writeLayer(dir);
    const stdinLog = join(dir, "stdin.log");
    const argsLog = join(dir, "args.log");
    const bin = fakeFly(
      dir,
      [
        `fs.writeFileSync(${JSON.stringify(argsLog)}, JSON.stringify(process.argv.slice(2)));`,
        `fs.writeFileSync(${JSON.stringify(stdinLog)}, fs.readFileSync(0, "utf8"));`,
        fakeFlyProtocol(emptyStateBody(), 200, syncResponseBody(dir)),
      ].join("\n"),
    );
    await withEnv({ FLY_BIN: bin }, () => syncDeploymentLayer(flySyncOpts(dir)));
    assert.equal(
      readFileSync(stdinLog, "utf8"),
      JSON.stringify(deploymentLayerBundle(join(dir, "sandbox"))),
      "the full bundle reaches the remote script's stdin",
    );
    const args = JSON.parse(readFileSync(argsLog, "utf8")) as string[];
    assert.deepEqual(args.slice(0, 4), ["ssh", "console", "-a", "acme-core"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the Fly transport captures a legal near-limit layer response without overflowing stdout", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-fly-capture-"));
  const body = JSON.stringify({
    contract: 1,
    tools: [],
    skills: [{ path: "skills/large/SKILL.md", content: '"'.repeat(499_000) }],
  });
  assert.ok(Buffer.byteLength(body) < 1_000_000);
  assert.ok(Buffer.byteLength(`QM_LAYER_RESPONSE=${JSON.stringify({ status: 200, body })}\n`) > 1024 * 1024);
  const bin = fakeFly(
    dir,
    `const body=JSON.stringify({contract:1,tools:[],skills:[{path:"skills/large/SKILL.md",content:'"'.repeat(499000)}]});console.log('QM_LAYER_RESPONSE='+JSON.stringify({status:200,body}));`,
  );
  try {
    await withEnv({ FLY_BIN: bin }, async () => {
      const response = await flyDeploymentLayerTransport({
        config: makeConfig("http://example.invalid"),
        configDir: dir,
        method: "GET",
        body: "",
      });
      assert.equal(response.status, 200);
      assert.equal(response.body, body);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the Fly transport rejects fixed and chunked oversized responses inside the core VM", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-fly-response-limit-"));
  const bin = fakeFly(
    dir,
    `const {spawnSync}=require("node:child_process");const args=process.argv.slice(2),command=args[args.indexOf("-C")+1],result=spawnSync(command,{shell:true,encoding:"utf8",input:fs.readFileSync(0),env:process.env});process.stdout.write(result.stdout||"");process.stderr.write(result.stderr||"");process.exit(result.status??1);`,
  );
  try {
    for (const mode of ["fixed", "chunked"] as const) {
      const serverScript = `const http=require("node:http"),mode=process.argv[1],tail="response-private-tail",payload="x".repeat(2000000)+tail;const server=http.createServer((_request,response)=>{if(mode==="fixed")response.writeHead(500,{"content-length":Buffer.byteLength(payload)});else response.writeHead(500);for(let offset=0;offset<payload.length;offset+=32000)response.write(payload.slice(offset,offset+32000));response.end()});server.listen(0,"127.0.0.1",()=>process.send({port:server.address().port}));process.on("SIGTERM",()=>server.close(()=>process.exit(0)))`;
      const server = spawn(process.execPath, ["-e", serverScript, mode], {
        stdio: ["ignore", "ignore", "inherit", "ipc"],
      });
      try {
        const port = await new Promise<number>((resolve, reject) => {
          server.once("message", (message) => resolve((message as { port: number }).port));
          server.once("error", reject);
          server.once("exit", (code) => reject(new Error(`response server exited with ${String(code)}`)));
        });
        await withEnv({ CORE_SIGNING_SECRET: SECRET, FLY_BIN: bin, PORT: String(port) }, async () => {
          await assert.rejects(
            async () =>
              flyDeploymentLayerTransport({
                config: makeConfig("http://example.invalid"),
                configDir: dir,
                method: "GET",
                body: "",
              }),
            (error) => {
              assert.match(String(error), /deployment-layer response exceeds 65536-byte limit/);
              assert.doesNotMatch(String(error), /response-private-tail/);
              return true;
            },
          );
        });
      } finally {
        if (server.exitCode === null && server.signalCode === null) {
          const exited = new Promise<void>((resolve) => server.once("exit", () => resolve()));
          server.kill();
          await exited;
        }
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the Fly transport never sends signed headers or bodies across redirects", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-fly-redirect-"));
  const sourceLog = join(dir, "source.json");
  const sinkLog = join(dir, "sink.json");
  const serverScript = `const fs=require("node:fs"),http=require("node:http");const [sourceLog,sinkLog]=process.argv.slice(1);const read=async request=>Buffer.concat(await Array.fromAsync(request)).toString("utf8");let source;const sink=http.createServer((request,response)=>{void read(request).then(body=>{fs.writeFileSync(sinkLog,JSON.stringify({method:request.method,headers:request.headers,body}));response.end("{}");})});sink.listen(0,"127.0.0.1",()=>{const sinkPort=sink.address().port;source=http.createServer((request,response)=>{void read(request).then(body=>{fs.writeFileSync(sourceLog,JSON.stringify({method:request.method,headers:request.headers,body}));response.writeHead(307,{location:"http://127.0.0.1:"+sinkPort+"/capture"});response.end();})});source.listen(0,"127.0.0.1",()=>process.send({port:source.address().port}))});process.on("SIGTERM",()=>{source?.close();sink.close();process.exit(0)})`;
  const redirectServer = spawn(process.execPath, ["-e", serverScript, sourceLog, sinkLog], {
    stdio: ["ignore", "ignore", "inherit", "ipc"],
  });
  try {
    const port = await new Promise<number>((resolve, reject) => {
      redirectServer.once("message", (message) => resolve((message as { port: number }).port));
      redirectServer.once("error", reject);
      redirectServer.once("exit", (code) => reject(new Error(`redirect server exited with ${String(code)}`)));
    });
    const bin = fakeFly(
      dir,
      `const {spawnSync}=require("node:child_process");const args=process.argv.slice(2),command=args[args.indexOf("-C")+1],result=spawnSync(command,{shell:true,encoding:"utf8",input:fs.readFileSync(0),env:process.env});process.stdout.write(result.stdout||"");process.stderr.write(result.stderr||"");process.exit(result.status??1);`,
    );
    const body = JSON.stringify({ secret: "deployment-layer-body" });
    await withEnv({ CORE_SIGNING_SECRET: SECRET, FLY_BIN: bin, PORT: String(port) }, async () => {
      assert.throws(
        () =>
          flyDeploymentLayerTransport({
            config: makeConfig("http://example.invalid"),
            configDir: dir,
            method: "PUT",
            body,
          }),
        /deployment-layer request failed.*fetch failed/,
      );
    });
    const source = JSON.parse(readFileSync(sourceLog, "utf8")) as {
      method: string;
      headers: Record<string, string>;
      body: string;
    };
    assert.equal(source.method, "PUT");
    assert.match(source.headers["x-signature"] ?? "", /^v0=/);
    assert.match(source.headers["x-timestamp"] ?? "", /^\d+$/);
    assert.equal(source.body, body);
    assert.equal(existsSync(sinkLog), false);
  } finally {
    redirectServer.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a 202 degraded response is accepted and warns with the core's persisted-but-partial message", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-fly-degraded-"));
  const warnings: string[] = [];
  t.mock.method(console, "warn", (...parts: unknown[]) => void warnings.push(parts.join(" ")));
  try {
    writeLayer(dir);
    const bin = fakeFly(
      dir,
      fakeFlyProtocol(emptyStateBody(), 202, syncResponseBody(dir, { status: "degraded", message: "skill collision" })),
    );
    await withEnv({ FLY_BIN: bin }, () => syncDeploymentLayer(flySyncOpts(dir)));
    assert.ok(warnings.some((line) => /persisted but only partially applied: skill collision/.test(line)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a remote-script error (signing secret missing on core) is NOT deferrable as core-unreachable", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-fly-"));
  try {
    writeLayer(dir);
    const bin = fakeFly(
      dir,
      `console.log('QM_LAYER_ERROR=' + JSON.stringify({ message: "CORE_SIGNING_SECRET is not set on core" }));`,
    );
    await withEnv({ FLY_BIN: bin }, () =>
      assert.rejects(
        () => syncDeploymentLayer(flySyncOpts(dir, true)),
        /could not sync deployment layer: .*CORE_SIGNING_SECRET is not set on core/,
      ),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a remote connection failure (core process down inside the VM) IS deferrable", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-fly-"));
  try {
    writeLayer(dir);
    const bin = fakeFly(
      dir,
      `console.log('QM_LAYER_ERROR=' + JSON.stringify({ message: "fetch failed", code: "ECONNREFUSED" }));`,
    );
    await withEnv({ FLY_BIN: bin }, () => syncDeploymentLayer(flySyncOpts(dir, true)));
    await withEnv({ FLY_BIN: bin }, () =>
      assert.rejects(() => syncDeploymentLayer(flySyncOpts(dir)), /could not sync deployment layer/),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a fly-ssh transport failure defers under allowUnavailable, but a missing app never does", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-fly-"));
  try {
    writeLayer(dir);
    const transport = fakeFly(dir, `console.error("Error: tunnel unavailable"); process.exit(1);`);
    await withEnv({ FLY_BIN: transport }, () => syncDeploymentLayer(flySyncOpts(dir, true)));
    const missingApp = fakeFly(dir, `console.error("Error: Could not find App 'acme-core'"); process.exit(1);`);
    await withEnv({ FLY_BIN: missingApp }, () =>
      assert.rejects(() => syncDeploymentLayer(flySyncOpts(dir, true)), /Fly app acme-core not found/),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("junk files (.DS_Store, Thumbs.db, AppleDouble) are excluded from the bundle", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-junk-"));
  try {
    writeLayer(dir);
    const clean = deploymentLayerBundle(join(dir, "sandbox"));
    writeFileSync(join(dir, "sandbox", "skills", "a", ".DS_Store"), Buffer.from([0x00, 0x01, 0x42, 0x75, 0x64, 0x31]));
    writeFileSync(join(dir, "sandbox", "skills", "a", "Thumbs.db"), Buffer.from([0xd0, 0xcf, 0x11, 0xe0]));
    writeFileSync(join(dir, "sandbox", "skills", "a", "._SKILL.md"), Buffer.from([0x00, 0x05, 0x16, 0x07]));
    assert.deepEqual(deploymentLayerBundle(join(dir, "sandbox")), clean);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("non-junk tools entries fail loudly unless they are directories with tool.json", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-tools-shape-"));
  try {
    mkdirSync(join(dir, "sandbox", "tools"), { recursive: true });
    writeFileSync(join(dir, "sandbox", "tools", "README.md"), "not a tool\n");
    assert.throws(
      () => deploymentLayerBundle(join(dir, "sandbox")),
      /tools entry must be a directory containing tool\.json/,
    );
    rmSync(join(dir, "sandbox", "tools", "README.md"));
    mkdirSync(join(dir, "sandbox", "tools", "missing"));
    assert.throws(() => deploymentLayerBundle(join(dir, "sandbox")), /tool directory is missing tool\.json/);
    rmSync(join(dir, "sandbox", "tools", "missing"), { recursive: true });
    mkdirSync(join(dir, "sandbox", "tools", "linked"));
    writeFileSync(join(dir, "descriptor.json"), JSON.stringify({ id: "linked" }));
    symlinkSync(join(dir, "descriptor.json"), join(dir, "sandbox", "tools", "linked", "tool.json"));
    assert.throws(() => deploymentLayerBundle(join(dir, "sandbox")), /deployment layer file must be a regular file/);
    writeFileSync(join(dir, "sandbox", "tools", ".DS_Store"), "junk");
    rmSync(join(dir, "sandbox", "tools", "linked"), { recursive: true });
    assert.deepEqual(deploymentLayerBundle(join(dir, "sandbox")).tools, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("version-0 none and filesystem states bootstrap explicitly without claiming a filesystem layer was applied", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-boot-"));
  const captured: CapturedRequest[] = [];
  let source: "none" | "filesystem" = "none";
  const { server } = await startCoreStub(
    () => ({
      body: JSON.stringify({
        contract: 1,
        version: 0,
        generation: 0,
        contentHash: null,
        source,
        operationId: null,
      }),
    }),
    captured,
  );
  try {
    await withEnv({ CORE_SIGNING_SECRET: SECRET }, async () => {
      for (const sourceKind of ["none", "filesystem"] as const) {
        source = sourceKind;
        const state = await currentDeploymentLayerState({
          config: makeConfig("http://localhost:8080"),
          transport: dockerDeploymentLayerTransport,
          configDir: dir,
        });
        assert.equal(state.body, JSON.stringify({ contract: 1, tools: [], skills: [] }));
        assert.equal(createHash("sha256").update(state.body).digest("hex"), state.contentHash);
        assert.equal(state.status, "applied");
        assert.equal(state.runtimeContentHash, source === "none" ? state.contentHash : null);
        assert.equal(state.bootstrapped, true);
      }
    });
    assert.equal(captured.length, 2);
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer reads reject partial statuses and malformed durable state instead of defaulting applied", async () => {
  const bundle = { contract: 1, tools: [], skills: [] };
  const contentHash = createHash("sha256").update(JSON.stringify(bundle)).digest("hex");
  const valid = {
    contract: 1,
    version: 1,
    generation: 1,
    contentHash,
    source: "durable",
    operationId: null,
    status: "applied",
    runtimeContentHash: contentHash,
    bundle,
  };
  for (const [name, responseStatus, responseBody, pattern] of [
    ["partial response", 206, valid, /read failed \(206\)/],
    ["arbitrary success", 201, valid, /read failed \(201\)/],
    ["missing status", 200, { ...valid, status: undefined }, /invalid status/],
    ["malformed status", 200, { ...valid, status: "unknown" }, /invalid status/],
    ["malformed runtime hash", 200, { ...valid, runtimeContentHash: 3 }, /invalid runtimeContentHash/],
    ["version without hash", 200, { ...valid, contentHash: null }, /inconsistent version and contentHash/],
    [
      "applied filesystem source",
      200,
      { ...valid, source: "filesystem", runtimeContentHash: null },
      /inconsistent applied state/,
    ],
    ["applied none source", 200, { ...valid, source: "none", runtimeContentHash: null }, /inconsistent applied state/],
    ["applied different runtime", 200, { ...valid, runtimeContentHash: "1".repeat(64) }, /inconsistent applied state/],
  ] as const) {
    await assert.rejects(
      () =>
        currentDeploymentLayerState({
          config: makeConfig("http://example.invalid"),
          configDir: "/unused",
          transport: async () => ({ status: responseStatus, body: JSON.stringify(responseBody) }),
        }),
      pattern,
      name,
    );
  }
  for (const [source, runtimeContentHash] of [
    ["none", null],
    ["filesystem", null],
    ["durable", "1".repeat(64)],
  ] as const) {
    const state = await currentDeploymentLayerState({
      config: makeConfig("http://example.invalid"),
      configDir: "/unused",
      transport: async () => ({
        status: 200,
        body: JSON.stringify({ ...valid, source, status: "degraded", runtimeContentHash }),
      }),
    });
    assert.equal(state.status, "degraded");
    assert.equal(state.runtimeContentHash, runtimeContentHash);
    assert.equal(state.precondition.source, "durable");
  }
});

test("a durable record whose bundle is missing still fails the read", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-layer-durable-"));
  const captured: CapturedRequest[] = [];
  const { server } = await startCoreStub(
    () => ({
      body: JSON.stringify({
        contract: 1,
        version: 3,
        generation: 3,
        contentHash: "1".repeat(64),
        source: "durable",
        operationId: null,
        status: "applied",
        runtimeContentHash: "1".repeat(64),
      }),
    }),
    captured,
  );
  try {
    await withEnv({ CORE_SIGNING_SECRET: SECRET }, async () => {
      await assert.rejects(
        currentDeploymentLayerState({
          config: makeConfig("http://localhost:8080"),
          transport: dockerDeploymentLayerTransport,
          configDir: dir,
        }),
        /did not return a restorable bundle/,
      );
    });
  } finally {
    await new Promise<void>((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment layer reads reject hash-consistent bundles that the core cannot restore", async () => {
  const broker = (id: string, credentialPaths: Array<{ path: string; kind: "file" | "directory" }>) => ({
    id,
    auth: {
      check: "check",
      reauth: "reauth",
      credentialPaths,
      broker: {
        kind: "aws-role",
        roleArnEnv: "AWS_ROLE_ARN",
        region: "us-west-2",
        sessionActions: ["sts:GetCallerIdentity"],
      },
    },
  });
  const cases: Array<{ name: string; bundle: unknown; pattern: RegExp }> = [
    {
      name: "unsafe path",
      bundle: { contract: 1, tools: [], skills: [{ path: "skills/a/../secret", content: "secret" }] },
      pattern: /unsafe path/,
    },
    {
      name: "duplicate path",
      bundle: {
        contract: 1,
        tools: [],
        skills: [
          { path: "skills/a/SKILL.md", content: "---\nname: a\ndescription: A.\n---\na\n" },
          { path: "skills/a/SKILL.md", content: "---\nname: a\ndescription: B.\n---\nb\n" },
        ],
      },
      pattern: /duplicate path/,
    },
    {
      name: "NUL content",
      bundle: { contract: 1, tools: [], skills: [{ path: "skills/a/SKILL.md", content: "bad\0content" }] },
      pattern: /invalid text/,
    },
    {
      name: "lone surrogate",
      bundle: { contract: 1, tools: [], skills: [{ path: "skills/a/SKILL.md", content: "bad\ud800content" }] },
      pattern: /invalid text/,
    },
    {
      name: "malformed tool descriptor",
      bundle: { contract: 1, tools: [{ path: "tools/a/tool.json", content: "{}" }], skills: [] },
      pattern: /id.*required/,
    },
    {
      name: "misplaced tool descriptor",
      bundle: { contract: 1, tools: [{ path: "tools/a/extra.json", content: '{"id":"a"}' }], skills: [] },
      pattern: /tool path must be/,
    },
    {
      name: "missing skill manifest",
      bundle: { contract: 1, tools: [], skills: [{ path: "skills/a/README.md", content: "missing" }] },
      pattern: /has no SKILL\.md/,
    },
    {
      name: "invalid skill manifest",
      bundle: { contract: 1, tools: [], skills: [{ path: "skills/a/SKILL.md", content: "missing" }] },
      pattern: /missing YAML frontmatter/,
    },
    {
      name: "multiple broker owners",
      bundle: {
        contract: 1,
        tools: [
          {
            path: "tools/aws/tool.json",
            content: JSON.stringify(broker("aws", [{ path: ".aws", kind: "directory" }])),
          },
          {
            path: "tools/gh/tool.json",
            content: JSON.stringify(broker("gh", [{ path: ".config/gh", kind: "directory" }])),
          },
        ],
        skills: [],
      },
      pattern: /credential brokers on multiple tools/,
    },
    {
      name: "one broker spanning services",
      bundle: {
        contract: 1,
        tools: [
          {
            path: "tools/cloud/tool.json",
            content: JSON.stringify(
              broker("cloud", [
                { path: ".aws", kind: "directory" },
                { path: ".config/gh", kind: "directory" },
              ]),
            ),
          },
        ],
        skills: [],
      },
      pattern: /credential paths map to multiple services/,
    },
  ];
  for (const { name, bundle, pattern } of cases) {
    const serialized = JSON.stringify(bundle);
    const contentHash = createHash("sha256").update(serialized).digest("hex");
    await assert.rejects(
      () =>
        currentDeploymentLayerState({
          config: makeConfig("https://example.invalid"),
          configDir: "/unused",
          transport: async () => ({
            status: 200,
            body: JSON.stringify({
              contract: 1,
              version: 1,
              generation: 1,
              contentHash,
              source: "durable",
              operationId: null,
              status: "applied",
              runtimeContentHash: contentHash,
              bundle,
            }),
          }),
        }),
      pattern,
      name,
    );
  }
});

test("every GET-accepted brokered bundle is PUT-restorable through the CLI contract", async () => {
  const bundle = {
    contract: 1 as const,
    tools: [
      {
        path: "tools/aws/tool.json",
        content: JSON.stringify({
          id: "aws",
          auth: {
            check: "check",
            reauth: "reauth",
            credentialPaths: [{ path: ".aws", kind: "directory" }],
            broker: {
              kind: "aws-role",
              roleArnEnv: "AWS_ROLE_ARN",
              region: "us-west-2",
              sessionActions: ["sts:GetCallerIdentity"],
            },
          },
        }),
      },
    ],
    skills: [{ path: "skills/a/SKILL.md", content: "---\nname: a\ndescription: A.\n---\nRun A.\n" }],
  };
  const body = JSON.stringify(bundle);
  const contentHash = createHash("sha256").update(body).digest("hex");
  const transport = async (request: { method: "GET" | "PUT" | "DELETE"; body: string }) =>
    request.method === "GET"
      ? {
          status: 200,
          body: JSON.stringify({
            contract: 1,
            version: 1,
            generation: 1,
            contentHash,
            source: "durable",
            operationId: null,
            status: "applied",
            runtimeContentHash: contentHash,
            bundle,
          }),
        }
      : {
          status: 200,
          body: JSON.stringify({
            ok: true,
            version: 2,
            contentHash: createHash("sha256").update(request.body).digest("hex"),
            operationId: TEST_OPERATION_ID,
            changed: true,
            durable: true,
          }),
        };
  const state = await currentDeploymentLayerState({
    config: makeConfig("https://example.invalid"),
    configDir: "/unused",
    transport,
  });
  const restored = await syncDeploymentLayerBody(
    {
      config: makeConfig("https://example.invalid"),
      configDir: "/unused",
      transport,
      precondition: state.precondition,
      operationId: TEST_OPERATION_ID,
    },
    state.body,
  );
  assert.equal(restored?.contentHash, contentHash);
});
