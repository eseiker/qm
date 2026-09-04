import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  chownSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, join } from "node:path";
import {
  assertSecretByteLength,
  canonicalHttpOrigin,
  canonicalJson,
  deploymentSecretValue,
  flyBin,
  gitTopLevel,
  invalidSecretNames,
  isInvalidSecret,
  processErrorMatches,
  processErrorOutput,
  readEnvFile,
  readUtf8File,
  resolveBuildRepoRoot,
  senderAddress,
  validEmail,
  which,
  writeEnvValue,
} from "../src/util.ts";

test("readUtf8File reads only regular files through one descriptor", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-utf8-file-"));
  const file = join(dir, "input.txt");
  const link = join(dir, "input-link.txt");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(file, "hello\n");
  symlinkSync(file, link);
  assert.equal(readUtf8File(link), "hello\n");
  assert.throws(() => readUtf8File(dir), /regular file/);
  if (process.platform !== "win32") {
    const fifo = join(dir, "input.fifo");
    execFileSync("mkfifo", [fifo]);
    assert.throws(() => readUtf8File(fifo), /regular file/);
    assert.throws(() => readUtf8File("/dev/null"), /regular file/);
  }
});

test("readEnvFile distinguishes required and optional missing sources", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-source-"));
  const missing = join(dir, "missing.env");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  assert.deepEqual(readEnvFile(missing), new Map());
  assert.throws(() => readEnvFile(missing, { required: true }), /--env-file not found/);
});

test("deploymentSecretValue disables ambient fallback in file-only mode", () => {
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  const priorSecret = process.env.FUTURE_DEPLOYMENT_SECRET;
  try {
    process.env.FUTURE_DEPLOYMENT_SECRET = "ambient";
    delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    assert.equal(deploymentSecretValue("FUTURE_DEPLOYMENT_SECRET", undefined), "ambient");
    assert.equal(deploymentSecretValue("FUTURE_DEPLOYMENT_SECRET", ""), "ambient");
    process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
    assert.equal(deploymentSecretValue("FUTURE_DEPLOYMENT_SECRET", undefined), undefined);
    assert.equal(deploymentSecretValue("FUTURE_DEPLOYMENT_SECRET", ""), undefined);
    assert.equal(deploymentSecretValue("FUTURE_DEPLOYMENT_SECRET", "file"), "file");
  } finally {
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
    if (priorSecret === undefined) delete process.env.FUTURE_DEPLOYMENT_SECRET;
    else process.env.FUTURE_DEPLOYMENT_SECRET = priorSecret;
  }
});

test("git root discovery uses only the supplied environment without mutating an external git directory", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-git-root-"));
  const root = join(dir, "source \t");
  const gitDir = join(dir, "metadata");
  const hooks = join(dir, "hooks");
  const fakeBin = join(dir, "bin");
  const marker = join(dir, "executed");
  const log = join(dir, "git.log");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(root);
  mkdirSync(hooks);
  mkdirSync(fakeBin);
  mkdirSync(join(root, "deploy", "core"), { recursive: true });
  writeFileSync(join(root, "deploy", "core", "Dockerfile"), "FROM scratch\n");
  execFileSync("git", ["init", "--separate-git-dir", gitDir, root]);
  writeFileSync(join(hooks, "post-index-change"), `#!/bin/sh\n: > ${JSON.stringify(marker)}\n`, { mode: 0o755 });
  execFileSync("git", ["-C", root, "config", "core.hooksPath", hooks]);
  execFileSync("git", ["-C", root, "add", "deploy/core/Dockerfile"]);
  execFileSync("git", [
    "-C",
    root,
    "-c",
    "user.name=test",
    "-c",
    "user.email=test@example.com",
    "commit",
    "-m",
    "initial",
  ]);
  rmSync(marker, { force: true });
  const trustedGit = execFileSync("which", ["git"], { encoding: "utf8" }).trim();
  writeFileSync(
    join(fakeBin, "git"),
    [
      "#!/bin/sh",
      `if [ "${"${GIT_OPTIONAL_LOCKS:-}"}" != "0" ] || [ -n "${"${GIT_DIR:-}"}" ] || [ -n "${"${DATABASE_CA_CERT:-}"}" ]; then : > ${JSON.stringify(marker)}; fi`,
      `printf '%s\\n' "$@" > ${JSON.stringify(log)}`,
      `exec ${JSON.stringify(trustedGit)} "$@"`,
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  const index = join(gitDir, "index");
  const before = readFileSync(index);
  const beforeStat = statSync(index, { bigint: true });
  const previousCwd = process.cwd();
  const previousSecret = process.env.DATABASE_CA_CERT;
  const previousGitDir = process.env.GIT_DIR;
  process.env.DATABASE_CA_CERT = "ambient-secret";
  process.env.GIT_DIR = join(dir, "wrong-git-dir");
  try {
    process.chdir(root);
    const baseEnv: NodeJS.ProcessEnv = {
      HOME: process.env.HOME,
      PATH: `${fakeBin}${delimiter}${process.env.PATH ?? ""}`,
      GIT_DIR: join(dir, "supplied-wrong-git-dir"),
    };
    assert.equal(gitTopLevel(baseEnv), realpathSync(root));
    assert.equal(gitTopLevel(baseEnv, root), realpathSync(root));
    assert.equal(resolveBuildRepoRoot(undefined, ["core"], baseEnv), realpathSync(root));
  } finally {
    process.chdir(previousCwd);
    if (previousSecret === undefined) delete process.env.DATABASE_CA_CERT;
    else process.env.DATABASE_CA_CERT = previousSecret;
    if (previousGitDir === undefined) delete process.env.GIT_DIR;
    else process.env.GIT_DIR = previousGitDir;
  }
  const afterStat = statSync(index, { bigint: true });
  assert.deepEqual(readFileSync(index), before);
  assert.equal(afterStat.mtimeNs, beforeStat.mtimeNs);
  assert.equal(afterStat.ctimeNs, beforeStat.ctimeNs);
  assert.equal(existsSync(join(gitDir, "index.lock")), false);
  assert.equal(existsSync(marker), false);
  assert.match(readFileSync(log, "utf8"), /^--no-optional-locks\nrev-parse\n--show-toplevel\n$/);
});

test("managed credential encryption keys require strong material", () => {
  for (const name of [
    "CONNECTOR_SECRET_KEY",
    "CORE_SIGNING_SECRET",
    "SKILL_SIGNING_SECRET",
    "CAPABILITY_SECRET",
    "PORTAL_IDENTITY_SECRET",
    "PORTAL_SESSION_SECRET",
    "DEPLOY_APPS_SESSION_SECRET",
    "AWS_DEPLOY_GATE_SECRET",
    "AUTH_TOKEN_SECRET",
    "AUTH_CLIENT_SECRET",
  ]) {
    assert.equal(isInvalidSecret(name, "short"), true, name);
    assert.equal(isInvalidSecret(name, "x".repeat(32)), false, name);
    assert.equal(isInvalidSecret(name, "é".repeat(16)), false, name);
  }
});

test("auth signing keys must be coherent importable P-256 private JWKs", () => {
  const first = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  const second = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  assert.equal(isInvalidSecret("AUTH_SIGNING_JWK", JSON.stringify(first)), false);
  assert.equal(isInvalidSecret("AUTH_SIGNING_JWK", JSON.stringify({ ...first, key_ops: ["sign"] })), false);
  assert.equal(isInvalidSecret("AUTH_SIGNING_JWK", JSON.stringify({ ...first, d: `${first.d}=` })), false);
  for (const key of [
    "not-json",
    "[]",
    JSON.stringify({ ...first, kty: "RSA" }),
    JSON.stringify({ ...first, crv: "P-384" }),
    JSON.stringify({ kty: "EC", crv: "P-256", d: "x" }),
    JSON.stringify({ ...first, d: second.d }),
    JSON.stringify({ ...first, key_ops: ["verify"] }),
  ]) {
    assert.equal(isInvalidSecret("AUTH_SIGNING_JWK", key), true);
  }
});

test("shared secret validation rejects every runtime-forbidden key reuse", () => {
  for (const [left, right] of [
    ["CORE_SIGNING_SECRET", "CAPABILITY_SECRET"],
    ["CORE_SIGNING_SECRET", "PORTAL_IDENTITY_SECRET"],
    ["CAPABILITY_SECRET", "PORTAL_IDENTITY_SECRET"],
    ["CONNECTOR_SECRET_KEY", "CORE_SIGNING_SECRET"],
    ["CONNECTOR_SECRET_KEY", "CAPABILITY_SECRET"],
    ["CONNECTOR_SECRET_KEY", "PORTAL_IDENTITY_SECRET"],
    ["PORTAL_SESSION_SECRET", "CORE_SIGNING_SECRET"],
    ["AUTH_CLIENT_SECRET", "AUTH_TOKEN_SECRET"],
  ] as const) {
    const invalid = invalidSecretNames(
      new Map([
        [left, "x".repeat(64)],
        [right, "x".repeat(64)],
      ]),
    );
    assert.deepEqual([...invalid].sort(), [left, right].sort(), `${left} and ${right}`);
  }
  assert.deepEqual(
    [
      ...invalidSecretNames(
        new Map(["CORE_SIGNING_SECRET", "CAPABILITY_SECRET"].map((name, i) => [name, `${i}`.repeat(64)])),
      ),
    ],
    [],
  );
});

test("shared email validation matches the auth runtime for allowlists and senders", () => {
  for (const email of ["operator@example.com", "operator+tag@sub-domain.example.com", "agent/path@example.com"]) {
    assert.equal(validEmail(email), true);
    assert.equal(isInvalidSecret("AUTH_ALLOWED_EMAILS", email), false);
  }
  for (const email of [
    "not-an-email",
    "bad<name@example.com",
    'bad"name@example.com',
    "operator@sub_domain.example.com",
    "operator@-bad.example.com",
    "operator@bad..example.com",
    "operator@example.com:443",
    "operator@example.com/path",
    "operator@127.0.0.1",
    "operator@[127.0.0.1]",
    ".operator@example.com",
    "operator.@example.com",
    "oper..ator@example.com",
    "oper:ator@example.com",
    "oper[ator]@example.com",
    "opérator@example.com",
    `bad\0name@example.com`,
    `${"a".repeat(65)}@example.com`,
    `${"a".repeat(250)}@x.io`,
  ]) {
    assert.equal(validEmail(email), false);
    assert.equal(isInvalidSecret("AUTH_ALLOWED_EMAILS", email), true);
  }
  assert.equal(senderAddress("QM Operator <operator@example.com>"), "operator@example.com");
  assert.equal(isInvalidSecret("AUTH_EMAIL_FROM", "QM Operator <operator@example.com>"), false);
  assert.equal(isInvalidSecret("AUTH_EMAIL_FROM", "Opérateur <operator@example.com>"), false);
  assert.equal(isInvalidSecret("AUTH_EMAIL_FROM", "QM Operator <not-an-email>"), true);
  for (const sender of [
    "Bad\r\nBcc: victim@example.net <sender@example.com>",
    "Bad\u0007 <sender@example.com>",
    "Bad\u200e <sender@example.com>",
  ]) {
    assert.equal(isInvalidSecret("AUTH_EMAIL_FROM", sender), true);
  }
});

test("HTTP origins reject ambiguous bytes and normalize safe spellings", () => {
  assert.equal(canonicalHttpOrigin("HTTPS://API.EXAMPLE.COM:443/"), "https://api.example.com");
  assert.equal(canonicalHttpOrigin("http://api.example.com:80"), "http://api.example.com");
  for (const value of [
    "https://api.example.com?",
    "https://api.example.com#",
    "https:///api.example.com",
    "https://api.example.com\\",
    "https://api.example.com:",
    "https://@api.example.com",
    "https://:@api.example.com",
    "https://api%2eexample.com",
    "https://api.example.com\t",
  ]) {
    assert.equal(canonicalHttpOrigin(value), undefined, value);
  }
});

test("admin grant secrets contain only exact email org-admin entries", () => {
  assert.equal(isInvalidSecret("ADMIN_GRANTS", "admin@example.com:org_admin"), false);
  assert.equal(isInvalidSecret("ADMIN_GRANTS", "admin@example.com:org_admin, ops@example.com:org_admin"), false);
  for (const value of [
    "admin@example.com:viewer:org_admin",
    "admin@example.com::org_admin",
    "admin@example.com:viewer",
    "admin@example.com\0:org_admin",
  ]) {
    assert.equal(isInvalidSecret("ADMIN_GRANTS", value), true, value);
  }
});

test("secret validation rejects NUL and provider byte-limit overflow without echoing values", () => {
  assert.equal(isInvalidSecret("FUTURE_SECRET", "left\0right"), true);
  assert.doesNotThrow(() => assertSecretByteLength("FUTURE_SECRET", "é".repeat(32_768)));
  const value = `private-${"é".repeat(32_768)}`;
  assert.throws(
    () => assertSecretByteLength("FUTURE_SECRET", value),
    (error: unknown) => {
      assert.doesNotMatch((error as Error).message, /private/);
      assert.match((error as Error).message, /FUTURE_SECRET.*65536-byte/);
      return true;
    },
  );
});

test("structured process error matching ignores wrapper messages and resets stateful patterns", () => {
  const raw = Object.assign(new Error("inner"), { stderr: Buffer.from("ResourceNotFoundException\n") });
  const wrapped = new Error("argv contains AccessDeniedException", { cause: raw });
  assert.equal(processErrorOutput(wrapped), "ResourceNotFoundException\n");
  const pattern = /ResourceNotFoundException/g;
  assert.equal(processErrorMatches(wrapped, pattern), true);
  assert.equal(processErrorMatches(wrapped, pattern), true);
  assert.equal(processErrorMatches(new Error("ResourceNotFoundException only in argv"), pattern), false);
});

test("flyBin honors $FLY_BIN verbatim", () => {
  const saved = process.env.FLY_BIN;
  try {
    process.env.FLY_BIN = "/opt/fly/bin/flyctl";
    assert.equal(flyBin(), "/opt/fly/bin/flyctl");
  } finally {
    if (saved === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = saved;
  }
});

test("flyBin falls back to an auto-detected binary name when $FLY_BIN is unset", () => {
  const saved = process.env.FLY_BIN;
  try {
    delete process.env.FLY_BIN;
    assert.ok(["flyctl", "fly"].includes(flyBin()));
  } finally {
    if (saved !== undefined) process.env.FLY_BIN = saved;
  }
});

test("which treats configured binary names as paths without shell evaluation", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-which-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, "fly ctl");
  const marker = join(dir, "injected");
  writeFileSync(bin, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  assert.equal(which(bin), true);
  assert.equal(which(`${bin}; touch ${marker}`), false);
  assert.equal(existsSync(marker), false);
});

test("canonicalJson sorts keys and matches JSON.stringify's undefined semantics", () => {
  assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"b":1}');
  assert.equal(canonicalJson({ a: undefined, b: 1 }), JSON.stringify({ a: undefined, b: 1 }));
  assert.equal(canonicalJson([1, undefined, "x"]), JSON.stringify([1, undefined, "x"]));
  assert.equal(canonicalJson({ a: [undefined], b: null }), '{"a":[null],"b":null}');
  for (const value of [null, 0, "s", true, [], {}]) {
    assert.equal(canonicalJson(value), JSON.stringify(value));
  }
});

test("readEnvFile matches Node comment semantics for unquoted and quoted hashes", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  writeFileSync(file, "# ignored\nTOKEN=abc#def\nURL=https://host/path#fragment\nQUOTED='abc#def'\n");
  assert.deepEqual(
    [...readEnvFile(file)],
    [
      ["TOKEN", "abc"],
      ["URL", "https://host/path"],
      ["QUOTED", "abc#def"],
    ],
  );
});

test("writeEnvValue appends a new key with 0600 on a fresh file", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  writeEnvValue(file, "NEW_KEY", "value-1");
  assert.equal(readFileSync(file, "utf8"), "NEW_KEY=value-1\n");
  assert.equal(statSync(file).mode & 0o777, 0o600);
  writeEnvValue(file, "SECOND", "two");
  assert.equal(readFileSync(file, "utf8"), "NEW_KEY=value-1\nSECOND=two\n");
});

test("writeEnvValue replaces an existing key in place, preserving order and comments", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  writeFileSync(file, "# comment\nA=1\nB=old\nC=3\n");
  writeEnvValue(file, "B", "new#value");
  assert.equal(readFileSync(file, "utf8"), "# comment\nA=1\nB='new#value'\nC=3\n");
  assert.equal(readEnvFile(file).get("B"), "new#value");
});

test("writeEnvValue round-trips every representable single-line value through Node env files", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  const values = [
    " leading",
    "trailing ",
    "\tedge tabs\t",
    '"quoted"',
    "'single'",
    "`ticks`",
    " leading 'single' and `ticks` ",
    "literal\\nsequence",
    "slash\\path",
    "hash#fragment",
    "tab\tinside",
    "paired emoji 😀",
    "contains all three ' ` \" internally",
  ];
  for (const value of values) {
    writeEnvValue(file, "ROUNDTRIP_SECRET", value);
    assert.equal(readEnvFile(file).get("ROUNDTRIP_SECRET"), value);
    const env = { ...process.env };
    delete env.ROUNDTRIP_SECRET;
    const childValue = execFileSync(
      process.execPath,
      ["--env-file", file, "-e", "process.stdout.write(JSON.stringify(process.env.ROUNDTRIP_SECRET))"],
      { encoding: "utf8", env },
    );
    assert.equal(JSON.parse(childValue), value);
  }
  const unrepresentable = " ' ` \\\" \\n ";
  assert.throws(
    () => writeEnvValue(file, "ROUNDTRIP_SECRET", unrepresentable),
    (error: unknown) => {
      assert.match((error as Error).message, /cannot be represented losslessly/);
      assert.doesNotMatch((error as Error).message, /ROUNDTRIP_SECRET=.*['`]/);
      return true;
    },
  );
});

test("writeEnvValue serializes concurrent writers without losing updates", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-concurrent-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  writeFileSync(file, `BASE=${"x".repeat(500_000)}\n`);
  const util = new URL("../src/util.ts", import.meta.url).href;
  await Promise.all(
    Array.from({ length: 16 }, (_, index) => {
      const script = `import {writeEnvValue} from ${JSON.stringify(util)};writeEnvValue(${JSON.stringify(file)},${JSON.stringify(`KEY_${index}`)},${JSON.stringify(`value-${index}`)})`;
      return new Promise<void>((resolve, reject) => {
        execFile(process.execPath, ["--input-type=module", "-e", script], (error) => {
          if (error) reject(error);
          else resolve();
        });
      });
    }),
  );
  const values = readEnvFile(file);
  assert.equal(values.get("BASE"), "x".repeat(500_000));
  for (let index = 0; index < 16; index++) assert.equal(values.get(`KEY_${index}`), `value-${index}`);
  assert.equal(existsSync(`${file}.qm-lock`), false);
});

test("writeEnvValue recovers authenticated stale locks and rejects unsafe lock aliases", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-lock-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  const lock = `${file}.qm-lock`;
  const token = "00000000-0000-4000-8000-000000000000";
  const owner = `${lock}.2147483647.${token}.owner`;
  const temporary = join(dir, `..env.2147483647.${token}.tmp`);
  writeFileSync(owner, `2147483647:${token}:${basename(owner)}\n`, { mode: 0o600 });
  linkSync(owner, lock);
  writeFileSync(temporary, "TOKEN=stale-secret\n", { mode: 0o600 });
  writeEnvValue(file, "TOKEN", "fresh");
  assert.equal(readEnvFile(file).get("TOKEN"), "fresh");
  assert.equal(existsSync(lock), false);
  assert.equal(existsSync(owner), false);
  assert.equal(existsSync(temporary), false);
  const suffixTarget = join(dir, "custom.qm-lock");
  const suffixLock = `${suffixTarget}.qm-lock`;
  const suffixOwner = `${suffixLock}.2147483647.${token}.owner`;
  const suffixTemporary = join(dir, `.custom.qm-lock.2147483647.${token}.tmp`);
  writeFileSync(suffixOwner, `2147483647:${token}:${basename(suffixOwner)}\n`, { mode: 0o600 });
  linkSync(suffixOwner, suffixLock);
  writeFileSync(suffixTemporary, "TOKEN=stale-secret\n", { mode: 0o600 });
  writeEnvValue(suffixTarget, "TOKEN", "fresh");
  assert.equal(readEnvFile(suffixTarget).get("TOKEN"), "fresh");
  assert.equal(existsSync(suffixLock), false);
  assert.equal(existsSync(suffixOwner), false);
  assert.equal(existsSync(suffixTemporary), false);
  const unsafeTarget = join(dir, "unsafe.env");
  const unsafeLock = `${unsafeTarget}.qm-lock`;
  const unsafeOwner = `${unsafeLock}.2147483647.${token}.owner`;
  const unsafeTemporary = join(dir, `.unsafe.env.2147483647.${token}.tmp`);
  writeFileSync(unsafeOwner, `2147483647:${token}:${basename(unsafeOwner)}\n`, { mode: 0o600 });
  linkSync(unsafeOwner, unsafeLock);
  writeFileSync(unsafeTemporary, "TOKEN=stale-secret\n", { mode: 0o640 });
  assert.throws(() => writeEnvValue(unsafeTarget, "TOKEN", "fresh"), /temporary state is unsafe/);
  assert.equal(readFileSync(unsafeTemporary, "utf8"), "TOKEN=stale-secret\n");
  assert.equal(existsSync(unsafeTarget), false);
  const victim = join(dir, "victim");
  writeFileSync(victim, "sentinel\n", { mode: 0o600 });
  symlinkSync(victim, lock);
  assert.throws(() => writeEnvValue(file, "TOKEN", "changed"), /lock is unsafe/);
  assert.equal(readFileSync(victim, "utf8"), "sentinel\n");
  assert.equal(readEnvFile(file).get("TOKEN"), "fresh");
});

test("writeEnvValue rejects FIFO targets and locks without blocking", (t) => {
  if (process.platform === "win32") return t.skip("FIFOs are unavailable on Windows");
  const dir = mkdtempSync(join(tmpdir(), "qm-env-fifo-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  const util = new URL("../src/util.ts", import.meta.url).href;
  const rejectsQuickly = (path: string, pattern: string): void => {
    const script = `import {writeEnvValue} from ${JSON.stringify(util)};try{writeEnvValue(${JSON.stringify(path)},"TOKEN","value");process.exit(2)}catch(error){if(!new RegExp(${JSON.stringify(pattern)}).test(String(error?.message))){console.error(error);process.exit(3)}}`;
    execFileSync(process.execPath, ["--input-type=module", "-e", script], { timeout: 2_000 });
  };
  execFileSync("mkfifo", [file]);
  rejectsQuickly(file, "unlinked regular file");
  rmSync(file);
  writeFileSync(file, "TOKEN=old\n", { mode: 0o600 });
  execFileSync("mkfifo", [`${file}.qm-lock`]);
  rejectsQuickly(file, "lock is unsafe");
  assert.equal(readFileSync(file, "utf8"), "TOKEN=old\n");
});

test("writeEnvValue collapses duplicate occurrences into the first", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  writeFileSync(file, "A=1\nexport B=first\nC=3\n# B=commented\nB=third\n");
  writeEnvValue(file, "B", "only");
  assert.equal(readFileSync(file, "utf8"), "A=1\nB=only\nC=3\n");
});

test("writeEnvValue preserves ownership and makes the environment file owner-only", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  writeFileSync(file, "A=1\n", { mode: 0o640 });
  chmodSync(file, 0o640);
  const alternateGroup = process.getgroups?.().find((gid) => gid !== statSync(dir).gid);
  if (alternateGroup !== undefined && typeof process.getuid === "function") {
    chownSync(file, process.getuid(), alternateGroup);
  }
  const before = statSync(file);
  writeEnvValue(file, "A", "2");
  const after = statSync(file);
  assert.equal(after.mode & 0o777, 0o600);
  assert.equal(after.uid, before.uid);
  assert.equal(after.gid, before.gid);
  assert.notEqual(after.ino, before.ino);
  assert.equal(readFileSync(file, "utf8"), "A=2\n");
});

test("writeEnvValue rejects inherited macOS access grants without rewriting secrets", (t) => {
  if (process.platform !== "darwin") return t.skip("macOS ACL semantics");
  const dir = mkdtempSync(join(tmpdir(), "qm-env-acl-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  execFileSync("/bin/chmod", ["+a", "everyone allow read,file_inherit", dir]);
  writeFileSync(file, "A=1\n", { mode: 0o644 });
  assert.match(execFileSync("/bin/ls", ["-lde", file], { encoding: "utf8" }), / inherited allow read/);
  assert.throws(() => writeEnvValue(file, "A", "2"), /unsafe access control list/);
  assert.equal(readFileSync(file, "utf8"), "A=1\n");
});

test("writeEnvValue rejects invalid keys and process-unsafe values", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  assert.throws(() => writeEnvValue(file, "BAD KEY", "x"));
  assert.throws(() => writeEnvValue(file, "GOOD_KEY", "a\nb"));
  assert.throws(() => writeEnvValue(file, "GOOD_KEY", "a\0b"));
  assert.throws(() => writeEnvValue(file, "GOOD_KEY", "a\ufeffb"), /byte-order mark/);
  assert.throws(() => writeEnvValue(file, "GOOD_KEY", "high\ud800surrogate"), /valid UTF-8 text/);
  assert.throws(() => writeEnvValue(file, "GOOD_KEY", "low\udc00surrogate"), /valid UTF-8 text/);
});

test("writeEnvValue rejects malformed existing UTF-8 without changing the file", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  const bytes = Buffer.from([0x41, 0x3d, 0xff, 0x0a, 0x42, 0x3d, 0x6f, 0x6c, 0x64, 0x0a]);
  writeFileSync(file, bytes);
  assert.throws(() => readEnvFile(file), /valid UTF-8 text/);
  assert.throws(() => writeEnvValue(file, "B", "new"), /valid UTF-8 text/);
  assert.deepEqual(readFileSync(file), bytes);
});

test("deployment environment files reject a UTF-8 byte-order mark without mutation", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  const bom = Buffer.from([0xef, 0xbb, 0xbf]);
  for (const content of [
    Buffer.concat([bom, Buffer.from("A=1\nB=old\n")]),
    Buffer.concat([Buffer.from("SAFE=1\n"), bom, Buffer.from("A=1\n")]),
  ]) {
    writeFileSync(file, content);
    assert.throws(() => readEnvFile(file), /byte-order mark/);
    assert.throws(() => writeEnvValue(file, "A", "new"), /byte-order mark/);
    assert.deepEqual(readFileSync(file), content);
  }
});

test("writeEnvValue rejects direct, symlink, and hardlink aliases of the deployment config", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-alias-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = join(dir, "qm.config.jsonc");
  const sentinel = "config-sentinel\n";
  writeFileSync(config, sentinel);
  assert.throws(() => writeEnvValue(config, "TOKEN", "value", config), /must be separate/);
  assert.equal(readFileSync(config, "utf8"), sentinel);
  const symlink = join(dir, "symlink.env");
  symlinkSync(config, symlink);
  assert.throws(() => writeEnvValue(symlink, "TOKEN", "value", config), /unlinked regular file/);
  assert.equal(readFileSync(config, "utf8"), sentinel);
  const hardlink = join(dir, "hardlink.env");
  linkSync(config, hardlink);
  assert.throws(() => writeEnvValue(hardlink, "TOKEN", "value", config), /unlinked regular file/);
  assert.equal(readFileSync(config, "utf8"), sentinel);
  const separate = join(dir, "separate.env");
  writeEnvValue(separate, "TOKEN", "value", config);
  assert.equal(readFileSync(separate, "utf8"), "TOKEN=value\n");
});

test("readEnvFile matches Node --env-file for export prefixes and quoted values", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  writeFileSync(
    file,
    [
      "FIRST=one",
      'DQ="wrapped#value"',
      "SQ='single'",
      "BT=`tick`",
      "export EXPORTED=yes",
      'ESCAPED="line1\\nline2"',
      'TRAILING="abc" rest is ignored',
      "UNQUOTED_HASH=abc#comment",
      "NBSP=\u00a0secret\u00a0",
      "SPACED=  padded  ",
      "LAST=last",
    ].join("\r\n"),
  );
  const expected = new Map([
    ["FIRST", "one"],
    ["DQ", "wrapped#value"],
    ["SQ", "single"],
    ["BT", "tick"],
    ["EXPORTED", "yes"],
    ["ESCAPED", "line1\nline2"],
    ["TRAILING", "abc"],
    ["UNQUOTED_HASH", "abc"],
    ["NBSP", "\u00a0secret\u00a0"],
    ["SPACED", "padded"],
    ["LAST", "last"],
  ]);
  assert.deepEqual(readEnvFile(file), expected);
  const env = { ...process.env };
  for (const name of expected.keys()) delete env[name];
  const fromNode = JSON.parse(
    execFileSync(
      process.execPath,
      [
        "--env-file",
        file,
        "-e",
        `process.stdout.write(JSON.stringify(${JSON.stringify([...expected.keys()])}.map(name => [name, process.env[name]])))`,
      ],
      { encoding: "utf8", env },
    ),
  );
  assert.deepEqual(new Map(fromNode), expected);
});

test("readEnvFile rejects empty assignments that Node parses under a different key", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  for (const content of ["A= \nB=value\n", "A=\t\nB=value\n", "export A=\nB=value\n", "export A= \nB=value\n"]) {
    writeFileSync(file, content);
    assert.throws(() => readEnvFile(file), /ambiguous empty assignments/);
    assert.throws(() => writeEnvValue(file, "B", "changed"), /ambiguous empty assignments/);
    assert.equal(readFileSync(file, "utf8"), content);
  }
  writeFileSync(file, "A=\r\nB=value\r\n");
  assert.deepEqual(
    readEnvFile(file),
    new Map([
      ["A", ""],
      ["B", "value"],
    ]),
  );
});

test("readEnvFile rejects multiline and unclosed quoted assignments before returning values", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  for (const content of ['SAFE=before\nSECRET="first\nsecond"\n', "SAFE=before\nSECRET='unclosed\n"]) {
    writeFileSync(file, content);
    assert.throws(() => readEnvFile(file), /multiline or unclosed quoted values/);
    assert.throws(() => writeEnvValue(file, "SAFE", "after"), /multiline or unclosed quoted values/);
    assert.equal(readFileSync(file, "utf8"), content);
  }
});

test("readEnvFile rejects lone carriage returns without changing the source", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-env-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, ".env");
  const content = "SAFE=abc\rdef\n";
  writeFileSync(file, content);
  assert.throws(() => readEnvFile(file), /lone carriage returns/);
  assert.throws(() => writeEnvValue(file, "SAFE", "after"), /lone carriage returns/);
  assert.equal(readFileSync(file, "utf8"), content);
});

async function withFakeStdin<T>(fn: (emit: (bytes: Buffer) => void) => Promise<T>): Promise<T> {
  const { EventEmitter } = await import("node:events");
  const fake = Object.assign(new EventEmitter(), {
    isTTY: true,
    setRawMode(): void {},
    resume(): void {},
    pause(): void {},
  });
  const descriptor = Object.getOwnPropertyDescriptor(process, "stdin")!;
  Object.defineProperty(process, "stdin", { value: fake, configurable: true });
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    return await fn((bytes) => void fake.emit("data", bytes));
  } finally {
    process.stdout.write = write;
    Object.defineProperty(process, "stdin", descriptor);
  }
}

test("promptHidden decodes multi-byte UTF-8 (split across chunks) and backspaces whole characters", async () => {
  const { promptHidden } = await import("../src/util.ts");
  await withFakeStdin(async (emit) => {
    const pending = promptHidden("SECRET");
    const bytes = Buffer.from("pä中x", "utf8");
    emit(bytes.subarray(0, 4));
    emit(bytes.subarray(4));
    emit(Buffer.from([0x7f]));
    emit(Buffer.from([0x7f]));
    emit(Buffer.from("é!\r", "utf8"));
    assert.equal(await pending, "päé!");
  });
});

test("promptHidden treats Ctrl-D as enter on a non-empty buffer and as cancel on an empty one", async () => {
  const { promptHidden } = await import("../src/util.ts");
  await withFakeStdin(async (emit) => {
    const pending = promptHidden("SECRET");
    emit(Buffer.from("hunter2", "utf8"));
    emit(Buffer.from([0x04]));
    assert.equal(await pending, "hunter2");
  });
  await withFakeStdin(async (emit) => {
    const pending = promptHidden("SECRET");
    emit(Buffer.from([0x04]));
    await assert.rejects(() => pending, /secret entry cancelled/);
  });
});
