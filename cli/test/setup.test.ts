import { test } from "node:test";
import assert from "node:assert/strict";
import { linkSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { CONFIG_FILENAME, loadConfigAt } from "../src/config.ts";
import {
  adminGrantEmails,
  mintSigningJwk,
  pendingSecrets,
  playbookFor,
  updateEnvContent,
  runSetup,
} from "../src/commands/setup.ts";
import { CliError } from "../src/log.ts";
import { readEnvFile } from "../src/util.ts";

function configFor(
  services: string[],
  extra = "",
  env = `{ "core": { "HARNESS": "pi" } }`,
): ReturnType<typeof loadConfigAt>["config"] {
  const dir = mkdtempSync(join(tmpdir(), "qm-setup-"));
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      `{
      "contract": 1, "orgId": "acme", "publicUrl": "http://localhost:8082", "target": "docker",
      "model": "claude-opus-4-8", "services": ${JSON.stringify(services)}, "plugins": [], "skills": [],
      "env": ${env}, "sandbox": { "backend": "sprites", "namePrefix": "acme-sandboxes" }${extra}
    }`,
    );
    return loadConfigAt(join(dir, CONFIG_FILENAME)).config;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("pendingSecrets collects required deployment secrets and leaves optional integrations to Admin", () => {
  const config = configFor(["core", "slack", "web-ui"]);
  const env = new Map([
    ["ANTHROPIC_API_KEY", "sk-ant-real-value"],
    ["CORE_SIGNING_SECRET", "short"],
  ]);
  const { todo, done } = pendingSecrets(config, env);
  assert.deepEqual(
    done.map((s) => s.name),
    [],
  );
  const names = todo.map((s) => s.name);
  assert.ok(names.includes("CORE_SIGNING_SECRET"));
  assert.ok(!names.includes("ANTHROPIC_API_KEY"));
  assert.ok(!names.includes("SLACK_BOT_TOKEN"));
  assert.ok(!names.includes("SLACK_APP_TOKEN"));
  assert.ok(todo.every((secret) => secret.required));
});

test("pendingSecrets excludes terraform-managed secrets", () => {
  const config = configFor(["core"]);
  const { todo } = pendingSecrets(config, new Map());
  assert.ok(!todo.some((s) => s.managedBy !== "operator"));
});

test("pendingSecrets keeps a malformed administrator seed pending", () => {
  const config = configFor(
    ["core", "portal"],
    `,
      "secretEnv": { "core": { "ADMIN_GRANTS": "ADMIN_GRANTS" } }`,
  );
  for (const value of ["admin@example.com", "admin@example.com:viewer:org_admin", "admin@example.com::org_admin"]) {
    assert.ok(
      pendingSecrets(config, new Map([["ADMIN_GRANTS", value]])).todo.some((secret) => secret.name === "ADMIN_GRANTS"),
    );
  }
  assert.ok(
    pendingSecrets(config, new Map([["ADMIN_GRANTS", "admin@example.com:org_admin"]])).done.some(
      (secret) => secret.name === "ADMIN_GRANTS",
    ),
  );
});

test("updateEnvContent replaces blank and commented lines in place and appends new names", () => {
  const before = [
    "# Anthropic key (core)",
    "ANTHROPIC_API_KEY=",
    "# SLACK_BOT_TOKEN=  # optional",
    "KEEP_ME=untouched",
    "",
  ].join("\n");
  const after = updateEnvContent(
    before,
    new Map([
      ["ANTHROPIC_API_KEY", "sk-ant-x"],
      ["SLACK_BOT_TOKEN", "xoxb-y"],
      ["BRAND_NEW", "z"],
    ]),
  );
  const lines = after.split("\n");
  assert.equal(lines[0], "# Anthropic key (core)");
  assert.equal(lines[1], "ANTHROPIC_API_KEY=sk-ant-x");
  assert.equal(lines[2], "SLACK_BOT_TOKEN=xoxb-y");
  assert.equal(lines[3], "KEEP_ME=untouched");
  assert.ok(after.includes("BRAND_NEW=z\n"));
});

test("updateEnvContent replaces an already-set value", () => {
  const after = updateEnvContent("export A=old\nB=keep\n# A=commented\nA=stale\n", new Map([["A", "new"]]));
  assert.equal(after, "A=new\nB=keep\n");
});

test("updateEnvContent rejects process-unsafe values without echoing them", () => {
  assert.throws(
    () => updateEnvContent("", new Map([["TOKEN", "private\0value"]])),
    (error: unknown) => {
      assert.match((error as Error).message, /TOKEN.*NUL/);
      assert.doesNotMatch((error as Error).message, /private/);
      return true;
    },
  );
  assert.throws(() => updateEnvContent("", new Map([["BAD KEY", "value"]])), /not a valid environment/);
});

test("playbooks substitute the manifest names", () => {
  const config = configFor(["core"]);
  const slack = playbookFor("SLACK_BOT_TOKEN", config).join("\n");
  assert.ok(slack.includes("slack-app-manifest.yml"));
  const sso = playbookFor("OIDC_CLIENT_ID", config).join("\n");
  assert.ok(sso.includes(`${config.publicUrl}/auth/callback`));
  assert.doesNotMatch(sso, /Slack/);
  assert.match(playbookFor("ADMIN_GRANTS", config).join("\n"), /:org_admin/);
  assert.deepEqual(playbookFor("NO_SUCH_SECRET", config), []);
});

test("the sign-in allowlist derives from the administrator seed", () => {
  assert.equal(adminGrantEmails("admin@example.com:org_admin"), "admin@example.com");
  assert.equal(
    adminGrantEmails("admin@example.com:org_admin, ops@example.com:org_admin"),
    "admin@example.com,ops@example.com",
  );
  assert.equal(adminGrantEmails("U012345:org_admin"), "", "a Slack-style principal is not an email address");
  assert.equal(adminGrantEmails("bad<name@example.com:org_admin"), "");
  assert.equal(adminGrantEmails("admin@example.com:viewer:org_admin"), "");
  assert.equal(adminGrantEmails("admin@example.com::org_admin"), "");
  assert.equal(adminGrantEmails("admin@example.com\0:org_admin"), "");
  assert.equal(adminGrantEmails("admin@example.com:viewer"), "");
  assert.equal(adminGrantEmails("admin@example.com"), "");
  assert.equal(adminGrantEmails(undefined), "");
  assert.equal(adminGrantEmails(""), "");
});

test("the broker signing key is a fresh P-256 private JWK", () => {
  const first = JSON.parse(mintSigningJwk()) as Record<string, unknown>;
  assert.equal(first.kty, "EC");
  assert.equal(first.crv, "P-256");
  for (const field of ["d", "x", "y"]) assert.equal(typeof first[field], "string", field);
  assert.notEqual(mintSigningJwk(), JSON.stringify(first), "every deployment gets its own key");
});

test("the broker's operator secrets replace the external-IdP ones", () => {
  const external = configFor(["core", "web-ui", "admin", "portal"]);
  const externalNames = pendingSecrets(external, new Map()).todo.map((secret) => secret.name);
  assert.ok(externalNames.includes("OIDC_CLIENT_SECRET"));
  assert.ok(!externalNames.includes("AUTH_EMAIL_FROM"));

  const broker = configFor(
    ["core", "web-ui", "admin", "portal", "auth"],
    "",
    `{ "core": { "HARNESS": "pi" }, "auth": { "AUTH_EMAIL_TRANSPORT": "resend" } }`,
  );
  const brokerNames = pendingSecrets(broker, new Map()).todo.map((secret) => secret.name);
  assert.ok(!brokerNames.includes("OIDC_CLIENT_SECRET"), "the broker mints the portal's client secret");
  assert.ok(!brokerNames.includes("OIDC_CLIENT_ID"));
  assert.ok(!brokerNames.includes("PORTAL_EXPECTED_TEAM_ID"));
  for (const name of [
    "AUTH_ALLOWED_EMAILS",
    "AUTH_EMAIL_FROM",
    "AUTH_SIGNING_JWK",
    "AUTH_TOKEN_SECRET",
    "AUTH_CLIENT_SECRET",
  ]) {
    assert.ok(brokerNames.includes(name), `broker mode should collect ${name}`);
  }
  assert.match(playbookFor("AUTH_EMAIL_FROM", broker).join("\n"), /verified sender/);
  assert.match(playbookFor("OIDC_CLIENT_ID", broker).join("\n"), /external identity provider/);
});

test("runSetup refuses to run without a TTY", async () => {
  await assert.rejects(
    () => runSetup({ dir: tmpdir() }),
    (e: unknown) => {
      assert.ok(e instanceof CliError);
      assert.match((e as Error).message, /interactive/);
      return true;
    },
  );
});

async function withSetupTty<T>(fn: (input: PassThrough) => Promise<T>): Promise<T> {
  const input = Object.assign(new PassThrough(), { isTTY: true, setRawMode(): void {} });
  const descriptor = Object.getOwnPropertyDescriptor(process, "stdin")!;
  const write = process.stdout.write;
  Object.defineProperty(process, "stdin", { value: input, configurable: true });
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    return await fn(input);
  } finally {
    process.stdout.write = write;
    Object.defineProperty(process, "stdin", descriptor);
    input.destroy();
  }
}

test("runSetup preserves hidden secret bytes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-setup-hidden-"));
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "acme",
        publicUrl: "http://localhost:8080",
        target: "docker",
        services: ["core"],
        secretEnv: { core: { CUSTOM_SECRET: "CUSTOM_SECRET" } },
      }),
    );
    await withSetupTty(async (input) => {
      setImmediate(() => input.end("  padded-secret  \n"));
      await runSetup({ dir });
    });
    assert.equal(readEnvFile(join(dir, ".env")).get("CUSTOM_SECRET"), "  padded-secret  ");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runSetup rejects malformed UTF-8 hidden input without writing it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-setup-hidden-utf8-"));
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "acme",
        publicUrl: "http://localhost:8080",
        target: "docker",
        services: ["core"],
        secretEnv: { core: { CUSTOM_SECRET: "CUSTOM_SECRET" } },
      }),
    );
    await withSetupTty(async (input) => {
      setImmediate(() => input.end(Buffer.from([0xc3, 0x28, 0x0a])));
      await assert.rejects(() => runSetup({ dir }), /valid UTF-8 text/);
    });
    assert.equal(readEnvFile(join(dir, ".env")).has("CUSTOM_SECRET"), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runSetup refuses direct, symlink, and hardlink aliases between config and environment", async () => {
  const configBody = JSON.stringify({
    contract: 1,
    orgId: "acme",
    publicUrl: "http://localhost:8080",
    target: "docker",
    services: ["core"],
  });
  for (const kind of ["direct", "symlink", "hardlink"] as const) {
    const dir = mkdtempSync(join(tmpdir(), `qm-setup-${kind}-`));
    try {
      const config = join(dir, CONFIG_FILENAME);
      const env = join(dir, ".env");
      if (kind === "direct") {
        writeFileSync(env, configBody);
        symlinkSync(env, config);
      } else {
        writeFileSync(config, configBody);
        if (kind === "symlink") symlinkSync(config, env);
        else linkSync(config, env);
      }
      await withSetupTty(() => assert.rejects(() => runSetup({ dir }), /environment file|must be separate/));
      assert.equal(readFileSync(kind === "direct" ? env : config, "utf8"), configBody);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("runSetup writes generated secrets to a separate environment file", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-setup-safe-"));
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "acme",
        publicUrl: "http://localhost:8080",
        target: "docker",
        services: ["core"],
      }),
    );
    await withSetupTty(() => runSetup({ dir }));
    assert.match(readFileSync(join(dir, ".env"), "utf8"), /^CORE_SIGNING_SECRET=[a-f0-9]{64}$/m);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
