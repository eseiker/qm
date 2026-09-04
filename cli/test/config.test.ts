import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CONFIG_FILENAME,
  SECRET_SELECTOR_ENVIRONMENT_CONTRACTS,
  effectiveCoreEnvironment,
  effectiveDeployAppsDomain,
  effectiveModelProvider,
  effectivePortalPublicUrl,
  loadConfigAt,
  loadConfigInDir,
  mockHarnessWarning,
  sandboxCoreEnv,
  updateConfigImageOverrides,
  validatePortalTrust,
} from "../src/config.ts";
import { secretConditionSelectors } from "../src/secrets.ts";
import { isVirtualService } from "../src/services.ts";
import { usesSlackOidc } from "../src/slack-manifests.ts";

const BASE = {
  contract: 1,
  orgId: "acme",
  publicUrl: "https://agent.acme.example",
  target: "docker",
  services: ["core"],
};

function writeConfig(extra: Record<string, unknown>): { dir: string; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "qm-cfg-"));
  const path = join(dir, CONFIG_FILENAME);
  const env =
    extra.target === "aws"
      ? {
          ...(extra.env as Record<string, unknown> | undefined),
          core: {
            AWS_DEPLOY_IMAGE: "acme-sandbox",
            ...(extra.env as { core?: Record<string, unknown> } | undefined)?.core,
          },
        }
      : extra.env;
  writeFileSync(path, JSON.stringify({ ...BASE, ...extra, ...(env === undefined ? {} : { env }) }));
  return { dir, path };
}

function withConfig(extra: Record<string, unknown>, fn: (r: { dir: string; path: string }) => void): void {
  const r = writeConfig(extra);
  try {
    fn(r);
  } finally {
    rmSync(r.dir, { recursive: true, force: true });
  }
}

function withRawConfig(raw: string, fn: (r: { dir: string; path: string }) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "qm-cfg-raw-"));
  const path = join(dir, CONFIG_FILENAME);
  writeFileSync(path, raw);
  try {
    fn({ dir, path });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("required fields: orgId, target, services (must include core), valid service names", () => {
  withConfig({ orgId: "" }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /"orgId" must be a lowercase DNS label/),
  );
  for (const orgId of ["../other", "ACME", "a/b", "-acme", "acme-"]) {
    withConfig({ orgId }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /"orgId" must be a lowercase DNS label/),
    );
  }
  withConfig({ target: "k8s" }, ({ path }) => assert.throws(() => loadConfigAt(path), /"target" must be/));
  withConfig({ services: undefined }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /"services" must be an array/),
  );
  withConfig({ services: ["web-ui"] }, ({ path }) => assert.throws(() => loadConfigAt(path), /must include "core"/));
  withConfig({ services: ["core", "nope"] }, ({ path }) => assert.throws(() => loadConfigAt(path), /unknown service/));
  withConfig({ services: ["core", "web-ui", "admin", "portal"] }, ({ path }) => {
    const { config } = loadConfigAt(path);
    assert.deepEqual(config.services, ["core", "web-ui", "admin", "portal"]);
  });
  withConfig({ unknownField: "bad" }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /unknown top-level field "unknownField"/),
  );
  withConfig({ org_id: "acme" }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /unknown top-level field "org_id"/),
  );
  withConfig({ "//": "comment-key convention for plain-JSON configs" }, ({ path }) => {
    assert.ok(loadConfigAt(path).config);
  });
});

test("config parsing rejects duplicate object keys at every nesting level", () => {
  for (const raw of [
    '{"contract":1,"contract":1}',
    '{"env":{"core":{"TOKEN":"first","TOKEN":"second"}}}',
    '{"plugins":[{"env":{"TOKEN":"first","\\u0054OKEN":"second"}}]}',
    '{"env":{},"\\u0065nv":{}}',
  ]) {
    withRawConfig(raw, ({ path }) => assert.throws(() => loadConfigAt(path), /duplicate object key/));
  }
});

test("config parsing rejects NUL in every string key and value", () => {
  for (const raw of [
    '{"value":"left\\u0000right"}',
    '{"left\\u0000right":"value"}',
    '{"nested":[{"value":"left\\u0000right"}]}',
  ]) {
    withRawConfig(raw, ({ path }) => assert.throws(() => loadConfigAt(path), /configuration must not contain NUL/));
  }
});

test("config parsing rejects malformed UTF-8 before validation", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-cfg-bytes-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, CONFIG_FILENAME);
  writeFileSync(
    path,
    Buffer.concat([
      Buffer.from(
        '{"contract":1,"orgId":"acme","publicUrl":"http://localhost:8080","target":"docker","services":["core"],"env":{"core":{"X":"',
      ),
      Buffer.from([0xc3, 0x28]),
      Buffer.from('"}}}'),
    ]),
  );
  assert.throws(() => loadConfigAt(path), /valid UTF-8 text/);
});

test("config loading accepts file symlinks and rejects non-regular inputs", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-cfg-input-"));
  const file = join(dir, CONFIG_FILENAME);
  const link = join(dir, "linked.jsonc");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(file, JSON.stringify(BASE));
  symlinkSync(file, link);
  assert.equal(loadConfigAt(link).config.orgId, "acme");
  assert.throws(() => loadConfigAt(dir), /regular file/);
  if (process.platform !== "win32") {
    const fifo = join(dir, "config.fifo");
    execFileSync("mkfifo", [fifo]);
    assert.throws(() => loadConfigAt(fifo), /regular file/);
    assert.throws(() => loadConfigAt("/dev/null"), /regular file/);
  }
});

test("string-map keys are valid environment names without losing __proto__", () => {
  withRawConfig(
    '{"contract":1,"orgId":"acme","publicUrl":"http://localhost:8080","target":"docker","services":["core"],"env":{"core":{"__proto__":"kept"}}}',
    ({ path }) => {
      const env = loadConfigAt(path).config.env.core!;
      assert.equal(Object.hasOwn(env, "__proto__"), true);
      assert.equal(env["__proto__"], "kept");
    },
  );
  withConfig({ env: { core: { "BAD KEY": "value" } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /env\.core.*not a valid env var name/),
  );
  withConfig({ plugins: [{ name: "linear", env: { "BAD KEY": "value" } }] }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /plugins\[0\]\.env.*not a valid env var name/),
  );
  withConfig(
    {
      target: "aws",
      publicUrl: "https://acme.example.com",
      aws: {
        accountId: "123456789012",
        region: "us-east-1",
        cluster: "acme",
        deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
        secretsPrefix: "acme/",
        imageLabel: "release",
        networking: { cloudMapNamespace: "acme.internal" },
        services: {
          core: {
            ecrRepository: "core",
            ecsService: "acme-core",
            cpu: 512,
            memory: 1024,
            buildArgs: { "BAD KEY": "value" },
          },
        },
      },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /buildArgs.*not a valid env var name/),
  );
});

test("portal and broker allowlists use the auth runtime email grammar", () => {
  withConfig(
    {
      services: ["core", "portal"],
      env: { portal: { OIDC_CLIENT_ID: "client", OIDC_ALLOWED_EMAILS: "bad<name@example.com" } },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /OIDC_ALLOWED_EMAILS.*valid/),
  );
  withConfig(
    {
      services: ["core", "portal"],
      env: { portal: { OIDC_CLIENT_ID: "client", OIDC_ALLOWED_EMAILS: "operator@sub-domain.example.com" } },
    },
    ({ path }) =>
      assert.equal(loadConfigAt(path).config.env.portal?.OIDC_ALLOWED_EMAILS, "operator@sub-domain.example.com"),
  );
  withConfig(
    {
      services: ["core", "portal", "auth"],
      env: { auth: { AUTH_EMAIL_TRANSPORT: "resend" } },
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.throws(
        () => validatePortalTrust(config, path, new Map([["AUTH_ALLOWED_EMAILS", "bad<name@example.com"]])),
        /valid AUTH_ALLOWED_EMAILS/,
      );
      assert.doesNotThrow(() =>
        validatePortalTrust(config, path, new Map([["AUTH_ALLOWED_EMAILS", "operator@sub-domain.example.com"]])),
      );
    },
  );
});

test("built-in broker wiring cannot be overridden through env or secretEnv", () => {
  const managed = {
    portal: [
      "AUTH_BROKER_UPSTREAM",
      "AUTH_BROKER_PREFIX",
      "OIDC_CLIENT_ID",
      "OIDC_ISSUER",
      "OIDC_AUTH_ENDPOINT",
      "OIDC_TOKEN_ENDPOINT",
      "OIDC_USERINFO_ENDPOINT",
      "OIDC_JWKS_URI",
      "OIDC_SCOPES",
      "OIDC_PRINCIPAL_CLAIM",
      "OIDC_ALLOWED_EMAIL_DOMAIN",
      "PORTAL_EXPECTED_TEAM_ID",
    ],
    auth: ["AUTH_ISSUER", "AUTH_CLIENT_ID", "AUTH_REDIRECT_URI"],
  } as const;
  for (const source of ["env", "secretEnv"] as const) {
    for (const [service, names] of Object.entries(managed)) {
      for (const name of names) {
        withConfig(
          {
            services: ["core", "portal", "auth"],
            env: { auth: { AUTH_EMAIL_TRANSPORT: "resend", AUTH_ALLOWED_EMAIL_DOMAIN: "example.com" } },
            [source]: {
              ...(source === "env"
                ? { auth: { AUTH_EMAIL_TRANSPORT: "resend", AUTH_ALLOWED_EMAIL_DOMAIN: "example.com" } }
                : {}),
              [service]: { [name]: source === "env" ? "configured" : "CONFIGURED_STORE_NAME" },
            },
          },
          ({ path }) =>
            assert.throws(
              () => loadConfigAt(path),
              /built-in auth broker|derived from publicUrl|Slack sign-in|managed outside the deployment secret store/,
            ),
        );
      }
    }
  }
});

test("portal public origins are canonical and bound to publicUrl", () => {
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal", "auth"],
      env: {
        portal: { PORTAL_PUBLIC_URL: "HTTPS://PORTAL.EXAMPLE.COM:443/" },
        auth: { AUTH_EMAIL_TRANSPORT: "resend", AUTH_ALLOWED_EMAIL_DOMAIN: "example.com" },
      },
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.equal(config.env.portal?.PORTAL_PUBLIC_URL, "https://portal.example.com");
      assert.equal(effectivePortalPublicUrl(config), "https://portal.example.com");
    },
  );
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: { portal: { PORTAL_PUBLIC_URL: "https://other.example.com" } },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /PORTAL_PUBLIC_URL must match publicUrl/),
  );
});

test("Slack OIDC manifest selectors cannot be secret-backed", () => {
  for (const name of ["OIDC_ISSUER", "OIDC_AUTH_ENDPOINT", "OIDC_TOKEN_ENDPOINT", "OIDC_USERINFO_ENDPOINT"]) {
    withConfig(
      {
        publicUrl: "https://portal.example.com",
        services: ["core", "portal"],
        env: { portal: { OIDC_CLIENT_ID: "client", OIDC_ALLOWED_EMAILS: "admin@example.com" } },
        secretEnv: { portal: { [name]: `${name}_STORE` } },
      },
      ({ path }) =>
        assert.throws(
          () => loadConfigAt(path),
          /controls Slack SSO manifest selection.*non-secret|managed outside the deployment secret store/,
        ),
    );
  }
});

test("external OIDC topology uses canonical HTTPS URLs before manifest selection", () => {
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: {
        portal: {
          OIDC_CLIENT_ID: "client",
          OIDC_ALLOWED_EMAILS: "admin@example.com",
          OIDC_ISSUER: "HTTPS://SLACK.COM:443/",
          OIDC_AUTH_ENDPOINT: "HTTPS://SLACK.COM:443/openid/connect/authorize?team=T1",
          OIDC_TOKEN_ENDPOINT: "HTTPS://SLACK.COM:443/api/openid.connect.token",
          OIDC_USERINFO_ENDPOINT: "HTTPS://SLACK.COM:443/api/openid.connect.userInfo",
        },
      },
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.equal(config.env.portal?.OIDC_ISSUER, "https://slack.com");
      assert.equal(config.env.portal?.OIDC_AUTH_ENDPOINT, "https://slack.com/openid/connect/authorize?team=T1");
      assert.equal(usesSlackOidc(config), true);
    },
  );
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: {
        portal: {
          OIDC_CLIENT_ID: "client",
          OIDC_ALLOWED_EMAILS: "admin@example.com",
          OIDC_ISSUER: "HTTPS://AUTH.EXAMPLE.COM:443/tenant/",
          OIDC_JWKS_URI: "https://auth.example.com/tenant/jwks.json",
        },
      },
    },
    ({ path }) => assert.equal(loadConfigAt(path).config.env.portal?.OIDC_ISSUER, "https://auth.example.com/tenant/"),
  );
  for (const name of ["OIDC_ISSUER", "OIDC_AUTH_ENDPOINT", "OIDC_TOKEN_ENDPOINT", "OIDC_USERINFO_ENDPOINT"]) {
    for (const value of [
      "slack.com",
      "http://slack.com/path",
      "https:///slack.com/path",
      "https://user@slack.com/path",
      "https://slack.com/path#fragment",
      "https://slack.com/path#",
      "https://slack.com/path?",
      "https://slack.com\\path",
      ...(name === "OIDC_ISSUER" ? ["https://slack.com/not-the-token-issuer"] : []),
    ]) {
      withConfig(
        {
          publicUrl: "https://portal.example.com",
          services: ["core", "portal"],
          env: {
            portal: {
              OIDC_CLIENT_ID: "client",
              OIDC_ALLOWED_EMAILS: "admin@example.com",
              [name]: value,
            },
          },
        },
        ({ path }) => assert.throws(() => loadConfigAt(path), /must be an absolute HTTPS URL/),
      );
    }
  }
});

test("apiUrl must be an http(s) origin URL; the trailing slash is stripped", () => {
  withConfig({ apiUrl: "HTTPS://API.ACME.EXAMPLE:443/" }, ({ path }) =>
    assert.equal(loadConfigAt(path).config.apiUrl, "https://api.acme.example"),
  );
  withConfig({}, ({ path }) => assert.equal(loadConfigAt(path).config.apiUrl, undefined));
  for (const apiUrl of [
    "",
    "not a url",
    "ftp://api.acme.example",
    "https://api.acme.example/v1",
    "https://api.acme.example?x=1",
    "https://api.acme.example?",
    "https://api.acme.example#",
    "https:///api.acme.example",
    "https://api.acme.example\\",
    "https://@api.acme.example",
    "https://:@api.acme.example",
    "https://user:pw@api.acme.example",
    "https://api.acme.example.",
  ]) {
    withConfig({ apiUrl }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /"apiUrl" must be a non-empty http\(s\) origin URL/),
    );
  }
});

test("real harness public coordinates require HTTPS or loopback on every target", () => {
  for (const coordinates of [
    { publicUrl: "http://agent.acme.example" },
    { publicUrl: "https://agent.acme.example", apiUrl: "http://api.agent.acme.example" },
  ]) {
    withConfig({ ...coordinates, env: { core: { HARNESS: "pi" } } }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /HARNESS=pi requires an HTTPS publicUrl and apiUrl, or loopback origins/),
    );
  }
  for (const coordinates of [
    { publicUrl: "http://localhost:8080" },
    { publicUrl: "http://127.0.0.2:8080", apiUrl: "http://[::1]:8788" },
  ]) {
    withConfig({ ...coordinates, env: { core: { HARNESS: "pi" } } }, ({ path }) =>
      assert.doesNotThrow(() => loadConfigAt(path)),
    );
  }
});

test("publicUrl must be an http(s) origin URL on every target", () => {
  withConfig({ publicUrl: "HTTPS://ACME.EXAMPLE:443/" }, ({ path }) =>
    assert.equal(loadConfigAt(path).config.publicUrl, "https://acme.example"),
  );
  for (const publicUrl of [
    "",
    "not a url",
    "ftp://acme.example",
    "https://acme.example/subpath",
    "https://acme.example?x=1",
    "https://acme.example?",
    "https://acme.example#",
    "https:///acme.example",
    "https://acme.example\\",
    "https://@acme.example",
    "https://:@acme.example",
    "https://user:pw@acme.example",
    "https://acme.example.",
  ]) {
    withConfig({ publicUrl }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /"publicUrl" must be a non-empty http\(s\) origin URL/),
    );
  }
});

test("botName and orgName are optional trimmed strings with length caps", () => {
  withConfig({}, ({ path }) => {
    const { config } = loadConfigAt(path);
    assert.equal(config.botName, undefined);
    assert.equal(config.orgName, undefined);
  });
  withConfig({ botName: " straylight ", orgName: " Acme Corp " }, ({ path }) => {
    const { config } = loadConfigAt(path);
    assert.equal(config.botName, "straylight");
    assert.equal(config.orgName, "Acme Corp");
  });
  withConfig({ botName: "x".repeat(31) }, ({ path }) => assert.equal(loadConfigAt(path).config.botName?.length, 31));
  for (const botName of ["", "   ", 7, "x".repeat(32), "{{bot}}", "a<b>c", "bot\nX", 'a"b', "a\\b"]) {
    withConfig({ botName }, ({ path }) => assert.throws(() => loadConfigAt(path), /"botName" must be/));
  }
  for (const orgName of ["", 7, "x".repeat(41), "Acme {{Corp}}"]) {
    withConfig({ orgName }, ({ path }) => assert.throws(() => loadConfigAt(path), /"orgName" must be/));
  }
});

test("basePort must be a positive integer", () => {
  withConfig({ basePort: 9000 }, ({ path }) => assert.equal(loadConfigAt(path).config.basePort, 9000));
  withConfig({ basePort: -1 }, ({ path }) => assert.throws(() => loadConfigAt(path), /basePort/));
  withConfig({ basePort: 1.5 }, ({ path }) => assert.throws(() => loadConfigAt(path), /basePort/));
});

test("plugins: image is OPTIONAL (source plugins); env attaches to either; bad image rejected", () => {
  withConfig({ plugins: [{ name: "intercom", env: { INTERCOM_REGION: "us" } }] }, ({ path }) => {
    const { config } = loadConfigAt(path);
    const p0 = config.plugins[0]!;
    assert.equal(p0.name, "intercom");
    assert.equal(p0.image, undefined);
    assert.deepEqual(p0.env, { INTERCOM_REGION: "us" });
  });
  withConfig({ plugins: [{ name: "linear", image: "ghcr.io/acme/linear:1" }] }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.plugins[0]!.image, "ghcr.io/acme/linear:1");
  });
  withConfig({ plugins: [{ name: "x", image: "" }] }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /image must be a non-empty string/),
  );
  withConfig({ plugins: [{ name: "core" }] }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /collides with a built-in/),
  );
  withConfig({ plugins: [{ name: "a" }, { name: "a" }] }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /duplicate plugin name/),
  );
});

test("env (per-service) and imageOverrides validate by service name", () => {
  withConfig(
    {
      publicUrl: "http://example.com",
      env: { core: { PUBLIC_WEB_URL: "HTTP://EXAMPLE.COM:80/" } },
      imageOverrides: { core: "ghcr.io/x:1" },
    },
    ({ path }) => {
      const { config } = loadConfigAt(path);
      assert.deepEqual(config.env.core, { PUBLIC_WEB_URL: "http://example.com" });
      assert.equal(config.imageOverrides.core, "ghcr.io/x:1");
    },
  );
  withConfig({ env: { core: { PUBLIC_WEB_URL: "http://x" } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /PUBLIC_WEB_URL must match publicUrl/),
  );
  withConfig({ env: { nope: {} } }, ({ path }) => assert.throws(() => loadConfigAt(path), /unknown service/));
  withConfig({ env: { core: { S3_PREFIX: "core/" } } }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.env.core?.S3_PREFIX, "core/");
  });
});

test("listen ports are managed consistently across deployment targets", () => {
  withConfig({ env: { core: { PORT: "9000" } } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /env\.core\.PORT.*managed/);
  });
  withConfig({ plugins: [{ name: "linear", env: { PORT: "9000" } }] }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /plugins\[0\]\.env\.PORT.*managed/);
  });
});

test("the admin release version comes from its image", () => {
  withConfig({ env: { admin: { QM_VERSION: "9.9.9" } } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /env\.admin\.QM_VERSION.*baked into the Admin image/);
  });
  withConfig({ secretEnv: { admin: { QM_VERSION: "QM_VERSION_SECRET" } } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /secretEnv\.admin\.QM_VERSION.*baked into the Admin image/);
  });
  withConfig(
    {
      target: "aws",
      services: ["core", "admin"],
      aws: {
        accountId: "123456789012",
        region: "us-west-2",
        cluster: "acme",
        deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
        secretsPrefix: "acme/",
        imageLabel: "release",
        networking: { cloudMapNamespace: "acme.internal" },
        services: {
          core: { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024 },
          admin: {
            ecrRepository: "admin",
            ecsService: "acme-admin",
            cpu: 512,
            memory: 1024,
            buildArgs: { QM_VERSION: "9.9.9" },
          },
        },
      },
    },
    ({ path }) => {
      assert.throws(() => loadConfigAt(path), /aws\.services\.admin\.buildArgs\.QM_VERSION.*reserved/);
    },
  );
});

test("retired browser updater config requires a drained workflow and revoked token", () => {
  for (const name of [
    "QM_UPDATE_GITHUB_REPOSITORY",
    "QM_UPDATE_GITHUB_WORKFLOW",
    "QM_UPDATE_GITHUB_REF",
    "QM_UPDATE_GITHUB_TOKEN",
    "QM_UPDATE_GITHUB_API_URL",
  ] as const) {
    withConfig({ env: { admin: { [name]: "retired" } } }, ({ path }) => {
      assert.throws(
        () => loadConfigAt(path),
        new RegExp(
          `env\\.admin\\.${name}.*retired browser updater.*drain every queued or running update job.*remove its workflows.*QM_UPDATE_GITHUB_\\* config.*QM_DEPLOY_ENV.*every resident QM_UPDATE_GITHUB_TOKEN.*FLY_SANDBOX_API_TOKEN.*FLY_API_TOKEN`,
        ),
      );
    });
  }
  withConfig(
    {
      env: {
        admin: {
          QM_UPDATE_GITHUB_REPOSITORY: "yc-software/qm",
          QM_UPDATE_GITHUB_WORKFLOW: ".github/workflows/custom-update.yaml",
        },
      },
    },
    ({ path }) =>
      assert.throws(() => loadConfigAt(path), /drain every queued or running update job.*remove its workflows/),
  );
  withConfig({ secretEnv: { admin: { QM_UPDATE_GITHUB_TOKEN: "RETIRED_TOKEN" } } }, ({ path }) => {
    assert.throws(
      () => loadConfigAt(path),
      /secretEnv\.admin\.QM_UPDATE_GITHUB_TOKEN.*retired browser updater.*QM_DEPLOY_ENV.*every resident QM_UPDATE_GITHUB_TOKEN.*FLY_SANDBOX_API_TOKEN.*FLY_API_TOKEN/,
    );
  });
});

test("portal-mounted admin uses the portal's fixed /admin route", () => {
  withConfig({ services: ["core", "admin", "portal"], env: { admin: { ADMIN_BASE_PATH: "/ops" } } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /env\.admin\.ADMIN_BASE_PATH.*must be "\/admin"/);
  });
  withConfig(
    { services: ["core", "admin", "portal"], secretEnv: { admin: { ADMIN_BASE_PATH: "ADMIN_PATH_SECRET" } } },
    ({ path }) => {
      assert.throws(() => loadConfigAt(path), /secretEnv\.admin\.ADMIN_BASE_PATH.*managed/);
    },
  );
  withConfig({ services: ["core", "admin", "portal"], env: { admin: { ADMIN_BASE_PATH: "/admin" } } }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.env.admin?.ADMIN_BASE_PATH, "/admin");
  });
});

test("model, skills, and the fly keys parse onto the config", () => {
  withConfig({ model: "claude-opus-4-8", skills: ["./skills/support"] }, ({ path }) => {
    const { config } = loadConfigAt(path);
    assert.equal(config.model, "claude-opus-4-8");
    assert.deepEqual(config.skills, ["./skills/support"]);
  });
  withConfig(
    {
      target: "fly",
      appPrefix: "qm",
      region: "sjc",
      flyOrg: "personal",
      imageFrom: "qm",
      deployAppPrefix: "qm-d",
      sandbox: { backend: "sprites", namePrefix: "qm-sandboxes" },
    },
    ({ path }) => {
      const { config } = loadConfigAt(path);
      assert.equal(config.appPrefix, "qm");
      assert.equal(config.region, "sjc");
      assert.equal(config.flyOrg, "personal");
      assert.equal(config.imageFrom, "qm");
      assert.equal(config.deployAppPrefix, "qm-d");
    },
  );
});

test("custom portal issuers require an HTTPS JWKS URI on Fly", () => {
  withConfig(
    {
      target: "fly",
      services: ["core", "portal"],
      env: { portal: { OIDC_ISSUER: "https://auth.example.com" } },
      sandbox: { backend: "sprites", namePrefix: "acme-sandboxes" },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /OIDC_JWKS_URI/),
  );
});

test("AWS workload architecture accepts arm64 or amd64 only", () => {
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release",
    networking: { cloudMapNamespace: "acme.internal" },
    services: {
      core: { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024, architecture: "amd64" },
    },
  };
  withConfig({ target: "aws", aws }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.aws!.services.core!.architecture, "amd64");
  });
  withConfig(
    { target: "aws", aws: { ...aws, services: { core: { ...aws.services.core, architecture: "ppc64" } } } },
    ({ path }) => {
      assert.throws(() => loadConfigAt(path), /architecture.*must be "arm64" or "amd64"/);
    },
  );

  const untypedAws = { ...aws, services: { core: { ...aws.services.core, architecture: undefined } } };
  withConfig({ target: "aws", imageOverrides: { core: "ghcr.io/acme/core:1" }, aws: untypedAws }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /core\.architecture is required/);
  });
  withConfig(
    {
      target: "aws",
      plugins: [{ name: "linear", image: "ghcr.io/acme/linear:1" }],
      aws: {
        ...untypedAws,
        services: {
          ...untypedAws.services,
          linear: { ecrRepository: "linear", ecsService: "linear", cpu: 256, memory: 512 },
        },
      },
    },
    ({ path }) => {
      assert.throws(() => loadConfigAt(path), /linear\.architecture is required/);
    },
  );
});

test("AWS config rejects public surfaces without the HTTPS portal and real harnesses over HTTP", () => {
  const service = (name: string) => ({
    ecrRepository: `qm-${name}`,
    ecsService: `acme-${name}`,
    cpu: name === "core" ? 2048 : 512,
    memory: name === "core" ? 4096 : 1024,
  });
  const aws = (names: string[]) => ({
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release",
    networking: { cloudMapNamespace: "acme.internal" },
    services: Object.fromEntries(names.map((name) => [name, service(name)])),
  });
  const cases: Array<{ label: string; config: Record<string, unknown>; error: RegExp }> = [
    {
      label: "web-ui without portal",
      config: {
        target: "aws",
        publicUrl: "https://agent.acme.example",
        services: ["core", "web-ui"],
        aws: aws(["core", "web-ui"]),
      },
      error: /web-ui requires the authenticated portal/,
    },
    {
      label: "admin without portal",
      config: {
        target: "aws",
        publicUrl: "https://agent.acme.example",
        services: ["core", "admin"],
        aws: aws(["core", "admin"]),
      },
      error: /admin requires the authenticated portal/,
    },
    {
      label: "portal over HTTP",
      config: {
        target: "aws",
        publicUrl: "http://agent.acme.example",
        services: ["core", "web-ui", "portal"],
        env: { core: { HARNESS: "mock" } },
        aws: aws(["core", "web-ui", "portal"]),
      },
      error: /portal requires an HTTPS publicUrl/,
    },
    {
      label: "portal without a tenant gate",
      config: {
        target: "aws",
        publicUrl: "https://agent.acme.example",
        services: ["core", "web-ui", "portal"],
        env: { core: { HARNESS: "mock" }, portal: { OIDC_CLIENT_ID: "client", PORTAL_EXPECTED_TEAM_ID: " " } },
        aws: aws(["core", "web-ui", "portal"]),
      },
      error: /PORTAL_EXPECTED_TEAM_ID/,
    },
    {
      label: "custom OIDC issuer without a JWKS URI",
      config: {
        target: "aws",
        publicUrl: "https://agent.acme.example",
        services: ["core", "web-ui", "portal"],
        env: {
          core: { HARNESS: "mock" },
          portal: {
            OIDC_CLIENT_ID: "client",
            OIDC_ISSUER: "https://auth.example.com",
            OIDC_ALLOWED_EMAILS: "admin@example.com",
          },
        },
        aws: aws(["core", "web-ui", "portal"]),
      },
      error: /OIDC_JWKS_URI/,
    },
    {
      label: "custom OIDC issuer with an insecure JWKS URI",
      config: {
        target: "aws",
        publicUrl: "https://agent.acme.example",
        services: ["core", "web-ui", "portal"],
        env: {
          core: { HARNESS: "mock" },
          portal: {
            OIDC_CLIENT_ID: "client",
            OIDC_ISSUER: "https://auth.example.com",
            OIDC_JWKS_URI: "http://auth.example.com/jwks.json",
            OIDC_ALLOWED_EMAILS: "admin@example.com",
          },
        },
        aws: aws(["core", "web-ui", "portal"]),
      },
      error: /absolute HTTPS URL/,
    },
    {
      label: "real harness over HTTP",
      config: {
        target: "aws",
        publicUrl: "http://agent.acme.example",
        services: ["core"],
        env: { core: { HARNESS: "pi" } },
        aws: aws(["core"]),
      },
      error: /HARNESS=pi requires an HTTPS publicUrl/,
    },
    {
      label: "virtual service real harness over HTTP",
      config: {
        target: "aws",
        publicUrl: "http://agent.acme.example",
        services: ["core", "slack"],
        env: { slack: { HARNESS: "pi" } },
        aws: aws(["core"]),
      },
      error: /HARNESS=pi requires an HTTPS publicUrl/,
    },
    {
      label: "apiUrl protocol differing from publicUrl",
      config: {
        target: "aws",
        publicUrl: "https://agent.acme.example",
        apiUrl: "http://api.agent.acme.example",
        services: ["core"],
        env: { core: { HARNESS: "mock" } },
        aws: aws(["core"]),
      },
      error: /apiUrl must use the same protocol as publicUrl/,
    },
  ];
  for (const deployBranch of ["refs/heads/main", "a..b", "bad branch", "release/", ".hidden", "x.lock"]) {
    cases.push({
      label: `deployBranch ${JSON.stringify(deployBranch)}`,
      config: {
        target: "aws",
        publicUrl: "http://agent.acme.example",
        services: ["core"],
        env: { core: { HARNESS: "mock" } },
        aws: { ...aws(["core"]), deployBranch },
      },
      error: /"aws\.deployBranch" must be a valid git branch name/,
    });
  }
  withConfig(
    {
      target: "aws",
      publicUrl: "http://agent.acme.example",
      services: ["core"],
      env: { core: { HARNESS: "mock" } },
      aws: { ...aws(["core"]), deployBranch: "release/prod-2", deployEnvironment: "production" },
    },
    ({ path }) => {
      assert.equal(loadConfigAt(path).config.aws?.deployBranch, "release/prod-2");
      assert.equal(loadConfigAt(path).config.aws?.deployEnvironment, "production");
    },
  );
  for (const deployEnvironment of ["bad:name", "bad environment", ".hidden", "x".repeat(256)]) {
    withConfig(
      {
        target: "aws",
        publicUrl: "http://agent.acme.example",
        services: ["core"],
        env: { core: { HARNESS: "mock" } },
        aws: { ...aws(["core"]), deployEnvironment },
      },
      ({ path }) =>
        assert.throws(
          () => loadConfigAt(path),
          /"aws\.deployEnvironment" must be a valid GitHub environment name/,
          JSON.stringify(deployEnvironment),
        ),
    );
  }
  for (const item of cases) {
    withConfig(item.config, ({ path }) => assert.throws(() => loadConfigAt(path), item.error, item.label));
  }
  withConfig(
    {
      target: "aws",
      publicUrl: "http://agent.acme.example",
      services: ["core"],
      env: { core: { HARNESS: "mock" } },
      aws: aws(["core"]),
    },
    ({ path }) => {
      assert.equal(loadConfigAt(path).config.env.core?.HARNESS, "mock");
    },
  );
  withConfig(
    {
      target: "aws",
      publicUrl: "https://agent.acme.example",
      services: ["core", "web-ui", "portal"],
      env: {
        core: { HARNESS: "pi" },
        portal: { OIDC_CLIENT_ID: "client", OIDC_ALLOWED_EMAIL_DOMAIN: "example.com", PORTAL_EXPECTED_TEAM_ID: "T123" },
      },
      aws: aws(["core", "web-ui", "portal"]),
    },
    ({ path }) => {
      assert.equal(loadConfigAt(path).config.services.includes("portal"), true);
    },
  );
  withConfig(
    {
      target: "aws",
      publicUrl: "https://agent.acme.example",
      services: ["core", "web-ui", "portal"],
      env: { core: { HARNESS: "pi" }, portal: { OIDC_CLIENT_ID: "client", OIDC_ALLOWED_EMAILS: "admin@example.com" } },
      aws: aws(["core", "web-ui", "portal"]),
    },
    ({ path }) => {
      assert.equal(loadConfigAt(path).config.env.portal?.OIDC_ALLOWED_EMAILS, "admin@example.com");
    },
  );
  withConfig(
    {
      target: "aws",
      publicUrl: "https://agent.acme.example",
      services: ["core", "web-ui", "portal"],
      env: { core: { HARNESS: "pi" }, portal: { OIDC_PRINCIPAL_CLAIM: "email" } },
      aws: aws(["core", "web-ui", "portal"]),
    },
    ({ path }) => {
      assert.equal(loadConfigAt(path).config.env.portal?.OIDC_CLIENT_ID, undefined);
    },
  );
});

test("AWS conditions cannot select a deployment provider that the renderer replaces", () => {
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release",
    networking: { cloudMapNamespace: "acme.internal" },
    services: { core: { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024 } },
  };
  withConfig(
    {
      target: "aws",
      publicUrl: "https://acme.example.com",
      services: ["core", "slack"],
      aws,
      env: { slack: { DEPLOY_PROVIDER: "fly" } },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /DEPLOY_PROVIDER must be "aws" or unset/),
  );
  withConfig(
    {
      target: "aws",
      publicUrl: "https://acme.example.com",
      services: ["core", "slack"],
      aws,
      env: { slack: { DEPLOY_PROVIDER: "fly" }, core: { DEPLOY_PROVIDER: "aws" } },
    },
    ({ path }) => assert.equal(effectiveCoreEnvironment(loadConfigAt(path).config).DEPLOY_PROVIDER?.trim(), "aws"),
  );
});

test("AWS validates release labels, unique coordinates, Fargate sizes, and owned networking", () => {
  const service = { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024 };
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release-1",
    networking: { cloudMapNamespace: "acme.internal" },
    services: { core: service },
  };
  withConfig({ target: "aws", aws }, ({ path }) =>
    assert.equal(loadConfigAt(path).config.aws?.imageLabel, "release-1"),
  );
  for (const imageLabel of [undefined, "", ".release", "release!", "x".repeat(129)]) {
    withConfig({ target: "aws", aws: { ...aws, imageLabel } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /aws\.imageLabel/);
    });
  }
  for (const invalid of [
    { cpu: 1, memory: 1 },
    { cpu: 256, memory: 768 },
    { cpu: 4096, memory: 4096 },
  ]) {
    withConfig({ target: "aws", aws: { ...aws, services: { core: { ...service, ...invalid } } } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /not a supported Fargate task size/);
    });
  }
  for (const field of ["ecrRepository", "ecsService"] as const) {
    withConfig(
      {
        target: "aws",
        services: ["core", "web-ui"],
        aws: {
          ...aws,
          services: {
            core: service,
            "web-ui": { ...service, ecrRepository: "web", ecsService: "acme-web", [field]: service[field] },
          },
        },
      },
      ({ path }) => assert.throws(() => loadConfigAt(path), new RegExp(`duplicates aws\\.services\\.core\\.${field}`)),
    );
  }
  withConfig({ target: "aws", aws: { ...aws, alb: "legacy-alb", rdsInstance: "legacy-db" } }, ({ path }) => {
    const parsed = loadConfigAt(path).config.aws!;
    assert.equal(parsed.alb, "legacy-alb");
    assert.equal(parsed.rdsInstance, "legacy-db");
  });
  for (const alb of ["", "internal-thing", "has_underscore", "x".repeat(33)]) {
    withConfig({ target: "aws", aws: { ...aws, alb } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /aws\.alb/);
    });
  }
  for (const rdsInstance of ["", "9starts-with-digit", "double--hyphen", "ends-", "Mixed-Case"]) {
    withConfig({ target: "aws", aws: { ...aws, rdsInstance } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /aws\.rdsInstance/);
    });
  }
  for (const objectStoreBucket of ["legacy-bucket", "assets.acme.example", "192.168.5.bucket"]) {
    withConfig({ target: "aws", aws: { ...aws, objectStoreBucket } }, ({ path }) => {
      assert.equal(loadConfigAt(path).config.aws!.objectStoreBucket, objectStoreBucket);
    });
  }
  for (const objectStoreBucket of [
    "ab",
    ".leading-dot",
    "trailing-dot.",
    "double..dot",
    "Mixed.Case",
    "under_score",
    "x".repeat(64),
    "192.168.5.4",
  ]) {
    withConfig({ target: "aws", aws: { ...aws, objectStoreBucket } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /aws\.objectStoreBucket.*valid S3 bucket name/);
    });
  }
  withConfig({ target: "aws", aws: { ...aws, predeployDbSnapshot: false } }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.aws!.predeployDbSnapshot, false);
  });
  for (const predeployDbSnapshot of ["false", 0, null]) {
    withConfig({ target: "aws", aws: { ...aws, predeployDbSnapshot } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /aws\.predeployDbSnapshot/);
    });
  }
  withConfig({ target: "aws", aws: { ...aws, dbRetentionMinDays: 35 } }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.aws!.dbRetentionMinDays, 35);
  });
  for (const dbRetentionMinDays of ["7", 1.5, -1, 36, null]) {
    withConfig({ target: "aws", aws: { ...aws, dbRetentionMinDays } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /aws\.dbRetentionMinDays/);
    });
  }
  withConfig(
    {
      target: "aws",
      aws: { ...aws, services: { core: { ...service, desiredCount: 2, targetGroup: "legacy-core-tg" } } },
    },
    ({ path }) => {
      const core = loadConfigAt(path).config.aws!.services.core!;
      assert.equal(core.desiredCount, 2);
      assert.equal(core.targetGroup, "legacy-core-tg");
    },
  );
  for (const desiredCount of [0, -1, 1.5, "2"]) {
    withConfig({ target: "aws", aws: { ...aws, services: { core: { ...service, desiredCount } } } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /aws\.services\.core\.desiredCount/);
    });
  }
  for (const targetGroup of ["", "has_underscore", "-leading", "trailing-", "x".repeat(33)]) {
    withConfig({ target: "aws", aws: { ...aws, services: { core: { ...service, targetGroup } } } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /aws\.services\.core\.targetGroup/);
    });
  }
  withConfig(
    {
      target: "aws",
      services: ["core", "web-ui"],
      aws: {
        ...aws,
        services: {
          core: { ...service, targetGroup: "shared-tg" },
          "web-ui": { ...service, ecrRepository: "web", ecsService: "acme-web", targetGroup: "shared-tg" },
        },
      },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /duplicates aws\.services\.core\.targetGroup/),
  );
  withConfig(
    { target: "aws", aws: { ...aws, services: { core: { ...service, dockerfile: "layered/core.Dockerfile" } } } },
    ({ path }) => {
      assert.equal(loadConfigAt(path).config.aws?.services.core?.dockerfile, "layered/core.Dockerfile");
    },
  );
  for (const dockerfile of [
    "",
    "/abs/Dockerfile",
    "layered/../../escape.Dockerfile",
    "layered\\..\\escape.Dockerfile",
  ]) {
    withConfig({ target: "aws", aws: { ...aws, services: { core: { ...service, dockerfile } } } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /services\.core\.dockerfile/);
    });
  }
  for (const field of ["subnets", "securityGroups"] as const) {
    withConfig({ target: "aws", aws: { ...aws, networking: { ...aws.networking, [field]: ["x"] } } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), new RegExp(`aws\\.networking\\.${field}.*not supported`));
    });
  }
});

test("AWS rejects coordinates that its Terraform-derived resources cannot accept", () => {
  const service = { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024 };
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release",
    networking: { cloudMapNamespace: "acme.internal" },
    services: { core: service },
  };
  for (const accountId of ["1", "12345678901x", "1234567890123"]) {
    withConfig({ target: "aws", aws: { ...aws, accountId } }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /aws\.accountId.*12 digits/),
    );
  }
  for (const region of [
    "cn-north-1",
    "us-gov-west-1",
    "us-iso-east-1",
    "us-isob-east-1",
    "eu-isoe-west-1",
    "us-isof-south-1",
  ]) {
    withConfig({ target: "aws", aws: { ...aws, region } }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /commercial AWS partition/),
    );
  }
  for (const cluster of ["Acme", "1acme", "acme--prod", "acme_", `a${"b".repeat(49)}`]) {
    withConfig({ target: "aws", aws: { ...aws, cluster } }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /aws\.cluster.*derived IAM and RDS/),
    );
  }
  for (const secretsPrefix of ["acme?", "x".repeat(257)]) {
    withConfig({ target: "aws", aws: { ...aws, secretsPrefix } }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /secretsPrefix.*AWS secret-name/),
    );
  }
  for (const cloudMapNamespace of ["-acme.internal", "acme..internal", `${"a".repeat(64)}.internal`, "a".repeat(254)]) {
    withConfig({ target: "aws", aws: { ...aws, networking: { cloudMapNamespace } } }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /cloudMapNamespace.*valid DNS/),
    );
  }
  for (const deployRoleArn of [
    "not-an-arn",
    "arn:aws:iam::999999999999:role/deploy",
    "arn:aws-cn:iam::123456789012:role/deploy",
    "arn:aws:iam::123456789012:user/deploy",
  ]) {
    withConfig({ target: "aws", aws: { ...aws, deployRoleArn } }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /deployRoleArn.*account 123456789012.*commercial AWS partition/),
    );
  }
  for (const role of ["taskRoleArn", "executionRoleArn"] as const) {
    for (const arn of [
      "not-an-arn",
      "arn:aws:iam::999999999999:role/custom",
      "arn:aws-cn:iam::123456789012:role/custom",
    ]) {
      withConfig({ target: "aws", aws: { ...aws, services: { core: { ...service, [role]: arn } } } }, ({ path }) => {
        assert.throws(() => loadConfigAt(path), new RegExp(`${role}.*account 123456789012.*commercial AWS partition`));
      });
    }
  }
  const longSecret = `X${"Y".repeat(300)}`;
  withConfig(
    {
      target: "aws",
      plugins: [{ name: "linear", secrets: [{ name: longSecret }] }],
      aws: { ...aws, secretsPrefix: "p".repeat(220) },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /plus computed secret.*512-character/),
  );
});

test("Fly Sprites config reaches core as a backend and name prefix without OCI fields", () => {
  withConfig(
    { target: "fly", region: "sjc", flyOrg: "acme", sandbox: { backend: "sprites", namePrefix: "acme" } },
    ({ path }) => {
      assert.deepEqual(sandboxCoreEnv(loadConfigAt(path).config), {
        env: { SANDBOX_BACKEND: "sprites", SPRITES_NAME_PREFIX: "acme" },
        missingSecrets: [],
      });
    },
  );
  for (const target of [{}, { target: "fly", region: "sjc", flyOrg: "acme" }]) {
    withConfig(
      {
        ...target,
        sandbox: {
          app: "legacy",
          namePrefix: "new",
          image: `registry.fly.io/legacy@sha256:${"a".repeat(64)}`,
          baseImage: `ghcr.io/yc-software/qm-sandbox-base@sha256:${"b".repeat(64)}`,
        },
      },
      ({ path }) => {
        const config = loadConfigAt(path).config;
        assert.deepEqual(config.sandbox, { app: "legacy", namePrefix: "new" });
        assert.deepEqual(sandboxCoreEnv(config).env, {
          SANDBOX_BACKEND: "sprites",
          SPRITES_NAME_PREFIX: "new",
        });
      },
    );
  }
});

test("Docker defaults to the local sandbox and accepts only its runnable image", () => {
  withConfig({}, ({ path }) => {
    assert.deepEqual(sandboxCoreEnv(loadConfigAt(path).config), {
      env: { SANDBOX_BACKEND: "local" },
      missingSecrets: [],
    });
  });
  withConfig({ sandbox: { backend: "local", image: "qm-sandbox-local:latest" } }, ({ path }) => {
    assert.deepEqual(sandboxCoreEnv(loadConfigAt(path).config), {
      env: { SANDBOX_BACKEND: "local", LOCAL_SANDBOX_IMAGE: "qm-sandbox-local:latest" },
      missingSecrets: [],
    });
  });
});

test("Sprites name prefixes are explicit and cannot select OCI images", () => {
  withConfig(
    {
      target: "fly",
      region: "sjc",
      flyOrg: "acme",
      sandbox: { backend: "sprites", namePrefix: "acme", image: "example.invalid/sandbox:latest" },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /sprites.*cannot consume/i),
  );
  withConfig({ target: "fly", region: "sjc", flyOrg: "acme", sandbox: { backend: "sprites" } }, ({ path }) => {
    assert.deepEqual(sandboxCoreEnv(loadConfigAt(path).config).env, { SANDBOX_BACKEND: "sprites" });
  });
  withConfig(
    { target: "fly", region: "sjc", flyOrg: "acme", sandbox: { backend: "sprites", namePrefix: " acme " } },
    ({ path }) => assert.equal(loadConfigAt(path).config.sandbox?.namePrefix, "acme"),
  );
  const longPrefix = "a".repeat(256);
  withConfig(
    { target: "fly", region: "sjc", flyOrg: "acme", sandbox: { backend: "sprites", namePrefix: longPrefix } },
    ({ path }) => assert.equal(loadConfigAt(path).config.sandbox?.namePrefix, longPrefix),
  );
  for (const namePrefix of ["", "UPPER", "has_space", "-leading", "trailing-"]) {
    withConfig(
      { target: "fly", region: "sjc", flyOrg: "acme", sandbox: { backend: "sprites", namePrefix } },
      ({ path }) => assert.throws(() => loadConfigAt(path), /sandbox.namePrefix.*lowercase letters, digits/),
    );
  }
  withConfig(
    {
      target: "fly",
      region: "sjc",
      flyOrg: "acme",
      sandbox: {
        backend: "sprites",
        app: "legacy",
        namePrefix: "new",
        image: `registry.fly.io/legacy@sha256:${"a".repeat(64)}`,
        baseImage: `ghcr.io/yc-software/qm-sandbox-base@sha256:${"b".repeat(64)}`,
      },
    },
    ({ path }) => {
      assert.deepEqual(loadConfigAt(path).config.sandbox, {
        backend: "sprites",
        app: "legacy",
        namePrefix: "new",
      });
    },
  );
});

test("v0.1.6 sandbox shapes preserve the historical Sprite name prefix", () => {
  const image = `registry.fly.io/acme-sandboxes@sha256:${"a".repeat(64)}`;
  const baseImage = `ghcr.io/yc-software/qm-sandbox-base@sha256:${"b".repeat(64)}`;
  const legacySandbox = {
    app: "acme-sandboxes",
    image,
    baseImage,
  };
  withConfig(
    {
      target: "fly",
      region: "sjc",
      flyOrg: "personal",
      appPrefix: "qm",
      deployAppPrefix: "qm-d",
      sandbox: legacySandbox,
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.deepEqual(config.sandbox, { app: "acme-sandboxes" });
      assert.deepEqual(sandboxCoreEnv(config).env, { SANDBOX_BACKEND: "sprites" });
    },
  );
  withConfig(
    {
      target: "fly",
      region: "sjc",
      flyOrg: "personal",
      sandbox: { backend: "sprites", ...legacySandbox },
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.deepEqual(config.sandbox, { backend: "sprites", app: "acme-sandboxes" });
      assert.deepEqual(sandboxCoreEnv(config).env, { SANDBOX_BACKEND: "sprites" });
    },
  );
  withConfig({ target: "fly", region: "sjc", flyOrg: "personal" }, ({ path }) => {
    assert.deepEqual(sandboxCoreEnv(loadConfigAt(path).config).env, { SANDBOX_BACKEND: "sprites" });
  });
  withConfig(
    {
      sandbox: legacySandbox,
      env: { core: { SANDBOX_BACKEND: "sprites" } },
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.deepEqual(config.sandbox, { backend: "sprites", app: "acme-sandboxes" });
      assert.equal(config.env.core?.SANDBOX_BACKEND, undefined);
      assert.deepEqual(sandboxCoreEnv(config).env, { SANDBOX_BACKEND: "sprites" });
    },
  );
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release",
    networking: { cloudMapNamespace: "acme.internal" },
    services: { core: { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024 } },
  };
  withConfig({ target: "aws", aws }, ({ path }) => {
    assert.deepEqual(sandboxCoreEnv(loadConfigAt(path).config).env, { SANDBOX_BACKEND: "aws" });
  });
  withConfig({ target: "aws", aws, sandbox: { backend: "sprites", ...legacySandbox } }, ({ path }) => {
    const config = loadConfigAt(path).config;
    assert.deepEqual(config.sandbox, { backend: "sprites", app: "acme-sandboxes" });
    assert.deepEqual(sandboxCoreEnv(config).env, { SANDBOX_BACKEND: "sprites" });
  });
  withConfig({ target: "aws", aws, sandbox: legacySandbox }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /target "aws" requires an explicit "sandbox.backend"/);
  });
});

test("legacy sandbox fields either migrate safely or fail with an actionable boundary", () => {
  const digestBase = `ghcr.io/yc-software/qm-sandbox-base@sha256:${"b".repeat(64)}`;
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release",
    networking: { cloudMapNamespace: "acme.internal" },
    services: { core: { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024 } },
  };
  for (const sandbox of [
    { env: {} },
    { secretEnv: [] },
    { baseImage: digestBase },
    { env: {}, secretEnv: [], baseImage: digestBase },
  ]) {
    withConfig({ sandbox }, ({ path }) => {
      assert.equal(loadConfigAt(path).config.sandbox, undefined);
    });
  }
  withConfig(
    { target: "fly", region: "sjc", flyOrg: "personal", sandbox: { backend: "sprites", env: {}, secretEnv: [] } },
    ({ path }) => {
      assert.deepEqual(loadConfigAt(path).config.sandbox, { backend: "sprites" });
    },
  );
  withConfig({ target: "aws", aws, sandbox: { env: {}, secretEnv: [], baseImage: digestBase } }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.sandbox, undefined);
  });
  withConfig({ sandbox: { baseImage: "base" } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /baseImage.*inert v0.1.6 metadata.*sandbox.app/);
  });
  withConfig({ sandbox: { app: "legacy", env: { TZ: "UTC" } } }, ({ path }) => {
    assert.throws(
      () => loadConfigAt(path),
      /sandbox.env from v0.1.6 cannot be migrated automatically.*stage each value.*verify the replacement.*remove sandbox.env.*roll the deployment.*confirm no live references/,
    );
  });
  const legacySecretEnv = { backend: "sprites", app: "legacy", secretEnv: ["TOKEN", "COMPANY_TOKEN"] };
  withConfig({ sandbox: legacySecretEnv }, ({ path }) => {
    assert.throws(
      () => loadConfigAt(path),
      /sandbox.secretEnv from v0.1.6 cannot be migrated automatically \(TOKEN, COMPANY_TOKEN\).*connector, keychain, or tool path.*verify the replacement.*remove sandbox.secretEnv.*roll the deployment.*confirm no live references.*delete \.env or environment entries TOKEN, COMPANY_TOKEN/,
    );
  });
  withConfig({ target: "fly", region: "sjc", flyOrg: "personal", sandbox: legacySecretEnv }, ({ path }) => {
    assert.throws(
      () => loadConfigAt(path),
      /remove sandbox.secretEnv.*roll the deployment.*confirm no live references.*delete Fly secrets FLY_RESIDENT_ENV_TOKEN, FLY_RESIDENT_ENV_COMPANY_TOKEN/,
    );
  });
  withConfig({ target: "aws", aws, sandbox: legacySecretEnv }, ({ path }) => {
    assert.throws(
      () => loadConfigAt(path),
      /remove sandbox.secretEnv.*roll the deployment.*confirm no live references.*delete AWS Secrets Manager entries acme\/TOKEN, acme\/COMPANY_TOKEN/,
    );
  });
  withConfig({ sandbox: { app: "legacy", secretEnv: ["not-valid"] } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /sandbox.secretEnv.*not a valid env var name/);
  });
});

test("legacy Sprites environment selection preserves an explicit namespace byte-for-byte", () => {
  const prefix = `legacy-${"a".repeat(96)}`;
  withConfig(
    {
      target: "fly",
      region: "sjc",
      flyOrg: "personal",
      sandbox: {
        app: "retired-app",
        image: `registry.fly.io/retired-app@sha256:${"a".repeat(64)}`,
        baseImage: `ghcr.io/yc-software/qm-sandbox-base@sha256:${"b".repeat(64)}`,
      },
      env: { core: { SANDBOX_BACKEND: "sprites", SPRITES_NAME_PREFIX: prefix } },
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.deepEqual(config.sandbox, { backend: "sprites", app: "retired-app", namePrefix: prefix });
      assert.deepEqual(sandboxCoreEnv(config).env, {
        SANDBOX_BACKEND: "sprites",
        SPRITES_NAME_PREFIX: prefix,
      });
      assert.equal(config.env.core?.SANDBOX_BACKEND, undefined);
      assert.equal(config.env.core?.SPRITES_NAME_PREFIX, undefined);
    },
  );
  withConfig(
    {
      target: "fly",
      region: "sjc",
      flyOrg: "personal",
      sandbox: { app: "retired-app" },
      env: { core: { SANDBOX_BACKEND: "sprites", SPRITES_NAME_PREFIX: "" } },
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.deepEqual(config.sandbox, { backend: "sprites", app: "retired-app" });
      assert.deepEqual(sandboxCoreEnv(config).env, { SANDBOX_BACKEND: "sprites" });
      assert.equal(config.env.core?.SPRITES_NAME_PREFIX, undefined);
    },
  );
  for (const configured of [" spaced ", "UPPER", "bad_value"]) {
    withConfig(
      {
        target: "fly",
        region: "sjc",
        flyOrg: "personal",
        env: { core: { SANDBOX_BACKEND: "sprites", SPRITES_NAME_PREFIX: configured } },
      },
      ({ path }) => assert.throws(() => loadConfigAt(path), /env.core.SPRITES_NAME_PREFIX.*lowercase letters/),
    );
  }
  withConfig(
    {
      target: "fly",
      region: "sjc",
      flyOrg: "personal",
      sandbox: { backend: "sprites", namePrefix: "new" },
      env: { core: { SPRITES_NAME_PREFIX: "old" } },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /SPRITES_NAME_PREFIX conflicts with sandbox.namePrefix/),
  );
});

test("Porter and smolmachines remain valid runtime sandbox selections", () => {
  const legacySandbox = {
    backend: "sprites",
    app: "retired-app",
    image: `registry.fly.io/retired-app@sha256:${"a".repeat(64)}`,
    baseImage: `ghcr.io/yc-software/qm-sandbox-base@sha256:${"b".repeat(64)}`,
  };
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release",
    networking: { cloudMapNamespace: "acme.internal" },
    services: { core: { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024 } },
  };
  for (const backend of ["porter", "smolmachines"] as const) {
    for (const target of [
      { sandbox: legacySandbox },
      { target: "fly", region: "sjc", flyOrg: "personal", sandbox: legacySandbox },
      { target: "aws", aws, sandbox: legacySandbox },
    ]) {
      withConfig({ ...target, env: { core: { SANDBOX_BACKEND: backend, SPRITES_NAME_PREFIX: "" } } }, ({ path }) => {
        const config = loadConfigAt(path).config;
        assert.equal(config.env.core?.SANDBOX_BACKEND, backend);
        assert.equal(config.sandbox, undefined);
        assert.deepEqual(sandboxCoreEnv(config).env, { SANDBOX_BACKEND: backend });
      });
    }
    withConfig(
      {
        sandbox: { image: `registry.fly.io/retired-app@sha256:${"a".repeat(64)}` },
        env: { core: { SANDBOX_BACKEND: backend } },
      },
      ({ path }) => {
        const config = loadConfigAt(path).config;
        assert.equal(config.sandbox, undefined);
        assert.deepEqual(sandboxCoreEnv(config).env, { SANDBOX_BACKEND: backend });
      },
    );
  }
  withConfig({ sandbox: { backend: "local" }, env: { core: { SANDBOX_BACKEND: "porter" } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /SANDBOX_BACKEND conflicts with the sandbox block/),
  );
  withConfig(
    {
      sandbox: { backend: "sprites", app: "legacy", namePrefix: "current" },
      env: { core: { SANDBOX_BACKEND: "smolmachines" } },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /SANDBOX_BACKEND conflicts with the sandbox block/),
  );
});

test("v0.1.6 local and AWS environment selections normalize into the sandbox block", () => {
  withConfig(
    {
      sandbox: {
        app: "retired-app",
        image: `registry.fly.io/retired-app@sha256:${"a".repeat(64)}`,
        baseImage: `ghcr.io/yc-software/qm-sandbox-base@sha256:${"b".repeat(64)}`,
      },
      env: { core: { SANDBOX_BACKEND: "local" } },
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.deepEqual(config.sandbox, { backend: "local" });
      assert.deepEqual(sandboxCoreEnv(config).env, { SANDBOX_BACKEND: "local" });
    },
  );
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release",
    networking: { cloudMapNamespace: "acme.internal" },
    services: { core: { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024 } },
  };
  withConfig({ target: "aws", aws, env: { core: { SANDBOX_BACKEND: "aws" } } }, ({ path }) => {
    const config = loadConfigAt(path).config;
    assert.deepEqual(config.sandbox, { backend: "aws" });
    assert.deepEqual(sandboxCoreEnv(config).env, { SANDBOX_BACKEND: "aws" });
  });
  withConfig(
    { target: "fly", region: "sjc", flyOrg: "personal", env: { core: { SANDBOX_BACKEND: "local" } } },
    ({ path }) => {
      assert.throws(() => loadConfigAt(path), /sandbox.backend.*local.*requires target "docker"/);
    },
  );
  withConfig({ env: { core: { SANDBOX_BACKEND: "aws" } } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /sandbox.backend.*aws.*requires target "aws"/);
  });
});

test("AWS distinguishes Sprites from Lambda MicroVM sandbox coordinates", () => {
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release",
    networking: { cloudMapNamespace: "acme.internal" },
    services: { core: { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024 } },
  };
  withConfig(
    { target: "aws", aws, sandbox: { backend: "sprites", namePrefix: "acme" }, env: { core: {} } },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.deepEqual(sandboxCoreEnv(config).env, {
        SANDBOX_BACKEND: "sprites",
        SPRITES_NAME_PREFIX: "acme",
      });
    },
  );
  withConfig({ target: "aws", aws, sandbox: { backend: "aws" } }, ({ path }) => {
    assert.equal(sandboxCoreEnv(loadConfigAt(path).config).env.SANDBOX_BACKEND, "aws");
  });
  withConfig(
    {
      target: "aws",
      aws,
      sandbox: { backend: "sprites", namePrefix: "acme" },
      env: { core: { AWS_DEPLOY_IMAGE: "" } },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /deployment publisher MicroVM image/),
  );
});

test("sandbox runtime environment coordinates reject invalid or secret overrides", () => {
  for (const name of ["LOCAL_SANDBOX_IMAGE", "AWS_SANDBOX_REGION"]) {
    withConfig({ env: { core: { [name]: "spoofed" } } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), new RegExp(`${name}.*derived.*cannot be overridden`));
    });
  }
  withConfig({ env: { core: { SANDBOX_BACKEND: "invalid" } } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /SANDBOX_BACKEND must be one of/);
  });
  for (const name of ["SANDBOX_BACKEND", "SPRITES_NAME_PREFIX"]) {
    withConfig({ secretEnv: { core: { [name]: "SECRET_NAME" } } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), new RegExp(`${name}.*non-secret`));
    });
  }
});

test("virtual services cannot own core sandbox topology across deployment targets", () => {
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    imageLabel: "release",
    networking: { cloudMapNamespace: "acme.internal" },
    services: { core: { ecrRepository: "core", ecsService: "acme-core", cpu: 512, memory: 1024 } },
  };
  const targets = [
    {},
    { target: "fly", region: "sjc", flyOrg: "personal", sandbox: { backend: "sprites", namePrefix: "acme" } },
    { target: "aws", publicUrl: "https://acme.example.com", aws },
  ];
  for (const target of targets) {
    for (const source of ["env", "secretEnv"] as const) {
      for (const [name, value] of [
        ["SANDBOX_BACKEND", "sprites"],
        ["SANDBOX_SECONDARY_BACKEND", "porter"],
        ["SPRITES_NAME_PREFIX", "acme"],
      ] as const) {
        withConfig({ ...target, services: ["core", "slack"], [source]: { slack: { [name]: value } } }, ({ path }) =>
          assert.throws(() => loadConfigAt(path), /controls the core sandbox/),
        );
      }
    }
  }
  for (const source of ["env", "secretEnv"] as const) {
    for (const name of ["AWS_DEPLOY_APPS_DOMAIN", "DEPLOY_APPS_DOMAIN", "PORTER_DEPLOY_APPS_DOMAIN"]) {
      withConfig(
        {
          services: ["core", "slack"],
          [source]: { slack: { [name]: source === "env" ? "apps.example.com" : "STORE_NAME" } },
        },
        ({ path }) => assert.throws(() => loadConfigAt(path), /controls deployment routing/),
      );
    }
  }
});

test("virtual services cannot override target-managed core runtime coordinates", () => {
  for (const source of ["env", "secretEnv"] as const) {
    for (const name of [
      "PORT",
      "LOCAL_SANDBOX_IMAGE",
      "AWS_SANDBOX_REGION",
      "AWS_SANDBOX_IMAGE",
      "AWS_SANDBOX_IMAGE_VERSION",
      "AWS_SANDBOX_EXEC_ROLE_ARN",
      "AWS_SANDBOX_S3_BUCKET",
    ]) {
      withConfig({ services: ["core", "slack"], [source]: { slack: { [name]: "ATTACKER_VALUE" } } }, ({ path }) =>
        assert.throws(() => loadConfigAt(path), /managed by the deployment target|derived from the sandbox/),
      );
    }
  }
});

test("sandbox secondary backend uses the core runtime selection rules", () => {
  withConfig({ env: { core: { SANDBOX_SECONDARY_BACKEND: "invalid" } } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /SANDBOX_SECONDARY_BACKEND must be one of/);
  });
  withConfig({ env: { core: { SANDBOX_SECONDARY_BACKEND: "local" } } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /SANDBOX_SECONDARY_BACKEND must differ/);
  });
  withConfig({ env: { core: { SANDBOX_SECONDARY_BACKEND: "porter" } } }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.env.core?.SANDBOX_SECONDARY_BACKEND, "porter");
  });
});

test("value-inspected secret selectors must be configured as non-secret environment values", () => {
  for (const { service, name } of secretConditionSelectors().filter(
    (selector) => selector.mode === "value-inspected",
  )) {
    withConfig(
      {
        services: ["core", "portal", "auth", "slack"],
        secretEnv: { [service]: { [name]: "SHARED_STORE_NAME" } },
      },
      ({ path }) => assert.throws(() => loadConfigAt(path), /non-secret/),
    );
  }
  withConfig({ secretEnv: { core: { UNRELATED_DESTINATION: "MODEL_PROVIDER" } } }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.secretEnv?.core?.UNRELATED_DESTINATION, "MODEL_PROVIDER");
  });
  for (const [service, name] of [
    ["auth", "AUTH_ALLOWED_EMAIL_DOMAIN"],
    ["core", "AWS_DEPLOY_APPS_DOMAIN"],
    ["core", "DEPLOY_APPS_DOMAIN"],
    ["slack", "AWS_DEPLOY_APPS_DOMAIN"],
    ["slack", "DEPLOY_APPS_DOMAIN"],
    ["slack", "PORTER_DEPLOY_APPS_DOMAIN"],
  ] as const) {
    withConfig(
      { services: ["core", "portal", "auth", "slack"], secretEnv: { [service]: { [name]: "STORE_NAME" } } },
      ({ path }) => assert.throws(() => loadConfigAt(path), /non-secret environment value|controls deployment routing/),
    );
  }
});

test("deployment apps domain follows the core runtime provider precedence", () => {
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: {
        core: {
          AWS_DEPLOY_APPS_DOMAIN: "apps.aws.portal.example.com",
          PORTER_DEPLOY_APPS_DOMAIN: "apps.porter.example.com",
          DEPLOY_APPS_DOMAIN: "Apps.Common.Portal.Example.Com.",
        },
      },
    },
    ({ path }) => assert.equal(effectiveDeployAppsDomain(loadConfigAt(path).config), "apps.common.portal.example.com"),
  );
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: { core: { AWS_DEPLOY_APPS_DOMAIN: "apps.aws.portal.example.com" } },
    },
    ({ path }) => {
      assert.equal(effectiveDeployAppsDomain(loadConfigAt(path).config), "apps.aws.portal.example.com");
    },
  );
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: {
        core: {
          DEPLOY_PROVIDER: "porter",
          AWS_DEPLOY_APPS_DOMAIN: "apps.aws.portal.example.com",
        },
      },
    },
    ({ path }) => assert.equal(effectiveDeployAppsDomain(loadConfigAt(path).config), "apps.aws.portal.example.com"),
  );
  withConfig({ env: { core: { PORTER_DEPLOY_APPS_DOMAIN: "apps.porter.example.com" } } }, ({ path }) => {
    assert.equal(effectiveDeployAppsDomain(loadConfigAt(path).config), undefined);
  });
});

test("gated deployment apps domains require the portal service", () => {
  for (const name of ["DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_APPS_DOMAIN"] as const) {
    withConfig({ env: { core: { [name]: "apps.example.com" } } }, ({ path }) => {
      assert.throws(() => loadConfigAt(path), /gated deployment apps domain requires the portal service/);
    });
  }
  withConfig({ env: { core: { PORTER_DEPLOY_APPS_DOMAIN: "apps.porter.example.com" } } }, ({ path }) => {
    assert.equal(effectiveDeployAppsDomain(loadConfigAt(path).config), undefined);
  });
});

test("deployment apps domains are canonical controlled DNS names", () => {
  for (const name of ["DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_APPS_DOMAIN"] as const) {
    withConfig(
      {
        publicUrl: "https://portal.example.com",
        services: ["core", "portal"],
        env: { core: { [name]: "Apps.Portal.Example.Com." } },
      },
      ({ path }) => {
        const config = loadConfigAt(path).config;
        assert.equal(config.env.core?.[name], "apps.portal.example.com");
        assert.equal(effectiveDeployAppsDomain(config), "apps.portal.example.com");
      },
    );
    for (const value of [
      "https://apps.example.com",
      "apps.example.com:443",
      "apps.example.com/path",
      "*.example.com",
      "single-label",
      "apps..example.com",
      "apps.fly.dev",
    ]) {
      withConfig({ env: { core: { [name]: value } } }, ({ path }) =>
        assert.throws(() => loadConfigAt(path), /bare DNS name|shared platform domain/),
      );
    }
  }
  const boundary = ["a".repeat(63), "b".repeat(43), "portal", "example", "com"].join(".");
  const oversized = ["a".repeat(63), "b".repeat(44), "portal", "example", "com"].join(".");
  assert.equal(boundary.length, 126);
  assert.equal(oversized.length, 127);
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: { core: { DEPLOY_APPS_DOMAIN: boundary } },
    },
    ({ path }) => assert.equal(effectiveDeployAppsDomain(loadConfigAt(path).config), boundary),
  );
  withConfig({ env: { core: { DEPLOY_APPS_DOMAIN: oversized } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /bare DNS name/),
  );
});

test("Porter direct deployment domains are canonical bounded DNS names", () => {
  const boundary = ["a".repeat(63), "b".repeat(63), "c".repeat(61)].join(".");
  const oversized = ["a".repeat(63), "b".repeat(63), "c".repeat(62)].join(".");
  assert.equal(boundary.length, 189);
  assert.equal(oversized.length, 190);
  for (const value of [
    "",
    " ",
    " apps.example.com",
    "apps.example.com ",
    "https://apps.example.com",
    "apps.example.com/path",
    "*.apps.example.com",
    "apps.example.com:443",
    "apps.example.com\0",
    "127.0.0.1",
    "apps.127.0.0.1",
    oversized,
  ]) {
    withConfig({ env: { core: { PORTER_DEPLOY_APPS_DOMAIN: value } } }, ({ path }) =>
      assert.throws(
        () => loadConfigAt(path),
        /PORTER_DEPLOY_APPS_DOMAIN must be a bare DNS name|configuration must not contain NUL bytes/,
      ),
    );
  }
  for (const [value, expected] of [
    ["APPS.DIRECT.EXAMPLE.COM.", "apps.direct.example.com"],
    ["team.onporter.run", "team.onporter.run"],
    [boundary, boundary],
  ]) {
    withConfig({ env: { core: { PORTER_DEPLOY_APPS_DOMAIN: value } } }, ({ path }) =>
      assert.equal(loadConfigAt(path).config.env.core?.PORTER_DEPLOY_APPS_DOMAIN, expected),
    );
  }
});

test("Porter routing cannot ambiguously select gated and direct domains", () => {
  withConfig(
    {
      env: {
        core: {
          DEPLOY_PROVIDER: "porter",
          AWS_DEPLOY_APPS_DOMAIN: "apps.gated.example.com",
          PORTER_DEPLOY_APPS_DOMAIN: "apps.direct.example.com",
        },
      },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /are ambiguous when DEPLOY_PROVIDER is porter/),
  );
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: {
        core: {
          DEPLOY_PROVIDER: "porter",
          DEPLOY_APPS_DOMAIN: "apps.portal.example.com",
          PORTER_DEPLOY_APPS_DOMAIN: "apps.direct.example.com",
        },
      },
    },
    ({ path }) => assert.equal(effectiveDeployAppsDomain(loadConfigAt(path).config), "apps.portal.example.com"),
  );
  for (const [name, gated, direct] of [
    ["DEPLOY_APPS_DOMAIN", "apps.portal.example.com", "apps.portal.example.com"],
    ["DEPLOY_APPS_DOMAIN", "Apps.Portal.Example.Com.", "APPS.PORTAL.EXAMPLE.COM."],
    ["AWS_DEPLOY_APPS_DOMAIN", "apps.portal.example.com", "APPS.PORTAL.EXAMPLE.COM."],
  ] as const) {
    withConfig(
      {
        publicUrl: "https://portal.example.com",
        services: ["core", "portal"],
        env: {
          core: {
            DEPLOY_PROVIDER: "porter",
            [name]: gated,
            PORTER_DEPLOY_APPS_DOMAIN: direct,
          },
        },
      },
      ({ path }) => assert.throws(() => loadConfigAt(path), /must use distinct gated and direct domains/),
    );
  }
  withConfig(
    { env: { core: { DEPLOY_PROVIDER: "porter", PORTER_DEPLOY_APPS_DOMAIN: "apps.direct.example.com" } } },
    ({ path }) => assert.doesNotThrow(() => loadConfigAt(path)),
  );
});

test("portal cannot override the core-derived deployment apps domain", () => {
  for (const source of ["env", "secretEnv"] as const) {
    for (const name of ["DEPLOY_APPS_DOMAIN", "PORTAL_APPS_DOMAIN"]) {
      withConfig(
        {
          services: ["core", "portal"],
          [source]: { portal: { [name]: source === "env" ? "apps.example.com" : "STORE_NAME" } },
        },
        ({ path }) => assert.throws(() => loadConfigAt(path), /derived from the core deployment routing domain/),
      );
    }
  }
});

test("portal apps domains require a compatible browser cookie scope", () => {
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: { core: { DEPLOY_APPS_DOMAIN: "apps.portal.example.com" } },
    },
    ({ path }) => assert.equal(effectiveDeployAppsDomain(loadConfigAt(path).config), "apps.portal.example.com"),
  );
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: {
        core: { DEPLOY_APPS_DOMAIN: "apps.example.com" },
        portal: { PORTAL_COOKIE_DOMAIN: ".Example.Com." },
      },
    },
    ({ path }) => assert.equal(loadConfigAt(path).config.env.portal?.PORTAL_COOKIE_DOMAIN, "example.com"),
  );
  for (const env of [
    { core: { DEPLOY_APPS_DOMAIN: "apps.unrelated.net" } },
    {
      core: { DEPLOY_APPS_DOMAIN: "apps.example.com" },
      portal: { PORTAL_COOKIE_DOMAIN: "other.example.com" },
    },
  ]) {
    withConfig({ publicUrl: "https://portal.example.com", services: ["core", "portal"], env }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /apps domain must be under|cookie scope|must cover/),
    );
  }
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      secretEnv: { portal: { PORTAL_COOKIE_DOMAIN: "COOKIE_DOMAIN_STORE" } },
    },
    ({ path }) =>
      assert.throws(
        () => loadConfigAt(path),
        /cookie scope.*non-secret environment value|managed outside the deployment secret store/,
      ),
  );
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      secretEnv: { portal: { PORTAL_PUBLIC_URL: "PORTAL_URL_STORE" } },
    },
    ({ path }) =>
      assert.throws(
        () => loadConfigAt(path),
        /portal public origin.*non-secret environment value|managed outside the deployment secret store/,
      ),
  );
  for (const [publicUrl, cookie] of [
    ["https://tenant.fly.dev", "fly.dev"],
    ["https://tenant.github.io", "github.io"],
    ["https://tenant.onporter.run", "onporter.run"],
  ]) {
    withConfig(
      { publicUrl, services: ["core", "portal"], env: { portal: { PORTAL_COOKIE_DOMAIN: cookie } } },
      ({ path }) =>
        assert.throws(() => loadConfigAt(path), /PORTAL_COOKIE_DOMAIN must not be a shared platform domain/),
    );
  }
});

test("gated deployment login and portal origins must match", () => {
  const base = {
    publicUrl: "https://portal.example.com",
    services: ["core", "portal"],
  };
  withConfig({ ...base, env: { core: { DEPLOY_APPS_LOGIN_URL: "https://portal.example.com" } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /DEPLOY_APPS_LOGIN_URL requires a gated deployment apps domain/),
  );
  for (const core of [
    { DEPLOY_APPS_DOMAIN: "apps.example.com", DEPLOY_APPS_LOGIN_URL: "https://evil.example.com" },
    { DEPLOY_APPS_DOMAIN: "apps.example.com", PUBLIC_WEB_URL: "https://evil.example.com" },
  ]) {
    withConfig({ ...base, env: { core, portal: { PORTAL_COOKIE_DOMAIN: "example.com" } } }, ({ path }) =>
      assert.throws(
        () => loadConfigAt(path),
        /core deployment login origin must match|PUBLIC_WEB_URL must match publicUrl/,
      ),
    );
  }
  withConfig(
    {
      ...base,
      env: {
        core: { DEPLOY_APPS_DOMAIN: "apps.example.com" },
        portal: { PORTAL_COOKIE_DOMAIN: "example.com", PORTAL_PUBLIC_URL: "https://other.example.com" },
      },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /PORTAL_PUBLIC_URL must match publicUrl/),
  );
  withConfig(
    {
      ...base,
      publicUrl: "https://other.example.com",
      env: {
        core: {
          DEPLOY_APPS_DOMAIN: "apps.example.com",
          DEPLOY_APPS_LOGIN_URL: "HTTPS://OTHER.EXAMPLE.COM:443/",
        },
        portal: { PORTAL_COOKIE_DOMAIN: "example.com", PORTAL_PUBLIC_URL: "HTTPS://OTHER.EXAMPLE.COM:443/" },
      },
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.equal(effectiveDeployAppsDomain(config), "apps.example.com");
      assert.equal(config.env.core?.DEPLOY_APPS_LOGIN_URL, "https://other.example.com");
      assert.equal(config.env.portal?.PORTAL_PUBLIC_URL, "https://other.example.com");
    },
  );
  withConfig(
    {
      publicUrl: "https://localhost:8080",
      services: ["core", "portal"],
      env: { core: { DEPLOY_APPS_DOMAIN: "apps.localhost" } },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /requires a valid DNS portal host/),
  );
  for (const name of ["DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_APPS_DOMAIN"] as const) {
    withConfig(
      {
        publicUrl: "http://portal.example.com",
        services: ["core", "portal"],
        env: { core: { [name]: "apps.portal.example.com" } },
      },
      ({ path }) => assert.throws(() => loadConfigAt(path), /gated deployment apps require HTTPS/),
    );
  }
  withConfig(
    {
      publicUrl: "https://127.0.0.1",
      services: ["core", "portal"],
      env: {
        core: { DEPLOY_APPS_DOMAIN: "apps.example.com" },
        portal: { PORTAL_COOKIE_DOMAIN: "example.com" },
      },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /requires a valid DNS portal host/),
  );
  withConfig(
    {
      publicUrl: "https://portal.example.com",
      services: ["core", "portal"],
      env: { core: { DEPLOY_APPS_DOMAIN: "apps.127.0.0.1" } },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /DEPLOY_APPS_DOMAIN must be a bare DNS name/),
  );
  for (const publicHost of [
    `${"a".repeat(64)}.example.com`,
    `${Array.from({ length: 32 }, () => "abcdefgh").join(".")}.example.com`,
    "bad_host.example.com",
    "-bad.example.com",
    "bad-.example.com",
  ]) {
    withConfig(
      {
        publicUrl: `https://${publicHost}`,
        services: ["core", "portal"],
        env: {
          core: { DEPLOY_APPS_DOMAIN: "apps.example.com" },
          portal: { PORTAL_COOKIE_DOMAIN: "example.com" },
        },
      },
      ({ path }) => assert.throws(() => loadConfigAt(path), /requires a valid DNS portal host/),
    );
  }
  for (const name of ["PUBLIC_WEB_URL", "DEPLOY_APPS_LOGIN_URL"]) {
    withConfig({ ...base, secretEnv: { core: { [name]: "URL_STORE" } } }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /gated deployment login origin.*non-secret/),
    );
  }
  for (const value of [
    "https://portal.example.com?",
    "https://portal.example.com#",
    "https:///portal.example.com",
    "https://portal.example.com\\",
    "https://@portal.example.com",
    "https://:@portal.example.com",
  ]) {
    for (const name of ["DEPLOY_APPS_LOGIN_URL", "PUBLIC_WEB_URL"]) {
      withConfig(
        { ...base, env: { core: { DEPLOY_APPS_DOMAIN: "apps.portal.example.com", [name]: value } } },
        ({ path }) => assert.throws(() => loadConfigAt(path), /must be a non-empty http\(s\) origin/),
      );
    }
    withConfig(
      {
        ...base,
        env: {
          core: { DEPLOY_APPS_DOMAIN: "apps.portal.example.com" },
          portal: { PORTAL_PUBLIC_URL: value },
        },
      },
      ({ path }) => assert.throws(() => loadConfigAt(path), /PORTAL_PUBLIC_URL must be a non-empty http\(s\) origin/),
    );
  }
});

test("deployment app session keys cannot be configured as plaintext", () => {
  for (const name of ["DEPLOY_APPS_SESSION_SECRET", "PORTAL_SESSION_SECRET"]) {
    for (const service of ["core", "slack"] as const) {
      withConfig(
        {
          services: ["core", "slack"],
          env: { [service]: { [name]: "plaintext" } },
        },
        ({ path }) =>
          assert.throws(() => loadConfigAt(path), /managed secret destination.*cannot be configured as plaintext/),
      );
    }
  }
});

test("plaintext and secret environment sources cannot target the same runtime destination", () => {
  for (const [envService, secretService] of [
    ["core", "core"],
    ["core", "slack"],
    ["slack", "core"],
    ["slack", "slack"],
    ["portal", "portal"],
  ] as const) {
    withConfig(
      {
        services: ["core", "portal", "slack"],
        env: { [envService]: { SHARED_DESTINATION: "plaintext" } },
        secretEnv: { [secretService]: { SHARED_DESTINATION: "STORE_NAME" } },
      },
      ({ path }) => assert.throws(() => loadConfigAt(path), /conflicts with a plaintext/),
    );
  }
  withConfig(
    {
      services: ["core", "portal"],
      env: { core: { SHARED_DESTINATION: "core" } },
      secretEnv: { portal: { SHARED_DESTINATION: "PORTAL_STORE" } },
    },
    ({ path }) => assert.equal(loadConfigAt(path).config.secretEnv?.portal?.SHARED_DESTINATION, "PORTAL_STORE"),
  );
});

test("plaintext selector contracts cover every conditional secret input", () => {
  const selectors = secretConditionSelectors()
    .map(({ service, name, mode }) => `${isVirtualService(service) ? "core" : service}\0${name}\0${mode}`)
    .sort();
  const contracts = Object.entries(SECRET_SELECTOR_ENVIRONMENT_CONTRACTS)
    .flatMap(([service, entries]) =>
      Object.entries(entries).map(
        ([name, contract]) =>
          `${service}\0${name}\0${contract.kind === "enumerated" ? "value-inspected" : "presence-only"}`,
      ),
    )
    .sort();
  assert.deepEqual(
    selectors.filter((selector) => !contracts.includes(selector)),
    [],
  );
  for (const [service, entries] of Object.entries(SECRET_SELECTOR_ENVIRONMENT_CONTRACTS)) {
    for (const [name, contract] of Object.entries(entries)) {
      for (const value of ["", " ", ` ${contract.kind === "enumerated" ? contract.values[0] : "configured"} `]) {
        withConfig({ env: { [service]: { [name]: value } } }, ({ path }) => {
          assert.throws(() => loadConfigAt(path), /nonblank value without surrounding whitespace/);
        });
      }
      if (contract.kind === "enumerated") {
        withConfig({ env: { [service]: { [name]: "not-allowed" } } }, ({ path }) => {
          assert.throws(() => loadConfigAt(path), /must be one of/);
        });
      }
    }
  }
});

test("loadConfigInDir reads qm.config.jsonc from the deployment dir (no walk-up)", () => {
  withConfig({}, ({ dir }) => {
    assert.equal(loadConfigInDir(dir).config.orgId, "acme");
  });
  const empty = mkdtempSync(join(tmpdir(), "qm-empty-"));
  try {
    assert.throws(() => loadConfigInDir(empty), /no qm.config.jsonc/);
  } finally {
    rmSync(empty, { recursive: true, force: true });
  }
});

test("config JSONC accepts comments and trailing commas like tsconfig.json", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-jsonc-"));
  const path = join(dir, CONFIG_FILENAME);
  try {
    writeFileSync(
      path,
      `{
      // JSONC comment
      "contract": 1,
      "orgId": "acme",
      "publicUrl": "http://localhost:8080",
      "target": "docker",
      "services": ["core",],
    }`,
    );
    assert.deepEqual(loadConfigAt(path).config.services, ["core"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("config nesting fails with a controlled error before recursive validation can overflow", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-json-depth-"));
  const path = join(dir, CONFIG_FILENAME);
  try {
    writeFileSync(path, `{"//":${"[".repeat(300)}0${"]".repeat(300)}}`);
    assert.throws(() => loadConfigAt(path), /nesting exceeds 256 levels/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("updateConfigImageOverrides preserves JSONC while recording immutable service pins", () => {
  const digest = `registry.fly.io/acme-core@sha256:${"a".repeat(64)}`;
  const updated = updateConfigImageOverrides(
    `{
  // deployment
  "contract": 1,
  "imageOverrides": {}
}
`,
    { core: digest },
  );
  assert.match(updated, /\/\/ deployment/);
  assert.equal(
    (JSON.parse(updated.replace(/^\s*\/\/.*$/gm, "")) as { imageOverrides: { core: string } }).imageOverrides.core,
    digest,
  );
});

test("updateConfigImageOverrides preserves a trailing comma on the preceding root property", () => {
  const digest = `registry.fly.io/acme-core@sha256:${"a".repeat(64)}`;
  const updated = updateConfigImageOverrides(`{\n  "contract": 1,\n}\n`, { core: digest });
  assert.equal(
    (JSON.parse(updated.replace(/,\s*}/g, "}")) as { imageOverrides: { core: string } }).imageOverrides.core,
    digest,
  );
  assert.doesNotMatch(updated, /,\s*,/);
});

test("secretEnv (per-service) validates service keys, env-var names, and managed ports", () => {
  withConfig(
    { secretEnv: { core: { OPENAI_API_KEY: "OPENAI_API_KEY", DEPLOY_APPS_SESSION_SECRET: "PORTAL_SESSION_SECRET" } } },
    ({ path }) => {
      const secretEnv = loadConfigAt(path).config.secretEnv;
      assert.equal(Object.getPrototypeOf(secretEnv!), null);
      assert.deepEqual(secretEnv?.core, {
        OPENAI_API_KEY: "OPENAI_API_KEY",
        DEPLOY_APPS_SESSION_SECRET: "PORTAL_SESSION_SECRET",
      });
    },
  );
  withConfig({ secretEnv: {} }, ({ path }) => assert.equal(loadConfigAt(path).config.secretEnv, undefined));
  withConfig({ secretEnv: { nope: { A: "A" } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /"secretEnv" has unknown service "nope"/),
  );
  withConfig({ secretEnv: { core: { "not a name": "A" } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /not a valid env var name/),
  );
  withConfig({ secretEnv: { core: { A: "not a name" } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /must name a secret-store entry/),
  );
  withConfig({ secretEnv: { core: { A: 1 } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /"secretEnv.core.A" must be a string/),
  );
  withConfig({ secretEnv: { core: { PORT: "SOME_SECRET" } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /"secretEnv.core.PORT" is managed by the deployment target/),
  );
});

test("securityScreen declares one external proxy and requires secret-store routing", () => {
  const securityScreen = {
    backend: "proxy",
    provider: "example-screen",
    endpoint: "https://screen.example.test/classify",
    rollout: "shadow",
  };
  withConfig(
    { securityScreen, secretEnv: { core: { SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN" } } },
    ({ path }) => assert.deepEqual(loadConfigAt(path).config.securityScreen, securityScreen),
  );
  withConfig({ securityScreen }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /securityScreen requires secretEnv\.core\.SECURITY_SCREEN_PROXY_TOKEN/),
  );
  withConfig({ secretEnv: { core: { SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN" } } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /SECURITY_SCREEN_PROXY_TOKEN requires securityScreen/),
  );
  for (const invalid of [
    { ...securityScreen, backend: "sdk" },
    { ...securityScreen, provider: "Bad Provider" },
    { ...securityScreen, provider: "surface" },
    { ...securityScreen, provider: "origin" },
    { ...securityScreen, endpoint: "http://screen.example.test/classify" },
    { ...securityScreen, rollout: "gradual" },
    { ...securityScreen, extra: true },
  ]) {
    withConfig(
      { securityScreen: invalid, secretEnv: { core: { SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN" } } },
      ({ path }) => assert.throws(() => loadConfigAt(path), /securityScreen/),
    );
  }
});

test("securityScreen owns its derived environment and keeps its token on core", () => {
  const securityScreen = {
    backend: "proxy",
    provider: "example-screen",
    endpoint: "https://screen.example.test/classify",
    rollout: "enforce",
  };
  withConfig(
    {
      securityScreen,
      secretEnv: { core: { SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN" } },
      env: { core: { SECURITY_SCREEN_PROXY_ENDPOINT: "https://other.example.test/classify" } },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /managed by securityScreen/),
  );
  withConfig(
    {
      securityScreen,
      secretEnv: { core: { SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN" } },
      env: { core: { SECURITY_SCREEN_PROXY_TOKEN: "plaintext-token" } },
    },
    ({ path }) =>
      assert.throws(
        () => loadConfigAt(path),
        /env\.core\.SECURITY_SCREEN_PROXY_TOKEN.*managed by securityScreen|conflicts with a plaintext/,
      ),
  );
  withConfig(
    {
      securityScreen,
      secretEnv: {
        core: {
          SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN",
          SECURITY_SCREEN_PROXY_ENDPOINT: "EXAMPLE_SCREEN_ENDPOINT",
        },
      },
    },
    ({ path }) =>
      assert.throws(
        () => loadConfigAt(path),
        /secretEnv\.core\.SECURITY_SCREEN_PROXY_ENDPOINT.*managed by securityScreen/,
      ),
  );
  withConfig(
    {
      services: ["core", "slack"],
      securityScreen,
      secretEnv: {
        core: { SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN" },
        slack: { SECURITY_SCREEN_PROXY_ROLLOUT: "EXAMPLE_SCREEN_ROLLOUT" },
      },
    },
    ({ path }) =>
      assert.throws(
        () => loadConfigAt(path),
        /secretEnv\.slack\.SECURITY_SCREEN_PROXY_ROLLOUT.*managed by securityScreen/,
      ),
  );
  withConfig(
    {
      services: ["core", "slack"],
      securityScreen,
      secretEnv: {
        core: { SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN" },
        slack: { SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN" },
      },
    },
    ({ path }) => assert.throws(() => loadConfigAt(path), /SECURITY_SCREEN_PROXY_TOKEN may be routed only to core/),
  );
});

test("aws.services logGroup and stopTimeout adopt live task-def values and validate their shapes", () => {
  const aws = {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme",
    imageLabel: "release",
    deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
    secretsPrefix: "acme/",
    networking: { cloudMapNamespace: "acme.internal" },
  };
  const services = (core: Record<string, unknown>): Record<string, unknown> => ({
    core: { ecrRepository: "qm-core", ecsService: "acme-core", cpu: 2048, memory: 4096, ...core },
  });
  withConfig(
    { target: "aws", aws: { ...aws, services: services({ logGroup: "/ecs/legacy-core", stopTimeout: 120 }) } },
    ({ path }) => {
      const core = loadConfigAt(path).config.aws!.services.core!;
      assert.equal(core.logGroup, "/ecs/legacy-core");
      assert.equal(core.stopTimeout, 120);
    },
  );
  withConfig({ target: "aws", aws: { ...aws, services: services({ logGroup: "bad name" }) } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /logGroup" must be a valid CloudWatch log group name/),
  );
  withConfig({ target: "aws", aws: { ...aws, services: services({ logGroup: "" }) } }, ({ path }) =>
    assert.throws(() => loadConfigAt(path), /must be a non-empty string/),
  );
  for (const stopTimeout of [1, 121, 30.5, "30"]) {
    withConfig({ target: "aws", aws: { ...aws, services: services({ stopTimeout }) } }, ({ path }) =>
      assert.throws(() => loadConfigAt(path), /stopTimeout" must be an integer between 2 and 120/),
    );
  }
});

test("modelProvider must name a vendor the configured harness can bill", () => {
  withConfig({ modelProvider: "openrouter", env: { core: { HARNESS: "pi" } } }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.modelProvider, "openrouter");
  });
  withConfig({ modelProvider: "openrouter", env: { core: { HARNESS: "codex" } } }, ({ path }) => {
    assert.throws(
      () => loadConfigAt(path),
      /model provider "openrouter" cannot serve a base model on env.core.HARNESS "codex"/,
    );
  });
  withConfig({ modelProvider: "anthropic", env: { core: { HARNESS: "codex" } } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /cannot serve a base model/);
  });
  withConfig({ modelProvider: "openai", env: { core: { HARNESS: "codex" } } }, ({ path }) => {
    assert.equal(loadConfigAt(path).config.modelProvider, "openai");
  });
  withConfig({ modelProvider: "openrouter" }, ({ path }) => {
    assert.equal(
      loadConfigAt(path).config.modelProvider,
      "openrouter",
      "an unset harness is mock, which bills anything",
    );
  });
});

test("env.core.MODEL_PROVIDER is validated as the provider core will actually use", () => {
  withConfig(
    { modelProvider: "openai", env: { core: { HARNESS: "codex", MODEL_PROVIDER: "anthropic" } } },
    ({ path }) => {
      assert.throws(() => loadConfigAt(path), /model provider "anthropic" cannot serve a base model/);
    },
  );
  withConfig(
    { modelProvider: "anthropic", env: { core: { HARNESS: "codex", MODEL_PROVIDER: "openai" } } },
    ({ path }) => {
      assert.equal(loadConfigAt(path).config.modelProvider, "anthropic", "the override decides, the declaration stays");
    },
  );
  withConfig({ env: { core: { HARNESS: "pi", MODEL_PROVIDER: "bedrock" } } }, ({ path }) => {
    assert.throws(() => loadConfigAt(path), /env.core.MODEL_PROVIDER must be one of/);
  });
  withConfig(
    {
      services: ["core", "slack"],
      modelProvider: "openrouter",
      env: { slack: { HARNESS: "codex", MODEL_PROVIDER: "anthropic" }, core: { MODEL_PROVIDER: "openai" } },
    },
    ({ path }) => {
      const config = loadConfigAt(path).config;
      assert.deepEqual(effectiveCoreEnvironment(config), { HARNESS: "codex", MODEL_PROVIDER: "openai" });
      assert.equal(effectiveModelProvider(config), "openai");
    },
  );
  withConfig(
    { services: ["core", "slack"], env: { slack: { HARNESS: "pi", MODEL_PROVIDER: " openai " } } },
    ({ path }) => assert.throws(() => loadConfigAt(path), /env.slack.MODEL_PROVIDER.*surrounding whitespace/),
  );
});

test("Slack HTTP events require an effective integer port", () => {
  for (const port of [undefined, "", "0", "-1", "1.5", "65536", "not-a-number"]) {
    withConfig(
      {
        services: ["core", "slack"],
        env: { slack: { SLACK_EVENTS_MODE: "http", ...(port === undefined ? {} : { SLACK_EVENTS_PORT: port }) } },
      },
      ({ path }) => assert.throws(() => loadConfigAt(path), /SLACK_EVENTS_PORT to be an integer from 1 to 65535/),
    );
  }
  withConfig(
    { services: ["core", "slack"], env: { slack: { SLACK_EVENTS_MODE: "http", SLACK_EVENTS_PORT: "3001" } } },
    ({ path }) => assert.equal(effectiveCoreEnvironment(loadConfigAt(path).config).SLACK_EVENTS_PORT, "3001"),
  );
  withConfig(
    {
      services: ["core", "slack"],
      env: {
        slack: { SLACK_EVENTS_MODE: "http", SLACK_EVENTS_PORT: "not-a-number" },
        core: { SLACK_EVENTS_MODE: "socket" },
      },
    },
    ({ path }) => assert.equal(effectiveCoreEnvironment(loadConfigAt(path).config).SLACK_EVENTS_MODE, "socket"),
  );
});

test("a mock deployment is named as one, and a real harness draws no warning", () => {
  withConfig({ env: { core: {} } }, ({ path }) => {
    assert.match(mockHarnessWarning(loadConfigAt(path).config)!, /unset, which means "mock".*calls no model provider/s);
  });
  withConfig({ env: { core: { HARNESS: "mock" } } }, ({ path }) => {
    assert.match(mockHarnessWarning(loadConfigAt(path).config)!, /set to "mock"/);
  });
  withConfig({ services: ["core", "slack"], env: { slack: { HARNESS: "mock" } } }, ({ path }) => {
    assert.match(mockHarnessWarning(loadConfigAt(path).config)!, /set to "mock"/);
  });
  withConfig({ env: { core: { HARNESS: "pi" } } }, ({ path }) => {
    assert.equal(mockHarnessWarning(loadConfigAt(path).config), undefined);
  });
  withConfig(
    {
      target: "fly",
      appPrefix: "acme",
      env: { core: {} },
      sandbox: { backend: "sprites", namePrefix: "acme-sandboxes" },
    },
    ({ path }) => {
      assert.equal(mockHarnessWarning(loadConfigAt(path).config), undefined, "the fly template renders HARNESS=pi");
    },
  );
});
