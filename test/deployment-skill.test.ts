import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

function read(path: string): string {
  return readFileSync(path, "utf8");
}

test("package-consumer deployment skill covers both self-owned providers and the completion contract", () => {
  const root = read("cli/templates/deployment/deployment.md");
  for (const phrase of [
    "Before cloud mutation",
    "Fly.io or AWS",
    "deployment repository",
    "npm ci",
    "slack render",
    "work-email OIDC provider",
    "check --live",
    "private live session canary",
    "fresh UUID",
    "generated sidebar title",
    "Web chat",
    "idempotent",
    "test-channel links",
    "adminConnectorsUrl",
    "adminOnboardingUrl",
    "userConnectionsUrl",
    "configured connectors",
  ]) {
    assert.ok(root.includes(phrase), `package deployment.md includes ${phrase}`);
  }
  assert.match(read("deployment.md"), /cli\/templates\/deployment\/deployment\.md/);
  for (const path of [
    ".codex/skills/deploy-qm/SKILL.md",
    ".codex/skills/deploy-qm/agents/openai.yaml",
    ".codex/skills/deploy-qm/references/fly.md",
    ".codex/skills/deploy-qm/references/aws.md",
    ".codex/skills/deploy-qm/references/slack.md",
    ".codex/skills/deploy-qm/references/email.md",
  ]) {
    assert.ok(existsSync(path), `${path} exists`);
  }
  assert.match(read(".codex/skills/deploy-qm/SKILL.md"), /\.\.\/\.\.\/\.\.\/deployment\.md/);
  for (const path of [
    "cli/templates/deployment/references/fly.md",
    "cli/templates/deployment/references/aws.md",
    "cli/templates/deployment/references/slack.md",
    "cli/templates/deployment/references/email.md",
  ]) {
    assert.doesNotMatch(read(path), /QM_REPO|cli\/bin\/qm\.ts|fresh QM clone/);
  }
});

test("update documentation keeps npm outside the trusted launcher boundary", () => {
  const direct = "node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version <version>";
  const bootstrap = 'node "$bootstrap/qm/cli/bin/qm.ts" update --yes --version "$version"';
  for (const path of [
    "SECURITY.md",
    "cli/README.md",
    "docs/deploy-directory.md",
    "cli/templates/deployment/SKILL.md",
    "cli/templates/deployment/deployment.md",
  ]) {
    const content = read(path);
    const prose = content.replace(/\s+/g, " ");
    assert.ok(content.includes(direct), `${path} gives the direct installed update command`);
    assert.ok(content.includes(bootstrap), `${path} gives the direct pinned-source bootstrap command`);
    assert.match(prose, /Published QM 0\.1\.7 and earlier do not contain `qm update`/);
    assert.match(prose, /one-time bootstrap to the first hardened updater/);
    assert.match(prose, /exact current stable version directly from the official npm registry over HTTPS/);
    assert.match(prose, /mutable registry value selects a tag but does not authenticate source/);
    assert.match(prose, /matching protected immutable annotated tag/);
    assert.match(prose, /not registry or release prose, is the source trust anchor/);
    assert.match(prose, /Independently inspect the recorded official Actions run when verifying release provenance/);
    assert.match(prose, /fresh clone in a mode-0700 temporary directory outside the deployment/);
    assert.match(prose, /Use only the verified immutable annotated tag, never editable release prose/);
    assert.match(prose, /do not install or execute the new package through the deployment's npm project/);
    assert.match(content, /node --input-type=module <<'NODE'/);
    assert.match(content, /https:\/\/registry\.npmjs\.org\/@yc-software%2fqm\/latest/);
    assert.match(content, /response\.statusCode !== 200/);
    assert.match(content, /body\.length > 1_000_000/);
    assert.match(content, /Object\.hasOwn\(metadata, "deprecated"\)/);
    assert.match(content, /^set -euo pipefail$/m);
    assert.match(content, /^repository=yc-software\/qm$/m);
    assert.match(content, /^repository_id=1316527318$/m);
    assert.match(content, /refs\/tags\/\$tag:refs\/tags\/\$tag/);
    assert.match(content, /cat-file -t "\$tag_ref"/);
    assert.match(content, /cat-file -p "\$tag_ref"/);
    assert.match(content, /rev-parse "\$tag_ref\^\{commit\}"/);
    assert.match(content, /Repository: \$repository \(\$repository_id\)/);
    assert.match(content, /Commit: \$release_commit/);
    assert.match(content, /Version: \$version/);
    assert.match(content, /Images: sha256:\[0-9a-f\]\{64\}/);
    assert.match(content, /test -z .*sed -n '9p'/);
    assert.doesNotMatch(content, /<release-commit>/);
    assert.match(
      prose,
      /installed `@yc-software\/qm` package and its `dist\/bin\/qm\.js` entry point are part of the trusted launcher boundary and must be unchanged/,
      `${path} trusts the currently installed updater entry point`,
    );
    assert.match(prose, /trusted, clean operator shell/, `${path} requires a trusted clean operator shell`);
    assert.match(prose, /`PATH` resolves `node` to a trusted Node executable/, `${path} trusts the Node executable`);
    assert.match(prose, /`qm update --yes` is supported on macOS and Linux, not Windows/);
    assert.match(
      prose,
      /The automatic path requires an existing exact registry pin and refuses a local package link; normalize a source checkout through its ordinary trusted package-manager workflow first/,
      `${path} rejects local-link mutation before npm`,
    );
    assert.match(
      prose,
      /On macOS, the deployment tree and external local-input and environment paths must be free of extended ACLs\. Their mutation-controlling ancestors may have deny-only ACLs, but no permission-granting ACL entries/,
      `${path} states the macOS ACL boundary`,
    );
    assert.match(
      prose,
      /On Linux, trusted `getfacl`, `getfattr`, and `lsattr` commands must be available on the launcher `PATH`; protected paths must be free of extended access and default ACLs/,
      `${path} states the Linux ACL boundary`,
    );
    assert.match(
      prose,
      /Never launch an update through `npm exec`, `npx`, a package script, or another npm-mediated launcher/,
      `${path} prohibits npm-mediated update launchers`,
    );
    for (const paragraph of content.split(/\n\s*\n/).map((value) => value.replace(/\\\s*\n|\s+/g, " "))) {
      assert.doesNotMatch(
        paragraph,
        /\b(?:npm\s+(?:exec|x)|npx)\b.*\bqm(?:\s+--)?\s+update\b/i,
        `${path} contains no npm-exec, npm-x, or npx update command`,
      );
      assert.doesNotMatch(
        paragraph,
        /\bnpm\s+(?:run|run-script)\b.*\bupdate\b/i,
        `${path} contains no package-script update command`,
      );
    }
    assert.match(prose, /project(?:'s)? `.npmrc` and package settings before QM starts/);
    assert.match(
      prose,
      /`NODE_OPTIONS`, `NODE_PATH`, and platform dynamic-loader variables such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, and `DYLD_LIBRARY_PATH` must be absent or independently trusted/,
      `${path} requires ambient preloads and loaders to be absent or trusted`,
    );
    assert.match(prose, /npm exec --yes=false -- qm <command>/, `${path} preserves routine npm exec commands`);
    assert.match(
      prose,
      /intentionally trusts the operator's external home, ambient provider variables, agent and keyring sockets, provider configuration and credentials, credential helpers, CLI plugins and aliases, proxy and CA settings, and external provider executables/,
      `${path} states the provider reconciliation trust boundary`,
    );
    assert.match(
      prose,
      /Provider reconciliation is state-changing and may modify provider resources, just as ordinary `up` can/,
    );
    assert.match(
      prose,
      /Provider executables, transitive helpers, and plugins receive the operator's filtered ambient environment and external `PATH`; their interpreter and runtime loaders, caches, output paths, and delegated executables are not exhaustively isolated/,
      `${path} states the transitive provider trust boundary`,
    );
    assert.match(
      prose,
      /The external objects and every alias to them must not be writable through the deployment/,
      `${path} states the external inode and alias trust boundary`,
    );
    assert.match(
      prose,
      /The updater never converts ambient operator-shell values into deployment workload secrets\. Local values must already be in the explicit deployment environment file; existing remote provider secret stores remain authoritative/,
      `${path} keeps ambient provider credentials out of deployment workloads`,
    );
    assert.match(
      prose,
      /After any forced kill, confirm that no descendant npm, Node\/QM, Docker, Fly, AWS, or other provider process remains before repairing the package or running a recovery command/,
      `${path} requires orphan checks before recovery`,
    );
    assert.match(prose, /`npm exec --yes=false -- qm up`/, `${path} gives Docker/Fly recovery`);
    assert.match(prose, /npm exec --yes=false -- qm up --yes/, `${path} gives the AWS recovery command`);
  }
});

test("deployment bootstrap and AWS profile selection fail closed", () => {
  const deployment = read("cli/templates/deployment/deployment.md");
  assert.match(deployment, /if test -f package-lock\.json; then\s+npm ci\s+else\s+npm install\s+fi/);
  assert.doesNotMatch(deployment, /npm ci\s*\|\|\s*npm install/);
  const aws = read("cli/templates/deployment/references/aws.md");
  assert.match(aws, /export AWS_PROFILE=<profile>/);
  assert.doesNotMatch(aws, /aws --profile <profile>/);
});

test("the deploy skill tells an agent where the sign-in email transport comes from", () => {
  const email = read("cli/templates/deployment/references/email.md");
  for (const phrase of [
    "AUTH_EMAIL_TRANSPORT",
    "resend.com/api-keys",
    "DNS",
    "SMTP_PORT",
    "SMTP_TLS",
    "AUTH_ALLOWED_EMAILS",
  ]) {
    assert.ok(email.includes(phrase), `email reference covers ${phrase}`);
  }
  assert.match(email, /operator — needs DNS control/, "the one step an agent cannot do itself is called out");
  assert.match(read("cli/templates/deployment/deployment.md"), /references\/email\.md/);
  for (const skill of [".codex/skills/deploy-qm/SKILL.md", "cli/templates/deployment/SKILL.md"]) {
    assert.match(read(skill), /references\/email\.md/, `${skill} routes the agent to the email reference`);
  }
  assert.match(
    read(".codex/skills/deploy-qm/references/email.md"),
    /cli\/templates\/deployment\/references\/email\.md/,
  );
});

test("the package deployment skill excludes the unsupported Porter hosting path", () => {
  assert.doesNotMatch(read("cli/templates/deployment/deployment.md"), /references\/porter\.md|Fly\.io, AWS, or Porter/);
  assert.ok(!existsSync("cli/templates/deployment/references/porter.md"));
  assert.ok(!existsSync(".codex/skills/deploy-qm/references/porter.md"));
  assert.match(read("docs/porter.md"), /not a target of the packaged `qm init` deployment workflow/);
});

test("connector onboarding is governed by the live admin-configured list", () => {
  const onboarding = read("plugins/onboarding/skills/onboarding/SKILL.md");
  const connectApps = read("skills-seed/connect-apps/SKILL.md");
  for (const skill of [onboarding, connectApps]) {
    assert.match(skill, /configured by (?:the |your )?admin/i);
    assert.doesNotMatch(skill, /Slack and Google first|Slack, Google, Notion, Linear, and GitHub/);
  }
  assert.match(onboarding, /complete allowlist|same allowlist/);
  assert.doesNotMatch(onboarding, /machine-local credentials such as|`gh`, `glab`, or AWS/);
});

test("the source repository has no account-bound production deployment workflow", () => {
  const files = execFileSync("git", ["ls-files"], { encoding: "utf8" }).trim().split("\n").filter(existsSync);
  const retiredStack = ["qm", "deploy"].join("-");
  assert.ok(!files.some((file) => file.startsWith(`${retiredStack}/`)));
  const isPrivateMirror = files.some((file) => file.startsWith("deploy/layers/") && file !== "deploy/layers/README.md");
  if (!isPrivateMirror) {
    assert.ok(!files.includes(".github/workflows/deploy.yml"));
    assert.doesNotMatch(
      read(".github/workflows/cicd.yml"),
      /aws-actions\/configure-aws-credentials|flyctl deploy|qm up/,
    );
  }

  assert.ok(!files.some((file) => file.startsWith("cli/templates/workflows/")));
});

test("Slack distribution stays private and deployment-owned", () => {
  const slack = read("cli/templates/deployment/references/slack.md");
  assert.match(slack, /one private Socket Mode app per deployment and workspace/);
  assert.match(slack, /exact bot manifest creation URL/);
  assert.match(slack, /Admin Slack card/);
});

test("each provider has an independent agent-computer proof", () => {
  const root = read("cli/templates/deployment/deployment.md");
  const fly = read("cli/templates/deployment/references/fly.md");
  const aws = read("cli/templates/deployment/references/aws.md");

  assert.match(root, /`qm-computer-proof\.txt` in its current workspace/);
  assert.match(fly, /## Agent-computer proof/);
  assert.match(fly, /exact signed-in principal/);
  assert.match(fly, /\/home\/sprite\/workspace\/qm-computer-proof\.txt/);
  assert.doesNotMatch(fly, /agent_scope|fly machine exec/);
  assert.match(aws, /## Agent-computer proof/);
  assert.match(aws, /deployment-owned S3 home\s+snapshot/);
  assert.match(aws, /workspace\/qm-computer-proof\.txt/);
});
