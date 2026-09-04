# Deploy QM

This repository defines one QM deployment. The `@yc-software/qm` dependency supplies
the deployment engine; this repository owns the organization-specific config,
sandbox layer, provider coordinates, and generated Slack manifests.

The automated release gate is `qm check --live`, including its private live
session canary. The task is complete only after that gate passes, the
administrator can sign in and receive a real web response, and, when Slack is
requested, the bot replies in a test channel.

## 1. Collect choices and authorization

Before cloud mutation, read `qm.config.jsonc` when it exists. Its `target` is
the selected provider; confirm it with the operator and do not offer to change
it in place. If the repository has not been initialized, collect:

- hosting target: Fly.io or AWS. Recommend Fly.io when the operator has no
  preference. The docker target runs everything on the local machine, is for a
  quick local test drive only, and is outside this workflow; never present it
  as the recommended path for a real deployment;
- the first administrator's verified work email;
- how people sign in: the built-in `auth` broker, which emails a one-time link,
  or an external OIDC provider. Ask whether the company runs on Slack before
  assuming the broker — Slack sign-in needs no email transport, no sending
  domain, and no DNS, and domain verification is the step most likely to stall
  a deploy. Recommend Slack sign-in to a Slack workspace and the broker
  otherwise;
- model provider: Anthropic, OpenAI, or OpenRouter (one key that routes to
  many models). This is a deployment choice, not a post-deploy one: it becomes
  `modelProvider` in `qm.config.jsonc`, which makes that provider's API key a
  required secret. Collect the key in the same pass as the other credentials —
  a deployment that cannot answer one message is not finished. An operator who
  genuinely wants to defer omits `modelProvider` and adds the key from the
  Admin page later, but do not offer that as the default;
- model;
- region and provider account or organization;
- whether the provider hostname is acceptable;
- connectors to enable, including whether to add Slack now.

The deployment slug is a local name for this deployment — it appears in the
package name, resource names, and Slack branding. Derive it from the
organization's name (a lowercase DNS label) and confirm it in passing; do not
make the operator decide it as a standalone question. On Fly.io the slug is
the default `appPrefix`, and app names like `<prefix>-core` must be free on
fly.dev; on a collision set a distinctive `appPrefix` rather than renaming
the organization.

Explain the selected provider's billable resources and confirm the provider
identity, region, resource list, and expected billing.

Changing providers means initializing a new empty deployment directory. Never
rewrite only `target`; provider config, files, secret rules, and teardown
contracts are scaffolded as one unit.

## 2. Prepare the deployment repository

Require Node 24+, npm, and Git. Provider-specific prerequisites are in the
selected reference. Fly builds remotely and does not require local Docker or
Buildx. Init and setup generate secrets through Node and do not require
OpenSSL. The update command specifically requires native npm `>=11.12.0 and
<12`.

For a repository without `qm.config.jsonc`, first confirm the hosting target
and the derived slug, then initialize its root with the current CLI:

```bash
npm exec --yes --package=@yc-software/qm@latest -- \
  qm init . --org <slug> --target <fly-or-aws> --model-provider <provider>
npm install
```

`qm init` writes the version it resolved to as an exact dependency, so the pin
lands in the deployment repository and its lockfile rather than in the command
that bootstraps it.

`--model-provider` takes `anthropic`, `openai`, or `openrouter` and defaults to
`anthropic`. It writes `modelProvider` into the scaffolded config, which is what
promotes that provider's key from an optional fallback to a required secret.

For an already-initialized clone, install reproducibly. Use `npm ci` when
`package-lock.json` exists; otherwise use `npm install` to create it:

```bash
if test -f package-lock.json; then
  npm ci
else
  npm install
fi
npm exec --yes=false -- qm version
```

After Admin reports a new stable release, copy its exact version into the
update command. The command accepts only the version currently promoted on npm's
`latest` tag. It installs that package in isolation from the official registry with
lifecycle scripts disabled, verifies its npm signatures, SLSA provenance, source
commit, and embedded image manifest, then lets the trusted native npm install the
exact dependency offline from the verified private cache. The updater enforces native
npm `>=11.12.0 and <12`. npm owns the package, lock, and installed-tree changes; there
is no updater journal, transplant, or rollback. The automatic path requires an
existing exact registry pin and refuses a local package link; normalize a source
checkout through its ordinary trusted package-manager workflow first. On macOS, the
deployment tree and external local-input and environment paths must be free of
extended ACLs. Their mutation-controlling ancestors may have deny-only ACLs, but no
permission-granting ACL entries. On Linux, trusted `getfacl`, `getfattr`, and `lsattr`
commands must be available on the launcher `PATH`; protected paths must be free of
extended access and default ACLs, extended attributes, and immutable file flags:

```bash
node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version <version>
```

The installed `@yc-software/qm` package and its `dist/bin/qm.js` entry point are part
of the trusted launcher boundary and must be unchanged before the updater starts.
Run that entry point directly only from a trusted, clean operator shell whose `PATH`
resolves `node` to a trusted Node executable. Never launch an update through
`npm exec`, `npx`, a package script, or another npm-mediated launcher. npm processes
this project's `.npmrc` and package settings before QM starts, outside the updater's
isolated npm environment. Ambient preloads and loaders also execute before QM;
`NODE_OPTIONS`, `NODE_PATH`, and platform dynamic-loader variables such as
`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, and `DYLD_LIBRARY_PATH` must
be absent or independently trusted. They are part of the trusted launcher boundary.
Keep using `npm exec --yes=false -- qm <command>` for routine non-update commands.

`qm update --yes` is supported on macOS and Linux, not Windows.

### One-time bootstrap from QM 0.1.7 and earlier

Published QM 0.1.7 and earlier do not contain `qm update`. For the one-time
bootstrap to the first hardened updater, do not install or execute the new package
through the deployment's npm project. The trusted Node code below obtains the exact
current stable version directly from the official npm registry over HTTPS and rejects
anything except stable semver. That mutable registry value selects a tag but does not
authenticate source. The matching protected immutable annotated tag, not registry or
release prose, is the source trust anchor. The commands require that tag to point
directly to a commit whose message has the exact official repository identity, version,
peeled commit, bootstrap link, and fixed warning. Independently inspect the recorded
official Actions run when verifying release provenance. From a trusted, clean operator
shell, create a fresh clone in a mode-0700 temporary directory outside the deployment,
then invoke the verified source entry with trusted Node 24 or newer from the deployment
directory:

```bash
set -euo pipefail
bootstrap=$(mktemp -d)
chmod 700 "$bootstrap"
version=$(
  node --input-type=module <<'NODE'
import { get } from "node:https";

const response = await new Promise((resolve, reject) => {
  const request = get(
    "https://registry.npmjs.org/@yc-software%2fqm/latest",
    { headers: { accept: "application/json" } },
    resolve,
  );
  request.on("error", reject);
});
if (response.statusCode !== 200) throw new Error(`npm registry returned HTTP ${response.statusCode}`);
response.setEncoding("utf8");
let body = "";
for await (const chunk of response) {
  body += chunk;
  if (body.length > 1_000_000) throw new Error("npm registry response is too large");
}
const metadata = JSON.parse(body);
const stable = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
if (typeof metadata.version !== "string" || !stable.test(metadata.version)) {
  throw new Error("npm latest is not stable semver");
}
if (Object.hasOwn(metadata, "deprecated")) throw new Error("npm latest is deprecated");
process.stdout.write(metadata.version);
NODE
)
tag="v$version"
repository=yc-software/qm
repository_id=1316527318
git clone --filter=blob:none --no-checkout --no-tags "https://github.com/$repository.git" "$bootstrap/qm"
git -C "$bootstrap/qm" fetch --depth=1 --no-tags origin "refs/tags/$tag:refs/tags/$tag"
tag_ref="refs/tags/$tag"
test "$(git -C "$bootstrap/qm" cat-file -t "$tag_ref")" = tag
tag_object=$(git -C "$bootstrap/qm" cat-file -p "$tag_ref")
release_commit=$(git -C "$bootstrap/qm" rev-parse "$tag_ref^{commit}")
test "$(printf '%s\n' "$tag_object" | sed -n '1p')" = "object $release_commit"
test "$(printf '%s\n' "$tag_object" | sed -n '2p')" = "type commit"
test "$(printf '%s\n' "$tag_object" | sed -n '3p')" = "tag $tag"
tag_message=$(git -C "$bootstrap/qm" for-each-ref --format='%(contents)' "$tag_ref")
test "$(printf '%s\n' "$tag_message" | sed -n '1p')" = "QM release provenance"
test "$(printf '%s\n' "$tag_message" | sed -n '2p')" = "Repository: $repository ($repository_id)"
printf '%s\n' "$tag_message" | sed -n '3p' | grep -Eq '^Run: https://github\.com/yc-software/qm/actions/runs/[1-9][0-9]*$'
test "$(printf '%s\n' "$tag_message" | sed -n '4p')" = "Commit: $release_commit"
test "$(printf '%s\n' "$tag_message" | sed -n '5p')" = "Version: $version"
printf '%s\n' "$tag_message" | sed -n '6p' | grep -Eq '^Images: sha256:[0-9a-f]{64}$'
test "$(printf '%s\n' "$tag_message" | sed -n '7p')" = "Bootstrap for QM 0.1.7 and earlier: https://github.com/$repository/blob/$release_commit/SECURITY.md#one-time-bootstrap-from-qm-017-and-earlier"
test "$(printf '%s\n' "$tag_message" | sed -n '8p')" = "Bootstrap only from this immutable annotated tag after verifying its repository, commit, and version marker; release notes and mutable main are not trust sources. Never use deployment npm, npm exec, npx, or package scripts."
test -z "$(printf '%s\n' "$tag_message" | sed -n '9p')"
git -C "$bootstrap/qm" checkout --detach "$release_commit"
test "$(git -C "$bootstrap/qm" rev-parse HEAD)" = "$release_commit"
cd /absolute/path/to/deployment
node "$bootstrap/qm/cli/bin/qm.ts" update --yes --version "$version"
```

Use only the verified immutable annotated tag, never editable release prose, mutable
`main`, `curl | node`, `npm install`, `npm exec`, `npx`, or a package script for this
bootstrap. The pinned source launcher performs the hardened package signature, SLSA
provenance, source-commit, and manifest verification before npm can change the
deployment. After the first hardened version is installed, use the direct installed
entry above for later updates.

Only npm verification and mutation are isolated. Provider reconciliation runs the
verified CLI from a temporary working directory with absolute deployment inputs, but
intentionally trusts the operator's external home, ambient provider variables, agent
and keyring sockets, provider configuration and credentials, credential helpers, CLI
plugins and aliases, proxy and CA settings, and external provider executables.
Provider executables, transitive helpers, and plugins receive the operator's filtered
ambient environment and external `PATH`; their interpreter and runtime loaders,
caches, output paths, and delegated executables are not exhaustively isolated.
Provider reconciliation is state-changing and may modify provider resources, just as
ordinary `up` can. Every path those trusted inputs delegate to is trusted too; they must not reference
deployment-controlled code. The external objects and every alias to them must not be
writable through the deployment. Direct `PATH` entries that resolve inside the
deployment are excluded; explicit provider-configuration paths that do so are
rejected.

The updater never converts ambient operator-shell values into deployment workload
secrets. Local values must already be in the explicit deployment environment file;
existing remote provider secret stores remain authoritative.

Treat the update as same-owner exclusive maintenance for this deployment directory.
Finish every other QM CLI command and package-manager write before starting it, and
start neither until it exits. Admin only reports the promoted release; it never runs
this command. After any forced kill, confirm that no descendant npm, Node/QM, Docker,
Fly, AWS, or other provider process remains before repairing the package or running a
recovery command. If npm is interrupted, inspect the checkout, restore `package.json`
and `package-lock.json` through version control as needed, and run trusted
`npm ci --ignore-scripts` before retrying.

The verified target CLI runs its ordinary `up` path. Docker rebuilds its generated
local sandbox wrapper when its packaged base or agent wrapper changed. Every AWS
target rebuilds its deployment-publisher Lambda MicroVM image when its deterministic
source hash, recorded version, or remote active version is stale or missing; an AWS
Lambda MicroVM agent backend reuses that pin. Sprites on Fly, Docker, or AWS use the
Sprites API directly and do no OCI sandbox-image work. A remote failure leaves the
verified package pin in place. On Docker or Fly, reconcile it with
`npm exec --yes=false -- qm up`; on AWS, use
`npm exec --yes=false -- qm up --yes`. Then review and commit the durable tracked
changes. Retry the exact update command only while its version remains npm `latest`.

For a new Sprites deployment, `sandbox.namePrefix` is the only explicit durable
namespace selector. Without it, the runtime keeps the historical `qm` prefix. Legacy
`sandbox.app` may remain alongside a migrated `sandbox.namePrefix`, but it stays inert
and neither selects nor overrides the prefix. `sandbox.image` and `sandbox.baseImage`
are also compatibility data for this path and never select an OCI image. Migrate a legacy explicit
`env.core.SPRITES_NAME_PREFIX` value byte-for-byte to `sandbox.namePrefix`; replacing
it with a scaffold default would silently abandon the old namespace. Any prefix change
is a planned data migration. Existing Sprites remain under the old namespace and must
not be deleted as cleanup.

Do not remove legacy `sandbox.env` or `sandbox.secretEnv` just to make validation pass.
Direct Sprites has no resident environment injection. Move every value and credential
to the supported tool, skill, connector, or keychain delivery path used by its
consumer and verify it can use the replacement. Remove the legacy fields and roll the
deployment, then verify the live consumer. On Fly, confirm the affected app rollout no
longer references the old injection, then delete each `FLY_RESIDENT_ENV_<name>` app
secret. On AWS, confirm the new task definition no longer references the old
injection, then delete each original `${aws.secretsPrefix}<name>` entry from Secrets
Manager. On Docker, complete the replacement container rollout, then remove each
original `<name>` from the deployment's `.env` or other environment source. The CLI
does not perform that provider cleanup or accept field presence as acknowledgement
that this migration succeeded. This work is separate from revoking and deleting the
retired source credential `FLY_SANDBOX_API_TOKEN` and unsetting its deployed core
`FLY_API_TOKEN` alias.

Automatic updates stop before changing files when any workload `imageOverrides` are
set. They also stop for Fly `imageFrom` or an explicit Docker-local `sandbox.image`.
Roll workload overrides, `imageFrom`, and the local Docker image forward through their
normal image process. Automatic updates also stop for `sandbox/Dockerfile` whenever
the effective backend is Sprites on Fly, Docker, or AWS. Sprites no longer consume OCI
sandbox images, so review and archive or remove that retired file before updating;
never silently delete its custom content. Docker's local sandbox build is separate.
Every AWS target still requires its packaged deployment-publisher MicroVM image, and
the AWS agent-computer backend reuses the same pin. `sandbox publish` is retired and
hard-rejected.

If this repository has retired default or renamed Admin-dispatched GitHub update
workflows or any `QM_UPDATE_GITHUB_*` Admin config, first cancel every queued or
running job for every configured or detected legacy workflow and wait for each job to
reach a terminal status. Only then remove every workflow copy and all settings and
delete the GitHub repository secret `QM_DEPLOY_ENV`, revoke the old GitHub token and
remove every resident `QM_UPDATE_GITHUB_TOKEN` copy, then revoke and delete the
retired source credential `FLY_SANDBOX_API_TOKEN` from every repository, host, and CI
secret store before updating. Removing or disabling a workflow or redeploying Admin
does not cancel queued jobs. Fly reconciliation stages removal of its deployed core
`FLY_API_TOKEN` alias, but that is not a substitute for revoking and deleting the
source credential.

After the live acceptance checks pass, review `git diff` and commit
`package.json`, `package-lock.json`, `qm.config.jsonc`, and every other tracked
deployment-state change produced by the update. Do not leave the new running
release recorded only in one checkout.

Confirm `.env` is private and ignored before adding credentials:

```bash
test "$(stat -f '%Lp' .env 2>/dev/null || stat -c '%a' .env)" = 600
git check-ignore --quiet .env
```

Never print, paste into chat, or commit `.env`. Never initialize over an
existing deployment config.

## 3. Configure the administrator, sign-in, and the base model

Set the exact lowercased administrator email in `.env` as
`ADMIN_GRANTS=<email>:org_admin`.

Follow the sign-in route chosen in step 1. Only the `auth` broker needs an email
transport; skip to "Slack sign-in" below when the operator picked Slack, and
skip `references/email.md` entirely with it.

### The built-in broker

The `auth` broker emails a one-time link. There is no identity provider to
register: the CLI generates the broker's signing key and the portal's client
credentials and derives every `OIDC_*` value from `publicUrl`. Setting any of
them by hand is refused.

What the operator supplies is a way to send those emails. Do not ask them to
pick a transport by name; ask what they already use for email. An existing
mail account or relay (Google Workspace, Postmark, SES, Fastmail) means SMTP —
recommend it, since it needs no DNS work — and only an operator who prefers
Resend and controls DNS for a sending domain should pick `resend`. Set
`env.auth.AUTH_EMAIL_TRANSPORT` accordingly, optionally set
`env.auth.AUTH_ALLOWED_EMAIL_DOMAIN` to admit a whole domain, then read
`.codex/skills/deploy-qm/references/email.md` before collecting secrets — the
Resend path needs DNS control you will not have, so raise it with the operator
early. Configure services, model, and the final public origin in the same pass.

### Slack sign-in

A workspace that already runs on Slack can sign in with it and skip email
altogether. Drop `"auth"` from `services` and follow
`.codex/skills/deploy-qm/references/slack.md`, which covers the SSO app, the
`env.portal` endpoints, the workspace trust boundary, and the client
credentials. The bot app in that same reference is a separate decision — Slack
sign-in does not require the agent in the workspace, and the agent does not
require Slack sign-in.

### Another OIDC provider

To use a different work-email OIDC provider, drop `"auth"` from
`services`, register `<publicUrl>/auth/callback` with the provider, and put its
endpoints and the email gate in `env.portal`. For Google Workspace:

```json
{
  "OIDC_AUTH_ENDPOINT": "https://accounts.google.com/o/oauth2/v2/auth",
  "OIDC_TOKEN_ENDPOINT": "https://oauth2.googleapis.com/token",
  "OIDC_USERINFO_ENDPOINT": "https://openidconnect.googleapis.com/v1/userinfo",
  "OIDC_ISSUER": "https://accounts.google.com",
  "OIDC_JWKS_URI": "https://www.googleapis.com/oauth2/v3/certs",
  "OIDC_SCOPES": "openid email profile",
  "OIDC_PRINCIPAL_CLAIM": "email",
  "OIDC_ALLOWED_EMAILS": "<verified-work-email>"
}
```

### Playground mode

A playground is a public try-it deployment: unauthenticated visitors get
anonymous browser-pinned identities instead of a sign-in page, while the one
administrator still signs in through whichever route above the deployment
configured. Enable it in `qm.config.jsonc`:

```json
"env": { "portal": { "PORTAL_PLAYGROUND": "1" } }
```

A playground must be its **own deployment**, never a flag on a working org's
instance: every visitor is an ordinary internal principal of the deployment's
org, so anything granted or published at org scope — including org-granted
credentials — is theirs. Grant nothing sensitive at org scope, connect no real
connector credentials, and load no company data. A cleared cookie is a fresh
identity, so set `env.core.ORG_BUDGET_USD_PER_WINDOW` — the one hard spend
ceiling — in the same pass, and from the Admin page after first boot restrict
the model picker to the subset you want to offer (one model or several).
Nothing garbage-collects an abandoned visitor's scope yet.
`plugins/portal/README.md` § "Playground mode" covers the rest: per-address
mint limits, the boot refusals, and what anonymous visitors are denied.

### The base model

Whichever sign-in route the deployment takes, the base model needs a key in the
same pass. `modelProvider` decides which one `qm setup` asks for —
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `OPENROUTER_API_KEY` — and the wizard
prints where to mint it. The operator owns the billing relationship, so they
create the key; you only place it. It is a required secret, so `qm doctor` calls
the provider to prove the key is accepted and `qm up` refuses a deployment that
has none. Treat a rejected key exactly like a rejected sign-in credential: stop
and get a working one rather than deploying a stack that greets the
administrator and then fails their first message.

`modelProvider` also picks the model itself, so no model id has to be chosen at
deploy time: Anthropic serves `claude-opus-5`, OpenAI `gpt-5.6-sol`, OpenRouter
`openrouter/auto`. Set `model` in `qm.config.jsonc` only to override that, and
only with a model the chosen provider can bill — a mismatch is refused at
startup rather than at the first message. The same rule covers the harness:
`HARNESS` `codex` runs OpenAI models alone, `claude` runs Anthropic models
alone, and `openrouter` needs the default `pi` harness.

An operator may still prefer to hold the key centrally and rotate it from the
Admin page. That is a deliberate choice, not the default: drop `modelProvider`
from `qm.config.jsonc`, note in the handoff that the deployment has no base model
yet, and finish by walking them through Model provider on the Admin page. Never
leave a deployment modelless without saying so.

Read exactly one provider reference now and follow its provider-specific
preflight and setup order:

- Fly.io: `.codex/skills/deploy-qm/references/fly.md`
- AWS: `.codex/skills/deploy-qm/references/aws.md`

## 4. Deploy and prove the web surface

Follow the selected provider reference, then run:

```bash
npm exec --yes=false -- qm check --live
npm exec --yes=false -- qm conformance
npm exec --yes=false -- qm outputs --json
```

`check --live` verifies provider infrastructure, private storage, public
health, and a private end-to-end web session. The session canary runs one real
agent turn plus auxiliary title generation, verifies the exact reply and
persisted transcript, requires a generated title, checks the session-scoped
error log, and archives itself. It does not recall or capture administrator
memory. Fly runs it inside the core machine; AWS runs it as a one-off task on
the core service's private network. It does not add a public session endpoint.

Open `adminOnboardingUrl` from the JSON output and confirm Model provider
reports the chosen vendor as configured, sourced from the environment. It does
when `modelProvider` is set: the key travelled with the rest of the deployment
secrets, so there is nothing to paste here. Enter and validate a key on that
page only when the operator chose to defer, or when they are replacing the
deployment key with one they would rather rotate from Admin — the write-only
surface stores it in durable encrypted storage and takes precedence over the
deployment key. On the deferred route, set Base model on that same page after
the key: a key alone leaves the deployment on a model it cannot bill.

Never paste any provider key into chat or terminal output. `.env` is the one
place a deployment key belongs, and `qm secrets push` moves it without printing
it.

Open `webUiUrl`, sign in as the seeded administrator, send a message, and
receive a real model response. Use a specific request rather than a greeting,
then confirm its generated sidebar title replaces the `Web chat` fallback. A
missing title is one failed runtime assertion; inspect the core error log and
rerun `check --live` before continuing. Ask the agent to create a fresh UUID in
`qm-computer-proof.txt` in its current workspace, then use the provider reference's
backend-specific path to verify that UUID outside the model transcript.

## 5. Configure connectors

Open `adminConnectorsUrl` from `outputs --json`. For each chosen connector:

1. Open the provider-console link shown by Admin.
2. Register the exact callback shown there.
3. Enter the client id and secret in the write-only fields and save.
4. Open `userConnectionsUrl` and complete one real user connection.

Verify configured connectors appear and unconfigured connectors remain hidden.

## 6. Add the Slack bot

This is the agent in the workspace, not sign-in; a deployment using Slack
sign-in already created its SSO app in step 3. Skip this when the bot was
deferred. Otherwise read `.codex/skills/deploy-qm/references/slack.md`, then run:

```bash
npm exec --yes=false -- qm slack render
npm exec --yes=false -- qm outputs
```

Create the app from the exact bot manifest URL. Enter its bot and app tokens in
the Admin Slack card, invite it to a test channel, mention it, and receive a
reply.

## 7. Return the handoff

Return:

- the web, Admin onboarding, Admin connectors, and user connections URLs;
- how people sign in, and the Slack SSO app link when that is the route;
- Slack bot app and test-channel links when enabled;
- provider, account or organization, and region;
- the base model provider and where its key lives — the deployment `.env` or the
  Admin page — so the operator knows what to rotate and where;
- pass/fail for health, the private live session canary, sign-in, manual web
  chat and generated title, agent-computer proof, connector visibility, user
  OAuth, Slack reply, conformance, and an idempotent deployment rerun;
- `npm exec --yes=false -- qm status`, logs, rollback, and teardown commands;
- recurring cost or manual work still owned by the operator, including model
  usage billed directly by the provider.

Do not claim completion with a missing test or placeholder. If blocked, leave
the repository resumable and name the exact next human action without exposing
a secret.
