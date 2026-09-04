# Deployment directory contract

Contract v1 makes a QM deployment a committed, portable directory. The `qm` CLI is the only interpreter of that directory: it validates the same inputs it uses to render containers, task definitions, secret routing, and the agent-computer layer.

## Layout

`package.json` pins the `@yc-software/qm` deployment engine at the exact version that scaffolded the directory, so the directory records which CLI interprets it rather than drifting with whatever version an operator has installed; `contract: 1` remains only the compatibility floor. `package-lock.json` records the installed artifact. `qm.config.jsonc` is the deployment config. `deployment.md` and `.codex/skills/deploy-qm/` are materialized package assets an operator can hand to an agent. `sandbox/` adds tools and skills to agent computers; `plugins/` adds services; `.env.example` documents the computed secret names; `.env` supplies local values and is never committed. `qm init` writes `slack-app-manifest.yml` for the optional Socket Mode bot. It also writes `slack-sso-manifest.yml` only when the portal is configured to use Slack OpenID. `qm slack render` refreshes the applicable manifests after `publicUrl` changes, and `qm outputs` returns their creation links and the web coordinates. `qm init --target aws` also vendors the reference `infra/` Terraform module and its derived `terraform.tfvars`; the copy belongs to the deployment after generation. Init never overwrites an existing deployment config.

`qm update` reads the official npm registry's promoted `latest` metadata without changing the deployment and prints that exact stable version. `--version` must match the version currently promoted as `latest` and cannot select an older stable release or downgrade the deployment. `qm update --yes --version <version>` requires native npm `>=11.12.0 and <12`, downloads that package into a private isolated npm environment with lifecycle scripts disabled, verifies its npm signatures and SLSA attestation against QM's official release workflow and source commit, and checks its embedded image manifest. The trusted native npm then installs the exact dependency offline from the verified private cache. npm owns the resulting `package.json`, `package-lock.json`, and `node_modules` changes; the updater has no separate journal, transplant, atomicity guarantee, or rollback. The automatic path requires an existing exact registry pin and refuses a local package link; normalize a source checkout through its ordinary trusted package-manager workflow first. On macOS, the deployment tree and external local-input and environment paths must be free of extended ACLs. Their mutation-controlling ancestors may have deny-only ACLs, but no permission-granting ACL entries. On Linux, trusted `getfacl`, `getfattr`, and `lsattr` commands must be available on the launcher `PATH`; protected paths must be free of extended access and default ACLs, extended attributes, and immutable file flags. `qm update --yes` is supported on macOS and Linux, not Windows.

### One-time bootstrap from QM 0.1.7 and earlier

Published QM 0.1.7 and earlier do not contain `qm update`. For the one-time bootstrap to the first hardened updater, do not install or execute the new package through the deployment's npm project. The trusted Node code below obtains the exact current stable version directly from the official npm registry over HTTPS and rejects anything except stable semver. That mutable registry value selects a tag but does not authenticate source. The matching protected immutable annotated tag, not registry or release prose, is the source trust anchor. The commands require that tag to point directly to a commit whose message has the exact official repository identity, version, peeled commit, bootstrap link, and fixed warning. Independently inspect the recorded official Actions run when verifying release provenance. From a trusted, clean operator shell, create a fresh clone in a mode-0700 temporary directory outside the deployment, then invoke the verified source entry with trusted Node 24 or newer from the deployment directory:

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

Use only the verified immutable annotated tag, never editable release prose, mutable `main`, `curl | node`, `npm install`, `npm exec`, `npx`, or a package script for this bootstrap. The pinned source launcher performs the hardened package signature, SLSA provenance, source-commit, and manifest verification before npm can change the deployment. After the first hardened version is installed, use the direct installed entry below for later updates.

The installed `@yc-software/qm` package and its `dist/bin/qm.js` entry point are part of the trusted launcher boundary and must be unchanged before the updater starts. Run the updater only from a trusted, clean operator shell whose `PATH` resolves `node` to a trusted Node executable, by invoking that entry point directly:

```bash
node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version <version>
```

Never launch an update through `npm exec`, `npx`, a package script, or another npm-mediated launcher. npm processes the deployment's project `.npmrc` and package settings before QM starts, outside the updater's isolated npm environment. Ambient preloads and loaders also execute before QM; `NODE_OPTIONS`, `NODE_PATH`, and platform dynamic-loader variables such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, and `DYLD_LIBRARY_PATH` must be absent or independently trusted. They are part of the trusted launcher boundary. Routine non-update commands continue to use `npm exec --yes=false -- qm <command>`.

Only npm verification and mutation are isolated. Provider reconciliation runs the verified CLI from a temporary working directory with absolute deployment inputs, but intentionally trusts the operator's external home, ambient provider variables, agent and keyring sockets, provider configuration and credentials, credential helpers, CLI plugins and aliases, proxy and CA settings, and external provider executables. Provider executables, transitive helpers, and plugins receive the operator's filtered ambient environment and external `PATH`; their interpreter and runtime loaders, caches, output paths, and delegated executables are not exhaustively isolated. Provider reconciliation is state-changing and may modify provider resources, just as ordinary `up` can. Every path those trusted inputs delegate to is trusted too; they must not reference deployment-controlled code. The external objects and every alias to them must not be writable through the deployment. Direct `PATH` entries that resolve inside the deployment are excluded; explicit provider-configuration paths that do so are rejected.

The updater never converts ambient operator-shell values into deployment workload secrets. Local values must already be in the explicit deployment environment file; existing remote provider secret stores remain authoritative.

An update is same-owner exclusive maintenance for its deployment directory. The operator must finish every other QM CLI command and package-manager write before starting it, start neither while it runs, and use the exact version-pinned command from Admin's read-only npm `latest` notice. After any forced kill, confirm that no descendant npm, Node/QM, Docker, Fly, AWS, or other provider process remains before repairing the package or running a recovery command. If npm is interrupted, inspect the checkout and repair it through version control and trusted npm, normally by restoring `package.json` and `package-lock.json` and running `npm ci --ignore-scripts`, before retrying.

The verified target package's executable runs the ordinary provider-specific `up` path. That path rebuilds Docker's generated local sandbox wrapper when its packaged base or agent wrapper is stale. Every AWS target deterministically rebuilds its deployment-publisher Lambda MicroVM image when its source hash, recorded version, or remote active version is stale or missing; an AWS Lambda MicroVM agent backend reuses that pin. Sprites on Fly, Docker, or AWS use the Sprites API and do no OCI sandbox-image work during an update. If remote reconciliation fails, the verified package remains pinned. On Docker or Fly, the operator reconciles it with `npm exec --yes=false -- qm up`; on AWS, the operator uses `npm exec --yes=false -- qm up --yes`. The operator then reviews and commits the durable tracked changes. The exact update command remains retryable only while its version is npm `latest`.

Automatic update refuses any workload `imageOverrides`; on Fly it also refuses `imageFrom`, and on Docker local it refuses an explicit `sandbox.image`. Workload overrides, `imageFrom`, and Docker's local sandbox image use their normal custom-image rollout. Automatic update also refuses `sandbox/Dockerfile` whenever the effective backend is Sprites on Fly, Docker, or AWS. Sprites no longer consume OCI sandbox images, so the operator must review and archive or remove that retired file before updating, without silently deleting its custom content. Docker's local sandbox build is separate, and an AWS target still requires its packaged deployment-publisher MicroVM image regardless of the agent backend. After successful live checks, the operator commits the changed package, lock, configuration, and every other tracked deployment-state change so a later checkout cannot restore the old release.

The retired Admin-dispatched GitHub updater is never migrated implicitly. A deployment containing its default or renamed workflows or any `QM_UPDATE_GITHUB_*` Admin configuration must first cancel every queued or running job for every configured or detected legacy workflow and wait for each job to reach a terminal status. Deleting or disabling a workflow or redeploying Admin does not cancel queued jobs. Only after every job is terminal may the operator remove every workflow copy and all `QM_UPDATE_GITHUB_*` settings, delete the GitHub repository secret `QM_DEPLOY_ENV`, revoke the old GitHub token and remove every resident `QM_UPDATE_GITHUB_TOKEN` copy, then revoke and delete the retired source credential `FLY_SANDBOX_API_TOKEN` from every repository, host, and CI secret store. Fly reconciliation stages removal of its deployed core `FLY_API_TOKEN` alias, but that is not a substitute for revoking and deleting the source credential.

The sandbox layout is:

```text
sandbox/
  Dockerfile
  tools/<id>/tool.json
  tools/<id>/<binary>
  skills/<id>/SKILL.md
  skills/<id>/<text assets>
```

`sandbox/Dockerfile` is an optional input only for the separate `sandbox build` local-image path. Direct Sprites and the packaged AWS `infra build-image` artifact do not consume it, so every declared binary for those agent backends must be present in its tool directory. Skill assets delivered through the deployment-layer API are text in v1, and `sandbox build` validates tool binaries locally.

## Configuration

The root object requires `contract: 1`, `orgId`, `publicUrl`, `target`, and `services` including `core`. Docker defaults to local sandbox containers. New structured Fly configurations default to Sprites; legacy `env.core.SANDBOX_BACKEND` selections for Porter and SmolMachines remain compatibility paths. On AWS the agent-computer substrate is an explicit choice: omitting the `sandbox` block runs named Lambda MicroVM images, `sandbox.backend: "sprites"` selects Sprites, and `sandbox.backend: "aws"` states the MicroVM default in the file. That choice does not affect the separate deployment-publisher MicroVM image required by every AWS target. Unknown contract majors fail closed. `target` is `docker`, `fly`, or `aws`.

Common optional fields select the model, plugins, extra skill directories, per-service non-secret environment values, image overrides, sandbox settings, and an external security screen. `botName` (at most 31 characters, so the generated "`<botName>` SSO" app name fits Slack's 35-character cap) names the bot everywhere users see it — the generated Slack app manifests, the prompt identity, and sign-in pages — and `orgName` (at most 40) is how the bot refers to the organization; both default to neutral values and can be changed live from the Admin page's Branding card, which then takes precedence over the deployed values. `sandbox.backend: "local"` selects Docker-local containers, `sandbox.backend: "sprites"` selects direct Sprites on Docker, Fly, or AWS, and `sandbox.backend: "aws"` selects AWS Lambda MicroVMs. `sandbox.namePrefix` is the only explicit Sprites namespace selector; when absent, the runtime uses the historical `qm` prefix. `sandbox.image` is supported only by Docker's local backend. `securityScreen` contains `backend: "proxy"`, a lowercase provider label, an HTTPS endpoint, and a `shadow` or `enforce` rollout. Its presence requires `secretEnv.core.SECURITY_SCREEN_PROXY_TOKEN`; absence keeps Auto on the built-in model classifier.

Legacy Sprites configuration is compatibility data, not a new namespace choice. `sandbox.app` may remain alongside a migrated `sandbox.namePrefix`, but it stays inert and never sets or overrides `SPRITES_NAME_PREFIX`; former published-image fields such as `sandbox.image` and `sandbox.baseImage` never select an OCI image. A legacy explicit `env.core.SPRITES_NAME_PREFIX` must be accepted and migrated byte-for-byte to `sandbox.namePrefix`; replacing it with a new scaffold default would silently change the durable namespace. Any intentional `sandbox.namePrefix` change is a data migration: existing Sprites remain discoverable only under the old prefix and must not be deleted as cleanup.

Legacy `sandbox.env` and `sandbox.secretEnv` are not inert compatibility fields. Direct Sprites has no resident environment injection, so the CLI cannot choose safe replacements for their consumers. Before updating, the operator must move every value and credential to its supported tool, skill, connector, or keychain delivery path and verify each consumer can use the replacement. The operator then removes the legacy fields and rolls the deployment before finishing target-specific cleanup. On Fly, the operator confirms the affected app rollout no longer references the old injection, then deletes each `FLY_RESIDENT_ENV_<name>` app secret. On AWS, the operator confirms the new task definition no longer references the old injection, then deletes each original `${aws.secretsPrefix}<name>` entry from Secrets Manager. On Docker, the operator completes the replacement container rollout, then removes each original `<name>` from the deployment's `.env` or other environment source. The CLI performs none of that provider cleanup automatically. This per-consumer cleanup is separate from revoking and deleting the retired source credential `FLY_SANDBOX_API_TOKEN` and unsetting its deployed core `FLY_API_TOKEN` alias.

Fly requires `region` and `flyOrg`. AWS requires a 12-digit account, region, deployment label, ECS cluster, deploy-role ARN, Secrets Manager prefix, DNS-valid Cloud Map namespace, and an entry for every enabled first-party service and discovered plugin containing a unique valid ECR repository, a unique valid ECS service, and a valid Fargate CPU/memory combination. The cluster is constrained so every IAM, RDS, ALB, and related name derived by the reference module is valid. `imageLabel` identifies the complete deployment manifest used by rollback and live drift checks; the matching OCI/ECR tag is a convenience pointer. Workloads may also set `arm64`/`amd64` architecture, non-secret build arguments, or role ARNs. External prebuilt images must declare their architecture; source-built and built-in workloads use their platform default. Cloud Map names are the private workload addresses. The reference AWS module exposes CloudFront over HTTPS and restricts its HTTP ALB origin to CloudFront's managed origin prefix. With portal enabled, it is the ALB's sole target; access to private core, web, and admin surfaces requires signed portal identity. Without portal, only core is an ALB target. A real harness requires an HTTPS `publicUrl`.

`publicUrl` is the one public coordinate. The CLI derives the core, Slack, web, admin, and portal URL environment from it. Config `env` is for non-secret values only; secret-shaped keys are rejected.

## Security screen proxy

The proxy endpoint receives one or more HTTPS `POST`s per bounded classification with `content-type: application/json`, the routed token in `x-api-key`, redirects disabled, and this body:

```json
{
  "text": "untrusted content",
  "hook": "user_input",
  "metadata": {
    "surface": "webhook",
    "origin": "automation",
    "qm": {
      "request_id": "uuid",
      "input_index": 0,
      "chunk_index": 0,
      "chunk_count": 1
    },
    "provider-label": {
      "request_id": "uuid",
      "input_index": 0,
      "chunk_index": 0,
      "chunk_count": 1
    }
  }
}
```

`hook` is `user_input` or `tool_response`; metadata fields appear only when known. The chunk coordinates are also mirrored under the configured provider label so a direct provider endpoint can consume its own namespace without a built-in adapter. Inputs are capped at 16,000 characters and split into overlapping 1,600-character requests with at most two in flight per classification. All chunks share a request ID. A successful provider returns finite `score` and `threshold` numbers from zero through one plus an optional lowercase `primary_outcome` label:

```json
{
  "score": 0.91,
  "threshold": 0.7,
  "primary_outcome": "prompt_injection"
}
```

A chunk whose score is at or above its threshold resolves to Strict, and any Strict chunk makes the whole classification Strict. When chunks agree, the highest-scoring result supplies the diagnostics. The configured provider is an audit label and metadata namespace, not a built-in adapter name, so any service implementing this contract can be selected. Throttled requests retry with bounded backoff inside the classification deadline. Invalid responses, timeouts, redirects, and other provider errors are unavailable classifications: enforcement fails closed, while shadow mode leaves the built-in model authoritative and records the comparison. Shadow changes authority, not disclosure: it still sends the full screened content to the configured endpoint, so operators must trust that provider with external messages, files, and surface results.

## Secrets

First-party services publish a typed `SecretSpec` schema. The CLI combines the enabled services and feature predicates with plugin `secrets` to form the computed secret set. That same schema determines which task receives each secret. Core validates its own required runtime secrets at production boot.

`init` renders the set as `.env.example`; that file has names and descriptions, never values, and is not an input to deployment. Operators place values in gitignored `.env`. Docker reads the file locally. `qm secrets push` uploads supplied operator-managed values to Fly secrets or AWS Secrets Manager without printing them. Terraform owns `DATABASE_URL` on AWS because it owns RDS. `doctor` treats missing and placeholder required values as failures and reports absent optional plugin secrets without blocking deployment.

## Tool descriptors

Only `id` is required. The remaining fields buy these runtime guarantees:

| Field                       | Guarantee                                                                                                                                                                                                                                                              |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `label`                     | Human-readable name in resident-login status.                                                                                                                                                                                                                          |
| `advertise`                 | Added to the agent computer's installed-CLI list.                                                                                                                                                                                                                      |
| `hints`                     | Added to the model's deployment-tool guidance.                                                                                                                                                                                                                         |
| `auth.check`, `auth.reauth` | Merged into the resident-login connector registry.                                                                                                                                                                                                                     |
| `auth.credentialPaths`      | One `$HOME`-relative set of `{ path, kind }` entries drives resident capture, ephemeral linking, and device-flow persistence. Each entry explicitly declares `file` or `directory`; absolute paths and traversal are rejected, and `.ssh` warns.                       |
| `auth.splitEnv`             | Adds publish-time environment after all placeholders resolve. `{actingSlackUserId}` is the only v1 placeholder. It is trustworthy only where the surface or broker cryptographically binds the acting Slack identity; otherwise no acting identity should be supplied. |
| `egress`                    | Validated as host names and checked for dangerous wildcards. Runtime enforcement is not claimed in v1.                                                                                                                                                                 |
| `approvals`                 | Appended to the command-policy floor. A rule may deny or require approval for its own tool; it may never add an allow or loosen administrator policy.                                                                                                                  |
| `install.binary`            | Must be present in the portable layer, or installed by `sandbox/Dockerfile` only for the separate local-image path; that image build checks PATH, while Direct Sprites and the packaged AWS `infra build-image` artifact do not consume the Dockerfile.                |

Raw approval patterns must start with the canonical `\b<install.binary-or-id>\b` boundary and cannot use a top-level alternative, so every match begins with their own tool; nested alternatives after that prefix remain available. A `command` rule is safely anchored to that same effective binary by the CLI. Duplicate tool ids fail. Skills require `name` and `description` frontmatter.

Deployment-specific safety belongs here too. For example, an ambiently authenticated CLI declares a deny `approvals` rule for its login command, a `hints` entry telling the model not to log in, and its `auth.credentialPaths`; generic core carries no vendor-specific command exception or credential path.

## Delivery and pins

When `sandbox/` exists, every `up` sends its descriptors and complete text skill trees to source-authenticated `PUT /v1/deployment-layer`. Without `sandbox/`, `up` skips layer sync and leaves the deployed layer unchanged. Core validates submitted bundles again, stores them in Postgres table `deployment_layer`, versions them by a canonical SHA-256 content hash, records an audit event, hydrates them before serving, and returns the restorable bundle with its generation, content hash, apply status, runtime content hash, and source from source-authenticated `GET /v1/deployment-layer`. Each mutation signs the exact prior generation and a new 128-bit operation identity, so response-loss retries are idempotent while stale and concurrent writers fail closed. Removed layer-owned skills are archived. Filesystem `DEPLOYMENT_LAYER` remains a bootstrap input for local and recovery use.

Docker builds its local sandbox wrapper during `up`. Every AWS target uses `infra build-image` to package and pin the Lambda MicroVM runner required by `DEPLOY_PROVIDER=aws` for agent-published bundled apps; this happens regardless of the agent-computer backend. With `sandbox.backend: "aws"` or no sandbox block, the same image pin also backs agent computers. Sprites, Porter, and SmolMachines use their own agent-computer providers and do not consume that image for agents, but an AWS target still needs it for publishing. Direct Sprites does no OCI sandbox-image work. The sandbox directory is synchronized separately as the signed deployment layer. `sandbox publish` is retired and hard-rejected.

Postgres stores create their tables lazily with idempotent DDL through the shared pool. The Terraform module creates RDS and its `DATABASE_URL` secret. On AWS, `up` takes a manual RDS snapshot before its first mutation — refusing an unavailable database or one whose automated-backup retention is below `aws.dbRetentionMinDays` (default 1) — named after the deployment manifest it precedes and recorded in that manifest; older pre-deploy snapshots are pruned to a bounded count, and `aws.predeployDbSnapshot: false` opts a deployment out. Restore remains operator-run: `rollback` prints the snapshot to restore alongside the code it rolls back.

## Targets and prerequisites

| Requirement                                                                                | Docker                                                                                                     | Fly                                                                               | AWS                                                                                          |
| ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Node 24 and `qm` CLI; native npm `>=11.12.0 and <12` for `qm update`                       | yes                                                                                                        | yes                                                                               | yes                                                                                          |
| Target tooling and authentication                                                          | Docker daemon and CLI                                                                                      | `flyctl` and Fly auth                                                             | AWS CLI with `lambda-microvms` and AWS auth; Terraform; Docker for image transfer and builds |
| Agent-computer substrate and credentials                                                   | Docker socket for local; `SPRITES_TOKEN`, `PORTER_DEPLOY_API_TOKEN`, or `SMOLMACHINES_TOKEN` when selected | `SPRITES_TOKEN`, `PORTER_DEPLOY_API_TOKEN`, or `SMOLMACHINES_TOKEN` when selected | the same external-backend credentials, or Lambda MicroVM image/version and execution role    |
| AWS bundled-app publisher runner                                                           | no                                                                                                         | no                                                                                | `AWS_DEPLOY_IMAGE` Lambda MicroVM image/version and execution role                           |
| Slack bot app created from generated manifest, bot token, app token                        | when Slack enabled                                                                                         | when Slack enabled                                                                | when Slack enabled                                                                           |
| Admin email, verified sender, and a Resend key or SMTP credentials                         | with the built-in `auth` broker                                                                            | with the built-in `auth` broker                                                   | with the built-in `auth` broker                                                              |
| Slack SSO app, client id/secret, team gate, and exact `<publicUrl>/auth/callback` redirect | only with Slack OIDC                                                                                       | only with Slack OIDC                                                              | only with Slack OIDC                                                                         |
| Postgres                                                                                   | local container or supplied DSN                                                                            | Fly Postgres or supplied DSN                                                      | Terraform RDS                                                                                |
| AWS credentials, ECS/ECR/RDS/ALB/Cloud Map, exact GitHub OIDC trust                        | no                                                                                                         | no                                                                                | yes                                                                                          |

`doctor` checks target resources read-only. When user-owned CI is requested, the AWS account must already have the account-level GitHub provider at `arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com`; check it with `aws iam get-open-id-connect-provider --open-id-connect-provider-arn <arn>` and, if absent, have an account administrator run `aws iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com`. The AWS doctor verifies ECS, ECR, RDS, CloudFront-to-ALB routing, the deploy role and its exact operator-owned GitHub repository plus configured branch or environment trust, required secret values, the deployment-publisher MicroVM image, and the independently selected agent-computer backend. Environment-based trust must be paired with GitHub deployment-branch restrictions because its OIDC subject does not contain a branch. Fork pull requests cannot assume the deploy role. No workflow in the qm source repository deploys a production stack.

## Commands, conformance, and versioning

After provider bootstrap, the normal gate order is `check`, `doctor`, `plan`, `up --yes`, then `check --live`. AWS bootstrap includes Terraform provisioning, setup and secret delivery, and `infra build-image` before the first `doctor`; run `infra build-image` again whenever `doctor` reports that publisher image missing or stale. Confirmed `up` also rebuilds a missing or stale deployment-publisher image after read-only preflight regardless of the agent-computer backend. First-party services come from the package's matching image manifest; `--build-from` is an explicit contributor escape hatch for unreleased source. `check` is static and has JSON output keyed to clause ids. `doctor` makes read-only external checks. `plan` renders without mutation. On AWS, rollback restores the prior recorded deployment manifest as one unit under the deployment lease; `--to` selects another complete manifest by manifest id or recorded release label. Because rollback restores code and configuration but never data, it prints the pre-deploy database snapshot recorded on the deployment it rolls back. Docker and Fly do not claim rollback.

AWS `up` is mutually excluded by a DynamoDB lease, snapshots the RDS instance before its first mutation, registers digest-pinned task definitions, enables the ECS circuit breaker, updates services, and waits stable. AWS `check --live` compares environment, secret routing, task definitions, and the configured release label in both directions. Fly `check --live` verifies every configured workload has a live image-bearing machine and the public health endpoint responds. `qm conformance` remains the later cross-check between the static contract and core's resolved deployment-layer descriptors.

The semver-stable `@yc-software/qm/contract` export contains only config loading, layer validation/parsing, env derivation, approval compilation, and the contract version; AWS task rendering joins it with the AWS backend. A new incompatible directory shape increments the contract major. A CLI may add optional fields within a major.

Built-in targets live in one registry that owns discovery, initialization files and ignores, accepted deploy flags, backend creation, substrate preflight, and provider output coordinates. To add one, implement that provider contract and backend lifecycle (`up`, status, logs, down, rollback, doctor, secret delivery, and live checking), add a namespaced config block and templates, render through the shared environment and secret pipelines, document prerequisites honestly, and add conformance fixtures. Loading arbitrary provider packages at runtime is outside contract v1.

## Clause status

| Clause                            | Status         | Verifier                                                                         |
| --------------------------------- | -------------- | -------------------------------------------------------------------------------- |
| `config.v1`                       | ENFORCED       | `loadConfigAt`, `qm check`                                                       |
| `config.no-secret-values`         | ENFORCED       | `qm check`                                                                       |
| `secrets.computed-set`            | ENFORCED       | typed schema, `qm check`                                                         |
| `sandbox.descriptors`             | ENFORCED       | `validateSandboxLayer`, core PUT validation                                      |
| `sandbox.approvals-tighten`       | ENFORCED       | descriptor parsers, command-policy composition                                   |
| `runtime.layer-resolved`          | ENFORCED       | deployment-layer store/API and core PUT validation, `qm conformance` cross-check |
| `aws.rendered-task`               | ENFORCED       | `renderTaskDefinition`, AWS `plan`/`up`, digest and task-diff tests              |
| `aws.live-drift`                  | ENFORCED       | `qm check --live`, bidirectional task/environment/secret/release checks          |
| `sandbox.egress`                  | VALIDATED-ONLY | wildcard/host warnings in `qm check`; no runtime enforcement claimed             |
| `sandbox.aws-substrate`           | ENFORCED       | selected agent-computer backend and its live drift, separate from app publishing |
| `target.provider-registry`        | ENFORCED       | provider registry and packed-artifact tests                                      |
| `extension.deployment-data-proxy` | RESERVED       | optional env-gated org adapter; not part of contract v1                          |

ENFORCED means code rejects or tests the clause today. VALIDATED-ONLY means the directory is checked but runtime enforcement is explicitly absent. RESERVED names a compatibility slot without claiming implementation.
