# `qm`

The standalone deployment CLI for QM. The normative directory schema,
security guarantees, target behavior, and lifecycle are in
[`docs/deploy-directory.md`](../docs/deploy-directory.md). `qm init` materializes
the agent-consumable package runbook into the deployment repository.

```bash
npm exec --yes --package=@yc-software/qm@latest -- \
  qm init . --org acme --target aws
npm install
```

Fill the generated account, region, service, and operator-owned GitHub coordinates,
configure an encrypted Terraform backend, then provision the stack:

```bash
npm exec --yes=false -- qm infra render
terraform -chdir=infra init
terraform -chdir=infra plan -out=qm.tfplan
terraform -chdir=infra apply qm.tfplan
```

Set `publicUrl`, `env.core.AWS_PUBLIC_ORIGIN_URL`, and `aws.deployRoleArn` from the
Terraform outputs. Finish setup, render and apply those coordinates, then build the
publisher image and deploy:

```bash
npm exec --yes=false -- qm setup .
npm exec --yes=false -- qm infra render
terraform -chdir=infra plan -out=qm.tfplan
terraform -chdir=infra apply qm.tfplan
npm exec --yes=false -- qm infra build-image
npm exec --yes=false -- qm check
npm exec --yes=false -- qm secrets push
npm exec --yes=false -- qm doctor
npm exec --yes=false -- qm plan
npm exec --yes=false -- qm up --yes
npm exec --yes=false -- qm check --live
```

This package is published to npm as `@yc-software/qm`, with npm provenance attesting the
building workflow. Before dispatching `.github/workflows/release.yml` from `main`, bump
the checked-in `cli/package.json` and `cli/package-lock.json` version past every stable
version named by an npm dist-tag or versioned `refs/tags/v*` Git ref. One dispatch signs and pushes the first-party images,
tests and publishes the package with those exact digests under `release-candidate`, creates
`v<version>` and its GitHub release, then promotes the same package to npm `latest`.
Repository setup must enable immutable releases, configure the release credentials, and
create the two active `refs/tags/v*` rulesets described in [`SECURITY.md`](../SECURITY.md):
a creation-only ruleset whose sole `always` bypass is the dedicated release actor, and a
separate update-and-deletion ruleset with no bypass. The read-only settings credential
cannot inspect bypass actors, so an administrator must audit both lists out of band before
dispatching the workflow.
After an ambiguous npm response, a failed-job or full rerun adopts the package only when
its registry tarball, source commit, Sigstore provenance, embedded image manifest, and
provenance workflow run match that run's rebuilt artifact. A separate workflow run must
set `recovery_version` explicitly; it derives the source commit and origin run from verified
package provenance and revalidates the package-owned signed image set. A no-input run never
adopts a package from another run. The checked-in image manifest is a sentinel replaced with
real digests during release.

The GitHub release's `images.json` is the authoritative production image identity. The
release also publishes `<version>` registry tags for Helm compatibility, but those aliases
remain mutable convenience pointers; production Helm installs pin the attached digests.

The serialized Release workflow is the sole authorized writer of npm dist-tags for `@yc-software/qm`; do not grant its npm token to other workflows or change those tags manually. npm provides no compare-and-swap for dist-tags, so release-candidate cleanup and latest promotion rely on this single-writer boundary and verify each mutation with a fresh registry read.

The CLI deploys long-running QM services; it is not the runtime. Docker runs them
locally. Fly runs them as Fly apps, and new structured Fly deployments use Sprites
agent computers; legacy Porter and SmolMachines selections remain compatibility paths.
AWS runs digest-pinned tasks on ECS Fargate using each workload's configured
architecture, with ARM64 as the default and AMD64 supported. Its structured
agent-computer choices are Sprites and Lambda MicroVMs, with the same legacy external
backend compatibility.

## Deployment directory

```text
qm.config.jsonc
package.json
package-lock.json
deployment.md
.codex/skills/deploy-qm/
.env.example
.env
slack-app-manifest.yml
slack-sso-manifest.yml
sandbox/
  tools/<id>/tool.json
  tools/<id>/<binary>
  skills/<id>/SKILL.md
  Dockerfile
plugins/<name>/Dockerfile
infra/
```

`qm.config.jsonc` is committed and contains no secret values. `.env` is ignored.
`package.json` pins the CLI package at the exact version that scaffolded the
directory — `contract: 1` is only the compatibility floor — so every checkout
resolves the same interpreter; upgrade the pin deliberately.
`cd` into it and the DEPLOY commands act on it; `--config` / `--env-file` / `--sandbox-dir` relocate
a piece (e.g. several deployments sharing one `sandbox/`). `check` validates the config,
computed secret names, tools, skills, and plugins without network access; `up`, `plan`, and
`sandbox build` run the same checks first. `doctor` verifies external prerequisites read-only.
`plan` renders the deployment; AWS mutation requires `up --yes`.

For a single-host Docker deployment, `sandbox.backend: "local"` runs each agent
computer in its own container. `qm up` builds the local runtime from the CLI's
pinned sandbox base, mounts the host Docker socket into trusted core, and connects
core to each sandbox's private network. An explicit `sandbox.image` uses that
runnable local image instead.

On AWS, `up` snapshots the RDS instance under the deploy lease before its first
mutation, names the snapshot after the deployment manifest it precedes, and
records it in that manifest. `rollback` restores code and configuration only,
so it prints that snapshot as the matching data restore point
(`aws rds restore-db-instance-from-db-snapshot`). Pre-deploy snapshots are
pruned to a bounded count; `aws.predeployDbSnapshot: false` opts out.

`sandbox build` is a local validation build. Docker `up` builds its local sandbox
wrapper automatically. Direct Sprites uses `SPRITES_TOKEN` and does not consume OCI
sandbox images. Every AWS target uses `infra build-image` to build and reconcile
`AWS_DEPLOY_IMAGE`; `DEPLOY_PROVIDER=aws` uses that Lambda MicroVM as its bundled-app
publisher runner regardless of the agent-computer backend. When agent computers use
AWS Lambda MicroVMs, the same pin also backs them. Every ordinary `up` also syncs the
deployment layer. `sandbox publish` is retired and the CLI rejects it because no
supported cloud sandbox backend consumes an OCI layer image.

New Sprites deployments use `sandbox.namePrefix` as their only explicit durable
namespace selector. Without it the runtime keeps the historical `qm` prefix. In a
legacy Sprites config, `sandbox.app` may remain alongside a migrated
`sandbox.namePrefix` but stays inert. It and former published-image fields such as
`sandbox.image` or `sandbox.baseImage` are compatibility data only: they neither
override the prefix nor select an OCI image. A legacy
`env.core.SPRITES_NAME_PREFIX` value must be migrated byte-for-byte to
`sandbox.namePrefix`; never replace it with a scaffold default. Changing the prefix is
a deliberate data migration because existing Sprites remain under the old namespace;
it does not authorize deleting them.

Legacy `sandbox.env` and `sandbox.secretEnv` cannot be carried into direct Sprites,
which has no resident environment injection. Before updating, move every value and
credential to the supported tool, skill, connector, or keychain delivery path for its
consumer and verify it can use the replacement. Remove the legacy fields and roll the
deployment, then verify the live consumer. On Fly, confirm the affected app rollout no
longer references the old injection, then delete each `FLY_RESIDENT_ENV_<name>` app
secret. On AWS, confirm the new task definition no longer references the old
injection, then delete each original `${aws.secretsPrefix}<name>` entry from Secrets
Manager. On Docker, complete the replacement container rollout, then remove each
original `<name>` from the deployment's `.env` or other environment source. The CLI
never performs that cleanup automatically. This per-consumer migration is separate
from revoking and deleting the retired source credential `FLY_SANDBOX_API_TOKEN` and
unsetting its deployed core `FLY_API_TOKEN` alias.

Auto uses its built-in model classifier unless `qm.config.jsonc` declares one
`securityScreen` proxy with a provider label, HTTPS endpoint, and `shadow` or
`enforce` rollout. The proxy token is routed separately through
`secretEnv.core.SECURITY_SCREEN_PROXY_TOKEN`.

## Commands

```text
init [dir] [--org id] [--target docker|fly|aws]
check [--json] [--live]
doctor
update [--yes] [--version version]
infra render|build-image|delete-image|delete-task-definitions
conformance [dir] [--static]
plan
up [--yes] [--build-from[=repo]] [--image-label label]
slack render
outputs [--json]
proof scope-key <scope-id>
secrets push [--from file]
status
logs [service] [-f] [--tail n]
down [--purge]
rollback [--to revision-or-sha]
sandbox build [--from image] [--tag tag] [--dry-run]
```

All deploy commands accept `--config`, `--env-file`, and `--sandbox-dir`. `dev` remains
the contributor worktree loop and is separate from the portable deployment contract.

## Package contract

The `@yc-software/qm/contract` export is the supported programmatic surface for
conformance tests. It exposes the contract version, parsing/rendering
functions, and provider ids without registering arbitrary runtime plugins.
Incompatible directory
changes increment the contract major; optional fields may be added within a
major.

The package has no runtime dependencies. Commands shell out to Git plus
target-specific tools: Docker with Buildx for Docker and AWS image work, Flyctl for
Fly, and the AWS CLI for AWS. Terraform is operator-run against the module generated
by `init`.

`update` resolves the exact stable QM package currently promoted on npm's `latest`
tag. `--version` must match that version and cannot select another published release
or downgrade the deployment. `--yes` requires `--version`. The updater downloads the
package from the official registry into a private isolated npm environment with
lifecycle scripts disabled, verifies its npm signatures, SLSA provenance, source
commit, and embedded image manifest, then lets the trusted native npm install the
exact dependency offline from the verified private cache. This path requires the
native npm bundled with Node to be `>=11.12.0 and <12`. npm owns the resulting
package, lock, and installed-tree changes; there is no QM journal, transplant, or
rollback. The automatic path requires an existing exact registry pin and refuses a
local package link; normalize a source checkout through its ordinary trusted
package-manager workflow first.

On macOS, the deployment tree and external local-input and environment paths must be
free of extended ACLs. Their mutation-controlling ancestors may have deny-only ACLs,
but no permission-granting ACL entries. On Linux, trusted `getfacl`, `getfattr`, and
`lsattr` commands must be available on the launcher `PATH`; protected paths must be
free of extended access and default ACLs, extended attributes, and immutable file flags.

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
entry below for later updates.

The installed `@yc-software/qm` package and its `dist/bin/qm.js` entry point are
part of the trusted launcher boundary and must be unchanged before the updater
starts. Run the updater only from a trusted, clean operator shell whose `PATH`
resolves `node` to a trusted Node executable, by invoking that entry point directly:

```bash
node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version <version>
```

Never launch an update through `npm exec`, `npx`, a package script, or another
npm-mediated launcher. npm processes the deployment's project `.npmrc` and package
settings before QM starts, outside the updater's isolated npm environment. Ambient
preloads and loaders also execute before QM; `NODE_OPTIONS`, `NODE_PATH`, and platform
dynamic-loader variables such as `LD_PRELOAD`, `LD_LIBRARY_PATH`,
`DYLD_INSERT_LIBRARIES`, and `DYLD_LIBRARY_PATH` must be absent or independently
trusted. They are part of the trusted launcher boundary. Routine non-update commands
continue to use `npm exec --yes=false -- qm <command>`.

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

Run an update as same-owner exclusive maintenance for its deployment directory. Finish every
other QM CLI command and package-manager write first, do not start another while the
update is running, and run the exact version-pinned command shown by Admin. Admin only
reports npm's promoted `latest`; it never starts the update. After any forced kill,
confirm that no descendant npm, Node/QM, Docker, Fly, AWS, or other provider process
remains before repairing the package or running a recovery command. If npm is
interrupted, inspect the checkout and repair it through version control and the
trusted npm workflow before retrying; normally restore `package.json` and
`package-lock.json`, then run `npm ci --ignore-scripts`.

The verified target CLI then runs its ordinary `up`. Docker rebuilds its generated
local sandbox wrapper when its packaged base or agent wrapper changed. Every AWS
target rebuilds its deployment-publisher Lambda MicroVM image when its deterministic
source hash, recorded version, or remote active version is stale or missing; an AWS
Lambda MicroVM agent backend reuses that pin. Sprites on Fly, Docker, or AWS continue
through the Sprites API with no OCI sandbox-image work. A remote failure leaves the
verified pin in place. On Docker or Fly, reconcile it with
`npm exec --yes=false -- qm up`; on AWS, use
`npm exec --yes=false -- qm up --yes`. Then review and commit the durable tracked
changes. The exact update command can be retried only while its version remains npm
`latest`.

Automated updates refuse any workload `imageOverrides`; on Fly they also refuse
`imageFrom`, and on Docker local they refuse an explicit `sandbox.image`. Workload
overrides, `imageFrom`, and Docker's local sandbox image use their normal custom-image
rollout. They also refuse `sandbox/Dockerfile` whenever the effective backend is
Sprites on Fly, Docker, or AWS. Sprites does not consume that file, so review and
archive or remove it before an automatic update without silently deleting custom
content. Docker's local sandbox build is separate, and an AWS target still requires
its packaged deployment-publisher MicroVM image regardless of the agent backend.
After live acceptance succeeds, commit the package, lock, configuration, and every
other tracked deployment-state change so another checkout cannot restore the old
release.

A retired Admin-dispatched GitHub updater used `.github/workflows/qm-update.yml`,
renamed copies of that workflow, and `QM_UPDATE_GITHUB_*` settings. Before updating
such a checkout, cancel every queued or running job for every configured or detected
legacy workflow and wait for each job to reach a terminal status. Only then remove
every workflow copy and all settings, delete the GitHub repository secret
`QM_DEPLOY_ENV`, revoke the old GitHub token and remove every resident
`QM_UPDATE_GITHUB_TOKEN` copy, then revoke and delete the retired source credential
`FLY_SANDBOX_API_TOKEN` from every repository, host, and CI secret store. Removing
or disabling a workflow or redeploying Admin does not cancel queued jobs. Fly
reconciliation stages removal of its deployed core `FLY_API_TOKEN` alias, but that is
not a substitute for revoking and deleting the source credential.
