---
name: deploy-qm
description: Deploy the QM package from an organization-owned deployment repository to Fly.io or AWS, onboard an administrator, configure connectors, and optionally activate Slack.
---

# Deploy QM

Read `../../../deployment.md` completely and follow it as the authoritative
workflow. Read only the selected provider reference. Read `references/email.md`
before collecting secrets, because sign-in needs an email transport and one of
its steps needs the operator's DNS. Read `references/slack.md` only when Slack
is requested.

A deployment needs a base model key and a way for people to sign in. Collect
both in the same pass. The base model provider is a deployment choice recorded
as `modelProvider`, not a setting to leave for the Admin page. Sign-in is either
the built-in `auth` broker, which needs an email transport, or an external OIDC
provider such as Slack, which needs no email at all — read `references/email.md`
only once the operator has chosen the broker.

Use the repository's installed `@yc-software/qm` dependency through
`npm exec --yes=false -- qm <command>` for routine commands.

Do not require or clone the QM source repository except for the one-time pinned
bootstrap below. Published QM 0.1.7 and earlier do not contain `qm update`. For the
one-time bootstrap to the first hardened updater, do not install or execute the new
package through the deployment's npm project. The trusted Node code below obtains the
exact current stable version directly from the official npm registry over HTTPS and
rejects anything except stable semver. That mutable registry value selects a tag but
does not authenticate source. The matching protected immutable annotated tag, not
registry or release prose, is the source trust anchor. The commands require that tag
to point directly to a commit whose message has the exact official repository identity,
version, peeled commit, bootstrap link, and fixed warning. Independently inspect the
recorded official Actions run when verifying release provenance. From a trusted, clean
operator shell, create a fresh clone in a mode-0700 temporary directory outside the
deployment, then invoke the verified source entry with trusted Node 24 or newer from
the deployment directory:

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

The installed `@yc-software/qm` package and its
`dist/bin/qm.js` entry point are part of the trusted launcher boundary and must be
unchanged before the updater starts. When Admin reports a new stable release, run
the updater only from a trusted, clean operator shell whose `PATH` resolves `node`
to a trusted Node executable, by invoking that entry point directly:

```bash
node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version <version>
```

Never launch an update through `npm exec`, `npx`, a package script, or another
npm-mediated launcher. npm processes the deployment's project `.npmrc` and package
settings before QM starts, outside the updater's isolated npm environment. Ambient
preloads and loaders also execute before QM; `NODE_OPTIONS`, `NODE_PATH`, and platform
dynamic-loader variables such as `LD_PRELOAD`, `LD_LIBRARY_PATH`,
`DYLD_INSERT_LIBRARIES`, and `DYLD_LIBRARY_PATH` must be absent or independently
trusted. They are part of the trusted launcher boundary. Keep using
`npm exec --yes=false -- qm <command>` for routine non-update commands.

`qm update --yes` is supported on macOS and Linux, not Windows.

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

Run Admin's exact direct update command, including `--version`, from the deployment
repository. The updater
accepts only npm's currently promoted `latest`, verifies the isolated package and its
release provenance and manifest, lets the trusted native npm install it offline from
a verified private cache, and lets the target CLI's ordinary `up` converge its managed
substrate. The update path requires native npm `>=11.12.0 and <12`. npm owns the
package, lock, and installed-tree changes; there is no updater journal or rollback.
The automatic path requires an existing exact registry pin and refuses a local
package link; normalize a source checkout through its ordinary trusted
package-manager workflow first.
On macOS, the deployment tree and external local-input and environment paths must be
free of extended ACLs. Their mutation-controlling ancestors may have deny-only ACLs,
but no permission-granting ACL entries. On Linux, trusted `getfacl`, `getfattr`, and
`lsattr` commands must be available on the launcher `PATH`; protected paths must be
free of extended access and default ACLs, extended attributes, and immutable file flags.
Treat this as same-owner exclusive maintenance: finish every other QM CLI command and
package-manager write for the deployment directory first, and start neither until the
update exits. After any forced kill, confirm that no descendant npm, Node/QM, Docker,
Fly, AWS, or other provider process remains before repairing the package or running a
recovery command. If npm is interrupted, inspect and repair the checkout with version
control and trusted npm before retrying. If remote reconciliation fails, retain the
new pin and reconcile it with `npm exec --yes=false -- qm up` on Docker or Fly or
`npm exec --yes=false -- qm up --yes` on AWS. Then review and commit the durable
tracked changes. Retry the exact update command only while its version remains npm
`latest`. If retired
`QM_UPDATE_GITHUB_*` settings or default or renamed legacy
update workflows remain, first cancel all queued or running jobs for every configured
or detected legacy workflow and wait for terminal status. Only then remove every
workflow copy and the settings, delete the GitHub repository secret `QM_DEPLOY_ENV`,
revoke the old GitHub token and remove every resident `QM_UPDATE_GITHUB_TOKEN` copy,
then revoke and delete the retired source credential `FLY_SANDBOX_API_TOKEN` from
every repository, host, and CI secret store and unset its deployed core
`FLY_API_TOKEN` alias before updating.

If the command reports custom image or sandbox configuration, use that
deployment's normal image rollout instead of removing the safety check. Automatic
update rejects `sandbox/Dockerfile` when the effective backend is Sprites on Fly,
Docker, or AWS; review and archive or remove that retired file without silently
deleting custom content.
Docker's local sandbox build remains separate. Every AWS target still builds its
packaged deployment-publisher MicroVM image, and the AWS agent-computer backend reuses
that pin. For Sprites, only `sandbox.namePrefix` selects a new durable namespace.
Preserve a legacy explicit `env.core.SPRITES_NAME_PREFIX` byte-for-byte when migrating
it, and never reinterpret legacy `sandbox.app`, `sandbox.image`, or
`sandbox.baseImage` as a new prefix or image.
A legacy `sandbox.app` may remain beside the migrated `sandbox.namePrefix`, but it
stays inert.
Do not remove legacy `sandbox.env` or `sandbox.secretEnv` until every value and
credential has moved to the supported tool, skill, connector, or keychain delivery
path for its consumer and that consumer can use the replacement. Remove the legacy
fields and roll the deployment, then verify the live consumer. On Fly, confirm the
affected app rollout no longer references the old injection, then delete each
`FLY_RESIDENT_ENV_<name>` app secret. On AWS, confirm the new task definition no longer
references the old injection, then delete each original
`${aws.secretsPrefix}<name>` entry from Secrets Manager. On Docker, complete the
replacement container rollout, then remove each original `<name>` from the
deployment's `.env` or other environment source. Field presence is not deletion
authority or acknowledgement of a completed migration. This is separate from
revoking and deleting the retired source credential `FLY_SANDBOX_API_TOKEN` and
unsetting its deployed core `FLY_API_TOKEN` alias.
After live acceptance passes, review and commit every tracked package, lock,
configuration, and deployment-state change produced by the update.
Do not stop at infrastructure health: complete the acceptance checks and return
the handoff required by `deployment.md`. A web response without a generated
sidebar title is not a completed deployment.
