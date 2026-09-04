# Security policy

QM is designed to isolate each person's data and activity by scope. It is early,
experimental software: that design goal is not a promise that data cannot leak,
a certification, or a substitute for a deployment-specific security review.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through this repository's
**Security → Report a vulnerability** flow. Do not open a public issue, discussion,
or pull request with exploit details.

Include the affected revision, configuration, impact, and the smallest reproduction
you can safely provide. We will acknowledge the report, investigate it, and coordinate
disclosure with you. Do not access data that is not yours or test against deployments
you do not own.

## Threat model and limitations

This is a public summary of the current security model. This
summary highlights material limitations; it is not exhaustive and does not promise
that planned controls will ship.

### Scope

QM's interactive agent surfaces currently assume one organization of authenticated
internal users. Guests and external users are outside that interaction boundary,
apart from a deployment's explicit, admin-controlled exception for internal users in
Slack rooms that include external participants. Published apps are a separate,
deliberate exception: an owner can distribute a capability link to visitors outside
the organization. Holding that link authorizes reach to that app only; it does not
create a QM principal or authorize interaction with the agent or control plane. QM is
not a hardened public or multi-tenant service boundary.

### Protected assets and actors

The assets in scope include credentials and capability tokens, conversation and model
request data, memory, files and workspaces, deployment data, audit records, and side
effects made in connected systems. Relevant actors include internal users, org
admins, deployment operators, the model-driven agent, sandbox processes, surface
plugins, model and browser providers, and connected services.

The security goals are to prevent unauthorized cross-scope reads, writes, and
deliveries; keep credentials within their authorized scope; authenticate actors; and
preserve attribution and audit evidence. QM does not guarantee correct model output
or continuous availability.

### Trust boundaries and operator assumptions

- The deployment operator controls the cloud account, network, identity provider,
  database, object storage, runtime configuration, encryption keys, and initial admin
  grants. QM does not protect a deployment from a malicious or compromised operator.
- An org admin is a privileged content reader, not only a policy administrator.
  Admin content reads are scope-authorized and audited, but require no additional
  user approval.
- Model providers receive the prompt and request data sent to them. Browser providers
  receive browser tasks and traffic, and browser egress uses their network. Operators
  must evaluate those providers and their retention policies.
- The agent and software it runs in a sandbox are not trusted to make authorization
  decisions. Core is intended to enforce identity, scope, grants, delivery, and
  deterministic effect gates around them. The sandbox remains a sensitive boundary
  because it executes model-generated commands and can hold usable credentials.
- Surface and connector inputs are untrusted data. Authentication proves the source
  or initiating principal where implemented; it does not make the content safe.
- A published app and its runtime are a separate trust boundary. App code receives
  visitor requests and data, may hold explicitly supplied app environment, and may
  use configured per-app acting-as access. QM keeps ambient author credentials out of
  the app, but does not review app code or guarantee how it handles visitor data.

### What the controls do and do not guarantee

QM resolves a principal and scope for each turn, separates scope workspaces, uses
signed ingress and capability tokens, applies grants and audience checks, and records
security-relevant actions. These controls are designed to reduce cross-scope access
and make actions attributable. They are not a formal non-interference proof or a
guarantee that the model cannot disclose data.

Command approvals, content screening, and egress policy are defense in depth. Their
effect depends on the selected posture, configured rules, available classifier, and
sandbox backend. Audit records support investigation; they do not prevent an action.
Encryption at rest protects stored secret material from direct storage reads, not
plaintext credentials while a process is using them. An approval means a human
accepted the displayed action under the information available at that time, not that
the resulting behavior is safe.

### Deliberately portal-only actions

Three actions are intentionally excluded from the agent self-API, even though the
web portal offers them. They look like capability-parity gaps in an audit; they are
walls, not gaps, and should not be "fixed" without revisiting the reasoning here.

- **Admin grant changes.** Granting or revoking org-admin rights happens only in the
  portal, on an authenticated admin's own turn. If the agent could change grants, a
  prompt-injected or compromised agent process could escalate its own operator's
  privileges — or demote everyone else's.
- **Impersonation.** The agent always acts as the principal resolved for the turn.
  There is no self-API route to act as a different principal, because every
  authorization decision downstream keys off that identity; a switchable identity
  would turn one confused turn into another person's authority.
- **Command-approval decisions.** Approving a gated command is a human judgment made
  on the approver's own turn. An agent-reachable approval route would collapse the
  human-in-the-loop gate into a single model decision, which is exactly what the
  gate exists to prevent.

The common shape: each is a decision that authorizes _future_ agent behavior, so the
decision itself must come from outside the agent. Parity work should route around
these, not through them.

### Known limitations

- **Command policy is bypassable.** It classifies shell text and catches configured or
  common dangerous forms, but obfuscation, encoding, or writing and then executing a
  script can evade it. It is a speed bump against mistakes and injection, not a
  sandbox boundary.
- **Browser actions sit outside some core gates.** Actions inside the browser runner
  do not re-enter command policy or human-in-the-loop approval. They rely on
  task-level consent and the runner's spend checks. Browser traffic exits through the
  browser provider rather than QM's egress proxy.
- **Sandbox credentials are plaintext while in use.** Credentials and capability
  tokens materialized as environment variables or files are readable by processes in
  that sandbox. Scope isolation and auditing limit exposure, and short-lived
  capabilities expire, but those controls do not stop a compromised agent process
  from spending or exfiltrating usable credentials.
- **Credential purposes are not enforced authorization.** Core enforces the grant's
  owner, audience, once-or-standing mode, expiry, revocation, and audit. The stated
  purpose travels with the credential as an instruction to the model and an audit
  field; core does not determine whether a later command stays within that purpose.
  Once a credential is materialized into a sandbox, the purpose text does not confine
  how a compromised agent process can use it.
- **Security screening is incomplete and heuristic.** Auto screens supported,
  provenance-labelled external text and supported tool results. Command and
  background-process output, opaque or multimodal results, raw webhook payloads, and
  replay remediation across a shadow-to-enforcement cutover are not all covered.
  Classifier approval is not authorization and cannot guarantee prompt-injection
  resistance.
- **Audience-floor filtering has known gaps.** Model-context entries do not yet carry
  complete origin labels for every granted read, so mixed-permission filtering is
  incomplete. The ambient Slack judge path also does not yet repeat the full
  internal-only check used by addressed turns.
- **Egress enforcement is conditional.** Force-through egress depends on backend
  network enforcement, and core does not yet reject every backend that is too coarse
  for the requested policy. Deployment-runtime egress enforcement is not built.
- **Admins can read sensitive content.** A scope-authorized admin can directly read
  transcripts, captured provider requests, documents, memory, connector and keychain
  metadata, mirrored message bodies, ambient-judge inputs, user details, and skill
  bodies. The read is audited, not separately consent-gated.
- **Durable data can outlive user expectations.** Sessions, memory, and exact model
  request captures persist when durable stores are enabled, and request capture is on
  by default. File artifacts have no expiry, and artifact retirement and byte
  reclamation are not implemented, so artifacts and deduplicated bytes can accumulate
  indefinitely.
- **Published-app capability links are bearer authorization.** Anyone who obtains a
  link can reach that app without establishing an identity, and the link is not bound
  to an intended recipient. The gateway removes the token from the address bar and
  places it in a one-day browser cookie, but copied links remain usable and app ACL
  changes do not revoke individual link holders.
- **Portal sessions have residual risk.** A signed portal session defaults to eight
  hours and renews on use. Logout clears the browser cookie but cannot revoke an
  already copied session token before its expiration.
- **Some model-provider paths bypass the intended gateway.** The ambient Slack judge's
  model call does not yet use the ModelGateway, and the OpenCode adapter currently
  supplies its provider key to the supervised sidecar.
- **Some governance and data-loss controls are absent.** Standing-instruction edits
  are not uniformly bounded by an org floor or human approval, governance changes are
  not uniformly versioned or revertible, provider-side token revocation and an org
  kill switch are incomplete, and secret scanning on file write is not implemented.

## Dependency cooldown

The release workflow requires `RELEASE_SETTINGS_TOKEN`, a fine-grained token or GitHub
App token with repository Administration read access. It uses that token only to require
the versioned immutable-releases endpoint to report `enabled: true` and to verify the
structures of the release tag rulesets before irreversible work and immediately before npm
and GitHub publication. It never changes repository settings.

Release tags require `RELEASE_TAG_TOKEN`, a fine-grained Contents write token belonging to
a dedicated machine user. Two distinct active repository tag rulesets must each include
exactly `refs/tags/v*` and exclude no refs. One contains only the creation restriction and
grants its sole `always` bypass to that machine user. The other contains only update and
deletion restrictions and has no bypass actors. The workflow first uses the token to
validate that it resolves to a user account, then uses it to create the annotated tag
object and ref, after which even that actor cannot move or delete it.
GitHub's REST API omits bypass actors from ruleset responses for Administration read
credentials, so the workflow verifies both enforceable structures but cannot prove either
bypass list. Repository administrators must establish and audit the sole creation bypass
and empty lock bypass out of band; dispatch remains contingent on that operator control.

Fresh tag, release, and asset checks prevent a raced draft from reaching image aliases or
npm `latest`, but they cannot make GitHub's draft publication atomic or undo a published
npm version. The tag rulesets prevent ordinary Contents writers from racing or moving the
tag. A compromised creation actor can preempt a not-yet-created tag, a writer can race a
draft asset, and an administrator can race a settings change; each can still strand a
version. Post-publication checks detect that state and stop promotion rather than prevent
the denial of service. Restrict those privileges as an operational trust boundary. Enable
release immutability and configure both release credentials and both rulesets before
dispatching a release.

To blunt npm supply-chain attacks (compromised maintainer publishes a malicious
version that is caught and yanked within hours), newly published package versions must
age for **7 days** before they can enter a lockfile. This is enforced by
`min-release-age=7` in `.npmrc` (honored by npm ≥ 11.10.0, pinned via `.node-version`).
The cooldown gates `npm install`/`npm update`; CI installs with `npm ci` from the
committed lockfiles and is unaffected. Pulling an urgent security fix ahead of the
window requires both an exact reviewed version and an explicit `min-release-age=0`
override.

`qm update --yes --version <version>` has a separate trust boundary. It accepts only
the exact stable package currently promoted on npm's `latest` tag and requires the
native npm bundled with Node to be `>=11.12.0 and <12`. Using a private home,
temporary directory, and cache, it downloads that package from the official registry
with lifecycle scripts disabled, verifies its npm signatures and SLSA attestation
against QM's official release workflow and source commit, and checks its embedded
image manifest. Only then does that trusted native npm install the exact dependency
from the private cache without network access. npm owns the resulting `package.json`,
`package-lock.json`, and `node_modules` changes; QM does not implement a parallel
package transaction. The automatic path requires an existing exact registry pin and
refuses a local package link; normalize a source checkout through its ordinary
trusted package-manager workflow first.

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

An update is same-owner, exclusive maintenance for its deployment directory. Finish
every other QM CLI command and package-manager write before starting it, and do not
start either kind of operation until the update exits. Admin is a read-only npm
`latest` notice; the operator runs the exact version-pinned command it reports. There
is no updater journal, atomicity claim, or rollback. After any forced kill, confirm
that no descendant npm, Node/QM, Docker, Fly, AWS, or other provider process remains
before repairing the package or running a recovery command. If npm is interrupted,
inspect the checkout and repair it with version control and the trusted npm workflow,
normally by restoring `package.json` and `package-lock.json` and running
`npm ci --ignore-scripts`, before retrying. If the later provider `up` fails, the new
verified exact pin remains in place.
On Docker or Fly, reconcile it with `npm exec --yes=false -- qm up`; on AWS, use
`npm exec --yes=false -- qm up --yes`. Then review and commit the durable tracked
changes.

The exact direct Node command above is retryable only while that version remains npm
`latest`.

Legacy `sandbox.env` and `sandbox.secretEnv` need an operator-controlled credential
migration before an update. Direct Sprites has no resident environment injection, so
QM cannot infer a safe replacement destination. Move each value or credential to the
supported tool, skill, connector, or keychain delivery path used by its consumer,
verify that consumer can use the replacement, remove the legacy fields, and roll the
deployment. After verifying the live consumer, finish the target-specific cleanup. On
Fly, confirm the affected app rollout no longer references the old injection, then
delete each `FLY_RESIDENT_ENV_<name>` app secret. On AWS, confirm the new task
definition no longer references the old injection, then delete each original
`${aws.secretsPrefix}<name>` entry from Secrets Manager. On Docker, complete the
replacement container rollout, then remove each original `<name>` from the
deployment's `.env` or other environment source. QM neither deletes those sources
automatically nor treats a legacy field as acknowledgement that the migration
happened. This cleanup is separate from revoking and deleting the retired source
credential `FLY_SANDBOX_API_TOKEN` and unsetting its deployed core `FLY_API_TOKEN`
alias below.

## Legacy update workflow

Deployments that used the retired Admin-dispatched GitHub workflow must first cancel
every queued or running job for every configured or detected legacy workflow,
including renamed copies, and wait for every job to reach a terminal status. Deleting
or disabling a workflow, removing Admin configuration, or redeploying Admin does not
cancel an already queued job. After all jobs are terminal, remove every workflow copy
and all `QM_UPDATE_GITHUB_*` settings, delete the GitHub repository secret
`QM_DEPLOY_ENV`, revoke the old GitHub token and remove its
`QM_UPDATE_GITHUB_TOKEN` copy from the Admin app and every other resident secret
store, then revoke and delete the retired source credential
`FLY_SANDBOX_API_TOKEN` from every repository, host, and CI secret store and unset
its deployed core `FLY_API_TOKEN` alias.

## Supported versions

Security fixes are made on the latest release and the `main` branch. Older releases
may require upgrading.

Public source releases must start from a fresh export; publishing a private
repository's existing history is explicitly unsupported.
