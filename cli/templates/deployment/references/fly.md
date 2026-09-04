# Fly.io deployment

Use this after the choices and billing confirmation in `deployment.md`.

## Preflight

New structured Fly deployments use Sprites. Existing deployments whose legacy
`env.core.SANDBOX_BACKEND` selects Porter or SmolMachines retain that provider and its
credentials; routine deployment and update work must not switch their substrate.

For the new Sprites path, require authenticated Flyctl, a Sprites token, and permission
to create apps, Managed Postgres, and private object storage:

```bash
fly auth whoami
fly orgs list
sprite login
```

Set `flyOrg`, `region`, globally unique `appPrefix`, `publicUrl`, and the new
deployment's `sandbox.namePrefix`. The public origin is normally
`https://<app-prefix>-portal.fly.dev`. Confirm the service app names are
available in the selected organization.

`sandbox.namePrefix` is the only explicit durable Sprite namespace selector.
Legacy `sandbox.app` may remain beside a migrated `sandbox.namePrefix`, but it stays
inert and neither selects nor overrides the prefix. `sandbox.image` and
`sandbox.baseImage` also do not select an image on this path; without an explicit
prefix, the runtime preserves the historical `qm` namespace. Migrate a legacy
`env.core.SPRITES_NAME_PREFIX` value byte-for-byte to `sandbox.namePrefix`. Changing
that value is a planned data migration, and old Sprites under the previous prefix must
not be deleted as cleanup.

Direct Sprites has no replacement for legacy resident `sandbox.env` or
`sandbox.secretEnv`. Move every value and credential to the supported tool, skill,
connector, or keychain delivery path used by its consumer and verify it can use the
replacement. Remove the legacy fields and roll the affected app. After verifying the
live consumer and confirming the rollout no longer references the old injection,
delete each `FLY_RESIDENT_ENV_<name>` secret from that Fly app. Field presence never
authorizes automatic deletion or acknowledges a completed migration. Revoking and
deleting the retired source credential `FLY_SANDBOX_API_TOKEN` and unsetting its
deployed core `FLY_API_TOKEN` alias are separate cleanup items.

On the Sprites path, copy the token into `SPRITES_TOKEN` when setup prompts for it:

```bash
npm exec --yes=false -- qm setup .
npm exec --yes=false -- qm slack render
npm exec --yes=false -- qm check
```

The Sprites token is separate from Flyctl's control-plane credentials. When Sprites is
the effective backend, Fly agent computers are managed directly through the Sprites API
using that token and the configured name prefix. They neither publish nor consume an
OCI sandbox image; `sandbox publish` is retired and rejected.

## Deploy

```bash
npm exec --yes=false -- qm secrets push
npm exec --yes=false -- qm plan
npm exec --yes=false -- qm up
npm exec --yes=false -- qm doctor
npm exec --yes=false -- qm check --live
```

`secrets push` ownership-marks service apps before delivering secrets. When
storage credentials or `DATABASE_URL` are absent, deployment creates or reuses
private Tigris and Managed Postgres.
`check --live` proves service health and durable object storage.

After the first successful deployment, rerun `npm exec --yes=false -- qm up` and confirm it
reconciles the same apps.

## Agent-computer proof

Use the exact signed-in principal to select one Sprite by its generated scope
name. Read `/home/sprite/workspace/qm-computer-proof.txt` and require it to match the
UUID created in the browser. A missing or ambiguous scope match is a failed
proof.

For a retained Porter or SmolMachines backend, use that provider's authenticated
control plane to select the exact generated personal scope and read the same proof file.
Do not guess a scope from a display name; a missing or ambiguous match is a failed proof.

Routine operations:

```bash
npm exec --yes=false -- qm status
npm exec --yes=false -- qm logs core --follow
npm exec --yes=false -- qm down
```

`down` stops the control-plane apps. It does not authorize deleting Postgres,
object storage, or Sprites.
