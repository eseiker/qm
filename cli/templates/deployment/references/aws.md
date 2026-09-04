# AWS deployment

Use this after the choices and billing confirmation in `deployment.md`.
Terraform state, credentials, and every resource must belong to the operator.

## Preflight

Require Terraform, Docker, authenticated AWS credentials, and two available AZs:

```bash
export AWS_PROFILE=<profile>
aws sts get-caller-identity
aws ec2 describe-availability-zones --region <region> \
  --filters Name=state,Values=available
terraform version
docker buildx version
```

Every AWS deployment uses a Lambda MicroVM as the runner for
`DEPLOY_PROVIDER=aws` bundled-app publishing. Verify API support before mutation:

```bash
aws lambda-microvms list-microvm-images --region <region>
```

If Lambda MicroVMs are unavailable, stop and offer a non-AWS hosting target. Selecting
Sprites, Porter, or SmolMachines for agent computers does not remove the publisher
runner requirement.

Choose the agent-computer backend separately. Omitting `sandbox` or setting
`sandbox.backend: "aws"` uses the same AWS deployment-image pin for agent computers.
`sandbox.backend: "sprites"` uses direct Sprites and may select its durable namespace
with `sandbox.namePrefix`; it needs a token from `sprite login`, which `qm setup` stores
as the `SPRITES_TOKEN` deployment secret. Existing Porter and SmolMachines selections
remain external agent-computer backends. None of those external backends consumes an
OCI sandbox image or uses `AWS_DEPLOY_IMAGE` for agent computers.

`sandbox.namePrefix` is the only explicit Sprite namespace selector. Legacy
`sandbox.app` may remain beside a migrated `sandbox.namePrefix`, but it stays inert and
neither selects nor overrides the prefix. `sandbox.image` and `sandbox.baseImage` also
do not select an image on this path; without an explicit prefix, the runtime preserves
the historical `qm` namespace.
Migrate a legacy `env.core.SPRITES_NAME_PREFIX` value byte-for-byte to
`sandbox.namePrefix`. Changing that value is a planned data migration, and old Sprites
under the previous prefix must not be deleted as cleanup.

Direct Sprites has no replacement for legacy resident `sandbox.env` or
`sandbox.secretEnv`. Move every value and credential to the supported tool, skill,
connector, or keychain delivery path used by its consumer and verify it can use the
replacement. Remove the legacy fields and roll the affected ECS tasks. After verifying
the live consumer and confirming the new task definitions no longer reference the old
injection, delete the original `${aws.secretsPrefix}<name>` entries from AWS Secrets
Manager. Field presence never authorizes automatic deletion or acknowledges a
completed migration. Revoking and deleting the retired source credential
`FLY_SANDBOX_API_TOKEN` and unsetting its deployed core `FLY_API_TOKEN` alias are
separate cleanup items.

Set the account, region, service coordinates, and an operator-owned GitHub repository
and exact branch in the generated config and Terraform variables. Never trust the
upstream QM repository.

Configure a private encrypted Terraform backend, then:

```bash
npm exec --yes=false -- qm infra render
terraform -chdir=infra init
terraform -chdir=infra plan -out=qm.tfplan
terraform -chdir=infra apply qm.tfplan
```

Set `publicUrl`, `env.core.AWS_PUBLIC_ORIGIN_URL`, and `aws.deployRoleArn` from
the Terraform outputs. Finish `npm exec --yes=false -- qm setup .`, render again, and apply.

## Prepare the publisher runner and agent computer

Build the deterministic `AWS_DEPLOY_IMAGE` before the first deployment:

```bash
npm exec --yes=false -- qm infra build-image
```

`DEPLOY_PROVIDER=aws` uses that Lambda MicroVM image to publish and run bundled apps,
regardless of whether agent computers use Lambda MicroVMs, Sprites, Porter, or
SmolMachines. When the agent backend is AWS Lambda MicroVM, the same image pin also
backs agent computers. Then deploy through the normal control-plane path:

```bash
npm exec --yes=false -- qm check
npm exec --yes=false -- qm secrets push
npm exec --yes=false -- qm doctor
npm exec --yes=false -- qm plan
npm exec --yes=false -- qm up --yes
npm exec --yes=false -- qm check --live
```

Confirmed `up` also rebuilds a missing or stale deployment-publisher image after
read-only preflight for every AWS target. Sprites is managed directly with its token
and configured name prefix; Porter and SmolMachines use their own agent-computer
coordinates. Those external agent backends do no OCI sandbox-image work, but they do
not remove the AWS publisher-image requirement. `sandbox publish` is retired and
rejected for every path.

Existing deployments created before private session canaries must rerun
`npm exec --yes=false -- qm infra render`, review the Terraform plan, and apply it with
infrastructure-administrator credentials before enabling `check --live`. This
adds the deploy role's stack-scoped permission to run and inspect the one-off
core canary task.

The package image manifest supplies first-party control-plane images. The AWS
backend transfers them into deployment-owned ECR and records immutable digests.
After the first successful deployment, rerun `npm exec --yes=false -- qm up --yes` and
confirm it reconciles the same stack.

## Agent-computer proof

For Sprites, use the exact signed-in principal to select one Sprite by its generated
scope name. Read `/home/sprite/workspace/qm-computer-proof.txt` and require it to match
the UUID created in the browser. A missing or ambiguous scope match is a failed proof.

For Lambda MicroVMs, copy the exact personal scope id shown for the signed-in
administrator in Admin, then derive the same opaque storage key as the runtime and read
only the proof file from the deployment-owned S3 home snapshot:

```bash
scope_id='personal:<exact-admin-principal>'
scope_key="$(npm exec --yes=false -- qm proof scope-key "$scope_id")"
bucket="$(terraform -chdir=infra output -raw object_store_bucket)"
aws --region <region> s3 cp \
  "s3://$bucket/sandbox-home/$scope_key.tar" - |
  tar -xOf - workspace/qm-computer-proof.txt
```

Require the output to match the UUID created in the browser. A missing or
ambiguous scope, snapshot, or file is a failed proof.

For a retained Porter or SmolMachines backend, use that provider's authenticated
control plane to select the exact generated personal scope and read the same proof file.
Do not guess a scope from a display name; a missing or ambiguous match is a failed proof.

Routine operations:

```bash
npm exec --yes=false -- qm status
npm exec --yes=false -- qm logs core --follow
npm exec --yes=false -- qm rollback --to <release-label-or-manifest-id>
npm exec --yes=false -- qm down
```

Terraform destroy is separate and destructive. Decide how to retain RDS
snapshots, S3 objects, and secrets before following the generated `AGENTS.md`
teardown section.
