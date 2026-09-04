# Local sandbox base

`fly/Dockerfile` builds the tool-rich base used by Docker's local sandbox wrapper.
Build the complete local image with:

```bash
npm run sandbox:local:build
```

Deployments whose effective sandbox backend is Sprites on Fly, Docker, or AWS use the
Sprites API with `SPRITES_TOKEN`; Sprites does not consume this OCI image. Docker's
local sandbox build is separate. Every AWS target still builds its packaged
deployment-publisher MicroVM image for `DEPLOY_PROVIDER=aws`; an AWS Lambda MicroVM
agent backend reuses that pin, while Sprites does not.

Direct Sprites also has no resident environment injection. Before removing legacy
`sandbox.env` or `sandbox.secretEnv`, move every value and credential to the supported
tool, skill, connector, or keychain delivery path for its consumer and verify it can
use the replacement. Remove the legacy fields and roll the deployment. After
verifying the live consumer, finish target-specific cleanup. On Fly, confirm the
affected app rollout no longer references the old injection, then delete each
`FLY_RESIDENT_ENV_<name>` app secret. On AWS, confirm the new task definition no longer
references the old injection, then delete each original
`${aws.secretsPrefix}<name>` entry from Secrets Manager. On Docker, complete the
replacement container rollout, then remove each original `<name>` from the
deployment's `.env` or other environment source. The fields do not authorize
automatic deletion or acknowledge that migration is complete. This is separate from
revoking and deleting the retired source credential `FLY_SANDBOX_API_TOKEN` and
unsetting its deployed core `FLY_API_TOKEN` alias.
