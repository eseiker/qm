import { isStrongSigningSecret } from "../auth/source-auth.ts";

type SecretGate =
  | "production"
  | "real-harness"
  | "codex"
  | "postgres"
  | "sprites"
  | "smolmachines"
  | "porter"
  | "porter-deploy"
  | "fly-deploy"
  | "deploy-apps-domain"
  | "google-oauth"
  | "dropbox-oauth"
  | "linear-oauth"
  | "email-auth"
  | "model-anthropic"
  | "model-openai"
  | "model-openrouter";

export interface RuntimeSecretSpec {
  name: string;
  requiredWhen: SecretGate | readonly SecretGate[];
}

export const CORE_SECRET_SPECS: readonly RuntimeSecretSpec[] = [
  { name: "CAPABILITY_SECRET", requiredWhen: "production" },
  { name: "CONNECTOR_SECRET_KEY", requiredWhen: "production" },
  { name: "CORE_SIGNING_SECRET", requiredWhen: "production" },
  { name: "PORTAL_IDENTITY_SECRET", requiredWhen: "production" },
  { name: "SKILL_SIGNING_SECRET", requiredWhen: "production" },
  { name: "AUTH_ALLOWED_EMAILS", requiredWhen: "email-auth" },
  { name: "PUBLIC_API_URL", requiredWhen: "real-harness" },
  { name: "OPENAI_API_KEY", requiredWhen: ["codex", "model-openai"] },
  { name: "ANTHROPIC_API_KEY", requiredWhen: "model-anthropic" },
  { name: "OPENROUTER_API_KEY", requiredWhen: "model-openrouter" },
  { name: "DATABASE_URL", requiredWhen: "postgres" },
  { name: "SPRITES_TOKEN", requiredWhen: "sprites" },
  { name: "SMOLMACHINES_TOKEN", requiredWhen: "smolmachines" },
  { name: "PORTER_DEPLOY_API_TOKEN", requiredWhen: ["porter", "porter-deploy"] },
  { name: "FLY_DEPLOY_API_TOKEN", requiredWhen: "fly-deploy" },
  { name: "DEPLOY_APPS_SESSION_SECRET", requiredWhen: "deploy-apps-domain" },
  { name: "AWS_DEPLOY_GATE_SECRET", requiredWhen: "deploy-apps-domain" },
  { name: "GOOGLE_OAUTH_CLIENT_SECRET", requiredWhen: "google-oauth" },
  { name: "DROPBOX_OAUTH_CLIENT_SECRET", requiredWhen: "dropbox-oauth" },
  { name: "LINEAR_OAUTH_CLIENT_SECRET", requiredWhen: "linear-oauth" },
];

const GATE_PREDICATES: Readonly<Record<SecretGate, (env: NodeJS.ProcessEnv) => boolean>> = {
  production: (env) => env.NODE_ENV === "production",
  "real-harness": (env) => ["pi", "opencode", "codex", "claude"].includes(env.HARNESS?.trim() ?? ""),
  codex: (env) => env.HARNESS?.trim() === "codex" && !hasCodexHarnessAuth(env),
  postgres: (env) => env.SESSION_STORE === "postgres" || env.RUN_STORE === "postgres",
  sprites: (env) => env.SANDBOX_BACKEND?.trim() === "sprites" || env.SANDBOX_SECONDARY_BACKEND?.trim() === "sprites",
  smolmachines: (env) =>
    env.SANDBOX_BACKEND?.trim() === "smolmachines" || env.SANDBOX_SECONDARY_BACKEND?.trim() === "smolmachines",
  porter: (env) => env.SANDBOX_BACKEND?.trim() === "porter" || env.SANDBOX_SECONDARY_BACKEND?.trim() === "porter",
  "porter-deploy": (env) => env.DEPLOY_PROVIDER === "porter",
  "fly-deploy": (env) => env.DEPLOY_PROVIDER === "fly",
  "deploy-apps-domain": (env) => Boolean(env.AWS_DEPLOY_APPS_DOMAIN?.trim() || env.DEPLOY_APPS_DOMAIN?.trim()),
  "google-oauth": (env) => Boolean(env.GOOGLE_OAUTH_CLIENT_ID),
  "dropbox-oauth": (env) => Boolean(env.DROPBOX_OAUTH_CLIENT_ID),
  "linear-oauth": (env) => Boolean(env.LINEAR_OAUTH_CLIENT_ID),
  "email-auth": (env) => env.AUTH_ALLOWED_EMAILS !== undefined,
  "model-anthropic": (env) => env.MODEL_PROVIDER?.trim() === "anthropic",
  "model-openai": (env) =>
    env.MODEL_PROVIDER?.trim() === "openai" && !(env.HARNESS?.trim() === "codex" && hasCodexHarnessAuth(env)),
  "model-openrouter": (env) => env.MODEL_PROVIDER?.trim() === "openrouter",
};

function hasCodexHarnessAuth(env: NodeJS.ProcessEnv): boolean {
  return Boolean(env.CODEX_AUTH_CREDENTIAL?.trim() || (env.NODE_ENV !== "production" && env.CODEX_AUTH_FILE?.trim()));
}

function secretValue(name: string, env: NodeJS.ProcessEnv): string | undefined {
  if (name === "PUBLIC_API_URL") return env.PUBLIC_API_URL ?? env.AGENT_API_URL;
  if (name === "DEPLOY_APPS_SESSION_SECRET") return env.DEPLOY_APPS_SESSION_SECRET ?? env.PORTAL_SESSION_SECRET;
  return env[name];
}

export function validateCoreSecretEnv(env: NodeJS.ProcessEnv): string[] {
  const enabled = (spec: RuntimeSecretSpec): boolean => {
    const gates = typeof spec.requiredWhen === "string" ? [spec.requiredWhen] : spec.requiredWhen;
    return gates.some((gate) => GATE_PREDICATES[gate](env));
  };
  return CORE_SECRET_SPECS.filter(
    (spec) =>
      (enabled(spec) ||
        ((spec.name === "CAPABILITY_SECRET" || spec.name === "PORTAL_IDENTITY_SECRET") &&
          env[spec.name] !== undefined)) &&
      isInvalidSecret(spec.name, secretValue(spec.name, env)),
  ).map((spec) => spec.name);
}

function isInvalidSecret(name: string, value: string | undefined): boolean {
  const candidate = value?.trim();
  if (!candidate || /^(replace-me|placeholder|changeme|todo)$/i.test(candidate)) return true;
  return (
    (name === "CONNECTOR_SECRET_KEY" ||
      name === "CORE_SIGNING_SECRET" ||
      name === "SKILL_SIGNING_SECRET" ||
      name === "CAPABILITY_SECRET" ||
      name === "PORTAL_IDENTITY_SECRET" ||
      name === "DEPLOY_APPS_SESSION_SECRET" ||
      name === "AWS_DEPLOY_GATE_SECRET") &&
    !isStrongSigningSecret(candidate)
  );
}
