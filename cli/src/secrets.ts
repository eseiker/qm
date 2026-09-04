import { isVirtualService, virtualServiceEnv, type DeclaredServiceName } from "./services.ts";
import { effectiveModelProvider, validatePortalTrust, type ModelProvider, type QmConfig } from "./config.ts";
import { TARGET_ENV_DEFAULTS } from "./target-env-defaults.ts";
import { CliError } from "./log.ts";
import { canonicalHttpOrigin, invalidSecretNames } from "./util.ts";

type SecretCondition =
  | { kind: "env-equals"; service: DeclaredServiceName; name: string; value: string }
  | { kind: "env-in"; service: DeclaredServiceName; name: string; values: string[] }
  | { kind: "env-absent"; service: DeclaredServiceName; name: string }
  | { kind: "env-all-absent"; service: DeclaredServiceName; names: string[] }
  | { kind: "env-present"; service: DeclaredServiceName; name: string }
  | { kind: "service-enabled"; service: DeclaredServiceName }
  | { kind: "service-absent"; service: DeclaredServiceName }
  | { kind: "all"; conditions: SecretCondition[] }
  | { kind: "any"; conditions: SecretCondition[] }
  | { kind: "target"; target: QmConfig["target"] }
  | { kind: "model-provider"; provider: ModelProvider };

export interface SecretSpec {
  name: string;
  service: DeclaredServiceName;
  envName?: string;
  required: boolean | { when: SecretCondition; optionalOtherwise?: true };
  description: string;
  generate?: string;
  managedBy?: "operator" | "terraform";
}

export interface ComputedSecret {
  name: string;
  services: string[];
  description: string;
  required: boolean;
  generate?: string;
  managedBy: "operator" | "terraform";
  aliases?: Array<{ service: DeclaredServiceName; name: string }>;
}

export interface SecretConditionSelector {
  service: DeclaredServiceName;
  name: string;
  mode: "presence-only" | "value-inspected";
}

export interface MissingSecretDestination {
  storeName: string;
  workload: string;
  name: string;
}

export interface MaterializedSecretValues {
  runtimeValues: Map<string, Map<string, string>>;
  missingRequiredDestinations: MissingSecretDestination[];
}

export interface MaterializeSecretValueOptions {
  completeness: "partial" | "complete";
  managedBy: "all" | ComputedSecret["managedBy"];
}

export const MINT_LOCALLY = "openssl rand -hex 32";
export const MINT_JWK =
  "node -e \"const {generateKeyPairSync}=require('node:crypto');process.stdout.write(JSON.stringify(generateKeyPairSync('ec',{namedCurve:'P-256'}).privateKey.export({format:'jwk'})))\"";

export const FIRST_PARTY_SECRET_SPECS: readonly SecretSpec[] = [
  {
    name: "ANTHROPIC_API_KEY",
    service: "core",
    required: { when: { kind: "model-provider", provider: "anthropic" }, optionalOtherwise: true },
    description:
      'Anthropic API key: bills the base model when modelProvider is "anthropic", an optional deployment fallback otherwise.',
  },
  {
    name: "OPENROUTER_API_KEY",
    service: "core",
    required: { when: { kind: "model-provider", provider: "openrouter" }, optionalOtherwise: true },
    description:
      'OpenRouter API key: bills the base model when modelProvider is "openrouter", an optional deployment fallback otherwise.',
  },
  {
    name: "OPENAI_API_KEY",
    service: "core",
    required: {
      when: {
        kind: "all",
        conditions: [
          {
            kind: "any",
            conditions: [
              { kind: "env-equals", service: "core", name: "HARNESS", value: "codex" },
              { kind: "model-provider", provider: "openai" },
            ],
          },
          {
            kind: "any",
            conditions: [
              { kind: "env-absent", service: "core", name: "HARNESS" },
              {
                kind: "env-in",
                service: "core",
                name: "HARNESS",
                values: ["mock", "pi", "opencode", "claude"],
              },
              {
                kind: "env-all-absent",
                service: "core",
                names: ["CODEX_AUTH_CREDENTIAL"],
              },
            ],
          },
        ],
      },
    },
    description:
      'OpenAI API key: the Codex harness needs it (its CLI cannot do browser OAuth in a container), and it bills the base model when modelProvider is "openai".',
  },
  {
    name: "PUBLIC_API_URL",
    service: "core",
    required: {
      when: { kind: "env-in", service: "core", name: "HARNESS", values: ["pi", "opencode", "codex", "claude"] },
    },
    description: "Public core self-API URL reachable from agent sandboxes.",
  },
  {
    name: "CORE_SIGNING_SECRET",
    service: "core",
    required: true,
    description: "HMAC key shared by core and surface plugins.",
    generate: MINT_LOCALLY,
  },
  {
    name: "CAPABILITY_SECRET",
    service: "core",
    required: true,
    description: "Signing key for scoped agent capabilities and egress grants; must differ from every other key.",
    generate: MINT_LOCALLY,
  },
  {
    name: "PORTAL_IDENTITY_SECRET",
    service: "core",
    required: true,
    description: "Signing key for portal-bound user identity; must differ from every other key.",
    generate: MINT_LOCALLY,
  },
  {
    name: "CONNECTOR_SECRET_KEY",
    service: "core",
    required: true,
    description: "Encryption key for durable connector credentials; must differ from every other key.",
    generate: MINT_LOCALLY,
  },
  {
    name: "SKILL_SIGNING_SECRET",
    service: "core",
    required: true,
    description: "Stable signing key for reviewed skills.",
    generate: MINT_LOCALLY,
  },
  {
    name: "FLY_DEPLOY_API_TOKEN",
    service: "core",
    required: { when: { kind: "env-equals", service: "core", name: "DEPLOY_PROVIDER", value: "fly" } },
    description: "Fly organization token used only by qm's opt-in per-deployment app publisher.",
    generate: "fly tokens create org -o <fly-org> -x 8760h",
  },
  {
    name: "PORTER_DEPLOY_API_TOKEN",
    service: "core",
    required: {
      when: {
        kind: "any",
        conditions: [
          { kind: "env-equals", service: "core", name: "SANDBOX_BACKEND", value: "porter" },
          { kind: "env-equals", service: "core", name: "SANDBOX_SECONDARY_BACKEND", value: "porter" },
          { kind: "env-equals", service: "core", name: "DEPLOY_PROVIDER", value: "porter" },
        ],
      },
    },
    description:
      "Admin-role Porter API token for the sandbox backend and the per-deployment app publisher — Developer-role tokens fail mid-deployment with PERMISSION_DENIED.",
    generate:
      "create an Admin-role API token in the Porter dashboard (https://dashboard.porter.run → Settings → API tokens)",
  },
  {
    name: "SPRITES_TOKEN",
    service: "core",
    required: {
      when: {
        kind: "any",
        conditions: [
          { kind: "env-equals", service: "core", name: "SANDBOX_BACKEND", value: "sprites" },
          { kind: "env-equals", service: "core", name: "SANDBOX_SECONDARY_BACKEND", value: "sprites" },
        ],
      },
    },
    description: "Fly Sprites API token for the agent-computer substrate.",
    generate: "sprite login   # then copy the token from ~/.sprite/credentials",
  },
  {
    name: "SMOLMACHINES_TOKEN",
    service: "core",
    required: {
      when: {
        kind: "any",
        conditions: [
          { kind: "env-equals", service: "core", name: "SANDBOX_BACKEND", value: "smolmachines" },
          { kind: "env-equals", service: "core", name: "SANDBOX_SECONDARY_BACKEND", value: "smolmachines" },
        ],
      },
    },
    description: "smolmachines API key for the agent-computer substrate.",
    generate: "create an API key in the smolmachines console (https://smolmachines.com/console)",
  },
  {
    name: "DATABASE_URL",
    service: "core",
    required: { when: { kind: "target", target: "aws" } },
    description: "Postgres connection string for durable state.",
    managedBy: "terraform",
  },
  {
    name: "DATABASE_CA_CERT",
    service: "core",
    required: false,
    description:
      "Extra root CA (PEM content) trusted for the Postgres connection, for providers that pin a private root (e.g. Supabase's pooler). Verification stays on.",
  },
  {
    name: "AWS_DEPLOY_GATE_SECRET",
    service: "core",
    required: {
      when: {
        kind: "any",
        conditions: [
          { kind: "env-present", service: "core", name: "AWS_DEPLOY_APPS_DOMAIN" },
          { kind: "env-present", service: "core", name: "DEPLOY_APPS_DOMAIN" },
        ],
      },
    },
    description: "HMAC key protecting public deployment-app URLs on the apps domain.",
    generate: MINT_LOCALLY,
  },
  {
    name: "GOOGLE_OAUTH_CLIENT_SECRET",
    service: "core",
    required: { when: { kind: "env-present", service: "core", name: "GOOGLE_OAUTH_CLIENT_ID" } },
    description: "Google OAuth client secret.",
  },
  {
    name: "DROPBOX_OAUTH_CLIENT_SECRET",
    service: "core",
    required: { when: { kind: "env-present", service: "core", name: "DROPBOX_OAUTH_CLIENT_ID" } },
    description: "Dropbox OAuth client secret.",
  },
  {
    name: "LINEAR_OAUTH_CLIENT_SECRET",
    service: "core",
    required: { when: { kind: "env-present", service: "core", name: "LINEAR_OAUTH_CLIENT_ID" } },
    description: "Linear OAuth client secret.",
  },
  {
    name: "SLACK_BOT_TOKEN",
    service: "slack",
    required: false,
    description: "Optional at first deploy; Slack bot OAuth token.",
  },
  {
    name: "SLACK_APP_TOKEN",
    service: "slack",
    required: false,
    description: "Optional at first deploy; Slack Socket Mode app token.",
  },
  {
    name: "SLACK_SIGNING_SECRET",
    service: "slack",
    required: { when: { kind: "env-equals", service: "slack", name: "SLACK_EVENTS_MODE", value: "http" } },
    description: "Slack request-signing secret (from the Slack app's Basic Information page); HTTP events mode only.",
  },
  {
    name: "CORE_SIGNING_SECRET",
    service: "slack",
    required: true,
    description: "HMAC key shared by core and surface plugins.",
    generate: MINT_LOCALLY,
  },
  {
    name: "CORE_SIGNING_SECRET",
    service: "web-ui",
    required: true,
    description: "HMAC key shared by core and surface plugins.",
    generate: MINT_LOCALLY,
  },
  {
    name: "CORE_SIGNING_SECRET",
    service: "admin",
    required: true,
    description: "HMAC key shared by core and surface plugins.",
    generate: MINT_LOCALLY,
  },
  {
    name: "OIDC_CLIENT_ID",
    service: "portal",
    required: {
      when: {
        kind: "all",
        conditions: [
          { kind: "service-absent", service: "auth" },
          { kind: "env-absent", service: "portal", name: "OIDC_CLIENT_ID" },
        ],
      },
    },
    description: "Deployment-specific OIDC client identifier when it should not be committed.",
  },
  {
    name: "OIDC_CLIENT_SECRET",
    service: "portal",
    required: { when: { kind: "service-absent", service: "auth" } },
    description:
      "Client secret issued by an external identity provider; the built-in auth broker mints its own instead.",
  },
  {
    name: "PORTAL_EXPECTED_TEAM_ID",
    service: "portal",
    required: {
      when: {
        kind: "all",
        conditions: [
          { kind: "service-absent", service: "auth" },
          {
            kind: "env-all-absent",
            service: "portal",
            names: ["OIDC_ALLOWED_EMAILS", "OIDC_ALLOWED_EMAIL_DOMAIN", "PORTAL_EXPECTED_TEAM_ID"],
          },
        ],
      },
    },
    description: "Deployment-specific OIDC workspace trust boundary when it should not be committed.",
  },
  {
    name: "PORTAL_SESSION_SECRET",
    service: "portal",
    required: true,
    description: "Cookie-signing secret for portal sessions.",
    generate: MINT_LOCALLY,
  },
  {
    name: "PORTAL_SESSION_SECRET",
    service: "core",
    envName: "DEPLOY_APPS_SESSION_SECRET",
    required: {
      when: {
        kind: "all",
        conditions: [
          { kind: "service-enabled", service: "portal" },
          {
            kind: "any",
            conditions: [
              { kind: "env-present", service: "core", name: "DEPLOY_APPS_DOMAIN" },
              { kind: "env-present", service: "core", name: "AWS_DEPLOY_APPS_DOMAIN" },
            ],
          },
        ],
      },
    },
    description: "Cookie-signing secret shared with core for deployment-app sign-in redirects.",
  },
  {
    name: "CORE_SIGNING_SECRET",
    service: "portal",
    required: true,
    description: "HMAC key shared by core and surface plugins.",
    generate: MINT_LOCALLY,
  },
  {
    name: "PORTAL_IDENTITY_SECRET",
    service: "portal",
    required: true,
    description: "Signing key shared with core for portal-bound user identity.",
    generate: MINT_LOCALLY,
  },
  {
    name: "PORTAL_IDENTITY_SECRET",
    service: "web-ui",
    required: true,
    description: "Signing key shared with core for portal-bound user identity.",
    generate: MINT_LOCALLY,
  },
  {
    name: "PORTAL_IDENTITY_SECRET",
    service: "admin",
    required: true,
    description: "Signing key shared with core for portal-bound user identity.",
    generate: MINT_LOCALLY,
  },
  {
    name: "CORE_SIGNING_SECRET",
    service: "auth",
    required: true,
    description: "HMAC key shared by core and surface plugins.",
    generate: MINT_LOCALLY,
  },
  {
    name: "AUTH_SIGNING_JWK",
    service: "auth",
    required: true,
    description:
      "P-256 private JSON Web Key the broker signs id_tokens with; the portal verifies it through the broker's JWKS.",
    generate: MINT_JWK,
  },
  {
    name: "AUTH_TOKEN_SECRET",
    service: "auth",
    required: true,
    description:
      "Key the broker seals sign-in links, authorization codes, and access tokens with; must differ from every other key.",
    generate: MINT_LOCALLY,
  },
  {
    name: "AUTH_CLIENT_SECRET",
    service: "auth",
    required: true,
    description: "Client secret the portal presents to the built-in auth broker; the CLI generates it for both sides.",
    generate: MINT_LOCALLY,
  },
  {
    name: "AUTH_CLIENT_SECRET",
    service: "portal",
    envName: "OIDC_CLIENT_SECRET",
    required: { when: { kind: "service-enabled", service: "auth" } },
    description: "Client secret the portal presents to the built-in auth broker.",
  },
  {
    name: "AUTH_ALLOWED_EMAILS",
    service: "auth",
    required: { when: { kind: "env-absent", service: "auth", name: "AUTH_ALLOWED_EMAIL_DOMAIN" } },
    description: "Comma-separated email addresses allowed to sign in through the built-in broker.",
  },
  {
    name: "AUTH_ALLOWED_EMAILS",
    service: "core",
    required: {
      when: {
        kind: "all",
        conditions: [
          { kind: "service-enabled", service: "auth" },
          { kind: "env-absent", service: "auth", name: "AUTH_ALLOWED_EMAIL_DOMAIN" },
        ],
      },
    },
    description: "Email-auth principals protected from unrelated directory-source deactivation.",
  },
  {
    name: "AUTH_ALLOWED_EMAILS",
    service: "portal",
    envName: "OIDC_ALLOWED_EMAILS",
    required: {
      when: {
        kind: "all",
        conditions: [
          { kind: "service-enabled", service: "auth" },
          { kind: "env-absent", service: "auth", name: "AUTH_ALLOWED_EMAIL_DOMAIN" },
        ],
      },
    },
    description: "Email addresses allowed to sign in; the portal enforces the same list the broker does.",
  },
  {
    name: "AUTH_EMAIL_FROM",
    service: "auth",
    required: true,
    description: 'Verified sender for sign-in links, e.g. "Acme <no-reply@acme.com>".',
  },
  {
    name: "RESEND_API_KEY",
    service: "auth",
    required: { when: { kind: "env-equals", service: "auth", name: "AUTH_EMAIL_TRANSPORT", value: "resend" } },
    description: "Resend API key used to deliver sign-in links.",
  },
  {
    name: "SMTP_HOST",
    service: "auth",
    required: { when: { kind: "env-equals", service: "auth", name: "AUTH_EMAIL_TRANSPORT", value: "smtp" } },
    description: "SMTP relay hostname used to deliver sign-in links.",
  },
  {
    name: "SMTP_USERNAME",
    service: "auth",
    required: { when: { kind: "env-equals", service: "auth", name: "AUTH_EMAIL_TRANSPORT", value: "smtp" } },
    description: "SMTP username for the sign-in-link relay.",
  },
  {
    name: "SMTP_PASSWORD",
    service: "auth",
    required: { when: { kind: "env-equals", service: "auth", name: "AUTH_EMAIL_TRANSPORT", value: "smtp" } },
    description: "SMTP password for the sign-in-link relay.",
  },
];

export const FIRST_PARTY_SECRET_NAMES = [...new Set(FIRST_PARTY_SECRET_SPECS.map((spec) => spec.name))].sort();
const FIRST_PARTY_SECRET_NAME_SET = new Set(FIRST_PARTY_SECRET_NAMES);

export function deploymentStoreSecretValue(
  name: string,
  fileValue: string | undefined,
  baseEnv: Readonly<NodeJS.ProcessEnv> = process.env,
): string | undefined {
  if (baseEnv.QM_DEPLOY_ENV_FILE_ONLY === "1") {
    return fileValue === undefined || fileValue.trim() === "" ? undefined : fileValue;
  }
  if (fileValue !== undefined && fileValue.trim() !== "") return fileValue;
  return FIRST_PARTY_SECRET_NAME_SET.has(name) ? baseEnv[name] : undefined;
}

export function secretConditionSelectors(): SecretConditionSelector[] {
  const selectors = new Map<string, SecretConditionSelector>();
  const add = (service: DeclaredServiceName, name: string, mode: SecretConditionSelector["mode"]): void => {
    const key = `${service}\u0000${name}`;
    const current = selectors.get(key);
    if (!current || mode === "value-inspected") selectors.set(key, { service, name, mode });
  };
  const walk = (condition: SecretCondition): void => {
    switch (condition.kind) {
      case "all":
      case "any":
        for (const nested of condition.conditions) walk(nested);
        return;
      case "model-provider":
        add("core", "MODEL_PROVIDER", "value-inspected");
        return;
      case "env-all-absent":
        for (const name of condition.names) add(condition.service, name, "presence-only");
        return;
      case "env-equals":
      case "env-in":
        add(condition.service, condition.name, "value-inspected");
        return;
      case "env-absent":
      case "env-present":
        add(condition.service, condition.name, "presence-only");
        return;
      case "service-enabled":
      case "service-absent":
      case "target":
        return;
      default:
        throw new Error("Unknown secret condition");
    }
  };
  for (const spec of FIRST_PARTY_SECRET_SPECS) {
    if (typeof spec.required !== "boolean") walk(spec.required.when);
  }
  return [...selectors.values()].sort((a, b) => a.service.localeCompare(b.service) || a.name.localeCompare(b.name));
}

function conditionMatches(config: QmConfig, condition: SecretCondition): boolean {
  if (condition.kind === "service-enabled") return config.services.includes(condition.service);
  if (condition.kind === "service-absent") return !config.services.includes(condition.service);
  if (condition.kind === "all") return condition.conditions.every((nested) => conditionMatches(config, nested));
  if (condition.kind === "any") return condition.conditions.some((nested) => conditionMatches(config, nested));
  if (condition.kind === "target") return config.target === condition.target;
  if (condition.kind === "model-provider") return effectiveModelProvider(config) === condition.provider;
  if (condition.kind === "env-all-absent") {
    const env = conditionEnvironment(config, condition.service, config.env);
    const secretEnv = conditionEnvironment(config, condition.service, config.secretEnv);
    return condition.names.every((name) => !env[name]?.trim() && secretEnv[name] === undefined);
  }
  const env = conditionEnvironment(config, condition.service, config.env);
  const secretEnv = conditionEnvironment(config, condition.service, config.secretEnv);
  const runtimeService = isVirtualService(condition.service) ? "core" : condition.service;
  const value = (env[condition.name] ?? targetEnvDefault(config, runtimeService, condition.name))?.trim();
  const secretBacked = secretEnv[condition.name] !== undefined;
  if (condition.kind === "env-absent") return !value && !secretBacked;
  if (condition.kind === "env-present") return Boolean(value) || secretBacked;
  if (condition.kind === "env-in") return value !== undefined && condition.values.includes(value);
  return value === condition.value;
}

function conditionEnvironment(
  config: QmConfig,
  service: DeclaredServiceName,
  source: Partial<Record<DeclaredServiceName, Record<string, string>>> | undefined,
): Record<string, string> {
  const env = source ?? {};
  if (service !== "core" && !isVirtualService(service)) return env[service] ?? {};
  return { ...virtualServiceEnv(config.services, env), ...env.core };
}

function targetEnvDefault(config: QmConfig, service: string, name: string): string | undefined {
  return TARGET_ENV_DEFAULTS[config.target](config, service, name);
}

function requirementFor(config: QmConfig, spec: SecretSpec): boolean | null {
  if (typeof spec.required === "boolean") return spec.required;
  if (conditionMatches(config, spec.required.when)) return true;
  return spec.required.optionalOtherwise ? false : null;
}

export function computedSecrets(config: QmConfig): ComputedSecret[] {
  const byName = new Map<string, ComputedSecret>();
  const firstPartyNames = new Set(FIRST_PARTY_SECRET_NAMES);
  for (const spec of FIRST_PARTY_SECRET_SPECS) {
    if (!config.services.includes(spec.service)) continue;
    const required = requirementFor(config, spec);
    if (required === null) continue;
    const current = byName.get(spec.name);
    if (current) {
      if (spec.envName) {
        if (!(current.aliases ?? []).some((alias) => alias.service === spec.service && alias.name === spec.envName)) {
          current.aliases = [...(current.aliases ?? []), { service: spec.service, name: spec.envName }];
        }
      } else if (!current.services.includes(spec.service)) current.services.push(spec.service);
      current.required ||= required;
      continue;
    }
    byName.set(spec.name, {
      name: spec.name,
      services: spec.envName ? [] : [spec.service],
      description: spec.description,
      required,
      ...(spec.generate ? { generate: spec.generate } : {}),
      managedBy: spec.managedBy ?? "operator",
      ...(spec.envName ? { aliases: [{ service: spec.service, name: spec.envName }] } : {}),
    });
  }
  for (const plugin of config.plugins) {
    const signing = byName.get("CORE_SIGNING_SECRET");
    if (signing && !signing.services.includes(plugin.name)) signing.services.push(plugin.name);
    for (const spec of plugin.secrets ?? []) {
      if (firstPartyNames.has(spec.name)) {
        throw new CliError(`contract config.plugins: ${plugin.name} cannot declare first-party secret ${spec.name}`, {
          clause: "config.plugins",
        });
      }
      const required = spec.required !== false;
      const current = byName.get(spec.name);
      if (current) {
        if (!current.services.includes(plugin.name)) current.services.push(plugin.name);
        current.required ||= required;
      } else {
        byName.set(spec.name, {
          name: spec.name,
          services: [plugin.name],
          description: spec.description ?? `Secret used by the ${plugin.name} plugin.`,
          required,
          managedBy: "operator",
        });
      }
    }
  }
  const pluginNames = config.plugins.map((plugin) => plugin.name);
  for (const [service, entries] of Object.entries(config.secretEnv ?? {}).sort(([a], [b]) => a.localeCompare(b))) {
    if (!config.services.includes(service as DeclaredServiceName)) continue;
    for (const [envName, storeName] of Object.entries(entries ?? {}).sort(([a], [b]) => a.localeCompare(b))) {
      let current = byName.get(storeName);
      if (firstPartyNames.has(storeName)) {
        const workload = isVirtualService(service) ? "core" : service;
        if (!current || !secretDestinations(current, pluginNames).get(workload)?.has(envName)) {
          throw new CliError(
            `contract config.secretEnv: ${storeName} may be delivered only to its catalog-owned workload destinations`,
            { clause: "config.secretEnv" },
          );
        }
      }
      if (!current) {
        current = {
          name: storeName,
          services: [],
          description: `Operator secret declared by config secretEnv.${service}.`,
          required: true,
          managedBy: "operator",
        };
        byName.set(storeName, current);
      }
      current.required = true;
      if (envName === storeName) {
        if (!current.services.includes(service)) current.services.push(service);
      } else if (!(current.aliases ?? []).some((alias) => alias.service === service && alias.name === envName)) {
        current.aliases = [...(current.aliases ?? []), { service: service as DeclaredServiceName, name: envName }];
      }
    }
  }
  const secrets = [...byName.values()]
    .map((secret) => ({
      ...secret,
      services: [...secret.services].sort(),
      ...(secret.aliases
        ? {
            aliases: [...secret.aliases].sort(
              (a, b) => a.service.localeCompare(b.service) || a.name.localeCompare(b.name),
            ),
          }
        : {}),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  const delivered = new Map<string, Map<string, string>>();
  const plaintext = new Map<string, Set<string>>();
  const addPlaintext = (workload: string, names: Iterable<string>): void => {
    const values = plaintext.get(workload) ?? new Set<string>();
    plaintext.set(workload, values);
    for (const name of names) values.add(name);
  };
  for (const [service, values] of Object.entries(config.env)) {
    if (service !== "core" && !config.services.includes(service as DeclaredServiceName)) continue;
    addPlaintext(isVirtualService(service) ? "core" : service, Object.keys(values ?? {}));
  }
  for (const plugin of config.plugins) addPlaintext(plugin.name, Object.keys(plugin.env ?? {}));
  for (const secret of secrets) {
    for (const [workload, names] of secretDestinations(secret, pluginNames)) {
      const workloadSecrets = delivered.get(workload) ?? new Map<string, string>();
      delivered.set(workload, workloadSecrets);
      for (const name of names) {
        if (plaintext.get(workload)?.has(name)) {
          throw new CliError(
            `contract config.env: ${workload} would receive secret env ${name} from ${secret.name} while it is configured as plaintext`,
            { clause: "config.env" },
          );
        }
        const prior = workloadSecrets.get(name);
        if (prior !== undefined && prior !== secret.name) {
          throw new CliError(
            `contract config.secretEnv: ${workload} would receive env ${name} from both ${prior} and ${secret.name}`,
            { clause: "config.secretEnv" },
          );
        }
        workloadSecrets.set(name, secret.name);
      }
    }
  }
  return secrets;
}

export function secretDestinations(
  secret: ComputedSecret,
  pluginNames: readonly string[] = [],
): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const add = (workload: string, name: string): void => {
    out.set(workload, (out.get(workload) ?? new Set()).add(name));
  };
  for (const service of secret.services) {
    if (isVirtualService(service)) add("core", secret.name);
    else add(service, secret.name);
  }
  for (const alias of secret.aliases ?? []) {
    add(isVirtualService(alias.service) ? "core" : alias.service, alias.name);
  }
  if (secret.name === "CORE_SIGNING_SECRET") {
    for (const plugin of pluginNames) add(plugin, secret.name);
  }
  return out;
}

function configWithRuntimeSecretValues(
  config: QmConfig,
  runtimeValues: ReadonlyMap<string, ReadonlyMap<string, string>>,
): QmConfig {
  return {
    ...config,
    env: {
      ...config.env,
      ...Object.fromEntries(
        [...runtimeValues].map(([workload, values]) => [
          workload,
          { ...config.env[workload as keyof typeof config.env], ...Object.fromEntries(values) },
        ]),
      ),
    },
  };
}

function validateMaterializedTrust(
  config: QmConfig,
  runtimeValues: ReadonlyMap<string, ReadonlyMap<string, string>>,
  completeness: MaterializeSecretValueOptions["completeness"],
): void {
  if (!config.services.includes("portal")) return;
  const trustConfig = configWithRuntimeSecretValues(config, runtimeValues);
  if (config.services.includes("auth")) {
    const authValues = runtimeValues.get("auth") ?? new Map<string, string>();
    validatePortalTrust(
      trustConfig,
      "secret values",
      completeness === "complete" || authValues.has("AUTH_ALLOWED_EMAILS") ? authValues : undefined,
    );
    return;
  }
  validatePortalTrust(
    trustConfig,
    "secret values",
    completeness === "complete" ? (runtimeValues.get("portal") ?? new Map<string, string>()) : undefined,
  );
}

export function materializeSecretValues(
  config: QmConfig,
  storeValues: ReadonlyMap<string, string>,
  options: MaterializeSecretValueOptions,
): MaterializedSecretValues {
  const pluginNames = config.plugins.map((plugin) => plugin.name);
  const selectedSecrets = computedSecrets(config).filter(
    (secret) => options.managedBy === "all" || secret.managedBy === options.managedBy,
  );
  const runtimeValues = new Map<string, Map<string, string>>();
  const destinationStores = new Map<string, Map<string, string>>();
  const missingRequiredDestinations: MissingSecretDestination[] = [];
  const invalidPublicApiDestinations: MissingSecretDestination[] = [];
  const selectedStoreValues = new Map<string, string>();
  for (const secret of selectedSecrets) {
    if (storeValues.has(secret.name)) selectedStoreValues.set(secret.name, storeValues.get(secret.name)!);
  }
  const invalidStoreNames = invalidSecretNames(selectedStoreValues);
  for (const secret of selectedSecrets) {
    const destinations = secretDestinations(secret, pluginNames);
    if (!storeValues.has(secret.name)) {
      if (secret.required) {
        for (const [workload, names] of destinations) {
          for (const name of names) missingRequiredDestinations.push({ storeName: secret.name, workload, name });
        }
      }
      continue;
    }
    const value = storeValues.get(secret.name)!;
    for (const [workload, names] of destinations) {
      const values = runtimeValues.get(workload) ?? new Map<string, string>();
      const stores = destinationStores.get(workload) ?? new Map<string, string>();
      runtimeValues.set(workload, values);
      destinationStores.set(workload, stores);
      for (const name of names) {
        const apiDestination = name === "PUBLIC_API_URL" || name === "AGENT_API_URL";
        const materialized = apiDestination ? (canonicalHttpOrigin(value) ?? value) : value;
        values.set(name, materialized);
        stores.set(name, secret.name);
        if (apiDestination && materialized !== (config.apiUrl ?? config.publicUrl)) {
          invalidPublicApiDestinations.push({ storeName: secret.name, workload, name });
        }
      }
    }
  }
  const invalidDestinations: MissingSecretDestination[] = [];
  for (const [workload, values] of runtimeValues) {
    const stores = destinationStores.get(workload)!;
    for (const name of invalidSecretNames(values)) {
      invalidDestinations.push({ storeName: stores.get(name)!, workload, name });
    }
  }
  const invalidNames = new Set([
    ...invalidStoreNames,
    ...invalidDestinations.map((destination) => destination.storeName),
    ...invalidPublicApiDestinations.map((destination) => destination.storeName),
  ]);
  if (options.completeness === "complete") {
    const requiredFailures = new Set([
      ...missingRequiredDestinations.map((destination) => destination.storeName),
      ...selectedSecrets
        .filter((secret) => secret.required && invalidNames.has(secret.name))
        .map((secret) => secret.name),
    ]);
    if (requiredFailures.size) {
      throw new CliError(`required secrets are missing or invalid: ${[...requiredFailures].sort().join(", ")}`);
    }
  }
  if (invalidNames.size) {
    const labels = new Set([
      ...invalidStoreNames,
      ...invalidDestinations.map(
        (destination) => `${destination.storeName} for ${destination.workload}.${destination.name}`,
      ),
      ...invalidPublicApiDestinations.map(
        (destination) => `${destination.storeName} for ${destination.workload}.${destination.name}`,
      ),
    ]);
    throw new CliError(
      `secret values are missing, placeholders, malformed, too short, or not distinct: ${[...labels]
        .sort()
        .join(", ")}`,
    );
  }
  validateMaterializedTrust(config, runtimeValues, options.completeness);
  return { runtimeValues, missingRequiredDestinations };
}

export function validateCompleteSecretValues(
  config: QmConfig,
  storeValues: ReadonlyMap<string, string>,
): MaterializedSecretValues {
  return materializeSecretValues(config, storeValues, { completeness: "complete", managedBy: "operator" });
}

export function runtimeSecretNames(
  workload: string,
  secret: ComputedSecret,
  pluginNames: readonly string[] = [],
): string[] {
  return [...(secretDestinations(secret, pluginNames).get(workload) ?? [])];
}

export function secretsForService(
  config: QmConfig,
  service: string,
  pluginNames: readonly string[] = [],
): ComputedSecret[] {
  return computedSecrets(config).filter((secret) => secretDestinations(secret, pluginNames).has(service));
}

function requiresOtherEmailTransport(config: QmConfig, condition: SecretCondition): boolean {
  if (condition.kind === "all")
    return condition.conditions.some((nested) => requiresOtherEmailTransport(config, nested));
  if (condition.kind === "any")
    return condition.conditions.every((nested) => requiresOtherEmailTransport(config, nested));
  if (condition.kind !== "env-equals" || condition.service !== "auth" || condition.name !== "AUTH_EMAIL_TRANSPORT")
    return false;
  const configured = config.env.auth?.AUTH_EMAIL_TRANSPORT?.trim();
  return configured !== undefined && configured !== "" && configured !== condition.value;
}

function conditionClause(condition: SecretCondition): string {
  if (condition.kind === "service-enabled") return `the ${condition.service} service is enabled`;
  if (condition.kind === "service-absent") return `the ${condition.service} service is not enabled`;
  if (condition.kind === "all") return condition.conditions.map(conditionClause).join(" and ");
  if (condition.kind === "any") return condition.conditions.map(conditionClause).join(" or ");
  if (condition.kind === "target") return `the target is ${condition.target}`;
  if (condition.kind === "env-all-absent")
    return `none of env.${condition.service}.{${condition.names.join(", ")}} are set`;
  if (condition.kind === "env-absent") return `env.${condition.service}.${condition.name} is not set`;
  if (condition.kind === "env-present") return `env.${condition.service}.${condition.name} is set`;
  if (condition.kind === "env-in")
    return `env.${condition.service}.${condition.name} is one of ${condition.values.map((value) => JSON.stringify(value)).join(", ")}`;
  if (condition.kind === "model-provider") return `modelProvider is ${JSON.stringify(condition.provider)}`;
  return `env.${condition.service}.${condition.name} is ${JSON.stringify(condition.value)}`;
}

export function renderEnvExample(config: QmConfig): string {
  const generate = (command: string): string => command.replace("<fly-org>", config.flyOrg ?? "<fly-org>");
  const lines = [
    "# Secret values for this deployment. This file holds names only; copy it to .env and fill in",
    "# the values. .env is gitignored. `qm secrets push` transfers values without persisting",
    "# or printing them.",
    "",
  ];
  const active = computedSecrets(config);
  for (const secret of active) {
    const consumers = [
      ...new Set([...secret.services, ...(secret.aliases ?? []).map((alias) => alias.service)]),
    ].sort();
    lines.push(`# ${secret.description} (${consumers.join(", ")})`);
    if (secret.generate) lines.push(`# Generate with: ${generate(secret.generate)}`);
    if (secret.managedBy === "terraform") lines.push(`# ${secret.name}=  # populated by Terraform`);
    else if (secret.required) lines.push(`${secret.name}=`);
    else lines.push(`# ${secret.name}=  # optional`);
    lines.push("");
  }
  const activeNames = new Set(active.map((secret) => secret.name));
  const inactive = FIRST_PARTY_SECRET_SPECS.filter(
    (spec, i, all) =>
      !activeNames.has(spec.name) &&
      all.findIndex((other) => other.name === spec.name) === i &&
      !(typeof spec.required === "object" && requiresOtherEmailTransport(config, spec.required.when)),
  );
  for (const spec of inactive) {
    const clauses = [
      ...(config.services.includes(spec.service) ? [] : [`the ${spec.service} service is enabled`]),
      ...(typeof spec.required === "boolean" ? [] : [conditionClause(spec.required.when)]),
    ];
    lines.push(`# ${spec.description} (${spec.service})`);
    lines.push(`# Needed when ${clauses.join(" and ")}${spec.required === false ? " (optional even then)" : ""}.`);
    if (spec.generate) lines.push(`# Generate with: ${generate(spec.generate)}`);
    lines.push(spec.managedBy === "terraform" ? `# ${spec.name}=  # populated by Terraform` : `# ${spec.name}=`);
    lines.push("");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}
