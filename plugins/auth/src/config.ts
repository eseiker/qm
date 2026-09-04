import { isIP } from "node:net";
import type { SmtpTlsMode } from "./smtp.ts";

type EmailTransportKind = "resend" | "smtp";

interface SmtpSettings {
  host: string;
  port: number;
  username: string;
  password: string;
  tls: SmtpTlsMode;
  tlsValid: boolean;
}

export interface AuthConfig {
  issuer: string;
  publicPath: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  signingJwk: Record<string, unknown> | null;
  tokenSecret: string;
  allowedEmails: readonly string[];
  allowedEmailDomain: string | undefined;
  emailFrom: string;
  brandName: string;
  transport: EmailTransportKind | undefined;
  resendApiKey: string;
  smtp: SmtpSettings;
  linkTtlS: number;
  codeTtlS: number;
  accessTtlS: number;
  requestTtlS: number;
  sendWindowS: number;
  sendLimitPerEmail: number;
  sendLimitPerIp: number;
  coreApiUrl: string;
  coreSigningSecret: string | undefined;
}

const PLACEHOLDER = /^(replace-me|placeholder|changeme|todo)$/i;
const MAX_RATE_LIMIT_SLOTS = 64;

function isMissingOrPlaceholder(value: string | undefined): boolean {
  const candidate = value?.trim();
  return !candidate || PLACEHOLDER.test(candidate);
}

function positiveIntegerFrom(raw: string | undefined, fallback: number): number {
  if (raw === undefined) return fallback;
  if (!/^[1-9]\d*$/.test(raw)) return Number.NaN;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) ? parsed : Number.NaN;
}

function listFrom(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function issuerPath(issuer: string): string {
  try {
    return new URL(issuer).pathname.replace(/\/$/, "");
  } catch {
    return "";
  }
}

function smtpTlsFrom(mode: string | undefined, port: number): { value: SmtpTlsMode; valid: boolean } {
  if (mode === undefined) return { value: port === 465 ? "implicit" : "starttls", valid: true };
  if (mode === "implicit" || mode === "none" || mode === "starttls") return { value: mode, valid: true };
  return { value: "starttls", valid: false };
}

function parseJwk(raw: string | undefined): Record<string, unknown> | null {
  if (!raw?.trim()) return null;
  try {
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export function readConfig(env: NodeJS.ProcessEnv): AuthConfig {
  const issuer = (env.AUTH_ISSUER ?? `http://localhost:${env.PORT ?? 8099}`).replace(/\/$/, "");
  const publicPath = issuerPath(issuer);
  const smtpPort = positiveIntegerFrom(env.SMTP_PORT, 587);
  const smtpTls = smtpTlsFrom(env.SMTP_TLS, smtpPort);
  const transport =
    env.AUTH_EMAIL_TRANSPORT === "smtp" || env.AUTH_EMAIL_TRANSPORT === "resend" ? env.AUTH_EMAIL_TRANSPORT : undefined;
  return {
    issuer,
    publicPath,
    clientId: env.AUTH_CLIENT_ID?.trim() ?? "",
    clientSecret: env.AUTH_CLIENT_SECRET ?? "",
    redirectUri: env.AUTH_REDIRECT_URI?.trim() ?? "",
    signingJwk: parseJwk(env.AUTH_SIGNING_JWK),
    tokenSecret: env.AUTH_TOKEN_SECRET ?? "",
    allowedEmails: listFrom(env.AUTH_ALLOWED_EMAILS),
    allowedEmailDomain: env.AUTH_ALLOWED_EMAIL_DOMAIN?.trim().toLowerCase() || undefined,
    emailFrom: env.AUTH_EMAIL_FROM?.trim() ?? "",
    brandName: env.AUTH_BRAND_NAME?.trim() || "qm",
    transport,
    resendApiKey: env.RESEND_API_KEY ?? "",
    smtp: {
      host: env.SMTP_HOST?.trim() ?? "",
      port: smtpPort,
      username: env.SMTP_USERNAME ?? "",
      password: env.SMTP_PASSWORD ?? "",
      tls: smtpTls.value,
      tlsValid: smtpTls.valid,
    },
    linkTtlS: positiveIntegerFrom(env.AUTH_LINK_TTL_S, 900),
    codeTtlS: positiveIntegerFrom(env.AUTH_CODE_TTL_S, 120),
    accessTtlS: positiveIntegerFrom(env.AUTH_ACCESS_TTL_S, 120),
    requestTtlS: positiveIntegerFrom(env.AUTH_REQUEST_TTL_S, 900),
    sendWindowS: positiveIntegerFrom(env.AUTH_SEND_WINDOW_S, 900),
    sendLimitPerEmail: positiveIntegerFrom(env.AUTH_SEND_LIMIT_PER_EMAIL, 5),
    sendLimitPerIp: positiveIntegerFrom(env.AUTH_SEND_LIMIT_PER_IP, 20),
    coreApiUrl: (env.CORE_API_URL ?? "http://localhost:8080").replace(/\/$/, ""),
    coreSigningSecret: env.CORE_SIGNING_SECRET,
  };
}

function validEmailDomain(value: string): boolean {
  if (value.length > 252 || !value.includes(".") || isIP(value) !== 0) return false;
  return value
    .split(".")
    .every(
      (label) => label.length > 0 && label.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label),
    );
}

export function validEmail(value: string): boolean {
  const separator = value.indexOf("@");
  if (value.length > 254 || separator < 1 || separator !== value.lastIndexOf("@")) return false;
  const local = value.slice(0, separator);
  const domain = value.slice(separator + 1);
  return (
    local.length <= 64 &&
    /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/.test(local) &&
    validEmailDomain(domain)
  );
}

function httpsUrlProblem(label: string, value: string, requireHttps: boolean): string | null {
  if (isMissingOrPlaceholder(value)) return `${label} is required and may not be a placeholder`;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return `${label} must be an absolute URL`;
  }
  if (requireHttps && url.protocol !== "https:") return `${label} must be https in production`;
  if (url.search || url.hash) return `${label} must not carry a query string or fragment`;
  return null;
}

function positiveIntegerProblem(label: string, value: number, maximum: number): string | null {
  if (!Number.isSafeInteger(value) || value < 1) return `${label} must be a positive whole number`;
  return value > maximum ? `${label} must be at most ${maximum} seconds` : null;
}

export function bootProblems(cfg: AuthConfig, isProd: boolean): string[] {
  const problems: string[] = [];
  const push = (problem: string | null): void => {
    if (problem) problems.push(problem);
  };

  push(httpsUrlProblem("AUTH_ISSUER", cfg.issuer, isProd));
  push(httpsUrlProblem("AUTH_REDIRECT_URI", cfg.redirectUri, isProd));
  if (isMissingOrPlaceholder(cfg.clientId)) problems.push("AUTH_CLIENT_ID is required and may not be a placeholder");
  if (isMissingOrPlaceholder(cfg.clientSecret))
    problems.push("AUTH_CLIENT_SECRET is required and may not be a placeholder");
  else if (Buffer.byteLength(cfg.clientSecret.trim(), "utf8") < 32)
    problems.push(
      "AUTH_CLIENT_SECRET must be at least 32 bytes — it is the portal's only credential at the token endpoint",
    );
  if (isMissingOrPlaceholder(cfg.tokenSecret))
    problems.push("AUTH_TOKEN_SECRET is required and may not be a placeholder");
  else if (Buffer.byteLength(cfg.tokenSecret.trim(), "utf8") < 32)
    problems.push("AUTH_TOKEN_SECRET must be at least 32 bytes");
  if (cfg.clientSecret && cfg.tokenSecret && cfg.clientSecret === cfg.tokenSecret) {
    problems.push("AUTH_CLIENT_SECRET must differ from AUTH_TOKEN_SECRET");
  }
  if (!cfg.signingJwk) problems.push("AUTH_SIGNING_JWK is required and must be a JSON Web Key object");
  else if (cfg.signingJwk.kty !== "EC" || cfg.signingJwk.crv !== "P-256" || typeof cfg.signingJwk.d !== "string") {
    problems.push("AUTH_SIGNING_JWK must be a P-256 private JSON Web Key (kty EC, crv P-256, with d)");
  }

  if (!cfg.allowedEmails.length && !cfg.allowedEmailDomain) {
    problems.push(
      "AUTH_ALLOWED_EMAILS or AUTH_ALLOWED_EMAIL_DOMAIN is required — without one, anybody with an inbox could sign in",
    );
  }
  const badEmail = cfg.allowedEmails.find((email) => !validEmail(email) || isMissingOrPlaceholder(email));
  if (badEmail)
    problems.push("AUTH_ALLOWED_EMAILS must be a comma-separated list of valid, non-placeholder email addresses");
  if (
    cfg.allowedEmailDomain &&
    (isMissingOrPlaceholder(cfg.allowedEmailDomain) || !validEmailDomain(cfg.allowedEmailDomain))
  ) {
    problems.push("AUTH_ALLOWED_EMAIL_DOMAIN must be a valid, non-placeholder email domain when set");
  }

  if (
    isMissingOrPlaceholder(cfg.emailFrom) ||
    /[\p{Cc}\p{Cf}]/u.test(cfg.emailFrom) ||
    !validEmail(senderAddress(cfg.emailFrom))
  ) {
    problems.push('AUTH_EMAIL_FROM must be a verified sender address, optionally as "Name <sender@example.com>"');
  }
  if (cfg.transport === undefined) {
    problems.push("AUTH_EMAIL_TRANSPORT must be exactly resend or smtp");
  } else if (cfg.transport === "resend") {
    if (isMissingOrPlaceholder(cfg.resendApiKey))
      problems.push("RESEND_API_KEY is required when AUTH_EMAIL_TRANSPORT is resend");
  } else {
    if (isMissingOrPlaceholder(cfg.smtp.host)) problems.push("SMTP_HOST is required when AUTH_EMAIL_TRANSPORT is smtp");
    if (isMissingOrPlaceholder(cfg.smtp.username))
      problems.push("SMTP_USERNAME is required when AUTH_EMAIL_TRANSPORT is smtp");
    if (isMissingOrPlaceholder(cfg.smtp.password))
      problems.push("SMTP_PASSWORD is required when AUTH_EMAIL_TRANSPORT is smtp");
    if (isProd && cfg.smtp.tls === "none")
      problems.push(
        "SMTP_TLS=none may not be used in production — SMTP credentials would cross the network in cleartext",
      );
  }
  if (!Number.isSafeInteger(cfg.smtp.port) || cfg.smtp.port < 1 || cfg.smtp.port > 65535)
    problems.push("SMTP_PORT must be a TCP port number");
  if (!cfg.smtp.tlsValid) problems.push("SMTP_TLS must be exactly starttls, implicit, or none");

  if (isProd && isMissingOrPlaceholder(cfg.coreSigningSecret)) {
    problems.push(
      "CORE_SIGNING_SECRET is required — single-use enforcement for links and codes is durable state held by core",
    );
  }
  for (const [name, value, maximum] of [
    ["AUTH_LINK_TTL_S", cfg.linkTtlS, 3600],
    ["AUTH_CODE_TTL_S", cfg.codeTtlS, 600],
    ["AUTH_ACCESS_TTL_S", cfg.accessTtlS, 600],
    ["AUTH_REQUEST_TTL_S", cfg.requestTtlS, 3600],
    ["AUTH_SEND_WINDOW_S", cfg.sendWindowS, 3600],
  ] as const) {
    push(positiveIntegerProblem(name, value, maximum));
  }
  for (const [name, limit] of [
    ["AUTH_SEND_LIMIT_PER_EMAIL", cfg.sendLimitPerEmail],
    ["AUTH_SEND_LIMIT_PER_IP", cfg.sendLimitPerIp],
  ] as const) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_RATE_LIMIT_SLOTS) {
      problems.push(
        `${name} must be a whole number between 1 and ${MAX_RATE_LIMIT_SLOTS} — each unit is one durable claim slot`,
      );
    }
  }
  return problems;
}

export function senderAddress(from: string): string {
  const normalized = from.trim();
  if (/\p{Cc}|\p{Cf}/u.test(normalized)) return "";
  if (validEmail(normalized)) return normalized;
  const angled = /^([^<>,]+)<([^<>]+)>$/u.exec(normalized);
  if (!angled) return "";
  const display = (angled[1] ?? "").trim();
  const address = (angled[2] ?? "").trim();
  if (!display) return "";
  return validEmail(address) ? address : "";
}
