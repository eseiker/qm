import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { EventEmitter, once } from "node:events";
import fs, {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertAwsDeploymentStorage,
  assertAwsPublicListener,
  awsDeploymentLayerTransport,
  assertGithubDeployTrust,
  awsCheckLive as awsCheckLiveWithIdentity,
  awsDoctor,
  awsDown,
  awsLogs,
  awsPreflightUp as awsPreflightUpWithIdentity,
  awsRollback,
  awsSecretsPush,
  awsStatus,
  awsUp as awsUpWithIdentity,
  githubTrustSubject,
  imageTransferArgs,
  isPinnedWorkloadImage,
  probeAwsSecretStore,
  renderTaskDefinition,
  serviceEnvironment,
  taskDefinitionChanges,
  taskDefinitionDiff,
} from "../src/backends/aws.ts";
import { effectiveDeployAppsDomain, type QmConfig } from "../src/config.ts";
import { computedSecrets } from "../src/secrets.ts";
import { awsObjectStoreBucket } from "../src/terraform.ts";
import { awsRunInherit, awsText, withAwsLease } from "../src/aws-lease.ts";
import { manifestRef } from "../src/manifest.ts";
import { hostingProvider, prepareUpSubstrate, type DeployContext } from "../src/backends/registry.ts";
import { microvmBuildArchiveSha256 } from "../src/commands/infra.ts";
import { readEnvFile, type FileIdentity } from "../src/util.ts";

process.env.QM_AWS_ROLLOUT_POLL_MS = "5";
process.env.QM_AWS_LIVE_PROBE_POLL_MS = "5";
process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS = "20";
process.env.QM_AWS_DB_SNAPSHOT_POLL_MS = "5";

const EMPTY_LAYER_BODY = JSON.stringify({ contract: 1, tools: [], skills: [] });
const EMPTY_LAYER = {
  key: "deployment/layers/empty.json",
  sha256: createHash("sha256").update(EMPTY_LAYER_BODY).digest("hex"),
};
const TEST_SECRET_VALUE = "test-secret-value".repeat(3);
const TEST_AUTH_SIGNING_JWK = JSON.stringify(
  generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }),
);
const TEST_CONFIG_IDENTITY: FileIdentity = { dev: -1n, ino: -1n };

function configIdentity(path: string): FileIdentity {
  const stat = statSync(path, { bigint: true });
  return { dev: stat.dev, ino: stat.ino };
}

function awsUp(
  config: QmConfig,
  configDir: string,
  opts: Omit<Parameters<typeof awsUpWithIdentity>[2], "configIdentity"> & { configIdentity?: FileIdentity },
): Promise<void> {
  return awsUpWithIdentity(config, configDir, {
    ...opts,
    configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY,
  });
}

function awsPreflightUp(
  config: QmConfig,
  configDir: string,
  opts: Omit<Parameters<typeof awsPreflightUpWithIdentity>[2], "configIdentity"> & {
    configIdentity?: FileIdentity;
  },
) {
  return awsPreflightUpWithIdentity(config, configDir, {
    ...opts,
    configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY,
  });
}

function awsCheckLive(
  config: QmConfig,
  opts: Omit<Parameters<typeof awsCheckLiveWithIdentity>[1], "configIdentity"> & {
    configIdentity?: FileIdentity;
  } = {},
): Promise<void> {
  return awsCheckLiveWithIdentity(config, {
    ...opts,
    configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY,
  });
}

function selectedTestSecretValue(name: string): string {
  if (name === "AUTH_SIGNING_JWK") return TEST_AUTH_SIGNING_JWK;
  if (name === "AUTH_EMAIL_FROM") return "Acme <no-reply@example.com>";
  if (name === "AUTH_ALLOWED_EMAILS") return "admin@example.com";
  if (name === "CORE_SIGNING_SECRET") return TEST_SECRET_VALUE;
  if (name === "PUBLIC_API_URL") return "https://agent.acme.example";
  return `${name.toLowerCase()}-${TEST_SECRET_VALUE}`;
}

function testSecretArn(name: string): string {
  return `arn:aws:secretsmanager:us-west-2:123456789012:secret:acme/qm/${name}-AbCdEf`;
}

function testSecretValues(dir: string, path = join(dir, ".env")): ReadonlyMap<string, string> {
  return readEnvFile(path);
}

async function withFakeStdin<T>(fn: (emit: (bytes: Buffer) => void) => Promise<T>): Promise<T> {
  const fake = Object.assign(new EventEmitter(), {
    isTTY: true,
    setRawMode(): void {},
    resume(): void {},
    pause(): void {},
  });
  const descriptor = Object.getOwnPropertyDescriptor(process, "stdin")!;
  const write = process.stdout.write.bind(process.stdout);
  Object.defineProperty(process, "stdin", { value: fake, configurable: true });
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    return await fn((bytes) => void fake.emit("data", bytes));
  } finally {
    process.stdout.write = write;
    Object.defineProperty(process, "stdin", descriptor);
  }
}

function fakeAws(
  dir: string,
  script: string,
  frontService: "core" | "portal" = "portal",
  ingress: { coreHosts?: string[]; targetGroups?: Partial<Record<"core" | "portal", string>> } = {},
): { log: string; restore: () => void } {
  const bin = join(dir, "aws-fake");
  const log = join(dir, "aws.log");
  const tgName = (name: "core" | "portal"): string =>
    ingress.targetGroups?.[name] ??
    `acme-qm-${name.replaceAll("-", "").slice(0, 4)}-${createHash("sha1").update(`acme-qm:${name}`).digest("hex").slice(0, 6)}`;
  const tgArn = (name: "core" | "portal"): string =>
    `arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/${tgName(name)}/1`;
  const targetName = tgName(frontService);
  const targetArn = tgArn(frontService);
  const coreHosts = frontService === "portal" ? (ingress.coreHosts ?? []) : [];
  const groups = [
    { TargetGroupArn: targetArn, TargetGroupName: targetName },
    ...(coreHosts.length ? [{ TargetGroupArn: tgArn("core"), TargetGroupName: tgName("core") }] : []),
  ];
  const baseRules =
    frontService === "portal"
      ? coreHosts.map((host) => ({
          IsDefault: false,
          Actions: [{ Type: "forward", TargetGroupArn: tgArn("core") }],
          Conditions: [{ Field: "host-header", HostHeaderConfig: { Values: [host] } }],
        }))
      : [
          {
            IsDefault: false,
            Actions: [{ Type: "forward", TargetGroupArn: targetArn }],
            Conditions: [{ Field: "path-pattern", PathPatternConfig: { Values: ["/v1/*"] } }],
          },
        ];
  const appCertificateNames = coreHosts.filter((host) => host.startsWith("*."));
  writeFileSync(log, "");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const fs = require("node:fs");
const a = process.argv.slice(2).join(" ");
fs.appendFileSync(${JSON.stringify(log)}, a + "\\n");
if (a.includes("sts get-caller-identity")) console.log(process.env.AWS_FAKE_ACCOUNT || "123456789012");
else if (a.includes("lambda-microvms get-microvm-image")) {
  if (process.env.AWS_FAKE_LAMBDA_UNSUPPORTED === "1") {
    console.error("invalid choice: 'lambda-microvms'");
    process.exit(2);
  }
  if (process.env.AWS_FAKE_IMAGE_MISSING === "1") {
    console.error("ResourceNotFoundException: image does not exist");
    process.exit(2);
  }
  if (process.env.AWS_FAKE_IMAGE_DENIED === "1") {
    console.error("AccessDeniedException: denied");
    process.exit(2);
  }
  if (process.env.AWS_FAKE_IMAGE_DENIED === "secondary") {
    console.error("An error occurred (AccessDeniedException) when calling the GetMicrovmImage operation: resource acme-ResourceNotFoundException is denied");
    process.exit(2);
  }
  if (process.env.AWS_FAKE_IMAGE_RESPONSE === "empty") process.exit(0);
  if (process.env.AWS_FAKE_IMAGE_RESPONSE === "malformed") {
    console.log("{}");
    process.exit(0);
  }
  if (process.env.AWS_FAKE_IMAGE_RESPONSE === "null") {
    console.log("null");
    process.exit(0);
  }
  const args = process.argv.slice(2);
  const id = args[args.indexOf("--image-identifier") + 1];
  const imageArn = id.startsWith("arn:") ? id : "arn:aws:lambda:us-west-2:123456789012:microvm-image:" + id;
  console.log(JSON.stringify({ imageArn }));
}
else if (a.includes("lambda-microvms list-microvm-image-versions")) {
  if (process.env.AWS_FAKE_IMAGE_RESPONSE === "empty-versions") process.exit(0);
  if (process.env.AWS_FAKE_IMAGE_RESPONSE === "malformed-versions") console.log("{}");
  else if (process.env.AWS_FAKE_IMAGE_RESPONSE === "malformed-version-type") console.log(JSON.stringify({ items: [{ imageVersion: ["1"], state: "SUCCESSFUL", status: "ACTIVE" }] }));
  else console.log(JSON.stringify({ items: [{ imageVersion: process.env.AWS_FAKE_IMAGE_VERSION || "1", state: process.env.AWS_FAKE_IMAGE_RESPONSE === "unknown-version-state" ? "UNKNOWN" : process.env.AWS_FAKE_IMAGE_STATE || "SUCCESSFUL", status: process.env.AWS_FAKE_IMAGE_RESPONSE === "unknown-version-status" ? "UNKNOWN" : process.env.AWS_FAKE_IMAGE_STATUS || "ACTIVE" }] }));
}
else if (a.includes("elbv2 describe-load-balancers")) console.log(JSON.stringify({ LoadBalancers: [{ LoadBalancerArn: "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/test/1", DNSName: process.env.AWS_FAKE_ALB_DNS || "agent.acme.example", State: { Code: "active" } }] }));
else if (a.includes("elbv2 describe-listeners")) {
  const protocol = process.env.AWS_FAKE_LISTENER_PROTOCOL || "HTTPS";
  const defaults = process.env.AWS_FAKE_DEFAULT_FORWARD === "1" ? [{ Type: "forward", TargetGroupArn: ${JSON.stringify(targetArn)} }] : ${frontService === "portal" ? JSON.stringify([{ Type: "forward", TargetGroupArn: targetArn }]) : JSON.stringify([{ Type: "fixed-response", FixedResponseConfig: { StatusCode: "404" } }])};
  const listeners = [{ ListenerArn: "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/app/test/1/2", Protocol: protocol, Port: protocol === "HTTPS" ? 443 : 80, Certificates: protocol === "HTTPS" ? [{ CertificateArn: "arn:aws:acm:us-west-2:123456789012:certificate/test" }] : [], DefaultActions: defaults }];
  if (process.env.AWS_FAKE_EXTRA_HTTP_LISTENER === "redirect") listeners.push({ ListenerArn: "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/app/test/1/3", Protocol: "HTTP", Port: 80, Certificates: [], DefaultActions: [{ Type: "redirect", RedirectConfig: { Protocol: "HTTPS", Port: "443", StatusCode: "HTTP_301" } }] });
  if (process.env.AWS_FAKE_EXTRA_HTTP_LISTENER === "forward") listeners.push({ ListenerArn: "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/app/test/1/3", Protocol: "HTTP", Port: 80, Certificates: [], DefaultActions: [{ Type: "forward", TargetGroupArn: ${JSON.stringify(targetArn)} }] });
  console.log(JSON.stringify({ Listeners: listeners }));
}
else if (a.includes("elbv2 describe-listener-certificates")) {
  const mode = process.env.AWS_FAKE_LISTENER_CERTIFICATE_RESPONSE;
  if (mode === "malformed") console.log("[]");
  else if (mode === "missing") console.log("{}");
  else if (mode === "missing-arn") console.log(JSON.stringify({ Certificates: [{}] }));
  else if (mode === "repeated-marker") console.log(JSON.stringify({ Certificates: [{ CertificateArn: "arn:aws:acm:us-west-2:123456789012:certificate/portal" }], NextMarker: "same" }));
  else if (mode === "paginated" && !a.includes("--marker page-2")) console.log(JSON.stringify({ Certificates: [{ CertificateArn: "arn:aws:acm:us-west-2:123456789012:certificate/portal" }], NextMarker: "page-2" }));
  else if (mode === "paginated") console.log(JSON.stringify({ Certificates: [{ CertificateArn: "arn:aws:acm:us-west-2:123456789012:certificate/apps" }] }));
  else console.log(JSON.stringify({ Certificates: [{ CertificateArn: "arn:aws:acm:us-west-2:123456789012:certificate/test" }] }));
}
else if (a.includes("acm describe-certificate")) {
  const arn = process.argv[process.argv.indexOf("--certificate-arn") + 1];
  const mode = process.env.AWS_FAKE_ACM_RESPONSE;
  if (mode === "malformed") console.log("[]");
  else if (mode === "missing") console.log("{}");
  else if (mode === "missing-sans") console.log(JSON.stringify({ Certificate: { CertificateArn: arn } }));
  else if (mode === "mismatch") console.log(JSON.stringify({ Certificate: { CertificateArn: arn + "-other", SubjectAlternativeNames: ${JSON.stringify(appCertificateNames)} } }));
  else {
    const names = mode === "portal-only" || arn.endsWith("/portal") ? ["*.agent.acme.example"] : ${JSON.stringify(appCertificateNames)};
    console.log(JSON.stringify({ Certificate: { CertificateArn: arn, SubjectAlternativeNames: names } }));
  }
}
else if (a.includes("elbv2 describe-target-groups")) console.log(JSON.stringify({ TargetGroups: ${JSON.stringify(groups)} }));
else if (a.includes("elbv2 describe-rules")) {
  const rules = process.env.AWS_FAKE_NO_CORE_RULE === "1" ? [] : ${JSON.stringify(baseRules)};
  if (process.env.AWS_FAKE_WRONG_RULE_TARGET === "1") for (const rule of rules) rule.Actions[0].TargetGroupArn = ${JSON.stringify(targetArn)};
  if (rules[0] && process.env.AWS_FAKE_WRONG_RULE_HOST === "1" && rules[0].Conditions[0].HostHeaderConfig) rules[0].Conditions[0].HostHeaderConfig.Values = ["other.example"];
  if (rules[0] && process.env.AWS_FAKE_EXTRA_ACTION === "1") rules[0].Actions.push({ Type: "authenticate-oidc" });
  if (rules[0] && process.env.AWS_FAKE_EXTRA_CONDITION === "1") rules[0].Conditions.push({ Field: "host-header", HostHeaderConfig: { Values: ["other.example"] } });
  if (process.env.AWS_FAKE_EXTRA_RULE === "1") rules.push({ IsDefault: false, Actions: [{ Type: "fixed-response", FixedResponseConfig: { StatusCode: "503" } }], Conditions: [{ Field: "path-pattern", PathPatternConfig: { Values: ["/v1/*"] } }] });
  console.log(JSON.stringify({ Rules: rules }));
}
else if (a.includes("elbv2 describe-target-health")) console.log(JSON.stringify({ TargetHealthDescriptions: [{ TargetHealth: { State: process.env.AWS_FAKE_UNHEALTHY_TARGET === "1" ? "unhealthy" : "healthy" } }] }));
else {
${script}
}
`,
  );
  chmodSync(bin, 0o755);
  const prior = process.env.AWS_BIN;
  const priorFetch = globalThis.fetch;
  process.env.AWS_BIN = bin;
  globalThis.fetch = async () => new Response("", { status: Number(process.env.AWS_FAKE_HTTP_STATUS ?? 404) });
  return {
    log,
    restore: () => {
      if (prior === undefined) delete process.env.AWS_BIN;
      else process.env.AWS_BIN = prior;
      globalThis.fetch = priorFetch;
    },
  };
}

function statefulAws(
  dir: string,
  configured: QmConfig,
  initialDynamo: Record<string, Record<string, { S: string }>> = {},
  opts: {
    failDescribe?: boolean;
    failDescribeOnceAfterUpdate?: boolean;
    ignoreUpdate?: boolean;
    failFirstUpdateAfterMutation?: boolean;
    failForcedDeploymentResponse?: boolean;
    failTransactions?: boolean;
    failTransactionPuts?: number;
    failPromotion?: boolean;
    failCleanup?: boolean;
    promotionAlreadyCurrent?: boolean;
    drainRollout?: boolean;
    primaryFailedTasks?: boolean;
    rolloutFailed?: boolean;
    transientFailedTaskPolls?: number;
    alternateStaleReadPolls?: number;
    foreignServiceTags?: boolean;
    foreignServiceTagsAfterLease?: boolean;
    snapshotStatus?: string;
    snapshotCreatingPolls?: number;
    failSnapshotDescribes?: number;
    failSnapshotDelete?: boolean;
    leaseLossMarker?: string;
    staleTaskDefinition?: boolean;
  } = {},
): {
  log: string;
  state: string;
  restore: () => void;
} {
  const state = join(dir, "aws-state.json");
  const frontService = configured.aws!.services.portal ? "portal" : "core";
  const coreHosts: string[] = [];
  if (frontService === "portal") {
    const api = configured.apiUrl;
    if (api && URL.canParse(api)) {
      const host = new URL(api).hostname.toLowerCase().replace(/\.$/, "");
      if (host !== new URL(configured.publicUrl).hostname.toLowerCase()) coreHosts.push(host);
    }
    const apps = effectiveDeployAppsDomain(configured);
    if (apps) coreHosts.push(`*.${apps.toLowerCase().replace(/\.$/, "")}`);
  }
  const targetGroups = Object.fromEntries(
    (["core", "portal"] as const).flatMap((name) => {
      const pinned = configured.aws!.services[name]?.targetGroup;
      return pinned ? [[name, pinned]] : [];
    }),
  );
  const tgName = (name: "core" | "portal"): string =>
    targetGroups[name] ??
    `acme-qm-${name.replaceAll("-", "").slice(0, 4)}-${createHash("sha1").update(`acme-qm:${name}`).digest("hex").slice(0, 6)}`;
  const frontTargetArn = `arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/${tgName(frontService)}/1`;
  const coreTargetArn = `arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/${tgName("core")}/1`;
  const services = Object.fromEntries(
    Object.entries(configured.aws!.services).map(([name, spec]) => [
      spec.ecsService,
      {
        workload: name,
        taskDefinition: `arn:aws:ecs:us-west-2:123456789012:task-definition/${spec.ecsService}:1`,
        desiredCount: 1,
        deploymentId: `ecs-svc/${spec.ecsService}-initial`,
      },
    ]),
  );
  const taskReferences = new Map(Object.values(services).map((service) => [service.taskDefinition, service.workload]));
  for (const item of Object.values(initialDynamo)) {
    if (!item.manifest?.S) continue;
    const manifest = JSON.parse(item.manifest.S) as { tasks?: Record<string, string> };
    for (const [workload, task] of Object.entries(manifest.tasks ?? {})) taskReferences.set(task, workload);
  }
  const definitions: Record<string, unknown> = {};
  try {
    const arns = Object.fromEntries(
      computedSecrets(configured).map((secret) => [secret.name, testSecretArn(secret.name)]),
    );
    for (const [task, workload] of taskReferences) {
      const repository = configured.aws!.services[workload]?.ecrRepository;
      if (!repository) continue;
      definitions[task] = {
        ...renderTaskDefinition(
          configured,
          workload,
          `123456789012.dkr.ecr.us-west-2.amazonaws.com/${repository}@sha256:${(opts.staleTaskDefinition
            ? "b"
            : "a"
          ).repeat(64)}`,
          arns,
        ),
        taskDefinitionArn: task,
      };
    }
  } catch {
    for (const task of Object.keys(definitions)) delete definitions[task];
  }
  writeFileSync(
    state,
    JSON.stringify({
      services,
      definitions,
      dynamo: initialDynamo,
      objects: { [EMPTY_LAYER.key]: EMPTY_LAYER_BODY },
      rdsSnapshots: [],
      revision: 1,
    }),
  );
  const fake = fakeAws(
    dir,
    `
const args = process.argv.slice(2);
const statePath = ${JSON.stringify(state)};
const s = JSON.parse(fs.readFileSync(statePath, "utf8"));
const save = () => fs.writeFileSync(statePath, JSON.stringify(s));
const after = (flag) => args[args.indexOf(flag) + 1];
if (a.includes("secretsmanager describe-secret")) {
  const secretId = after("--secret-id");
  console.log(JSON.stringify({ ARN: process.env.AWS_FAKE_DESCRIBE_SECRET_ARN || "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + secretId + "-AbCdEf" }));
}
else if (a.includes("secretsmanager get-secret-value") && !a.includes("--query")) {
  const secretId = after("--secret-id");
  const secretName = secretId.split("/").at(-1);
  const secretOverrides = JSON.parse(process.env.AWS_FAKE_SECRET_OVERRIDES || "{}");
  const storedSecrets = s.secretValues || {};
  if (secretName === process.env.AWS_FAKE_MISSING_SECRET_NAME && !Object.hasOwn(storedSecrets, secretName)) {
    console.error("ResourceNotFoundException: Secrets Manager can't find the specified secret value");
    process.exit(1);
  }
  let secret = Object.hasOwn(storedSecrets, secretName)
    ? storedSecrets[secretName]
    : Object.hasOwn(secretOverrides, secretName)
    ? secretOverrides[secretName]
    : secretName === "PUBLIC_API_URL"
    ? (process.env.AWS_FAKE_PUBLIC_API_URL || ${JSON.stringify(configured.apiUrl ?? configured.publicUrl)})
    : secretName === "CORE_SIGNING_SECRET"
      ? (process.env.AWS_FAKE_SECRET_VALUE || ${JSON.stringify(TEST_SECRET_VALUE)})
      : secretName + "-" + ${JSON.stringify(TEST_SECRET_VALUE)};
  if (a.includes("CORE_SIGNING_SECRET") && process.env.AWS_FAKE_ROTATE_SIGNING_SECRET === "1") {
    s.coreSigningReads = (s.coreSigningReads || 0) + 1;
    save();
    if (s.coreSigningReads > 1) secret = ${JSON.stringify(`${TEST_SECRET_VALUE}-rotated`)};
  }
  if (secretName === process.env.AWS_FAKE_ROTATE_SECRET_NAME) {
    s.rotatedSecretReads = (s.rotatedSecretReads || 0) + 1;
    save();
    if (s.rotatedSecretReads > 1) secret = process.env.AWS_FAKE_ROTATED_SECRET_VALUE || "replace-me";
  }
  if (process.env.AWS_FAKE_NUL_SECRET_NAME && a.includes(process.env.AWS_FAKE_NUL_SECRET_NAME)) {
    secret = "remote" + String.fromCharCode(0) + "sentinel";
  }
  let secretArn = process.env.AWS_FAKE_SECRET_ARN || "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + secretId + "-AbCdEf";
  if (secretName === "CORE_SIGNING_SECRET" && process.env.AWS_FAKE_ROTATE_SECRET_ARN === "1") {
    s.coreSigningArnReads = (s.coreSigningArnReads || 0) + 1;
    save();
    if (s.coreSigningArnReads > 1) secretArn = "arn:aws:secretsmanager:us-west-2:999999999999:secret:" + secretId + "-AbCdEf";
  }
  console.log(JSON.stringify({ ARN: secretArn, SecretString: secret }));
}
else if (a.includes("secretsmanager get-secret-value") && a.includes("--query SecretString")) {
  const secretName = after("--secret-id").split("/").at(-1);
  const secretOverrides = JSON.parse(process.env.AWS_FAKE_SECRET_OVERRIDES || "{}");
  const storedSecrets = s.secretValues || {};
  if (secretName === process.env.AWS_FAKE_MISSING_SECRET_NAME && !Object.hasOwn(storedSecrets, secretName)) {
    console.error("ResourceNotFoundException: Secrets Manager can't find the specified secret value");
    process.exit(1);
  }
  let secret = Object.hasOwn(storedSecrets, secretName)
    ? storedSecrets[secretName]
    : Object.hasOwn(secretOverrides, secretName)
    ? secretOverrides[secretName]
    : secretName === "PUBLIC_API_URL"
    ? (process.env.AWS_FAKE_PUBLIC_API_URL || ${JSON.stringify(configured.apiUrl ?? configured.publicUrl)})
    : secretName === "CORE_SIGNING_SECRET"
      ? (process.env.AWS_FAKE_SECRET_VALUE || ${JSON.stringify(TEST_SECRET_VALUE)})
      : secretName + "-" + ${JSON.stringify(TEST_SECRET_VALUE)};
  if (process.env.AWS_FAKE_NUL_SECRET_NAME && a.includes(process.env.AWS_FAKE_NUL_SECRET_NAME)) {
    secret = "remote" + String.fromCharCode(0) + "sentinel";
  }
  console.log(secret);
}
else if (a.includes("secretsmanager get-secret-value") && a.includes("--query ARN")) {
  const secretId = after("--secret-id");
  console.log(process.env.AWS_FAKE_SECRET_ARN || "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + secretId + "-AbCdEf");
}
else if (a.includes("secretsmanager put-secret-value")) {
  const secretName = after("--secret-id").split("/").at(-1);
  s.lastSecretValues = s.lastSecretValues || {};
  s.secretValues = s.secretValues || {};
  s.lastSecretValues[secretName] = fs.readFileSync(0, "utf8");
  s.secretValues[secretName] = s.lastSecretValues[secretName];
  save();
  console.log("");
}
else if (a.includes("ecr get-login-password")) console.log("pw");
else if (a.includes("ecr batch-get-image")) console.log(JSON.stringify({ images: [{ imageManifest: "{}", imageManifestMediaType: "application/vnd.oci.image.index.v1+json" }] }));
else if (a.includes("ecr put-image") && ${JSON.stringify(opts.failPromotion ?? false)}) { console.error("PutImageFailure"); process.exit(1); }
else if (a.includes("ecr put-image") && ${JSON.stringify(opts.promotionAlreadyCurrent ?? false)}) { console.error("ImageAlreadyExistsException"); process.exit(1); }
else if (a.includes("ecr put-image")) console.log(JSON.stringify({ image: { imageId: { imageDigest: "sha256:${"a".repeat(64)}" } } }));
else if (a.includes("ecr batch-delete-image") && ${JSON.stringify(opts.failCleanup ?? false)}) { console.error("AccessDeniedException"); process.exit(1); }
else if (a.includes("ecr describe-images")) console.log(JSON.stringify({ imageDetails: [{ imageDigest: "sha256:${"a".repeat(64)}" }] }));
else if (a.includes("ecs describe-services") && ${JSON.stringify(opts.failDescribe ?? false)}) { console.error("DescribeServicesFailure"); process.exit(1); }
else if (a.includes("ecs describe-services") && ${JSON.stringify(opts.failDescribeOnceAfterUpdate ?? false)} && s.updated && !s.describeFailedOnce) {
  s.describeFailedOnce = true;
  save();
  console.error("TransientDescribeFailure");
  process.exit(1);
}
else if (a.includes("ecs describe-services")) {
  const start = args.indexOf("--services") + 1;
  const end = Math.min(...[args.indexOf("--output", start), args.indexOf("--region", start)].filter((index) => index >= 0));
  const names = args.slice(start, end);
  const transientFailedTaskPolls = ${JSON.stringify(opts.transientFailedTaskPolls ?? 0)};
  let transientlyFailing = false;
  if (transientFailedTaskPolls && s.updated) {
    s.failedTaskPolls = (s.failedTaskPolls || 0) + 1;
    save();
    transientlyFailing = s.failedTaskPolls <= transientFailedTaskPolls;
  }
  const alternateStaleReadPolls = ${JSON.stringify(opts.alternateStaleReadPolls ?? 0)};
  const foreignTags = ${JSON.stringify(opts.foreignServiceTags ?? false)} || (${JSON.stringify(opts.foreignServiceTagsAfterLease ?? false)} && s.leaseAcquired);
  let staleName = null;
  if (alternateStaleReadPolls && s.updated) {
    s.stalePolls = (s.stalePolls || 0) + 1;
    save();
    if (s.stalePolls <= alternateStaleReadPolls) staleName = names[s.stalePolls % names.length];
  }
  console.log(JSON.stringify({ services: names.flatMap((name) => {
    const service = s.services[name];
    if (!service) return [];
    if (name === staleName && service.previousTaskDefinition) {
      return [{ serviceName: name, status: "ACTIVE", desiredCount: service.desiredCount, runningCount: service.desiredCount, taskDefinition: service.previousTaskDefinition, deployments: [{ id: service.deploymentId, status: "PRIMARY", taskDefinition: service.previousTaskDefinition, rolloutState: "COMPLETED", runningCount: service.desiredCount, failedTasks: 0 }], tags: [{ key: "Deployment", value: foreignTags ? "other" : ${JSON.stringify(configured.orgId)} }, { key: "ManagedBy", value: "terraform" }] }];
    }
    const deployments = ${JSON.stringify(opts.drainRollout ?? false)}
      ? [
          { id: service.deploymentId, status: "PRIMARY", taskDefinition: service.taskDefinition, rolloutState: "IN_PROGRESS", runningCount: service.desiredCount, failedTasks: 1 },
          { id: "old-protected", status: "ACTIVE", taskDefinition: service.taskDefinition, rolloutState: "COMPLETED", runningCount: 1, failedTasks: 0 },
        ]
      : ${JSON.stringify(opts.rolloutFailed ?? false)}
        ? [{ id: service.deploymentId, status: "PRIMARY", taskDefinition: service.taskDefinition, rolloutState: "FAILED", runningCount: 0, failedTasks: 1 }]
      : ${JSON.stringify(opts.primaryFailedTasks ?? false)} || transientlyFailing
        ? [{ id: service.deploymentId, status: "PRIMARY", taskDefinition: service.taskDefinition, rolloutState: "IN_PROGRESS", runningCount: 0, failedTasks: 1 }]
        : [{ id: service.deploymentId, status: "PRIMARY", taskDefinition: service.taskDefinition, rolloutState: "COMPLETED", runningCount: service.desiredCount, failedTasks: transientFailedTaskPolls && s.updated ? 1 : 0 }];
    return [{ serviceName: name, status: "ACTIVE", desiredCount: service.desiredCount, runningCount: ${JSON.stringify(opts.drainRollout ?? false)} ? service.desiredCount + 1 : service.desiredCount, taskDefinition: service.taskDefinition, networkConfiguration: { awsvpcConfiguration: { subnets: ["subnet-test"], securityGroups: ["sg-test"], assignPublicIp: "DISABLED" } }, deployments, loadBalancers: service.workload === ${JSON.stringify(frontService)} ? [{ targetGroupArn: ${JSON.stringify(frontTargetArn)} }] : (service.workload === "core" && ${JSON.stringify(coreHosts.length > 0)} ? [{ targetGroupArn: ${JSON.stringify(coreTargetArn)} }] : []), tags: [{ key: "Deployment", value: foreignTags ? "other" : ${JSON.stringify(configured.orgId)} }, { key: "ManagedBy", value: "terraform" }] }];
  }), failures: names.filter((name) => !s.services[name]).map((name) => ({ arn: name, reason: "MISSING" })) }));
}
else if (a.includes("ecs run-task")) console.log(JSON.stringify({ tasks: [{ taskArn: "arn:aws:ecs:us-west-2:123456789012:task/canary" }] }));
else if (a.includes("ecs wait tasks-stopped")) console.log("");
else if (a.includes("ecs describe-tasks")) console.log(JSON.stringify({ tasks: [{ stoppedReason: "Essential container exited", containers: [{ name: "core", exitCode: Number(process.env.AWS_FAKE_CANARY_EXIT || "0"), reason: process.env.AWS_FAKE_CANARY_REASON }] }] }));
else if (a.includes("ecs describe-task-definition")) {
  const id = after("--task-definition");
  console.log(JSON.stringify({ taskDefinition: s.definitions[id] }));
}
else if (a.includes("ecs register-task-definition")) {
  const file = after("--cli-input-json").slice("file://".length);
  const definition = JSON.parse(fs.readFileSync(file, "utf8"));
  const arn = "arn:aws:ecs:us-west-2:123456789012:task-definition/" + definition.family + ":" + (++s.revision);
  definition.taskDefinitionArn = arn;
  s.definitions[arn] = definition;
  save();
  console.log(arn);
}
else if (a.includes("ecs update-service")) {
  const name = after("--service");
  const service = s.services[name];
  if (!service) process.exit(4);
  service.previousTaskDefinition = service.taskDefinition;
  if (!${JSON.stringify(opts.ignoreUpdate ?? false)} && args.includes("--task-definition")) service.taskDefinition = after("--task-definition");
  if (!${JSON.stringify(opts.ignoreUpdate ?? false)} && args.includes("--desired-count")) service.desiredCount = Number(after("--desired-count"));
  if (!${JSON.stringify(opts.ignoreUpdate ?? false)}) service.deploymentId = "ecs-svc/" + name + "-" + (++s.revision);
  s.updated = true;
  if (${JSON.stringify(opts.failFirstUpdateAfterMutation ?? false)} && !s.failedFirstUpdate) {
    s.failedFirstUpdate = true;
    save();
    console.error("UpdateServiceResponseLost");
    process.exit(1);
  }
  save();
  if (${JSON.stringify(opts.failForcedDeploymentResponse ?? false)} && args.includes("--force-new-deployment")) {
    console.log(JSON.stringify({ service: { deployments: [] } }));
    process.exit(0);
  }
  console.log(JSON.stringify({ service: { deployments: [{ id: service.deploymentId, status: "PRIMARY", taskDefinition: service.taskDefinition, rolloutState: "IN_PROGRESS" }] } }));
}
else if (a.includes("dynamodb get-item")) {
  const key = JSON.parse(after("--key")).lockKey.S;
  console.log(JSON.stringify(s.dynamo[key] ? { Item: s.dynamo[key] } : {}));
}
else if (a.includes("dynamodb update-item") && ${JSON.stringify(opts.leaseLossMarker)} && fs.existsSync(${JSON.stringify(opts.leaseLossMarker)})) {
  console.error("An error occurred (ConditionalCheckFailedException) when calling the UpdateItem operation");
  process.exit(1);
}
else if (a.includes("dynamodb update-item")) console.log("");
else if (a.includes("dynamodb put-item") && a.includes("-deploy-locks")) {
  s.leaseAcquired = true;
  save();
  console.log("");
}
else if (a.includes("dynamodb transact-write-items")) {
  if (${JSON.stringify(opts.failTransactions ?? false)}) { console.error("TransactionRejected"); process.exit(1); }
  const failTransactionPuts = ${JSON.stringify(opts.failTransactionPuts ?? 0)};
  if (failTransactionPuts) {
    s.transactAttempts = (s.transactAttempts || 0) + 1;
    save();
    if (s.transactAttempts <= failTransactionPuts) { console.error("TransactionRejected"); process.exit(1); }
  }
  for (const write of JSON.parse(after("--transact-items"))) if (write.Put) s.dynamo[write.Put.Item.lockKey.S] = write.Put.Item;
  save();
  console.log("");
}
else if (a.includes("s3api put-object")) {
  s.objects[after("--key")] = fs.readFileSync(after("--body"), "utf8");
  save();
  console.log("");
}
else if (a.includes("s3api get-object")) {
  const body = s.objects[after("--key")];
  if (body === undefined) process.exit(5);
  const output = args[args.indexOf("--key") + 2];
  const bytes = Buffer.from(body);
  fs.writeFileSync(output, after("--range") === "bytes=0-1000000" ? bytes.subarray(0, 1000001) : bytes);
  console.log("");
}
else if (a.includes("rds describe-db-instances")) console.log(JSON.stringify({ DBInstances: [{ DBInstanceStatus: process.env.AWS_FAKE_DB_STATUS ?? "available", BackupRetentionPeriod: Number(process.env.AWS_FAKE_DB_RETENTION ?? "7") }] }));
else if (a.includes("rds create-db-snapshot")) {
  s.rdsSnapshots = s.rdsSnapshots || [];
  s.rdsSnapshots.push({ DBSnapshotIdentifier: after("--db-snapshot-identifier"), Status: ${JSON.stringify(opts.snapshotStatus ?? "available")}, SnapshotCreateTime: new Date(1700000000000 + s.rdsSnapshots.length * 1000).toISOString(), TagList: JSON.parse(after("--tags")) });
  save();
  console.log("");
}
else if (a.includes("rds describe-db-snapshots") && a.includes("--db-snapshot-identifier")) {
  const failDescribes = ${JSON.stringify(opts.failSnapshotDescribes ?? 0)};
  if (failDescribes) {
    s.snapshotDescribeFailures = (s.snapshotDescribeFailures || 0) + 1;
    save();
    if (s.snapshotDescribeFailures <= failDescribes) { console.error("TransientSnapshotDescribeFailure"); process.exit(1); }
  }
  const found = (s.rdsSnapshots || []).filter((item) => item.DBSnapshotIdentifier === after("--db-snapshot-identifier"));
  const creatingPolls = ${JSON.stringify(opts.snapshotCreatingPolls ?? 0)};
  if (creatingPolls) {
    s.snapshotPolls = (s.snapshotPolls || 0) + 1;
    save();
    if (s.snapshotPolls <= creatingPolls) for (const item of found) item.Status = "creating";
  }
  console.log(JSON.stringify({ DBSnapshots: found }));
}
else if (a.includes("rds describe-db-snapshots")) console.log(JSON.stringify({ DBSnapshots: s.rdsSnapshots || [] }));
else if (a.includes("rds delete-db-snapshot") && ${JSON.stringify(opts.failSnapshotDelete ?? false)}) { console.error("SnapshotDeleteDenied"); process.exit(1); }
else if (a.includes("rds delete-db-snapshot")) {
  s.rdsSnapshots = (s.rdsSnapshots || []).filter((item) => item.DBSnapshotIdentifier !== after("--db-snapshot-identifier"));
  save();
  console.log("");
}
else console.log("");`,
    frontService,
    { coreHosts, targetGroups },
  );
  let layerState = {
    version: 1,
    generation: 1,
    source: "durable" as "durable" | "none",
    body: EMPTY_LAYER_BODY,
    contentHash: EMPTY_LAYER.sha256 as string | null,
    runtimeContentHash: EMPTY_LAYER.sha256 as string | null,
    operationId: null as string | null,
    status: "applied" as "applied" | "degraded",
  };
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (init?.method === "PUT") {
      const body = String(init.body ?? "");
      const contentHash = createHash("sha256").update(body).digest("hex");
      const operationId = url.searchParams.get("operationId");
      const matches =
        url.searchParams.get("generation") === String(layerState.generation) &&
        url.searchParams.get("source") === layerState.source &&
        url.searchParams.get("contentHash") === layerState.contentHash &&
        url.searchParams.get("currentOperationId") === layerState.operationId;
      if (!matches) return new Response(JSON.stringify({ error: "deployment_layer_conflict" }), { status: 409 });
      const changed = contentHash !== layerState.contentHash;
      if (changed) {
        layerState = {
          version: layerState.generation + 1,
          generation: layerState.generation + 1,
          source: "durable",
          body,
          contentHash,
          runtimeContentHash: contentHash,
          operationId,
          status: "applied",
        };
      } else {
        layerState.runtimeContentHash = contentHash;
        layerState.status = "applied";
      }
      return new Response(
        JSON.stringify({
          ok: true,
          version: layerState.generation,
          contentHash,
          operationId: layerState.operationId,
          changed,
          durable: true,
          status: "applied",
        }),
        { status: 200 },
      );
    }
    if (init?.method === "DELETE") {
      const operationId = url.searchParams.get("operationId");
      const matches =
        url.searchParams.get("generation") === String(layerState.generation) &&
        url.searchParams.get("source") === layerState.source &&
        url.searchParams.get("contentHash") === layerState.contentHash &&
        url.searchParams.get("currentOperationId") === layerState.operationId;
      if (!matches || layerState.contentHash === null) {
        return new Response(JSON.stringify({ error: "deployment_layer_conflict" }), { status: 409 });
      }
      const replacedHash = layerState.contentHash;
      layerState = {
        version: 0,
        generation: layerState.generation + 1,
        source: "none",
        body: EMPTY_LAYER_BODY,
        contentHash: null,
        runtimeContentHash: EMPTY_LAYER.sha256,
        operationId,
        status: "applied",
      };
      return new Response(
        JSON.stringify({
          ok: true,
          version: layerState.generation,
          contentHash: replacedHash,
          operationId,
          changed: true,
          durable: true,
          status: "applied",
        }),
        { status: 200 },
      );
    }
    if (!String(input).includes("/v1/deployment-layer"))
      return new Response("", { status: Number(process.env.AWS_FAKE_HTTP_STATUS ?? 200) });
    if (layerState.version === 0) {
      return new Response(
        JSON.stringify({
          contract: 1,
          version: 0,
          generation: layerState.generation,
          source: layerState.source,
          contentHash: null,
          operationId: layerState.operationId,
        }),
        { status: 200 },
      );
    }
    return new Response(
      JSON.stringify({
        contract: 1,
        version: layerState.version,
        generation: layerState.generation,
        source: "durable",
        bundle: JSON.parse(layerState.body),
        contentHash: layerState.contentHash,
        runtimeContentHash: layerState.runtimeContentHash,
        operationId: layerState.operationId,
        status: layerState.status,
      }),
      { status: 200 },
    );
  }) as typeof fetch;
  return { ...fake, state };
}

const config: QmConfig = {
  contract: 1,
  orgId: "acme",
  publicUrl: "https://agent.acme.example",
  target: "aws",
  services: ["core", "slack", "web-ui", "admin", "portal"],
  plugins: [],
  skills: [],
  imageOverrides: {},
  sandbox: {
    backend: "sprites",
    namePrefix: "acme-sandboxes",
  },
  env: {
    core: { HARNESS: "pi", AWS_DEPLOY_IMAGE: "acme-qm-sandbox", AWS_DEPLOY_IMAGE_VERSION: "1" },
    admin: { ADMIN_BASE_PATH: "/admin" },
    portal: { OIDC_CLIENT_ID: "client", PORTAL_EXPECTED_TEAM_ID: "T1" },
  },
  aws: {
    accountId: "123456789012",
    region: "us-west-2",
    cluster: "acme-qm",
    deployRoleArn: "arn:aws:iam::123456789012:role/acme-deploy",
    imageLabel: "release",
    secretsPrefix: "acme/qm/",
    networking: { cloudMapNamespace: "acme.internal" },
    services: Object.fromEntries(
      ["core", "web-ui", "admin", "portal"].map((name) => [
        name,
        {
          ecrRepository: `qm-${name}`,
          ecsService: `acme-${name}`,
          cpu: name === "core" ? 2048 : 512,
          memory: name === "core" ? 4096 : 1024,
        },
      ]),
    ),
  },
};

function aliasedTrustConfig(kind: "portal" | "auth"): { config: QmConfig; storeName: string } {
  if (kind === "portal") {
    return {
      config: {
        ...config,
        secretEnv: { portal: { OIDC_ALLOWED_EMAILS: "PORTAL_ALLOWLIST_STORE" } },
      },
      storeName: "PORTAL_ALLOWLIST_STORE",
    };
  }
  return {
    config: {
      ...config,
      services: [...config.services, "auth"],
      env: { ...config.env, portal: {}, auth: { AUTH_EMAIL_TRANSPORT: "smtp" } },
      aws: {
        ...config.aws!,
        services: {
          ...config.aws!.services,
          auth: { ecrRepository: "qm-auth", ecsService: "acme-auth", cpu: 512, memory: 1024 },
        },
      },
    },
    storeName: "AUTH_ALLOWED_EMAILS",
  };
}

function requiredOperatorSecretValues(
  configured: QmConfig,
  overrides: Readonly<Record<string, string>> = {},
): Map<string, string> {
  return new Map(
    computedSecrets(configured)
      .filter((secret) => secret.managedBy === "operator" && secret.required)
      .map((secret) => [secret.name, overrides[secret.name] ?? selectedTestSecretValue(secret.name)]),
  );
}

const awsProviderSecretDestinations = [
  "AWS_DEPLOY_DATA_BUCKET",
  "AWS_DEPLOY_DATA_PREFIX",
  "AWS_DEPLOY_DATA_ROLE_ARN",
  "AWS_DEPLOY_EGRESS_CONNECTORS",
  "AWS_DEPLOY_INGRESS_CONNECTORS",
  "AWS_DEPLOY_PROFILE",
  "AWS_ENDPOINT_URL",
  "AWS_ENDPOINT_URL_S3",
  "AWS_SANDBOX_EGRESS_CONNECTORS",
  "AWS_SANDBOX_INGRESS_CONNECTORS",
  "AWS_SANDBOX_PROFILE",
  "AWS_SANDBOX_S3_PREFIX",
  "S3_PREFIX",
  "SECRETS_BACKEND",
  "SECRETS_PREFIX",
] as const;

test("AWS environment derives identity, public URLs, private wiring, and MicroVM coordinates", () => {
  assert.deepEqual(serviceEnvironment(config, "web-ui"), {
    CORE_API_URL: "http://core.acme.internal:8080",
    CORE_ORG_ID: "acme",
    NODE_ENV: "production",
    PORT: "8080",
    WEB_UI_PUBLIC_URL: "https://agent.acme.example",
  });
  assert.equal(serviceEnvironment(config, "admin").QM_VERSION, undefined);
  const core = serviceEnvironment(config, "core");
  assert.equal(core.ORG_ID, "acme");
  assert.equal(core.PUBLIC_WEB_URL, "https://agent.acme.example");
  assert.equal(core.WEB_UI_PUBLIC_URL, "https://agent.acme.example");
  assert.equal(core.REQUIRE_SIGNED_PORTAL_IDENTITY, "1");
  assert.equal(core.SANDBOX_BACKEND, "sprites");
  assert.equal(core.SPRITES_NAME_PREFIX, "acme-sandboxes");
  assert.equal(core.AWS_SANDBOX_IMAGE, undefined);
  assert.equal(core.AWS_DEPLOY_IMAGE, "acme-qm-sandbox");
  assert.equal(core.AWS_DEPLOY_IMAGE_VERSION, "1");
  assert.equal(core.DATA_DIR, "/data");
  const endpoints = serviceEnvironment(
    {
      ...config,
      env: {
        ...config.env,
        core: {
          ...config.env.core,
          AGENT_API_URL: "https://attacker.example",
          AWS_ENDPOINT_URL: "https://attacker.example",
          AWS_ENDPOINT_URL_S3: "https://attacker.example",
        },
        slack: { ...config.env.slack, SLACK_API_URL: "https://attacker.example" },
      },
    },
    "core",
  );
  assert.equal(endpoints.AGENT_API_URL, undefined);
  assert.equal(endpoints.AWS_ENDPOINT_URL, undefined);
  assert.equal(endpoints.AWS_ENDPOINT_URL_S3, undefined);
  assert.equal(endpoints.SLACK_API_URL, undefined);
  const { sandbox: _sandbox, ...rest } = config;
  const microvm = serviceEnvironment(rest as QmConfig, "core");
  assert.equal(microvm.SANDBOX_BACKEND, "aws");
  assert.equal(microvm.AWS_SANDBOX_REGION, "us-west-2");
  assert.equal(microvm.AWS_SANDBOX_IMAGE, "acme-qm-sandbox");
  assert.equal(microvm.AWS_SANDBOX_IMAGE_VERSION, "1");
  assert.equal(microvm.AWS_SANDBOX_EXEC_ROLE_ARN, "arn:aws:iam::123456789012:role/acme-qm-microvm-exec");
  assert.equal(microvm.AWS_SANDBOX_S3_BUCKET, awsObjectStoreBucket(config));
  assert.equal(microvm.SPRITES_NAME_PREFIX, undefined);
  for (const backend of ["porter", "smolmachines"] as const) {
    const external = serviceEnvironment(
      {
        ...rest,
        env: { ...rest.env, core: { ...rest.env.core, SANDBOX_BACKEND: backend } },
      } as QmConfig,
      "core",
    );
    assert.equal(external.SANDBOX_BACKEND, backend);
    assert.equal(external.AWS_SANDBOX_IMAGE, undefined);
    assert.equal(external.AWS_DEPLOY_IMAGE, "acme-qm-sandbox");
    assert.equal(external.AWS_DEPLOY_IMAGE_VERSION, "1");
    assert.equal(external.SPRITES_NAME_PREFIX, undefined);
  }
  assert.equal(core.SESSION_STORE, "postgres");
  assert.equal(core.RUN_STORE, "postgres");
  assert.equal(core.SNAPSHOT_STORE, "s3");
  assert.equal(core.TRANSFER_STORE, "s3");
  assert.equal(core.S3_REGION, "us-west-2");
  assert.equal(core.DEPLOY_PROVIDER, "aws");
  assert.equal(core.AWS_DEPLOY_REGION, "us-west-2");
  assert.equal(core.PORT, "8080");
  for (const service of ["core", "web-ui", "admin", "portal", "auth"] as const) {
    const environment = serviceEnvironment(
      {
        ...config,
        env: {
          ...config.env,
          [service]: {
            ...config.env[service],
            DATA_DIR: "/tmp/lost",
            NODE_ENV: "development",
            REQUIRE_SIGNED_PORTAL_IDENTITY: "0",
            AWS_ENDPOINT_URL: "https://attacker.example",
            AWS_ENDPOINT_URL_S3: "https://attacker.example",
          },
        },
      },
      service,
    );
    assert.equal(environment.NODE_ENV, "production");
    assert.equal(environment.REQUIRE_SIGNED_PORTAL_IDENTITY, service === "core" ? "1" : undefined);
    assert.equal(environment.DATA_DIR, service === "core" ? "/data" : "/tmp/lost");
    assert.equal(environment.AWS_ENDPOINT_URL, undefined);
    assert.equal(environment.AWS_ENDPOINT_URL_S3, undefined);
  }
});

test("AWS rejects secret destinations that overlap provider-owned environment before provider access", async (t) => {
  const cases = [
    ["core", "DATA_DIR"],
    ["core", "AGENT_API_URL"],
    ["core", "AWS_CONTAINER_AUTHORIZATION_TOKEN"],
    ["core", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"],
    ["core", "AWS_DEPLOY_REGION"],
    ["core", "AWS_SECRET_ACCESS_KEY"],
    ["core", "S3_BUCKET"],
    ["core", "S3_REGION"],
    ["core", "SNAPSHOT_STORE"],
    ["core", "SLACK_API_URL"],
    ["core", "TRANSFER_STORE"],
    ["portal", "PORTAL_XFF_TRUSTED_HOPS"],
    ...awsProviderSecretDestinations.map((name) => ["core", name] as const),
  ] as const;
  for (const [service, destination] of cases) {
    await t.test(`${service}.${destination}`, async () => {
      const configured: QmConfig = {
        ...config,
        secretEnv: { [service]: { [destination]: `LEGACY_${destination}_STORE` } },
      };
      const repository = configured.aws!.services[service]!.ecrRepository;
      const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/${repository}@sha256:${"a".repeat(64)}`;
      const expected = new RegExp(`provider-owned environment for ${service}: ${destination}`);
      assert.throws(() => renderTaskDefinition(configured, service, image), expected);
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-owned-secret-destination-"));
      const fake = statefulAws(dir, configured);
      try {
        await assert.rejects(awsSecretsPush(configured, dir, new Map()), expected);
        await assert.rejects(awsUp(configured, dir, { yes: true }), expected);
        await assert.rejects(awsRollback(configured), expected);
        assert.equal(readFileSync(fake.log, "utf8"), "");
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS topology never treats an inherited service-map property as a configured workload", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-inherited-service-"));
  const base = oneServiceConfig();
  const configured: QmConfig = {
    ...base,
    plugins: [{ name: "constructor", image: "ghcr.io/acme/constructor:1" }],
    aws: { ...base.aws!, services: { ...base.aws!.services } },
  };
  try {
    assert.throws(() => awsStatus(configured, dir), /missing enabled workloads: constructor/);
    assert.throws(
      () =>
        renderTaskDefinition(
          configured,
          "constructor",
          `123456789012.dkr.ecr.us-west-2.amazonaws.com/constructor@sha256:${"a".repeat(64)}`,
        ),
      /aws\.services\.constructor is missing/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS portal receives the core-selected deployment apps domain", () => {
  const cases: Array<{ core: Record<string, string>; expected?: string }> = [
    {
      core: {
        DEPLOY_APPS_DOMAIN: "Apps.Common.Example.COM.",
        AWS_DEPLOY_APPS_DOMAIN: "apps.aws.example.com",
      },
      expected: "apps.common.example.com",
    },
    { core: { AWS_DEPLOY_APPS_DOMAIN: "apps.aws.example.com" }, expected: "apps.aws.example.com" },
    { core: { PORTER_DEPLOY_APPS_DOMAIN: "apps.porter.example.com" } },
    { core: {} },
  ];
  for (const selected of cases) {
    const configured: QmConfig = {
      ...config,
      env: { ...config.env, core: { ...config.env.core, ...selected.core } },
    };
    const portal = serviceEnvironment(configured, "portal");
    assert.equal(portal.DEPLOY_APPS_DOMAIN, selected.expected);
    assert.equal(portal.AWS_DEPLOY_APPS_DOMAIN, undefined);
    assert.equal(portal.PORTER_DEPLOY_APPS_DOMAIN, undefined);
    assert.equal(portal.DEPLOY_APPS_DOMAIN, effectiveDeployAppsDomain(configured));
    const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-portal@sha256:${"a".repeat(64)}`;
    const rendered = renderTaskDefinition(configured, "portal", image).containerDefinitions[0]!.environment as Array<{
      name: string;
      value: string;
    }>;
    assert.equal(
      Object.fromEntries(rendered.map(({ name, value }) => [name, value])).DEPLOY_APPS_DOMAIN,
      selected.expected,
    );
  }
});

test("AWS gated portal apps share one session-secret store value with core", () => {
  const sessionArn = testSecretArn("PORTAL_SESSION_SECRET");
  const secretMap = (configured: QmConfig, service: "core" | "portal"): Record<string, string> => {
    const repository = configured.aws!.services[service]!.ecrRepository;
    const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/${repository}@sha256:${"a".repeat(64)}`;
    return Object.fromEntries(
      (
        renderTaskDefinition(configured, service, image, { PORTAL_SESSION_SECRET: sessionArn }).containerDefinitions[0]!
          .secrets as Array<{ name: string; valueFrom: string }>
      ).map(({ name, valueFrom }) => [name, valueFrom]),
    );
  };
  for (const domainName of ["DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_APPS_DOMAIN"] as const) {
    const configured: QmConfig = {
      ...config,
      env: {
        ...config.env,
        core: { ...config.env.core, [domainName]: "apps.agent.acme.example" },
      },
    };
    const core = secretMap(configured, "core");
    const portal = secretMap(configured, "portal");
    assert.equal(core.DEPLOY_APPS_SESSION_SECRET, sessionArn);
    assert.equal(core.PORTAL_SESSION_SECRET, undefined);
    assert.equal(portal.PORTAL_SESSION_SECRET, sessionArn);
    assert.equal(portal.DEPLOY_APPS_SESSION_SECRET, undefined);
    assert.equal(serviceEnvironment(configured, "core").PUBLIC_WEB_URL, config.publicUrl);
    assert.equal(serviceEnvironment(configured, "portal").DEPLOY_APPS_DOMAIN, "apps.agent.acme.example");
  }
  const porterOnly: QmConfig = {
    ...config,
    env: {
      ...config.env,
      core: { ...config.env.core, PORTER_DEPLOY_APPS_DOMAIN: "apps.porter.example.com" },
    },
  };
  assert.equal(secretMap(porterOnly, "core").DEPLOY_APPS_SESSION_SECRET, undefined);
  assert.equal(serviceEnvironment(porterOnly, "portal").DEPLOY_APPS_DOMAIN, undefined);
});

test("AWS built-in auth uses the effective portal origin with and without gated apps", () => {
  const builtIn = aliasedTrustConfig("auth").config;
  for (const gated of [false, true]) {
    const portalOrigin = builtIn.publicUrl;
    const configured: QmConfig = {
      ...builtIn,
      env: {
        ...builtIn.env,
        core: {
          ...builtIn.env.core,
          ...(gated ? { DEPLOY_APPS_DOMAIN: "apps.agent.acme.example" } : {}),
        },
        portal: { ...builtIn.env.portal, PORTAL_PUBLIC_URL: portalOrigin },
      },
    };
    const portal = serviceEnvironment(configured, "portal");
    const auth = serviceEnvironment(configured, "auth");
    assert.equal(portal.OIDC_ISSUER, `${portalOrigin}/idp`);
    assert.equal(auth.AUTH_ISSUER, `${portalOrigin}/idp`);
    assert.equal(auth.AUTH_REDIRECT_URI, `${portalOrigin}/auth/callback`);
    assert.equal(portal.DEPLOY_APPS_DOMAIN, gated ? "apps.agent.acme.example" : undefined);
    for (const service of ["portal", "auth"] as const) {
      const repository = configured.aws!.services[service]!.ecrRepository;
      const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/${repository}@sha256:${"a".repeat(64)}`;
      const rendered = Object.fromEntries(
        (
          renderTaskDefinition(configured, service, image).containerDefinitions[0]!.environment as Array<{
            name: string;
            value: string;
          }>
        ).map(({ name, value }) => [name, value]),
      );
      assert.equal(rendered[service === "portal" ? "OIDC_ISSUER" : "AUTH_ISSUER"], `${portalOrigin}/idp`);
    }
  }
});

test("a configured bot identity lands in the AWS core task env and only there", () => {
  const branded = { ...config, botName: "straylight", orgName: "Straylight Industries" };
  const core = serviceEnvironment(branded, "core");
  assert.equal(core.ORG_BRAND_SELF_LABEL, "straylight");
  assert.equal(core.ORG_BRAND_ORG_NAME, "Straylight Industries");
  assert.equal(serviceEnvironment(branded, "web-ui").ORG_BRAND_SELF_LABEL, undefined);
  assert.equal(serviceEnvironment(config, "core").ORG_BRAND_SELF_LABEL, undefined);
});

test("AWS routes security screen proxy configuration and its token only to core", () => {
  const screened: QmConfig = {
    ...config,
    securityScreen: {
      backend: "proxy",
      provider: "example-screen",
      endpoint: "https://screen.example.test/classify",
      rollout: "enforce",
    },
    secretEnv: { core: { SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN" } },
  };
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(serviceEnvironment(screened, "core")).filter(([name]) => name.startsWith("SECURITY_SCREEN_")),
    ),
    {
      SECURITY_SCREEN_BACKEND: "proxy",
      SECURITY_SCREEN_PROXY_ENDPOINT: "https://screen.example.test/classify",
      SECURITY_SCREEN_PROXY_PROVIDER: "example-screen",
      SECURITY_SCREEN_PROXY_ROLLOUT: "enforce",
    },
  );
  assert.deepEqual(
    Object.keys(serviceEnvironment(screened, "web-ui")).filter((name) => name.startsWith("SECURITY_SCREEN_")),
    [],
  );
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  const task = renderTaskDefinition(screened, "core", image, { EXAMPLE_SCREEN_TOKEN: "arn:example-screen-token" });
  assert.deepEqual(
    (task.containerDefinitions[0]!.secrets as Array<{ name: string; valueFrom: string }>).filter(({ name }) =>
      name.startsWith("SECURITY_SCREEN_"),
    ),
    [{ name: "SECURITY_SCREEN_PROXY_TOKEN", valueFrom: "arn:example-screen-token" }],
  );
});

test("AWS fixes every workload listen port to its ECS port mapping", () => {
  const configured: QmConfig = {
    ...config,
    env: {
      ...config.env,
      core: { ...config.env.core, PORT: "9000" },
      "web-ui": { PORT: "9001" },
      admin: { ...config.env.admin, PORT: "9002" },
      portal: { ...config.env.portal, PORT: "9003" },
    },
  };
  for (const service of ["core", "web-ui", "admin", "portal"] as const) {
    const def = configured.aws!.services[service]!;
    const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/${def.ecrRepository}@sha256:${"a".repeat(64)}`;
    const task = renderTaskDefinition(configured, service, image);
    const container = task.containerDefinitions[0]!;
    const environment = Object.fromEntries(
      (container.environment as Array<{ name: string; value: string }>).map(({ name, value }) => [name, value]),
    );
    assert.equal(environment.PORT, "8080");
    assert.deepEqual(container.portMappings, [{ containerPort: 8080, hostPort: 8080, protocol: "tcp" }]);
  }
});

test("AWS core receives the configured model and virtual-service environment", () => {
  const configured: QmConfig = {
    ...config,
    model: "anthropic/claude-sonnet-4-5",
    env: {
      ...config.env,
      slack: { SLACK_EVENTS_MODE: "http", SHARED_SETTING: "slack" },
      core: { ...config.env.core, SHARED_SETTING: "core" },
    },
  };
  const core = serviceEnvironment(configured, "core");
  assert.equal(core.PI_MODEL, "anthropic/claude-sonnet-4-5");
  assert.equal(core.SLACK_EVENTS_MODE, "http");
  assert.equal(core.SHARED_SETTING, "core");
});

test("AWS required runtime settings cannot be overridden by config env", () => {
  const overridden: QmConfig = {
    ...config,
    env: {
      ...config.env,
      core: {
        ...config.env.core,
        SESSION_STORE: "memory",
        RUN_STORE: "memory",
        SANDBOX_BACKEND: "aws",
      },
    },
  };
  const core = serviceEnvironment(overridden, "core");
  assert.equal(core.SESSION_STORE, "postgres");
  assert.equal(core.RUN_STORE, "postgres");
  assert.equal(core.SANDBOX_BACKEND, "sprites");
  const { sandbox: _sandbox, ...rest } = overridden;
  const microvm = serviceEnvironment(rest as QmConfig, "core");
  assert.equal(microvm.SESSION_STORE, "postgres");
  assert.equal(microvm.SANDBOX_BACKEND, "aws");
});

test("AWS deploy-role trust permits only the exact repository branch", () => {
  const subject = "repo:acme/deploy:ref:refs/heads/main";
  const exact = [
    {
      Effect: "Allow",
      Principal: { Federated: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
      Action: "sts:AssumeRoleWithWebIdentity",
      Condition: {
        StringEquals: {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": subject,
        },
      },
    },
  ];
  assert.doesNotThrow(() => assertGithubDeployTrust(exact, "123456789012", subject));
  assert.throws(
    () =>
      assertGithubDeployTrust(
        [
          ...exact,
          { ...exact[0], Condition: { StringLike: { "token.actions.githubusercontent.com:sub": "repo:acme/*" } } },
        ],
        "123456789012",
        subject,
      ),
    /exactly one/,
  );
  assert.throws(
    () =>
      assertGithubDeployTrust(
        [{ ...exact[0], Condition: { StringLike: { "token.actions.githubusercontent.com:sub": "repo:acme/*" } } }],
        "123456789012",
        subject,
      ),
    /must pin audience/,
  );
  const pinnedElsewhere = [
    {
      ...exact[0],
      Condition: {
        StringEquals: {
          ...exact[0]!.Condition.StringEquals,
          "token.actions.githubusercontent.com:sub": "repo:acme/deploy:ref:refs/heads/release",
        },
      },
    },
  ];
  assert.throws(
    () => assertGithubDeployTrust(pinnedElsewhere, "123456789012", subject),
    /including repo:acme\/deploy:ref:refs\/heads\/main \(live subject: repo:acme\/deploy:ref:refs\/heads\/release\)/,
  );
});

test("AWS deploy-role trust accepts a subject list that contains the expected subject", () => {
  const environmentSubject = "repo:acme/deploy:environment:production";
  const branchSubject = "repo:acme/deploy:ref:refs/heads/main";
  const withSubjects = (sub: unknown) => [
    {
      Effect: "Allow",
      Principal: { Federated: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
      Action: "sts:AssumeRoleWithWebIdentity",
      Condition: {
        StringEquals: {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": sub,
        },
      },
    },
  ];

  for (const expected of [environmentSubject, branchSubject]) {
    assert.doesNotThrow(() =>
      assertGithubDeployTrust(withSubjects([environmentSubject, branchSubject]), "123456789012", expected),
    );
  }

  assert.throws(
    () => assertGithubDeployTrust(withSubjects([branchSubject]), "123456789012", environmentSubject),
    /including repo:acme\/deploy:environment:production \(live subject: repo:acme\/deploy:ref:refs\/heads\/main\)/,
  );
  assert.throws(
    () =>
      assertGithubDeployTrust(
        withSubjects([environmentSubject, "repo:evil/repo:ref:refs/heads/main"]),
        "123456789012",
        environmentSubject,
      ),
    /only repo:acme\/deploy:\* subjects/,
  );
  assert.throws(
    () =>
      assertGithubDeployTrust(
        withSubjects([environmentSubject, "repo:acme/deploy:*"]),
        "123456789012",
        environmentSubject,
      ),
    /only repo:acme\/deploy:\* subjects/,
  );
  assert.throws(
    () => assertGithubDeployTrust(withSubjects([]), "123456789012", environmentSubject),
    /\(live subject: missing\)/,
  );

  const idPinned = [
    "repo:acme@153323858/deploy@1253778415:environment:production",
    "repo:acme@153323858/deploy@1253778415:ref:refs/heads/main",
  ];
  for (const expected of [environmentSubject, branchSubject]) {
    assert.doesNotThrow(() => assertGithubDeployTrust(withSubjects(idPinned), "123456789012", expected));
  }
  assert.throws(
    () =>
      assertGithubDeployTrust(
        withSubjects(["repo:evil@153323858/deploy@1253778415:environment:production"]),
        "123456789012",
        environmentSubject,
      ),
    /only repo:acme\/deploy:\* subjects/,
  );
  assert.throws(
    () =>
      assertGithubDeployTrust(
        withSubjects(["repo:acme@153323858/deploy@1253778415:*"]),
        "123456789012",
        environmentSubject,
      ),
    /live subject: repo:acme@153323858\/deploy@1253778415:\*/,
  );
});

test("githubTrustSubject pins the deploy branch, never the working checkout's branch", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-trust-subject-"));
  const wrongDir = mkdtempSync(join(tmpdir(), "qm-aws-trust-subject-wrong-"));
  const git = (...args: string[]): void => {
    const result = spawnSync("git", ["-C", dir, ...args], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
  };
  const wrongGit = (...args: string[]): void => {
    const result = spawnSync("git", ["-C", wrongDir, ...args], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
  };
  git("init", "-b", "feature-checkout");
  git("remote", "add", "origin", "git@github.com:acme/qm.git");
  wrongGit("init", "-b", "main");
  wrongGit("remote", "add", "origin", "git@github.com:evil/substitute.git");
  const priorRepo = process.env.GITHUB_REPOSITORY;
  const priorRef = process.env.GITHUB_REF;
  const priorGitDir = process.env.GIT_DIR;
  const priorGitWorkTree = process.env.GIT_WORK_TREE;
  delete process.env.GITHUB_REPOSITORY;
  delete process.env.GITHUB_REF;
  process.env.GIT_DIR = join(wrongDir, ".git");
  process.env.GIT_WORK_TREE = wrongDir;
  try {
    assert.equal(
      githubTrustSubject(dir),
      "repo:acme/qm:ref:refs/heads/main",
      "a feature-branch checkout still expects the main-pinned trust",
    );
    assert.equal(
      githubTrustSubject(dir, "release"),
      "repo:acme/qm:ref:refs/heads/release",
      "aws.deployBranch overrides the default",
    );
    assert.equal(
      githubTrustSubject(dir, "release", "production"),
      "repo:acme/qm:environment:production",
      "a GitHub environment replaces the branch in the OIDC subject",
    );
    mkdirSync(join(dir, "infra"), { recursive: true });
    writeFileSync(
      join(dir, "infra", "terraform.tfvars"),
      'github_repository = "acme/vendored"\ngithub_ref = "refs/heads/deploy"\n',
    );
    assert.equal(
      githubTrustSubject(dir),
      "repo:acme/vendored:ref:refs/heads/deploy",
      "vendored infra declares its own pinned ref",
    );
    assert.equal(
      githubTrustSubject(dir, "main"),
      "repo:acme/vendored:ref:refs/heads/main",
      "an explicit deployBranch wins over tfvars",
    );
    process.env.GITHUB_REPOSITORY = "acme/from-actions";
    process.env.GITHUB_REF = "refs/heads/pr-branch";
    assert.equal(
      githubTrustSubject(dir),
      "repo:acme/from-actions:ref:refs/heads/deploy",
      "the workflow's own ref never shapes the expected trust",
    );
    writeFileSync(
      join(dir, "infra", "terraform.tfvars"),
      'github_repository = "acme/vendored"\ngithub_ref = "release"\n',
    );
    assert.throws(() => githubTrustSubject(dir), /github_ref must be a refs\/heads\/\* branch ref/);
  } finally {
    if (priorRepo === undefined) delete process.env.GITHUB_REPOSITORY;
    else process.env.GITHUB_REPOSITORY = priorRepo;
    if (priorRef === undefined) delete process.env.GITHUB_REF;
    else process.env.GITHUB_REF = priorRef;
    if (priorGitDir === undefined) delete process.env.GIT_DIR;
    else process.env.GIT_DIR = priorGitDir;
    if (priorGitWorkTree === undefined) delete process.env.GIT_WORK_TREE;
    else process.env.GIT_WORK_TREE = priorGitWorkTree;
    rmSync(dir, { recursive: true, force: true });
    rmSync(wrongDir, { recursive: true, force: true });
  }
});

test("githubTrustSubject never accepts a global Git origin without a local deployment origin", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-trust-subject-local-"));
  const hostileHome = mkdtempSync(join(tmpdir(), "qm-aws-trust-subject-home-"));
  const result = spawnSync("git", ["-C", dir, "init", "-b", "main"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  writeFileSync(join(hostileHome, ".gitconfig"), '[remote "origin"]\n\turl = git@github.com:evil/substitute.git\n');
  const priorRepo = process.env.GITHUB_REPOSITORY;
  const priorHome = process.env.HOME;
  const priorGitConfig = process.env.GIT_CONFIG_GLOBAL;
  delete process.env.GITHUB_REPOSITORY;
  process.env.HOME = hostileHome;
  process.env.GIT_CONFIG_GLOBAL = join(hostileHome, ".gitconfig");
  try {
    assert.throws(() => githubTrustSubject(dir), /cannot derive the GitHub repository from this deployment checkout/);
  } finally {
    if (priorRepo === undefined) delete process.env.GITHUB_REPOSITORY;
    else process.env.GITHUB_REPOSITORY = priorRepo;
    if (priorHome === undefined) delete process.env.HOME;
    else process.env.HOME = priorHome;
    if (priorGitConfig === undefined) delete process.env.GIT_CONFIG_GLOBAL;
    else process.env.GIT_CONFIG_GLOBAL = priorGitConfig;
    rmSync(dir, { recursive: true, force: true });
    rmSync(hostileHome, { recursive: true, force: true });
  }
});

test("githubTrustSubject accepts only exact GitHub remote origins", () => {
  const priorRepo = process.env.GITHUB_REPOSITORY;
  delete process.env.GITHUB_REPOSITORY;
  try {
    for (const selected of [
      { remote: "https://github.com/acme/qm.enterprise.git", expected: "repo:acme/qm.enterprise:ref:refs/heads/main" },
      { remote: "git@github.com:acme/qm.enterprise.git", expected: "repo:acme/qm.enterprise:ref:refs/heads/main" },
      {
        remote: "ssh://git@github.com/acme/qm.enterprise.git",
        expected: "repo:acme/qm.enterprise:ref:refs/heads/main",
      },
      { remote: "https://evilgithub.com/acme/qm.git" },
      { remote: "https://user@github.com/acme/qm.git" },
      { remote: "ssh://github.com/acme/qm.git" },
      { remote: "https://github.com:443/acme/qm.git" },
      { remote: "https://github.com/acme/qm.git?ref=main" },
      { remote: "https://github.com/acme/qm.git#main" },
      { remote: "https://github.com/acme/qm/extra" },
    ]) {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-trust-subject-remote-"));
      try {
        const init = spawnSync("git", ["-C", dir, "init", "-b", "main"], { encoding: "utf8" });
        assert.equal(init.status, 0, init.stderr);
        const remote = spawnSync("git", ["-C", dir, "remote", "add", "origin", selected.remote], {
          encoding: "utf8",
        });
        assert.equal(remote.status, 0, remote.stderr);
        if (selected.expected) assert.equal(githubTrustSubject(dir), selected.expected);
        else {
          assert.throws(
            () => githubTrustSubject(dir),
            /cannot derive the GitHub repository from this deployment checkout/,
          );
        }
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  } finally {
    if (priorRepo === undefined) delete process.env.GITHUB_REPOSITORY;
    else process.env.GITHUB_REPOSITORY = priorRepo;
  }
});

test("githubTrustSubject reads vendored Terraform coordinates through a bounded stable descriptor", async (t) => {
  const priorRepo = process.env.GITHUB_REPOSITORY;
  process.env.GITHUB_REPOSITORY = "acme/actions";
  try {
    await t.test("final symlink", () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-trust-tfvars-symlink-"));
      const outside = join(dir, "outside.tfvars");
      mkdirSync(join(dir, "infra"));
      writeFileSync(outside, 'github_repository = "evil/substitute"\n');
      symlinkSync(outside, join(dir, "infra", "terraform.tfvars"));
      try {
        assert.throws(() => githubTrustSubject(dir), /terraform\.tfvars is not a safe rendered output file/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
    await t.test("oversized", () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-trust-tfvars-oversized-"));
      mkdirSync(join(dir, "infra"));
      writeFileSync(join(dir, "infra", "terraform.tfvars"), "x".repeat(1_048_577));
      try {
        assert.throws(() => githubTrustSubject(dir), /1048576-byte rendered file limit/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
    await t.test("path replacement", () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-trust-tfvars-swap-"));
      const infra = join(dir, "infra");
      const tfvars = join(infra, "terraform.tfvars");
      const displaced = join(infra, "displaced.tfvars");
      mkdirSync(infra);
      writeFileSync(tfvars, 'github_repository = "acme/original"\n');
      const originalReadSync = fs.readSync;
      let replaced = false;
      fs.readSync = ((...args: Parameters<typeof fs.readSync>): ReturnType<typeof fs.readSync> => {
        const count = originalReadSync(...args);
        if (!replaced) {
          replaced = true;
          fs.renameSync(tfvars, displaced);
          writeFileSync(tfvars, 'github_repository = "evil/replacement"\n');
        }
        return count;
      }) as typeof fs.readSync;
      syncBuiltinESMExports();
      try {
        assert.throws(
          () => githubTrustSubject(dir),
          /terraform\.tfvars (?:changed while it was being rendered|is not a safe rendered output file)/,
        );
      } finally {
        fs.readSync = originalReadSync;
        syncBuiltinESMExports();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  } finally {
    if (priorRepo === undefined) delete process.env.GITHUB_REPOSITORY;
    else process.env.GITHUB_REPOSITORY = priorRepo;
  }
});

test("AWS doctor rejects unsafe vendored Terraform inputs before provider access", async (t) => {
  for (const selected of ["oversized tfvars", "symlinked variables"] as const) {
    await t.test(selected, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-doctor-terraform-input-"));
      const infra = join(dir, "infra");
      mkdirSync(infra);
      if (selected === "oversized tfvars") {
        writeFileSync(join(infra, "terraform.tfvars"), "x".repeat(1_048_577));
      } else {
        const outside = join(dir, "outside.tf");
        writeFileSync(join(infra, "terraform.tfvars"), 'github_repository = "acme/qm"\n');
        writeFileSync(outside, 'variable "org_id" {}\n');
        symlinkSync(outside, join(infra, "variables.tf"));
      }
      const configured = oneServiceConfig();
      const fake = statefulAws(dir, configured);
      try {
        await assert.rejects(
          awsDoctor(configured, dir),
          selected === "oversized tfvars"
            ? /1048576-byte rendered file limit/
            : /variables\.tf is not a safe rendered output file/,
        );
        assert.equal(readFileSync(fake.log, "utf8"), "");
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS doctor requires the public listener transport to match publicUrl", () => {
  const httpsListener = {
    ListenerArn: "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/app/acme/123/456",
    Protocol: "HTTPS",
    Port: 443,
    Certificates: [{ CertificateArn: "arn:aws:acm:us-west-2:123456789012:certificate/abc" }],
  };
  const httpListener = { ...httpsListener, Protocol: "HTTP", Port: 80, Certificates: [] };

  assert.doesNotThrow(() => assertAwsPublicListener("https://agent.acme.example", httpsListener));
  assert.throws(() => assertAwsPublicListener("https://agent.acme.example", httpListener), /configure certificate_arn/);
  assert.throws(
    () => assertAwsPublicListener("https://agent.acme.example", { ...httpsListener, Certificates: [] }),
    /no certificate/,
  );
  assert.doesNotThrow(() => assertAwsPublicListener("http://agent.acme.example", httpListener));
  assert.throws(() => assertAwsPublicListener("http://agent.acme.example", httpsListener), /publicUrl is HTTP/);
});

test("AWS deploy refuses the HTTP bootstrap before any AWS mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-http-bootstrap-"));
  const fake = fakeAws(dir, `console.log("");`);
  try {
    await assert.rejects(
      () => awsUp({ ...config, publicUrl: "http://agent.acme.example" }, process.cwd(), { yes: true }),
      /requires an HTTPS publicUrl.*ACM certificate.*update publicUrl.*rerender\/apply Terraform/,
    );
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy requires the live ALB listener to match the HTTPS public URL", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-live-listener-"));
  const fake = fakeAws(dir, `console.log("");`);
  const prior = process.env.AWS_FAKE_LISTENER_PROTOCOL;
  process.env.AWS_FAKE_LISTENER_PROTOCOL = "HTTP";
  try {
    await assert.rejects(
      () => awsUp(config, process.cwd(), { yes: true }),
      /public front door is not ready.*listener is HTTP:80.*configure certificate_arn.*apply Terraform/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /sts get-caller-identity/);
    assert.match(calls, /elbv2 describe-listeners/);
    assert.doesNotMatch(calls, /dynamodb put-item|ecr get-login-password|ecs update-service/);
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_LISTENER_PROTOCOL;
    else process.env.AWS_FAKE_LISTENER_PROTOCOL = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS TLS preflight accepts a gated apps wildcard on a paginated SNI certificate", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-apps-certificate-pages-"));
  const configured: QmConfig = {
    ...config,
    env: { ...config.env, core: { ...config.env.core, DEPLOY_APPS_DOMAIN: "apps.agent.acme.example" } },
  };
  const fake = statefulAws(dir, configured);
  const prior = process.env.AWS_FAKE_LISTENER_CERTIFICATE_RESPONSE;
  process.env.AWS_FAKE_LISTENER_CERTIFICATE_RESPONSE = "paginated";
  try {
    await awsPreflightUp(configured, dir, { dryRun: true });
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /elbv2 describe-listener-certificates .* --no-paginate/);
    assert.match(calls, /elbv2 describe-listener-certificates .* --no-paginate --marker page-2/);
    assert.match(calls, /acm describe-certificate --certificate-arn .*\/portal/);
    assert.match(calls, /acm describe-certificate --certificate-arn .*\/apps/);
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_LISTENER_CERTIFICATE_RESPONSE;
    else process.env.AWS_FAKE_LISTENER_CERTIFICATE_RESPONSE = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS TLS preflight fails closed on incomplete gated-apps certificate evidence", async (t) => {
  const cases: Array<{
    name: string;
    list?: string;
    acm?: string;
    expected: RegExp;
  }> = [
    { name: "portal-only SAN", acm: "portal-only", expected: /do not cover \*\.apps\.agent\.acme\.example/ },
    { name: "malformed list", list: "malformed", expected: /invalid public-listener certificate list/ },
    { name: "missing list", list: "missing", expected: /certificate list is missing/ },
    { name: "missing ARN", list: "missing-arn", expected: /certificate entry is missing its ARN/ },
    { name: "repeated marker", list: "repeated-marker", expected: /invalid pagination marker/ },
    { name: "malformed ACM response", acm: "malformed", expected: /invalid ACM certificate response/ },
    { name: "missing ACM certificate", acm: "missing", expected: /ACM certificate .* is missing/ },
    { name: "missing ACM SANs", acm: "missing-sans", expected: /invalid identity or subject-alternative names/ },
    { name: "mismatched ACM identity", acm: "mismatch", expected: /invalid identity or subject-alternative names/ },
  ];
  for (const item of cases) {
    await t.test(item.name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-apps-certificate-invalid-"));
      const configured: QmConfig = {
        ...config,
        env: { ...config.env, core: { ...config.env.core, DEPLOY_APPS_DOMAIN: "apps.agent.acme.example" } },
      };
      const fake = statefulAws(dir, configured);
      const priorList = process.env.AWS_FAKE_LISTENER_CERTIFICATE_RESPONSE;
      const priorAcm = process.env.AWS_FAKE_ACM_RESPONSE;
      if (item.list) process.env.AWS_FAKE_LISTENER_CERTIFICATE_RESPONSE = item.list;
      if (item.acm) process.env.AWS_FAKE_ACM_RESPONSE = item.acm;
      try {
        await assert.rejects(awsPreflightUp(configured, dir, { dryRun: true }), item.expected);
        assert.doesNotMatch(
          readFileSync(fake.log, "utf8"),
          /dynamodb put-item|ecr get-login-password|ecs update-service/,
        );
      } finally {
        if (priorList === undefined) delete process.env.AWS_FAKE_LISTENER_CERTIFICATE_RESPONSE;
        else process.env.AWS_FAKE_LISTENER_CERTIFICATE_RESPONSE = priorList;
        if (priorAcm === undefined) delete process.env.AWS_FAKE_ACM_RESPONSE;
        else process.env.AWS_FAKE_ACM_RESPONSE = priorAcm;
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS TLS preflight skips certificate enumeration when no apps domain is configured", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-no-apps-certificate-"));
  const configured = oneServiceConfig();
  const fake = statefulAws(dir, configured);
  try {
    await awsPreflightUp(configured, dir, { dryRun: true });
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /describe-listener-certificates|acm describe-certificate/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy binds its public origin DNS to this stack's ALB", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-dns-binding-"));
  const fake = statefulAws(dir, oneServiceConfig());
  const prior = process.env.AWS_FAKE_ALB_DNS;
  process.env.AWS_FAKE_ALB_DNS = "127.0.0.1";
  try {
    await assert.rejects(
      () => awsUp(oneServiceConfig(), dir, { yes: true }),
      /AWS public origin agent\.acme\.example does not resolve to this stack's ALB 127\.0\.0\.1/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /dynamodb put-item|ecr get-login-password|ecs update-service/);
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_ALB_DNS;
    else process.env.AWS_FAKE_ALB_DNS = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy binds a split public API origin to this stack's ALB", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-api-dns-binding-"));
  const configured = { ...oneServiceConfig(), apiUrl: "https://api.invalid" };
  const fake = statefulAws(dir, configured);
  try {
    await assert.rejects(
      () => awsUp(configured, dir, { yes: true }),
      /AWS public API origin api\.invalid does not resolve to this stack's ALB agent\.acme\.example/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /dynamodb put-item|ecr get-login-password|ecs update-service/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy requires the exact active successful MicroVM image version", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-image-version-"));
  const configured = microvmConfig(oneServiceConfig());
  const fake = statefulAws(dir, configured);
  const prior = process.env.AWS_FAKE_IMAGE_STATE;
  process.env.AWS_FAKE_IMAGE_STATE = "FAILED";
  try {
    await assert.rejects(() => awsUp(configured, dir, { yes: true }), /requires a rebuild before service deployment/);
    const calls = readFileSync(fake.log, "utf8");
    assert.match(
      calls,
      /lambda-microvms get-microvm-image --image-identifier arn:aws:lambda:us-west-2:123456789012:microvm-image:acme-qm-sandbox/,
    );
    assert.match(
      calls,
      /lambda-microvms list-microvm-image-versions --image-identifier arn:aws:lambda:us-west-2:123456789012:microvm-image:acme-qm-sandbox/,
    );
    assert.doesNotMatch(calls, /dynamodb put-item|ecr get-login-password|ecs update-service/);
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_IMAGE_STATE;
    else process.env.AWS_FAKE_IMAGE_STATE = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy fails closed on empty or malformed MicroVM status responses", async (t) => {
  for (const response of [
    "empty",
    "malformed",
    "null",
    "empty-versions",
    "malformed-versions",
    "malformed-version-type",
    "unknown-version-state",
    "unknown-version-status",
  ] as const) {
    await t.test(response, async () => {
      const dir = mkdtempSync(join(tmpdir(), `qm-aws-image-response-${response}-`));
      const configured = microvmConfig(oneServiceConfig());
      const fake = statefulAws(dir, configured);
      const prior = process.env.AWS_FAKE_IMAGE_RESPONSE;
      process.env.AWS_FAKE_IMAGE_RESPONSE = response;
      try {
        await assert.rejects(
          awsUp(configured, dir, { yes: true }),
          /invalid response without an ARN|invalid versions response/,
        );
        assert.doesNotMatch(
          readFileSync(fake.log, "utf8"),
          /dynamodb put-item|ecr get-login-password|ecs update-service/,
        );
      } finally {
        if (prior === undefined) delete process.env.AWS_FAKE_IMAGE_RESPONSE;
        else process.env.AWS_FAKE_IMAGE_RESPONSE = prior;
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS deploy never classifies ResourceNotFoundException from command arguments or secondary error prose", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-image-argv-classification-"));
  const base = microvmConfig(oneServiceConfig());
  const configured: QmConfig = {
    ...base,
    env: {
      ...base.env,
      core: { ...base.env.core, AWS_DEPLOY_IMAGE: "acme-ResourceNotFoundException" },
    },
  };
  const fake = statefulAws(dir, configured);
  const prior = process.env.AWS_FAKE_IMAGE_DENIED;
  process.env.AWS_FAKE_IMAGE_DENIED = "secondary";
  try {
    await assert.rejects(awsUp(configured, dir, { yes: true }), /AccessDeniedException/);
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /dynamodb put-item|ecr get-login-password|ecs update-service/);
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_IMAGE_DENIED;
    else process.env.AWS_FAKE_IMAGE_DENIED = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy requires the live core-only ALB to default 404 and expose exactly /v1/*", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-live-routing-"));
  const run = async (
    env:
      | "AWS_FAKE_DEFAULT_FORWARD"
      | "AWS_FAKE_NO_CORE_RULE"
      | "AWS_FAKE_EXTRA_ACTION"
      | "AWS_FAKE_EXTRA_CONDITION"
      | "AWS_FAKE_EXTRA_RULE",
    expected: RegExp,
  ): Promise<void> => {
    const fake = statefulAws(dir, oneServiceConfig());
    const prior = process.env[env];
    process.env[env] = "1";
    try {
      await assert.rejects(() => awsUp(oneServiceConfig(), dir, { yes: true }), expected);
      assert.doesNotMatch(
        readFileSync(fake.log, "utf8"),
        /dynamodb put-item|ecr get-login-password|ecs update-service/,
      );
    } finally {
      if (prior === undefined) delete process.env[env];
      else process.env[env] = prior;
      fake.restore();
    }
  };
  try {
    await run("AWS_FAKE_DEFAULT_FORWARD", /non-portal listener default must return a fixed 404 response/);
    await run("AWS_FAKE_NO_CORE_RULE", /non-portal ALB must route only \/v1\/\* directly to core/);
    await run("AWS_FAKE_EXTRA_ACTION", /non-portal ALB must route only \/v1\/\* directly to core/);
    await run("AWS_FAKE_EXTRA_CONDITION", /non-portal ALB must route only \/v1\/\* directly to core/);
    await run("AWS_FAKE_EXTRA_RULE", /non-portal ALB has unexpected non-default rules/);
    const portal = statefulAws(dir, config);
    const priorExtraRule = process.env.AWS_FAKE_EXTRA_RULE;
    process.env.AWS_FAKE_EXTRA_RULE = "1";
    try {
      await assert.rejects(
        () => awsUp(config, dir, { yes: true }),
        /portal mode must not expose non-default ALB rules/,
      );
    } finally {
      if (priorExtraRule === undefined) delete process.env.AWS_FAKE_EXTRA_RULE;
      else process.env.AWS_FAKE_EXTRA_RULE = priorExtraRule;
      portal.restore();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS portal ALB adopts pinned target groups and requires exactly the env-derived host rules", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-host-split-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/usr/bin/env node\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`);
  chmodSync(dockerBin, 0o755);
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  const hostSplitConfig = (hosts: { apiUrl?: string; appsDomain?: string; commonAppsDomain?: string }): QmConfig => ({
    ...config,
    ...(hosts.apiUrl ? { apiUrl: hosts.apiUrl } : {}),
    env: {
      ...config.env,
      core: {
        ...config.env.core,
        ...(hosts.appsDomain ? { AWS_DEPLOY_APPS_DOMAIN: hosts.appsDomain } : {}),
        ...(hosts.commonAppsDomain ? { DEPLOY_APPS_DOMAIN: hosts.commonAppsDomain } : {}),
      },
    },
    aws: {
      ...config.aws!,
      services: {
        ...config.aws!.services,
        core: { ...config.aws!.services.core!, targetGroup: "legacy-core-tg" },
        portal: { ...config.aws!.services.portal!, targetGroup: "legacy-portal-tg" },
      },
    },
  });
  const bothHosts = { apiUrl: "https://api.agent.acme.example", appsDomain: "apps.agent.acme.example" };
  const run = async (
    configured: QmConfig,
    env?:
      | "AWS_FAKE_NO_CORE_RULE"
      | "AWS_FAKE_EXTRA_RULE"
      | "AWS_FAKE_WRONG_RULE_TARGET"
      | "AWS_FAKE_WRONG_RULE_HOST"
      | "AWS_FAKE_PUBLIC_API_URL",
    expected?: RegExp,
    envValue = "1",
  ): Promise<void> => {
    const fake = statefulAws(dir, configured);
    const prior = env ? process.env[env] : undefined;
    if (env) process.env[env] = envValue;
    try {
      if (expected) await assert.rejects(() => awsUp(configured, dir, { dryRun: true }), expected);
      else await awsUp(configured, dir, { dryRun: true });
      if (!expected || (env && env !== "AWS_FAKE_PUBLIC_API_URL"))
        assert.match(readFileSync(fake.log, "utf8"), /elbv2 describe-rules/);
    } finally {
      if (env) {
        if (prior === undefined) delete process.env[env];
        else process.env[env] = prior;
      }
      fake.restore();
    }
  };
  try {
    await run(hostSplitConfig(bothHosts));
    await run(
      hostSplitConfig({
        appsDomain: "apps.aws.agent.acme.example",
        commonAppsDomain: "apps.common.agent.acme.example",
      }),
    );
    await run(hostSplitConfig({ apiUrl: bothHosts.apiUrl }));
    await run(hostSplitConfig({ appsDomain: bothHosts.appsDomain }));
    await run(hostSplitConfig({ apiUrl: "https://api.agent.acme.example", appsDomain: "APPS.agent.acme.example." }));
    await run(hostSplitConfig({ appsDomain: `${"a".repeat(62)}.${"b".repeat(63)}` }));
    await run(
      hostSplitConfig({ appsDomain: `${"a".repeat(63)}.${"b".repeat(63)}` }),
      undefined,
      /does not derive a valid ALB host-header hostname/,
    );
    await run(hostSplitConfig({ apiUrl: config.publicUrl }));
    await run(
      hostSplitConfig(bothHosts),
      "AWS_FAKE_NO_CORE_RULE",
      /host rules must route exactly api\.agent\.acme\.example, \*\.apps\.agent\.acme\.example to core \(live: none\)/,
    );
    await run(hostSplitConfig(bothHosts), "AWS_FAKE_EXTRA_RULE", /not a single host-header forward to core/);
    await run(hostSplitConfig(bothHosts), "AWS_FAKE_WRONG_RULE_TARGET", /not a single host-header forward to core/);
    await run(
      hostSplitConfig(bothHosts),
      "AWS_FAKE_WRONG_RULE_HOST",
      /host rules must route exactly .* \(live: other\.example, \*\.apps\.agent\.acme\.example\)/,
    );
    await run(
      hostSplitConfig({ appsDomain: "*.apps.agent.acme.example" }),
      undefined,
      /env\.core\.DEPLOY_APPS_DOMAIN or AWS_DEPLOY_APPS_DOMAIN.* does not derive a valid ALB host-header hostname/,
    );
    await run(hostSplitConfig(bothHosts), "AWS_FAKE_PUBLIC_API_URL", undefined, config.publicUrl);
  } finally {
    process.env.PATH = priorPath;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up scales services to the configured desired count and live check flags drift from it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-desired-count-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/usr/bin/env node\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`);
  chmodSync(dockerBin, 0o755);
  const scaled = (): QmConfig => {
    const base = oneServiceConfig();
    return { ...base, aws: { ...base.aws!, services: { core: { ...base.aws!.services.core!, desiredCount: 2 } } } };
  };
  const fake = statefulAws(dir, scaled());
  const priorPath = process.env.PATH;
  const priorCanaryExit = process.env.AWS_FAKE_CANARY_EXIT;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(scaled(), dir, { yes: true });
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(state.services["acme-core"].desiredCount, 2);
    assert.match(readFileSync(fake.log, "utf8"), /ecs update-service .*--desired-count 2/);
    await assert.doesNotReject(() => awsCheckLive(scaled(), { report: false }));
    assert.match(
      readFileSync(fake.log, "utf8"),
      /ecs run-task .*postdeploy-smoke\.ts.*session.*http:\/\/core\.acme\.internal:8080/,
    );
    process.env.AWS_FAKE_CANARY_EXIT = "1";
    await assert.rejects(
      () => awsCheckLive(scaled(), { report: false }),
      /core: private live session smoke failed: canary task exited 1/,
    );
    if (priorCanaryExit === undefined) delete process.env.AWS_FAKE_CANARY_EXIT;
    else process.env.AWS_FAKE_CANARY_EXIT = priorCanaryExit;
    state.services["acme-core"].desiredCount = 1;
    writeFileSync(fake.state, JSON.stringify(state));
    await assert.rejects(
      () => awsCheckLive(scaled(), { report: false }),
      /core: runtime is ACTIVE with 1\/1 running, expected 2/,
    );
  } finally {
    if (priorCanaryExit === undefined) delete process.env.AWS_FAKE_CANARY_EXIT;
    else process.env.AWS_FAKE_CANARY_EXIT = priorCanaryExit;
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up snapshots the database under the lease before any mutation and records it in the manifest", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-db-snapshot-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/usr/bin/env node\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`);
  chmodSync(dockerBin, 0o755);
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single, {}, { snapshotCreatingPolls: 2 });
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(single, dir, { dryRun: true });
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /rds /, "plan is read-only and never touches RDS");
    await awsUp(single, dir, { yes: true });
    const calls = readFileSync(fake.log, "utf8");
    const lease = calls.indexOf("dynamodb put-item");
    const health = calls.indexOf("rds describe-db-instances --db-instance-identifier acme-qm-core");
    const create = calls.indexOf("rds create-db-snapshot");
    const wait = calls.indexOf("rds describe-db-snapshots --db-snapshot-identifier", create);
    const firstMutation = Math.min(
      ...[
        "s3api put-object",
        "ecr get-login-password",
        "ecs update-service",
        "ecs register-task-definition",
        "dynamodb transact-write-items",
      ]
        .map((call) => calls.indexOf(call))
        .concat(calls.indexOf("dynamodb put-item", lease + 1))
        .filter((index) => index >= 0),
    );
    assert.ok(lease >= 0 && lease < health, "the snapshot happens under the deploy lease");
    assert.ok(health < create && create < wait, "health is verified before creating, and the snapshot is awaited");
    assert.ok(wait < firstMutation, "the snapshot completes before the first mutation");
    assert.equal(
      calls.match(/rds describe-db-snapshots --db-snapshot-identifier/g)?.length,
      3,
      "the wait polls through creating until the snapshot is available",
    );
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    const manifestId = state.dynamo["deployment/current"].manifestId.S as string;
    const manifest = JSON.parse(state.dynamo[`deployment/manifest/${manifestId}`].manifest.S) as {
      dbSnapshot?: string;
    };
    assert.equal(
      manifest.dbSnapshot,
      `acme-qm-core-predeploy-${manifestId}`,
      "the snapshot is named after the manifest it precedes",
    );
    assert.deepEqual(
      (state.rdsSnapshots as Array<{ DBSnapshotIdentifier: string }>).map((item) => item.DBSnapshotIdentifier),
      [`acme-qm-core-predeploy-${manifestId}`],
    );
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up refuses to mutate when the database is unavailable or keeps no automated backups", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-db-unhealthy-"));
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single);
  const priorStatus = process.env.AWS_FAKE_DB_STATUS;
  const priorRetention = process.env.AWS_FAKE_DB_RETENTION;
  try {
    process.env.AWS_FAKE_DB_STATUS = "backing-up";
    await assert.rejects(
      () => awsUp(single, dir, { yes: true }),
      /database acme-qm-core is backing-up; refusing to deploy/,
    );
    delete process.env.AWS_FAKE_DB_STATUS;
    process.env.AWS_FAKE_DB_RETENTION = "0";
    await assert.rejects(
      () => awsUp(single, dir, { yes: true }),
      /keeps 0 day\(s\) of automated backups, below the required 1/,
    );
    delete process.env.AWS_FAKE_DB_RETENTION;
    const strict: QmConfig = { ...single, aws: { ...single.aws!, dbRetentionMinDays: 35 } };
    await assert.rejects(
      () => awsUp(strict, dir, { yes: true }),
      /keeps 7 day\(s\) of automated backups, below the required 35/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.doesNotMatch(calls, /rds create-db-snapshot|ecr get-login-password|ecs update-service|s3api put-object/);
  } finally {
    if (priorStatus === undefined) delete process.env.AWS_FAKE_DB_STATUS;
    else process.env.AWS_FAKE_DB_STATUS = priorStatus;
    if (priorRetention === undefined) delete process.env.AWS_FAKE_DB_RETENTION;
    else process.env.AWS_FAKE_DB_RETENTION = priorRetention;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("aws.predeployDbSnapshot false skips the snapshot without touching RDS", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-db-disabled-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/usr/bin/env node\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`);
  chmodSync(dockerBin, 0o755);
  const base = oneServiceConfig();
  const single: QmConfig = { ...base, aws: { ...base.aws!, predeployDbSnapshot: false } };
  const fake = statefulAws(dir, single);
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(single, dir, { yes: true });
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /rds /);
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    const manifestId = state.dynamo["deployment/current"].manifestId.S as string;
    const manifest = JSON.parse(state.dynamo[`deployment/manifest/${manifestId}`].manifest.S) as {
      dbSnapshot?: string;
    };
    assert.equal(manifest.dbSnapshot, undefined);
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up prunes pre-deploy snapshots beyond the bound, legacy untagged ones included, and never manifest-referenced, foreign, or operator snapshots", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-db-prune-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/usr/bin/env node\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`);
  chmodSync(dockerBin, 0o755);
  const single = oneServiceConfig();
  const clusterTag = [
    { Key: "ManagedBy", Value: "qm-cli" },
    { Key: "QmCluster", Value: "acme-qm" },
  ];
  const fake = statefulAws(
    dir,
    single,
    manifestItems(
      [
        {
          id: "current",
          imageLabel: "release",
          dbSnapshot: "acme-qm-core-predeploy-oldest",
          tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1" },
        },
      ],
      "current",
    ),
  );
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.rdsSnapshots = [
    {
      DBSnapshotIdentifier: "acme-qm-core-predeploy-oldest",
      Status: "available",
      SnapshotCreateTime: "2026-01-01T00:00:00.000Z",
      TagList: clusterTag,
    },
    {
      DBSnapshotIdentifier: "acme-qm-core-predeploy-older",
      Status: "available",
      SnapshotCreateTime: "2026-01-02T00:00:00.000Z",
      TagList: clusterTag,
    },
    {
      DBSnapshotIdentifier: "acme-qm-core-predeploy-newest",
      Status: "available",
      SnapshotCreateTime: "2026-01-03T00:00:00.000Z",
      TagList: clusterTag,
    },
    { DBSnapshotIdentifier: "acme-qm-core-predeploy-aborted", Status: "creating", TagList: clusterTag },
    {
      DBSnapshotIdentifier: "acme-qm-core-predeploy-legacy",
      Status: "available",
      SnapshotCreateTime: "2026-01-01T12:00:00.000Z",
      TagList: [{ Key: "ManagedBy", Value: "qm-cli" }],
    },
    {
      DBSnapshotIdentifier: "acme-qm-core-predeploy-foreign",
      Status: "available",
      SnapshotCreateTime: "2026-01-01T00:00:00.000Z",
      TagList: [
        { Key: "ManagedBy", Value: "qm-cli" },
        { Key: "QmCluster", Value: "other-qm" },
      ],
    },
    {
      DBSnapshotIdentifier: "acme-qm-core-operator-kept",
      Status: "available",
      SnapshotCreateTime: "2020-01-01T00:00:00.000Z",
    },
  ];
  writeFileSync(fake.state, JSON.stringify(state));
  const priorPath = process.env.PATH;
  const priorKeep = process.env.QM_AWS_DB_SNAPSHOT_KEEP;
  process.env.PATH = `${dir}:${priorPath}`;
  process.env.QM_AWS_DB_SNAPSHOT_KEEP = "2";
  try {
    await awsUp(single, dir, { yes: true });
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    const kept = (after.rdsSnapshots as Array<{ DBSnapshotIdentifier: string }>)
      .map((item) => item.DBSnapshotIdentifier)
      .sort();
    const manifestId = after.dynamo["deployment/current"].manifestId.S as string;
    assert.notEqual(manifestId, "current", "the deploy records a new manifest");
    assert.deepEqual(
      kept,
      [
        "acme-qm-core-operator-kept",
        "acme-qm-core-predeploy-aborted",
        "acme-qm-core-predeploy-foreign",
        "acme-qm-core-predeploy-oldest",
        `acme-qm-core-predeploy-${manifestId}`,
      ].sort(),
    );
  } finally {
    process.env.PATH = priorPath;
    if (priorKeep === undefined) delete process.env.QM_AWS_DB_SNAPSHOT_KEEP;
    else process.env.QM_AWS_DB_SNAPSHOT_KEEP = priorKeep;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up fails closed when the snapshot reports an unexpected status or never becomes available", async () => {
  const single = oneServiceConfig();
  const brokenDir = mkdtempSync(join(tmpdir(), "qm-aws-db-broken-"));
  const broken = statefulAws(brokenDir, single, {}, { snapshotStatus: "error" });
  try {
    await assert.rejects(
      () => awsUp(single, brokenDir, { yes: true }),
      /pre-deploy database snapshot .* is error instead of creating/,
    );
    assert.doesNotMatch(readFileSync(broken.log, "utf8"), /ecr get-login-password|ecs update-service|s3api put-object/);
  } finally {
    broken.restore();
    rmSync(brokenDir, { recursive: true, force: true });
  }
  const stuckDir = mkdtempSync(join(tmpdir(), "qm-aws-db-stuck-"));
  const stuck = statefulAws(stuckDir, single, {}, { snapshotCreatingPolls: 10_000 });
  const priorDeadline = process.env.QM_AWS_DB_SNAPSHOT_DEADLINE_MS;
  process.env.QM_AWS_DB_SNAPSHOT_DEADLINE_MS = "40";
  try {
    await assert.rejects(
      () => awsUp(single, stuckDir, { yes: true }),
      /timed out waiting for pre-deploy database snapshot/,
    );
    assert.doesNotMatch(readFileSync(stuck.log, "utf8"), /ecr get-login-password|ecs update-service|s3api put-object/);
  } finally {
    if (priorDeadline === undefined) delete process.env.QM_AWS_DB_SNAPSHOT_DEADLINE_MS;
    else process.env.QM_AWS_DB_SNAPSHOT_DEADLINE_MS = priorDeadline;
    stuck.restore();
    rmSync(stuckDir, { recursive: true, force: true });
  }
});

test("a snapshot prune failure warns without failing the deploy", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-db-prune-warn-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/usr/bin/env node\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`);
  chmodSync(dockerBin, 0o755);
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single, {}, { failSnapshotDelete: true, staleTaskDefinition: true });
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.rdsSnapshots = [
    {
      DBSnapshotIdentifier: "acme-qm-core-predeploy-stale",
      Status: "available",
      SnapshotCreateTime: "2026-01-01T00:00:00.000Z",
      TagList: [{ Key: "QmCluster", Value: "acme-qm" }],
    },
  ];
  writeFileSync(fake.state, JSON.stringify(state));
  const priorPath = process.env.PATH;
  const priorKeep = process.env.QM_AWS_DB_SNAPSHOT_KEEP;
  process.env.PATH = `${dir}:${priorPath}`;
  process.env.QM_AWS_DB_SNAPSHOT_KEEP = "1";
  const warnings: string[] = [];
  const warnLog = console.warn;
  console.warn = (...parts: unknown[]): void => void warnings.push(parts.join(" "));
  try {
    await awsUp(single, dir, { yes: true });
    assert.match(warnings.join("\n"), /could not prune pre-deploy database snapshot acme-qm-core-predeploy-stale/);
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.ok(after.dynamo["deployment/current"], "the deploy still records its manifest");
    assert.match(readFileSync(fake.log, "utf8"), /ecs update-service/);
  } finally {
    console.warn = warnLog;
    process.env.PATH = priorPath;
    if (priorKeep === undefined) delete process.env.QM_AWS_DB_SNAPSHOT_KEEP;
    else process.env.QM_AWS_DB_SNAPSHOT_KEEP = priorKeep;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the snapshot wait tolerates transient describe failures and fails after three in a row", async () => {
  const single = oneServiceConfig();
  const transientDir = mkdtempSync(join(tmpdir(), "qm-aws-db-transient-"));
  const transientDocker = join(transientDir, "docker");
  writeFileSync(transientDocker, `#!/usr/bin/env node\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`);
  chmodSync(transientDocker, 0o755);
  const transient = statefulAws(transientDir, single, {}, { failSnapshotDescribes: 1, staleTaskDefinition: true });
  const priorPath = process.env.PATH;
  process.env.PATH = `${transientDir}:${priorPath}`;
  try {
    await awsUp(single, transientDir, { yes: true });
    assert.match(readFileSync(transient.log, "utf8"), /ecs update-service/);
  } finally {
    process.env.PATH = priorPath;
    transient.restore();
    rmSync(transientDir, { recursive: true, force: true });
  }
  const brokenDir = mkdtempSync(join(tmpdir(), "qm-aws-db-describe-broken-"));
  const broken = statefulAws(brokenDir, single, {}, { failSnapshotDescribes: 10_000 });
  try {
    await assert.rejects(() => awsUp(single, brokenDir, { yes: true }), /TransientSnapshotDescribeFailure/);
    assert.doesNotMatch(readFileSync(broken.log, "utf8"), /ecr get-login-password|ecs update-service|s3api put-object/);
  } finally {
    broken.restore();
    rmSync(brokenDir, { recursive: true, force: true });
  }
});

test("a no-op re-deploy isolates its staging tag and deletes its unreferenced pre-deploy snapshot", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-db-noop-"));
  const dockerLog = join(dir, "docker.log");
  writeFileSync(dockerLog, "");
  const dockerBin = join(dir, "docker");
  writeFileSync(
    dockerBin,
    `#!/usr/bin/env node\nrequire("node:fs").appendFileSync(${JSON.stringify(dockerLog)}, process.argv.slice(2).join(" ") + "\\n");\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`,
  );
  chmodSync(dockerBin, 0o755);
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single);
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(single, dir, { yes: true });
    const first = JSON.parse(readFileSync(fake.state, "utf8"));
    const firstManifestId = first.dynamo["deployment/current"].manifestId.S as string;
    await awsUp(single, dir, { yes: true });
    const second = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(second.dynamo["deployment/current"].manifestId.S, firstManifestId);
    assert.deepEqual(
      (second.rdsSnapshots as Array<{ DBSnapshotIdentifier: string }>).map((item) => item.DBSnapshotIdentifier),
      [`acme-qm-core-predeploy-${firstManifestId}`],
      "the no-op run's snapshot protects nothing and is deleted",
    );
    const staged = [...readFileSync(dockerLog, "utf8").matchAll(/--tag \S+:(qm-staging-[0-9a-f-]{36})(?:\s|$)/g)].map(
      (match) => match[1]!,
    );
    assert.equal(staged.length, 2);
    assert.notEqual(staged[0], staged[1]);
    const cleanups = [
      ...readFileSync(fake.log, "utf8").matchAll(
        /ecr batch-delete-image[^\n]*--image-ids imageTag=(qm-staging-[0-9a-f-]{36})(?:\s|$)/g,
      ),
    ].map((match) => match[1]!);
    assert.deepEqual(cleanups, staged);
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up renews the deploy lease with a holder-conditioned update while it runs", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-renew-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/usr/bin/env node\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`);
  chmodSync(dockerBin, 0o755);
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single, {}, { snapshotCreatingPolls: 3 });
  const priorPath = process.env.PATH;
  const priorRenew = process.env.QM_AWS_LEASE_RENEW_MS;
  process.env.PATH = `${dir}:${priorPath}`;
  process.env.QM_AWS_LEASE_RENEW_MS = "10";
  try {
    await awsUp(single, dir, { yes: true });
    const calls = readFileSync(fake.log, "utf8");
    assert.match(
      calls,
      /dynamodb update-item --table-name acme-qm-deploy-locks --key \{"lockKey":\{"S":"deploy"\}\} --update-expression SET expiresAt = :expiresAt --condition-expression holder = :holder/,
    );
    assert.ok(
      calls.indexOf("dynamodb update-item") < calls.indexOf("dynamodb delete-item"),
      "renewal happens while the lease is held",
    );
  } finally {
    process.env.PATH = priorPath;
    if (priorRenew === undefined) delete process.env.QM_AWS_LEASE_RENEW_MS;
    else process.env.QM_AWS_LEASE_RENEW_MS = priorRenew;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an independent AWS lease renewer runs while the main event loop is synchronously blocked past its TTL", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-blocked-loop-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb update-item") && process.env.AWS_TEST_CREDENTIAL !== "present") { console.error("AccessDeniedException"); process.exit(1); }
console.log("");`,
  );
  const priorRenew = process.env.QM_AWS_LEASE_RENEW_MS;
  const priorSeconds = process.env.QM_AWS_LEASE_SECONDS;
  const priorCredential = process.env.AWS_TEST_CREDENTIAL;
  process.env.QM_AWS_LEASE_RENEW_MS = "20";
  process.env.QM_AWS_LEASE_SECONDS = "1";
  process.env.AWS_TEST_CREDENTIAL = "present";
  try {
    await withAwsLease(config.aws!, async () => {
      spawnSync(process.execPath, ["-e", "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1250)"]);
    });
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /dynamodb update-item/);
    assert.ok(calls.indexOf("dynamodb update-item") < calls.indexOf("dynamodb delete-item"));
  } finally {
    if (priorRenew === undefined) delete process.env.QM_AWS_LEASE_RENEW_MS;
    else process.env.QM_AWS_LEASE_RENEW_MS = priorRenew;
    if (priorSeconds === undefined) delete process.env.QM_AWS_LEASE_SECONDS;
    else process.env.QM_AWS_LEASE_SECONDS = priorSeconds;
    if (priorCredential === undefined) delete process.env.AWS_TEST_CREDENTIAL;
    else process.env.AWS_TEST_CREDENTIAL = priorCredential;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("non-conditional AWS lease renewal failures abort once the held TTL expires", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-renewal-failure-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb update-item")) { console.error("An error occurred (AccessDeniedException) when calling the UpdateItem operation"); process.exit(1); }
console.log("");`,
  );
  const priorRenew = process.env.QM_AWS_LEASE_RENEW_MS;
  const priorSeconds = process.env.QM_AWS_LEASE_SECONDS;
  process.env.QM_AWS_LEASE_RENEW_MS = "50";
  process.env.QM_AWS_LEASE_SECONDS = "1";
  const warnLog = console.warn;
  console.warn = () => {};
  try {
    await assert.rejects(
      withAwsLease(config.aws!, async () => {
        await new Promise((resolve) => setTimeout(resolve, 2_200));
      }),
      /AWS deployment lease crossed its safe renewal deadline/,
    );
    assert.match(readFileSync(fake.log, "utf8"), /dynamodb update-item/);
  } finally {
    console.warn = warnLog;
    if (priorRenew === undefined) delete process.env.QM_AWS_LEASE_RENEW_MS;
    else process.env.QM_AWS_LEASE_RENEW_MS = priorRenew;
    if (priorSeconds === undefined) delete process.env.QM_AWS_LEASE_SECONDS;
    else process.env.QM_AWS_LEASE_SECONDS = priorSeconds;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an immediate AWS lease renewal loss cleans up the acquired lease and signal handlers", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-immediate-loss-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb update-item")) {
  console.error("An error occurred (ConditionalCheckFailedException) when calling the UpdateItem operation");
  process.exit(1);
}
console.log("");`,
  );
  const sigint = process.listenerCount("SIGINT");
  const sigterm = process.listenerCount("SIGTERM");
  const blockTurn = setTimeout(() => {
    spawnSync(process.execPath, ["-e", "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300)"]);
  }, 0);
  try {
    await assert.rejects(
      withAwsLease(config.aws!, async () => assert.fail("operation started after its lease was lost")),
      /AWS deployment lease was lost to another operation/,
    );
    assert.equal(process.listenerCount("SIGINT"), sigint);
    assert.equal(process.listenerCount("SIGTERM"), sigterm);
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /dynamodb update-item/);
    assert.match(calls, /dynamodb delete-item .*--condition-expression holder = :holder/);
  } finally {
    clearTimeout(blockTurn);
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a stalled AWS lease renewal crosses the shared safety deadline closed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-stalled-renewal-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb update-item")) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500);
console.log("");`,
  );
  const priorRenew = process.env.QM_AWS_LEASE_RENEW_MS;
  const priorSeconds = process.env.QM_AWS_LEASE_SECONDS;
  process.env.QM_AWS_LEASE_RENEW_MS = "5";
  process.env.QM_AWS_LEASE_SECONDS = "1";
  try {
    await assert.rejects(
      withAwsLease(config.aws!, async () => {
        await new Promise((resolve) => setTimeout(resolve, 2_200));
        awsText(config.aws!, ["sts", "get-caller-identity"]);
      }),
      /AWS deployment lease crossed its safe renewal deadline/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /dynamodb update-item/);
    assert.doesNotMatch(calls, /sts get-caller-identity/);
  } finally {
    if (priorRenew === undefined) delete process.env.QM_AWS_LEASE_RENEW_MS;
    else process.env.QM_AWS_LEASE_RENEW_MS = priorRenew;
    if (priorSeconds === undefined) delete process.env.QM_AWS_LEASE_SECONDS;
    else process.env.QM_AWS_LEASE_SECONDS = priorSeconds;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS lease release joins its renewer and removes signal handlers", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-renewer-stop-"));
  const fake = fakeAws(dir, `console.log("");`);
  const priorRenew = process.env.QM_AWS_LEASE_RENEW_MS;
  process.env.QM_AWS_LEASE_RENEW_MS = "5";
  const sigint = process.listenerCount("SIGINT");
  const sigterm = process.listenerCount("SIGTERM");
  try {
    await withAwsLease(config.aws!, async () => {
      await new Promise((resolve) => setTimeout(resolve, 80));
    });
    const stoppedCalls = readFileSync(fake.log, "utf8");
    const renewals = stoppedCalls.match(/dynamodb update-item/g)?.length ?? 0;
    assert.ok(renewals > 0);
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert.equal(readFileSync(fake.log, "utf8").match(/dynamodb update-item/g)?.length ?? 0, renewals);
    assert.equal(process.listenerCount("SIGINT"), sigint);
    assert.equal(process.listenerCount("SIGTERM"), sigterm);
  } finally {
    if (priorRenew === undefined) delete process.env.QM_AWS_LEASE_RENEW_MS;
    else process.env.QM_AWS_LEASE_RENEW_MS = priorRenew;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS lease release terminates a stalled renewer before conditioned cleanup", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-renewer-timeout-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb update-item")) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500);
console.log("");`,
  );
  const priorRenew = process.env.QM_AWS_LEASE_RENEW_MS;
  const priorStop = process.env.QM_AWS_LEASE_RENEW_STOP_TIMEOUT_MS;
  process.env.QM_AWS_LEASE_RENEW_MS = "5";
  process.env.QM_AWS_LEASE_RENEW_STOP_TIMEOUT_MS = "20";
  try {
    await assert.rejects(
      withAwsLease(config.aws!, async () => {
        for (
          let attempt = 0;
          attempt < 500 && !readFileSync(fake.log, "utf8").includes("dynamodb update-item");
          attempt++
        ) {
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
      }),
      /could not stop the AWS deployment lease renewer cleanly/,
    );
    const calls = readFileSync(fake.log, "utf8");
    const renewals = calls.match(/dynamodb update-item/g)?.length ?? 0;
    assert.ok(renewals > 0);
    assert.match(calls, /dynamodb delete-item .*--condition-expression holder = :holder/);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(readFileSync(fake.log, "utf8").match(/dynamodb update-item/g)?.length ?? 0, renewals);
  } finally {
    if (priorRenew === undefined) delete process.env.QM_AWS_LEASE_RENEW_MS;
    else process.env.QM_AWS_LEASE_RENEW_MS = priorRenew;
    if (priorStop === undefined) delete process.env.QM_AWS_LEASE_RENEW_STOP_TIMEOUT_MS;
    else process.env.QM_AWS_LEASE_RENEW_STOP_TIMEOUT_MS = priorStop;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a lost AWS lease blocks the next provider command and cannot report operation success", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-lost-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb update-item")) { console.error("An error occurred (ConditionalCheckFailedException) when calling the UpdateItem operation"); process.exit(1); }
console.log("");`,
  );
  const priorRenew = process.env.QM_AWS_LEASE_RENEW_MS;
  process.env.QM_AWS_LEASE_RENEW_MS = "5";
  const waitForLoss = async (state: Int32Array): Promise<void> => {
    for (let attempt = 0; attempt < 500 && Atomics.load(state, 0) === 0; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.notEqual(Atomics.load(state, 0), 0);
  };
  try {
    await t.test("command boundary", async () => {
      await assert.rejects(
        withAwsLease(config.aws!, async (lease) => {
          await waitForLoss(lease.state);
          awsText(config.aws!, ["sts", "get-caller-identity"]);
        }),
        /AWS deployment lease was lost to another operation/,
      );
      assert.doesNotMatch(readFileSync(fake.log, "utf8"), /sts get-caller-identity/);
    });
    writeFileSync(fake.log, "");
    await t.test("inherited-process boundary", async () => {
      const marker = join(dir, "process-boundary-ran");
      await assert.rejects(
        withAwsLease(config.aws!, async (lease) => {
          await waitForLoss(lease.state);
          awsRunInherit(process.execPath, ["-e", `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ran")`]);
        }),
        /AWS deployment lease was lost to another operation/,
      );
      assert.equal(existsSync(marker), false);
    });
    writeFileSync(fake.log, "");
    await t.test("HTTP boundary", async () => {
      const priorFetch = globalThis.fetch;
      let fetches = 0;
      globalThis.fetch = (async () => {
        fetches += 1;
        return new Response("");
      }) as typeof fetch;
      try {
        await assert.rejects(
          withAwsLease(config.aws!, async (lease) => {
            await waitForLoss(lease.state);
            await awsDeploymentLayerTransport({
              config,
              configIdentity: TEST_CONFIG_IDENTITY,
              configDir: dir,
              method: "GET",
              body: "",
            });
          }),
          /AWS deployment lease was lost to another operation/,
        );
        assert.equal(fetches, 0);
      } finally {
        globalThis.fetch = priorFetch;
      }
    });
    writeFileSync(fake.log, "");
    await t.test("final success boundary", async () => {
      await assert.rejects(
        withAwsLease(config.aws!, async (lease) => {
          await waitForLoss(lease.state);
          return "completed";
        }),
        /AWS deployment lease was lost to another operation/,
      );
    });
  } finally {
    if (priorRenew === undefined) delete process.env.QM_AWS_LEASE_RENEW_MS;
    else process.env.QM_AWS_LEASE_RENEW_MS = priorRenew;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS preflight stops after lease loss during its public network request", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-network-loss-"));
  const lossMarker = join(dir, "lose-lease");
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single, {}, { leaseLossMarker: lossMarker });
  const providerFetch = globalThis.fetch;
  globalThis.fetch = async (...args) => {
    if (!String(args[0]).includes("/v1/deployment-layer")) {
      writeFileSync(lossMarker, "lose");
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
    return providerFetch(...args);
  };
  const priorRenew = process.env.QM_AWS_LEASE_RENEW_MS;
  process.env.QM_AWS_LEASE_RENEW_MS = "5";
  try {
    await assert.rejects(
      withAwsLease(single.aws!, () => awsPreflightUp(single, dir, { yes: true })),
      /AWS deployment lease was lost to another operation/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /dynamodb update-item/);
    assert.doesNotMatch(calls, /secretsmanager get-secret-value|lambda-microvms get-microvm-image/);
  } finally {
    if (priorRenew === undefined) delete process.env.QM_AWS_LEASE_RENEW_MS;
    else process.env.QM_AWS_LEASE_RENEW_MS = priorRenew;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy rejects a NUL-bearing PUBLIC_API_URL before attempting its derived repair", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-public-api-url-"));
  const fake = statefulAws(dir, oneServiceConfig());
  const prior = process.env.AWS_FAKE_NUL_SECRET_NAME;
  process.env.AWS_FAKE_NUL_SECRET_NAME = "PUBLIC_API_URL";
  try {
    await assert.rejects(() => awsUp(oneServiceConfig(), dir, { yes: true }), /PUBLIC_API_URL contains a NUL byte/);
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /get-secret-value .*PUBLIC_API_URL/);
    assert.doesNotMatch(calls, /dynamodb put-item|ecr get-login-password|ecs update-service/);
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_NUL_SECRET_NAME;
    else process.env.AWS_FAKE_NUL_SECRET_NAME = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("every AWS mutation rejects the wrong caller account before side effects", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-account-guard-"));
  const fake = fakeAws(dir, `console.log("");`);
  const envFile = join(dir, "deployment.env");
  writeFileSync(
    envFile,
    `${computedSecrets(oneServiceConfig())
      .filter((secret) => secret.managedBy === "operator")
      .map((secret) => `${secret.name}=${selectedTestSecretValue(secret.name)}`)
      .join("\n")}\n`,
  );
  const prior = process.env.AWS_FAKE_ACCOUNT;
  process.env.AWS_FAKE_ACCOUNT = "999999999999";
  const mismatch = /authenticated to AWS account 999999999999, expected 123456789012/;
  try {
    await assert.rejects(() => awsUp(oneServiceConfig(), dir, { yes: true }), mismatch);
    await assert.rejects(() => awsUp(oneServiceConfig(), dir, { dryRun: true }), mismatch);
    await assert.rejects(() => awsDown(oneServiceConfig()), mismatch);
    await assert.rejects(() => awsRollback(oneServiceConfig()), mismatch);
    await assert.rejects(() => awsSecretsPush(oneServiceConfig(), dir, testSecretValues(dir, envFile)), mismatch);
    const calls = readFileSync(fake.log, "utf8");
    assert.equal(calls.match(/sts get-caller-identity/g)?.length, 5);
    assert.doesNotMatch(calls, /dynamodb|ecr |ecs update-service|secretsmanager/);
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_ACCOUNT;
    else process.env.AWS_FAKE_ACCOUNT = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy rejects required secret containers without an AWSCURRENT value before mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-empty-secret-"));
  const targetName = `acme-qm-port-${createHash("sha1").update("acme-qm:portal").digest("hex").slice(0, 6)}`;
  const targetArn = `arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/${targetName}/1`;
  const fake = fakeAws(
    dir,
    `
if (a.includes("ecs describe-services")) console.log(JSON.stringify({ services: ${JSON.stringify(
      Object.entries(config.aws!.services).map(([name, spec]) => ({
        serviceName: spec.ecsService,
        status: "ACTIVE",
        desiredCount: 1,
        taskDefinition: `arn:aws:ecs:us-west-2:123456789012:task-definition/${spec.ecsService}:1`,
        loadBalancers: name === "portal" ? [{ targetGroupArn: targetArn }] : [],
        tags: [
          { key: "Deployment", value: config.orgId },
          { key: "ManagedBy", value: "terraform" },
        ],
      })),
    )} }));
else if (a.includes("secretsmanager get-secret-value")) {
  console.error("ResourceNotFoundException: Secrets Manager can't find the specified secret value");
  process.exit(1);
}
console.log("");`,
  );
  try {
    await assert.rejects(() => awsUp(config, process.cwd(), { yes: true }), /ResourceNotFoundException/);
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /secretsmanager get-secret-value/);
    assert.doesNotMatch(calls, /dynamodb put-item|ecr get-login-password|ecr describe-images|ecs update-service/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy rejects weak signing keys before mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-weak-secret-"));
  const fake = statefulAws(dir, oneServiceConfig());
  const prior = process.env.AWS_FAKE_SECRET_VALUE;
  process.env.AWS_FAKE_SECRET_VALUE = "short";
  try {
    await assert.rejects(
      () => awsUp(oneServiceConfig(), dir, { yes: true }),
      /required AWS secret CORE_SIGNING_SECRET has no usable/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /dynamodb put-item|ecr describe-images|ecs update-service/);
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_SECRET_VALUE;
    else process.env.AWS_FAKE_SECRET_VALUE = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy rejects individually valid duplicate authoritative runtime secrets before mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-duplicate-remote-secret-"));
  const configured = oneServiceConfig();
  const fake = statefulAws(dir, configured);
  const prior = process.env.AWS_FAKE_SECRET_VALUE;
  process.env.AWS_FAKE_SECRET_VALUE = `CAPABILITY_SECRET-${TEST_SECRET_VALUE}`;
  try {
    await assert.rejects(
      () => awsUp(configured, dir, { yes: true }),
      /AWS secrets failed runtime validation: CAPABILITY_SECRET, CORE_SIGNING_SECRET/,
    );
    assert.doesNotMatch(
      readFileSync(fake.log, "utf8"),
      /dynamodb put-item|rds create-db-snapshot|ecr get-login-password|ecs update-service/,
    );
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_SECRET_VALUE;
    else process.env.AWS_FAKE_SECRET_VALUE = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy rejects a local signing secret that differs from Secrets Manager before mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-signing-secret-mismatch-"));
  const configured = oneServiceConfig();
  const configPath = join(dir, "qm.config.jsonc");
  const envFile = join(dir, "deployment.env");
  const raw = JSON.stringify(configured);
  writeFileSync(configPath, raw);
  writeFileSync(envFile, `CORE_SIGNING_SECRET=${"different-signing-secret".repeat(3)}\n`);
  const fake = statefulAws(dir, configured);
  try {
    const ctx: DeployContext = {
      config: configured,
      configPath,
      configIdentity: configIdentity(configPath),
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      envFile,
      target: "aws",
    };
    const provider = hostingProvider("aws");
    const options = provider.upOptions(ctx, { yes: true }, false);
    await assert.rejects(async () => {
      const preflighted = await provider.preflightUp(ctx, options);
      const prepared = await prepareUpSubstrate(preflighted, options);
      await provider.createBackend(prepared).up(options);
    }, /CORE_SIGNING_SECRET .*does not match.*AWS Secrets Manager/);
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /secretsmanager get-secret-value .*CORE_SIGNING_SECRET/);
    assert.doesNotMatch(
      calls,
      /s3api (?:put-object|delete-object)|lambda-microvms (?:create|update|delete|terminate)|dynamodb (?:put-item|update-item|delete-item|transact-write-items)|rds (?:create|delete)-db-snapshot|ecr (?:put-image|batch-delete-image)|ecs (?:run-task|register-task-definition|deregister-task-definition|update-service)|secretsmanager (?:create-secret|put-secret-value|update-secret|delete-secret)/,
    );
    assert.equal(readFileSync(configPath, "utf8"), raw);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS preflight reads the default deployment env file for signing-secret consistency", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-default-signing-secret-mismatch-"));
  const configured = oneServiceConfig();
  const configPath = join(dir, "qm.config.jsonc");
  writeFileSync(configPath, JSON.stringify(configured));
  writeFileSync(join(dir, ".env"), `CORE_SIGNING_SECRET=${"different-default-signing-secret".repeat(2)}\n`);
  const fake = statefulAws(dir, configured);
  try {
    const ctx: DeployContext = {
      config: configured,
      configPath,
      configIdentity: configIdentity(configPath),
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      target: "aws",
    };
    const provider = hostingProvider("aws");
    const options = provider.upOptions(ctx, { yes: true }, false);
    await assert.rejects(provider.preflightUp(ctx, options), /CORE_SIGNING_SECRET .*does not match/);
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /lambda-microvms (?:create|update|delete)|dynamodb put-item/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy rechecks the authoritative signing secret under its lease before stack mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rotated-signing-secret-"));
  const configured = oneServiceConfig();
  const configPath = join(dir, "qm.config.jsonc");
  const envFile = join(dir, "deployment.env");
  writeFileSync(configPath, JSON.stringify(configured));
  writeFileSync(envFile, `CORE_SIGNING_SECRET=${TEST_SECRET_VALUE}\n`);
  const fake = statefulAws(dir, configured);
  const prior = process.env.AWS_FAKE_ROTATE_SIGNING_SECRET;
  process.env.AWS_FAKE_ROTATE_SIGNING_SECRET = "1";
  try {
    const ctx: DeployContext = {
      config: configured,
      configPath,
      configIdentity: configIdentity(configPath),
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      envFile,
      target: "aws",
    };
    const provider = hostingProvider("aws");
    const options = provider.upOptions(ctx, { yes: true }, false);
    const preflighted = await provider.preflightUp(ctx, options);
    await assert.rejects(
      awsUp(configured, dir, { yes: true, envFile, preflight: preflighted.awsPreflight }),
      /CORE_SIGNING_SECRET .*does not match.*AWS Secrets Manager/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.ok(calls.indexOf("dynamodb put-item") < calls.lastIndexOf("CORE_SIGNING_SECRET"));
    assert.match(calls, /dynamodb delete-item/);
    assert.doesNotMatch(
      calls,
      /s3api put-object|rds create-db-snapshot|ecr get-login-password|ecs register-task-definition|ecs update-service/,
    );
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_ROTATE_SIGNING_SECRET;
    else process.env.AWS_FAKE_ROTATE_SIGNING_SECRET = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy rechecks authoritative secret ARN ownership under its lease before stack mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rotated-secret-arn-"));
  const configured = oneServiceConfig();
  const configPath = join(dir, "qm.config.jsonc");
  writeFileSync(configPath, JSON.stringify(configured));
  const fake = statefulAws(dir, configured);
  const prior = process.env.AWS_FAKE_ROTATE_SECRET_ARN;
  process.env.AWS_FAKE_ROTATE_SECRET_ARN = "1";
  try {
    const ctx: DeployContext = {
      config: configured,
      configPath,
      configIdentity: configIdentity(configPath),
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      target: "aws",
    };
    const provider = hostingProvider("aws");
    const options = provider.upOptions(ctx, { yes: true }, false);
    const preflighted = await provider.preflightUp(ctx, options);
    await assert.rejects(
      awsUp(configured, dir, { yes: true, preflight: preflighted.awsPreflight }),
      /AWS secret CORE_SIGNING_SECRET returned an ARN outside the configured account and secret path/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.ok(calls.indexOf("dynamodb put-item") < calls.lastIndexOf("CORE_SIGNING_SECRET"));
    assert.match(calls, /dynamodb delete-item/);
    assert.doesNotMatch(
      calls,
      /s3api put-object|rds create-db-snapshot|ecr get-login-password|ecs register-task-definition|ecs update-service/,
    );
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_ROTATE_SECRET_ARN;
    else process.env.AWS_FAKE_ROTATE_SECRET_ARN = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS deploy revalidates aliased portal trust from its authoritative store under the lease", async (t) => {
  for (const kind of ["portal", "auth"] as const) {
    await t.test(kind, async () => {
      const dir = mkdtempSync(join(tmpdir(), `qm-aws-${kind}-alias-up-`));
      const selected = aliasedTrustConfig(kind);
      const dockerLog = join(dir, "docker.log");
      const dockerBin = join(dir, "docker");
      writeFileSync(dockerLog, "");
      writeFileSync(dockerBin, `#!/bin/sh\nprintf ran >> ${JSON.stringify(dockerLog)}\n`);
      chmodSync(dockerBin, 0o755);
      const configPath = join(dir, "qm.config.jsonc");
      writeFileSync(configPath, JSON.stringify(selected.config));
      const fake = statefulAws(dir, selected.config);
      const priorPath = process.env.PATH;
      const priorCore = process.env.CORE_SIGNING_SECRET;
      const priorOverrides = process.env.AWS_FAKE_SECRET_OVERRIDES;
      const priorRotateName = process.env.AWS_FAKE_ROTATE_SECRET_NAME;
      const priorRotatedValue = process.env.AWS_FAKE_ROTATED_SECRET_VALUE;
      process.env.PATH = `${dir}:${priorPath}`;
      process.env.CORE_SIGNING_SECRET = TEST_SECRET_VALUE;
      process.env.AWS_FAKE_SECRET_OVERRIDES = JSON.stringify({
        AUTH_EMAIL_FROM: selectedTestSecretValue("AUTH_EMAIL_FROM"),
        AUTH_SIGNING_JWK: selectedTestSecretValue("AUTH_SIGNING_JWK"),
        [selected.storeName]: "admin@example.com",
      });
      process.env.AWS_FAKE_ROTATE_SECRET_NAME = selected.storeName;
      process.env.AWS_FAKE_ROTATED_SECRET_VALUE = "not-an-email";
      try {
        const preflight = await awsPreflightUp(selected.config, dir, { yes: true });
        await assert.rejects(
          awsUp(selected.config, dir, { yes: true, preflight }),
          kind === "portal"
            ? /OIDC_ALLOWED_EMAILS must contain valid, non-placeholder email addresses/
            : /required AWS secret AUTH_ALLOWED_EMAILS has no usable runtime value/,
        );
        const calls = readFileSync(fake.log, "utf8");
        assert.ok(calls.indexOf("dynamodb put-item") < calls.lastIndexOf(selected.storeName));
        assert.match(calls, /dynamodb delete-item/);
        assert.doesNotMatch(
          calls,
          /s3api put-object|rds create-db-snapshot|ecr get-login-password|ecs register-task-definition|ecs update-service/,
        );
        assert.equal(readFileSync(dockerLog, "utf8"), "");
      } finally {
        process.env.PATH = priorPath;
        if (priorCore === undefined) delete process.env.CORE_SIGNING_SECRET;
        else process.env.CORE_SIGNING_SECRET = priorCore;
        if (priorOverrides === undefined) delete process.env.AWS_FAKE_SECRET_OVERRIDES;
        else process.env.AWS_FAKE_SECRET_OVERRIDES = priorOverrides;
        if (priorRotateName === undefined) delete process.env.AWS_FAKE_ROTATE_SECRET_NAME;
        else process.env.AWS_FAKE_ROTATE_SECRET_NAME = priorRotateName;
        if (priorRotatedValue === undefined) delete process.env.AWS_FAKE_ROTATED_SECRET_VALUE;
        else process.env.AWS_FAKE_ROTATED_SECRET_VALUE = priorRotatedValue;
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS preflight treats an exactly empty env-file signing secret as absent", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-blank-signing-secret-"));
  const configured = oneServiceConfig();
  const configPath = join(dir, "qm.config.jsonc");
  const envFile = join(dir, "deployment.env");
  writeFileSync(configPath, JSON.stringify(configured));
  writeFileSync(envFile, 'CORE_SIGNING_SECRET=""\n');
  const fake = statefulAws(dir, configured);
  const prior = process.env.CORE_SIGNING_SECRET;
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  process.env.CORE_SIGNING_SECRET = TEST_SECRET_VALUE;
  delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
  try {
    const ctx: DeployContext = {
      config: configured,
      configPath,
      configIdentity: configIdentity(configPath),
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      envFile,
      target: "aws",
    };
    const provider = hostingProvider("aws");
    const options = provider.upOptions(ctx, { yes: true }, false);
    await assert.doesNotReject(provider.preflightUp(ctx, options));
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /lambda-microvms (?:create|update|delete)|dynamodb put-item/);
  } finally {
    if (prior === undefined) delete process.env.CORE_SIGNING_SECRET;
    else process.env.CORE_SIGNING_SECRET = prior;
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS preflight requires a named env file at backend admission", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-missing-env-file-"));
  const configured = oneServiceConfig();
  const fake = statefulAws(dir, configured);
  try {
    await assert.rejects(
      awsPreflightUp(configured, dir, { envFile: join(dir, "removed.env") }),
      /--env-file not found/,
    );
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS preflight treats whitespace signing-secret bytes as a selected value", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-whitespace-signing-secret-"));
  const configured = oneServiceConfig();
  const configPath = join(dir, "qm.config.jsonc");
  const envFile = join(dir, "deployment.env");
  writeFileSync(configPath, JSON.stringify(configured));
  writeFileSync(envFile, 'CORE_SIGNING_SECRET="                                "\n');
  const fake = statefulAws(dir, configured);
  const prior = process.env.CORE_SIGNING_SECRET;
  process.env.CORE_SIGNING_SECRET = TEST_SECRET_VALUE;
  try {
    const ctx: DeployContext = {
      config: configured,
      configPath,
      configIdentity: configIdentity(configPath),
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      envFile,
      target: "aws",
    };
    const provider = hostingProvider("aws");
    const options = provider.upOptions(ctx, { yes: true }, false);
    await assert.rejects(provider.preflightUp(ctx, options), /CORE_SIGNING_SECRET .*does not match/);
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /dynamodb put-item|ecr get-login-password|ecs update-service/);
  } finally {
    if (prior === undefined) delete process.env.CORE_SIGNING_SECRET;
    else process.env.CORE_SIGNING_SECRET = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rejects NUL in selected deployment secrets before any provider call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-nul-preflight-"));
  const configured = oneServiceConfig();
  const configPath = join(dir, "qm.config.jsonc");
  const envFile = join(dir, "deployment.env");
  writeFileSync(configPath, JSON.stringify(configured));
  writeFileSync(envFile, `DATABASE_URL=postgres://database.example/qm\0ignored\n`);
  const fake = statefulAws(dir, configured);
  try {
    const ctx: DeployContext = {
      config: configured,
      configPath,
      configIdentity: configIdentity(configPath),
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      envFile,
      target: "aws",
    };
    const provider = hostingProvider("aws");
    const options = provider.upOptions(ctx, { yes: true }, false);
    await assert.rejects(provider.preflightUp(ctx, options), /DATABASE_URL contains a NUL byte/);
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rejects NUL entered at a secret prompt before any provider call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-prompt-nul-"));
  const configured: QmConfig = { ...oneServiceConfig(), env: {} };
  const fake = statefulAws(dir, configured);
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
  try {
    await withFakeStdin(async (emit) => {
      const pending = awsSecretsPush(configured, dir, new Map());
      emit(Buffer.from([0, 13]));
      await assert.rejects(
        pending,
        (error: unknown) =>
          error instanceof Error && /contains a NUL byte/.test(error.message) && !error.message.includes("\0"),
      );
    });
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret push never treats ambient custom store names as deployment values", async (t) => {
  for (const storeName of ["GITHUB_TOKEN", "AWS_SESSION_TOKEN"] as const) {
    await t.test(storeName, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-custom-secret-ambient-"));
      const configured: QmConfig = {
        ...oneServiceConfig(),
        env: {},
        secretEnv: { core: { CUSTOM_RUNTIME_TOKEN: storeName } },
      };
      const fake = statefulAws(dir, configured);
      const prior = process.env[storeName];
      process.env[storeName] = `ambient-${storeName.toLowerCase()}-${TEST_SECRET_VALUE}`;
      try {
        await withFakeStdin(async (emit) => {
          const pending = awsSecretsPush(configured, dir, requiredOperatorSecretValues(oneServiceConfig()));
          emit(Buffer.from([0, 13]));
          await assert.rejects(pending, /contains a NUL byte/);
        });
        assert.equal(readFileSync(fake.log, "utf8"), "");
      } finally {
        if (prior === undefined) delete process.env[storeName];
        else process.env[storeName] = prior;
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS secret push accepts an explicit custom store value without ambient fallback", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-custom-secret-file-"));
  const configured: QmConfig = {
    ...oneServiceConfig(),
    env: {},
    secretEnv: { core: { CUSTOM_GITHUB_TOKEN: "GITHUB_TOKEN" } },
  };
  const fake = statefulAws(dir, configured);
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.services["acme-core"].desiredCount = 0;
  writeFileSync(fake.state, JSON.stringify(state));
  const explicit = `explicit-github-token-${TEST_SECRET_VALUE}`;
  const prior = process.env.GITHUB_TOKEN;
  process.env.GITHUB_TOKEN = `ambient-github-token-${TEST_SECRET_VALUE}`;
  try {
    await awsSecretsPush(configured, dir, requiredOperatorSecretValues(configured, { GITHUB_TOKEN: explicit }));
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(after.lastSecretValues.GITHUB_TOKEN, explicit);
  } finally {
    if (prior === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret push uses one ambient snapshot across prompted secret resolution", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-ambient-snapshot-"));
  const configured: QmConfig = {
    ...oneServiceConfig(),
    env: {},
    secretEnv: { core: { CUSTOM_RUNTIME_TOKEN: "AAA_CUSTOM_STORE" } },
  };
  const fake = statefulAws(dir, configured);
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.services["acme-core"].desiredCount = 0;
  writeFileSync(fake.state, JSON.stringify(state));
  const prior = process.env.OPENAI_API_KEY;
  delete process.env.OPENAI_API_KEY;
  const selected = requiredOperatorSecretValues(configured);
  selected.delete("AAA_CUSTOM_STORE");
  try {
    await withFakeStdin(async (emit) => {
      const pending = awsSecretsPush(configured, dir, selected);
      process.env.OPENAI_API_KEY = `late-openai-${TEST_SECRET_VALUE}`;
      emit(Buffer.from(`custom-${TEST_SECRET_VALUE}\r`));
      await pending;
    });
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(after.lastSecretValues.AAA_CUSTOM_STORE, `custom-${TEST_SECRET_VALUE}`);
    assert.equal(after.lastSecretValues.OPENAI_API_KEY, undefined);
  } finally {
    if (prior === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret push derives PUBLIC_API_URL from the current configured API coordinate", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-public-api-url-"));
  const configured: QmConfig = { ...oneServiceConfig(), apiUrl: "https://api.new.example" };
  const fake = statefulAws(dir, configured);
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.services["acme-core"].desiredCount = 0;
  writeFileSync(fake.state, JSON.stringify(state));
  const selected = requiredOperatorSecretValues(configured, {
    PUBLIC_API_URL: "https://api.stale.example",
  });
  try {
    await awsSecretsPush(configured, dir, selected);
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(after.lastSecretValues.PUBLIC_API_URL, "https://api.new.example");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret upload rejects individually valid duplicate auth secrets before any provider call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-duplicate-selected-secret-"));
  const configured: QmConfig = {
    ...oneServiceConfig(),
    services: ["core", "auth"],
    aws: {
      ...oneServiceConfig().aws!,
      services: {
        core: oneServiceConfig().aws!.services.core!,
        auth: { ecrRepository: "qm-auth", ecsService: "acme-auth", cpu: 512, memory: 1024 },
      },
    },
    secretEnv: {
      auth: {
        AUTH_CLIENT_SECRET: "AUTH_CLIENT_SECRET",
        AUTH_TOKEN_SECRET: "AUTH_TOKEN_SECRET",
      },
    },
  };
  const duplicate = "individually-valid-duplicate-auth-secret".repeat(2);
  const operator = computedSecrets(configured).filter((secret) => secret.managedBy === "operator" && secret.required);
  writeFileSync(
    join(dir, ".env"),
    operator
      .map(
        (secret) =>
          `${secret.name}=${["AUTH_CLIENT_SECRET", "AUTH_TOKEN_SECRET"].includes(secret.name) ? duplicate : selectedTestSecretValue(secret.name)}`,
      )
      .join("\n"),
  );
  const fake = statefulAws(dir, configured);
  try {
    await assert.rejects(
      awsSecretsPush(configured, dir, testSecretValues(dir)),
      /selected AWS secrets failed runtime validation: AUTH_CLIENT_SECRET, AUTH_TOKEN_SECRET/,
    );
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret upload validates the gated portal session value before any provider call", async (t) => {
  const configured: QmConfig = {
    ...config,
    env: {
      ...config.env,
      core: { ...config.env.core, DEPLOY_APPS_DOMAIN: "apps.agent.acme.example" },
    },
  };
  const cases: Array<{ name: string; value: string; expected: RegExp }> = [
    { name: "placeholder", value: "replace-me", expected: /PORTAL_SESSION_SECRET/ },
    { name: "short", value: "short", expected: /PORTAL_SESSION_SECRET/ },
    {
      name: "signing-key collision",
      value: TEST_SECRET_VALUE,
      expected: /CORE_SIGNING_SECRET, PORTAL_SESSION_SECRET/,
    },
  ];
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
  try {
    for (const selected of cases) {
      await t.test(selected.name, async () => {
        const dir = mkdtempSync(join(tmpdir(), "qm-aws-gated-session-invalid-"));
        const fake = statefulAws(dir, configured);
        try {
          await assert.rejects(
            awsSecretsPush(
              configured,
              dir,
              requiredOperatorSecretValues(configured, { PORTAL_SESSION_SECRET: selected.value }),
            ),
            selected.expected,
          );
          assert.equal(readFileSync(fake.log, "utf8"), "");
        } finally {
          fake.restore();
          rmSync(dir, { recursive: true, force: true });
        }
      });
    }
  } finally {
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
  }
});

test("AWS secret upload validates aliased portal trust before any external call", async (t) => {
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
  try {
    for (const kind of ["portal", "auth"] as const) {
      await t.test(kind, async () => {
        const dir = mkdtempSync(join(tmpdir(), `qm-aws-${kind}-alias-push-`));
        const dockerLog = join(dir, "docker.log");
        const dockerBin = join(dir, "docker");
        writeFileSync(dockerLog, "");
        writeFileSync(dockerBin, `#!/bin/sh\nprintf ran >> ${JSON.stringify(dockerLog)}\n`);
        chmodSync(dockerBin, 0o755);
        const priorPath = process.env.PATH;
        process.env.PATH = `${dir}:${priorPath}`;
        const selected = aliasedTrustConfig(kind);
        const fake = statefulAws(dir, selected.config);
        try {
          await assert.rejects(
            awsSecretsPush(
              selected.config,
              dir,
              requiredOperatorSecretValues(selected.config, { [selected.storeName]: "not-an-email" }),
            ),
            kind === "portal"
              ? /OIDC_ALLOWED_EMAILS must contain valid, non-placeholder email addresses/
              : /AUTH_ALLOWED_EMAILS must have a non-empty, non-placeholder runtime value/,
          );
          assert.equal(readFileSync(fake.log, "utf8"), "");
          assert.equal(readFileSync(dockerLog, "utf8"), "");
        } finally {
          process.env.PATH = priorPath;
          fake.restore();
          rmSync(dir, { recursive: true, force: true });
        }
      });
    }
  } finally {
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
  }
});

test("AWS rejects NUL in optional remote secrets before deployment mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-remote-nul-preflight-"));
  const configured = oneServiceConfig();
  const fake = statefulAws(dir, configured);
  const prior = process.env.AWS_FAKE_NUL_SECRET_NAME;
  process.env.AWS_FAKE_NUL_SECRET_NAME = "DATABASE_CA_CERT";
  try {
    await assert.rejects(
      awsUp(configured, dir, { yes: true }),
      (error: unknown) =>
        error instanceof Error &&
        /DATABASE_CA_CERT contains a NUL byte/.test(error.message) &&
        !error.message.includes("sentinel"),
    );
    assert.doesNotMatch(
      readFileSync(fake.log, "utf8"),
      /dynamodb put-item|s3api put-object|rds create-db-snapshot|ecr get-login-password|ecs update-service/,
    );
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_NUL_SECRET_NAME;
    else process.env.AWS_FAKE_NUL_SECRET_NAME = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rejects deployment environment aliases of its mutable config before any provider call", async (t) => {
  for (const kind of ["lexical", "hardlink"] as const) {
    await t.test(kind, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-env-config-alias-"));
      const configured = oneServiceConfig();
      const configPath = join(dir, "qm.config.jsonc");
      const envFile = kind === "lexical" ? configPath : join(dir, "deployment.env");
      writeFileSync(configPath, JSON.stringify(configured));
      if (kind === "hardlink") linkSync(configPath, envFile);
      const fake = statefulAws(dir, configured);
      try {
        const ctx: DeployContext = {
          config: configured,
          configPath,
          configIdentity: configIdentity(configPath),
          configDir: dir,
          sandboxDir: join(dir, "sandbox"),
          envFile,
          target: "aws",
        };
        const provider = hostingProvider("aws");
        const options = provider.upOptions(ctx, { yes: true }, false);
        await assert.rejects(provider.preflightUp(ctx, options), /environment file must be physically disjoint/);
        assert.equal(readFileSync(fake.log, "utf8"), "");
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS provider env reads reject a path swapped to the loaded config identity", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-env-config-swap-"));
  const configured = oneServiceConfig();
  const configPath = join(dir, "qm.config.jsonc");
  const envFile = join(dir, "deployment.env");
  writeFileSync(configPath, JSON.stringify(configured));
  writeFileSync(envFile, `CORE_SIGNING_SECRET=${TEST_SECRET_VALUE}\n`);
  const identity = configIdentity(configPath);
  rmSync(envFile);
  symlinkSync(configPath, envFile);
  const fake = statefulAws(dir, configured);
  try {
    await t.test("source-build admission", async () => {
      await assert.rejects(
        awsPreflightUpWithIdentity(configured, dir, { yes: true, envFile, configIdentity: identity }),
        /environment file must be separate from the deployment config/,
      );
      assert.equal(readFileSync(fake.log, "utf8"), "");
    });
    await t.test("deployment-layer transport", async () => {
      const priorFetch = globalThis.fetch;
      let fetches = 0;
      globalThis.fetch = (async () => {
        fetches += 1;
        return new Response("");
      }) as typeof fetch;
      try {
        await assert.rejects(
          awsDeploymentLayerTransport({
            config: configured,
            configIdentity: identity,
            configDir: dir,
            envFile,
            method: "GET",
            body: "",
          }),
          /environment file must be separate from the deployment config/,
        );
        assert.equal(fetches, 0);
        assert.equal(readFileSync(fake.log, "utf8"), "");
      } finally {
        globalThis.fetch = priorFetch;
      }
    });
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS doctor verifies durable deployment storage and object-store access", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-doctor-storage-"));
  const ready = fakeAws(
    dir,
    `
if (a.includes("dynamodb describe-table")) console.log(JSON.stringify({ Table: { TableStatus: "ACTIVE" } }));
else console.log("");`,
  );
  try {
    assert.doesNotThrow(() => assertAwsDeploymentStorage(config));
    const calls = readFileSync(ready.log, "utf8");
    assert.match(calls, /dynamodb describe-table --table-name acme-qm-deploy-locks/);
    assert.ok(
      calls.includes(
        `s3api list-objects-v2 --bucket ${awsObjectStoreBucket(config)} --prefix deployment/ --max-keys 1`,
      ),
    );
  } finally {
    ready.restore();
  }
  const inactive = fakeAws(
    dir,
    `
if (a.includes("dynamodb describe-table")) console.log(JSON.stringify({ Table: { TableStatus: "CREATING" } }));
else console.log("");`,
  );
  try {
    assert.throws(() => assertAwsDeploymentStorage(config), /CREATING/);
    assert.doesNotMatch(readFileSync(inactive.log, "utf8"), /list-objects-v2/);
  } finally {
    inactive.restore();
  }
  const denied = fakeAws(
    dir,
    `
if (a.includes("dynamodb describe-table")) console.log(JSON.stringify({ Table: { TableStatus: "ACTIVE" } }));
else if (a.includes("s3api list-objects-v2")) { console.error("AccessDenied"); process.exit(1); }
else console.log("");`,
  );
  try {
    assert.throws(() => assertAwsDeploymentStorage(config), /AccessDenied/);
  } finally {
    denied.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS task definitions are digest-pinned and route only computed secrets", () => {
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  const task = renderTaskDefinition(config, "core", image);
  assert.equal(task.runtimePlatform.cpuArchitecture, "ARM64");
  assert.equal(task.executionRoleArn, "arn:aws:iam::123456789012:role/acme-qm-task-execution");
  assert.equal(task.taskRoleArn, "arn:aws:iam::123456789012:role/acme-qm-core-task");
  const container = task.containerDefinitions[0]!;
  assert.equal(container.image, image);
  const names = (container.secrets as Array<{ name: string }>).map((secret) => secret.name);
  assert.deepEqual(names, [
    "CAPABILITY_SECRET",
    "CONNECTOR_SECRET_KEY",
    "CORE_SIGNING_SECRET",
    "DATABASE_URL",
    "PORTAL_IDENTITY_SECRET",
    "PUBLIC_API_URL",
    "SKILL_SIGNING_SECRET",
    "SPRITES_TOKEN",
  ]);
  assert.throws(() => renderTaskDefinition(config, "core", "repo:latest"), /must be pinned by digest/);
});

test("AWS task architecture allows per-workload overrides", () => {
  const amd64Core: QmConfig = {
    ...config,
    aws: {
      ...config.aws!,
      services: {
        ...config.aws!.services,
        core: { ...config.aws!.services.core!, architecture: "amd64" },
      },
    },
  };
  const coreImage = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  assert.equal(renderTaskDefinition(amd64Core, "core", coreImage).runtimePlatform.cpuArchitecture, "X86_64");
});

test("AWS task parity ignores only ECS response defaults and catches live-only fields", () => {
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  const task = renderTaskDefinition(config, "core", image);
  const live = structuredClone(task) as unknown as Record<string, unknown>;
  live.taskDefinitionArn = "arn:task";
  live.revision = 4;
  live.compatibilities = ["EC2", "FARGATE"];
  live.volumes = [];
  const container = (live.containerDefinitions as Array<Record<string, unknown>>)[0]!;
  container.cpu = 0;
  container.mountPoints = [];
  container.environment = [...(container.environment as unknown[])].reverse();
  assert.deepEqual(taskDefinitionDiff(task, live), []);
  container.entryPoint = ["unexpected"];
  assert.deepEqual(taskDefinitionDiff(task, live), ["taskDefinition.containerDefinitions.core.entryPoint"]);
});

test("AWS task parity catches a correctly named secret routed to the wrong ARN", () => {
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  const expected = renderTaskDefinition(config, "core", image, { CORE_SIGNING_SECRET: "arn:expected" });
  const live = structuredClone(expected) as unknown as Record<string, unknown>;
  const container = (live.containerDefinitions as Array<{ secrets: Array<{ name: string; valueFrom: string }> }>)[0]!;
  container.secrets.find((secret) => secret.name === "CORE_SIGNING_SECRET")!.valueFrom = "arn:attacker";
  assert.deepEqual(taskDefinitionDiff(expected, live), [
    "taskDefinition.containerDefinitions.core.secrets.CORE_SIGNING_SECRET",
  ]);
  assert.deepEqual(taskDefinitionChanges(expected, live), [
    {
      path: "taskDefinition.containerDefinitions.core.secrets.CORE_SIGNING_SECRET",
      live: "arn:attacker",
      desired: "arn:expected",
    },
  ]);
});

test("AWS image transfer preserves the source manifest instead of pulling the host architecture", () => {
  assert.deepEqual(imageTransferArgs("ghcr.io/acme/core:1", "123.dkr.ecr.us-west-2.amazonaws.com/core:sha"), [
    "imagetools",
    "create",
    "--prefer-index=false",
    "--tag",
    "123.dkr.ecr.us-west-2.amazonaws.com/core:sha",
    "ghcr.io/acme/core:1",
  ]);
});

test("AWS source builds honor a standalone Buildx override without self-attested git provenance", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-web-ui-build-"));
  const sourceDir = join(dir, "source");
  const dockerLog = join(dir, "docker.log");
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerLog, "");
  writeFileSync(
    dockerBin,
    `#!/usr/bin/env node\nrequire("node:fs").appendFileSync(${JSON.stringify(dockerLog)}, process.argv.slice(2).join(" ") + "\\n");\n`,
  );
  chmodSync(dockerBin, 0o755);
  for (const service of ["core", "web-ui", "portal"]) {
    mkdirSync(join(sourceDir, "deploy", service), { recursive: true });
    writeFileSync(join(sourceDir, "deploy", service, "Dockerfile"), `FROM scratch\nLABEL service=${service}\n`);
  }
  const git = (...args: string[]): string => {
    const result = spawnSync(
      "git",
      ["-C", sourceDir, "-c", "user.email=test@acme.example", "-c", "user.name=test", ...args],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  git("init");
  git("add", "-A");
  git("commit", "-m", "initial");
  git("rev-parse", "HEAD");
  writeFileSync(join(sourceDir, "uncommitted.txt"), "dirty\n");
  const priorPath = process.env.PATH;
  const priorBuildx = process.env.DOCKER_BUILDX_BIN;
  process.env.PATH = `${dir}:${priorPath}`;
  process.env.DOCKER_BUILDX_BIN = dockerBin;
  const webUiConfig: QmConfig = {
    ...config,
    services: ["core", "web-ui", "portal"],
    aws: {
      ...config.aws!,
      services: {
        core: config.aws!.services.core!,
        "web-ui": { ...config.aws!.services["web-ui"]!, architecture: "amd64", buildArgs: { WEB_UI_BASE: "/custom/" } },
        portal: config.aws!.services.portal!,
      },
    },
  };
  const fake = statefulAws(dir, webUiConfig);
  try {
    await awsUp(webUiConfig, dir, { yes: true, buildFrom: true, buildFromPath: sourceDir });
    const build = readFileSync(dockerLog, "utf8")
      .split("\n")
      .find((line) => line.startsWith("build ") && line.includes("qm-web-ui"));
    assert.match(build ?? "", /--platform linux\/amd64/);
    assert.match(build ?? "", /--provenance=false/);
    assert.match(build ?? "", /--build-arg WEB_UI_BASE=\/custom\//);
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    const manifestId = state.dynamo["deployment/current"].manifestId.S;
    const manifest = JSON.parse(state.dynamo[`deployment/manifest/${manifestId}`].manifest.S);
    for (const service of ["core", "web-ui", "portal"]) {
      assert.deepEqual(manifest.imageProvenance[service], {
        kind: "source-build",
        source: "checkout",
      });
    }
    await assert.doesNotReject(() => awsCheckLive(webUiConfig, { report: false, configDir: dir }));
    const changedPrebuiltConfig: QmConfig = {
      ...webUiConfig,
      imageOverrides: { core: `ghcr.io/acme/core@sha256:${"c".repeat(64)}` },
      aws: {
        ...webUiConfig.aws!,
        services: {
          ...webUiConfig.aws!.services,
          core: { ...webUiConfig.aws!.services.core!, architecture: "arm64" },
        },
      },
    };
    await assert.rejects(
      () => awsCheckLive(changedPrebuiltConfig, { report: false, configDir: dir }),
      /core: image build provenance drift \(deployed from source, current workload uses a configured image\)/,
    );
    assert.doesNotMatch(readFileSync(dockerLog, "utf8"), /imagetools inspect/);
  } finally {
    process.env.PATH = priorPath;
    if (priorBuildx === undefined) delete process.env.DOCKER_BUILDX_BIN;
    else process.env.DOCKER_BUILDX_BIN = priorBuildx;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS Docker children use one frozen neutral environment for Buildx override and fallback", async (t) => {
  for (const override of [true, false]) {
    await t.test(override ? "override" : "fallback", async () => {
      const dir = mkdtempSync(join(tmpdir(), `qm-aws-build-env-${override ? "override" : "fallback"}-`));
      const dockerLog = join(dir, "docker-env.jsonl");
      const buildxLog = join(dir, "buildx-env.jsonl");
      const lateLog = join(dir, "late-buildx.jsonl");
      const dockerBin = join(dir, "docker");
      const buildxBin = join(dir, "buildx-override");
      const lateBuildxBin = join(dir, "late-buildx");
      const envLogger = (path: string): string =>
        `#!/usr/bin/env node\nrequire("node:fs").appendFileSync(${JSON.stringify(path)}, JSON.stringify({ args: process.argv.slice(2), env: process.env }) + "\\n");\n`;
      writeFileSync(dockerLog, "");
      writeFileSync(buildxLog, "");
      writeFileSync(lateLog, "");
      writeFileSync(dockerBin, envLogger(dockerLog));
      writeFileSync(buildxBin, envLogger(buildxLog));
      writeFileSync(lateBuildxBin, envLogger(lateLog));
      chmodSync(dockerBin, 0o755);
      chmodSync(buildxBin, 0o755);
      chmodSync(lateBuildxBin, 0o755);
      const single = oneServiceConfig();
      const configured: QmConfig = {
        ...single,
        secretEnv: {
          ...single.secretEnv,
          core: {
            ...single.secretEnv?.core,
            FUTURE_DESTINATION: "FUTURE_SECRET_STORE",
          },
        },
      };
      const fileSecret = "file-only-future-secret-value";
      writeFileSync(join(dir, ".env"), `CORE_SIGNING_SECRET=${TEST_SECRET_VALUE}\nFUTURE_SECRET_STORE=${fileSecret}\n`);
      const fake = statefulAws(dir, configured);
      const names = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "CORE_SIGNING_SECRET",
        "DOCKER_BUILDX_BIN",
        "DOCKER_CONFIG",
        "FUTURE_DESTINATION",
        "FUTURE_SECRET_STORE",
        "GIT_CONFIG_COUNT",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "QM_DEPLOY_ENV_FILE_ONLY",
        "QM_UPDATE_TOKEN",
      ];
      const prior = new Map(names.map((name) => [name, process.env[name]]));
      const priorPath = process.env.PATH;
      const safeDockerConfig = join(dir, "docker-control");
      const credential = "ambient-aws-credential-value";
      const ambientCore = "ambient-core-secret-value";
      const updateToken = "automatic-update-secret-value";
      process.env.PATH = `${dir}:${priorPath}`;
      process.env.AWS_ACCESS_KEY_ID = credential;
      process.env.AWS_SECRET_ACCESS_KEY = `${credential}-secret`;
      process.env.AWS_SESSION_TOKEN = `${credential}-session`;
      process.env.CORE_SIGNING_SECRET = ambientCore;
      process.env.DOCKER_CONFIG = safeDockerConfig;
      process.env.FUTURE_DESTINATION = "ambient-future-alias-value";
      process.env.FUTURE_SECRET_STORE = "ambient-future-store-value";
      process.env.GIT_CONFIG_COUNT = "0";
      process.env.LD_PRELOAD = "";
      process.env.NODE_OPTIONS = "--no-warnings";
      process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
      process.env.QM_UPDATE_TOKEN = updateToken;
      if (override) process.env.DOCKER_BUILDX_BIN = buildxBin;
      else delete process.env.DOCKER_BUILDX_BIN;
      const providerFetch = globalThis.fetch;
      globalThis.fetch = async (...args) => {
        process.env.DOCKER_BUILDX_BIN = lateBuildxBin;
        process.env.DOCKER_CONFIG = join(dir, "late-docker-control");
        return providerFetch(...args);
      };
      try {
        await awsUp(configured, dir, { yes: true });
        const parse = (path: string): Array<{ args: string[]; env: Record<string, string> }> =>
          readFileSync(path, "utf8")
            .trim()
            .split("\n")
            .filter(Boolean)
            .map((line) => JSON.parse(line));
        const dockerCalls = parse(dockerLog);
        const buildxCalls = parse(buildxLog);
        const buildCalls = override ? buildxCalls : dockerCalls.filter((call) => call.args[0] === "buildx");
        assert.ok(dockerCalls.some((call) => call.args[0] === "login"));
        assert.ok(buildCalls.some((call) => call.args.includes("imagetools") && call.args.includes("create")));
        assert.equal(readFileSync(lateLog, "utf8"), "");
        for (const call of [...dockerCalls, ...buildxCalls]) {
          assert.equal(call.env.DOCKER_CONFIG, safeDockerConfig);
          assert.equal(call.env.BUILDX_GIT_INFO, "false");
          assert.equal(call.env.BUILDX_GIT_LABELS, "false");
          for (const name of [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "CORE_SIGNING_SECRET",
            "FUTURE_DESTINATION",
            "FUTURE_SECRET_STORE",
            "GIT_CONFIG_COUNT",
            "LD_PRELOAD",
            "NODE_OPTIONS",
            "QM_DEPLOY_ENV_FILE_ONLY",
            "QM_UPDATE_TOKEN",
          ]) {
            assert.equal(call.env[name], undefined, `${name} leaked into ${call.args.join(" ")}`);
          }
          for (const value of [
            credential,
            `${credential}-secret`,
            `${credential}-session`,
            ambientCore,
            fileSecret,
            updateToken,
          ]) {
            assert.equal(
              Object.values(call.env).includes(value),
              false,
              `a sensitive value leaked into ${call.args.join(" ")}`,
            );
          }
        }
      } finally {
        process.env.PATH = priorPath;
        for (const [name, value] of prior) {
          if (value === undefined) delete process.env[name];
          else process.env[name] = value;
        }
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS rejects source-build control secret collisions before Docker or deployment mutation", async (t) => {
  for (const canonical of [false, true]) {
    await t.test(canonical ? "canonical source name" : "selected secret value", async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-build-env-collision-"));
      const dockerLog = join(dir, "docker.log");
      const dockerBin = join(dir, "docker");
      writeFileSync(dockerLog, "");
      writeFileSync(
        dockerBin,
        `#!/usr/bin/env node\nrequire("node:fs").appendFileSync(${JSON.stringify(dockerLog)}, "ran\\n");\n`,
      );
      chmodSync(dockerBin, 0o755);
      const single = oneServiceConfig();
      const configured: QmConfig = canonical
        ? {
            ...single,
            secretEnv: { ...single.secretEnv, core: { ...single.secretEnv?.core, DOCKER_CONFIG: "DOCKER_CONFIG" } },
          }
        : single;
      writeFileSync(
        join(dir, ".env"),
        `CORE_SIGNING_SECRET=${TEST_SECRET_VALUE}${canonical ? `\nDOCKER_CONFIG=${"canonical-docker-secret".repeat(2)}` : ""}\n`,
      );
      const fake = statefulAws(dir, configured);
      const priorPath = process.env.PATH;
      const priorDockerConfig = process.env.DOCKER_CONFIG;
      process.env.PATH = `${dir}:${priorPath}`;
      process.env.DOCKER_CONFIG = canonical ? join(dir, "safe-docker-control") : TEST_SECRET_VALUE;
      try {
        await assert.rejects(
          () => awsUp(configured, dir, { yes: true }),
          /source-build provider control DOCKER_CONFIG conflicts with a deployment secret/,
        );
        const calls = readFileSync(fake.log, "utf8");
        assert.doesNotMatch(calls, /rds create-db-snapshot|ecr get-login-password|s3api put-object|ecs update-service/);
        assert.equal(readFileSync(dockerLog, "utf8"), "");
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerConfig === undefined) delete process.env.DOCKER_CONFIG;
        else process.env.DOCKER_CONFIG = priorDockerConfig;
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS source builds never stamp mutable checkout identity", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-dockerfile-override-"));
  const sourceDir = join(dir, "source");
  const dockerLog = join(dir, "docker.log");
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerLog, "");
  writeFileSync(
    dockerBin,
    `#!/usr/bin/env node\nrequire("node:fs").appendFileSync(${JSON.stringify(dockerLog)}, process.argv.slice(2).join(" ") + "\\n");\n`,
  );
  chmodSync(dockerBin, 0o755);
  for (const service of ["core", "web-ui", "admin", "portal"]) {
    mkdirSync(join(sourceDir, "deploy", service), { recursive: true });
    writeFileSync(join(sourceDir, "deploy", service, "Dockerfile"), `FROM scratch\nLABEL service=${service}\n`);
  }
  mkdirSync(join(sourceDir, "cli"), { recursive: true });
  writeFileSync(join(sourceDir, "cli", "package.json"), JSON.stringify({ version: "1.2.3-test" }));
  mkdirSync(join(sourceDir, "layered"), { recursive: true });
  writeFileSync(join(sourceDir, "layered", "core.Dockerfile"), "FROM scratch\nLABEL layered=core\n");
  const git = (...args: string[]): string => {
    const result = spawnSync(
      "git",
      ["-C", sourceDir, "-c", "user.email=test@acme.example", "-c", "user.name=test", ...args],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  git("init");
  git("add", "-A");
  git("commit", "-m", "initial");
  git("rev-parse", "HEAD");
  const layeredConfig: QmConfig = {
    ...config,
    services: ["core", "web-ui", "admin", "portal"],
    aws: {
      ...config.aws!,
      services: {
        core: { ...config.aws!.services.core!, dockerfile: "layered/core.Dockerfile" },
        "web-ui": config.aws!.services["web-ui"]!,
        admin: config.aws!.services.admin!,
        portal: config.aws!.services.portal!,
      },
    },
  };
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  const fake = statefulAws(dir, layeredConfig);
  try {
    await awsUp(layeredConfig, dir, { yes: true, buildFrom: true, buildFromPath: sourceDir });
    const builds = readFileSync(dockerLog, "utf8")
      .split("\n")
      .filter((line) => line.includes("buildx build"));
    const coreBuild = builds.find((line) => line.includes("qm-core"));
    assert.ok(
      coreBuild?.includes(`-f ${join(sourceDir, "layered", "core.Dockerfile")}`),
      `core build uses the override: ${coreBuild}`,
    );
    assert.doesNotMatch(coreBuild ?? "", /--build-arg GIT_SHA=/);
    assert.doesNotMatch(builds.join("\n"), /QM_VERSION/);
    const webUiBuild = builds.find((line) => line.includes("qm-web-ui"));
    assert.ok(
      webUiBuild?.includes(`-f ${join(sourceDir, "deploy", "web-ui", "Dockerfile")}`),
      `web-ui build keeps the default: ${webUiBuild}`,
    );
    const dirtySource = join(dir, "dirty-source");
    for (const service of ["core", "web-ui", "admin", "portal"]) {
      mkdirSync(join(dirtySource, "deploy", service), { recursive: true });
      writeFileSync(join(dirtySource, "deploy", service, "Dockerfile"), `FROM scratch\nLABEL service=${service}\n`);
    }
    mkdirSync(join(dirtySource, "cli"), { recursive: true });
    writeFileSync(join(dirtySource, "cli", "package.json"), JSON.stringify({ version: "1.2.3-dirty" }));
    mkdirSync(join(dirtySource, "layered"), { recursive: true });
    writeFileSync(join(dirtySource, "layered", "core.Dockerfile"), "FROM scratch\nLABEL layered=core\n");
    const dirtyGit = (...args: string[]): string => {
      const result = spawnSync(
        "git",
        ["-C", dirtySource, "-c", "user.email=test@acme.example", "-c", "user.name=test", ...args],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0, result.stderr);
      return result.stdout.trim();
    };
    dirtyGit("init");
    dirtyGit("add", "-A");
    dirtyGit("commit", "-m", "initial");
    dirtyGit("rev-parse", "HEAD");
    writeFileSync(join(dirtySource, "deploy", "core", "Dockerfile"), "FROM scratch\nLABEL service=core-modified\n");
    await awsUp(layeredConfig, dir, { yes: true, buildFrom: true, buildFromPath: dirtySource });
    const dirtyCoreBuild = readFileSync(dockerLog, "utf8")
      .split("\n")
      .find((line) => line.includes("buildx build") && line.includes("qm-core") && line.includes(dirtySource));
    assert.doesNotMatch(dirtyCoreBuild ?? "", /--build-arg GIT_SHA=/);
    assert.doesNotMatch(readFileSync(dockerLog, "utf8"), /QM_VERSION/);
    const missingConfig: QmConfig = {
      ...layeredConfig,
      aws: {
        ...layeredConfig.aws!,
        services: {
          ...layeredConfig.aws!.services,
          core: { ...layeredConfig.aws!.services.core!, dockerfile: "layered/absent.Dockerfile" },
        },
      },
    };
    await assert.rejects(
      () => awsUp(missingConfig, dir, { yes: true, buildFrom: true, buildFromPath: sourceDir }),
      /aws\.services\.core\.dockerfile is missing from the build checkout/,
    );
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS source-plugin provenance records the build source and detects source-mode drift", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-plugin-provenance-"));
  const pluginDir = join(dir, "plugins", "linear");
  mkdirSync(pluginDir, { recursive: true });
  writeFileSync(join(pluginDir, "Dockerfile"), "FROM scratch\nCOPY handler.js /handler.js\n");
  writeFileSync(join(pluginDir, "handler.js"), "export const version = 1;\n");
  const single = oneServiceConfig();
  const sourceConfig: QmConfig = {
    ...single,
    plugins: [{ name: "linear" }],
    aws: {
      ...single.aws!,
      services: {
        ...single.aws!.services,
        linear: { ecrRepository: "qm-linear", ecsService: "acme-linear", cpu: 256, memory: 512, architecture: "amd64" },
      },
    },
  };
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/bin/sh\necho 'Digest: sha256:${"a".repeat(64)}'\n`);
  chmodSync(dockerBin, 0o755);
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  const fake = statefulAws(dir, sourceConfig);
  try {
    await awsUp(sourceConfig, dir, { yes: true });
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    const manifestId = state.dynamo["deployment/current"].manifestId.S;
    const manifest = JSON.parse(state.dynamo[`deployment/manifest/${manifestId}`].manifest.S);
    assert.deepEqual(manifest.imageProvenance.linear, { kind: "source-build", source: "plugin" });
    await assert.doesNotReject(() => awsCheckLive(sourceConfig, { report: false, configDir: dir }));

    const persisted = JSON.parse(readFileSync(fake.state, "utf8"));
    const persistedManifest = JSON.parse(persisted.dynamo[`deployment/manifest/${manifestId}`].manifest.S);
    persistedManifest.imageProvenance.linear = { kind: "configured", source: "ghcr.io/acme/linear:1" };
    persisted.dynamo[`deployment/manifest/${manifestId}`].manifest.S = JSON.stringify(persistedManifest);
    writeFileSync(fake.state, JSON.stringify(persisted));
    await assert.rejects(
      () => awsCheckLive(sourceConfig, { report: false, configDir: dir }),
      /linear: image build provenance drift \(deployed from a configured image, current workload builds from source\)/,
    );
    persistedManifest.imageProvenance.linear = { kind: "source-build", source: "plugin" };
    persisted.dynamo[`deployment/manifest/${manifestId}`].manifest.S = JSON.stringify(persistedManifest);
    writeFileSync(fake.state, JSON.stringify(persisted));

    rmSync(pluginDir, { recursive: true, force: true });
    const configuredImage: QmConfig = {
      ...sourceConfig,
      plugins: [{ name: "linear", image: "ghcr.io/acme/linear:1" }],
    };
    await assert.rejects(
      () => awsCheckLive(configuredImage, { report: false, configDir: dir }),
      /linear: image build provenance drift \(deployed from source, current workload uses a configured image\)/,
    );
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS live-image provenance accepts only the configured ECR repository and a full digest", () => {
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  assert.equal(isPinnedWorkloadImage(config, "core", image), true);
  assert.equal(isPinnedWorkloadImage(config, "core", `attacker.example/core@sha256:${"a".repeat(64)}`), false);
  assert.equal(
    isPinnedWorkloadImage(config, "core", "123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core:latest"),
    false,
  );
});

test("AWS renders third-party plugins as private ECS workloads with scoped secrets", () => {
  const pluginConfig: QmConfig = {
    ...config,
    plugins: [
      {
        name: "linear",
        image: "ghcr.io/acme/linear:1",
        env: { LINEAR_REGION: "us" },
        secrets: [{ name: "LINEAR_TOKEN" }],
      },
    ],
    aws: {
      ...config.aws!,
      services: {
        ...config.aws!.services,
        linear: { ecrRepository: "qm-linear", ecsService: "acme-linear", cpu: 256, memory: 512, architecture: "amd64" },
      },
    },
  };
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-linear@sha256:${"c".repeat(64)}`;
  const task = renderTaskDefinition(pluginConfig, "linear", image, {
    CORE_SIGNING_SECRET: "arn:core-signing",
    LINEAR_TOKEN: "arn:linear-token",
  });
  const container = task.containerDefinitions[0]!;
  assert.equal(container.name, "linear");
  assert.deepEqual(
    Object.fromEntries(
      (container.environment as Array<{ name: string; value: string }>).map(({ name, value }) => [name, value]),
    ),
    {
      CORE_API_URL: "http://core.acme.internal:8080",
      CORE_ORG_ID: "acme",
      LINEAR_REGION: "us",
      NODE_ENV: "production",
      PORT: "8080",
    },
  );
  assert.deepEqual(container.secrets, [
    { name: "CORE_SIGNING_SECRET", valueFrom: "arn:core-signing" },
    { name: "LINEAR_TOKEN", valueFrom: "arn:linear-token" },
  ]);
});

test("AWS historical-task validation preserves signing for discovered source plugins", async (t) => {
  const configured = (): QmConfig => {
    const base = oneServiceConfig();
    return {
      ...base,
      aws: {
        ...base.aws!,
        services: {
          ...base.aws!.services,
          srcplug: {
            ecrRepository: "qm-srcplug",
            ecsService: "acme-srcplug",
            cpu: 256,
            memory: 512,
          },
        },
      },
    };
  };
  await t.test("rollback", async () => {
    const dir = mkdtempSync(join(tmpdir(), "qm-aws-source-plugin-rollback-"));
    mkdirSync(join(dir, "plugins", "srcplug"), { recursive: true });
    writeFileSync(join(dir, "plugins", "srcplug", "Dockerfile"), "FROM scratch\n");
    const sourceConfig = configured();
    const tasks = (revision: number): Record<string, string> => ({
      core: `arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:${revision}`,
      srcplug: `arn:aws:ecs:us-west-2:123456789012:task-definition/acme-srcplug:${revision}`,
    });
    const fake = statefulAws(
      dir,
      sourceConfig,
      manifestItems(
        [
          { id: "old", tasks: tasks(7) },
          { id: "current", previous: "old", tasks: tasks(9) },
        ],
        "current",
      ),
    );
    try {
      const state = JSON.parse(readFileSync(fake.state, "utf8"));
      const sourceTask = tasks(7).srcplug;
      assert.ok(sourceTask);
      const environment = Object.fromEntries(
        state.definitions[sourceTask].containerDefinitions[0].environment.map(
          ({ name, value }: { name: string; value: string }) => [name, value],
        ),
      );
      assert.equal(environment.NODE_ENV, "production");
      await assert.doesNotReject(
        awsRollback(sourceConfig, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY }),
      );
      assert.match(
        readFileSync(fake.log, "utf8"),
        /ecs update-service .*--service acme-srcplug .*--task-definition .*acme-srcplug:7/,
      );
    } finally {
      fake.restore();
      rmSync(dir, { recursive: true, force: true });
    }
  });
  await t.test("secret rotation", async () => {
    const dir = mkdtempSync(join(tmpdir(), "qm-aws-source-plugin-secrets-"));
    mkdirSync(join(dir, "plugins", "srcplug"), { recursive: true });
    writeFileSync(join(dir, "plugins", "srcplug", "Dockerfile"), "FROM scratch\n");
    const sourceConfig = configured();
    const fake = statefulAws(dir, sourceConfig);
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    const tasks = {
      core: state.services["acme-core"].taskDefinition,
      srcplug: state.services["acme-srcplug"].taskDefinition,
    };
    state.dynamo = manifestItems([{ id: "current", imageLabel: "release", tasks }], "current");
    writeFileSync(fake.state, JSON.stringify(state));
    const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
    process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
    try {
      await assert.doesNotReject(awsSecretsPush(sourceConfig, dir, requiredOperatorSecretValues(sourceConfig)));
      assert.match(
        readFileSync(fake.log, "utf8"),
        /ecs update-service .*--service acme-srcplug --force-new-deployment/,
      );
    } finally {
      if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
      else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
      fake.restore();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

test("AWS fixes third-party plugin PORT to its ECS port mapping", () => {
  const pluginConfig: QmConfig = {
    ...config,
    plugins: [
      {
        name: "linear",
        image: "ghcr.io/acme/linear:1",
        env: {
          PORT: "9000",
          AWS_ENDPOINT_URL: "https://attacker.example",
          AWS_ENDPOINT_URL_S3: "https://attacker.example",
        },
      },
    ],
    aws: {
      ...config.aws!,
      services: {
        ...config.aws!.services,
        linear: { ecrRepository: "qm-linear", ecsService: "acme-linear", cpu: 256, memory: 512, architecture: "amd64" },
      },
    },
  };
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-linear@sha256:${"c".repeat(64)}`;
  const task = renderTaskDefinition(pluginConfig, "linear", image, { CORE_SIGNING_SECRET: "arn:core-signing" });
  const environment = Object.fromEntries(
    (task.containerDefinitions[0]!.environment as Array<{ name: string; value: string }>).map(({ name, value }) => [
      name,
      value,
    ]),
  );
  assert.equal(environment.PORT, "8080");
  assert.equal(environment.NODE_ENV, "production");
  assert.equal(environment.AWS_ENDPOINT_URL, undefined);
  assert.equal(environment.AWS_ENDPOINT_URL_S3, undefined);
});

test("AWS routes optional plugin secrets only when the secret exists", () => {
  const pluginConfig: QmConfig = {
    ...config,
    plugins: [{ name: "linear", image: "ghcr.io/acme/linear:1", secrets: [{ name: "LINEAR_TOKEN", required: false }] }],
    aws: {
      ...config.aws!,
      services: {
        ...config.aws!.services,
        linear: { ecrRepository: "linear", ecsService: "linear", cpu: 256, memory: 512, architecture: "amd64" },
      },
    },
  };
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/linear@sha256:${"d".repeat(64)}`;
  const absent = renderTaskDefinition(pluginConfig, "linear", image, { CORE_SIGNING_SECRET: "arn:core" });
  assert.deepEqual(
    (absent.containerDefinitions[0]!.secrets as Array<{ name: string }>).map((secret) => secret.name),
    ["CORE_SIGNING_SECRET"],
  );
  const present = renderTaskDefinition(pluginConfig, "linear", image, {
    CORE_SIGNING_SECRET: "arn:core",
    LINEAR_TOKEN: "arn:linear",
  });
  assert.deepEqual(
    (present.containerDefinitions[0]!.secrets as Array<{ name: string }>).map((secret) => secret.name),
    ["CORE_SIGNING_SECRET", "LINEAR_TOKEN"],
  );
});

test("AWS task rendering rejects guessed architecture for external images", () => {
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/linear@sha256:${"d".repeat(64)}`;
  const pluginConfig: QmConfig = {
    ...config,
    plugins: [{ name: "linear", image: "ghcr.io/acme/linear:1" }],
    aws: {
      ...config.aws!,
      services: {
        ...config.aws!.services,
        linear: { ecrRepository: "linear", ecsService: "linear", cpu: 256, memory: 512 },
      },
    },
  };
  assert.throws(() => renderTaskDefinition(pluginConfig, "linear", image), /linear\.architecture is required/);

  const overriddenCore: QmConfig = { ...config, imageOverrides: { core: "ghcr.io/acme/core:1" } };
  const coreImage = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  assert.throws(() => renderTaskDefinition(overriddenCore, "core", coreImage), /core\.architecture is required/);

  const sourcePlugin: QmConfig = { ...pluginConfig, plugins: [{ name: "linear" }] };
  assert.equal(renderTaskDefinition(sourcePlugin, "linear", image).runtimePlatform.cpuArchitecture, "ARM64");
});

test("AWS retains built-in health enforcement when an image is overridden", () => {
  const overridden: QmConfig = {
    ...config,
    imageOverrides: { core: "ghcr.io/acme/core:custom" },
    aws: {
      ...config.aws!,
      services: { ...config.aws!.services, core: { ...config.aws!.services.core!, architecture: "amd64" } },
    },
  };
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  const container = renderTaskDefinition(overridden, "core", image).containerDefinitions[0]!;
  assert.deepEqual((container.healthCheck as { command: string[] }).command.slice(0, 3), ["CMD", "node", "-e"]);
  assert.match((container.healthCheck as { command: string[] }).command[3]!, /\/healthz/);
});

test("AWS secret upload uses parsed deployment values over stdin without staging plaintext", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secrets-"));
  const bin = join(dir, "aws-fake");
  const log = join(dir, "paths.log");
  const operatorSecrets = computedSecrets(config).filter((secret) => secret.managedBy === "operator");
  writeFileSync(
    join(dir, ".env"),
    operatorSecrets.map((secret) => `${secret.name}=${selectedTestSecretValue(secret.name)}`).join("\n"),
  );
  const sourceValues = testSecretValues(dir);
  rmSync(join(dir, ".env"));
  writeFileSync(
    bin,
    `#!/bin/sh
if [ "$1 $2" = "sts get-caller-identity" ]; then
  printf '%s\\n' 123456789012
  exit 0
fi
if [ "$1 $2" = "secretsmanager describe-secret" ]; then
  printf '{"ARN":"arn:aws:secretsmanager:us-west-2:123456789012:secret:%s-AbCdEf"}\\n' "$4"
  exit 0
fi
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  case " $* " in
    *" acme/qm/DATABASE_URL "*) printf '%s\\n' '{"ARN":"arn:aws:secretsmanager:us-west-2:123456789012:secret:acme/qm/DATABASE_URL-AbCdEf","SecretString":"postgres://database.example/qm"}' ;;
    *) printf '%s\\n' '{}' ;;
  esac
  exit 0
fi
if [ "$1 $2" = "dynamodb get-item" ]; then
  printf '%s\\n' '{}'
  exit 0
fi
if [ "$1 $2" = "ecs describe-services" ]; then
  printf '%s\\n' '{"services":[{"serviceName":"acme-core","desiredCount":0,"runningCount":0,"tags":[{"key":"Deployment","value":"acme"},{"key":"ManagedBy","value":"terraform"}]},{"serviceName":"acme-web-ui","desiredCount":0,"runningCount":0,"tags":[{"key":"Deployment","value":"acme"},{"key":"ManagedBy","value":"terraform"}]},{"serviceName":"acme-admin","desiredCount":0,"runningCount":0,"tags":[{"key":"Deployment","value":"acme"},{"key":"ManagedBy","value":"terraform"}]},{"serviceName":"acme-portal","desiredCount":0,"runningCount":0,"tags":[{"key":"Deployment","value":"acme"},{"key":"ManagedBy","value":"terraform"}]}],"failures":[]}'
  exit 0
fi
if [ "$1 $2" = "secretsmanager put-secret-value" ]; then
  payload=$(cat)
  test -n "$payload" || exit 9
  printf '%s\\n' "$*" >> "$AWS_SECRET_PATH_LOG"
  exit 0
fi
`,
  );
  chmodSync(bin, 0o755);
  const priorBin = process.env.AWS_BIN;
  const priorLog = process.env.AWS_SECRET_PATH_LOG;
  process.env.AWS_BIN = bin;
  process.env.AWS_SECRET_PATH_LOG = log;
  try {
    await awsSecretsPush(config, dir, sourceValues);
    const calls = readFileSync(log, "utf8").trim().split("\n");
    assert.equal(calls.length, operatorSecrets.length);
    assert.ok(calls.every((call) => call.includes("--secret-string file:///dev/stdin")));
    assert.ok(calls.every((call) => !call.includes("qm-secret-") && !call.includes(TEST_SECRET_VALUE)));
  } finally {
    if (priorBin === undefined) delete process.env.AWS_BIN;
    else process.env.AWS_BIN = priorBin;
    if (priorLog === undefined) delete process.env.AWS_SECRET_PATH_LOG;
    else process.env.AWS_SECRET_PATH_LOG = priorLog;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret upload accepts 65536 UTF-8 bytes and rejects 65537 before any provider call", async (t) => {
  for (const size of [65_536, 65_537] as const) {
    await t.test(String(size), async () => {
      const dir = mkdtempSync(join(tmpdir(), `qm-aws-secret-size-${size}-`));
      const secretsConfig: QmConfig = { ...oneServiceConfig(), env: {} };
      const operator = computedSecrets(secretsConfig).filter(
        (secret) => secret.managedBy === "operator" && secret.required,
      );
      writeFileSync(
        join(dir, ".env"),
        operator
          .map(
            (secret) =>
              `${secret.name}=${secret.name === "CAPABILITY_SECRET" ? "x".repeat(size) : selectedTestSecretValue(secret.name)}`,
          )
          .join("\n"),
      );
      const fake = statefulAws(dir, secretsConfig);
      const state = JSON.parse(readFileSync(fake.state, "utf8"));
      state.services["acme-core"].desiredCount = 0;
      writeFileSync(fake.state, JSON.stringify(state));
      try {
        if (size === 65_536) {
          await assert.doesNotReject(awsSecretsPush(secretsConfig, dir, testSecretValues(dir)));
          assert.match(readFileSync(fake.log, "utf8"), /secretsmanager put-secret-value/);
        } else {
          await assert.rejects(
            awsSecretsPush(secretsConfig, dir, testSecretValues(dir)),
            /CAPABILITY_SECRET exceeds the 65536-byte/,
          );
          assert.equal(readFileSync(fake.log, "utf8"), "");
        }
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS secret upload rejects an unstaged remote NUL before uploads or lease acquisition", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-remote-nul-"));
  const secretsConfig: QmConfig = { ...oneServiceConfig(), env: {} };
  const operator = computedSecrets(secretsConfig).filter(
    (secret) => secret.managedBy === "operator" && secret.required,
  );
  writeFileSync(
    join(dir, ".env"),
    operator.map((secret) => `${secret.name}=${selectedTestSecretValue(secret.name)}`).join("\n"),
  );
  const fake = statefulAws(dir, secretsConfig);
  const priorTarget = process.env.AWS_FAKE_NUL_SECRET_NAME;
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  process.env.AWS_FAKE_NUL_SECRET_NAME = "DATABASE_CA_CERT";
  process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
  try {
    await assert.rejects(
      awsSecretsPush(secretsConfig, dir, testSecretValues(dir)),
      (error: unknown) =>
        error instanceof Error &&
        /DATABASE_CA_CERT contains a NUL byte/.test(error.message) &&
        !error.message.includes("sentinel"),
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /dynamodb put-item|secretsmanager put-secret-value/);
  } finally {
    if (priorTarget === undefined) delete process.env.AWS_FAKE_NUL_SECRET_NAME;
    else process.env.AWS_FAKE_NUL_SECRET_NAME = priorTarget;
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret upload validates untouched remote values before the first upload", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-remote-invalid-"));
  const secretsConfig: QmConfig = { ...oneServiceConfig(), env: {} };
  const fake = statefulAws(dir, secretsConfig);
  const priorOverrides = process.env.AWS_FAKE_SECRET_OVERRIDES;
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  process.env.AWS_FAKE_SECRET_OVERRIDES = JSON.stringify({ DATABASE_CA_CERT: "replace-me" });
  process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
  try {
    await assert.rejects(
      awsSecretsPush(secretsConfig, dir, requiredOperatorSecretValues(secretsConfig)),
      /DATABASE_CA_CERT/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /secretsmanager get-secret-value/);
    assert.doesNotMatch(calls, /dynamodb put-item|secretsmanager put-secret-value/);
  } finally {
    if (priorOverrides === undefined) delete process.env.AWS_FAKE_SECRET_OVERRIDES;
    else process.env.AWS_FAKE_SECRET_OVERRIDES = priorOverrides;
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret upload rejects an untouched remote ARN before lease acquisition", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-remote-arn-"));
  const secretsConfig: QmConfig = { ...oneServiceConfig(), env: {} };
  const fake = statefulAws(dir, secretsConfig);
  const priorArn = process.env.AWS_FAKE_SECRET_ARN;
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  process.env.AWS_FAKE_SECRET_ARN =
    "arn:aws:secretsmanager:us-west-2:999999999999:secret:acme/qm/ANTHROPIC_API_KEY-AbCdEf";
  process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
  try {
    await assert.rejects(
      awsSecretsPush(secretsConfig, dir, requiredOperatorSecretValues(secretsConfig)),
      /returned an ARN outside the configured account and secret path/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /dynamodb put-item|secretsmanager put-secret-value/);
  } finally {
    if (priorArn === undefined) delete process.env.AWS_FAKE_SECRET_ARN;
    else process.env.AWS_FAKE_SECRET_ARN = priorArn;
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret upload revalidates untouched remote values under the lease", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-remote-rotated-"));
  const secretsConfig: QmConfig = { ...oneServiceConfig(), env: {} };
  const fake = statefulAws(dir, secretsConfig);
  const priorOverrides = process.env.AWS_FAKE_SECRET_OVERRIDES;
  const priorRotateName = process.env.AWS_FAKE_ROTATE_SECRET_NAME;
  const priorRotatedValue = process.env.AWS_FAKE_ROTATED_SECRET_VALUE;
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  process.env.AWS_FAKE_SECRET_OVERRIDES = JSON.stringify({ DATABASE_CA_CERT: "valid-ca-certificate" });
  process.env.AWS_FAKE_ROTATE_SECRET_NAME = "DATABASE_CA_CERT";
  process.env.AWS_FAKE_ROTATED_SECRET_VALUE = "replace-me";
  process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
  try {
    await assert.rejects(
      awsSecretsPush(secretsConfig, dir, requiredOperatorSecretValues(secretsConfig)),
      /DATABASE_CA_CERT/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.ok(calls.indexOf("dynamodb put-item") < calls.lastIndexOf("DATABASE_CA_CERT"));
    assert.match(calls, /dynamodb delete-item/);
    assert.doesNotMatch(calls, /secretsmanager put-secret-value|ecs register-task-definition|ecs update-service/);
  } finally {
    if (priorOverrides === undefined) delete process.env.AWS_FAKE_SECRET_OVERRIDES;
    else process.env.AWS_FAKE_SECRET_OVERRIDES = priorOverrides;
    if (priorRotateName === undefined) delete process.env.AWS_FAKE_ROTATE_SECRET_NAME;
    else process.env.AWS_FAKE_ROTATE_SECRET_NAME = priorRotateName;
    if (priorRotatedValue === undefined) delete process.env.AWS_FAKE_ROTATED_SECRET_VALUE;
    else process.env.AWS_FAKE_ROTATED_SECRET_VALUE = priorRotatedValue;
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret upload proves every selected container ARN before the first upload", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-container-arn-"));
  const secretsConfig: QmConfig = { ...oneServiceConfig(), env: {} };
  const fake = statefulAws(dir, secretsConfig);
  const priorArn = process.env.AWS_FAKE_DESCRIBE_SECRET_ARN;
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  process.env.AWS_FAKE_DESCRIBE_SECRET_ARN =
    "arn:aws:secretsmanager:us-west-2:999999999999:secret:acme/qm/ANTHROPIC_API_KEY-AbCdEf";
  process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
  try {
    await assert.rejects(
      awsSecretsPush(secretsConfig, dir, requiredOperatorSecretValues(secretsConfig)),
      /returned an ARN outside the configured account and secret path/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /dynamodb put-item.*\n[\s\S]*secretsmanager describe-secret/);
    assert.match(calls, /dynamodb delete-item/);
    assert.doesNotMatch(calls, /secretsmanager put-secret-value|ecs register-task-definition|ecs update-service/);
  } finally {
    if (priorArn === undefined) delete process.env.AWS_FAKE_DESCRIBE_SECRET_ARN;
    else process.env.AWS_FAKE_DESCRIBE_SECRET_ARN = priorArn;
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret upload rejects active services when no deployment manifest exists", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secrets-active-"));
  const secretsConfig: QmConfig = { ...oneServiceConfig(), env: {} };
  const operator = computedSecrets(secretsConfig).filter(
    (secret) => secret.managedBy === "operator" && secret.required,
  );
  writeFileSync(
    join(dir, ".env"),
    operator.map((secret) => `${secret.name}=${selectedTestSecretValue(secret.name)}`).join("\n"),
  );
  const fake = statefulAws(dir, secretsConfig);
  try {
    await assert.rejects(
      () => awsSecretsPush(secretsConfig, dir, testSecretValues(dir)),
      /cannot defer secret activation without a current deployment manifest while workloads are active: core/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /ecs describe-services/);
    assert.doesNotMatch(calls, /secretsmanager put-secret-value/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret rotation holds the deploy lease across the complete write set", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-lease-"));
  const secretsConfig: QmConfig = { ...oneServiceConfig(), env: {} };
  const operator = computedSecrets(secretsConfig).filter(
    (secret) => secret.managedBy === "operator" && secret.required,
  );
  const optionalNames = computedSecrets(secretsConfig)
    .filter((secret) => secret.managedBy === "operator" && !secret.required)
    .map((secret) => secret.name);
  const optionalValues = new Map(optionalNames.map((name) => [name, process.env[name]]));
  writeFileSync(
    join(dir, ".env"),
    operator.map((secret) => `${secret.name}=${selectedTestSecretValue(secret.name)}`).join("\n"),
  );
  const fake = statefulAws(dir, secretsConfig);
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const taskArn = state.services["acme-core"].taskDefinition;
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  const arns = Object.fromEntries(
    computedSecrets(secretsConfig).map((secret) => [secret.name, testSecretArn(secret.name)]),
  );
  state.definitions[taskArn] = renderTaskDefinition(secretsConfig, "core", image, arns);
  state.dynamo = manifestItems([{ id: "current", imageLabel: "release", tasks: { core: taskArn } }], "current");
  writeFileSync(fake.state, JSON.stringify(state));
  for (const name of optionalNames) delete process.env[name];
  try {
    await awsSecretsPush(secretsConfig, dir, testSecretValues(dir));
    const calls = readFileSync(fake.log, "utf8");
    const acquire = calls.indexOf("dynamodb put-item");
    const firstWrite = calls.indexOf("secretsmanager put-secret-value");
    const lastWrite = calls.lastIndexOf("secretsmanager put-secret-value");
    const restart = calls.indexOf("ecs update-service");
    const rolloutPoll = calls.indexOf("ecs describe-services", restart);
    const release = calls.indexOf("dynamodb delete-item");
    assert.ok(acquire >= 0 && acquire < firstWrite);
    assert.ok(lastWrite < restart && restart < rolloutPoll && rolloutPoll < release);
    assert.match(calls, /ecs update-service --cluster acme-qm --service acme-core --force-new-deployment/);
    assert.equal(calls.match(/secretsmanager put-secret-value/g)?.length, operator.length);
  } finally {
    for (const [name, value] of optionalValues) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret rotation rejects a historical sidecar secret before any upload or restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-sidecar-"));
  const configured: QmConfig = { ...oneServiceConfig(), env: {} };
  const fake = statefulAws(dir, configured);
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const task = state.services["acme-core"].taskDefinition;
  state.dynamo = manifestItems([{ id: "current", imageLabel: "release", tasks: { core: task } }], "current");
  state.definitions[task].containerDefinitions.push({
    name: "sidecar",
    image: "attacker.example/sidecar:latest",
    environment: [],
    secrets: [{ name: "CORE_SIGNING_SECRET", valueFrom: testSecretArn("CORE_SIGNING_SECRET") }],
  });
  writeFileSync(fake.state, JSON.stringify(state));
  try {
    await assert.rejects(
      awsSecretsPush(configured, dir, requiredOperatorSecretValues(configured)),
      /lacks a trusted digest-pinned task definition/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /secretsmanager put-secret-value|ecs update-service/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret rotation rejects historical fallback endpoint injection before any upload", async (t) => {
  for (const endpoint of ["AGENT_API_URL", "AWS_ENDPOINT_URL_S3", "SLACK_API_URL"] as const) {
    for (const source of ["plaintext", "secret"] as const) {
      await t.test(`${endpoint} ${source}`, async () => {
        const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-slack-endpoint-"));
        const configured: QmConfig = { ...oneServiceConfig(), env: {} };
        const fake = statefulAws(dir, configured);
        const state = JSON.parse(readFileSync(fake.state, "utf8"));
        const task = state.services["acme-core"].taskDefinition;
        state.dynamo = manifestItems([{ id: "current", imageLabel: "release", tasks: { core: task } }], "current");
        const container = state.definitions[task].containerDefinitions[0];
        if (source === "plaintext") {
          container.environment.push({ name: endpoint, value: "https://attacker.example" });
        } else {
          container.secrets.push({ name: endpoint, valueFrom: testSecretArn("CORE_SIGNING_SECRET") });
        }
        writeFileSync(fake.state, JSON.stringify(state));
        try {
          await assert.rejects(
            awsSecretsPush(configured, dir, requiredOperatorSecretValues(configured)),
            /stale or unowned (?:environment|secret) entries/,
          );
          assert.doesNotMatch(readFileSync(fake.log, "utf8"), /secretsmanager put-secret-value|ecs update-service/);
        } finally {
          fake.restore();
          rmSync(dir, { recursive: true, force: true });
        }
      });
    }
  }
});

test("AWS secret rotation rejects historical provider-owned secret destinations before any upload", async (t) => {
  for (const destination of awsProviderSecretDestinations) {
    await t.test(destination, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-provider-destination-"));
      const configured: QmConfig = { ...oneServiceConfig(), env: {} };
      const fake = statefulAws(dir, configured);
      const state = JSON.parse(readFileSync(fake.state, "utf8"));
      const task = state.services["acme-core"].taskDefinition;
      state.dynamo = manifestItems([{ id: "current", imageLabel: "release", tasks: { core: task } }], "current");
      state.definitions[task].containerDefinitions[0].secrets.push({
        name: destination,
        valueFrom: testSecretArn("CORE_SIGNING_SECRET"),
      });
      writeFileSync(fake.state, JSON.stringify(state));
      try {
        await assert.rejects(
          awsSecretsPush(configured, dir, requiredOperatorSecretValues(configured)),
          /stale or unowned secret entries/,
        );
        assert.doesNotMatch(readFileSync(fake.log, "utf8"), /secretsmanager put-secret-value|ecs update-service/);
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS secret rotation rejects every unexpected historical task-definition channel", async (t) => {
  for (const channel of ["secretOptions", "repositoryCredentials", "command", "taskRoleArn"] as const) {
    await t.test(channel, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-task-channel-"));
      const configured: QmConfig = { ...oneServiceConfig(), env: {} };
      const fake = statefulAws(dir, configured);
      const state = JSON.parse(readFileSync(fake.state, "utf8"));
      const task = state.services["acme-core"].taskDefinition;
      state.dynamo = manifestItems([{ id: "current", imageLabel: "release", tasks: { core: task } }], "current");
      addHistoricalTaskChannel(state.definitions[task], channel);
      writeFileSync(fake.state, JSON.stringify(state));
      try {
        await assert.rejects(
          awsSecretsPush(configured, dir, requiredOperatorSecretValues(configured)),
          /stale or unowned task-definition fields/,
        );
        assert.doesNotMatch(readFileSync(fake.log, "utf8"), /secretsmanager put-secret-value|ecs update-service/);
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS secret rotation refuses foreign exact-name services before uploading or restarting", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-foreign-secret-rotation-"));
  const secretsConfig: QmConfig = { ...oneServiceConfig(), env: {} };
  const operator = computedSecrets(secretsConfig).filter(
    (secret) => secret.managedBy === "operator" && secret.required,
  );
  writeFileSync(
    join(dir, ".env"),
    operator.map((secret) => `${secret.name}=${selectedTestSecretValue(secret.name)}`).join("\n"),
  );
  const fake = statefulAws(dir, secretsConfig, {}, { foreignServiceTags: true });
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const taskArn = state.services["acme-core"].taskDefinition;
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  const arns = Object.fromEntries(
    computedSecrets(secretsConfig).map((secret) => [secret.name, testSecretArn(secret.name)]),
  );
  state.definitions[taskArn] = renderTaskDefinition(secretsConfig, "core", image, arns);
  state.dynamo = manifestItems([{ id: "current", imageLabel: "release", tasks: { core: taskArn } }], "current");
  writeFileSync(fake.state, JSON.stringify(state));
  try {
    await assert.rejects(
      () => awsSecretsPush(secretsConfig, dir, testSecretValues(dir)),
      /ownership tags do not match deployment acme/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /secretsmanager put-secret-value|ecs update-service/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS secret upload registers and records a task revision for a newly supplied optional secret", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-optional-secret-"));
  const secretsConfig = oneServiceConfig();
  const required = computedSecrets(secretsConfig).filter(
    (secret) => secret.managedBy === "operator" && secret.required,
  );
  writeFileSync(
    join(dir, ".env"),
    [
      ...required.map((secret) => `${secret.name}=${selectedTestSecretValue(secret.name)}`),
      "DATABASE_CA_CERT=optional-value",
    ].join("\n"),
  );
  const fake = statefulAws(dir, secretsConfig);
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const oldTask = state.services["acme-core"].taskDefinition;
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  const arns = Object.fromEntries(
    computedSecrets(secretsConfig)
      .filter((secret) => secret.required)
      .map((secret) => [secret.name, testSecretArn(secret.name)]),
  );
  state.definitions[oldTask] = renderTaskDefinition(secretsConfig, "core", image, arns);
  state.dynamo = manifestItems([{ id: "current", imageLabel: "release", tasks: { core: oldTask } }], "current");
  writeFileSync(fake.state, JSON.stringify(state));
  try {
    await awsSecretsPush(secretsConfig, dir, testSecretValues(dir));
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /ecs register-task-definition/);
    assert.match(calls, /ecs update-service .*--task-definition/);
    assert.doesNotMatch(calls, /--force-new-deployment/);
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    const currentId = after.dynamo["deployment/current"].manifestId.S;
    assert.notEqual(currentId, "current");
    const manifest = JSON.parse(after.dynamo[`deployment/manifest/${currentId}`].manifest.S);
    assert.notEqual(manifest.tasks.core, oldTask);
    const names = after.definitions[manifest.tasks.core].containerDefinitions[0].secrets.map(
      (secret: { name: string }) => secret.name,
    );
    assert.ok(names.includes("DATABASE_CA_CERT"));
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS optional-secret activation restores prior tasks when a later service restart fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-secret-compensation-"));
  const secretsConfig = twoServiceConfig();
  const required = computedSecrets(secretsConfig).filter(
    (secret) => secret.managedBy === "operator" && secret.required,
  );
  writeFileSync(
    join(dir, ".env"),
    [
      ...required.map((secret) => `${secret.name}=${selectedTestSecretValue(secret.name)}`),
      "DATABASE_CA_CERT=optional-value",
    ].join("\n"),
  );
  const fake = statefulAws(dir, secretsConfig, {}, { failForcedDeploymentResponse: true });
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const oldTasks = {
    core: state.services["acme-core"].taskDefinition,
    "web-ui": state.services["acme-web-ui"].taskDefinition,
  };
  const arns = Object.fromEntries(
    computedSecrets(secretsConfig)
      .filter((secret) => secret.required)
      .map((secret) => [secret.name, testSecretArn(secret.name)]),
  );
  for (const workload of ["core", "web-ui"] as const) {
    const repository = secretsConfig.aws!.services[workload]!.ecrRepository;
    const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/${repository}@sha256:${"a".repeat(64)}`;
    state.definitions[oldTasks[workload]] = renderTaskDefinition(secretsConfig, workload, image, arns);
  }
  state.dynamo = manifestItems([{ id: "current", imageLabel: "release", tasks: oldTasks }], "current");
  writeFileSync(fake.state, JSON.stringify(state));
  try {
    await assert.rejects(
      () => awsSecretsPush(secretsConfig, dir, testSecretValues(dir)),
      /did not identify the replacement deployment for web-ui/,
    );
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(after.services["acme-core"].taskDefinition, oldTasks.core);
    assert.equal(after.dynamo["deployment/current"].manifestId.S, "current");
    const updates = readFileSync(fake.log, "utf8")
      .split("\n")
      .filter((line) => line.includes("ecs update-service"));
    assert.ok(updates.some((line) => line.includes("--service acme-core") && !line.includes(oldTasks.core)));
    assert.ok(updates.some((line) => line.includes("--service acme-core") && line.includes(oldTasks.core)));
    assert.ok(
      updates.some((line) => line.includes("--service acme-web-ui") && line.includes("--force-new-deployment")),
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

const oneServiceConfig = (name = "core"): QmConfig => ({
  ...config,
  services: ["core"],
  aws: { ...config.aws!, services: { [name]: config.aws!.services[name] ?? config.aws!.services.core! } },
});

const microvmConfig = (configured: QmConfig): QmConfig => {
  const { sandbox: _sandbox, ...rest } = configured;
  return rest;
};

const twoServiceConfig = (): QmConfig => ({
  ...config,
  services: ["core", "web-ui"],
  aws: { ...config.aws!, services: { core: config.aws!.services.core!, "web-ui": config.aws!.services["web-ui"]! } },
});

test("AWS plan reports stale and missing MicroVM rebuilds without mutating", async () => {
  const lines: string[] = [];
  const log = console.log;
  console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
  try {
    for (const scenario of ["stale", "missing"] as const) {
      const dir = mkdtempSync(join(tmpdir(), `qm-aws-plan-microvm-${scenario}-`));
      const configPath = join(dir, "qm.config.jsonc");
      const { sandbox: _sandbox, ...base } = oneServiceConfig();
      const core = { ...base.env.core };
      if (scenario === "stale") core.AWS_DEPLOY_IMAGE_SOURCE_SHA256 = "stale";
      else delete core.AWS_DEPLOY_IMAGE_VERSION;
      const configured: QmConfig = { ...base, env: { ...base.env, core } };
      const raw = JSON.stringify(configured);
      writeFileSync(configPath, raw);
      const fake = statefulAws(dir, configured);
      try {
        const ctx: DeployContext = {
          config: configured,
          configPath,
          configIdentity: configIdentity(configPath),
          configDir: dir,
          sandboxDir: join(dir, "sandbox"),
          target: "aws",
        };
        const prepared = await prepareUpSubstrate(ctx, { dryRun: true });
        assert.equal(prepared.awsMicrovmBuildPlanned, true);
        await hostingProvider("aws").createBackend(prepared).up({ dryRun: true });
        const output = lines.join("\n");
        assert.match(output, /MicroVM image: rebuild required before the core deployment/);
        assert.match(output, /Plan only\. Re-run `qm up --yes` to deploy\./);
        const calls = readFileSync(fake.log, "utf8");
        assert.doesNotMatch(
          calls,
          /s3api put-object|lambda-microvms (?:create|update|delete)|dynamodb put-item|ecs register-task-definition|ecs update-service/,
        );
        assert.equal(readFileSync(configPath, "utf8"), raw);
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
      lines.length = 0;
    }
  } finally {
    console.log = log;
  }
});

test("AWS non-core only plans skip every deployment-image check", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-only-no-microvm-"));
  const configPath = join(dir, "qm.config.jsonc");
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/bin/sh\necho 'Digest: sha256:${"a".repeat(64)}'\n`);
  chmodSync(dockerBin, 0o755);
  const base = twoServiceConfig();
  const core = { ...base.env.core };
  delete core.AWS_DEPLOY_IMAGE;
  delete core.AWS_DEPLOY_IMAGE_VERSION;
  const configured: QmConfig = { ...base, env: { ...base.env, core } };
  writeFileSync(configPath, JSON.stringify(configured));
  const tasks = Object.fromEntries(
    Object.entries(configured.aws!.services).map(([name, service]) => [
      name,
      `arn:aws:ecs:us-west-2:123456789012:task-definition/${service.ecsService}:1`,
    ]),
  );
  const fake = statefulAws(
    dir,
    configured,
    manifestItems([{ id: "current", imageLabel: "release", tasks }], "current"),
  );
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const arns = Object.fromEntries(
    computedSecrets(configured).map((secret) => [secret.name, testSecretArn(secret.name)]),
  );
  state.definitions[tasks.core!] = renderTaskDefinition(
    configured,
    "core",
    `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`,
    arns,
  );
  writeFileSync(fake.state, JSON.stringify(state));
  const priorPath = process.env.PATH;
  const priorUnsupported = process.env.AWS_FAKE_LAMBDA_UNSUPPORTED;
  process.env.PATH = `${dir}:${priorPath}`;
  process.env.AWS_FAKE_LAMBDA_UNSUPPORTED = "1";
  try {
    const ctx: DeployContext = {
      config: configured,
      configPath,
      configIdentity: configIdentity(configPath),
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      target: "aws",
    };
    const provider = hostingProvider("aws");
    const options = provider.upOptions(ctx, { only: "web-ui" }, true);
    const preflighted = await provider.preflightUp(ctx, options);
    const prepared = await prepareUpSubstrate(preflighted, options);
    await provider.createBackend(prepared).up(options);
    assert.equal(prepared.awsMicrovmBuildPlanned, undefined);
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /lambda-microvms/);
  } finally {
    process.env.PATH = priorPath;
    if (priorUnsupported === undefined) delete process.env.AWS_FAKE_LAMBDA_UNSUPPORTED;
    else process.env.AWS_FAKE_LAMBDA_UNSUPPORTED = priorUnsupported;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS plan reports missing and inactive remote MicroVM versions without mutation", async () => {
  for (const scenario of ["missing", "inactive"] as const) {
    const dir = mkdtempSync(join(tmpdir(), `qm-aws-plan-remote-${scenario}-`));
    const configPath = join(dir, "qm.config.jsonc");
    const { sandbox: _sandbox, ...base } = oneServiceConfig();
    const configured: QmConfig = {
      ...base,
      env: {
        ...base.env,
        core: {
          ...base.env.core,
          AWS_DEPLOY_IMAGE_VERSION: "1",
          AWS_DEPLOY_IMAGE_SOURCE_SHA256: microvmBuildArchiveSha256(),
        },
      },
    };
    const raw = JSON.stringify(configured);
    writeFileSync(configPath, raw);
    const fake = statefulAws(dir, configured);
    const priorMissing = process.env.AWS_FAKE_IMAGE_MISSING;
    const priorStatus = process.env.AWS_FAKE_IMAGE_STATUS;
    if (scenario === "missing") process.env.AWS_FAKE_IMAGE_MISSING = "1";
    else process.env.AWS_FAKE_IMAGE_STATUS = "INACTIVE";
    const lines: string[] = [];
    const log = console.log;
    console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
    try {
      const ctx: DeployContext = {
        config: configured,
        configPath,
        configIdentity: configIdentity(configPath),
        configDir: dir,
        sandboxDir: join(dir, "sandbox"),
        target: "aws",
      };
      const provider = hostingProvider("aws");
      const options = provider.upOptions(ctx, {}, true);
      const preflighted = await provider.preflightUp(ctx, options);
      assert.equal(preflighted.awsPreflight?.microvmRebuildRequired, true);
      const prepared = await prepareUpSubstrate(preflighted, options);
      await provider.createBackend(prepared).up(options);
      assert.match(lines.join("\n"), /MicroVM image: rebuild required before the core deployment/);
      assert.doesNotMatch(
        readFileSync(fake.log, "utf8"),
        /s3api put-object|lambda-microvms (?:create|update|delete)|dynamodb put-item|ecs register-task-definition|ecs update-service/,
      );
      assert.equal(readFileSync(configPath, "utf8"), raw);
    } finally {
      console.log = log;
      if (priorMissing === undefined) delete process.env.AWS_FAKE_IMAGE_MISSING;
      else process.env.AWS_FAKE_IMAGE_MISSING = priorMissing;
      if (priorStatus === undefined) delete process.env.AWS_FAKE_IMAGE_STATUS;
      else process.env.AWS_FAKE_IMAGE_STATUS = priorStatus;
      fake.restore();
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("AWS MicroVM preflight fails clearly when the CLI lacks lambda-microvms", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-plan-no-microvms-"));
  const { sandbox: _sandbox, ...configured } = oneServiceConfig();
  const fake = statefulAws(dir, configured as QmConfig);
  const prior = process.env.AWS_FAKE_LAMBDA_UNSUPPORTED;
  process.env.AWS_FAKE_LAMBDA_UNSUPPORTED = "1";
  try {
    const ctx: DeployContext = {
      config: configured as QmConfig,
      configPath: join(dir, "qm.config.jsonc"),
      configIdentity: TEST_CONFIG_IDENTITY,
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      target: "aws",
    };
    const options = hostingProvider("aws").upOptions(ctx, {}, true);
    await assert.rejects(
      () => hostingProvider("aws").preflightUp(ctx, options),
      /AWS CLI lacks the `lambda-microvms` commands/,
    );
    assert.doesNotMatch(
      readFileSync(fake.log, "utf8"),
      /s3api put-object|dynamodb put-item|ecs register-task-definition|ecs update-service/,
    );
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_LAMBDA_UNSUPPORTED;
    else process.env.AWS_FAKE_LAMBDA_UNSUPPORTED = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

function manifestItems(
  manifests: Array<{
    id: string;
    previous?: string;
    imageLabel?: string;
    dbSnapshot?: string;
    tasks: Record<string, string>;
    imageProvenance?: Record<
      string,
      | { kind: "configured"; source: string }
      | { kind: "source-build"; source?: "plugin" | "checkout"; gitCommit?: string; dirty?: boolean }
    >;
    layer?: { key: string; sha256: string };
  }>,
  current: string,
) {
  const items: Record<string, Record<string, { S: string }>> = {
    "deployment/current": { lockKey: { S: "deployment/current" }, manifestId: { S: current } },
  };
  for (const manifest of manifests) {
    const value = { ...manifest, layer: manifest.layer ?? EMPTY_LAYER, createdAt: "2026-01-01T00:00:00.000Z" };
    items[`deployment/manifest/${manifest.id}`] = {
      lockKey: { S: `deployment/manifest/${manifest.id}` },
      manifest: { S: JSON.stringify(value) },
    };
    if (manifest.imageLabel)
      items[`deployment/label/${manifest.imageLabel}`] = {
        lockKey: { S: `deployment/label/${manifest.imageLabel}` },
        manifestId: { S: manifest.id },
      };
  }
  return items;
}

test("rollback uses a coherent durable manifest across independent service histories", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-"));
  const multi = twoServiceConfig();
  const old = {
    core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:7",
    "web-ui": "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-web-ui:4",
  };
  const current = {
    core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:9",
    "web-ui": "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-web-ui:8",
  };
  const fake = statefulAws(
    dir,
    multi,
    manifestItems(
      [
        { id: "old", tasks: old },
        { id: "current", previous: "old", tasks: current },
      ],
      "current",
    ),
  );
  try {
    await awsRollback(multi);
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /--task-definition arn:aws:ecs:us-west-2:123456789012:task-definition\/acme-core:7/);
    assert.match(calls, /--task-definition arn:aws:ecs:us-west-2:123456789012:task-definition\/acme-web-ui:4/);
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(state.dynamo["deployment/current"].manifestId.S, "old");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

type HistoricalTaskChannel = "secretOptions" | "repositoryCredentials" | "command" | "taskRoleArn";

function addHistoricalTaskChannel(definition: Record<string, unknown>, channel: HistoricalTaskChannel): void {
  const container = (definition.containerDefinitions as Array<Record<string, unknown>>)[0]!;
  if (channel === "secretOptions") {
    (container.logConfiguration as Record<string, unknown>).secretOptions = [
      { name: "splunk-token", valueFrom: testSecretArn("CAPABILITY_SECRET") },
    ];
  } else if (channel === "repositoryCredentials") {
    container.repositoryCredentials = { credentialsParameter: testSecretArn("CAPABILITY_SECRET") };
  } else if (channel === "command") {
    container.command = ["node", "exfiltrate.js"];
  } else {
    definition.taskRoleArn = "arn:aws:iam::123456789012:role/attacker";
  }
}

test("AWS rollback rejects every unexpected historical task-definition channel", async (t) => {
  for (const channel of ["secretOptions", "repositoryCredentials", "command", "taskRoleArn"] as const) {
    await t.test(channel, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-task-channel-"));
      const configured = oneServiceConfig();
      const old = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:7";
      const current = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:9";
      const fake = statefulAws(
        dir,
        configured,
        manifestItems(
          [
            { id: "old", tasks: { core: old } },
            { id: "current", previous: "old", tasks: { core: current } },
          ],
          "current",
        ),
      );
      const state = JSON.parse(readFileSync(fake.state, "utf8"));
      addHistoricalTaskChannel(state.definitions[old], channel);
      writeFileSync(fake.state, JSON.stringify(state));
      try {
        await assert.rejects(awsRollback(configured), /stale or unowned task-definition fields/);
        assert.doesNotMatch(readFileSync(fake.log, "utf8"), /ecs update-service|dynamodb transact-write-items/);
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS rollback rejects historical provider-owned secret destinations before mutation", async (t) => {
  for (const destination of awsProviderSecretDestinations) {
    await t.test(destination, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-provider-destination-"));
      const configured = oneServiceConfig();
      const old = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:7";
      const current = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:9";
      const fake = statefulAws(
        dir,
        configured,
        manifestItems(
          [
            { id: "old", tasks: { core: old } },
            { id: "current", previous: "old", tasks: { core: current } },
          ],
          "current",
        ),
      );
      const state = JSON.parse(readFileSync(fake.state, "utf8"));
      state.definitions[old].containerDefinitions[0].secrets.push({
        name: destination,
        valueFrom: testSecretArn("CORE_SIGNING_SECRET"),
      });
      writeFileSync(fake.state, JSON.stringify(state));
      try {
        await assert.rejects(awsRollback(configured), /stale or unowned secret entries/);
        assert.doesNotMatch(readFileSync(fake.log, "utf8"), /ecs update-service|dynamodb transact-write-items/);
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS rollback enforces the current portal auth-broker wiring", async (t) => {
  for (const mode of ["built-in removed", "external injected"] as const) {
    await t.test(mode, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-portal-broker-"));
      const configured = mode === "built-in removed" ? aliasedTrustConfig("auth").config : config;
      const tasks = (revision: number): Record<string, string> =>
        Object.fromEntries(
          Object.entries(configured.aws!.services).map(([workload, service]) => [
            workload,
            `arn:aws:ecs:us-west-2:123456789012:task-definition/${service.ecsService}:${revision}`,
          ]),
        );
      const old = tasks(7);
      const current = tasks(9);
      const fake = statefulAws(
        dir,
        configured,
        manifestItems(
          [
            { id: "old", tasks: old },
            { id: "current", previous: "old", tasks: current },
          ],
          "current",
        ),
      );
      const state = JSON.parse(readFileSync(fake.state, "utf8"));
      const portalTask = old.portal;
      assert.ok(portalTask);
      const environment = state.definitions[portalTask].containerDefinitions[0].environment;
      if (mode === "built-in removed") {
        state.definitions[portalTask].containerDefinitions[0].environment = environment.filter(
          (entry: { name: string }) => entry.name !== "AUTH_BROKER_UPSTREAM",
        );
      } else {
        environment.push({ name: "AUTH_BROKER_UPSTREAM", value: "http://auth.acme.internal:8080" });
      }
      writeFileSync(fake.state, JSON.stringify(state));
      try {
        await assert.rejects(awsRollback(configured), /stale or unowned environment entries/);
        assert.doesNotMatch(readFileSync(fake.log, "utf8"), /ecs update-service|dynamodb transact-write-items/);
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS rollback validates the authoritative runtime secret set under its lease", async (t) => {
  for (const selected of [{ name: "weak", value: "x" }, { name: "empty", value: "" }, { name: "missing" }] as const) {
    await t.test(selected.name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-runtime-secret-"));
      const configured = oneServiceConfig();
      const old = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:7";
      const current = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:9";
      const fake = statefulAws(
        dir,
        configured,
        manifestItems(
          [
            { id: "old", tasks: { core: old } },
            { id: "current", previous: "old", tasks: { core: current } },
          ],
          "current",
        ),
      );
      const priorOverrides = process.env.AWS_FAKE_SECRET_OVERRIDES;
      const priorMissing = process.env.AWS_FAKE_MISSING_SECRET_NAME;
      if (selected.name === "missing") {
        delete process.env.AWS_FAKE_SECRET_OVERRIDES;
        process.env.AWS_FAKE_MISSING_SECRET_NAME = "CORE_SIGNING_SECRET";
      } else {
        process.env.AWS_FAKE_SECRET_OVERRIDES = JSON.stringify({ CORE_SIGNING_SECRET: selected.value });
        delete process.env.AWS_FAKE_MISSING_SECRET_NAME;
      }
      try {
        await assert.rejects(
          awsRollback(configured),
          selected.name === "missing"
            ? /ResourceNotFoundException/
            : /required AWS secret CORE_SIGNING_SECRET has no usable/,
        );
        const calls = readFileSync(fake.log, "utf8");
        assert.ok(calls.indexOf("dynamodb put-item") < calls.indexOf("acme/qm/CORE_SIGNING_SECRET"));
        assert.match(calls, /dynamodb delete-item/);
        assert.doesNotMatch(calls, /ecs update-service|dynamodb transact-write-items/);
      } finally {
        if (priorOverrides === undefined) delete process.env.AWS_FAKE_SECRET_OVERRIDES;
        else process.env.AWS_FAKE_SECRET_OVERRIDES = priorOverrides;
        if (priorMissing === undefined) delete process.env.AWS_FAKE_MISSING_SECRET_NAME;
        else process.env.AWS_FAKE_MISSING_SECRET_NAME = priorMissing;
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
  await t.test("valid", async () => {
    const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-runtime-secret-"));
    const configured = oneServiceConfig();
    const old = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:7";
    const current = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:9";
    const fake = statefulAws(
      dir,
      configured,
      manifestItems(
        [
          { id: "old", tasks: { core: old } },
          { id: "current", previous: "old", tasks: { core: current } },
        ],
        "current",
      ),
    );
    try {
      await awsRollback(configured);
      const calls = readFileSync(fake.log, "utf8");
      const lease = calls.indexOf("dynamodb put-item");
      const secret = calls.indexOf("acme/qm/CORE_SIGNING_SECRET", lease);
      const update = calls.indexOf("ecs update-service");
      assert.ok(lease >= 0 && lease < secret && secret < update);
    } finally {
      fake.restore();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

test("AWS rollback repairs stale or missing PUBLIC_API_URL before reactivating tasks", async (t) => {
  for (const mode of ["stale", "missing"] as const) {
    await t.test(mode, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-public-api-url-"));
      const configured: QmConfig = { ...oneServiceConfig(), apiUrl: "https://api.new.example" };
      const old = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:7";
      const current = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:9";
      const fake = statefulAws(
        dir,
        configured,
        manifestItems(
          [
            { id: "old", tasks: { core: old } },
            { id: "current", previous: "old", tasks: { core: current } },
          ],
          "current",
        ),
      );
      const priorOverrides = process.env.AWS_FAKE_SECRET_OVERRIDES;
      const priorMissing = process.env.AWS_FAKE_MISSING_SECRET_NAME;
      if (mode === "stale") {
        process.env.AWS_FAKE_SECRET_OVERRIDES = JSON.stringify({
          PUBLIC_API_URL: "https://api.stale.example",
        });
        delete process.env.AWS_FAKE_MISSING_SECRET_NAME;
      } else {
        delete process.env.AWS_FAKE_SECRET_OVERRIDES;
        process.env.AWS_FAKE_MISSING_SECRET_NAME = "PUBLIC_API_URL";
      }
      try {
        await awsRollback(configured);
        const calls = readFileSync(fake.log, "utf8");
        const put = calls.indexOf("secretsmanager put-secret-value --secret-id acme/qm/PUBLIC_API_URL");
        const update = calls.indexOf("ecs update-service");
        assert.ok(put >= 0 && put < update);
        const after = JSON.parse(readFileSync(fake.state, "utf8"));
        assert.equal(after.secretValues.PUBLIC_API_URL, "https://api.new.example");
      } finally {
        if (priorOverrides === undefined) delete process.env.AWS_FAKE_SECRET_OVERRIDES;
        else process.env.AWS_FAKE_SECRET_OVERRIDES = priorOverrides;
        if (priorMissing === undefined) delete process.env.AWS_FAKE_MISSING_SECRET_NAME;
        else process.env.AWS_FAKE_MISSING_SECRET_NAME = priorMissing;
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS rollback refuses historical task definitions outside current environment and secret ownership", async (t) => {
  for (const kind of [
    "provider environment",
    "AWS endpoint plaintext",
    "legacy API endpoint secret",
    "Slack endpoint secret",
    "plugin cross-service secret",
    "sidecar secret",
  ] as const) {
    await t.test(kind, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-stale-task-"));
      const base = oneServiceConfig();
      const configured: QmConfig =
        kind === "plugin cross-service secret"
          ? {
              ...base,
              plugins: [{ name: "linear", image: "ghcr.io/acme/linear:1", secrets: [{ name: "LINEAR_TOKEN" }] }],
              aws: {
                ...base.aws!,
                services: {
                  ...base.aws!.services,
                  linear: {
                    ecrRepository: "qm-linear",
                    ecsService: "acme-linear",
                    cpu: 256,
                    memory: 512,
                    architecture: "amd64",
                  },
                },
              },
            }
          : base;
      const taskSet = (revision: number): Record<string, string> =>
        Object.fromEntries(
          Object.entries(configured.aws!.services).map(([workload, service]) => [
            workload,
            `arn:aws:ecs:us-west-2:123456789012:task-definition/${service.ecsService}:${revision}`,
          ]),
        );
      const old = taskSet(7);
      const current = taskSet(9);
      const fake = statefulAws(
        dir,
        configured,
        manifestItems(
          [
            { id: "old", tasks: old },
            { id: "current", previous: "old", tasks: current },
          ],
          "current",
        ),
      );
      const state = JSON.parse(readFileSync(fake.state, "utf8"));
      const workload = kind === "plugin cross-service secret" ? "linear" : "core";
      const definition = state.definitions[old[workload]!];
      if (kind === "provider environment") {
        definition.containerDefinitions[0].environment.find(
          (entry: { name: string }) => entry.name === "DATA_DIR",
        ).value = "/tmp/lost";
      } else if (kind === "AWS endpoint plaintext") {
        definition.containerDefinitions[0].environment.push({
          name: "AWS_ENDPOINT_URL_S3",
          value: "https://attacker.example",
        });
      } else if (kind === "legacy API endpoint secret") {
        definition.containerDefinitions[0].secrets.push({
          name: "AGENT_API_URL",
          valueFrom: testSecretArn("CORE_SIGNING_SECRET"),
        });
      } else if (kind === "Slack endpoint secret") {
        definition.containerDefinitions[0].secrets.push({
          name: "SLACK_API_URL",
          valueFrom: testSecretArn("CORE_SIGNING_SECRET"),
        });
      } else if (kind === "plugin cross-service secret") {
        definition.containerDefinitions[0].secrets.push({
          name: "DATABASE_URL",
          valueFrom: testSecretArn("DATABASE_URL"),
        });
      } else {
        definition.containerDefinitions.push({
          name: "sidecar",
          image: "attacker.example/sidecar:latest",
          environment: [],
          secrets: [{ name: "CORE_SIGNING_SECRET", valueFrom: testSecretArn("CORE_SIGNING_SECRET") }],
        });
      }
      writeFileSync(fake.state, JSON.stringify(state));
      try {
        await assert.rejects(
          awsRollback(configured),
          kind === "sidecar secret"
            ? /lacks a trusted digest-pinned task definition/
            : /stale or unowned (?:environment|secret) entries/,
        );
        assert.doesNotMatch(readFileSync(fake.log, "utf8"), /ecs update-service|dynamodb transact-write-items/);
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS rollback surfaces the pre-deploy database snapshot of the deployment it rolls back", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-snapshot-"));
  const single = oneServiceConfig();
  const fake = statefulAws(
    dir,
    single,
    manifestItems(
      [
        { id: "old", tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:7" } },
        {
          id: "current",
          previous: "old",
          dbSnapshot: "acme-qm-core-predeploy-current",
          tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:9" },
        },
      ],
      "current",
    ),
  );
  const lines: string[] = [];
  const log = console.log;
  console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
  try {
    await awsRollback(single);
    const out = lines.join("\n");
    assert.match(out, /rollback restores code and configuration, not data/);
    assert.match(
      out,
      /restore-db-instance-from-db-snapshot --db-snapshot-identifier acme-qm-core-predeploy-current --db-instance-identifier acme-qm-core-restored --region us-west-2, then repoint the stack at the restored instance/,
    );
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rollback --to a manifest several steps back surfaces the target's successor snapshot, not the current one", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-snapshot-chain-"));
  const single = oneServiceConfig();
  const fake = statefulAws(
    dir,
    single,
    manifestItems(
      [
        { id: "a", tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:5" } },
        {
          id: "b",
          previous: "a",
          dbSnapshot: "acme-qm-core-predeploy-b",
          tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:7" },
        },
        {
          id: "c",
          previous: "b",
          dbSnapshot: "acme-qm-core-predeploy-c",
          tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:9" },
        },
      ],
      "c",
    ),
  );
  const lines: string[] = [];
  const log = console.log;
  console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
  try {
    await awsRollback(single, "a");
    const out = lines.join("\n");
    assert.match(
      out,
      /--db-snapshot-identifier acme-qm-core-predeploy-b --db-instance-identifier acme-qm-core-restored --region us-west-2/,
      "the data restore point is the snapshot taken before the target's successor",
    );
    assert.doesNotMatch(out, /acme-qm-core-predeploy-c/);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rollback surfaces the snapshot even when a rotation manifest sits directly after the target", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-snapshot-rotation-"));
  const single = oneServiceConfig();
  const fake = statefulAws(
    dir,
    single,
    manifestItems(
      [
        { id: "b", tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:5" } },
        {
          id: "r",
          previous: "b",
          tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:5" },
        },
        {
          id: "c",
          previous: "r",
          dbSnapshot: "acme-qm-core-predeploy-c",
          tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:9" },
        },
      ],
      "c",
    ),
  );
  const lines: string[] = [];
  const log = console.log;
  console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
  try {
    await awsRollback(single, "b");
    assert.match(
      lines.join("\n"),
      /--db-snapshot-identifier acme-qm-core-predeploy-c/,
      "the rotation record between target and deploy does not hide the restore point",
    );
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rollback resolves a label through its full-service manifest before mutating ECS", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-label-"));
  const single = oneServiceConfig();
  const target = { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:2" };
  const fake = statefulAws(
    dir,
    single,
    manifestItems(
      [
        { id: "v2", imageLabel: "release-2", tasks: target },
        { id: "current", previous: "v2", tasks: target },
      ],
      "current",
    ),
  );
  try {
    await awsRollback(single, "release-2");
    assert.match(
      readFileSync(fake.log, "utf8"),
      /--task-definition arn:aws:ecs:us-west-2:123456789012:task-definition\/acme-core:2/,
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

function awsRollbackLayerFixture(dir: string): {
  single: QmConfig;
  fake: ReturnType<typeof statefulAws>;
  oldBody: string;
  currentBody: string;
  oldHash: string;
  currentHash: string;
} {
  const single = oneServiceConfig();
  const task = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:2";
  const oldBody = JSON.stringify({
    contract: 1,
    tools: [],
    skills: [{ path: "skills/old/SKILL.md", content: "---\nname: old\ndescription: Old.\n---\nOld.\n" }],
  });
  const currentBody = JSON.stringify({
    contract: 1,
    tools: [],
    skills: [
      { path: "skills/current/SKILL.md", content: "---\nname: current\ndescription: Current.\n---\nCurrent.\n" },
    ],
  });
  const oldHash = createHash("sha256").update(oldBody).digest("hex");
  const currentHash = createHash("sha256").update(currentBody).digest("hex");
  const oldLayer = { key: "deployment/layers/old.json", sha256: oldHash };
  const currentLayer = { key: "deployment/layers/current.json", sha256: currentHash };
  const fake = statefulAws(
    dir,
    single,
    manifestItems(
      [
        { id: "old", tasks: { core: task }, layer: oldLayer },
        { id: "current", previous: "old", tasks: { core: task }, layer: currentLayer },
      ],
      "current",
    ),
  );
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.objects[oldLayer.key] = oldBody;
  state.objects[currentLayer.key] = currentBody;
  writeFileSync(fake.state, JSON.stringify(state));
  return { single, fake, oldBody, currentBody, oldHash, currentHash };
}

function durableLayerStateBody(
  body: string,
  contentHash: string,
  generation = 2,
  operationId: string | null = "1".repeat(32),
): string {
  return JSON.stringify({
    contract: 1,
    version: generation,
    generation,
    source: "durable",
    bundle: JSON.parse(body),
    contentHash,
    runtimeContentHash: contentHash,
    operationId,
    status: "applied",
  });
}

function layerMutationResponse(
  version: number,
  contentHash: string,
  operationId: string | null,
  status: "applied" | "degraded" = "applied",
): Response {
  return new Response(
    JSON.stringify({
      ok: true,
      version,
      contentHash,
      operationId,
      changed: true,
      durable: true,
      status,
      ...(status === "degraded" ? { message: "projection failed" } : {}),
    }),
    { status: status === "degraded" ? 202 : 200 },
  );
}

test("AWS rollback bounds deployment-layer artifact downloads before reading them", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-layer-oversized-"));
  const { single, fake } = awsRollbackLayerFixture(dir);
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.objects["deployment/layers/old.json"] = "x".repeat(2_000_000);
  writeFileSync(fake.state, JSON.stringify(state));
  try {
    await assert.rejects(
      awsRollback(single, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY }),
      /deployment-layer artifact is invalid/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /s3api get-object .*deployment\/layers\/old\.json .*--range bytes=0-1000000/);
    assert.doesNotMatch(calls, /ecs update-service/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rollback bounds a deployment-layer artifact that grows after descriptor stat", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-layer-growth-"));
  const { single, fake } = awsRollbackLayerFixture(dir);
  const originalReadSync = fs.readSync;
  let injected = false;
  let largestRead = 0;
  fs.readSync = ((
    descriptor: number,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number | null,
  ): number => {
    largestRead = Math.max(largestRead, length);
    const count = originalReadSync(descriptor, buffer, offset, length, position);
    if (!injected && position === 0 && count < length) {
      buffer[offset + count] = 0;
      injected = true;
      return count + 1;
    }
    return count;
  }) as typeof fs.readSync;
  syncBuiltinESMExports();
  try {
    await assert.rejects(
      awsRollback(single, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY }),
      /deployment-layer artifact is invalid/,
    );
    assert.equal(injected, true);
    assert.ok(largestRead <= 1_000_001);
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /ecs update-service/);
  } finally {
    fs.readSync = originalReadSync;
    syncBuiltinESMExports();
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rollback snapshots the current layer and conditionally restores the recorded layer", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-layer-"));
  const single = oneServiceConfig();
  const task = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:2";
  const oldBody = JSON.stringify({
    contract: 1,
    tools: [],
    skills: [{ path: "skills/old/SKILL.md", content: "---\nname: old\ndescription: Old.\n---\nOld.\n" }],
  });
  const currentBody = JSON.stringify({
    contract: 1,
    tools: [],
    skills: [
      { path: "skills/current/SKILL.md", content: "---\nname: current\ndescription: Current.\n---\nCurrent.\n" },
    ],
  });
  const artifact = (id: string, body: string) => ({
    key: `deployment/layers/${id}.json`,
    sha256: createHash("sha256").update(body).digest("hex"),
  });
  const oldLayer = artifact("old", oldBody);
  const currentLayer = artifact("current", currentBody);
  const fake = statefulAws(
    dir,
    single,
    manifestItems(
      [
        { id: "old", tasks: { core: task }, layer: oldLayer },
        { id: "current", previous: "old", tasks: { core: task }, layer: currentLayer },
      ],
      "current",
    ),
  );
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.objects[oldLayer.key] = oldBody;
  state.objects[currentLayer.key] = currentBody;
  writeFileSync(fake.state, JSON.stringify(state));
  const priorFetch = globalThis.fetch;
  const priorSecret = process.env.CORE_SIGNING_SECRET;
  const bodies: string[] = [];
  const urls: URL[] = [];
  const currentOperationId = "1".repeat(32);
  process.env.CORE_SIGNING_SECRET = "test-signing-secret-with-32-bytes";
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    urls.push(url);
    if (init?.method !== "PUT") {
      return new Response(
        JSON.stringify({
          contract: 1,
          version: 2,
          generation: 2,
          source: "durable",
          bundle: JSON.parse(currentBody),
          contentHash: currentLayer.sha256,
          runtimeContentHash: currentLayer.sha256,
          operationId: currentOperationId,
          status: "applied",
        }),
        { status: 200 },
      );
    }
    const body = String(init.body ?? "");
    bodies.push(body);
    const operationId = url.searchParams.get("operationId");
    return new Response(
      JSON.stringify({
        ok: true,
        version: 3,
        contentHash: createHash("sha256").update(body).digest("hex"),
        operationId,
        changed: true,
        durable: true,
        status: "applied",
      }),
      { status: 200 },
    );
  }) as typeof fetch;
  try {
    await awsRollback(single, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY });
    assert.deepEqual(bodies, [oldBody]);
    const put = urls.find((url) => url.searchParams.has("operationId"))!;
    assert.equal(put.searchParams.get("generation"), "2");
    assert.equal(put.searchParams.get("source"), "durable");
    assert.equal(put.searchParams.get("contentHash"), currentLayer.sha256);
    assert.equal(put.searchParams.get("currentOperationId"), currentOperationId);
    assert.match(put.searchParams.get("operationId") ?? "", /^[a-f0-9]{32}$/);
    assert.equal(JSON.parse(readFileSync(fake.state, "utf8")).dynamo["deployment/current"].manifestId.S, "old");
  } finally {
    globalThis.fetch = priorFetch;
    if (priorSecret === undefined) delete process.env.CORE_SIGNING_SECRET;
    else process.env.CORE_SIGNING_SECRET = priorSecret;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rollback restores an acknowledged layer mutation when subsequent layer reads are broken", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-layer-broken-read-"));
  const single = oneServiceConfig();
  const targetTask = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:2";
  const oldBody = JSON.stringify({
    contract: 1,
    tools: [],
    skills: [{ path: "skills/old/SKILL.md", content: "---\nname: old\ndescription: Old.\n---\nOld.\n" }],
  });
  const currentBody = JSON.stringify({
    contract: 1,
    tools: [],
    skills: [
      { path: "skills/current/SKILL.md", content: "---\nname: current\ndescription: Current.\n---\nCurrent.\n" },
    ],
  });
  const oldHash = createHash("sha256").update(oldBody).digest("hex");
  const currentHash = createHash("sha256").update(currentBody).digest("hex");
  const oldLayer = { key: "deployment/layers/old.json", sha256: oldHash };
  const currentLayer = { key: "deployment/layers/current.json", sha256: currentHash };
  const fake = statefulAws(
    dir,
    single,
    manifestItems(
      [
        { id: "old", tasks: { core: targetTask }, layer: oldLayer },
        { id: "current", previous: "old", tasks: { core: targetTask }, layer: currentLayer },
      ],
      "current",
    ),
  );
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.objects[oldLayer.key] = oldBody;
  state.objects[currentLayer.key] = currentBody;
  writeFileSync(fake.state, JSON.stringify(state));
  const priorFetch = globalThis.fetch;
  const requests: Array<{ body: string; url: URL }> = [];
  let reads = 0;
  const currentOperationId = "1".repeat(32);
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (init?.method !== "PUT") {
      reads += 1;
      if (reads > 1) return new Response("current release is broken", { status: 503 });
      return new Response(
        JSON.stringify({
          contract: 1,
          version: 2,
          generation: 2,
          source: "durable",
          bundle: JSON.parse(currentBody),
          contentHash: currentHash,
          runtimeContentHash: currentHash,
          operationId: currentOperationId,
          status: "applied",
        }),
        { status: 200 },
      );
    }
    const body = String(init.body ?? "");
    requests.push({ body, url });
    const restoring = body === currentBody;
    const operationId = url.searchParams.get("operationId");
    return new Response(
      JSON.stringify({
        ok: true,
        version: restoring ? 4 : 3,
        contentHash: restoring ? currentHash : oldHash,
        operationId,
        changed: true,
        durable: true,
        status: restoring ? "applied" : "degraded",
        ...(restoring ? {} : { message: "projection failed" }),
      }),
      { status: restoring ? 200 : 202 },
    );
  }) as typeof fetch;
  try {
    await assert.rejects(
      awsRollback(single, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY }),
      /deployment layer was not durably applied/,
    );
    assert.equal(reads, 1);
    const forwards = requests.filter((request) => request.body === oldBody);
    const restores = requests.filter((request) => request.body === currentBody);
    assert.ok(forwards.length >= 1);
    assert.equal(restores.length, 1);
    assert.equal(new Set(forwards.map((request) => request.url.searchParams.get("operationId"))).size, 1);
    const forwardOperationId = forwards[0]!.url.searchParams.get("operationId");
    assert.match(forwardOperationId ?? "", /^[a-f0-9]{32}$/);
    assert.equal(restores[0]!.url.searchParams.get("generation"), "3");
    assert.equal(restores[0]!.url.searchParams.get("contentHash"), oldHash);
    assert.equal(restores[0]!.url.searchParams.get("currentOperationId"), forwardOperationId);
    assert.notEqual(restores[0]!.url.searchParams.get("operationId"), forwardOperationId);
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(after.dynamo["deployment/current"].manifestId.S, "current");
    assert.equal(
      after.services["acme-core"].taskDefinition,
      "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1",
    );
  } finally {
    globalThis.fetch = priorFetch;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rollback reuses one deployment-layer operation ID across forward retries", async (t) => {
  const priorDeadline = process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS;
  const priorPoll = process.env.QM_AWS_LIVE_PROBE_POLL_MS;
  process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS = "1000";
  process.env.QM_AWS_LIVE_PROBE_POLL_MS = "1";
  t.after(() => {
    if (priorDeadline === undefined) delete process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS;
    else process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS = priorDeadline;
    if (priorPoll === undefined) delete process.env.QM_AWS_LIVE_PROBE_POLL_MS;
    else process.env.QM_AWS_LIVE_PROBE_POLL_MS = priorPoll;
  });
  for (const scenario of ["degraded", "lost-response"] as const) {
    await t.test(scenario, async () => {
      const dir = mkdtempSync(join(tmpdir(), `qm-aws-rollback-layer-${scenario}-`));
      const { single, fake, oldBody, currentBody, oldHash, currentHash } = awsRollbackLayerFixture(dir);
      const priorFetch = globalThis.fetch;
      const operationIds: Array<string | null> = [];
      let attempts = 0;
      globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (init?.method !== "PUT") {
          return new Response(durableLayerStateBody(currentBody, currentHash), { status: 200 });
        }
        assert.equal(String(init.body ?? ""), oldBody);
        const operationId = url.searchParams.get("operationId");
        operationIds.push(operationId);
        attempts += 1;
        if (attempts === 1) {
          if (scenario === "degraded") return layerMutationResponse(3, oldHash, operationId, "degraded");
          throw new Error("deployment-layer response lost after persistence");
        }
        return layerMutationResponse(3, oldHash, operationId);
      }) as typeof fetch;
      try {
        await awsRollback(single, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY });
        assert.equal(attempts, 2);
        assert.equal(new Set(operationIds).size, 1);
        assert.match(operationIds[0] ?? "", /^[a-f0-9]{32}$/);
        assert.equal(JSON.parse(readFileSync(fake.state, "utf8")).dynamo["deployment/current"].manifestId.S, "old");
      } finally {
        globalThis.fetch = priorFetch;
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS rollback retries ambiguous layer discovery and restores only its lost-response operation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-layer-ambiguous-"));
  const { single, fake, oldBody, currentBody, oldHash, currentHash } = awsRollbackLayerFixture(dir);
  const priorFetch = globalThis.fetch;
  const forwardOperationIds: Array<string | null> = [];
  const restores: URL[] = [];
  let reads = 0;
  const priorDeadline = process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS;
  const priorPoll = process.env.QM_AWS_LIVE_PROBE_POLL_MS;
  process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS = "500";
  process.env.QM_AWS_LIVE_PROBE_POLL_MS = "1";
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const body = String(init?.body ?? "");
    if (init?.method !== "PUT") {
      reads += 1;
      if (reads === 1) return new Response(durableLayerStateBody(currentBody, currentHash), { status: 200 });
      if (reads === 2) throw new Error("transient compensation read failure");
      const operationId = forwardOperationIds[0];
      return new Response(durableLayerStateBody(oldBody, oldHash, 3, operationId), { status: 200 });
    }
    if (body === oldBody) {
      forwardOperationIds.push(url.searchParams.get("operationId"));
      await new Promise((resolve) => setTimeout(resolve, 600));
      throw new Error("deployment-layer response lost after persistence");
    }
    assert.equal(body, currentBody);
    restores.push(url);
    return layerMutationResponse(4, currentHash, url.searchParams.get("operationId"));
  }) as typeof fetch;
  try {
    await assert.rejects(
      awsRollback(single, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY }),
      /deployment-layer response lost after persistence/,
    );
    assert.ok(forwardOperationIds.length >= 1);
    assert.equal(new Set(forwardOperationIds).size, 1);
    assert.equal(reads, 3);
    assert.equal(restores.length, 1);
    assert.equal(restores[0]!.searchParams.get("generation"), "3");
    assert.equal(restores[0]!.searchParams.get("contentHash"), oldHash);
    assert.equal(restores[0]!.searchParams.get("currentOperationId"), forwardOperationIds[0]);
    assert.notEqual(restores[0]!.searchParams.get("operationId"), forwardOperationIds[0]);
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(after.dynamo["deployment/current"].manifestId.S, "current");
    assert.equal(
      after.services["acme-core"].taskDefinition,
      "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1",
    );
  } finally {
    if (priorDeadline === undefined) delete process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS;
    else process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS = priorDeadline;
    if (priorPoll === undefined) delete process.env.QM_AWS_LIVE_PROBE_POLL_MS;
    else process.env.QM_AWS_LIVE_PROBE_POLL_MS = priorPoll;
    globalThis.fetch = priorFetch;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rollback refuses to compensate across an identical-hash ABA writer", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-layer-aba-"));
  const { single, fake, oldBody, currentBody, oldHash, currentHash } = awsRollbackLayerFixture(dir);
  const priorFetch = globalThis.fetch;
  const forwardUrls: URL[] = [];
  const restoreUrls: URL[] = [];
  let reads = 0;
  const priorDeadline = process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS;
  const priorPoll = process.env.QM_AWS_LIVE_PROBE_POLL_MS;
  process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS = "200";
  process.env.QM_AWS_LIVE_PROBE_POLL_MS = "1";
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const body = String(init?.body ?? "");
    if (init?.method !== "PUT") {
      reads += 1;
      return new Response(durableLayerStateBody(currentBody, currentHash), { status: 200 });
    }
    if (body === oldBody) {
      forwardUrls.push(url);
      if (forwardUrls.length === 1) {
        return layerMutationResponse(3, oldHash, url.searchParams.get("operationId"), "degraded");
      }
    } else {
      assert.equal(body, currentBody);
      restoreUrls.push(url);
    }
    return new Response(JSON.stringify({ error: "deployment_layer_conflict" }), { status: 409 });
  }) as typeof fetch;
  try {
    await assert.rejects(
      awsRollback(single, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY }),
      /compensation also failed.*deployment layer sync failed \(409\)/,
    );
    assert.equal(reads, 1);
    assert.ok(forwardUrls.length >= 2);
    assert.ok(restoreUrls.length >= 1);
    const forwardOperationId = forwardUrls[0]!.searchParams.get("operationId");
    assert.equal(new Set(forwardUrls.map((url) => url.searchParams.get("operationId"))).size, 1);
    for (const url of restoreUrls) {
      assert.equal(url.searchParams.get("generation"), "3");
      assert.equal(url.searchParams.get("contentHash"), oldHash);
      assert.equal(url.searchParams.get("currentOperationId"), forwardOperationId);
    }
    assert.equal(new Set(restoreUrls.map((url) => url.searchParams.get("operationId"))).size, 1);
    assert.notEqual(restoreUrls[0]!.searchParams.get("operationId"), forwardOperationId);
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(after.dynamo["deployment/current"].manifestId.S, "current");
    assert.equal(
      after.services["acme-core"].taskDefinition,
      "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1",
    );
  } finally {
    if (priorDeadline === undefined) delete process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS;
    else process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS = priorDeadline;
    if (priorPoll === undefined) delete process.env.QM_AWS_LIVE_PROBE_POLL_MS;
    else process.env.QM_AWS_LIVE_PROBE_POLL_MS = priorPoll;
    globalThis.fetch = priorFetch;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rollback clears an acknowledged version-zero layer mutation without synthesizing a bundle", async (t) => {
  for (const source of ["none", "filesystem"] as const) {
    await t.test(source, async () => {
      const dir = mkdtempSync(join(tmpdir(), `qm-aws-rollback-layer-${source}-`));
      const { single, fake, oldBody, currentBody, oldHash } = awsRollbackLayerFixture(dir);
      const priorFetch = globalThis.fetch;
      const forwardUrls: URL[] = [];
      const clears: Array<{ body: string; url: URL }> = [];
      let reads = 0;
      globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        const body = String(init?.body ?? "");
        if (init?.method === "DELETE") {
          clears.push({ body, url });
          return layerMutationResponse(2, oldHash, url.searchParams.get("operationId"));
        }
        if (init?.method === "PUT") {
          assert.equal(body, oldBody);
          forwardUrls.push(url);
          if (forwardUrls.length === 1) {
            return layerMutationResponse(1, oldHash, url.searchParams.get("operationId"), "degraded");
          }
          return new Response(JSON.stringify({ error: "deployment_layer_conflict" }), { status: 409 });
        }
        reads += 1;
        return new Response(
          JSON.stringify({ contract: 1, version: 0, generation: 0, source, contentHash: null, operationId: null }),
          { status: 200 },
        );
      }) as typeof fetch;
      try {
        await assert.rejects(
          awsRollback(single, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY }),
          /deployment layer was not durably applied/,
        );
        assert.equal(reads, 1);
        assert.ok(forwardUrls.length >= 1);
        assert.equal(clears.length, 1);
        const forwardOperationId = forwardUrls[0]!.searchParams.get("operationId");
        assert.equal(clears[0]!.body, "");
        assert.equal(clears[0]!.url.searchParams.get("generation"), "1");
        assert.equal(clears[0]!.url.searchParams.get("source"), "durable");
        assert.equal(clears[0]!.url.searchParams.get("contentHash"), oldHash);
        assert.equal(clears[0]!.url.searchParams.get("currentOperationId"), forwardOperationId);
        assert.notEqual(clears[0]!.url.searchParams.get("operationId"), forwardOperationId);
        assert.notEqual(oldBody, currentBody);
        const after = JSON.parse(readFileSync(fake.state, "utf8"));
        assert.equal(after.dynamo["deployment/current"].manifestId.S, "current");
      } finally {
        globalThis.fetch = priorFetch;
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS rollback treats a pre-mutation layer timeout as already restored", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-layer-timeout-before-mutation-"));
  const { single, fake, oldBody } = awsRollbackLayerFixture(dir);
  const priorFetch = globalThis.fetch;
  const priorDeadline = process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS;
  const priorPoll = process.env.QM_AWS_LIVE_PROBE_POLL_MS;
  process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS = "300";
  process.env.QM_AWS_LIVE_PROBE_POLL_MS = "1";
  let reads = 0;
  let puts = 0;
  let deletes = 0;
  globalThis.fetch = (async (_input: string | URL | Request, init?: RequestInit) => {
    if (init?.method === "DELETE") {
      deletes += 1;
      throw new Error("clear must not run");
    }
    if (init?.method === "PUT") {
      puts += 1;
      assert.equal(String(init.body ?? ""), oldBody);
      await new Promise((resolve) => setTimeout(resolve, 400));
      throw new Error("deployment-layer request timed out before mutation");
    }
    reads += 1;
    return new Response(
      JSON.stringify({ contract: 1, version: 0, generation: 0, source: "none", contentHash: null, operationId: null }),
      { status: 200 },
    );
  }) as typeof fetch;
  try {
    await assert.rejects(
      awsRollback(single, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY }),
      /request timed out before mutation/,
    );
    assert.equal(reads, 2);
    assert.equal(puts, 1);
    assert.equal(deletes, 0);
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(after.dynamo["deployment/current"].manifestId.S, "current");
  } finally {
    if (priorDeadline === undefined) delete process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS;
    else process.env.QM_AWS_LIVE_PROBE_DEADLINE_MS = priorDeadline;
    if (priorPoll === undefined) delete process.env.QM_AWS_LIVE_PROBE_POLL_MS;
    else process.env.QM_AWS_LIVE_PROBE_POLL_MS = priorPoll;
    globalThis.fetch = priorFetch;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rollback of a scaled-to-zero stack defers the layer sync instead of failing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-down-"));
  const single = oneServiceConfig();
  const oldBody = JSON.stringify({ contract: 1, tools: [], skills: [{ path: "skills/old/SKILL.md", content: "old" }] });
  const currentBody = JSON.stringify({ contract: 1, tools: [], skills: [] });
  const artifact = (id: string, body: string) => ({
    key: `deployment/layers/${id}.json`,
    sha256: createHash("sha256").update(body).digest("hex"),
  });
  const fake = statefulAws(
    dir,
    single,
    manifestItems(
      [
        {
          id: "old",
          tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1" },
          layer: artifact("old", oldBody),
        },
        {
          id: "current",
          previous: "old",
          tasks: { core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:2" },
          layer: artifact("current", currentBody),
        },
      ],
      "current",
    ),
  );
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.services["acme-core"].desiredCount = 0;
  state.services["acme-core"].taskDefinition = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:2";
  state.objects[artifact("old", oldBody).key] = oldBody;
  state.objects[artifact("current", currentBody).key] = currentBody;
  writeFileSync(fake.state, JSON.stringify(state));
  const priorFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    throw new Error("no core is running; the layer sync must be deferred");
  }) as typeof fetch;
  try {
    await awsRollback(single, undefined, { configDir: dir, configIdentity: TEST_CONFIG_IDENTITY });
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(after.dynamo["deployment/current"].manifestId.S, "old");
    assert.equal(
      after.services["acme-core"].taskDefinition,
      "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1",
    );
    assert.equal(after.services["acme-core"].desiredCount, 0);
  } finally {
    globalThis.fetch = priorFetch;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rollback refuses an incomplete manifest before mutating ECS", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-rollback-incomplete-"));
  const multi = twoServiceConfig();
  const fake = statefulAws(
    dir,
    multi,
    manifestItems(
      [
        { id: "old", tasks: { core: "core:1" } },
        { id: "current", previous: "old", tasks: { core: "core:2", "web-ui": "web:2" } },
      ],
      "current",
    ),
  );
  try {
    await assert.rejects(() => awsRollback(multi), /missing workloads: web-ui/);
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /ecs update-service/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secrets push never creates secret containers outside Terraform", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-push-"));
  const secretsConfig: QmConfig = { ...oneServiceConfig(), env: {} };
  const adversarialConfig: QmConfig = {
    ...secretsConfig,
    aws: { ...secretsConfig.aws!, secretsPrefix: "ResourceNotFoundException/" },
  };
  const operator = computedSecrets(secretsConfig).filter(
    (secret) => secret.managedBy === "operator" && secret.required,
  );
  writeFileSync(
    join(dir, ".env"),
    operator.map((secret) => `${secret.name}=${selectedTestSecretValue(secret.name)}`).join("\n"),
  );
  const denied = fakeAws(
    dir,
    `
const args = process.argv.slice(2);
const secretId = args[args.indexOf("--secret-id") + 1];
if (a.includes("secretsmanager describe-secret")) console.log(JSON.stringify({ ARN: "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + secretId + "-AbCdEf" }));
else if (a.includes("secretsmanager get-secret-value") && a.includes("DATABASE_URL")) console.log(JSON.stringify({ ARN: "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + secretId + "-AbCdEf", SecretString: "postgres://database.example/qm" }));
else if (a.includes("secretsmanager get-secret-value")) console.log("{}");
else if (a.includes("dynamodb get-item")) console.log("{}");
else if (a.includes("ecs describe-services")) console.log(JSON.stringify({ services: [{ serviceName: "acme-core", desiredCount: 0, runningCount: 0, tags: [{ key: "Deployment", value: "acme" }, { key: "ManagedBy", value: "terraform" }] }], failures: [] }));
else if (a.includes("put-secret-value")) { console.error("An error occurred (AccessDeniedException) when calling the PutSecretValue operation"); process.exit(1); }
console.log("");`,
  );
  try {
    await assert.rejects(() => awsSecretsPush(adversarialConfig, dir, testSecretValues(dir)), /AccessDeniedException/);
    assert.ok(
      !readFileSync(denied.log, "utf8").includes("create-secret"),
      "a non-missing error must not be masked by create-secret",
    );
  } finally {
    denied.restore();
  }
  const missing = fakeAws(
    dir,
    `
const args = process.argv.slice(2);
const secretId = args[args.indexOf("--secret-id") + 1];
if (a.includes("secretsmanager describe-secret") && secretId.endsWith("/SPRITES_TOKEN")) { console.error("An error occurred (ResourceNotFoundException) when calling the DescribeSecret operation"); process.exit(1); }
else if (a.includes("secretsmanager describe-secret")) console.log(JSON.stringify({ ARN: "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + secretId + "-AbCdEf" }));
else if (a.includes("secretsmanager get-secret-value") && a.includes("DATABASE_URL")) console.log(JSON.stringify({ ARN: "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + secretId + "-AbCdEf", SecretString: "postgres://database.example/qm" }));
else if (a.includes("secretsmanager get-secret-value")) console.log("{}");
else if (a.includes("dynamodb get-item")) console.log("{}");
else if (a.includes("ecs describe-services")) console.log(JSON.stringify({ services: [{ serviceName: "acme-core", desiredCount: 0, runningCount: 0, tags: [{ key: "Deployment", value: "acme" }, { key: "ManagedBy", value: "terraform" }] }], failures: [] }));
else if (a.includes("put-secret-value")) console.log("");
console.log("");`,
  );
  try {
    await assert.rejects(
      () => awsSecretsPush(secretsConfig, dir, testSecretValues(dir)),
      /apply the rendered Terraform before pushing secrets/,
    );
    const calls = readFileSync(missing.log, "utf8");
    assert.ok((calls.match(/secretsmanager describe-secret/g)?.length ?? 0) > 1);
    assert.doesNotMatch(calls, /put-secret-value|create-secret/);
  } finally {
    missing.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("aws logs never reinterprets --tail and interleaves all workloads instead of blocking", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-logs-"));
  const fake = fakeAws(dir, `console.log("line-from-" + process.argv[4]);`);
  const lines: string[] = [];
  const log = console.log;
  console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
  try {
    awsLogs(oneServiceConfig(), "core", { follow: false, tail: 7 });
    const calls = readFileSync(fake.log, "utf8");
    assert.ok(!calls.includes("--since"), "--tail must not silently become --since");
    assert.ok(
      lines.join("\n").includes("--tail is a docker-only line count"),
      "explicit notice instead of reinterpretation",
    );
    const twoServices = twoServiceConfig();
    await awsLogs(twoServices, undefined, { follow: false });
    const out = lines.join("\n").replace(/\x1b\[[0-9;]*m/g, "");
    assert.match(out, /core\s*\| line-from-/);
    assert.match(out, /web-ui\s*\| line-from-/);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS virtual Slack logs resolve to the core task", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-slack-logs-"));
  const fake = fakeAws(dir, `console.log("");`);
  try {
    awsLogs(oneServiceConfig(), "slack", {});
    assert.match(readFileSync(fake.log, "utf8"), /logs tail \/ecs\/acme-core/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS status batches DescribeServices at the API limit and surfaces failures", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-status-batches-"));
  const services = Object.fromEntries(
    Array.from({ length: 11 }, (_, index) => {
      const name = index === 0 ? "core" : `plugin-${index}`;
      return [name, { ...config.aws!.services.core!, ecsService: `svc-${index}`, ecrRepository: `repo-${index}` }];
    }),
  );
  const many: QmConfig = {
    ...config,
    services: ["core"],
    plugins: Array.from({ length: 10 }, (_, index) => ({
      name: `plugin-${index + 1}`,
      image: `ghcr.io/acme/plugin-${index + 1}:1`,
    })),
    aws: { ...config.aws!, services },
  };
  const fake = statefulAws(dir, many);
  try {
    awsStatus(many);
    const calls = readFileSync(fake.log, "utf8")
      .split("\n")
      .filter((line) => line.includes("ecs describe-services"));
    assert.equal(calls.length, 2);
    assert.ok(
      calls.every((line) => line.split(" --services ")[1]!.split(" --output ")[0]!.trim().split(/\s+/).length <= 10),
    );
  } finally {
    fake.restore();
  }
  const failed = fakeAws(
    dir,
    `if (a.includes("describe-services")) console.log(JSON.stringify({ failures: [{ arn: "svc", reason: "MISSING" }] })); else console.log("");`,
  );
  try {
    assert.throws(() => awsStatus(oneServiceConfig()), /MISSING/);
  } finally {
    failed.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS down holds the deploy lease across the ECS mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-down-lease-"));
  const fake = statefulAws(dir, oneServiceConfig());
  try {
    await awsDown(oneServiceConfig());
    const calls = readFileSync(fake.log, "utf8");
    const update = calls.indexOf("ecs update-service");
    assert.ok(calls.indexOf("dynamodb put-item") >= 0);
    assert.ok(calls.indexOf("dynamodb put-item") < update);
    const rolloutPoll = calls.indexOf("ecs describe-services", update);
    assert.ok(update < rolloutPoll && rolloutPoll < calls.indexOf("dynamodb delete-item"));
  } finally {
    fake.restore();
  }
  const rolledBack = statefulAws(dir, oneServiceConfig(), {}, { ignoreUpdate: true });
  try {
    await assert.rejects(() => awsDown(oneServiceConfig()), /did not reach the requested state/);
  } finally {
    rolledBack.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS lease acquisition surfaces a held lease and skips release", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-held-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb put-item")) { console.error("An error occurred (ConditionalCheckFailedException) when calling the PutItem operation"); process.exit(1); }
console.log("");`,
  );
  try {
    await assert.rejects(
      withAwsLease(config.aws!, async () => {}),
      /another QM operation holds the "deploy" lease in acme-qm-deploy-locks/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /dynamodb delete-item/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ambiguous AWS lease acquisition cleanup is holder-conditioned and ignores exception tokens in arguments", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-argv-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb put-item")) { console.error("AccessDeniedException"); process.exit(1); }
console.log("");`,
  );
  const aws = { ...config.aws!, cluster: "ConditionalCheckFailedException" };
  try {
    await assert.rejects(
      withAwsLease(aws, async () => {}),
      /AccessDeniedException/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /dynamodb delete-item/);
    assert.match(calls, /--condition-expression holder = :holder/);
    const put = calls.split("\n").find((line) => line.includes("dynamodb put-item"))!;
    const cleanup = calls.split("\n").find((line) => line.includes("dynamodb delete-item"))!;
    const putHolder = JSON.parse(put.match(/--item (.+) --condition-expression/)![1]!).holder.S;
    const cleanupHolder = JSON.parse(cleanup.match(/--expression-attribute-values (.+) --region/)![1]!)[":holder"].S;
    assert.equal(cleanupHolder, putHolder);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS lease release failures surface after success and alongside primary failures", async (t) => {
  for (const primary of [false, true]) {
    await t.test(primary ? "primary and release fail" : "release fails", async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-release-"));
      const fake = fakeAws(
        dir,
        `
if (a.includes("dynamodb put-item")) console.log("");
else if (a.includes("dynamodb delete-item")) { console.error("DeleteLeaseFailure"); process.exit(1); }
else console.log("");`,
      );
      try {
        await assert.rejects(
          withAwsLease(config.aws!, async () => {
            if (primary) throw new Error("primary operation failure");
          }),
          primary
            ? /primary operation failure; the AWS deployment lease could not be released/
            : /could not release the AWS deployment lease/,
        );
        assert.match(readFileSync(fake.log, "utf8"), /dynamodb delete-item/);
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("a standalone AWS lease wrapper exits only after its conditioned release", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-standalone-release-"));
  const fake = fakeAws(dir, `console.log("");`);
  const moduleUrl = new URL("../src/aws-lease.ts", import.meta.url).href;
  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `import { withAwsLease } from ${JSON.stringify(moduleUrl)}; await withAwsLease(${JSON.stringify(config.aws!)}, async () => {}); process.stdout.write("DONE\\n");`,
    ],
    { env: process.env, encoding: "utf8" },
  );
  try {
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "DONE\n");
    assert.match(readFileSync(fake.log, "utf8"), /dynamodb delete-item .*--condition-expression holder = :holder/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS lease signal cleanup reports a failed conditioned release before exiting", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-signal-release-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb put-item")) console.log("");
else if (a.includes("dynamodb delete-item")) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 700);
  console.error("DeleteLeaseFailure");
  process.exit(1);
}
else console.log("");`,
  );
  const moduleUrl = new URL("../src/aws-lease.ts", import.meta.url).href;
  const script = `
import { withAwsLease } from ${JSON.stringify(moduleUrl)};
await withAwsLease(${JSON.stringify(config.aws!)}, async () => process.stdout.write("READY\\n")).catch(() => {});
setInterval(() => {}, 1000);
`;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", script], {
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => (stdout += chunk));
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  let readyTimeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      new Promise<void>((resolve) => {
        child.stdout.on("data", () => {
          if (stdout.includes("READY")) resolve();
        });
      }),
      new Promise<never>((_resolve, reject) => {
        readyTimeout = setTimeout(() => reject(new Error(`lease signal child did not become ready: ${stderr}`)), 5_000);
      }),
    ]);
    if (readyTimeout) clearTimeout(readyTimeout);
    for (
      let attempt = 0;
      attempt < 500 && !readFileSync(fake.log, "utf8").includes("dynamodb delete-item");
      attempt++
    ) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.match(readFileSync(fake.log, "utf8"), /dynamodb delete-item/);
    const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
    child.kill("SIGTERM");
    const [code, signal] = await exited;
    assert.equal(code, 130, JSON.stringify({ signal, stdout, stderr }));
    assert.match(stderr, /could not release the AWS deployment lease/);
  } finally {
    if (readyTimeout) clearTimeout(readyTimeout);
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an AWS signal during lease acquisition still performs conditioned cleanup", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-signal-acquire-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb put-item")) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 700);
console.log("");`,
  );
  const moduleUrl = new URL("../src/aws-lease.ts", import.meta.url).href;
  const script = `
import { setTimeout as wait } from "node:timers/promises";
import { withAwsLease } from ${JSON.stringify(moduleUrl)};
await withAwsLease(${JSON.stringify(config.aws!)}, async () => wait(1000)).catch(() => {});
setInterval(() => {}, 1000);
`;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", script], {
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  try {
    for (let attempt = 0; attempt < 500 && !readFileSync(fake.log, "utf8").includes("dynamodb put-item"); attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.match(readFileSync(fake.log, "utf8"), /dynamodb put-item/);
    const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
    child.kill("SIGTERM");
    const [code] = await exited;
    assert.equal(code, 130, stderr);
    assert.match(readFileSync(fake.log, "utf8"), /dynamodb delete-item .*--condition-expression holder = :holder/);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an AWS signal queued during a failed conditional acquisition exits before work resumes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-signal-failed-acquire-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb put-item")) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 700);
  console.error("An error occurred (ConditionalCheckFailedException) when calling the PutItem operation");
  process.exit(1);
}
console.log("");`,
  );
  const moduleUrl = new URL("../src/aws-lease.ts", import.meta.url).href;
  const script = `
import { withAwsLease } from ${JSON.stringify(moduleUrl)};
await withAwsLease(${JSON.stringify(config.aws!)}, async () => process.stdout.write("STARTED\\n")).catch(() => process.stdout.write("CAUGHT\\n"));
setInterval(() => {}, 1000);
`;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", script], {
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => (stdout += chunk));
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  try {
    for (let attempt = 0; attempt < 500 && !readFileSync(fake.log, "utf8").includes("dynamodb put-item"); attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.match(readFileSync(fake.log, "utf8"), /dynamodb put-item/);
    const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
    child.kill("SIGTERM");
    const [code] = await exited;
    assert.equal(code, 130, JSON.stringify({ stdout, stderr }));
    assert.doesNotMatch(stdout, /STARTED|CAUGHT/);
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /dynamodb delete-item/);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an AWS signal during renewer shutdown waits for the conditioned release", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-signal-join-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb update-item")) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500);
console.log("");`,
  );
  const moduleUrl = new URL("../src/aws-lease.ts", import.meta.url).href;
  const script = `
import { readFileSync } from "node:fs";
import { withAwsLease } from ${JSON.stringify(moduleUrl)};
await withAwsLease(${JSON.stringify(config.aws!)}, async () => {
  process.stdout.write("READY\\n");
  while (!readFileSync(${JSON.stringify(fake.log)}, "utf8").includes("dynamodb update-item")) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  process.stdout.write("RELEASING\\n");
});
process.stdout.write("DONE\\n");
`;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", script], {
    env: { ...process.env, QM_AWS_LEASE_RENEW_MS: "5" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => (stdout += chunk));
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  let releaseTimeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      new Promise<void>((resolve) => {
        child.stdout.on("data", () => {
          if (stdout.includes("RELEASING")) resolve();
        });
      }),
      new Promise<never>((_resolve, reject) => {
        releaseTimeout = setTimeout(
          () => reject(new Error(`lease release child did not start release: ${stderr}`)),
          5_000,
        );
      }),
    ]);
    if (releaseTimeout) clearTimeout(releaseTimeout);
    const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
    child.kill("SIGTERM");
    const [code] = await exited;
    assert.equal(code, 130, stderr);
    assert.match(readFileSync(fake.log, "utf8"), /dynamodb delete-item .*--condition-expression holder = :holder/);
  } finally {
    if (releaseTimeout) clearTimeout(releaseTimeout);
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an AWS signal drains an in-flight HTTP boundary before conditioned release", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-signal-http-"));
  const fake = fakeAws(dir, `console.log("");`);
  const inFlight = join(dir, "http-in-flight");
  const resolveRequest = join(dir, "resolve-http");
  const resumed = join(dir, "resumed-after-http");
  writeFileSync(join(dir, ".env"), `CORE_SIGNING_SECRET=${TEST_SECRET_VALUE}\n`);
  const leaseModuleUrl = new URL("../src/aws-lease.ts", import.meta.url).href;
  const awsModuleUrl = new URL("../src/backends/aws.ts", import.meta.url).href;
  const script = `
import { existsSync, writeFileSync } from "node:fs";
import { setTimeout as wait } from "node:timers/promises";
import { awsDeploymentLayerTransport } from ${JSON.stringify(awsModuleUrl)};
import { withAwsLease } from ${JSON.stringify(leaseModuleUrl)};
globalThis.fetch = async () => {
  writeFileSync(${JSON.stringify(inFlight)}, "started");
  while (!existsSync(${JSON.stringify(resolveRequest)})) await wait(10);
  return new Response("{}");
};
await withAwsLease(${JSON.stringify(config.aws!)}, async () => {
  await awsDeploymentLayerTransport({ config: ${JSON.stringify(config)}, configDir: ${JSON.stringify(dir)}, method: "PUT", body: "{}" });
  writeFileSync(${JSON.stringify(resumed)}, "ran");
}).catch(() => {});
setInterval(() => {}, 1000);
`;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", script], {
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  try {
    for (let attempt = 0; attempt < 500 && !existsSync(inFlight); attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(existsSync(inFlight), true, stderr);
    const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
    child.kill("SIGTERM");
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /dynamodb delete-item/);
    writeFileSync(resolveRequest, "resolve");
    const [code] = await exited;
    assert.equal(code, 130, stderr);
    assert.equal(existsSync(resumed), false);
    assert.match(readFileSync(fake.log, "utf8"), /dynamodb delete-item .*--condition-expression holder = :holder/);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an AWS signal marks the lease stopping before a blocked renewal lets work resume", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-signal-stop-"));
  const fake = fakeAws(
    dir,
    `
if (a.includes("dynamodb update-item")) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500);
console.log("");`,
  );
  const marker = join(dir, "resumed-after-signal");
  const moduleUrl = new URL("../src/aws-lease.ts", import.meta.url).href;
  const script = `
import { readFileSync } from "node:fs";
import { awsRunInherit, withAwsLease } from ${JSON.stringify(moduleUrl)};
await withAwsLease(${JSON.stringify(config.aws!)}, async () => {
  process.stdout.write("READY\\n");
  while (!readFileSync(${JSON.stringify(fake.log)}, "utf8").includes("dynamodb update-item")) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  await new Promise((resolve) => setTimeout(resolve, 250));
  awsRunInherit(process.execPath, ["-e", ${JSON.stringify(`require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ran")`)}]);
}).catch(() => {});
setInterval(() => {}, 1000);
`;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", script], {
    env: { ...process.env, QM_AWS_LEASE_RENEW_MS: "5" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => (stdout += chunk));
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  try {
    for (
      let attempt = 0;
      attempt < 500 && !readFileSync(fake.log, "utf8").includes("dynamodb update-item");
      attempt++
    ) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.match(stdout, /READY/);
    assert.match(readFileSync(fake.log, "utf8"), /dynamodb update-item/);
    const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
    child.kill("SIGTERM");
    const [code] = await exited;
    assert.equal(code, 130, stderr);
    assert.equal(existsSync(marker), false);
    assert.match(readFileSync(fake.log, "utf8"), /dynamodb delete-item/);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an AWS signal during a provider child blocks the next mutation and successful return", async (t) => {
  for (const first of ["awsText", "awsTextAsync"] as const) {
    await t.test(
      first === "awsText" ? "queued before the async mutation" : "delivered after the async mutation",
      async () => {
        const dir = mkdtempSync(join(tmpdir(), "qm-aws-lease-signal-sync-child-"));
        const fake = fakeAws(
          dir,
          `
if (a.includes("probe-first")) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 700);
console.log("");`,
        );
        const moduleUrl = new URL("../src/aws-lease.ts", import.meta.url).href;
        const script = `
import { awsText, awsTextAsync, withAwsLease } from ${JSON.stringify(moduleUrl)};
await withAwsLease(${JSON.stringify(config.aws!)}, async () => {
  ${first === "awsText" ? "awsText" : "await awsTextAsync"}(${JSON.stringify(config.aws!)}, ["probe-first"]);
  await awsTextAsync(${JSON.stringify(config.aws!)}, ["probe-second"]);
  process.stdout.write("DONE\\n");
}).catch(() => {});
setInterval(() => {}, 1000);
`;
        const child = spawn(process.execPath, ["--input-type=module", "--eval", script], {
          env: process.env,
          stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", (chunk: string) => (stdout += chunk));
        child.stderr.on("data", (chunk: string) => (stderr += chunk));
        try {
          for (let attempt = 0; attempt < 500 && !readFileSync(fake.log, "utf8").includes("probe-first"); attempt++) {
            await new Promise((resolve) => setTimeout(resolve, 10));
          }
          assert.match(readFileSync(fake.log, "utf8"), /probe-first/);
          const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
          child.kill("SIGTERM");
          const [code] = await exited;
          assert.equal(code, 130, stderr);
          assert.doesNotMatch(readFileSync(fake.log, "utf8"), /probe-second/);
          assert.doesNotMatch(stdout, /DONE/);
          assert.match(
            readFileSync(fake.log, "utf8"),
            /dynamodb delete-item .*--condition-expression holder = :holder/,
          );
        } finally {
          if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
          fake.restore();
          rmSync(dir, { recursive: true, force: true });
        }
      },
    );
  }
});

test("AWS live check rejects downed services and classifies probe errors as live drift", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-live-runtime-"));
  const single = oneServiceConfig();
  const taskArn = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1";
  const fake = statefulAws(dir, single, manifestItems([{ id: "current", tasks: { core: taskArn } }], "current"));
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  state.services["acme-core"].desiredCount = 0;
  writeFileSync(fake.state, JSON.stringify(state));
  try {
    await assert.rejects(
      () => awsCheckLive(single),
      (error: unknown) =>
        error instanceof Error &&
        /0\/0 running/.test(error.message) &&
        (error as { clause?: string }).clause === "aws.live-drift",
    );
  } finally {
    fake.restore();
  }
  const denied = fakeAws(
    dir,
    `if (a.includes("get-secret-value")) { console.error("AccessDeniedException"); process.exit(1); } console.log("");`,
  );
  try {
    await assert.rejects(
      () => awsCheckLive(single),
      (error: unknown) =>
        error instanceof Error &&
        /AccessDeniedException/.test(error.message) &&
        (error as { clause?: string }).clause === "aws.live-drift",
    );
  } finally {
    denied.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS Sprites live check evaluates publisher image readiness and core health", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-live-sprites-"));
  const base = oneServiceConfig();
  const single: QmConfig = {
    ...base,
    sandbox: { backend: "sprites", namePrefix: "acme-sandboxes" },
    env: { ...base.env, core: { ...base.env.core, HARNESS: "pi" } },
  };
  assert.equal(serviceEnvironment(single, "core").AWS_DEPLOY_IMAGE, "acme-qm-sandbox");
  const taskArn = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1";
  const fake = statefulAws(
    dir,
    single,
    manifestItems([{ id: "current", imageLabel: "release", tasks: { core: taskArn } }], "current"),
    { primaryFailedTasks: true },
  );
  try {
    await assert.rejects(
      () => awsCheckLive(single, { report: false }),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /core: configured task is not the sole healthy PRIMARY deployment/);
        return true;
      },
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS live check rejects an ingress target group without a healthy target", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-live-health-"));
  const single = oneServiceConfig();
  const taskArn = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1";
  const fake = statefulAws(dir, single, manifestItems([{ id: "current", tasks: { core: taskArn } }], "current"));
  const prior = process.env.AWS_FAKE_UNHEALTHY_TARGET;
  process.env.AWS_FAKE_UNHEALTHY_TARGET = "1";
  try {
    await assert.rejects(
      () => awsCheckLive(single),
      (error: unknown) =>
        error instanceof Error &&
        /core target group has no healthy targets/.test(error.message) &&
        (error as { clause?: string }).clause === "aws.live-drift",
    );
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_UNHEALTHY_TARGET;
    else process.env.AWS_FAKE_UNHEALTHY_TARGET = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS live check rejects a reachable public URL returning a server error", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-live-http-"));
  const single = oneServiceConfig();
  const taskArn = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1";
  const fake = statefulAws(dir, single, manifestItems([{ id: "current", tasks: { core: taskArn } }], "current"));
  const prior = process.env.AWS_FAKE_HTTP_STATUS;
  process.env.AWS_FAKE_HTTP_STATUS = "503";
  try {
    await assert.rejects(
      () => awsCheckLive(single),
      (error: unknown) =>
        error instanceof Error &&
        /public network drift:.*HTTP 503/.test(error.message) &&
        (error as { clause?: string }).clause === "aws.live-drift",
    );
  } finally {
    if (prior === undefined) delete process.env.AWS_FAKE_HTTP_STATUS;
    else process.env.AWS_FAKE_HTTP_STATUS = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS live check uses the package-pinned source image without consulting mutable tags", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-live-manifest-"));
  const single = microvmConfig(oneServiceConfig());
  const taskArn = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1";
  const fake = statefulAws(
    dir,
    single,
    manifestItems(
      [
        {
          id: "current",
          imageLabel: "release",
          tasks: { core: taskArn },
          imageProvenance: { core: { kind: "configured", source: manifestRef("core") } },
        },
      ],
      "current",
    ),
  );
  const priorImageState = process.env.AWS_FAKE_IMAGE_STATE;
  const priorAlbDns = process.env.AWS_FAKE_ALB_DNS;
  const priorSecretValue = process.env.AWS_FAKE_SECRET_VALUE;
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const arns = Object.fromEntries(computedSecrets(single).map((secret) => [secret.name, testSecretArn(secret.name)]));
  state.definitions[taskArn] = {
    ...renderTaskDefinition(
      single,
      "core",
      `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`,
      arns,
    ),
    taskDefinitionArn: taskArn,
  };
  writeFileSync(fake.state, JSON.stringify(state));
  const dockerLog = join(dir, "docker.log");
  writeFileSync(dockerLog, "");
  const dockerBin = join(dir, "docker");
  writeFileSync(
    dockerBin,
    `#!/usr/bin/env node\nrequire("node:fs").appendFileSync(${JSON.stringify(dockerLog)}, process.argv.slice(2).join(" ") + "\\n");\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`,
  );
  chmodSync(dockerBin, 0o755);
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await assert.doesNotReject(() => awsCheckLive(single, { report: false }));
    process.env.AWS_FAKE_SECRET_VALUE = "short";
    await assert.rejects(() => awsCheckLive(single, { report: false }), /secret CORE_SIGNING_SECRET/);
    if (priorSecretValue === undefined) delete process.env.AWS_FAKE_SECRET_VALUE;
    else process.env.AWS_FAKE_SECRET_VALUE = priorSecretValue;
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /ecr describe-images/);
    assert.doesNotMatch(readFileSync(dockerLog, "utf8"), /buildx imagetools inspect/);
    const overridden: QmConfig = {
      ...single,
      imageOverrides: { core: `ghcr.io/acme/core@sha256:${"b".repeat(64)}` },
      aws: { ...single.aws!, services: { core: { ...single.aws!.services.core!, architecture: "arm64" } } },
    };
    await assert.rejects(
      () => awsCheckLive(overridden, { report: false }),
      new RegExp(`core: image drift .*desired .*@sha256:${"b".repeat(64)}`),
    );
    const afterConfiguredCheck = readFileSync(dockerLog, "utf8");
    const persisted = JSON.parse(readFileSync(fake.state, "utf8"));
    const persistedManifest = JSON.parse(persisted.dynamo["deployment/manifest/current"].manifest.S);
    delete persistedManifest.imageProvenance;
    persisted.dynamo["deployment/manifest/current"].manifest.S = JSON.stringify(persistedManifest);
    writeFileSync(fake.state, JSON.stringify(persisted));
    await assert.doesNotReject(() => awsCheckLive(overridden, { report: false }));
    assert.equal(readFileSync(dockerLog, "utf8"), afterConfiguredCheck);
    persistedManifest.imageProvenance = { core: { kind: "configured", source: manifestRef("core") } };
    persisted.dynamo["deployment/manifest/current"].manifest.S = JSON.stringify(persistedManifest);
    writeFileSync(fake.state, JSON.stringify(persisted));
    process.env.AWS_FAKE_IMAGE_STATE = "FAILED";
    await assert.rejects(
      () => awsCheckLive(single, { report: false }),
      /deploy image drift: AWS deploy image .* version 1 is not SUCCESSFUL and ACTIVE/,
    );
    if (priorImageState === undefined) delete process.env.AWS_FAKE_IMAGE_STATE;
    else process.env.AWS_FAKE_IMAGE_STATE = priorImageState;
    process.env.AWS_FAKE_ALB_DNS = "127.0.0.1";
    await assert.rejects(
      () => awsCheckLive(single, { report: false }),
      /public network drift: AWS public origin .* does not resolve to this stack's ALB 127\.0\.0\.1/,
    );
    if (priorAlbDns === undefined) delete process.env.AWS_FAKE_ALB_DNS;
    else process.env.AWS_FAKE_ALB_DNS = priorAlbDns;
    const otherLabel: QmConfig = { ...single, aws: { ...single.aws!, imageLabel: "other-release" } };
    await assert.rejects(
      () => awsCheckLive(otherLabel, { report: false }),
      /manifest label release does not match configured release other-release/,
    );
  } finally {
    if (priorSecretValue === undefined) delete process.env.AWS_FAKE_SECRET_VALUE;
    else process.env.AWS_FAKE_SECRET_VALUE = priorSecretValue;
    process.env.PATH = priorPath;
    if (priorImageState === undefined) delete process.env.AWS_FAKE_IMAGE_STATE;
    else process.env.AWS_FAKE_IMAGE_STATE = priorImageState;
    if (priorAlbDns === undefined) delete process.env.AWS_FAKE_ALB_DNS;
    else process.env.AWS_FAKE_ALB_DNS = priorAlbDns;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS live check detects prebuilt plugin image drift from current config", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-live-plugin-image-"));
  const single = oneServiceConfig();
  const pluginConfig: QmConfig = {
    ...single,
    plugins: [{ name: "linear", image: "ghcr.io/acme/linear:1" }],
    aws: {
      ...single.aws!,
      services: {
        ...single.aws!.services,
        linear: { ecrRepository: "qm-linear", ecsService: "acme-linear", cpu: 256, memory: 512, architecture: "amd64" },
      },
    },
  };
  const tasks = {
    core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1",
    linear: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-linear:1",
  };
  const fake = statefulAws(
    dir,
    pluginConfig,
    manifestItems(
      [
        {
          id: "current",
          imageLabel: "release",
          tasks,
          imageProvenance: {
            core: { kind: "configured", source: "ghcr.io/qm/qm-core:0.1.0" },
            linear: { kind: "configured", source: "ghcr.io/acme/linear:1" },
          },
        },
      ],
      "current",
    ),
  );
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const arns = Object.fromEntries(
    computedSecrets(pluginConfig).map((secret) => [secret.name, testSecretArn(secret.name)]),
  );
  state.definitions[tasks.core] = {
    ...renderTaskDefinition(
      pluginConfig,
      "core",
      `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`,
      arns,
    ),
    taskDefinitionArn: tasks.core,
  };
  state.definitions[tasks.linear] = {
    ...renderTaskDefinition(
      pluginConfig,
      "linear",
      `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-linear@sha256:${"a".repeat(64)}`,
      arns,
    ),
    taskDefinitionArn: tasks.linear,
  };
  writeFileSync(fake.state, JSON.stringify(state));
  const dockerBin = join(dir, "docker");
  writeFileSync(
    dockerBin,
    `#!/usr/bin/env node\nconsole.log("Digest: sha256:" + (process.argv.at(-1).includes("linear") ? "${"b".repeat(64)}" : "${"a".repeat(64)}"));\n`,
  );
  chmodSync(dockerBin, 0o755);
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await assert.rejects(
      () => awsCheckLive(pluginConfig, { report: false }),
      new RegExp(`linear: image drift .*desired .*qm-linear@sha256:${"b".repeat(64)}`),
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /ecr describe-images|ecr batch-delete-image/);
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS rejects stale service entries after a workload is removed", async () => {
  const single = oneServiceConfig();
  const stale: QmConfig = {
    ...single,
    aws: {
      ...single.aws!,
      services: { ...single.aws!.services, portal: config.aws!.services.portal! },
    },
  };
  const expected = /aws\.services topology mismatch \(disabled workloads: portal\)/;
  await assert.rejects(() => awsUp(stale, process.cwd(), { dryRun: true }), expected);
  await assert.rejects(() => awsCheckLive(stale, { report: false }), expected);
  assert.throws(() => awsStatus(stale), expected);
});

test("AWS up rejects an image label that differs from the durable directory before side effects", async () => {
  await assert.rejects(
    () => awsUp(oneServiceConfig(), process.cwd(), { yes: true, imageLabel: "other" }),
    /differs from durable aws\.imageLabel/,
  );
});

test("AWS plan rejects an explicit nonexistent source checkout before cloud access", async () => {
  await assert.rejects(
    () =>
      awsUp(oneServiceConfig(), process.cwd(), {
        dryRun: true,
        buildFrom: true,
        buildFromPath: "/definitely/not/a/qm/checkout",
      }),
    /not a QM checkout/,
  );
});

test("AWS mutations release the deploy lease when their initial service snapshot fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-snapshot-lease-"));
  const single = oneServiceConfig();
  const run = async (operation: () => void | Promise<void>, preflight = false): Promise<void> => {
    const fake = statefulAws(dir, single, {}, { failDescribe: true });
    try {
      await assert.rejects(async () => operation(), /DescribeServicesFailure/);
      const calls = readFileSync(fake.log, "utf8");
      if (preflight) assert.doesNotMatch(calls, /dynamodb/);
      else {
        assert.ok(calls.indexOf("dynamodb put-item") < calls.indexOf("ecs describe-services"));
        assert.ok(calls.indexOf("ecs describe-services") < calls.indexOf("dynamodb delete-item"));
      }
    } finally {
      fake.restore();
    }
  };
  try {
    await run(() => awsUp(single, dir, { yes: true }), true);
    await run(() => awsRollback(single));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS service rollback includes an update whose successful response was lost", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-update-response-"));
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single, {}, { failFirstUpdateAfterMutation: true });
  try {
    await assert.rejects(() => awsDown(single), /UpdateServiceResponseLost/);
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(state.services["acme-core"].desiredCount, 1);
    assert.equal(readFileSync(fake.log, "utf8").match(/ecs update-service/g)?.length, 2);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS down refuses foreign exact-name services before acquiring the lease or mutating ECS", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-foreign-service-"));
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single, {}, { foreignServiceTags: true });
  try {
    await assert.rejects(() => awsDown(single), /ownership tags do not match deployment acme/);
    const calls = readFileSync(fake.log, "utf8");
    assert.doesNotMatch(calls, /dynamodb put-item|ecs update-service/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up refuses foreign exact-name services before acquiring the lease or publishing images", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-foreign-service-up-"));
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single, {}, { foreignServiceTags: true });
  try {
    await assert.rejects(() => awsUp(single, dir, { yes: true }), /ownership tags do not match deployment acme/);
    const calls = readFileSync(fake.log, "utf8");
    assert.doesNotMatch(calls, /dynamodb put-item|ecr get-login-password|ecs update-service/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up refreshes injected provider preflight under the deployment lease", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-stale-provider-preflight-"));
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single, {}, { foreignServiceTags: true });
  try {
    await assert.rejects(
      () =>
        awsUp(single, dir, {
          yes: true,
          preflight: {
            microvmRebuildRequired: false,
            publicApiUrlNeedsUpdate: false,
            secretArns: Object.fromEntries(
              computedSecrets(single).map((secret) => [secret.name, testSecretArn(secret.name)]),
            ),
            secretValues: new Map(),
          },
        }),
      /ownership tags do not match deployment acme/,
    );
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /dynamodb put-item/);
    assert.match(calls, /dynamodb delete-item/);
    assert.doesNotMatch(calls, /rds create-db-snapshot|ecr get-login-password|ecs update-service/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up repairs stale PUBLIC_API_URL under the lease before deployment mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-public-api-url-"));
  const configured = microvmConfig({ ...oneServiceConfig(), apiUrl: "https://agent.acme.example" });
  const fake = statefulAws(dir, configured);
  const docker = join(dir, "docker");
  writeFileSync(docker, "#!/bin/sh\nexit 0\n");
  chmodSync(docker, 0o755);
  const priorPath = process.env.PATH;
  const priorOverrides = process.env.AWS_FAKE_SECRET_OVERRIDES;
  process.env.PATH = `${dir}:${priorPath}`;
  process.env.AWS_FAKE_SECRET_OVERRIDES = JSON.stringify({
    PUBLIC_API_URL: "https://api.stale.example",
  });
  try {
    await awsUp(configured, dir, { yes: true });
    const calls = readFileSync(fake.log, "utf8");
    const lease = calls.indexOf("dynamodb put-item");
    const put = calls.indexOf("secretsmanager put-secret-value --secret-id acme/qm/PUBLIC_API_URL", lease);
    const deploymentMutation = calls.search(/rds create-db-snapshot|s3api put-object|ecr get-login-password/);
    assert.ok(lease >= 0 && lease < put && put < deploymentMutation);
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.equal(after.secretValues.PUBLIC_API_URL, "https://agent.acme.example");
  } finally {
    process.env.PATH = priorPath;
    if (priorOverrides === undefined) delete process.env.AWS_FAKE_SECRET_OVERRIDES;
    else process.env.AWS_FAKE_SECRET_OVERRIDES = priorOverrides;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("direct AWS up refreshes the full provider preflight under the deployment lease", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-direct-stale-provider-preflight-"));
  const single = oneServiceConfig();
  const fake = statefulAws(dir, single, {}, { foreignServiceTagsAfterLease: true });
  try {
    await assert.rejects(() => awsUp(single, dir, { yes: true }), /ownership tags do not match deployment acme/);
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /dynamodb put-item/);
    assert.match(calls, /dynamodb delete-item/);
    assert.doesNotMatch(calls, /rds create-db-snapshot|ecr get-login-password|ecs update-service/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS plan uses the package-pinned source image without consulting or mutating mutable labels", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-plan-source-"));
  const single = oneServiceConfig();
  const taskArn = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1";
  const fake = statefulAws(
    dir,
    single,
    manifestItems([{ id: "current", imageLabel: "release", tasks: { core: taskArn } }], "current"),
  );
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const arns = Object.fromEntries(computedSecrets(single).map((secret) => [secret.name, testSecretArn(secret.name)]));
  state.definitions[taskArn] = {
    ...renderTaskDefinition(
      single,
      "core",
      `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"b".repeat(64)}`,
      arns,
    ),
    taskDefinitionArn: taskArn,
  };
  writeFileSync(fake.state, JSON.stringify(state));
  const dockerLog = join(dir, "docker.log");
  writeFileSync(dockerLog, "");
  const dockerBin = join(dir, "docker");
  writeFileSync(
    dockerBin,
    `#!/usr/bin/env node\nrequire("node:fs").appendFileSync(${JSON.stringify(dockerLog)}, process.argv.slice(2).join(" ") + "\\n");\nconsole.log("Digest: sha256:${"b".repeat(64)}");\n`,
  );
  chmodSync(dockerBin, 0o755);
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  const lines: string[] = [];
  const log = console.log;
  console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
  try {
    await awsUp(single, dir, { dryRun: true });
    const calls = readFileSync(fake.log, "utf8");
    assert.doesNotMatch(calls, /ecr describe-images|ecr batch-delete-image|dynamodb put-item|ecs update-service/);
    assert.doesNotMatch(readFileSync(dockerLog, "utf8"), /buildx imagetools inspect/);
    assert.match(lines.join("\n"), new RegExp(`qm-core@sha256:${"a".repeat(64)}`));
  } finally {
    console.log = log;
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("aws up resolves image digests only while holding the deploy lease", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-"));
  const dockerLog = join(dir, "docker.log");
  writeFileSync(dockerLog, "");
  const dockerBin = join(dir, "docker");
  writeFileSync(
    dockerBin,
    `#!/usr/bin/env node\nrequire("node:fs").appendFileSync(${JSON.stringify(dockerLog)}, process.argv.slice(2).join(" ") + "\\n");\n`,
  );
  chmodSync(dockerBin, 0o755);
  const single = microvmConfig(oneServiceConfig());
  const fake = statefulAws(dir, single);
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const currentTask = state.services["acme-core"].taskDefinition;
  state.definitions[currentTask].containerDefinitions[0].image =
    `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"b".repeat(64)}`;
  writeFileSync(fake.state, JSON.stringify(state));
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  const lines: string[] = [];
  const log = console.log;
  console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
  try {
    await awsUp(single, dir, { yes: true });
    const calls = readFileSync(fake.log, "utf8");
    assert.match(
      calls,
      /ecs register-task-definition .*--tags \[\{"key":"ManagedBy","value":"qm-cli"\},\{"key":"Deployment","value":"acme"\}\]/,
    );
    const lease = calls.indexOf("dynamodb put-item");
    const login = calls.indexOf("get-login-password");
    const digest = calls.indexOf("ecr describe-images");
    const update = calls.indexOf("ecs update-service");
    const manifest = calls.indexOf("dynamodb transact-write-items");
    const promotion = calls.indexOf("ecr put-image");
    const cleanup = calls.indexOf("ecr batch-delete-image");
    const release = calls.indexOf("dynamodb delete-item");
    assert.ok(
      [lease, login, digest, update, manifest, promotion, cleanup, release].every((index) => index !== -1),
      calls,
    );
    assert.ok(
      calls.lastIndexOf("lambda-microvms get-microvm-image") > lease,
      "the deploy image is revalidated after acquiring the shared lease",
    );
    assert.ok(lease < login && login < digest, "push + digest resolution happen inside the lease");
    assert.ok(
      digest < update && update < manifest,
      "the staged digest drives ECS before the durable manifest is recorded",
    );
    assert.ok(manifest < promotion, "the stable tag is promoted only after deployment success is durable");
    assert.ok(promotion < cleanup && cleanup < release, "the staging tag is cleaned before releasing the lease");
    const now = Math.floor(Date.now() / 1000);
    const leaseExpiry = Number(calls.match(/dynamodb put-item[^\n]*"expiresAt":\{"N":"(\d+)"\}/)?.[1]);
    assert.ok(leaseExpiry > now && leaseExpiry <= now + 60 * 60 + 5, "the lease uses a bounded TTL");
    const transactions = calls.split("\n").filter((line) => line.includes("dynamodb transact-write-items"));
    assert.equal(transactions.length, 1, "the manifest is one unconditional transaction");
    assert.doesNotMatch(calls, /--client-request-token/);
    assert.match(calls, /ecr batch-delete-image .*imageTag=qm-staging/);
    assert.ok(readFileSync(dockerLog, "utf8").includes("imagetools create"), "the image was pushed via docker");
    assert.match(readFileSync(dockerLog, "utf8"), /--tag [^\s]+\/qm-core:qm-staging/);
  } finally {
    console.log = log;
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up requires a complete trusted baseline before a partial deployment", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-partial-up-"));
  const multi = twoServiceConfig();
  const first = statefulAws(dir, multi);
  try {
    await assert.rejects(
      () => awsUp(multi, dir, { dryRun: true, only: ["core"] }),
      /first AWS deployment must include every workload/,
    );
    await assert.rejects(
      () => awsUp(multi, dir, { yes: true, only: ["core"] }),
      /first AWS deployment must include every workload/,
    );
    const calls = readFileSync(first.log, "utf8");
    assert.doesNotMatch(calls, /ecr get-login-password|ecs update-service/);
    assert.match(calls, /dynamodb delete-item/);
  } finally {
    first.restore();
  }

  const tasks = {
    core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1",
    "web-ui": "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-web-ui:1",
  };
  const baseline = statefulAws(
    dir,
    multi,
    manifestItems(
      [
        {
          id: "baseline",
          imageLabel: "previous",
          tasks,
          imageProvenance: {
            core: { kind: "source-build" },
            "web-ui": { kind: "configured", source: "ghcr.io/qm/qm-web-ui:0.1.0" },
          },
        },
      ],
      "baseline",
    ),
  );
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(multi, dir, { yes: true, only: ["core"] });
    const after = JSON.parse(readFileSync(baseline.state, "utf8"));
    const currentId = after.dynamo["deployment/current"].manifestId.S;
    const current = JSON.parse(after.dynamo[`deployment/manifest/${currentId}`].manifest.S);
    assert.equal(current.tasks["web-ui"], tasks["web-ui"]);
    assert.deepEqual(current.imageProvenance, {
      core: { kind: "configured", source: manifestRef("core") },
      "web-ui": { kind: "configured", source: "ghcr.io/qm/qm-web-ui:0.1.0" },
    });
  } finally {
    process.env.PATH = priorPath;
    baseline.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS partial up rejects stale untouched task environment and cross-service secrets before mutation", async (t) => {
  const cases = [
    { name: "provider environment", untouched: "core", selected: "web-ui" },
    { name: "legacy API endpoint plaintext", untouched: "core", selected: "web-ui" },
    { name: "legacy API endpoint secret", untouched: "core", selected: "web-ui" },
    { name: "Slack endpoint plaintext", untouched: "core", selected: "web-ui" },
    { name: "Slack endpoint secret", untouched: "core", selected: "web-ui" },
    { name: "AWS endpoint plaintext", untouched: "core", selected: "web-ui" },
    { name: "AWS endpoint secret", untouched: "core", selected: "web-ui" },
    { name: "provider control secret", untouched: "core", selected: "web-ui" },
    { name: "cross-service secret", untouched: "web-ui", selected: "core" },
  ] as const;
  for (const scenario of cases) {
    await t.test(scenario.name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-aws-partial-stale-task-"));
      const configured = twoServiceConfig();
      const tasks = {
        core: "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:4",
        "web-ui": "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-web-ui:4",
      };
      const fake = statefulAws(
        dir,
        configured,
        manifestItems([{ id: "current", imageLabel: "release", tasks }], "current"),
      );
      const state = JSON.parse(readFileSync(fake.state, "utf8"));
      state.services["acme-core"].taskDefinition = tasks.core;
      state.services["acme-web-ui"].taskDefinition = tasks["web-ui"];
      const container = state.definitions[tasks[scenario.untouched]].containerDefinitions[0];
      if (scenario.name === "provider environment") {
        container.environment.find((entry: { name: string }) => entry.name === "DATA_DIR").value = "/tmp/lost";
      } else if (scenario.name === "legacy API endpoint plaintext") {
        container.environment.push({ name: "AGENT_API_URL", value: "https://attacker.example" });
      } else if (scenario.name === "legacy API endpoint secret") {
        container.secrets.push({ name: "AGENT_API_URL", valueFrom: testSecretArn("CORE_SIGNING_SECRET") });
      } else if (scenario.name === "Slack endpoint plaintext") {
        container.environment.push({ name: "SLACK_API_URL", value: "https://attacker.example" });
      } else if (scenario.name === "Slack endpoint secret") {
        container.secrets.push({ name: "SLACK_API_URL", valueFrom: testSecretArn("CORE_SIGNING_SECRET") });
      } else if (scenario.name === "AWS endpoint plaintext") {
        container.environment.push({ name: "AWS_ENDPOINT_URL_S3", value: "https://attacker.example" });
      } else if (scenario.name === "AWS endpoint secret") {
        container.secrets.push({ name: "AWS_ENDPOINT_URL_S3", valueFrom: testSecretArn("CORE_SIGNING_SECRET") });
      } else if (scenario.name === "provider control secret") {
        container.secrets.push({ name: "SECRETS_BACKEND", valueFrom: testSecretArn("CORE_SIGNING_SECRET") });
      } else {
        container.secrets.push({ name: "DATABASE_URL", valueFrom: testSecretArn("DATABASE_URL") });
      }
      writeFileSync(fake.state, JSON.stringify(state));
      try {
        await assert.rejects(
          awsUp(configured, dir, { yes: true, only: [scenario.selected] }),
          /stale or unowned (?:environment|secret) entries/,
        );
        assert.doesNotMatch(
          readFileSync(fake.log, "utf8"),
          /rds create-db-snapshot|s3api put-object|ecr get-login-password|ecs register-task-definition|ecs update-service|dynamodb transact-write-items/,
        );
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("AWS up replaces a stale core DATA_DIR with the provider-owned durable path", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-data-dir-"));
  const configured = microvmConfig(oneServiceConfig());
  const fake = statefulAws(dir, configured);
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const before = state.services["acme-core"].taskDefinition;
  state.definitions[before].containerDefinitions[0].environment.find(
    (entry: { name: string }) => entry.name === "DATA_DIR",
  ).value = "/tmp/lost";
  writeFileSync(fake.state, JSON.stringify(state));
  const docker = join(dir, "docker");
  writeFileSync(docker, "#!/bin/sh\nexit 0\n");
  chmodSync(docker, 0o755);
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(configured, dir, { yes: true });
    const after = JSON.parse(readFileSync(fake.state, "utf8"));
    const current = after.services["acme-core"].taskDefinition;
    assert.notEqual(current, before);
    const environment = Object.fromEntries(
      after.definitions[current].containerDefinitions[0].environment.map(
        ({ name, value }: { name: string; value: string }) => [name, value],
      ),
    );
    assert.equal(environment.DATA_DIR, "/data");
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up cleans staging tags when ECS deployment fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-cleanup-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const fake = statefulAws(dir, oneServiceConfig(), {}, { ignoreUpdate: true, staleTaskDefinition: true });
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await assert.rejects(() => awsUp(oneServiceConfig(), dir, { yes: true }), /did not reach the requested state/);
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /ecr batch-delete-image .*imageTag=qm-staging/);
    assert.doesNotMatch(calls, /imageTag=release/);
    assert.ok(calls.indexOf("ecr batch-delete-image") < calls.indexOf("dynamodb delete-item"));
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up succeeds while a protected old task keeps the rollout from completing, even with a historical failed task", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-drain-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const drainConfig = (): QmConfig => {
    const base = oneServiceConfig();
    return { ...base, aws: { ...base.aws!, alb: "legacy-alb" } };
  };
  const fake = statefulAws(dir, drainConfig(), {}, { drainRollout: true, staleTaskDefinition: true });
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(drainConfig(), dir, { yes: true });
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.ok(state.dynamo["deployment/current"], "deployment manifest recorded despite the draining old task");
    const calls = readFileSync(fake.log, "utf8");
    assert.doesNotMatch(calls, /ecs wait services-stable/);
    assert.match(
      calls,
      /elbv2 describe-load-balancers --names legacy-alb/,
      "front-door lookup honors the configured ALB name",
    );
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up tolerates a transient describe-services failure while polling the rollout", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-transient-describe-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const fake = statefulAws(
    dir,
    oneServiceConfig(),
    {},
    {
      failDescribeOnceAfterUpdate: true,
      staleTaskDefinition: true,
    },
  );
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(oneServiceConfig(), dir, { yes: true });
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.ok(state.describeFailedOnce, "the transient failure was actually injected");
    assert.ok(state.dynamo["deployment/current"], "deploy succeeded despite the transient poll failure");
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up aborts failed tasks only after four polls with no replacement running — longer than any single ENI/pull flake", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-failed-tasks-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const fake = statefulAws(dir, oneServiceConfig(), {}, { primaryFailedTasks: true, staleTaskDefinition: true });
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await assert.rejects(
      () => awsUp(oneServiceConfig(), dir, { yes: true }),
      /keeps failing tasks with no replacement starting \(failedTasks=1, 0\/1 running across \d+ polls\)/,
    );
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up survives a three-poll failed-task flake that ECS replaces — the window a transient ENI/pull failure needs", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-transient-failed-task-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const fake = statefulAws(
    dir,
    oneServiceConfig(),
    {},
    {
      transientFailedTaskPolls: 3,
      staleTaskDefinition: true,
    },
  );
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(oneServiceConfig(), dir, { yes: true });
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.ok(state.failedTaskPolls >= 3, "the failed-task polls were actually served");
    assert.ok(state.dynamo["deployment/current"], "deploy succeeded despite the transient task failure");
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up survives alternating single-service stale reads — only the same workload's same failure on consecutive polls confirms an abort", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-alternating-stale-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/usr/bin/env node\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`);
  chmodSync(dockerBin, 0o755);
  const multi = twoServiceConfig();
  const fake = statefulAws(dir, multi, {}, { alternateStaleReadPolls: 4, staleTaskDefinition: true });
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(multi, dir, { yes: true });
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.ok(state.stalePolls >= 4, "the alternating stale reads were actually served");
    assert.ok(
      state.dynamo["deployment/current"],
      "deploy succeeded despite four polls of alternating transient failures",
    );
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up still fails fast on a FAILED rollout state — the ECS circuit-breaker verdict needs no flake window", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-rollout-failed-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const fake = statefulAws(dir, oneServiceConfig(), {}, { rolloutFailed: true, staleTaskDefinition: true });
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await assert.rejects(() => awsUp(oneServiceConfig(), dir, { yes: true }), /PRIMARY rollout is FAILED/);
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS promotion never classifies ImageAlreadyExistsException from its tag argument", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-promotion-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const configured = oneServiceConfig();
  configured.aws = { ...configured.aws!, imageLabel: "release-ImageAlreadyExistsException" };
  const fake = statefulAws(dir, configured, {}, { failPromotion: true });
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(configured, dir, { yes: true });
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /dynamodb transact-write-items/);
    assert.doesNotMatch(calls, /ecr batch-delete-image .*imageTag=qm-/);
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up treats an already-current stable label as successful promotion", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-current-label-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const fake = statefulAws(dir, oneServiceConfig(), {}, { promotionAlreadyCurrent: true });
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await awsUp(oneServiceConfig(), dir, { yes: true });
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /ecr put-image/);
    assert.match(calls, /ecr batch-delete-image .*imageTag=qm-staging/);
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS cleanup never classifies ImageNotFoundException from its repository argument", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-cleanup-classification-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const configured = oneServiceConfig();
  configured.aws = {
    ...configured.aws!,
    services: {
      core: { ...configured.aws!.services.core!, ecrRepository: "qm-ImageNotFoundException" },
    },
  };
  const fake = statefulAws(dir, configured, {}, { failCleanup: true });
  const priorPath = process.env.PATH;
  const warnings: string[] = [];
  const warn = console.warn;
  process.env.PATH = `${dir}:${priorPath}`;
  console.warn = (...parts: unknown[]): void => void warnings.push(parts.join(" "));
  try {
    await awsUp(configured, dir, { yes: true });
    assert.match(warnings.join("\n"), /could not clean staging image core:qm-staging/);
  } finally {
    console.warn = warn;
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS up keeps a healthy rollout and its staging tag when the manifest write fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-up-manifest-failure-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, "#!/bin/sh\nexit 0\n");
  chmodSync(dockerBin, 0o755);
  const fake = statefulAws(dir, oneServiceConfig(), {}, { failTransactions: true, staleTaskDefinition: true });
  const initialTask = JSON.parse(readFileSync(fake.state, "utf8")).services["acme-core"].taskDefinition;
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  try {
    await assert.rejects(
      () => awsUp(oneServiceConfig(), dir, { yes: true }),
      /AWS deployment manifest write failed[\s\S]*check --live/,
    );
    const state = JSON.parse(readFileSync(fake.state, "utf8"));
    assert.notEqual(state.services["acme-core"].taskDefinition, initialTask);
    assert.equal(state.dynamo["deployment/current"], undefined);
    const calls = readFileSync(fake.log, "utf8");
    assert.doesNotMatch(calls, /ecr batch-delete-image .*imageTag=qm-staging/);
    assert.ok(calls.indexOf("dynamodb transact-write-items") < calls.indexOf("dynamodb delete-item"));
  } finally {
    process.env.PATH = priorPath;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS front door tolerates exactly one extra port-80 HTTPS-redirect listener; any other extra listener still fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-front-door-listeners-"));
  const dockerBin = join(dir, "docker");
  writeFileSync(dockerBin, `#!/usr/bin/env node\nconsole.log("Digest: sha256:${"a".repeat(64)}");\n`);
  chmodSync(dockerBin, 0o755);
  const priorPath = process.env.PATH;
  process.env.PATH = `${dir}:${priorPath}`;
  const run = async (mode: "redirect" | "forward" | undefined, expected?: RegExp): Promise<void> => {
    const fake = statefulAws(dir, oneServiceConfig());
    const prior = process.env.AWS_FAKE_EXTRA_HTTP_LISTENER;
    if (mode) process.env.AWS_FAKE_EXTRA_HTTP_LISTENER = mode;
    try {
      if (expected) await assert.rejects(() => awsUp(oneServiceConfig(), dir, { dryRun: true }), expected);
      else await awsUp(oneServiceConfig(), dir, { dryRun: true });
    } finally {
      if (prior === undefined) delete process.env.AWS_FAKE_EXTRA_HTTP_LISTENER;
      else process.env.AWS_FAKE_EXTRA_HTTP_LISTENER = prior;
      fake.restore();
    }
  };
  try {
    await run(undefined);
    await run("redirect");
    await run(
      "forward",
      /expected exactly one public listener plus at most one port-80 HTTPS-redirect listener, found HTTPS:443 \(default fixed-response\), HTTP:80 \(default forward\)/,
    );
  } finally {
    process.env.PATH = priorPath;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS live check accepts a successful deploy mid-drain: PRIMARY at full strength (historical failed task included) while a protected old task keeps the rollout IN_PROGRESS", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-aws-check-drain-"));
  const single = oneServiceConfig();
  const taskArn = "arn:aws:ecs:us-west-2:123456789012:task-definition/acme-core:1";
  const fake = statefulAws(
    dir,
    single,
    manifestItems([{ id: "current", imageLabel: "release", tasks: { core: taskArn } }], "current"),
    { drainRollout: true },
  );
  const state = JSON.parse(readFileSync(fake.state, "utf8"));
  const arns = Object.fromEntries(computedSecrets(single).map((secret) => [secret.name, testSecretArn(secret.name)]));
  state.definitions[taskArn] = {
    ...renderTaskDefinition(
      single,
      "core",
      `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`,
      arns,
    ),
    taskDefinitionArn: taskArn,
  };
  writeFileSync(fake.state, JSON.stringify(state));
  try {
    await assert.doesNotReject(() => awsCheckLive(single, { report: false, configDir: dir }));
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AWS renders config secretEnv extras and aliases as Secrets Manager references", () => {
  const extras: QmConfig = {
    ...config,
    env: { ...config.env, core: { ...config.env.core, DEPLOY_APPS_DOMAIN: "apps.agent.acme.example" } },
    secretEnv: {
      core: { CUSTOM_API_KEY: "CUSTOM_API_KEY", DEPLOY_APPS_SESSION_SECRET: "PORTAL_SESSION_SECRET" },
      slack: { SLACK_AUX_BOT_TOKEN: "SLACK_AUX_BOT_TOKEN" },
    },
  };
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  const task = renderTaskDefinition(extras, "core", image, { PORTAL_SESSION_SECRET: "arn:resolved:portal-session" });
  const secrets = Object.fromEntries(
    (task.containerDefinitions[0]!.secrets as Array<{ name: string; valueFrom: string }>).map((s) => [
      s.name,
      s.valueFrom,
    ]),
  );
  assert.equal(secrets.CUSTOM_API_KEY, "arn:aws:secretsmanager:us-west-2:123456789012:secret:acme/qm/CUSTOM_API_KEY");
  assert.equal(
    secrets.SLACK_AUX_BOT_TOKEN,
    "arn:aws:secretsmanager:us-west-2:123456789012:secret:acme/qm/SLACK_AUX_BOT_TOKEN",
    "a virtual service's extra folds onto the core task",
  );
  assert.equal(
    secrets.DEPLOY_APPS_SESSION_SECRET,
    "arn:resolved:portal-session",
    "an alias delivers the stored secret under its declared env name",
  );
  assert.equal(secrets.PORTAL_SESSION_SECRET, undefined, "the alias adds no plain-name delivery on core");
  const portalImage = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-portal@sha256:${"a".repeat(64)}`;
  const portalSecrets = (
    renderTaskDefinition(extras, "portal", portalImage).containerDefinitions[0]!.secrets as Array<{ name: string }>
  ).map((s) => s.name);
  assert.ok(portalSecrets.includes("PORTAL_SESSION_SECRET"), "the portal keeps its own plain delivery");
  assert.ok(!portalSecrets.includes("DEPLOY_APPS_SESSION_SECRET"));
});

test("env.core.SANDBOX_BACKEND adopts the deployment's substrate; the default is sprites", () => {
  assert.equal(serviceEnvironment(config, "core").SANDBOX_BACKEND, "sprites");
  const adopted: QmConfig = {
    ...config,
    env: { ...config.env, core: { ...config.env.core, SANDBOX_BACKEND: "sprites" } },
  };
  assert.equal(serviceEnvironment(adopted, "core").SANDBOX_BACKEND, "sprites");
});

test("env.core.S3_BUCKET adopts a pre-existing snapshot bucket; the derived object store remains the default", () => {
  assert.equal(serviceEnvironment(config, "core").S3_BUCKET, awsObjectStoreBucket(config));
  const adopted: QmConfig = {
    ...config,
    env: { ...config.env, core: { ...config.env.core, S3_BUCKET: "acme-prod-snapshots" } },
  };
  assert.equal(serviceEnvironment(adopted, "core").S3_BUCKET, "acme-prod-snapshots");
});

test("AWS renders adopted logGroup and stopTimeout pins; the defaults stay derived", () => {
  const image = `123456789012.dkr.ecr.us-west-2.amazonaws.com/qm-core@sha256:${"a".repeat(64)}`;
  const derived = renderTaskDefinition(config, "core", image).containerDefinitions[0]!;
  assert.equal(
    (derived.logConfiguration as { options: Record<string, string> }).options["awslogs-group"],
    "/ecs/acme-core",
  );
  assert.equal(derived.stopTimeout, undefined);
  const adopted: QmConfig = {
    ...config,
    aws: {
      ...config.aws!,
      services: {
        ...config.aws!.services,
        core: { ...config.aws!.services.core!, logGroup: "/ecs/legacy-core", stopTimeout: 120 },
      },
    },
  };
  const container = renderTaskDefinition(adopted, "core", image).containerDefinitions[0]!;
  assert.equal(
    (container.logConfiguration as { options: Record<string, string> }).options["awslogs-group"],
    "/ecs/legacy-core",
  );
  assert.equal(container.stopTimeout, 120);
});

test("AWS doctor classifies an un-pushed secret store as pending, not drift", () => {
  const rnf = Object.assign(new Error("aws command failed"), {
    stderr:
      "An error occurred (ResourceNotFoundException) when calling the GetSecretValue operation: Secrets Manager can't find the specified secret.",
  });
  const secrets = computedSecrets({
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "aws",
    services: ["core"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
  });
  const requiredNames = secrets.filter((secret) => secret.required).map((secret) => secret.name);
  assert.ok(requiredNames.length > 0);
  const probe = probeAwsSecretStore(
    secrets,
    () => {
      throw rnf;
    },
    () => assert.fail("PUBLIC_API_URL must not be validated when the store is empty"),
  );
  assert.deepEqual(probe.pending, requiredNames);
  assert.deepEqual(probe.failures, []);
  assert.equal(probe.values.size, 0);
});

test("AWS doctor still fails a pushed secret store holding a placeholder value", () => {
  const probe = probeAwsSecretStore(
    [
      {
        name: "CORE_SIGNING_SECRET",
        services: ["core"],
        description: "",
        required: true,
        managedBy: "operator",
      },
    ],
    () => "replace-me",
    () => {},
  );
  assert.deepEqual(probe.pending, []);
  assert.equal(probe.failures.length, 1);
  assert.match(probe.failures[0]!, /CORE_SIGNING_SECRET: missing, placeholder, or insecure value/);
});

test("AWS doctor rejects individually valid duplicate runtime secrets", () => {
  const value = "individually-valid-duplicate-runtime-secret";
  const probe = probeAwsSecretStore(
    ["CAPABILITY_SECRET", "CORE_SIGNING_SECRET"].map((name) => ({
      name,
      services: ["core"],
      description: "",
      required: true,
      managedBy: "operator" as const,
    })),
    () => value,
    () => {},
  );
  assert.deepEqual(probe.pending, []);
  assert.deepEqual(probe.failures, ["secrets failed runtime validation: CAPABILITY_SECRET, CORE_SIGNING_SECRET"]);
});

test("AWS doctor never classifies ResourceNotFoundException from an error message without process output", () => {
  const probe = probeAwsSecretStore(
    [
      {
        name: "CORE_SIGNING_SECRET",
        services: ["core"],
        description: "",
        required: true,
        managedBy: "operator",
      },
    ],
    () => {
      throw new Error("aws get ResourceNotFoundException failed: AccessDeniedException");
    },
    () => {},
  );
  assert.deepEqual(probe.pending, []);
  assert.equal(probe.failures.length, 1);
  assert.match(probe.failures[0]!, /AccessDeniedException/);
});

test("AWS doctor only classifies the primary structured AWS error code", () => {
  const denied = Object.assign(new Error("aws command failed"), {
    stderr:
      "An error occurred (AccessDeniedException) when calling the GetSecretValue operation: resource acme-ResourceNotFoundException is denied",
  });
  const probe = probeAwsSecretStore(
    [
      {
        name: "CORE_SIGNING_SECRET",
        services: ["core"],
        description: "",
        required: true,
        managedBy: "operator",
      },
    ],
    () => {
      throw denied;
    },
    () => {},
  );
  assert.deepEqual(probe.pending, []);
  assert.equal(probe.failures.length, 1);
  assert.match(probe.failures[0]!, /aws command failed/);
});
