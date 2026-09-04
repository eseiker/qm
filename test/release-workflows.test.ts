import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { promisify } from "node:util";

const images = readFileSync(".github/workflows/release-package.yml", "utf8");
const publish = readFileSync(".github/workflows/publish-cli.yml", "utf8");
const release = readFileSync(".github/workflows/release.yml", "utf8");
const releaseAliases = readFileSync("scripts/release-image-aliases.sh", "utf8");
type ImageManifest = { sandboxBase: string; services: Record<string, string> };
const currentManifestTemplate: ImageManifest = {
  sandboxBase:
    "ghcr.io/yc-software/qm/sandbox-base@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  services: Object.fromEntries(
    ["admin", "auth", "core", "egress-proxy", "portal", "web-ui"].map((service, index) => [
      service,
      `ghcr.io/yc-software/qm/${service}@sha256:${String(index + 1).padStart(64, "0")}`,
    ]),
  ),
};
const previousManifestTemplate = JSON.parse(
  readFileSync("test/fixtures/release-images-five-services.json", "utf8"),
) as ImageManifest;
const execFileAsync = promisify(execFile);

function ordered(body: string, first: string, second: string): void {
  const left = body.indexOf(first);
  const right = body.indexOf(second);
  assert.notEqual(left, -1, `missing ${first}`);
  assert.notEqual(right, -1, `missing ${second}`);
  assert.ok(left < right, `${first} must precede ${second}`);
}

function runAliasScenario(
  mode: "check" | "publish" | "verify",
  aliasState: "absent" | "exact" | "conflict",
  manifestTemplate: ImageManifest = currentManifestTemplate,
  manifestSuffix = "",
  preconditionSupported = true,
) {
  const directory = mkdtempSync(join(tmpdir(), "qm-release-aliases-"));
  const bin = join(directory, "bin");
  const state = join(directory, "state");
  const putLog = join(directory, "puts");
  const tokenScopeLog = join(directory, "token-scopes");
  const manifestPath = join(directory, "images.json");
  const sourceBody = '{"schemaVersion":2,"manifests":[]}';
  const conflictBody = '{"schemaVersion":2,"manifests":[{}]}';
  const sourceDigest = "sha256:" + createHash("sha256").update(sourceBody).digest("hex");
  const conflictDigest = "sha256:" + createHash("sha256").update(conflictBody).digest("hex");
  const replaceDigest = (ref: string) => ref.replace(/sha256:[0-9a-f]{64}$/, sourceDigest);
  const manifest = {
    sandboxBase: replaceDigest(manifestTemplate.sandboxBase),
    services: Object.fromEntries(
      Object.entries(manifestTemplate.services).map(([service, ref]) => [service, replaceDigest(ref)]),
    ),
  };

  mkdirSync(bin);
  mkdirSync(state);
  copyFileSync("test/fixtures/release-alias-curl.sh", join(bin, "curl"));
  chmodSync(join(bin, "curl"), 0o755);
  writeFileSync(manifestPath, JSON.stringify(manifest) + manifestSuffix);
  try {
    const result = spawnSync("bash", ["scripts/release-image-aliases.sh", mode, manifestPath, "1.2.3"], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        ALIAS_STATE: aliasState,
        CONFLICT_BODY: conflictBody,
        CONFLICT_DIGEST: conflictDigest,
        GH_TOKEN: "test-token",
        GITHUB_ACTOR: "github-actions[bot]",
        PATH: bin + ":" + (process.env.PATH ?? ""),
        PRECONDITION_SUPPORTED: String(preconditionSupported),
        PUT_LOG: putLog,
        SOURCE_BODY: sourceBody,
        SOURCE_DIGEST: sourceDigest,
        STATE_DIR: state,
        TOKEN_SCOPE_LOG: tokenScopeLog,
      },
    });
    const puts = existsSync(putLog) ? readFileSync(putLog, "utf8").trim().split("\n").filter(Boolean) : [];
    const tokenScopes = existsSync(tokenScopeLog)
      ? readFileSync(tokenScopeLog, "utf8").trim().split("\n").filter(Boolean)
      : [];
    return { puts, result, tokenScopes };
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
}

function workflowShellBlocks(workflow: string): string[] {
  const lines = workflow.split("\n");
  const blocks: string[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^(\s*)run: \|$/.exec(lines[index]!);
    if (!match) continue;
    const runIndent = match[1]!.length;
    const bodyIndent = runIndent + 2;
    const body: string[] = [];
    for (index += 1; index < lines.length; index += 1) {
      const line = lines[index]!;
      const indentation = /^\s*/.exec(line)![0].length;
      if (line.trim() && indentation <= runIndent) {
        index -= 1;
        break;
      }
      body.push(line.slice(Math.min(bodyIndent, line.length)));
    }
    blocks.push(body.join("\n"));
  }
  return blocks;
}

async function capturePublishedVersion(directory: string, argument: string): Promise<Record<string, unknown>> {
  let publishedVersion: Record<string, unknown> | undefined;
  const cache = mkdtempSync(join(tmpdir(), "qm-npm-publish-cache-"));
  const registry = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    if (request.method === "PUT") {
      const body = JSON.parse(Buffer.concat(chunks).toString()) as {
        versions?: Record<string, Record<string, unknown>>;
      };
      publishedVersion = body.versions?.["1.2.3"];
      response.statusCode = 201;
      response.setHeader("content-type", "application/json");
      response.end('{"ok":true}');
      return;
    }
    response.statusCode = 404;
    response.setHeader("content-type", "application/json");
    response.end('{"error":"not_found"}');
  });
  await new Promise<void>((resolve, reject) => registry.once("error", reject).listen(0, "127.0.0.1", resolve));
  try {
    const port = (registry.address() as AddressInfo).port;
    await execFileAsync(
      "npm",
      [
        "publish",
        argument,
        `--registry=http://127.0.0.1:${port}/`,
        `--//127.0.0.1:${port}/:_authToken=test-token`,
        "--access=public",
        "--tag=probe",
        "--ignore-scripts=true",
        "--dry-run=false",
      ],
      { cwd: directory, env: { ...process.env, NPM_CONFIG_CACHE: cache } },
    );
    assert.ok(publishedVersion);
    return publishedVersion;
  } finally {
    await new Promise<void>((resolve, reject) => registry.close((error) => (error ? reject(error) : resolve())));
    rmSync(cache, { force: true, recursive: true });
  }
}

test("one dispatchable workflow owns the complete release", () => {
  assert.match(release, /^on:\n {2}workflow_dispatch:$/m);
  assert.match(images, /^on:\n {2}workflow_call:$/m);
  assert.match(publish, /^on:\n {2}workflow_call:$/m);
  assert.doesNotMatch(images, /^ {2}workflow_dispatch:/m);
  assert.doesNotMatch(publish, /^ {2}workflow_dispatch:/m);
  assert.match(release, /concurrency:\n {2}group: release\n {2}cancel-in-progress: false/);
  assert.doesNotMatch(release, /^ {2}queue:/m);
  assert.doesNotMatch(release, /^ {4}if: github\.ref == 'refs\/heads\/main'$/m);
  assert.match(release, /releases are cut from main; this run is on \$GITHUB_REF/);
});

test("every new release keeps a dependency-free pinned-source bootstrap entry", () => {
  const bootstrap = release.indexOf("      - name: Verify the pinned-source bootstrap entry");
  const version = release.indexOf("      - id: version", bootstrap);
  assert.ok(bootstrap > release.indexOf("actions/setup-node@"));
  assert.ok(version > bootstrap);
  const step = release.slice(bootstrap, version);
  assert.match(step, /env -i HOME="\$RUNNER_TEMP" PATH="\$PATH" node cli\/bin\/qm\.ts version/);
  assert.match(step, /jq -er '\.version \| strings' cli\/package\.json/);
  assert.doesNotMatch(step, /npm (?:ci|install|exec|x)|npx/);
});

test("every multiline workflow shell step parses", () => {
  for (const [name, workflow] of [
    ["release", release],
    ["release-package", images],
    ["publish-cli", publish],
  ] as const) {
    const blocks = workflowShellBlocks(workflow);
    assert.ok(blocks.length > 0);
    for (const [index, block] of blocks.entries()) {
      const result = spawnSync("bash", ["-n"], { encoding: "utf8", input: block });
      assert.equal(result.status, 0, name + " shell block " + index + ": " + result.stderr);
    }
  }
});

test("the source package version is the release identity everywhere", () => {
  const cliVersion = (JSON.parse(readFileSync("cli/package.json", "utf8")) as { version: string }).version;
  const chart = readFileSync("deploy/helm/Chart.yaml", "utf8");
  const dockerfile = readFileSync("deploy/admin/Dockerfile", "utf8");
  const dockerBackend = readFileSync("cli/src/backends/docker.ts", "utf8");
  const awsBackend = readFileSync("cli/src/backends/aws.ts", "utf8");
  const flyBackend = readFileSync("cli/src/backends/fly.ts", "utf8");
  const rootLock = JSON.parse(readFileSync("package-lock.json", "utf8")) as {
    packages: Record<string, { link?: boolean; name?: string; resolved?: string; version?: string }>;
  };
  const services = readFileSync("cli/src/services.ts", "utf8");
  const sourceFly = readFileSync("deploy/admin/fly.toml", "utf8");
  const packagedFly = readFileSync("cli/templates/fly/admin.toml", "utf8");
  const helm = readFileSync("scripts/deploy-helm.sh", "utf8");
  const smoke = readFileSync("scripts/smoke-surface-image.sh", "utf8");

  assert.match(release, /version=\$\(jq -r \.version cli\/package\.json\)/);
  assert.match(release, /cli\/package\.json version must be stable semver/);
  assert.doesNotMatch(release, /patch \+ 1/);
  for (const workflow of [images, publish]) {
    assert.match(workflow, /source_version=\$\(jq -r \.version cli\/package\.json\)/);
    assert.match(workflow, /release version \$VERSION does not match cli\/package\.json \$source_version/);
  }
  assert.match(images, /- name: admin\n\s+dockerfile: deploy\/admin\/Dockerfile\n\s+- name: portal/);
  assert.match(dockerfile, /^COPY cli\/package\.json \.\/qm-package\.json$/m);
  assert.doesNotMatch(dockerfile, /QM_VERSION/);
  assert.equal(chart.match(/^appVersion: "(\S+)"$/m)?.[1], cliVersion);
  assert.deepEqual(rootLock.packages["node_modules/@yc-software/qm"], { resolved: "cli", link: true });
  assert.equal(rootLock.packages.cli?.name, "@yc-software/qm");
  assert.equal(rootLock.packages.cli?.version, cliVersion);
  assert.match(
    helm,
    /VERSION="\$\(node -p 'require\(process\.argv\[1\]\)\.version' "\$SOURCE_ROOT\/cli\/package\.json"\)"/,
  );
  assert.doesNotMatch(helm, /VERSION="\$\{QM_VERSION/);
  assert.doesNotMatch(helm, /process\.env\.QM_VERSION/);
  assert.match(helm, /git -C "\$ROOT" status --porcelain/);
  assert.match(helm, /SOURCE_CLEAN=false/);
  assert.match(helm, /SOURCE_CLEAN=true/);
  assert.match(helm, /an explicit development image tag is required for modified or non-git QM source/);
  assert.match(helm, /\^\[0-9A-Fa-f\]\{7,40\}\$/);
  assert.match(helm, /modified or non-git QM source requires a clearly non-commit development image tag/);
  ordered(helm, 'if [ "$SOURCE_CLEAN" != true ]; then', 'TAG="$GIT_SHA"');
  assert.match(helm, /GIT_SHA="\$\(git -C "\$ROOT" rev-parse HEAD\)"/);
  assert.match(helm, /\^\[a-f0-9\]\{40\}\$/);
  assert.doesNotMatch(helm, /rev-parse --short/);
  assert.match(helm, /git -C "\$ROOT" archive --format=tar HEAD \| tar -xf - -C "\$SOURCE_ROOT"/);
  assert.match(helm, /VERSION="\$\(node -p [^\n]+ "\$SOURCE_ROOT\/cli\/package\.json"\)"/);
  assert.match(helm, /-f "\$SOURCE_ROOT\/deploy\/\$svc\/Dockerfile"/);
  assert.match(helm, /^ {4}"\$SOURCE_ROOT"$/m);
  assert.match(helm, /"\$svc" == core && -n "\$GIT_SHA"/);
  assert.doesNotMatch(helm, /GIT_SHA=\$TAG/);
  assert.doesNotMatch(helm, /QM_VERSION/);
  assert.match(helm, /PUBLISH_CHART="\$SOURCE_CLEAN"/);
  assert.match(helm, /\[ "\$SOURCE_CLEAN" = true \] && \[ "\$TAG" = "\$VERSION" \]/);
  assert.match(helm, /CHART_VERSION="\$VERSION"/);
  assert.match(helm, /CHART_VERSION="\$VERSION-build\.git-\$GIT_SHA\.tag-\$tag_id"/);
  assert.match(helm, /CHART_VERSION="\$VERSION-dev\.build-\$build_id"/);
  assert.match(helm, /helm package "\$CHART" --version "\$CHART_VERSION" --app-version "\$TAG"/);
  assert.match(helm, /packages=\("\$PKG_DIR"\/\*\.tgz\)/);
  assert.match(helm, /\[ "\$\{#packages\[@\]\}" -ne 1 \] \|\| \[ ! -f "\$\{packages\[0\]\}" \]/);
  assert.match(helm, /PACKAGE="\$\{packages\[0\]\}"/);
  assert.match(helm, /EXPECTED_PACKAGE="\$PKG_DIR\/qm-\$CHART_VERSION\.tgz"/);
  assert.match(helm, /if \[ "\$PUBLISH_CHART" = true \]; then[\s\S]*?helm push/);
  assert.match(helm, /helm upgrade --install "\$RELEASE" "\$PACKAGE"/);
  assert.match(helm, /helm show chart "\$PACKAGE"/);
  assert.doesNotMatch(smoke, /QM_VERSION/);
  assert.doesNotMatch(dockerBackend, /QM_VERSION|sourcePackageVersion/);
  assert.doesNotMatch(awsBackend, /QM_VERSION|sourcePackageVersion/);
  assert.doesNotMatch(flyBackend, /QM_VERSION|sourcePackageVersion/);
  assert.doesNotMatch(services, /QM_VERSION|cliVersion/);
  assert.doesNotMatch(sourceFly, /QM_VERSION/);
  assert.doesNotMatch(packagedFly, /QM_VERSION/);
});

test("Helm source builds never claim a dirty or ignored working tree as a commit", () => {
  const directory = mkdtempSync(join(tmpdir(), "qm-deploy-helm-"));
  const root = join(directory, "repo");
  const bin = join(directory, "bin");
  const commandLog = join(directory, "commands");
  const runGit = (...args: string[]) => {
    const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  const runDeploy = (tag?: string) =>
    spawnSync("bash", [join(root, "scripts/deploy-helm.sh"), "registry.example/qm", ...(tag ? [tag] : [])], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        COMMAND_LOG: commandLog,
        PATH: bin + ":" + (process.env.PATH ?? ""),
        QM_DEPLOY: "0",
      },
    });

  try {
    mkdirSync(join(root, "scripts"), { recursive: true });
    mkdirSync(join(root, "cli"), { recursive: true });
    mkdirSync(join(root, "deploy/helm"), { recursive: true });
    mkdirSync(bin, { recursive: true });
    copyFileSync("scripts/deploy-helm.sh", join(root, "scripts/deploy-helm.sh"));
    writeFileSync(join(root, "cli/package.json"), '{"version":"1.2.3"}\n');
    writeFileSync(join(root, "deploy/helm/Chart.yaml"), "apiVersion: v2\nname: qm\nversion: 1.2.3\n");
    writeFileSync(join(root, ".gitignore"), "ignored.txt\n");
    writeFileSync(join(root, "tracked.txt"), "clean\n");
    for (const service of ["core", "auth", "web-ui", "admin", "portal", "egress-proxy"]) {
      mkdirSync(join(root, "deploy", service), { recursive: true });
      writeFileSync(join(root, "deploy", service, "Dockerfile"), "FROM scratch\n");
    }
    writeFileSync(
      join(bin, "docker"),
      '#!/usr/bin/env bash\nset -euo pipefail\nlast=""\nfor argument in "$@"; do last="$argument"; done\nprintf \'docker %s\\n\' "$*" >> "$COMMAND_LOG"\nif [ "$1" = build ] && [ -e "$last/ignored.txt" ]; then printf \'ignored-in-context\\n\' >> "$COMMAND_LOG"; fi\n',
    );
    writeFileSync(
      join(bin, "helm"),
      '#!/usr/bin/env bash\nset -euo pipefail\nprintf \'helm %s\\n\' "$*" >> "$COMMAND_LOG"\ncommand="$1"\nshift\nif [ "$command" = package ]; then\n  destination=""\n  version=""\n  while [ "$#" -gt 0 ]; do\n    case "$1" in\n      --destination) destination="$2"; shift 2 ;;\n      --version) version="$2"; shift 2 ;;\n      *) shift ;;\n    esac\n  done\n  mkdir -p "$destination"\n  : > "$destination/qm-$version.tgz"\nelif [ "$command" = show ]; then\n  printf \'version: 1.2.3\\n\'\nfi\n',
    );
    chmodSync(join(bin, "docker"), 0o755);
    chmodSync(join(bin, "helm"), 0o755);
    runGit("init", "--quiet");
    runGit("config", "user.name", "QM Test");
    runGit("config", "user.email", "qm-test@example.com");
    runGit("config", "commit.gpgsign", "false");
    runGit("add", ".");
    runGit("commit", "--quiet", "-m", "fixture");
    const head = runGit("rev-parse", "HEAD");
    writeFileSync(join(root, "ignored.txt"), "ignored\n");

    const clean = runDeploy();
    assert.equal(clean.status, 0, clean.stderr);
    const cleanLog = readFileSync(commandLog, "utf8");
    assert.match(cleanLog, new RegExp("GIT_SHA=" + head));
    assert.match(cleanLog, new RegExp("registry\\.example/qm/core:" + head));
    assert.match(cleanLog, new RegExp("--version 1\\.2\\.3-build\\.git-" + head + "\\.tag-[a-f0-9]{16}"));
    assert.match(cleanLog, /helm push/);
    assert.doesNotMatch(cleanLog, /ignored-in-context/);

    rmSync(commandLog, { force: true });
    const stable = runDeploy("1.2.3");
    assert.equal(stable.status, 0, stable.stderr);
    const stableLog = readFileSync(commandLog, "utf8");
    assert.match(stableLog, /helm package .* --version 1\.2\.3 --app-version 1\.2\.3/);
    assert.match(stableLog, /helm push/);

    writeFileSync(join(root, "tracked.txt"), "modified\n");
    for (const tag of [undefined, head, "1.2.3", "v1.2.3-rc.1"]) {
      const rejected = runDeploy(tag);
      assert.notEqual(rejected.status, 0, tag ?? "default tag");
      assert.match(rejected.stderr, /development image tag/);
    }

    rmSync(commandLog, { force: true });
    const development = runDeploy("dev-local");
    assert.equal(development.status, 0, development.stderr);
    assert.equal(existsSync(commandLog), true, development.stdout + development.stderr);
    const developmentLog = readFileSync(commandLog, "utf8");
    assert.match(developmentLog, /registry\.example\/qm\/core:dev-local/);
    assert.doesNotMatch(developmentLog, /GIT_SHA=/);
    assert.match(developmentLog, /--version 1\.2\.3-dev\.build-[a-f0-9]{32} --app-version dev-local/);
    assert.doesNotMatch(developmentLog, /helm push/);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("release preflight derives fresh recovery from verified provenance", () => {
  const cliReadme = readFileSync("cli/README.md", "utf8");
  assert.match(release, /GH_TOKEN: [$]\{\{ github\.token \}\}/);
  assert.match(release, /RELEASE_SETTINGS_TOKEN: [$]\{\{ secrets\.RELEASE_SETTINGS_TOKEN \|\| github\.token \}\}/);
  assert.match(release, /settings_token=\$RELEASE_SETTINGS_TOKEN\n {10}unset RELEASE_SETTINGS_TOKEN/);
  assert.doesNotMatch(release, /unset GH_TOKEN/);
  assert.match(release, /X-GitHub-Api-Version: 2026-03-10/);
  assert.match(release, /repos\/\$GITHUB_REPOSITORY\/immutable-releases/);
  assert.match(release, /\.enabled == true and \(\.enforced_by_owner \| type == "boolean"\)/);
  assert.match(release, /RELEASE_SETTINGS_TOKEN with Administration read access/);
  ordered(
    release,
    '"repos/$GITHUB_REPOSITORY/immutable-releases"',
    "source_version=$(jq -r .version cli/package.json)",
  );
  assert.match(release, /tags=\$\(npm_registry view @yc-software\/qm dist-tags --json\)/);
  assert.doesNotMatch(release, /npm_registry view @yc-software\/qm[^\n]*\|\| true/);
  assert.match(release, /matching-refs\/tags\/v/);
  assert.match(release, /cli\/package\.json version \$version must be newer than released QM \$newest/);
  assert.match(
    release,
    /published=\$\(npm_registry view "@yc-software\/qm@\$version" version deprecated gitHead dist --json[\s\S]*?2> "\$exact_error"\)/,
  );
  for (const workflow of [images, publish, release]) {
    assert.match(workflow, /elif ! printf '%s' "\$published" \| jq -e '\.error\.code == "E404"'/);
    assert.doesNotMatch(workflow, /grep -q 'E404'/);
  }
  assert.match(release, /audit signatures --json --include-attestations=true/);
  assert.match(release, /actions\/runs\/\(\[1-9\]\[0-9\]\*\)\/attempts\//);
  assert.match(release, /resolvedDependencies\[\][\s\S]*\.digest == \{gitCommit: \$sha\}/);
  assert.match(release, /compare\/\$release_sha\.\.\.\$GITHUB_SHA/);
  assert.match(release, /\.merge_base_commit\.sha == \$base/);
  assert.match(release, /\.status == "ahead"[\s\S]*\.ahead_by > 0[\s\S]*\.behind_by == 0/);
  assert.match(release, /resume=true/);
  assert.match(
    release,
    /if \[ -z "\$REQUESTED_VERSION" \]; then\n {14}if \[ "\$origin_run_id" != "\$GITHUB_RUN_ID" \] \|\| \[ "\$release_sha" != "\$GITHUB_SHA" \]; then/,
  );
  assert.match(release, /elif \[ "\$release_sha" != "\$GITHUB_SHA" \]; then\n {14}comparison=/);
  assert.match(release, /dispatch this workflow with recovery_version=\$version/);
  assert.doesNotMatch(release, /cannot resume stale QM/);
  assert.match(release, /release-candidate QM \$candidate is unfinished; dispatch recovery_version=\$candidate/);
  assert.match(release, /printf 'origin_run_id=%s\\nresume=%s\\nsha=%s\\ntag=%s\\nversion=%s\\n'/);
  assert.match(release, /node-version-file: \.node-version/);
  assert.match(release, /resume: \$\{\{ needs\.preflight\.outputs\.resume == 'true' \}\}/);
  assert.match(cliReadme, /A separate workflow run must\nset `recovery_version` explicitly/);
  assert.match(cliReadme, /A no-input run never\nadopts a package from another run/);
  assert.doesNotMatch(cliReadme, /recoverable only inside the same workflow run/);
  ordered(release, "resume=true", "  images:");
});

test("release controls are rechecked at every irreversible boundary", () => {
  const security = readFileSync("SECURITY.md", "utf8");
  for (const workflow of [release, publish]) {
    assert.match(workflow, /\.conditions\.ref_name\.include == \["refs\/tags\/v\*"\]/);
    assert.match(workflow, /\.conditions\.ref_name\.exclude == \[\]/);
    assert.match(workflow, /\[\.rules\[\]\.type\] \| sort == \["creation"\]/);
    assert.match(workflow, /\[\.rules\[\]\.type\] \| sort == \["deletion", "update"\]/);
    assert.match(workflow, /\[ "\$creation_rulesets" -lt 1 \] \|\| \[ "\$lock_rulesets" -lt 1 \]/);
    assert.doesNotMatch(workflow, /\["creation", "update", "deletion"\] - \[\.rules\[\]\.type\]/);
  }
  assert.match(publish, /^ {6}RELEASE_SETTINGS_TOKEN:\n {8}required: true$/m);
  assert.match(release, /RELEASE_SETTINGS_TOKEN: \$\{\{ secrets\.RELEASE_SETTINGS_TOKEN \}\}/);
  assert.match(
    publish,
    /require_release_rulesets\n {12}require_immutable_releases\n {12}set \+e\n {12}NODE_AUTH_TOKEN="\$npm_token" npm_registry publish/,
  );
  assert.match(
    release,
    /require_release_controls\n {12}require_immutable_releases\n {12}set \+e\n {12}gh release create/,
  );
  assert.match(
    release,
    /validate_release_asset "\$release_json"\n {12}require_release_controls\n {12}require_immutable_releases\n {12}gh api --method PATCH/,
  );
  const tagStepStart = release.indexOf("      - name: Create or verify the release tag");
  const tagStepEnd = release.indexOf("      - name: Create or complete the GitHub release", tagStepStart);
  assert.notEqual(tagStepStart, -1);
  assert.notEqual(tagStepEnd, -1);
  const tagStep = release.slice(tagStepStart, tagStepEnd);
  assert.match(tagStep, /RELEASE_TAG_TOKEN: \$\{\{ secrets\.RELEASE_TAG_TOKEN \}\}/);
  assert.match(tagStep, /tag_token=\$RELEASE_TAG_TOKEN\n {10}unset RELEASE_SETTINGS_TOKEN RELEASE_TAG_TOKEN/);
  assert.match(tagStep, /GH_TOKEN="\$tag_token" gh api "repos\/\$GITHUB_REPOSITORY\/git\/tags"/);
  assert.match(tagStep, /GH_TOKEN="\$tag_token" gh api "repos\/\$GITHUB_REPOSITORY\/git\/refs"/);
  assert.doesNotMatch(release.slice(0, tagStepStart) + release.slice(tagStepEnd), /RELEASE_TAG_TOKEN/);
  assert.match(publish, /settings_token=\$RELEASE_SETTINGS_TOKEN\n {10}unset NODE_AUTH_TOKEN RELEASE_SETTINGS_TOKEN/);
  assert.match(security, /REST API omits bypass actors/);
  assert.match(security, /creation restriction[\s\S]*sole `always` bypass/);
  assert.match(security, /update and\s+deletion restrictions and has no bypass actors/);
  assert.match(security, /dispatch remains contingent on that operator control/);
  assert.match(
    security,
    /Post-publication checks detect that state and stop promotion rather than prevent\nthe denial of service/,
  );
});

test("signed release images cover every runtime architecture and service", () => {
  assert.doesNotMatch(images, /npm publish/);
  assert.match(images, /platforms: linux\/amd64,linux\/arm64/);
  assert.match(images, /docker\/setup-qemu-action@[0-9a-f]{40}/);
  assert.match(images, /image: tonistiigi\/binfmt@sha256:[0-9a-f]{64}/);
  assert.match(images, /for architecture in amd64 arm64; do/);
  assert.match(images, /any\(\.manifests\[\]; \.platform\.os == "linux"/);
  assert.match(images, /permissions:\n\s+contents: read\n\s+packages: write\n\s+id-token: write/);
  assert.match(
    images,
    /cosign sign --yes[\s\S]*?-a origin_run_id="\$ORIGIN_RUN_ID"[\s\S]*?-a service='\$\{\{ matrix\.name \}\}'[\s\S]*?-a version="\$VERSION"[\s\S]*?"\$image"/,
  );
  assert.match(
    images,
    /cosign verify "\$image"[\s\S]*?-a origin_run_id="\$ORIGIN_RUN_ID"[\s\S]*?-a service='\$\{\{ matrix\.name \}\}'[\s\S]*?-a version="\$VERSION"/,
  );
  assert.match(
    images,
    /cosign verify "\$ref"[\s\S]*?-a origin_run_id="\$ORIGIN_RUN_ID"[\s\S]*?-a service="\$service"[\s\S]*?-a version="\$VERSION"/,
  );
  assert.equal((images.match(/--certificate-github-workflow-repository="\$GITHUB_REPOSITORY"/g) ?? []).length, 2);
  assert.equal((images.match(/--certificate-github-workflow-sha="\$RELEASE_SHA"/g) ?? []).length, 2);
  assert.match(images, /for service in core web-ui admin portal auth egress-proxy sandbox-base; do/);
  assert.match(images, /git ls-remote --exit-code origin "refs\/tags\/v\$VERSION"/);
  assert.match(images, /if \[ "\$tag_status" -ne 2 \]; then/);
  assert.match(images, /is already published; refusing to replace release image tags/);
  assert.match(
    images,
    /- name: core\n\s+dockerfile: deploy\/core\/Dockerfile\n\s+build-args: GIT_SHA=\$\{\{ github\.sha \}\}/,
  );
  assert.match(
    images,
    /tags: ghcr\.io\/yc-software\/qm\/\$\{\{ matrix\.name \}\}:release-\$\{\{ inputs\.version \}\}-\$\{\{ github\.run_id \}\}/,
  );
  assert.doesNotMatch(images, /github\.run_attempt/);
  assert.match(images, /^ {6}packages: read$/m);
  assert.match(images, /docker\/login-action@[0-9a-f]{40}/);
  assert.match(images, /^ {4}if: \$\{\{ !inputs\.resume \}\}$/m);
  assert.match(images, /always\(\) && \(inputs\.resume \|\| needs\.image\.result == 'success'\)/);
  assert.match(images, /^ {6}origin_run_id:\n {8}description: Workflow run recorded by image signatures/m);
  assert.match(release, /origin_run_id: \$\{\{ needs\.preflight\.outputs\.origin_run_id \}\}/);
  assert.match(images, /npm_registry pack[\s\S]*"@yc-software\/qm@\$VERSION"[\s\S]*--min-release-age=0/);
  assert.match(images, /tar -xOzf "\$package_tarball" package\/manifest\.json/);
  ordered(images, "Validate release identity", "docker/setup-qemu-action");
  ordered(images, "docker/setup-qemu-action", "docker/setup-buildx-action");
  ordered(images, "Verify image platforms", "Sign exact image");
});

test("the exact signed image set flows into the package and release asset", () => {
  assert.match(images, /value: \$\{\{ jobs\.descriptor\.outputs\.manifest \}\}/);
  assert.match(images, /^ {2}descriptor:\n {4}needs: image$/m);
  assert.doesNotMatch(images, /actions\/(?:upload|download)-artifact/);
  assert.match(images, /tag="\$repository:release-\$VERSION-\$GITHUB_RUN_ID"/);
  assert.match(images, /imagetools inspect "\$tag" --format '\{\{json \.Manifest\}\}'/);
  assert.match(images, /mapfile -t services < <\(jq -er '\.services \| keys\[\]' images\.json\)/);
  assert.match(
    images,
    /if \[ "\$RESUME" != true \]; then[\s\S]*\.services \| keys == \["admin", "auth", "core", "egress-proxy", "portal", "web-ui"\]/,
  );
  assert.match(images, /\$parts\[0\] == \("ghcr\.io\/yc-software\/qm\/" \+ \$service\)/);
  assert.match(images, /\.services \| type == "object" and length > 0 and \(has\("sandbox-base"\) \| not\)/);
  assert.match(images, /Reject conflicting release image aliases/);
  assert.match(images, /release-image-aliases\.sh check images\.json "\$VERSION"/);
  assert.match(
    release,
    /image_manifest: \$\{\{ needs\.images\.outputs\.manifest \}\}[\s\S]*?version: \$\{\{ needs\.preflight\.outputs\.version \}\}/,
  );
  assert.match(publish, /printf '%s\\n' "\$IMAGE_MANIFEST" \| jq -c \. > cli\/manifest\.json/);
  assert.match(publish, /keys == \["sandboxBase", "services"\]/);
  assert.match(release, /printf '%s' "\$MANIFEST" \| jq \. > images\.json/);
  assert.match(release, /"images\.json#Pinned image digests"/);
});

test("recovery accepts prior package-owned service sets and rejects ambiguous manifests", () => {
  for (const body of [images, publish, release, releaseAliases]) {
    assert.match(body, /length == 1/);
    assert.match(body, /\$parts\[0\] == \("ghcr\.io\/yc-software\/qm\/" \+ \$service\)/);
    assert.match(body, /has\("sandbox-base"\) \| not/);
  }
  const recoveryStart = images.indexOf("Recover the published image manifest");
  const recoveryEnd = images.indexOf("Assemble signed image manifest", recoveryStart);
  const recovery = images.slice(recoveryStart, recoveryEnd);
  assert.doesNotMatch(recovery, /for service in core web-ui admin portal auth egress-proxy/);
  assert.doesNotMatch(publish, /\.services \| keys == \["admin", "auth", "core", "egress-proxy", "portal", "web-ui"\]/);
  assert.deepEqual(Object.keys(previousManifestTemplate.services).sort(), [
    "admin",
    "auth",
    "core",
    "portal",
    "web-ui",
  ]);
});

test("release npm traffic is isolated and every dist tag is validated", () => {
  for (const workflow of [images, publish, release]) {
    assert.match(workflow, /^env:\n {2}NPM_CONFIG_DRY_RUN: "false"\n {2}NPM_CONFIG_GLOBALCONFIG: \/dev\/null/m);
    assert.match(workflow, /^ {2}NPM_CONFIG_PREFER_ONLINE: "true"$/m);
    assert.match(workflow, /^ {2}NPM_CONFIG_REGISTRY: https:\/\/registry\.npmjs\.org$/m);
    assert.match(workflow, /^ {2}NPM_CONFIG_WORKSPACES: "false"$/m);
    assert.doesNotMatch(workflow, /NPM_CONFIG_USERCONFIG/);
    assert.doesNotMatch(workflow, /^ {2}NPM_CONFIG_MIN_RELEASE_AGE:/m);
    const setupNodeCount = (workflow.match(/actions\/setup-node@/g) ?? []).length;
    const npmScopeCount = (workflow.match(/^ {10}scope: "@yc-software"$/gm) ?? []).length;
    assert.equal(npmScopeCount, setupNodeCount);
    assert.match(workflow, /--@yc-software:registry="\$NPM_CONFIG_REGISTRY"/);
  }
  for (const workflow of [publish, release]) {
    assert.match(workflow, /all\(to_entries\[\];[\s\S]*\.value \| test\(\$semver\)\)/);
    assert.match(workflow, /\.latest \| type == "string" and test\(\$stable\)/);
    assert.match(workflow, /\.\["release-candidate"\] \| type == "string" and test\(\$stable\)/);
    assert.match(workflow, /\.\[\] \| select\(test\(\$stable\)\)[\s\S]*sort -V/);
  }
  assert.doesNotMatch(release, /for (?:released|tagged) in "\$latest" "\$candidate"/);
  assert.doesNotMatch(publish, /for tagged in "\$latest" "\$candidate"/);
});

test("candidate publication re-verifies the exact provenance origin", () => {
  assert.match(publish, /npm_token=\$NODE_AUTH_TOKEN[\s\S]*?unset NODE_AUTH_TOKEN RELEASE_SETTINGS_TOKEN/);
  assert.match(publish, /npm run --ignore-scripts=true prepack/);
  assert.match(
    publish,
    /expected_pack=\$\(npm pack --json --dry-run=false --ignore-scripts=true --pack-destination "\$expected_dir"\)/,
  );
  assert.match(
    publish,
    /confirmation_pack=\$\(npm pack --json --dry-run=false --ignore-scripts=true --pack-destination "\$confirmation_dir"\)/,
  );
  assert.match(
    publish,
    /NODE_AUTH_TOKEN="\$npm_token" npm_registry publish "\$publish_directory"[\s\S]*--tag release-candidate[\s\S]*--ignore-scripts=true/,
  );
  assert.match(
    publish,
    /NODE_AUTH_TOKEN="\$npm_token" npm_registry dist-tag add "@yc-software\/qm@\$VERSION" release-candidate/,
  );
  assert.doesNotMatch(publish, /^ {12}npm_registry (?:publish|dist-tag add)/m);
  assert.doesNotMatch(publish, /npm_registry publish "\$expected_tarball"/);
  assert.match(
    publish,
    /remote_pack=\$\(npm_registry pack[\s\S]*"@yc-software\/qm@\$VERSION"[\s\S]*--min-release-age=0\)/,
  );
  assert.match(publish, /cmp --silent "\$expected_tarball" "\$remote_tarball"/);
  assert.match(publish, /cmp --silent "\$expected_tarball" "\$confirmation_tarball"/);
  assert.match(publish, /published_git_head.*RELEASE_SHA/s);
  assert.match(publish, /audit signatures --json --include-attestations=true/);
  assert.match(publish, /published_integrity=.*\.dist\.integrity/);
  assert.match(publish, /tarball_integrity="sha512-\$\(openssl dgst -sha512 -binary/);
  assert.match(publish, /\[ "\$published_integrity" != "\$tarball_integrity" \]/);
  assert.match(publish, /predicateType == "https:\/\/slsa\.dev\/provenance\/v1"/);
  assert.match(publish, /actions\/runs\/\$ORIGIN_RUN_ID\/attempts\//);
  assert.match(publish, /resolvedDependencies\[\][\s\S]*\.digest == \{gitCommit: \$sha\}/);
  assert.match(
    publish,
    /for _ in \$\(seq 1 10\); do[\s\S]*set \+e[\s\S]*\(\n\s+set -euo pipefail\n\s+verify_published\n\s+\)[\s\S]*verification_status=\$\?[\s\S]*set -e/,
  );
  assert.doesNotMatch(publish, /if \(verify_published\)/);
  assert.match(publish, /npm_registry dist-tag add "@yc-software\/qm@\$VERSION" release-candidate/);
  assert.match(publish, /candidate_status=\$\?[\s\S]*candidate_ready/);
  assert.match(publish, /\[ "\$RELEASE_SHA" != "\$GITHUB_SHA" \][\s\S]*\[ "\$ORIGIN_RUN_ID" != "\$GITHUB_RUN_ID" \]/);
  assert.match(publish, /verified older QM \$VERSION without moving release-candidate back/);
  assert.match(publish, /verified_origin_run_id="\$\{BASH_REMATCH\[1\]\}"/);
  assert.match(publish, /printf 'origin_run_id=%s\\n' "\$verified_origin_run_id" >> "\$GITHUB_OUTPUT"/);
  assert.match(publish, /value: \$\{\{ jobs\.package\.outputs\.origin_run_id \}\}/);
  assert.match(release, /ORIGIN_RUN_ID: \$\{\{ needs\.cli\.outputs\.origin_run_id \}\}/);
  assert.match(release, /package provenance workflow run \$ORIGIN_RUN_ID does not match preflight/);
  assert.match(publish, /\.repository == \{[\s\S]*url: "git\+https:\/\/github\.com\/yc-software\/qm\.git"/);
  assert.match(publish, /tar -xOzf "\$expected_tarball" package\/package\.json/);
  assert.match(publish, /\.scripts\.prepack == "npm run build"/);
  assert.match(publish, /prepublishOnly\|postpack\|publish\|postpublish/);
  assert.doesNotMatch(publish, /refusing to adopt an artifact from another job/);
  ordered(publish, "npm run --ignore-scripts=true prepack", "expected_pack=$(npm pack");
  ordered(
    publish,
    'cmp --silent "$expected_tarball" "$confirmation_tarball"',
    'npm_registry publish "$publish_directory"',
  );
  ordered(publish, "Test the built release artifact", "Publish or verify the release candidate");
});

test("credentialless preparation feeds one exact artifact to a fresh publish runner", () => {
  const prepareStart = publish.indexOf("  prepare:");
  const packageStart = publish.indexOf("  package:", prepareStart);
  assert.notEqual(prepareStart, -1);
  assert.notEqual(packageStart, -1);
  const prepare = publish.slice(prepareStart, packageStart);
  const packageJob = publish.slice(packageStart);
  const secretStepStart = packageJob.indexOf("      - name: Publish or verify the release candidate");
  assert.notEqual(secretStepStart, -1);
  const beforeSecrets = packageJob.slice(0, secretStepStart);
  const secretStep = packageJob.slice(secretStepStart);

  assert.match(prepare, /permissions:\n {6}contents: read/);
  assert.doesNotMatch(prepare, /id-token: write|\$\{\{ secrets\./);
  assert.match(prepare, /ref: \$\{\{ inputs\.sha \}\}/);
  assert.doesNotMatch(prepare, /cache: npm/);
  assert.match(prepare, /--workspaces=false ci/);
  assert.match(prepare, /npm run typecheck/);
  assert.match(prepare, /npm run --ignore-scripts=true prepack/);
  assert.match(prepare, /NPM_CONFIG_IGNORE_SCRIPTS: "true"[\s\S]*npm run test:pack/);
  assert.match(prepare, /id: upload\n {8}uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/);
  assert.match(prepare, /name: qm-cli-prepared-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/);
  assert.match(prepare, /compression-level: 0[\s\S]*overwrite: false[\s\S]*retention-days: 7/);
  assert.match(prepare, /artifact_id: \$\{\{ steps\.upload\.outputs\.artifact-id \}\}/);
  assert.match(prepare, /tarball_sha256: \$\{\{ steps\.pack\.outputs\.tarball_sha256 \}\}/);

  assert.match(packageJob, /^ {4}needs: prepare$/m);
  assert.match(packageJob, /permissions:\n {6}contents: read\n {6}id-token: write/);
  assert.match(packageJob, /ref: \$\{\{ inputs\.sha \}\}/);
  assert.doesNotMatch(packageJob, /cache: npm/);
  assert.match(
    packageJob,
    /uses: actions\/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093[\s\S]*artifact-ids: \$\{\{ needs\.prepare\.outputs\.artifact_id \}\}/,
  );
  assert.doesNotMatch(packageJob, /name: qm-cli-prepared-/);
  assert.match(packageJob, /EXPECTED_ARTIFACT_ID: \$\{\{ needs\.prepare\.outputs\.artifact_id \}\}/);
  assert.match(packageJob, /EXPECTED_TARBALL_SHA256: \$\{\{ needs\.prepare\.outputs\.tarball_sha256 \}\}/);
  assert.doesNotMatch(publish, /artifact[_-]digest/);
  assert.match(packageJob, /\[\[ ! "\$EXPECTED_ARTIFACT_ID" =~ \^\[1-9\]\[0-9\]\*\$ \]\]/);
  assert.match(packageJob, /\[\[ ! "\$EXPECTED_TARBALL_SHA256" =~ \^\[0-9a-f\]\{64\}\$ \]\]/);
  assert.doesNotMatch(packageJob, /artifact-ids:[^\n]*(?:\|\||name)/);
  assert.match(packageJob, /actual_tarball_sha256=\$\(sha256sum "\$artifact"/);
  assert.match(packageJob, /\[ "\$actual_tarball_sha256" != "\$EXPECTED_TARBALL_SHA256" \]/);
  assert.match(packageJob, /package_json == 1 && manifest_json == 1/);
  assert.match(packageJob, /prepared artifact contains a link or special entry/);
  assert.match(
    packageJob,
    /segments\[segment\] == "\.npmrc"[\s\S]*segments\[segment\] == "\.git"[\s\S]*segments\[segment\] == "node_modules"/,
  );
  assert.match(packageJob, /cmp --silent "\$artifact" "\$repack_dir\/\$repack_name"/);
  assert.match(packageJob, /checkout_sha=\$\(git rev-parse HEAD\)[\s\S]*"\$checkout_sha" != "\$RELEASE_SHA"/);
  assert.match(packageJob, /package_git_root=\$\(git -C "\$package_dir" rev-parse --show-toplevel\)/);
  assert.match(packageJob, /manifest: \$\{\{ steps\.verify\.outputs\.manifest \}\}/);
  assert.match(publish, /value: \$\{\{ jobs\.package\.outputs\.manifest \}\}/);
  assert.match(publish, /value: \$\{\{ jobs\.package\.outputs\.origin_run_id \}\}/);

  assert.doesNotMatch(beforeSecrets, /\$\{\{ secrets\./);
  assert.doesNotMatch(packageJob, /^ {10}npm (?:run|ci)(?: |$)/m);
  assert.doesNotMatch(packageJob, /npm run test:pack/);
  assert.equal((publish.match(/\$\{\{ secrets\./g) ?? []).length, 2);
  assert.match(secretStep, /working-directory: \$\{\{ runner\.temp \}\}/);
  assert.match(secretStep, /BASH_ENV: \/dev\/null/);
  assert.match(
    secretStep,
    /run: \|\n {10}set -euo pipefail\n {10}npm_token=\$NODE_AUTH_TOKEN\n {10}settings_token=\$RELEASE_SETTINGS_TOKEN\n {10}unset NODE_AUTH_TOKEN RELEASE_SETTINGS_TOKEN/,
  );
  assert.match(
    secretStep,
    /if \[ "\$RELEASE_SHA" != "\$GITHUB_SHA" \] \|\| \[ "\$ORIGIN_RUN_ID" != "\$GITHUB_RUN_ID" \]; then/,
  );
  assert.match(secretStep, /cmp --silent "\$expected_tarball" "\$remote_tarball"/);
  assert.doesNotMatch(secretStep, /^ {10}npm (?:run|ci)(?: |$)/m);
  assert.doesNotMatch(secretStep, /test:pack/);
  assert.doesNotMatch(secretStep, /^ {10}(?:source|\.)\s+/m);
});

test("an extracted exact tarball preserves gitHead when published beneath its checkout", async () => {
  const directory = mkdtempSync(join(tmpdir(), "qm-npm-git-head-"));
  try {
    writeFileSync(
      join(directory, "package.json"),
      JSON.stringify({ name: "@qm-release-test/git-head-probe", version: "1.2.3" }),
    );
    writeFileSync(join(directory, "index.js"), "export {};\n");
    for (const args of [
      ["init", "--quiet"],
      ["config", "user.name", "QM Test"],
      ["config", "user.email", "qm-test@example.com"],
      ["config", "commit.gpgsign", "false"],
      ["add", "."],
      ["commit", "--quiet", "-m", "fixture"],
    ]) {
      const result = spawnSync("git", args, { cwd: directory, encoding: "utf8" });
      assert.equal(result.status, 0, result.stderr);
    }
    const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: directory, encoding: "utf8" }).stdout.trim();
    const packed = spawnSync("npm", ["pack", "--json", "--ignore-scripts=true"], {
      cwd: directory,
      encoding: "utf8",
    });
    assert.equal(packed.status, 0, packed.stderr);
    const tarball = (JSON.parse(packed.stdout) as Array<{ filename: string }>)[0]!.filename;
    const extractRoot = join(directory, "prepared-cli-package");
    mkdirSync(extractRoot);
    const extracted = spawnSync("tar", ["-xzf", tarball, "-C", extractRoot], {
      cwd: directory,
      encoding: "utf8",
    });
    assert.equal(extracted.status, 0, extracted.stderr);
    const packageDirectory = join(extractRoot, "package");
    const repackRoot = join(directory, "repacked");
    mkdirSync(repackRoot);
    const repacked = spawnSync(
      "npm",
      ["pack", packageDirectory, "--json", "--ignore-scripts=true", "--pack-destination", repackRoot],
      { cwd: directory, encoding: "utf8" },
    );
    assert.equal(repacked.status, 0, repacked.stderr);
    const repackedTarball = (JSON.parse(repacked.stdout) as Array<{ filename: string }>)[0]!.filename;
    assert.deepEqual(readFileSync(join(directory, tarball)), readFileSync(join(repackRoot, repackedTarball)));
    const directoryVersion = await capturePublishedVersion(directory, directory);
    const extractedVersion = await capturePublishedVersion(directory, packageDirectory);
    const tarballVersion = await capturePublishedVersion(directory, join(directory, tarball));
    assert.equal(directoryVersion.gitHead, head);
    assert.equal(extractedVersion.gitHead, head);
    assert.equal(tarballVersion.gitHead, undefined);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("release recovery verifies the exact npm attestation bundle", () => {
  for (const workflow of [release, publish]) {
    assert.match(workflow, /attestationBundles\[\][\s\S]*\.bundle/);
    assert.match(workflow, /cosign verify-blob-attestation "\$(?:tarball|remote_tarball)"/);
    assert.match(workflow, /--certificate-github-workflow-sha="\$(?:release_sha|RELEASE_SHA)"/);
    assert.match(workflow, /published_integrity=.*\.dist\.integrity/);
    assert.match(workflow, /tarball_integrity="sha512-\$\(openssl dgst -sha512 -binary/);
    assert.match(workflow, /\(\.registry \| rtrimstr\("\/"\)\) == "https:\/\/registry\.npmjs\.org"/);
    assert.doesNotMatch(workflow, /curl[^\n]*(?:attestations|provenance)/);
  }
});

test("provenance verification stops at the first failed security check", () => {
  const directory = mkdtempSync(join(tmpdir(), "qm-release-verifier-"));
  const marker = join(directory, "accepted");
  try {
    const result = spawnSync(
      "bash",
      [
        "-c",
        'set -euo pipefail; verify_published() { false; printf accepted > "$MARKER"; }; set +e; ( set -euo pipefail; verify_published ); verification_status=$?; set -e; [ "$verification_status" -ne 0 ] && [ ! -e "$MARKER" ]',
      ],
      { encoding: "utf8", env: { ...process.env, MARKER: marker } },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(existsSync(marker), false);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("npm audit accepts the canonical registry shape without weakening the origin", () => {
  const audit = JSON.stringify({ verified: [{ registry: "https://registry.npmjs.org" }] });
  const result = spawnSync("jq", ["-e", '(.verified[0].registry | rtrimstr("/")) == "https://registry.npmjs.org"'], {
    encoding: "utf8",
    input: audit,
  });
  assert.equal(result.status, 0, result.stderr);
});

test("the orchestrator orders images, package staging, release, and promotion", () => {
  assert.match(
    release,
    /^ {2}images:\n[\s\S]*?needs: preflight[\s\S]*?uses: \.\/\.github\/workflows\/release-package\.yml/m,
  );
  assert.match(
    release,
    /^ {2}cli:\n[\s\S]*?needs:\n {6}- preflight\n {6}- images[\s\S]*?uses: \.\/\.github\/workflows\/publish-cli\.yml/m,
  );
  assert.match(release, /^ {2}release:\n[\s\S]*?needs:\n {6}- preflight\n {6}- cli$/m);
  assert.match(release, /MANIFEST: \$\{\{ needs\.cli\.outputs\.manifest \}\}/);
  assert.match(release, /^ {2}image-aliases:\n[\s\S]*?needs:\n {6}- preflight\n {6}- cli\n {6}- release$/m);
  assert.match(release, /^ {2}promote:\n[\s\S]*?needs:\n {6}- preflight\n {6}- image-aliases$/m);
  ordered(release, "  images:", "  cli:");
  ordered(release, "  cli:", "  release:");
  ordered(release, "  release:", "  image-aliases:");
  ordered(release, "  image-aliases:", "  promote:");
});

test("Helm release digests are authoritative and version aliases are retryable conveniences", () => {
  const porter = readFileSync("docs/porter.md", "utf8");
  const helmHelpers = readFileSync("deploy/helm/templates/_helpers.tpl", "utf8");
  const helmDeployment = readFileSync("deploy/helm/templates/deployment.yaml", "utf8");
  const helmValues = readFileSync("deploy/helm/values.yaml", "utf8");

  assert.match(release, /^ {2}image-aliases:\n[\s\S]*?permissions:\n {6}contents: read\n {6}packages: write/m);
  assert.match(release, /printf '%s' "\$MANIFEST" \| jq \. > images\.json/);
  assert.match(release, /images\.json > \/dev\/null/);
  assert.match(release, /releases\/tags\/\$TAG/);
  assert.match(release, /\.immutable == true/);
  assert.match(release, /\.published_at \| strings \| length > 0/);
  assert.match(release, /jq -Sc \. released-images\.json > "\$comparison\/released\.canonical\.json"/);
  assert.match(release, /jq -Sc \. images\.json > "\$comparison\/expected\.canonical\.json"/);
  assert.match(
    release,
    /cmp --silent "\$comparison\/released\.canonical\.json" "\$comparison\/expected\.canonical\.json"/,
  );
  assert.match(release, /release-image-aliases\.sh publish released-images\.json "\$VERSION"/);
  assert.match(releaseAliases, /for service in "\$\{SERVICES\[@\]\}"; do/);
  assert.match(releaseAliases, /HTTP_STATUS" = 404/);
  assert.match(releaseAliases, /\.code == "MANIFEST_UNKNOWN"/);
  assert.doesNotMatch(releaseAliases, /imagetools create|grep -Eqi/);
  assert.match(releaseAliases, /body_digest="sha256:\$\(sha256sum/);
  assert.match(releaseAliases, /--request PUT/);
  assert.match(releaseAliases, /--data-binary "@\$source_prefix\.body"/);
  assert.match(releaseAliases, /--header 'If-None-Match: \*'/);
  assert.match(releaseAliases, /require_create_precondition/);
  assert.match(releaseAliases, /\[ "\$probe_status" != 412 \]/);
  assert.match(releaseAliases, /alias_state "\$repository_path" "\$token" "\$digest"/);
  assert.match(releaseAliases, /\$parts\[0\] == \("ghcr\.io\/yc-software\/qm\/" \+ \$service\)/);
  assert.match(releaseAliases, /length == 1/);
  const requestManifest = /request_manifest\(\) \{([\s\S]*?)\n\}/.exec(releaseAliases)?.[1] ?? "";
  assert.doesNotMatch(requestManifest, /set [+-]e/);
  assert.match(requestManifest, /if HTTP_STATUS=\$\(curl/);
  assert.match(porter, /images\.json > qm-images\.values\.json/);
  assert.match(porter, /digests: \(\.services \| with_entries/);
  assert.match(porter, /repository\/service@sha256/);
  assert.match(porter, /mutable convenience pointers/);
  assert.match(porter, /explicit\ncompatibility and source-build fallbacks/);
  assert.match(porter, /never infers an image tag from\n`appVersion`/);
  assert.doesNotMatch(porter, /published tags are commit SHAs/);
  assert.match(helmValues, /^ {2}digests:\n {4}core: ""/m);
  assert.match(helmHelpers, /printf "%s@%s" \$repository \$digest/);
  assert.match(helmHelpers, /image\.digests\.%s or an explicit image tag is required/);
  assert.doesNotMatch(helmDeployment, /Chart\.AppVersion/);
  ordered(release, "Create or complete the GitHub release", "Publish exact release image aliases");
  ordered(release, "Publish exact release image aliases", "Promote the published release");
  ordered(images, "Assemble signed image manifest", "Reject conflicting release image aliases");
});

test("image alias reconciliation handles absent, exact, and conflicting registry state", () => {
  const absentCheck = runAliasScenario("check", "absent");
  assert.equal(absentCheck.result.status, 0, absentCheck.result.stderr);
  assert.equal(absentCheck.puts.length, 0);

  const absentPublish = runAliasScenario("publish", "absent");
  assert.equal(absentPublish.result.status, 0, absentPublish.result.stderr);
  assert.equal(absentPublish.puts.length, 7);
  assert.ok(absentPublish.tokenScopes.every((scope) => scope.endsWith(":pull,push")));

  const unsupportedPublish = runAliasScenario("publish", "absent", currentManifestTemplate, "", false);
  assert.equal(unsupportedPublish.result.status, 1, unsupportedPublish.result.stderr);
  assert.equal(unsupportedPublish.puts.length, 0);
  assert.match(unsupportedPublish.result.stderr, /does not enforce create-only manifest writes/);

  const absentVerify = runAliasScenario("verify", "absent");
  assert.equal(absentVerify.result.status, 1, absentVerify.result.stderr);
  assert.equal(absentVerify.puts.length, 0);
  assert.match(absentVerify.result.stderr, /does not exist at the released digest/);
  assert.ok(absentVerify.tokenScopes.every((scope) => scope.endsWith(":pull")));

  for (const mode of ["check", "publish", "verify"] as const) {
    const exact = runAliasScenario(mode, "exact");
    assert.equal(exact.result.status, 0, exact.result.stderr);
    assert.equal(exact.puts.length, 0);
    assert.ok(exact.tokenScopes.every((scope) => scope.endsWith(mode === "publish" ? ":pull,push" : ":pull")));

    const conflict = runAliasScenario(mode, "conflict");
    assert.equal(conflict.result.status, 1, conflict.result.stderr);
    assert.equal(conflict.puts.length, 0);
    assert.match(conflict.result.stderr, /is not safely publishable/);
  }

  const previous = runAliasScenario("verify", "exact", previousManifestTemplate);
  assert.equal(previous.result.status, 0, previous.result.stderr);
  assert.equal(previous.tokenScopes.length, 6);

  const invalidManifests: ImageManifest[] = [
    { ...currentManifestTemplate, services: {} },
    {
      ...currentManifestTemplate,
      services: { "../core": currentManifestTemplate.services.core! },
    },
    {
      ...currentManifestTemplate,
      services: { core: currentManifestTemplate.services.admin! },
    },
    {
      ...currentManifestTemplate,
      services: {
        core: currentManifestTemplate.services.core!.replace("ghcr.io/yc-software/qm", "ghcr.io/foreign/qm"),
      },
    },
  ];
  for (const manifest of invalidManifests) {
    const rejected = runAliasScenario("check", "exact", manifest);
    assert.equal(rejected.result.status, 1, rejected.result.stderr);
    assert.equal(rejected.tokenScopes.length, 0);
  }

  const concatenated = runAliasScenario(
    "check",
    "exact",
    currentManifestTemplate,
    JSON.stringify(currentManifestTemplate),
  );
  assert.equal(concatenated.result.status, 1, concatenated.result.stderr);
  assert.equal(concatenated.tokenScopes.length, 0);
});

test("tag and draft release reconciliation is idempotent and fail closed", () => {
  const finalizationStart = release.indexOf("      - name: Create or complete the GitHub release");
  const finalizationEnd = release.indexOf("  image-aliases:", finalizationStart);
  const finalization = release.slice(finalizationStart, finalizationEnd);
  const promotion = release.slice(release.indexOf("      - name: Promote the published release"));
  assert.match(release, /manifest_hash=\$\(jq -Sc \. images\.json \| sha256sum/);
  assert.match(release, /QM release provenance/);
  assert.equal((release.match(/Bootstrap for QM 0\.1\.7 and earlier:/g) ?? []).length, 2);
  assert.equal((release.match(/SECURITY\.md#one-time-bootstrap-from-qm-017-and-earlier/g) ?? []).length, 2);
  assert.equal(
    (release.match(/Bootstrap only from this immutable annotated tag after verifying its repository/g) ?? []).length,
    2,
  );
  assert.equal((release.match(/release notes and mutable main are not trust sources/g) ?? []).length, 2);
  assert.equal((release.match(/Never use deployment npm, npm exec, npx, or package scripts/g) ?? []).length, 2);
  assert.doesNotMatch(release, /<!--/);
  assert.match(release, /-f message="\$marker"/);
  assert.match(release, /-f object="\$RELEASE_SHA"/);
  assert.match(release, /\[ "\$tag_type" != tag \]/);
  assert.match(release, /\.message == \$marker[\s\S]*\.object\.type == "commit"[\s\S]*\.object\.sha == \$sha/);
  assert.match(release, /load_releases\(\)[\s\S]*releases\?per_page=100/);
  assert.match(release, /load_release\(\)[\s\S]*load_releases/);
  assert.match(release, /release_json=\$\(load_release\)[\s\S]*gh release create/);
  assert.match(release, /--verify-tag/);
  assert.match(release, /--draft/);
  assert.match(release, /\.author\.login == "github-actions\[bot\]"/);
  assert.equal((finalization.match(/\.name == \$tag/g) ?? []).length, 2);
  assert.equal((finalization.match(/\.body \| startswith\(\$marker\)/g) ?? []).length, 2);
  assert.doesNotMatch(promotion, /\.body \| startswith\(\$marker\)|\.name == \$tag/);
  assert.match(release, /\.draft == true\s+and \.immutable == false/);
  assert.match(release, /\.draft == false and \.immutable == true/);
  assert.match(release, /gh release upload "\$TAG"/);
  assert.match(release, /published with an incomplete image manifest asset/);
  assert.match(release, /published without its image manifest asset/);
  assert.match(release, /--method DELETE "repos\/\$GITHUB_REPOSITORY\/releases\/assets\/\$asset_id"/);
  assert.doesNotMatch(release, /release_retry|\.conclusion|--clobber/);
  assert.match(
    finalization,
    /\.tag_name == \$tag\n {13}and \.name == \$tag\n {13}and \(\.body \| startswith\(\$marker\)\)[\s\S]*?\.draft == false and \.immutable == true/,
  );
  assert.match(release, /Accept: application\/octet-stream/);
  assert.match(release, /--method PATCH "repos\/\$GITHUB_REPOSITORY\/releases\/\$release_id"/);
  assert.match(
    finalization,
    /validate_release_asset "\$release_json"\n {12}require_release_controls\n {12}require_immutable_releases\n {12}gh api --method PATCH[\s\S]*?\n {10}validate_release_tag\n {10}release_json=\$\(load_release\)/,
  );
  assert.match(release, /\.draft == false[\s\S]*\.prerelease == false/);
  assert.match(release, /\.immutable == true/);
  assert.match(release, /\(\.assets \| length == 1\)[\s\S]*\.assets\[0\]\.name == "images\.json"/);
  assert.match(release, /jq -Sc \. "\$downloaded\/images\.json" > "\$downloaded\/downloaded\.canonical\.json"/);
  assert.match(release, /jq -Sc \. images\.json > "\$downloaded\/expected\.canonical\.json"/);
  assert.match(
    release,
    /cmp --silent "\$downloaded\/downloaded\.canonical\.json" "\$downloaded\/expected\.canonical\.json"/,
  );
  ordered(finalization, 'validate_release_asset "$release_json"', "latest_inventory=$(load_releases)");
  ordered(
    finalization,
    "latest_inventory=$(load_releases)",
    "if printf '%s' \"$release_json\" | jq -e '.draft' > /dev/null; then",
  );
  assert.match(
    finalization,
    /\.assets\[0\]\.uploader\.login == "github-actions\[bot\]"' > \/dev\/null\n {10}validate_release_asset "\$release_json"/,
  );
  assert.doesNotMatch(release, /\$\(jq -Sc \. [^)]+\)" != "\$\(jq -Sc/);
});

test("release asset equality rejects malformed trailing data", () => {
  const directory = mkdtempSync(join(tmpdir(), "qm-release-asset-"));
  const expected = join(directory, "expected.json");
  const downloaded = join(directory, "downloaded.json");
  try {
    writeFileSync(expected, '{"services":{}}\n');
    writeFileSync(downloaded, '{"services":{}}\nnot-json\n');
    const result = spawnSync(
      "bash",
      [
        "-c",
        'set -euo pipefail; jq -Sc . "$DOWNLOADED" > "$DIRECTORY/downloaded.canonical.json"; jq -Sc . "$EXPECTED" > "$DIRECTORY/expected.canonical.json"; cmp --silent "$DIRECTORY/downloaded.canonical.json" "$DIRECTORY/expected.canonical.json"',
      ],
      {
        encoding: "utf8",
        env: { ...process.env, DIRECTORY: directory, DOWNLOADED: downloaded, EXPECTED: expected },
      },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /parse error/);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("GitHub Latest advances for a new release and never for an older recovery", () => {
  const functionMatch = /^( {10}newest_public_version\(\) \{[\s\S]*?^ {10}\})/m.exec(release);
  assert.ok(functionMatch);
  const policyStart = release.indexOf("          latest_inventory=$(load_releases)");
  const policyEnd = release.indexOf("          release_id=", policyStart);
  assert.notEqual(policyStart, -1);
  assert.notEqual(policyEnd, -1);
  const newestPublicVersion = functionMatch[1]!.replace(/^ {10}/gm, "");
  const policy = release.slice(policyStart, policyEnd).replace(/^ {10}/gm, "");
  const evaluate = (target: string, releases: unknown[]) =>
    spawnSync(
      "bash",
      [
        "-c",
        `set -euo pipefail
load_releases() { printf '%s' "$RELEASES"; }
${newestPublicVersion}
VERSION="$TARGET"
${policy}
printf '%s\n' "$make_latest"`,
      ],
      {
        encoding: "utf8",
        env: { ...process.env, RELEASES: JSON.stringify(releases), TARGET: target },
      },
    );
  const published = (version: string) => ({ draft: false, prerelease: false, tag_name: "v" + version });

  for (const releases of [[], [published("0.9.0")], [published("1.0.0")]]) {
    const advance = evaluate("1.0.0", releases);
    assert.equal(advance.status, 0, advance.stderr);
    assert.equal(advance.stdout.trim(), "true");
  }

  const recover = evaluate("1.0.0", [
    published("2.0.0"),
    { draft: true, prerelease: false, tag_name: "v3.0.0" },
    { draft: false, prerelease: true, tag_name: "v4.0.0" },
  ]);
  assert.equal(recover.status, 0, recover.stderr);
  assert.equal(recover.stdout.trim(), "false");

  const malformed = evaluate("1.0.0", [{ draft: "false", prerelease: false, tag_name: "v9.0.0" }, published("1.0.0")]);
  assert.notEqual(malformed.status, 0);

  assert.match(release, /-F draft=false\s+\\\n\s+-f make_latest="\$make_latest"/);
  assert.match(release, /elif \[ "\$make_latest" = true \]; then/);
  assert.match(release, /repos\/\$GITHUB_REPOSITORY\/releases\/latest/);
  assert.match(release, /expected_latest_tag="v\$final_newest"/);
  ordered(release, "latest_inventory=$(load_releases)", '-f make_latest="$make_latest"');
  ordered(release, '-f make_latest="$make_latest"', "final_inventory=$(load_releases)");
  ordered(release, "final_inventory=$(load_releases)", 'gh api "repos/$GITHUB_REPOSITORY/releases/latest"');
});

test("a legacy mutable GitHub Latest is accepted only when it is not the recovery target", () => {
  const latestPredicate =
    ".tag_name == $tag and .draft == false and .prerelease == false and (($tag != $target) or .immutable == true)";
  const workflowPredicate =
    /\.tag_name == \$tag\s+and \.draft == false\s+and \.prerelease == false\s+and \(\(\$tag != \$target\) or \.immutable == true\)/g;
  assert.equal((release.match(workflowPredicate) ?? []).length, 2);
  const evaluate = (latest: unknown, expectedTag: string, targetTag: string) =>
    spawnSync("jq", ["-e", "--arg", "tag", expectedTag, "--arg", "target", targetTag, latestPredicate], {
      encoding: "utf8",
      input: JSON.stringify(latest),
    });
  const mutableLatest = { tag_name: "v2.0.0", draft: false, prerelease: false, immutable: false };
  const immutableTarget = { tag_name: "v1.0.0", draft: false, prerelease: false, immutable: true };
  const mutableTarget = { ...immutableTarget, immutable: false };
  assert.equal(evaluate(mutableLatest, "v2.0.0", "v1.0.0").status, 0);
  assert.equal(evaluate(immutableTarget, "v1.0.0", "v1.0.0").status, 0);
  assert.notEqual(evaluate(mutableTarget, "v1.0.0", "v1.0.0").status, 0);
});

test("npm latest moves only after the matching completed release", () => {
  const promotion = release.slice(release.indexOf("      - name: Promote the published release"));
  assert.match(promotion, /npm_token=\$NODE_AUTH_TOKEN\n {10}unset NODE_AUTH_TOKEN/);
  assert.match(release, /^ {2}promote:[\s\S]*?permissions:\n {6}contents: read\n {6}packages: read/m);
  assert.match(
    release,
    /published=\$\(npm_registry view "@yc-software\/qm@\$VERSION" version deprecated gitHead --json/,
  );
  assert.match(release, /\[ "\$published_git_head" != "\$RELEASE_SHA" \]/);
  assert.match(release, /verify_promotion_inputs\(\)/);
  assert.match(release, /npm_registry pack[\s\S]*"@yc-software\/qm@\$VERSION"[\s\S]*--min-release-age=0/);
  assert.match(release, /tar -xOzf "\$package_tarball" package\/manifest\.json/);
  assert.match(release, /repos\/\$GITHUB_REPOSITORY\/releases\/tags\/\$TAG/);
  assert.match(release, /repos\/\$GITHUB_REPOSITORY\/releases\/assets\/\$asset_id/);
  assert.match(release, /\.immutable == true/);
  assert.match(promotion, /marker=\$\{marker%\$'\\n'\}/);
  assert.match(
    promotion,
    /validate_release_tag\(\)[\s\S]*?git\/ref\/tags\/\$TAG[\s\S]*?\.message == \$marker[\s\S]*?\.object\.sha == \$sha/,
  );
  assert.doesNotMatch(promotion, /\.body \| startswith\(\$marker\)|\.name == \$tag/);
  assert.match(
    release,
    /cmp --silent "\$verification\/package\.canonical\.json" "\$verification\/release\.canonical\.json"/,
  );
  assert.match(release, /release-image-aliases\.sh verify "\$verification\/release-images\.json" "\$VERSION"/);
  assert.match(
    promotion,
    /scripts\/release-image-aliases\.sh verify[\s\S]*?validate_release_tag[\s\S]*?verify_github_latest/,
  );
  assert.match(release, /read_packument\(\)[\s\S]*Cache-Control: no-cache/);
  assert.match(release, /all\(\."dist-tags"\[\];[\s\S]*\$packument\.versions \| has\(\$version\)\)/);
  assert.match(release, /newest_other_stable_tag\(\)[\s\S]*\.key != "latest" and \.key != "release-candidate"/);
  assert.match(release, /for attempt in \$\(seq 1 5\); do/);
  assert.match(release, /NODE_AUTH_TOKEN="\$npm_token" npm_registry dist-tag add "@yc-software\/qm@\$VERSION" latest/);
  assert.match(
    promotion,
    /verify_promotion_inputs\n {12}before_write=\$\(read_packument "\$attempt-before-write"\)[\s\S]*?mutation_input=\$\(read_packument "\$attempt-mutation"\)\n {12}validate_packument "\$mutation_input"\n {12}verify_github_latest\n {12}evaluate_latest_state "\$mutation_input"[\s\S]*?npm_registry dist-tag add "@yc-software\/qm@\$VERSION" latest/,
  );
  ordered(
    release,
    'npm_registry dist-tag add "@yc-software/qm@$VERSION" latest',
    'after=$(read_packument "$attempt-after")',
  );
  assert.match(release, /latest_status=\$\?[\s\S]*after=\$\(read_packument/);
  assert.match(
    release,
    /verified older QM \$VERSION without moving npm latest away from GitHub Latest \$EXPECTED_GITHUB_LATEST_TAG/,
  );
  assert.match(
    release,
    /stable npm dist-tag points to newer QM \$conflicting; only the release workflow may advance latest/,
  );
  assert.equal((release.match(/conflicting=\$\(newest_other_stable_tag/g) ?? []).length, 1);
  assert.match(
    promotion,
    /after=\$\(read_packument "\$attempt-after"\)\n {12}validate_packument "\$after"\n {12}verify_github_latest\n {12}evaluate_latest_state "\$after"/,
  );
  assert.match(
    promotion,
    /npm latest QM \$CURRENT_NPM_LATEST does not match GitHub Latest \$EXPECTED_GITHUB_LATEST_TAG/,
  );
  const mutationStart = promotion.indexOf('mutation_input=$(read_packument "$attempt-mutation")');
  const mutationEnd = promotion.indexOf('npm_registry dist-tag add "@yc-software/qm@$VERSION" latest', mutationStart);
  assert.notEqual(mutationStart, -1);
  assert.notEqual(mutationEnd, -1);
  const mutationWindow = promotion.slice(mutationStart, mutationEnd);
  assert.equal((mutationWindow.match(/read_packument/g) ?? []).length, 1);
  assert.equal((mutationWindow.match(/verify_github_latest/g) ?? []).length, 1);
  ordered(mutationWindow, 'mutation_input=$(read_packument "$attempt-mutation")', "verify_github_latest");
  ordered(mutationWindow, "verify_github_latest", 'evaluate_latest_state "$mutation_input"');
  assert.doesNotMatch(release, /greatest_available|@yc-software\/qm@\$target/);
  assert.equal(
    (`${images}\n${publish}\n${release}`.match(/dist-tag add "@yc-software\/qm@\$VERSION" latest/g) ?? []).length,
    1,
  );
  assert.match(
    release,
    /if \[ "\$candidate" = "\$VERSION" \]; then[\s\S]*NODE_AUTH_TOKEN="\$npm_token" npm_registry dist-tag rm/,
  );
  assert.doesNotMatch(promotion, /^ {12}npm_registry dist-tag/m);
  assert.match(release, /candidate_remove_status=\$\?[\s\S]*cleaned=\$\(read_packument/);
  ordered(release, "  image-aliases:", "  promote:");
});

test("the serialized release is the repository's only npm tag writer", () => {
  const workflows = Object.fromEntries(
    readdirSync(".github/workflows")
      .filter((file) => file.endsWith(".yml"))
      .map((file) => [file, readFileSync(join(".github/workflows", file), "utf8")]),
  );
  const tokenConsumers = Object.entries(workflows)
    .filter(([, workflow]) => workflow.includes("NPM_TOKEN"))
    .map(([file]) => file)
    .sort();
  const tagWriters = Object.entries(workflows)
    .filter(([, workflow]) => /npm_registry dist-tag (?:add|rm)/.test(workflow))
    .map(([file]) => file)
    .sort();
  const latestWriters = Object.entries(workflows)
    .filter(([, workflow]) => /dist-tag add "@yc-software\/qm@\$VERSION" latest/.test(workflow))
    .map(([file]) => file);

  assert.deepEqual(tokenConsumers, ["publish-cli.yml", "release.yml"]);
  assert.deepEqual(tagWriters, ["publish-cli.yml", "release.yml"]);
  assert.deepEqual(latestWriters, ["release.yml"]);
  assert.equal(
    Object.values(workflows).filter((workflow) => workflow.includes("uses: ./.github/workflows/publish-cli.yml"))
      .length,
    1,
  );
});

test("the CLI package manifest pins every shipped image", () => {
  const manifest = JSON.parse(readFileSync("cli/manifest.json", "utf8")) as {
    sandboxBase: string;
    services: Record<string, string>;
  };
  assert.deepEqual(Object.keys(manifest.services).sort(), [
    "admin",
    "auth",
    "core",
    "egress-proxy",
    "portal",
    "web-ui",
  ]);
  assert.ok(
    [manifest.sandboxBase, ...Object.values(manifest.services)].every((ref) => ref.startsWith("registry.invalid/")),
  );
  assert.equal(existsSync(".github/workflows/release-images.yml"), false);
  assert.equal(existsSync(".github/workflows/publish-images.yml"), false);
  assert.equal(existsSync(".github/workflows/publish-sandbox-base.yml"), false);
});

test("only release finalization writes repository contents", () => {
  assert.equal((release.match(/^ {6}contents: write$/gm) ?? []).length, 1);
  assert.match(release, /^ {2}release:\n[\s\S]*?permissions:\n {6}contents: write/m);
  assert.doesNotMatch(release, /packages: write\n {4}secrets: inherit/);
});

test("every external action is immutable", () => {
  for (const workflow of [images, publish, release]) {
    for (const line of workflow.split("\n").filter((candidate) => candidate.trimStart().startsWith("- uses:"))) {
      const reference = line.slice(line.indexOf("uses:") + "uses:".length).trim();
      if (reference.startsWith("./")) continue;
      assert.match(reference, /^[^@]+@[0-9a-f]{40}$/);
    }
  }
});
