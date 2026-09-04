import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import vm from "node:vm";
import {
  FAILURE_TTL_MS,
  SUCCESS_TTL_MS,
  compareVersions,
  createUpdateChecker,
  fetchUpdateStatus,
  resolveCurrentQmVersion,
} from "../src/update-check.ts";

const response = (body: unknown, status = 200) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), { status });

function withPackageManifest(value: unknown, run: (url: URL) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "qm-admin-version-"));
  const path = join(dir, "qm-package.json");
  try {
    writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
    run(pathToFileURL(path));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("Admin release identity accepts a valid non-empty environment value outside production", () => {
  withPackageManifest({ name: "@yc-software/qm", version: "1.2.3" }, (url) => {
    assert.equal(resolveCurrentQmVersion("4.5.6", url, "development"), "4.5.6");
    assert.equal(resolveCurrentQmVersion("4.5.6-rc.1", url, "test"), undefined);
  });
});

test("Admin release identity ignores valid and invalid environment values in production", () => {
  withPackageManifest({ name: "@yc-software/qm", version: "1.2.3" }, (url) => {
    assert.equal(resolveCurrentQmVersion("4.5.6", url, "production"), "1.2.3");
    assert.equal(resolveCurrentQmVersion("4.5.6-rc.1", url, "production"), "1.2.3");
  });
});

test("Admin release identity falls back to the baked package manifest", () => {
  withPackageManifest({ name: "@yc-software/qm", version: "1.2.3" }, (url) => {
    assert.equal(resolveCurrentQmVersion("", url), "1.2.3");
    assert.equal(resolveCurrentQmVersion(undefined, url), "1.2.3");
  });
});

test("invalid or missing baked Admin package identity disables update notices", () => {
  const invalid = [
    "not json",
    {},
    { name: "qm", version: "1.2.3" },
    { name: "@yc-software/qm", version: "1.2" },
    { name: "@yc-software/qm", version: "1.2.3-rc.1" },
  ];
  for (const value of invalid) {
    withPackageManifest(value, (url) => assert.equal(resolveCurrentQmVersion(undefined, url), undefined));
  }
  assert.equal(resolveCurrentQmVersion(undefined, new URL("file:///missing/qm-package.json")), undefined);
});

test("stable QM versions compare without numeric precision loss", () => {
  assert.equal(compareVersions("0.1.9", "0.1.10"), -1);
  assert.equal(compareVersions("1.0.0", "0.99.99"), 1);
  assert.equal(compareVersions("1.0.0", "1.0.0"), 0);
  assert.equal(compareVersions("9007199254740993.0.0", "9007199254740992.999.999"), 1);
  for (const invalid of ["v1.2.3", "1.2", "1.2.3-rc.1", "1.2.3+build", "01.2.3", "1.2.3 "]) {
    assert.throws(() => compareVersions(invalid, "1.2.3"), /invalid stable QM version/);
  }
});

test("a newly promoted stable release is available immediately from the constant-size manifest", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const status = await fetchUpdateStatus("0.1.9", (async (input, init) => {
    requests.push({ url: String(input), init });
    return response({ version: "0.2.0" });
  }) as typeof fetch);

  assert.equal(requests[0]?.url, "https://registry.npmjs.org/@yc-software%2fqm/latest");
  assert.equal(new Headers(requests[0]?.init?.headers).get("accept"), "application/json");
  assert.deepEqual(status, {
    currentVersion: "0.1.9",
    latestVersion: "0.2.0",
    updateAvailable: true,
    updateCommand: "node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version 0.2.0",
    releaseUrl: "https://github.com/yc-software/qm/releases/tag/v0.2.0",
  });
});

test("the promoted manifest must identify a non-deprecated stable release", async (t) => {
  const invalid = [
    null,
    {},
    { version: 2 },
    { version: "0.2" },
    { version: "0.2.0-rc.1" },
    { version: "0.2.0+build" },
    { version: "00.2.0" },
    { version: "0.2.0", deprecated: "withdrawn" },
    { version: "0.2.0", deprecated: "" },
  ];
  for (const metadata of invalid) {
    await t.test(JSON.stringify(metadata), async () => {
      await assert.rejects(fetchUpdateStatus("0.1.9", async () => response(metadata)));
    });
  }
  await assert.rejects(
    fetchUpdateStatus("0.1.9", async () => response("unavailable", 503)),
    /npm registry returned 503/,
  );
});

test("an invalid current release identity disables checks without a registry request", async () => {
  let calls = 0;
  const fetcher = (async () => {
    calls++;
    return response({ version: "0.2.0" });
  }) as typeof fetch;
  for (const currentVersion of [undefined, "", "0.1.9-rc.1", "v0.1.9", "00.1.9"]) {
    assert.equal(await createUpdateChecker(currentVersion, { fetcher })(), null);
  }
  assert.equal(calls, 0);
  await assert.rejects(fetchUpdateStatus("0.1.9-rc.1", fetcher), /invalid current stable QM version/);
  assert.equal(calls, 0);
});

test("successful checks are shared until the five-minute cache expires", async () => {
  let now = 1_000;
  let calls = 0;
  const checker = createUpdateChecker("0.1.9", {
    now: () => now,
    fetcher: async () => response({ version: calls++ === 0 ? "0.2.0" : "0.3.0" }),
  });

  const first = await checker();
  assert.equal(first?.latestVersion, "0.2.0");
  assert.deepEqual(await checker(), first);
  now += SUCCESS_TTL_MS - 1;
  assert.deepEqual(await checker(), first);
  assert.equal(calls, 1);
  now += 1;
  assert.equal((await checker())?.latestVersion, "0.3.0");
  assert.equal(calls, 2);
});

test("concurrent checks share one registry request", async () => {
  let calls = 0;
  let resolveResponse: ((value: Response) => void) | undefined;
  const checker = createUpdateChecker("0.1.9", {
    fetcher: (async () => {
      calls++;
      return new Promise<Response>((resolve) => {
        resolveResponse = resolve;
      });
    }) as typeof fetch,
  });

  const first = checker();
  const second = checker();
  assert.equal(calls, 1);
  resolveResponse?.(response({ version: "0.2.0" }));
  assert.deepEqual(await first, await second);
  assert.equal(calls, 1);
});

test("cold rate limits are shared briefly and retry after thirty seconds", async () => {
  let now = 1_000;
  let calls = 0;
  let available = false;
  const checker = createUpdateChecker("0.1.9", {
    now: () => now,
    fetcher: async () => {
      calls++;
      return available ? response({ version: "0.2.0" }) : response("unavailable", 429);
    },
  });

  const failed = await Promise.allSettled([checker(), checker()]);
  assert.deepEqual(
    failed.map((result) => result.status),
    ["rejected", "rejected"],
  );
  assert.equal(calls, 1);
  await assert.rejects(checker(), /npm registry returned 429/);
  assert.equal(calls, 1);
  now += FAILURE_TTL_MS;
  available = true;
  assert.equal((await checker())?.latestVersion, "0.2.0");
  assert.equal(calls, 2);
});

test("a current status stays available through an outage and later discovers a release", async () => {
  let now = 1_000;
  let calls = 0;
  let version: string | null = "0.2.0";
  const checker = createUpdateChecker("0.2.0", {
    now: () => now,
    fetcher: async () => {
      calls++;
      return version ? response({ version }) : response("unavailable", 408);
    },
  });

  const initial = await checker();
  assert.equal(initial?.updateAvailable, false);
  now += SUCCESS_TTL_MS;
  version = null;
  assert.deepEqual(await checker(), initial);
  assert.deepEqual(await checker(), initial);
  assert.equal(calls, 2);
  now += FAILURE_TTL_MS;
  version = "0.3.0";
  const recovered = await checker();
  assert.equal(recovered?.latestVersion, "0.3.0");
  assert.equal(recovered?.updateAvailable, true);
  assert.equal(calls, 3);
});

test("an available update is hidden when its cached registry status cannot be refreshed", async () => {
  let now = 1_000;
  let calls = 0;
  const checker = createUpdateChecker("0.1.9", {
    now: () => now,
    fetcher: async () => {
      calls++;
      return calls === 1 ? response({ version: "0.2.0" }) : response("unavailable", 503);
    },
  });

  assert.equal((await checker())?.updateAvailable, true);
  now += SUCCESS_TTL_MS;
  await assert.rejects(checker(), /npm registry returned 503/);
  await assert.rejects(checker(), /npm registry returned 503/);
  assert.equal(calls, 2);
});

test("semantic release failures never reuse a stale update", async (t) => {
  const invalidResponses = [
    () => response({ version: "0.3.0", deprecated: "withdrawn" }),
    () => response({ version: "0.3.0-rc.1" }),
    () => response("{"),
    () => response("missing", 404),
    () => ({ ok: false, status: 600 }) as Response,
  ];
  for (const invalidResponse of invalidResponses) {
    await t.test(String(invalidResponses.indexOf(invalidResponse)), async () => {
      let now = 1_000;
      let calls = 0;
      const checker = createUpdateChecker("0.1.9", {
        now: () => now,
        fetcher: async () => {
          calls++;
          return calls === 1 ? response({ version: "0.2.0" }) : invalidResponse();
        },
      });
      await checker();
      now += SUCCESS_TTL_MS;
      await assert.rejects(checker());
      await assert.rejects(checker());
      assert.equal(calls, 2);
    });
  }
});

test("a semantic failure invalidates stale status before a later transport outage", async () => {
  let now = 1_000;
  let calls = 0;
  const checker = createUpdateChecker("0.1.9", {
    now: () => now,
    fetcher: async () => {
      calls++;
      if (calls === 1) return response({ version: "0.2.0" });
      if (calls === 2) return response({ version: "0.3.0", deprecated: "withdrawn" });
      throw new TypeError("fetch failed");
    },
  });
  await checker();
  now += SUCCESS_TTL_MS;
  await assert.rejects(checker(), /deprecated/);
  now += FAILURE_TTL_MS;
  await assert.rejects(checker(), /npm registry request failed/);
  assert.equal(calls, 3);
});

const adminHtml = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
const updateScriptStart = adminHtml.indexOf("      const UPDATE_REFRESH_INTERVAL_MS");
const updateScriptEnd = adminHtml.indexOf("      async function openWebUiAs", updateScriptStart);
const updateScript = adminHtml.slice(updateScriptStart, updateScriptEnd);

interface UiResult {
  ok: boolean;
  status: number;
  data: unknown;
}

function updateStatus(version: string, updateAvailable = true): UiResult {
  return {
    ok: true,
    status: 200,
    data: {
      currentVersion: "0.1.9",
      latestVersion: version,
      updateAvailable,
      updateCommand: `node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version ${version}`,
      releaseUrl: `https://github.com/yc-software/qm/releases/tag/v${version}`,
    },
  };
}

function updateUiHarness(initialResult: UiResult = updateStatus("0.2.0")) {
  const elements = new Map<string, Record<string, any>>();
  const listeners = new Map<string, () => void>();
  const documentState: Record<string, any> = {
    activeElement: null,
    hidden: false,
    addEventListener: (name: string, listener: () => void) => listeners.set(name, listener),
  };
  const element = (id: string) => {
    if (!elements.has(id)) {
      const classes = new Set<string>(["hidden"]);
      const attributes = new Map<string, string>();
      const value: Record<string, any> = {
        id,
        href: "",
        selected: false,
        textContent: "",
        value: "",
        classList: {
          add: (...names: string[]) => names.forEach((name) => classes.add(name)),
          contains: (name: string) => classes.has(name),
          remove: (...names: string[]) => names.forEach((name) => classes.delete(name)),
        },
        contains: (candidate: Record<string, unknown> | null) => candidate?.id?.toString().startsWith("release-alert"),
        focus: () => {
          documentState.activeElement = value;
        },
        getAttribute: (name: string) => attributes.get(name) ?? null,
        removeAttribute: (name: string) => attributes.delete(name),
        select: () => {
          value.selected = true;
        },
        setAttribute: (name: string, attributeValue: string) => attributes.set(name, attributeValue),
      };
      elements.set(id, value);
    }
    return elements.get(id)!;
  };
  let apiHandler = async (_signal?: AbortSignal): Promise<UiResult> => initialResult;
  let copyResult = true;
  const apiCalls: Array<[string, string]> = [];
  const copyCalls: string[] = [];
  const timers: Array<{ callback: () => void; cleared: boolean; delay: number; id: number }> = [];
  const context = vm.createContext({
    $: element,
    AbortController,
    Date,
    api: async (method: string, path: string, _body: unknown, signal?: AbortSignal) => {
      apiCalls.push([method, path]);
      return apiHandler(signal);
    },
    clearTimeout: (id: number | null) => {
      const timer = timers.find((candidate) => candidate.id === id);
      if (timer) timer.cleared = true;
    },
    copyText: async (text: string) => {
      copyCalls.push(text);
      return copyResult;
    },
    document: documentState,
    setTimeout: (callback: () => void, delay: number) => {
      const timer = { callback, cleared: false, delay, id: timers.length + 1 };
      timers.push(timer);
      return timer.id;
    },
  });
  vm.runInContext(updateScript, context);
  return {
    apiCalls,
    context,
    copyCalls,
    document: documentState,
    element,
    listeners,
    setApiHandler: (handler: (signal?: AbortSignal) => Promise<UiResult>) => {
      apiHandler = handler;
    },
    setCopyResult: (value: boolean) => {
      copyResult = value;
    },
    timers,
  };
}

function activeTimerDelays(harness: ReturnType<typeof updateUiHarness>): number[] {
  return harness.timers.filter((timer) => !timer.cleared).map((timer) => timer.delay);
}

async function loadUpdate(harness: ReturnType<typeof updateUiHarness>): Promise<void> {
  await vm.runInContext("updateRefreshActive = true; loadUpdateAlert()", harness.context);
}

test("the update UI contains only a read-only notification flow", () => {
  assert.ok(updateScriptStart >= 0 && updateScriptEnd > updateScriptStart);
  assert.match(adminHtml, /<input[\s\S]*?id="release-alert-command"[\s\S]*?readonly[\s\S]*?\/>/);
  assert.match(adminHtml, /id="release-alert-state" role="status" aria-live="polite"/);
  assert.doesNotMatch(adminHtml, /api\("POST", "\/api\/update"/);
  assert.doesNotMatch(adminHtml, /id="update-review"/);
  assert.doesNotMatch(updateScript, /\bupdater\b|\bjob\b|GitHub/);
});

test("an available release renders its exact versions, rollout warning, command, and release link", () => {
  const harness = updateUiHarness();
  vm.runInContext(`renderUpdateAlert(${JSON.stringify(updateStatus("0.2.0").data)})`, harness.context);
  assert.equal(harness.element("release-alert").classList.contains("hidden"), false);
  assert.equal(harness.element("release-alert-title").textContent, "QM 0.2.0 is available");
  assert.equal(harness.element("release-alert-current").textContent, "QM 0.1.9");
  assert.equal(harness.element("release-alert-latest").textContent, "QM 0.2.0");
  assert.match(harness.element("release-alert-detail").textContent, /official QM images/);
  assert.match(harness.element("release-alert-detail").textContent, /custom image overrides/);
  assert.equal(
    harness.element("release-alert-command").value,
    "node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version 0.2.0",
  );
  assert.equal(harness.element("release-alert-notes").href, "https://github.com/yc-software/qm/releases/tag/v0.2.0");
});

test("a current release stays on bounded idle polling", async () => {
  const harness = updateUiHarness(updateStatus("0.1.9", false));
  await loadUpdate(harness);
  assert.equal(harness.element("release-alert").classList.contains("hidden"), true);
  assert.deepEqual(activeTimerDelays(harness), [300_000]);
  assert.deepEqual(harness.apiCalls, [["GET", "/api/update"]]);
});

test("registry failures back off to a bounded refresh interval", async () => {
  const harness = updateUiHarness({
    ok: false,
    status: 502,
    data: { error: "registry_unreachable" },
  });
  for (const delay of [300_000, 600_000, 1_200_000, 1_800_000, 1_800_000]) {
    await loadUpdate(harness);
    assert.deepEqual(activeTimerDelays(harness), [delay]);
  }
  assert.equal(harness.element("release-alert").classList.contains("hidden"), true);
});

test("hiding an update under focus returns focus to the Admin content", async () => {
  const harness = updateUiHarness();
  vm.runInContext(`renderUpdateAlert(${JSON.stringify(updateStatus("0.2.0").data)})`, harness.context);
  harness.element("release-alert-action").focus();
  harness.setApiHandler(async () => ({ ok: false, status: 502, data: null }));
  await loadUpdate(harness);
  assert.equal(harness.element("release-alert").classList.contains("hidden"), true);
  assert.equal(harness.document.activeElement, harness.element("admin-main"));
});

test("a hung update request is aborted before bounded backoff", async () => {
  const harness = updateUiHarness();
  let aborted = false;
  harness.setApiHandler(
    (signal) =>
      new Promise<UiResult>((_resolve, reject) => {
        signal?.addEventListener(
          "abort",
          () => {
            aborted = true;
            reject(new Error("aborted"));
          },
          { once: true },
        );
      }),
  );
  vm.runInContext("updateRefreshActive = true", harness.context);
  const pending = vm.runInContext("loadUpdateAlert()", harness.context) as Promise<void>;
  const timeout = harness.timers.find((timer) => !timer.cleared && timer.delay === 30_000);
  assert.ok(timeout);
  timeout.callback();
  await pending;
  assert.equal(aborted, true);
  assert.deepEqual(activeTimerDelays(harness), [300_000]);
});

test("returning to a visible Admin tab refreshes the release immediately", async () => {
  const harness = updateUiHarness(updateStatus("0.1.9", false));
  await loadUpdate(harness);
  harness.document.hidden = true;
  harness.listeners.get("visibilitychange")?.();
  assert.deepEqual(activeTimerDelays(harness), []);
  harness.document.hidden = false;
  harness.listeners.get("visibilitychange")?.();
  assert.deepEqual(harness.apiCalls, [
    ["GET", "/api/update"],
    ["GET", "/api/update"],
  ]);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.deepEqual(activeTimerDelays(harness), [300_000]);
});

test("missing identity and authorization responses stop update polling", async (t) => {
  for (const status of [204, 401, 403]) {
    await t.test(String(status), async () => {
      const harness = updateUiHarness({ ok: status === 204, status, data: null });
      await loadUpdate(harness);
      assert.deepEqual(activeTimerDelays(harness), []);
      assert.equal(vm.runInContext("updateRefreshActive", harness.context), false);
      assert.equal(harness.element("release-alert").classList.contains("hidden"), true);
    });
  }
});

test("a stale concurrent response cannot replace the newest release", async () => {
  const harness = updateUiHarness();
  const resolves: Array<(result: UiResult) => void> = [];
  harness.setApiHandler(
    () =>
      new Promise<UiResult>((resolve) => {
        resolves.push(resolve);
      }),
  );
  vm.runInContext("updateRefreshActive = true", harness.context);
  const older = vm.runInContext("loadUpdateAlert()", harness.context) as Promise<void>;
  const newest = vm.runInContext("loadUpdateAlert()", harness.context) as Promise<void>;
  resolves[1]!(updateStatus("0.3.0"));
  await newest;
  resolves[0]!(updateStatus("0.2.0"));
  await older;
  assert.equal(harness.element("release-alert-latest").textContent, "QM 0.3.0");
  assert.equal(
    harness.element("release-alert-command").value,
    "node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version 0.3.0",
  );
  assert.deepEqual(activeTimerDelays(harness), [300_000]);
});

test("failed copying leaves the persistent read-only command selected", async () => {
  const harness = updateUiHarness();
  harness.setCopyResult(false);
  vm.runInContext(`renderUpdateAlert(${JSON.stringify(updateStatus("0.2.0").data)})`, harness.context);
  const command = harness.element("release-alert-command");
  await vm.runInContext('$("release-alert-action").onclick()', harness.context);
  assert.deepEqual(harness.copyCalls, [
    "node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version 0.2.0",
  ]);
  assert.equal(harness.element("release-alert-command"), command);
  assert.equal(harness.document.activeElement, command);
  assert.equal(command.selected, true);
  assert.match(harness.element("release-alert-state").textContent, /selected/);
});
