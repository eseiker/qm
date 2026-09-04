import { test } from "node:test";
import assert from "node:assert/strict";
import { createMemoryMap, jsonbStringify } from "../src/persistence/durable-map.ts";

test("NUL characters are dropped for jsonb", () => {
  const out = jsonbStringify({ name: "a\u0000b" });
  assert.equal(out, '{"name":"ab"}');
});

test("a lone high surrogate (emoji cut in half by slice) becomes U+FFFD", () => {
  const cut = "prefix 😀".slice(0, 8); // strands the high surrogate
  const out = JSON.parse(jsonbStringify({ title: cut })) as { title: string };
  assert.ok(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(out.title), "no stranded surrogate survives");
  assert.ok(out.title.includes("\uFFFD"));
});

test("well-formed strings, keys, arrays, and nesting pass through untouched", () => {
  const value = { a: "hello 😀", list: ["x", { deep: "ok" }], n: 3, b: true, z: null };
  assert.equal(jsonbStringify(value), JSON.stringify(value));
});

test("keys are sanitized too", () => {
  const out = jsonbStringify({ ["k\u0000ey"]: 1 });
  assert.equal(out, '{"key":1}');
});

test("jsonb serialization preserves prototype-like keys as ordered own data", () => {
  const input = JSON.parse(
    '{"before":1,"__proto__":{"polluted":true},"constructor":{"marker":2},"prototype":{"marker":3},"after":4}',
  ) as Record<string, unknown>;
  const serialized = jsonbStringify(input);
  assert.equal(
    serialized,
    '{"before":1,"__proto__":{"polluted":true},"constructor":{"marker":2},"prototype":{"marker":3},"after":4}',
  );
  const roundTrip = JSON.parse(serialized) as Record<string, unknown>;
  assert.deepEqual(Object.keys(roundTrip), ["before", "__proto__", "constructor", "prototype", "after"]);
  assert.equal(Object.getPrototypeOf(roundTrip), Object.prototype);
  assert.equal(Object.hasOwn(roundTrip, "__proto__"), true);
  assert.equal((Object.prototype as { polluted?: unknown }).polluted, undefined);

  assert.equal(
    jsonbStringify(Object.fromEntries([["\u0000__proto__", { polluted: true }]])),
    '{"__proto__":{"polluted":true}}',
  );
});

test("memory map merge preserves prototype-like patch keys as ordered own data", async () => {
  const map = createMemoryMap<Record<string, unknown>>();
  await map.put("one", { before: 1 });
  const patch = JSON.parse(
    '{"__proto__":{"polluted":true},"constructor":"constructor-value","prototype":"prototype-value","after":2}',
  ) as Record<string, unknown>;
  const merged = await map.merge("one", patch);
  assert.ok(merged);
  assert.deepEqual(Object.keys(merged), ["before", "__proto__", "constructor", "prototype", "after"]);
  assert.equal(Object.getPrototypeOf(merged), Object.prototype);
  assert.equal(Object.hasOwn(merged, "__proto__"), true);
  assert.equal(
    JSON.stringify(merged),
    '{"before":1,"__proto__":{"polluted":true},"constructor":"constructor-value","prototype":"prototype-value","after":2}',
  );
  assert.deepEqual(await map.get("one"), merged);
  assert.equal((Object.prototype as { polluted?: unknown }).polluted, undefined);
});
