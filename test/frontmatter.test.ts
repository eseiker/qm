import test from "node:test";
import assert from "node:assert/strict";
import { parseFrontmatter, parseSeedSkillFrontmatter } from "../src/skills/frontmatter.ts";

test("parses plain and quoted scalars", () => {
  const { attrs, body } = parseFrontmatter(`---
name: demo
description: "a quoted desc"
other: 'single quoted'
---
# Body
text`);
  assert.equal(attrs.name, "demo");
  assert.equal(attrs.description, "a quoted desc");
  assert.equal(attrs.other, "single quoted");
  assert.match(body as string, /^# Body/);
});

test("parses block lists (key:\\n  - item)", () => {
  const { attrs } = parseFrontmatter(`---
name: demo
requiredCapabilities:
  - egress:example.com
  - command:demo
---
body`);
  assert.deepEqual(attrs.requiredCapabilities, ["egress:example.com", "command:demo"]);
});

test("parses inline flow arrays", () => {
  const { attrs } = parseFrontmatter(`---
sync_targets: [atlas, zion]
empty: []
---
body`);
  assert.deepEqual(attrs.sync_targets, ["atlas", "zion"]);
  assert.deepEqual(attrs.empty, []);
});

test("folds a > block scalar into one line; keeps newlines for |", () => {
  const { attrs } = parseFrontmatter(`---
description: >
  Track and identify
  real-name individuals.
literal: |
  line one
  line two
---
body`);
  assert.equal(attrs.description, "Track and identify real-name individuals.");
  assert.equal(attrs.literal, "line one\nline two");
});

test("tolerates unknown / nested shapes instead of throwing", () => {
  const { attrs } = parseFrontmatter(`---
name: demo
metadata:
  nested: value
  deeper:
    x: 1
weird line without a colon
description: ok
---
body`);
  assert.equal(attrs.name, "demo");
  assert.equal(attrs.description, "ok");
  assert.deepEqual(attrs.metadata, []);
});

test("skips comments and blank lines", () => {
  const { attrs } = parseFrontmatter(`---
# a comment
name: demo

description: ok
---
body`);
  assert.equal(attrs.name, "demo");
  assert.equal(attrs.description, "ok");
});

test("throws on a missing or unclosed fence (the structural contract)", () => {
  assert.throws(() => parseFrontmatter("no fence here"));
  assert.throws(() => parseFrontmatter("---\nname: x\nnever closed"));
});

test("accepts a BOM and CRLF without changing the body line endings", () => {
  const parsed = parseFrontmatter("\uFEFF---\r\nname: demo\r\ndescription: test\r\n---\r\nline one\r\nline two\r\n");
  assert.equal(parsed.attrs.name, "demo");
  assert.equal(parsed.body, "line one\r\nline two\r\n");
});

test("frontmatter preserves prototype-like keys as ordered own data", () => {
  const { attrs } = parseFrontmatter(`---
before: one
__proto__:
  - proto-value
constructor: constructor-value
prototype: prototype-value
after: two
---
body`);
  assert.deepEqual(Object.keys(attrs), ["before", "__proto__", "constructor", "prototype", "after"]);
  assert.equal(Object.getPrototypeOf(attrs), Object.prototype);
  assert.equal(Object.hasOwn(attrs, "__proto__"), true);
  assert.deepEqual(attrs.__proto__, ["proto-value"]);
  assert.equal(attrs.constructor, "constructor-value");
  assert.equal(attrs.prototype, "prototype-value");
  assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(attrs)) as Record<string, unknown>), Object.keys(attrs));
  assert.equal((Object.prototype as { polluted?: unknown }).polluted, undefined);
});

test("seed skill names cannot escape or alias their materialized directory", () => {
  const skill = (name: string) => `---\nname: ${name}\ndescription: test\n---\nbody`;
  for (const name of ["..", ".", "foo/bar", "foo\\bar", "foo bar", ".hidden", "foo."]) {
    assert.throws(() => parseSeedSkillFrontmatter(skill(name)), /skill name must/);
  }
  assert.equal(parseSeedSkillFrontmatter(skill("foo-bar_v1.2")).name, "foo-bar_v1.2");
});
