import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  chownSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  readRenderedFile,
  removeRenderedFile,
  renderedWriteEffectiveUid,
  secureRenderedWritesSupported,
  updateRenderedFile,
  writeRenderedFile,
} from "../src/safe-write.ts";

const linuxGetfacl = ["/usr/bin/getfacl", "/bin/getfacl"].find(existsSync);
const linuxGetfattr = ["/usr/bin/getfattr", "/bin/getfattr"].find(existsSync);
const linuxLsattr = ["/usr/bin/lsattr", "/bin/lsattr"].find(existsSync);
const linuxChattr = ["/usr/bin/chattr", "/bin/chattr"].find(existsSync);
const linuxSetfacl = ["/usr/bin/setfacl", "/bin/setfacl"].find(existsSync);
const linuxSetfattr = ["/usr/bin/setfattr", "/bin/setfattr"].find(existsSync);

test("rendered files are replaced atomically and removable", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const target = join(dir, "rendered.txt");
  writeRenderedFile(dir, ["rendered.txt"], "first\n");
  assert.equal(readFileSync(target, "utf8"), "first\n");
  assert.equal(
    updateRenderedFile(dir, ["rendered.txt"], (existing) => existing.replace("first", "second")),
    true,
  );
  assert.equal(readFileSync(target, "utf8"), "second\n");
  assert.equal(removeRenderedFile(dir, ["rendered.txt"]), true);
  assert.equal(removeRenderedFile(dir, ["rendered.txt"]), false);
  assert.equal(readRenderedFile(dir, ["rendered.txt"]), undefined);
});

test("rendered files reject final symlinks and hardlinks without changing their referents", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const sentinel = join(dir, "sentinel.txt");
  writeFileSync(sentinel, "sentinel\n");
  const symlink = join(dir, "symlink.txt");
  symlinkSync(sentinel, symlink);
  assert.throws(() => writeRenderedFile(dir, ["symlink.txt"], "changed\n"), /safe rendered output file/);
  assert.throws(() => removeRenderedFile(dir, ["symlink.txt"]), /safe rendered output file/);
  assert.equal(readFileSync(sentinel, "utf8"), "sentinel\n");
  const hardlink = join(dir, "hardlink.txt");
  linkSync(sentinel, hardlink);
  assert.throws(() => writeRenderedFile(dir, ["hardlink.txt"], "changed\n"), /safe rendered output file/);
  assert.throws(() => removeRenderedFile(dir, ["hardlink.txt"]), /safe rendered output file/);
  assert.equal(readFileSync(sentinel, "utf8"), "sentinel\n");
});

test("rendered files reject targets writable by another principal", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const target = join(dir, "rendered.txt");
  writeFileSync(target, "sentinel\n");
  chmodSync(target, 0o666);
  assert.throws(() => writeRenderedFile(dir, ["rendered.txt"], "changed\n"), /safe rendered output file/);
  assert.equal(readFileSync(target, "utf8"), "sentinel\n");
});

test("rendered files reject symlinked output roots and child directories", (t) => {
  const outer = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(outer, { recursive: true, force: true }));
  const actual = join(outer, "actual");
  const alias = join(outer, "alias");
  mkdirSync(actual);
  writeFileSync(join(actual, "rendered.txt"), "sentinel\n");
  symlinkSync(actual, alias, "dir");
  assert.throws(() => writeRenderedFile(alias, ["rendered.txt"], "changed\n"), /safe rendered output directory/);
  assert.equal(readFileSync(join(actual, "rendered.txt"), "utf8"), "sentinel\n");

  const root = join(outer, "root");
  const outside = join(outer, "outside");
  mkdirSync(root);
  mkdirSync(outside);
  writeFileSync(join(outside, "rendered.txt"), "sentinel\n");
  symlinkSync(outside, join(root, "nested"), "dir");
  assert.throws(() => writeRenderedFile(root, ["nested", "rendered.txt"], "changed\n"), /unsafe parent directory/);
  assert.equal(readFileSync(join(outside, "rendered.txt"), "utf8"), "sentinel\n");
});

test("rendered files reject writable mutation-controlling ancestors", (t) => {
  const outer = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(outer, { recursive: true, force: true }));
  const writable = join(outer, "writable");
  const root = join(writable, "root");
  mkdirSync(writable);
  chmodSync(writable, 0o777);
  mkdirSync(root);
  writeFileSync(join(root, "rendered.txt"), "sentinel\n");
  assert.throws(() => writeRenderedFile(root, ["rendered.txt"], "changed\n"), /unsafe mutation-controlling ancestor/);
  assert.equal(readFileSync(join(root, "rendered.txt"), "utf8"), "sentinel\n");
});

test("rendered file updates reject a final-path replacement without clobbering it", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const target = join(dir, "rendered.txt");
  const displaced = join(dir, "displaced.txt");
  writeFileSync(target, "original\n");
  assert.throws(
    () =>
      updateRenderedFile(dir, ["rendered.txt"], () => {
        renameSync(target, displaced);
        writeFileSync(target, "replacement\n");
        return "changed\n";
      }),
    /changed while it was being rendered/,
  );
  assert.equal(readFileSync(target, "utf8"), "replacement\n");
  assert.equal(readFileSync(displaced, "utf8"), "original\n");
});

test("rendered file updates reject an ancestor replacement without writing through it", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const parent = join(dir, "nested");
  const displaced = join(dir, "displaced");
  const target = join(parent, "rendered.txt");
  mkdirSync(parent);
  writeFileSync(target, "original\n");
  assert.throws(
    () =>
      updateRenderedFile(dir, ["nested", "rendered.txt"], () => {
        renameSync(parent, displaced);
        mkdirSync(parent);
        writeFileSync(target, "replacement\n");
        return "changed\n";
      }),
    /changed parent directories/,
  );
  assert.equal(readFileSync(target, "utf8"), "replacement\n");
  assert.equal(readFileSync(join(displaced, "rendered.txt"), "utf8"), "original\n");
});

test("rendered files reject an unsafe lexical ancestor hidden by an intermediate symlink", (t) => {
  const outer = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(outer, { recursive: true, force: true }));
  const writable = join(outer, "writable");
  const actual = join(outer, "actual");
  const root = join(actual, "root");
  mkdirSync(writable);
  chmodSync(writable, 0o777);
  mkdirSync(actual);
  mkdirSync(root);
  symlinkSync(actual, join(writable, "alias"), "dir");
  const target = join(root, "rendered.txt");
  writeFileSync(target, "sentinel\n");
  assert.throws(
    () => writeRenderedFile(join(writable, "alias", "root"), ["rendered.txt"], "changed\n"),
    /unsafe mutation-controlling ancestor/,
  );
  assert.equal(readFileSync(target, "utf8"), "sentinel\n");
});

test("rendered files reject an unsafe controller reached through chained intermediate symlinks", (t) => {
  const outer = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(outer, { recursive: true, force: true }));
  const safe = join(outer, "safe");
  const unsafe = join(outer, "unsafe");
  const actual = join(outer, "actual");
  mkdirSync(safe);
  mkdirSync(unsafe);
  chmodSync(unsafe, 0o777);
  mkdirSync(actual);
  mkdirSync(join(actual, "root"));
  const nested = join(unsafe, "nested");
  symlinkSync(actual, nested, "dir");
  symlinkSync(nested, join(safe, "alias"), "dir");
  const configDir = join(safe, "alias", "root");
  const target = join(actual, "root", "rendered.txt");
  writeFileSync(target, "original\n");
  assert.throws(
    () => writeRenderedFile(configDir, ["rendered.txt"], "changed\n"),
    /unsafe mutation-controlling ancestor/,
  );
  assert.equal(readFileSync(target, "utf8"), "original\n");
});

test("rendered file updates reject a dependency replacement before commit", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const target = join(dir, "rendered.txt");
  const source = join(dir, "source.txt");
  const displaced = join(dir, "displaced.txt");
  writeFileSync(target, "original\n");
  writeFileSync(source, "source\n");
  assert.throws(
    () =>
      updateRenderedFile(
        dir,
        ["rendered.txt"],
        (existing, dependencies) => {
          assert.equal(existing, "original\n");
          assert.equal(dependencies.get("source.txt"), "source\n");
          renameSync(source, displaced);
          writeFileSync(source, "replacement\n");
          return "changed\n";
        },
        [["source.txt"]],
      ),
    /source\.txt changed while it was being rendered/,
  );
  assert.equal(readFileSync(target, "utf8"), "original\n");
  assert.equal(readFileSync(source, "utf8"), "replacement\n");
  assert.equal(readFileSync(displaced, "utf8"), "source\n");
});

test("rendered file reads use a bounded fatal UTF-8 decoder", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const target = join(dir, "rendered.txt");
  writeFileSync(target, Buffer.alloc(1_048_576, 0x61));
  assert.equal(readRenderedFile(dir, ["rendered.txt"])?.length, 1_048_576);
  truncateSync(target, 1_048_577);
  assert.throws(() => readRenderedFile(dir, ["rendered.txt"]), /1048576-byte rendered file limit/);
  assert.equal(statSync(target).size, 1_048_577);
  writeFileSync(target, Buffer.from([0xef, 0xbb, 0xbf, 0x61]));
  assert.equal(readRenderedFile(dir, ["rendered.txt"]), "\ufeffa");
  writeFileSync(target, Buffer.from([0xff]));
  assert.throws(() => readRenderedFile(dir, ["rendered.txt"]), /valid UTF-8/);
  assert.deepEqual(readFileSync(target), Buffer.from([0xff]));
});

test("rendered file updates preserve owner group and mode", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const target = join(dir, "rendered.txt");
  writeFileSync(target, "original\n");
  chmodSync(target, 0o640);
  const uid = process.getuid!();
  const currentGid = process.getgid!();
  const gid = process.getgroups!().find((candidate) => candidate !== currentGid) ?? currentGid;
  chownSync(target, uid, gid);
  assert.equal(
    updateRenderedFile(dir, ["rendered.txt"], () => "changed\n"),
    true,
  );
  const rendered = statSync(target);
  assert.equal(rendered.uid, uid);
  assert.equal(rendered.gid, gid);
  assert.equal(rendered.mode & 0o7777, 0o640);
});

test(
  "rendered file updates reject restrictive Darwin ACLs without removing them",
  { skip: process.platform !== "darwin" },
  (t) => {
    const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const target = join(dir, "rendered.txt");
    writeFileSync(target, "original\n");
    execFileSync("/bin/chmod", ["+a", "group:everyone deny write", target]);
    assert.throws(() => updateRenderedFile(dir, ["rendered.txt"], () => "changed\n"), /must not have ACLs/);
    assert.equal(readFileSync(target, "utf8"), "original\n");
    assert.match(execFileSync("/bin/ls", ["-le", target], { encoding: "utf8" }), /group:everyone deny write/);
  },
);

test("rendered file updates reject unpreserved Darwin xattrs", { skip: process.platform !== "darwin" }, (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const target = join(dir, "rendered.txt");
  writeFileSync(target, "original\n");
  execFileSync("/usr/bin/xattr", ["-w", "com.qm.review", "guard", target]);
  assert.throws(
    () => updateRenderedFile(dir, ["rendered.txt"], () => "changed\n"),
    /extended metadata could not be preserved/,
  );
  assert.equal(readFileSync(target, "utf8"), "original\n");
  assert.equal(
    execFileSync("/usr/bin/xattr", ["-p", "com.qm.review", target], { encoding: "utf8" }).trimEnd(),
    "guard",
  );
});

test("rendered file updates reject unpreserved Darwin flags", { skip: process.platform !== "darwin" }, (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const target = join(dir, "rendered.txt");
  writeFileSync(target, "original\n");
  execFileSync("/usr/bin/chflags", ["hidden", target]);
  assert.throws(
    () => updateRenderedFile(dir, ["rendered.txt"], () => "changed\n"),
    /inode metadata could not be preserved/,
  );
  assert.equal(readFileSync(target, "utf8"), "original\n");
  assert.notEqual(execFileSync("/usr/bin/stat", ["-f", "%f", target], { encoding: "utf8" }).trim(), "0");
});

test(
  "rendered file updates reject inherited Linux ACLs before creating a replacement",
  { skip: process.platform !== "linux" || linuxGetfacl === undefined || linuxSetfacl === undefined },
  (t) => {
    const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const target = join(dir, "rendered.txt");
    writeFileSync(target, "original\n");
    const reader = process.getuid!() === 65_534 ? 1 : 65_534;
    execFileSync(linuxSetfacl!, ["-m", `d:u:${reader}:r--`, dir]);
    assert.throws(() => updateRenderedFile(dir, ["rendered.txt"], () => "changed\n"), /must not have ACLs/);
    assert.equal(readFileSync(target, "utf8"), "original\n");
    assert.match(
      execFileSync(linuxGetfacl!, ["-c", "-n", dir], { encoding: "utf8" }),
      new RegExp(`default:user:${reader}:r--`),
    );
  },
);

test(
  "rendered file updates reject unpreserved Linux xattrs",
  {
    skip:
      process.platform !== "linux" ||
      linuxGetfacl === undefined ||
      linuxGetfattr === undefined ||
      linuxLsattr === undefined ||
      linuxSetfattr === undefined,
  },
  (t) => {
    const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const target = join(dir, "rendered.txt");
    writeFileSync(target, "original\n");
    execFileSync(linuxSetfattr!, ["-n", "user.qm_review", "-v", "guard", target]);
    assert.throws(
      () => updateRenderedFile(dir, ["rendered.txt"], () => "changed\n"),
      /extended metadata could not be preserved/,
    );
    assert.equal(readFileSync(target, "utf8"), "original\n");
    assert.equal(
      execFileSync(linuxGetfattr!, ["--only-values", "-n", "user.qm_review", target], {
        encoding: "utf8",
      }).trimEnd(),
      "guard",
    );
  },
);

test(
  "rendered file updates reject unpreserved Linux inode flags",
  {
    skip:
      process.platform !== "linux" ||
      linuxGetfacl === undefined ||
      linuxGetfattr === undefined ||
      linuxLsattr === undefined ||
      linuxChattr === undefined,
  },
  (t) => {
    const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const target = join(dir, "rendered.txt");
    writeFileSync(target, "original\n");
    try {
      execFileSync(linuxChattr!, ["+d", target]);
    } catch {
      t.skip("filesystem does not support the nodump flag");
      return;
    }
    assert.throws(
      () => updateRenderedFile(dir, ["rendered.txt"], () => "changed\n"),
      /inode metadata could not be preserved/,
    );
    assert.equal(readFileSync(target, "utf8"), "original\n");
    assert.match(execFileSync(linuxLsattr!, ["-d", target], { encoding: "utf8" }), /d/);
  },
);

test(
  "rendered file updates reject unpreserved Linux project IDs",
  {
    skip:
      process.platform !== "linux" ||
      linuxGetfacl === undefined ||
      linuxGetfattr === undefined ||
      linuxLsattr === undefined ||
      linuxChattr === undefined,
  },
  (t) => {
    const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const target = join(dir, "rendered.txt");
    writeFileSync(target, "original\n");
    try {
      execFileSync(linuxChattr!, ["-p", "42", target]);
    } catch {
      t.skip("filesystem does not support project IDs");
      return;
    }
    assert.throws(
      () => updateRenderedFile(dir, ["rendered.txt"], () => "changed\n"),
      /inode metadata could not be preserved/,
    );
    assert.equal(readFileSync(target, "utf8"), "original\n");
    assert.match(execFileSync(linuxLsattr!, ["-p", "-d", target], { encoding: "utf8" }), /^\s*42\s/u);
  },
);

test("Linux metadata inspection never executes tools from PATH", { skip: process.platform !== "linux" }, (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, "bin");
  const output = join(dir, "output");
  mkdirSync(bin);
  for (const name of ["getfacl", "getfattr", "lsattr"]) {
    const fake = join(bin, name);
    writeFileSync(fake, `#!/bin/sh\nprintf pwn > ${JSON.stringify(output)}\n`);
    chmodSync(fake, 0o755);
  }
  writeFileSync(join(dir, "rendered.txt"), "original\n");
  const previous = process.env.PATH;
  process.env.PATH = bin;
  try {
    if (linuxGetfacl && linuxGetfattr && linuxLsattr) writeRenderedFile(dir, ["rendered.txt"], "rendered\n");
    else {
      assert.throws(
        () => writeRenderedFile(dir, ["rendered.txt"], "rendered\n"),
        /requires trusted (?:getfacl|getfattr|lsattr)/,
      );
    }
  } finally {
    if (previous === undefined) delete process.env.PATH;
    else process.env.PATH = previous;
  }
  assert.equal(existsSync(output), false);
});

test("new rendered files normalize permissions under a permissive umask", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-safe-write-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const previous = process.umask(0);
  try {
    writeRenderedFile(dir, ["rendered.txt"], "rendered\n");
  } finally {
    process.umask(previous);
  }
  assert.equal(statSync(join(dir, "rendered.txt")).mode & 0o7777, 0o644);
});

test("secure rendered writes require POSIX no-follow capabilities", () => {
  const supported = { directory: 1, effectiveUid: 501n, noFollow: 2, nonblock: 4, platform: "linux" };
  assert.equal(secureRenderedWritesSupported(supported), true);
  assert.equal(secureRenderedWritesSupported({ ...supported, platform: "win32" }), false);
  assert.equal(secureRenderedWritesSupported({ ...supported, platform: "freebsd" }), false);
  assert.equal(secureRenderedWritesSupported({ ...supported, effectiveUid: undefined }), false);
  assert.equal(secureRenderedWritesSupported({ ...supported, directory: undefined }), false);
  assert.equal(secureRenderedWritesSupported({ ...supported, directory: 0 }), false);
  assert.equal(secureRenderedWritesSupported({ ...supported, noFollow: undefined }), false);
  assert.equal(secureRenderedWritesSupported({ ...supported, noFollow: 0 }), false);
  assert.equal(secureRenderedWritesSupported({ ...supported, nonblock: undefined }), false);
  assert.equal(secureRenderedWritesSupported({ ...supported, nonblock: 0 }), false);
});

test("rendered writes prefer effective UID and only fall back when it is unavailable", () => {
  assert.equal(
    renderedWriteEffectiveUid(
      () => 502,
      () => 501,
    ),
    502n,
  );
  assert.equal(
    renderedWriteEffectiveUid(undefined, () => 501),
    501n,
  );
  assert.equal(renderedWriteEffectiveUid(undefined, undefined), undefined);
});
