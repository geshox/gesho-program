import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

if (process.platform !== "win32")
  throw new Error("Requires actual Windows NTFS");
const [rootArgument, artifactArgument, expected] = process.argv.slice(2);
assert.ok(rootArgument && artifactArgument);
assert.ok(expected === "expect-leak" || expected === "retain-owner");
const root = resolve(rootArgument);
const artifact = resolve(artifactArgument);
const manifest = JSON.parse(
  await readFile(join(artifact, "manifest.json"), "utf8"),
);
const image = await readFile(join(artifact, manifest.artifact));
assert.equal(
  createHash("sha256").update(image).digest("hex"),
  manifest.artifactSha256,
);
assert.equal(manifest.abiVersion, 1);
assert.equal(manifest.nodeApiVersion, 8);
const native = createRequire(join(root, "package.json"))(
  join(artifact, manifest.artifact),
);
const workspace = await mkdtemp(join(tmpdir(), "rea-failed-creation-probe-"));
process.env.REA_NATIVE_CREATION_FAILURE = "1";
let retry;
const failures = [];
try {
  let failure;
  try {
    native.call("runtime_create", [workspace, "owned-"]);
  } catch (cause) {
    failure = cause;
  }
  assert.equal(failure?.constraint, "Read private DACL by handle failed");
  assert.equal(failure?.win32Code, 5);
  assert.notEqual(failure.runtimeAllocation, "not-started");
  if (expected === "retain-owner") {
    assert.equal(
      failure.cleanupConstraint,
      "Delete owned object by handle failed",
    );
    assert.equal(failure.cleanupWin32Code, 5);
  } else assert.equal(failure.cleanupConstraint, undefined);
  const [name, ...extra] = await readdir(workspace);
  assert.ok(name && name.startsWith("owned-"));
  assert.equal(extra.length, 0);
  const allocated = join(workspace, name);
  const identity = await stat(allocated, { bigint: true });
  assert.equal(failure.requestedPath, allocated);
  const moved = allocated + "-moved";
  await writeFile(join(allocated, "owned-child.txt"), "owned child");
  await rename(allocated, moved);
  await mkdir(allocated);
  const replacement = await stat(allocated, { bigint: true });
  assert.notEqual(replacement.ino, identity.ino);
  const sentinel = join(allocated, "unrelated.txt");
  await writeFile(sentinel, "preserve replacement");

  retry = native.call("runtime_create", [workspace, "retry-"]);
  native.call("runtime_close", [retry.handle]);
  retry = undefined;
  if (expected === "expect-leak") {
    assert.equal((await stat(moved, { bigint: true })).ino, identity.ino);
    assert.equal(
      await readFile(join(moved, "owned-child.txt"), "utf8"),
      "owned child",
    );
  } else await assert.rejects(access(moved), { code: "ENOENT" });
  assert.equal((await stat(allocated, { bigint: true })).ino, replacement.ino);
  assert.equal(await readFile(sentinel, "utf8"), "preserve replacement");
  console.log(
    JSON.stringify({
      ok: true,
      expected,
      postAllocationValidationDenied: true,
      rollbackDispositionDenied: true,
      baselineLostOwner: expected === "expect-leak",
      renamedOwnerRemovedOnRetry: expected === "retain-owner",
      unrelatedReplacementPreserved: true,
      fixtureArtifactSha256: manifest.artifactSha256,
      originalHostDeleteDenialReproduced: false,
    }),
  );
} catch (failure) {
  failures.push(failure);
  console.error(failure);
}
try {
  if (retry) native.call("runtime_close", [retry.handle]);
  native.call("inspect", []);
  await rm(workspace, { recursive: true, force: true });
} catch (cleanupFailure) {
  failures.push(cleanupFailure);
}
if (failures.length !== 0)
  throw new AggregateError(failures, "Creation ownership probe failed");
