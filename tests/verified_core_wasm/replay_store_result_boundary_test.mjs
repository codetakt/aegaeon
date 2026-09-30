import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export async function checkReplayStoreResults(sourceRoot, wasmPath) {
  const wasmBytes = readFileSync(wasmPath);
  const manifest = {
    sha256: createHash("sha256").update(wasmBytes).digest("hex"),
    size_bytes: wasmBytes.length,
  };
  const cases = [
    ["false", false, 0], ["true", true, 1],
    ["undefined", undefined, 2], ["null", null, 2], ["NaN", NaN, 2],
    ["zero", 0, 2], ["one", 1, 2], ["two", 2, 2], ["minus-one", -1, 2],
    ["2^32", 2 ** 32, 2], ["infinity", Infinity, 2],
    ["empty-string", "", 2], ["zero-string", "0", 2], ["false-string", "false", 2],
    ["object", {}, 2], ["array", [], 2], ["boxed-false", new Boolean(false), 2],
    ["promise", Promise.resolve(false), 2], ["bigint-zero", 0n, 2],
    ["symbol", Symbol("fixture"), 2],
  ];
  let checks = 0;
  for (const kind of ["node", "web"]) {
    const adapter = await import(pathToFileURL(path.join(
      sourceRoot, `scripts/sdk/runtime_${kind}_reference.ts`,
    )));
    const namespace = Uint8Array.from([1, 2, 3]);
    const key = Uint8Array.from({ length: 32 }, (_, index) => index);
    let value;
    let throws = false;
    let calls = 0;
    const failure = new Error("replay-store unavailable");
    const replayStore = {
      checkAndStore(actualNamespace, actualKey, ttl) {
        calls++;
        assert.deepEqual([...actualNamespace], [...namespace]);
        assert.deepEqual([...actualKey], [...key]);
        assert.equal(ttl, 60000);
        if (throws) throw failure;
        return value;
      },
    };
    const options = { wasmBytes, manifest, secureContext: true, subtle: webcrypto.subtle };
    const { runtime, instance } = await adapter.initCore({ ...options, replayStore });
    const ns = runtime.writeBytes(namespace);
    const hash = runtime.writeBytes(key);
    const callback = runtime.buildImports().env
      .VerifiedCore_Api_Claims_Runtime_host_replay_store_check_and_store;
    const classify = instance.exports.VerifiedCore_Api_Claims_Runtime_replay_result_from_u32;
    assert.equal(typeof classify, "function", "replay classifier export is required");
    for (const [label, input, expected] of cases) {
      value = input;
      const before = calls;
      const result = callback(ns.ptr, ns.len, hash.ptr, 60000);
      assert.equal(calls, before + 1, `${kind}/${label}: callback count`);
      assert.equal(result, expected, `${kind}/${label}: host result`);
      assert.equal(classify(result), expected, `${kind}/${label}: WASM classification`);
      checks++;
    }
    throws = true;
    assert.throws(() => callback(ns.ptr, ns.len, hash.ptr, 60000), (error) => error === failure);
    checks++;

    const ordinary = await adapter.initCore(options);
    const normalNs = ordinary.runtime.writeBytes(namespace);
    const normalHash = ordinary.runtime.writeBytes(key);
    const normalCallback = ordinary.runtime.buildImports().env
      .VerifiedCore_Api_Claims_Runtime_host_replay_store_check_and_store;
    assert.equal(normalCallback(normalNs.ptr, normalNs.len, normalHash.ptr, 60000), 0);
    assert.equal(normalCallback(normalNs.ptr, normalNs.len, normalHash.ptr, 60000), 1);
    checks += 2;
  }
  return checks;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const sourceRoot = path.resolve(process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "../.."));
  const wasmPath = process.argv[3] ?? path.join(sourceRoot, "tests/fixtures/verified-core/verified_core.wasm");
  const checks = await checkReplayStoreResults(sourceRoot, wasmPath);
  console.log(`${checks} replay-store checks passed (Node and Web adapters under Node).`);
}
