#!/usr/bin/env node
/** Regression for the raw PKCE ABI; pass a freshly built WASM path explicitly. */
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { initCore as initNodeCore } from "../../scripts/sdk/runtime_node_reference.ts";
import { initCore as initWebCore } from "../../scripts/sdk/runtime_web_reference.ts";

export async function checkPkceAliasing(wasmPath: string, onCheck?: (id: string) => void): Promise<number> {
  const wasmBytes = readFileSync(wasmPath);
  const module = new WebAssembly.Module(wasmBytes);
  const imports: WebAssembly.Imports = {};
  let callbacks = 0;
  for (const entry of WebAssembly.Module.imports(module)) {
    assert.equal(entry.kind, "function", `unexpected import ${entry.module}.${entry.name}`);
    imports[entry.module] ??= {};
    imports[entry.module][entry.name] = () => {
      callbacks++;
      throw new Error(`PKCE unexpectedly invoked ${entry.module}.${entry.name}`);
    };
  }
  const instance = new WebAssembly.Instance(module, imports);
  const memory = instance.exports.memory;
  assert.ok(memory instanceof WebAssembly.Memory);
  const generate = instance.exports.vc_pkce_challenge_generate;
  const verify = instance.exports.vc_pkce_challenge_verify;
  assert.equal(typeof generate, "function", "PKCE generation export is required");
  assert.equal(typeof verify, "function", "PKCE verification export is required");
  const heapBase = instance.exports.__heap_base;
  const arena = Math.max(2 * 1024 * 1024, heapBase instanceof WebAssembly.Global ? Number(heapBase.value) + 4096 : 0);
  if (memory.buffer.byteLength < arena + 4096) {
    memory.grow(Math.ceil((arena + 4096 - memory.buffer.byteLength) / 65536));
  }
  let next = arena;
  let checks = 0;
  function alloc(length: number): number {
    const pointer = next;
    next = (next + length + 7) & ~7;
    assert.ok(next <= arena + 4096, "fixture arena exhausted");
    return pointer;
  }
  function bytes(pointer: number, length: number): Uint8Array {
    return new Uint8Array(memory.buffer, pointer, length);
  }
  function put(value: Uint8Array): number {
    const pointer = alloc(value.length);
    bytes(pointer, value.length).set(value);
    return pointer;
  }
  function slice(pointer: number, length: number): number {
    const address = alloc(8);
    const view = new DataView(memory.buffer);
    view.setUint32(address, pointer, true);
    view.setUint32(address + 4, length, true);
    return address;
  }
  function result(address: number): { code: number; pointer: number; length: number } {
    const view = new DataView(memory.buffer);
    return { code: view.getUint32(address, true), pointer: view.getUint32(address + 4, true), length: view.getUint32(address + 8, true) };
  }
  function rawGenerate(pointer: number, length: number) {
    const output = alloc(16);
    (generate as (out: number, input: number, method: number) => void)(output, slice(pointer, length), 1);
    return result(output);
  }
  function rawVerify(vp: number, vl: number, cp: number, cl: number, method = 1) {
    const output = alloc(16);
    bytes(output, 16).fill(0xa5);
    (verify as (out: number, verifier: number, challenge: number, method: number) => void)(output, slice(vp, vl), slice(cp, cl), method);
    const value = result(output);
    assert.equal(value.pointer, 0, "verification never returns a borrowed output");
    assert.equal(value.length, 0);
    checks++;
    return value.code;
  }
  function s256(value: Uint8Array): Buffer {
    return Buffer.from(createHash("sha256").update(value).digest("base64url"));
  }
  function reset() { next = arena; }

  // All normal verifier lengths; the oracle uses Node's independent SHA-256/base64url.
  for (let length = 43; length <= 128; length++) {
    reset();
    const input = Buffer.from("AZaz09-._~".repeat(13).slice(0, length));
    const vp = put(input);
    const expected = s256(input);
    const generated = rawGenerate(vp, length);
    assert.equal(generated.code, 0);
    assert.deepEqual(Buffer.from(bytes(generated.pointer, generated.length)), expected);
    assert.equal(rawVerify(vp, length, generated.pointer, 43), 0, `borrowed match at length ${length}`);
    assert.equal(rawVerify(vp, length, put(expected), 43), 0, `copied match at length ${length}`);
    onCheck?.(`length/${length}`);
  }

  // Preserve the original counterexample: generate(A)'s borrowed result is passed
  // directly to verify(B), whose generation overwrites exactly that storage.
  reset();
  const a = Buffer.from("A".repeat(43));
  const b = Buffer.from("B".repeat(43));
  assert.notDeepEqual(s256(a), s256(b)); // Difference of verifiers alone is insufficient.
  const vpA = put(a);
  const vpB = put(b);
  const borrowed = rawGenerate(vpA, a.length);
  assert.equal(rawVerify(vpB, b.length, borrowed.pointer, borrowed.length), 4, "borrowed mismatched challenge must be refused");
  assert.deepEqual(Buffer.from(bytes(borrowed.pointer, 43)), s256(b), "existing generation side effect is preserved");
  onCheck?.("borrowed-mismatch");

  // Both arguments may alias the shared generated buffer. The verifier is the
  // old 43-byte challenge, and the expected comparison uses both entry values.
  reset();
  const original = rawGenerate(put(a), a.length);
  const entry = Buffer.from(bytes(original.pointer, 43));
  assert.equal(rawVerify(original.pointer, 43, original.pointer, 43), s256(entry).equals(entry) ? 0 : 4);
  onCheck?.("both-inputs-alias");

  // Every relative overlapping offset for the shortest and longest verifier.
  // Challenge bytes need not be base64url: equal length + unequal bytes is a refusal.
  for (const length of [43, 128]) {
    for (let delta = -42; delta < length; delta++) {
      reset();
      const storage = alloc(384);
      bytes(storage, 384).fill(0x41);
      const vp = storage + 128;
      const cp = vp + delta;
      const verifierAtEntry = Buffer.from(bytes(vp, length));
      const challengeAtEntry = Buffer.from(bytes(cp, 43));
      assert.equal(rawVerify(vp, length, cp, 43), s256(verifierAtEntry).equals(challengeAtEntry) ? 0 : 4, `overlap ${length}/${delta}`);
      onCheck?.(`overlap/${length}/${delta}`);
    }
  }

  reset();
  const valid = put(a);
  const last = rawGenerate(valid, a.length);
  const before = Buffer.from(bytes(last.pointer, 43));
  for (const method of [0, 2, 0xffffffff]) {
    next = arena + 512;
    assert.equal(rawVerify(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, method), 7);
    onCheck?.(`method/${method}`);
  }
  for (const length of [0, 42, 129, 0xffffffff]) {
    next = arena + 512;
    assert.equal(rawVerify(valid, length, last.pointer, 43), 1);
    onCheck?.(`verifier-length/${length}`);
  }
  for (const length of [0, 42, 44, 0xffffffff]) {
    next = arena + 512;
    assert.equal(rawVerify(valid, 43, last.pointer, length), 1);
    onCheck?.(`challenge-length/${length}`);
  }
  next = arena + 512;
  assert.equal(rawVerify(0, 43, last.pointer, 43), 1);
  onCheck?.("null-verifier");
  assert.equal(rawVerify(valid, 43, 0, 43), 1);
  onCheck?.("null-challenge");
  for (const bad of [0, 0x21, 0x7f, 0x80, 0xff]) {
    next = arena + 512;
    const invalid = Buffer.from(a);
    invalid[21] = bad;
    assert.equal(rawVerify(put(invalid), 43, last.pointer, 43), 1);
    onCheck?.(`invalid-byte/${bad}`);
  }
  assert.deepEqual(Buffer.from(bytes(last.pointer, 43)), before, "argument failures leave generated storage unchanged");
  onCheck?.("argument-failure-preserves-storage");

  // Raw out-of-bounds WASM slices remain traps, not validated C slices. Snapshot
  // happens before generation, so this trap does not overwrite generated storage.
  next = arena + 512;
  assert.throws(() => rawVerify(valid, 43, memory.buffer.byteLength - 42, 43), WebAssembly.RuntimeError);
  assert.deepEqual(Buffer.from(bytes(last.pointer, 43)), before);
  assert.equal(callbacks, 0, "PKCE must not enter host callbacks");
  onCheck?.("trap-and-no-host-callbacks");

  // The existing adapters copy their inputs and generated output. Exercise their
  // actual allocation/copy/call path on the same module; no adapter contract is
  // narrowed to make the raw alias regression pass.
  const manifest = { sha256: createHash("sha256").update(wasmBytes).digest("hex"), size_bytes: wasmBytes.length };
  for (const initCore of [initNodeCore, initWebCore]) {
    const { handle } = await initCore({ manifest, wasmBytes, secureContext: true, subtle: webcrypto.subtle });
    const generated = await handle.pkceGenerate({ verifier: a });
    assert.equal(generated.statusCode, 0);
    assert.equal(generated.challenge, s256(a).toString());
    await handle.pkceGenerate({ verifier: b });
    assert.equal(generated.challenge, s256(a).toString(), "adapter output is a retained copy");
    assert.deepEqual(await handle.pkceVerify({ verifier: a, challenge: Buffer.from(generated.challenge) }), { statusCode: 0, ok: true });
    assert.deepEqual(await handle.pkceVerify({ verifier: b, challenge: Buffer.from(generated.challenge) }), { statusCode: 4, ok: false });
    const shared = Buffer.from("A".repeat(128));
    assert.deepEqual(await handle.pkceVerify({ verifier: shared, challenge: shared.subarray(0, 43) }), { statusCode: 4, ok: false });
    onCheck?.(initCore === initNodeCore ? "adapter/node" : "adapter/web");
  }
  return checks;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const wasmPath = process.argv[2] ?? resolve("tests/fixtures/verified-core/verified_core.wasm");
  const checks = await checkPkceAliasing(wasmPath);
  console.log(`PKCE raw ABI: ${checks} result checks passed; alias, input and trap observations checked.`);
}
