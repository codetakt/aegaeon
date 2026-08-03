#!/usr/bin/env node
/**
 * WASM-side equivalence tests.
 *
 * Instantiates the WASM module with functioning host callbacks (SHA-256 via
 * Node.js crypto) and validates PKCE + pure function outputs against shared
 * test vectors.
 *
 * Exit code 0: all vectors match.
 * Exit code 1: at least one mismatch (fail-close).
 *
 * Usage:
 *   node --experimental-strip-types \
 *     tests/verified_core_wasm/test_equivalence_wasm.ts [path/to/verified_core.wasm]
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { createHash } from "node:crypto";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

function findRoot() {
  try {
    return execSync("git rev-parse --show-toplevel", { encoding: "utf8" }).trim();
  } catch {
    return resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  }
}

const ROOT = findRoot();
const wasmPath =
  process.argv[2] ||
  resolve(ROOT, "tests/fixtures/verified-core/verified_core.wasm");
const vectorDir = resolve(ROOT, "tests/verified_core_wasm/vectors");

let passed = 0;
let failed = 0;

function pass(msg) {
  passed++;
  console.log(`  \x1b[32m✓\x1b[0m ${msg}`);
}

function fail(msg) {
  failed++;
  console.log(`  \x1b[31m✗\x1b[0m ${msg}`);
}

// ── Host callback state ──────────────────────────────────────────────
// Minimal handle registry: maps handle → Uint8Array
let nextHandle = 1;
const handleStore = new Map();
let wasmMemory = null;
let heapPtr = 0;

function ensureMemory(bytesNeeded) {
  if (!wasmMemory) return;
  const bufLen = wasmMemory.buffer.byteLength;
  if (bytesNeeded <= bufLen) return;
  const delta = bytesNeeded - bufLen;
  const pageSize = 65536;
  const pages = Math.ceil(delta / pageSize);
  wasmMemory.grow(pages);
}

function alloc(bytes) {
  if (!wasmMemory) return 0;
  if (heapPtr === 0) {
    heapPtr = 2 * 1024 * 1024;
  }
  const ptr = heapPtr;
  const next = heapPtr + bytes;
  ensureMemory(next);
  heapPtr = next;
  return ptr;
}

function readU32(ptr) {
  return new DataView(wasmMemory.buffer, ptr, 4).getUint32(0, true);
}

function writeU32(ptr, value) {
  new DataView(wasmMemory.buffer, ptr, 4).setUint32(0, value >>> 0, true);
}

function readCString(ptr) {
  if (!wasmMemory || ptr === 0) return "";
  const mem = new Uint8Array(wasmMemory.buffer);
  let end = ptr;
  while (end < mem.length && mem[end] !== 0) end++;
  return new TextDecoder().decode(mem.subarray(ptr, end));
}

function writeCString(str) {
  const bytes = new TextEncoder().encode(str);
  const ptr = alloc(bytes.length + 1);
  const mem = new Uint8Array(wasmMemory.buffer, ptr, bytes.length + 1);
  mem.set(bytes, 0);
  mem[bytes.length] = 0;
  return ptr;
}

function bytesPtrData(bytesPtr) {
  const len = readU32(bytesPtr);
  const dataPtr = readU32(bytesPtr + 4);
  return { len, dataPtr };
}

function hostRegisterBytes(ptr, len) {
  if (!wasmMemory || len === 0) return 0;
  const buf = new Uint8Array(wasmMemory.buffer, ptr, len);
  const copy = new Uint8Array(len);
  copy.set(buf);
  const h = nextHandle++;
  handleStore.set(h, copy);
  return h;
}

function hostReleaseHandle(handle) {
  handleStore.delete(handle);
}

function hostCryptoSha256(inputHandle, outputPtr) {
  const data = handleStore.get(inputHandle);
  if (!data) return 1; // error
  const hash = createHash("sha256").update(data).digest();
  const out = new Uint8Array(wasmMemory.buffer, outputPtr, 32);
  out.set(hash);
  return 0; // success
}

/**
 * Build host environment with functioning SHA-256.
 */
function buildHostEnv() {
  const env = {
      // FStar runtime stubs
      FStar_Bytes_get: (bytesPtr, idx) => {
        const { len, dataPtr } = bytesPtrData(bytesPtr);
        if (idx >>> 0 >= len) return 0;
        return new Uint8Array(wasmMemory.buffer, dataPtr, len)[idx >>> 0];
      },
      FStar_UInt32_uint_to_t: (v) => v >>> 0,
      Prims_op_Addition: (a, b) => (a + b) | 0,
      FStar_UInt32_v: (v) => v >>> 0,
      FStar_Bytes_len: (bytesPtr) => bytesPtrData(bytesPtr).len >>> 0,
      __eq__Prims_string: (a, b) => (readCString(a) === readCString(b) ? 1 : 0),
      FStar_String_uppercase: (sPtr) => writeCString(readCString(sPtr).toUpperCase()),
      Prims_op_LessThanOrEqual: (a, b) => (a <= b ? 1 : 0),
      Prims_strcat: (a, b) => writeCString(readCString(a) + readCString(b)),
      Prims_op_Subtraction: (a, b) => (a - b) | 0,
      Prims_pow2: (x) => (2 ** (x >>> 0)) | 0,
      Prims_op_Multiply: (a, b) => Math.imul(a, b),
      Prims_op_Modulus: (a, b) => (b === 0 ? 0 : (a % b) | 0),
      Prims_op_Division: (a, b) => (b === 0 ? 0 : (a / b) | 0),
      Prims_op_LessThan: (a, b) => (a < b ? 1 : 0),
      Prims_op_GreaterThanOrEqual: (a, b) => (a >= b ? 1 : 0),
      FStar_UInt8_v: (v) => v & 0xff,
      FStar_Char_char_of_u32: (v) => v >>> 0,
      FStar_String_strlen: (ptr) => readCString(ptr).length >>> 0,
      FStar_String_string_of_list: (listPtr) => {
        if (!wasmMemory || listPtr === 0) return writeCString("");
        const mem = wasmMemory.buffer;
        let ptr = listPtr >>> 0;
        const chars = [];
        let guard = 0;
        while (ptr !== 0 && guard < 65536) {
          guard++;
          const tag = new Uint8Array(mem, ptr, 1)[0];
          if (tag === 0) break;
          const ch = new DataView(mem, ptr + 4, 4).getUint32(0, true);
          chars.push(String.fromCodePoint(ch));
          ptr = new DataView(mem, ptr + 8, 4).getUint32(0, true);
        }
        return writeCString(chars.join(""));
      },
      FStar_Bytes_create: (outPtr, len, init) => {
        const n = len >>> 0;
        const dataPtr = alloc(n);
        if (n > 0) {
          const mem = new Uint8Array(wasmMemory.buffer, dataPtr, n);
          mem.fill(init & 0xff);
        }
        writeU32(outPtr, n);
        writeU32(outPtr + 4, dataPtr);
      },
      FStar_Bytes_sub: (outPtr, bytesPtr, start, len) => {
        const { len: srcLen, dataPtr } = bytesPtrData(bytesPtr);
        const off = start >>> 0;
        const n = len >>> 0;
        const dataPtrOut = alloc(n);
        if (n > 0 && off + n <= srcLen) {
          const src = new Uint8Array(wasmMemory.buffer, dataPtr + off, n);
          const dst = new Uint8Array(wasmMemory.buffer, dataPtrOut, n);
          dst.set(src);
        }
        writeU32(outPtr, n);
        writeU32(outPtr + 4, dataPtrOut);
      },
      __eq__FStar_Bytes_bytes: (aPtr, bPtr) => {
        const a = bytesPtrData(aPtr);
        const b = bytesPtrData(bPtr);
        if (a.len !== b.len) return 0;
        if (a.len === 0) return 1;
        const aBytes = new Uint8Array(wasmMemory.buffer, a.dataPtr, a.len);
        const bBytes = new Uint8Array(wasmMemory.buffer, b.dataPtr, b.len);
        for (let i = 0; i < a.len; i++) {
          if (aBytes[i] !== bBytes[i]) return 0;
        }
        return 1;
      },

      // libc-like stubs
      malloc: (size) => alloc(size >>> 0),
      calloc: (count, size) => {
        const n = (count >>> 0) * (size >>> 0);
        const ptr = alloc(n);
        if (n > 0) {
          const mem = new Uint8Array(wasmMemory.buffer, ptr, n);
          mem.fill(0);
        }
        return ptr;
      },
      free: (_ptr) => {},
      strlen: (ptr) => readCString(ptr).length >>> 0,

      // PKCE host callbacks
      Pkce_strlen: () => 0,
      Pkce_s256: () => 0,
      Pkce_Verification_base64url_encode: () => 0,
      Pkce_Verification_sha256: () => {},

      // DPoP host callbacks
      Dpop_Ath_validation_sha256: () => {},
      Dpop_Signature_verify_signature: () => 0,

      // VerifiedCore Claims Runtime host callbacks
      VerifiedCore_Api_Claims_Runtime_host_crypto_verify_signature: () => 1,
      VerifiedCore_Api_Claims_Runtime_host_crypto_sha256: hostCryptoSha256,
      VerifiedCore_Api_Claims_Runtime_host_replay_store_check_and_store: () => 0,
      VerifiedCore_Api_Claims_Runtime_host_bytes_eq: (a, b) =>
        a === b ? 1 : 0,

      // Parsing host callbacks
      Host_parse_dpop_compact: () => 1,
      Host_parse_jwt_compact: () => 1,
      Host_verify_ath_binding: () => 0,
      Host_check_audience_membership: () => 0,

      // vc_* ABI host callbacks
      vc_host_register_bytes: hostRegisterBytes,
      vc_host_release_handle: hostReleaseHandle,

      // libc stubs
      fprintf: () => 0,
      exit: (code) => {
        throw new Error(`WASM called exit(${code})`);
      },
  };

  const fallbackStub = () => 0;
  return {
    env: new Proxy(env, {
      get(target, prop) {
        if (prop in target) return target[prop];
        return fallbackStub;
      },
    }),
  };
}

// ── Helpers ──────────────────────────────────────────────────────────

/** Write a string into WASM linear memory and return {ptr, len}. */
function writeString(str) {
  const bytes = new TextEncoder().encode(str);
  const ptr = alloc(bytes.length + 1);
  const mem = new Uint8Array(wasmMemory.buffer, ptr, bytes.length + 1);
  mem.set(bytes, 0);
  mem[bytes.length] = 0;
  return { ptr, len: bytes.length };
}

/** Read a string from WASM linear memory. */
function readBytes(ptr, len) {
  return new Uint8Array(wasmMemory.buffer, ptr, len);
}

// ���─ Main ─────────────────────────────────────────────────────────────

console.log("=== WASM Equivalence Tests ===");
console.log(`  artifact: ${wasmPath}`);
console.log("");

// Load and instantiate WASM
let wasmBytes;
try {
  wasmBytes = readFileSync(wasmPath);
} catch (e) {
  console.log(`  FATAL: Cannot load WASM: ${e.message}`);
  process.exit(1);
}

let instance;
try {
  const mod = new WebAssembly.Module(wasmBytes);
  const env = buildHostEnv();
  instance = new WebAssembly.Instance(mod, env);
  wasmMemory = instance.exports.memory;
  pass("WASM instantiation with host callbacks");
} catch (e) {
  fail(`WASM instantiation failed: ${e.message}`);
  process.exit(1);
}

// ── Pure function tests ──────────────────────────────────────────────

console.log("");
console.log("--- Pure function vectors ---");

let pureVectors;
try {
  pureVectors = JSON.parse(readFileSync(resolve(vectorDir, "pure_functions.json"), "utf8"));
} catch (e) {
  fail(`Cannot load pure_functions.json: ${e.message}`);
  process.exit(1);
}

// status_to_u32
const statusToU32 = instance.exports.VerifiedCore_Api_Claims_Runtime_status_to_u32;
if (typeof statusToU32 === "function") {
  for (const v of pureVectors.status_to_u32) {
    const result = statusToU32(v.input);
    if (result === v.expected) {
      pass(`status_to_u32(${v.label}=${v.input}) → ${result}`);
    } else {
      fail(`status_to_u32(${v.label}=${v.input}) → ${result} (expected ${v.expected})`);
    }
  }
} else {
  fail("status_to_u32 not exported");
}

// iat_in_window
const iatInWindow = instance.exports.VerifiedCore_Api_Claims_Runtime_iat_in_window;
if (typeof iatInWindow === "function") {
  for (const v of pureVectors.iat_in_window) {
    const result = iatInWindow(BigInt(v.iat), BigInt(v.now), v.max_age, v.max_skew);
    if (result === v.expected) {
      pass(`iat_in_window(${v.id}) → ${result}`);
    } else {
      fail(`iat_in_window(${v.id}) → ${result} (expected ${v.expected})`);
    }
  }
} else {
  fail("iat_in_window not exported");
}

// not_expired
const notExpired = instance.exports.VerifiedCore_Api_Claims_Runtime_not_expired;
if (typeof notExpired === "function") {
  for (const v of pureVectors.not_expired) {
    const result = notExpired(BigInt(v.exp), BigInt(v.now));
    if (result === v.expected) {
      pass(`not_expired(${v.id}) → ${result}`);
    } else {
      fail(`not_expired(${v.id}) → ${result} (expected ${v.expected})`);
    }
  }
} else {
  fail("not_expired not exported");
}

// is_active
const isActive = instance.exports.VerifiedCore_Api_Claims_Runtime_is_active;
if (typeof isActive === "function") {
  for (const v of pureVectors.is_active) {
    const result = isActive(BigInt(v.nbf), BigInt(v.now));
    if (result === v.expected) {
      pass(`is_active(${v.id}) → ${result}`);
    } else {
      fail(`is_active(${v.id}) → ${result} (expected ${v.expected})`);
    }
  }
} else {
  fail("is_active not exported");
}

// bytes_handle_is_present
const handlePresent = instance.exports.VerifiedCore_Api_Claims_Runtime_bytes_handle_is_present;
if (typeof handlePresent === "function") {
  for (const v of pureVectors.bytes_handle_is_present) {
    const result = handlePresent(v.input >>> 0); // ensure u32
    if (result === v.expected) {
      pass(`bytes_handle_is_present(${v.label}) → ${result}`);
    } else {
      fail(`bytes_handle_is_present(${v.label}) → ${result} (expected ${v.expected})`);
    }
  }
} else {
  console.log("  [skip] bytes_handle_is_present not exported");
}

// ─��� PKCE S256 tests (requires SHA-256 host callback) ─────────────────

console.log("");
console.log("--- PKCE S256 vectors ---");

let pkceVectors;
try {
  pkceVectors = JSON.parse(readFileSync(resolve(vectorDir, "pkce_s256.json"), "utf8"));
} catch (e) {
  fail(`Cannot load pkce_s256.json: ${e.message}`);
  process.exit(1);
}

const vcPkceGenerate = instance.exports.vc_pkce_challenge_generate;
const vcPkceVerify = instance.exports.vc_pkce_challenge_verify;

if (typeof vcPkceGenerate !== "function" || typeof vcPkceVerify !== "function") {
  console.log(
    "  [skip] vc_pkce_challenge_generate/verify not exported (fixture may pre-date ABI shim)",
  );
} else {
  // vc_pkce_challenge_generate takes (verifier_ptr, verifier_len, method) and
  // returns a struct {code, data_ptr, data_len} packed in WASM linear memory.
  //
  // In WASM, C functions returning structs use a "sret" pattern: the caller
  // passes a pointer to the return value as the first argument.

  const VC_PKCE_METHOD_S256 = 1;

  /**
   * Call vc_pkce_challenge_generate via WASM.
   * Returns {code, challenge_bytes} or {code, null}.
   */
  function callPkceGenerate(verifierStr) {
    // Reset bump allocator for each call
    heapPtr = 2 * 1024 * 1024;
    // Reset handle store
    nextHandle = 1;
    handleStore.clear();

    const v = writeString(verifierStr);
    const vSlicePtr = alloc(8);
    writeU32(vSlicePtr, v.ptr >>> 0);
    writeU32(vSlicePtr + 4, v.len >>> 0);

    // Allocate space for vc_result (12 bytes: u32 code + u32 data_ptr + u32 data_len)
    const resultPtr = writeString._offset;
    writeString._offset += 16;

    // Clear result area
    const resultView = new Uint8Array(wasmMemory.buffer, resultPtr, 12);
    resultView.fill(0);

    // Call: sret pattern → first arg is pointer to result struct
    vcPkceGenerate(resultPtr, vSlicePtr, VC_PKCE_METHOD_S256);

    // Read result
    const dv = new DataView(wasmMemory.buffer, resultPtr, 12);
    const code = dv.getUint32(0, true);
    const dataPtr = dv.getUint32(4, true);
    const dataLen = dv.getUint32(8, true);

    if (code === 0 && dataLen > 0 && dataPtr !== 0) {
      const bytes = new Uint8Array(wasmMemory.buffer, dataPtr, dataLen);
      return { code, challenge: new TextDecoder().decode(bytes) };
    }
    return { code, challenge: null };
  }

  /**
   * Call vc_pkce_challenge_verify via WASM.
   * Returns the error code.
   */
  function callPkceVerify(verifierStr, challengeStr) {
    heapPtr = 2 * 1024 * 1024;
    nextHandle = 1;
    handleStore.clear();

    const v = writeString(verifierStr);
    const c = writeString(challengeStr);
    const vSlicePtr = alloc(8);
    writeU32(vSlicePtr, v.ptr >>> 0);
    writeU32(vSlicePtr + 4, v.len >>> 0);
    const cSlicePtr = alloc(8);
    writeU32(cSlicePtr, c.ptr >>> 0);
    writeU32(cSlicePtr + 4, c.len >>> 0);

    const resultPtr = writeString._offset;
    writeString._offset += 16;
    const resultView = new Uint8Array(wasmMemory.buffer, resultPtr, 12);
    resultView.fill(0);

    vcPkceVerify(resultPtr, vSlicePtr, cSlicePtr, VC_PKCE_METHOD_S256);

    const dv = new DataView(wasmMemory.buffer, resultPtr, 12);
    return dv.getUint32(0, true);
  }

  // Test valid vectors: generate challenge and compare
  for (const v of pkceVectors.vectors) {
    try {
      const gen = callPkceGenerate(v.verifier);
      if (gen.code !== 0) {
        fail(`pkce_generate(${v.id}): code=${gen.code} (expected 0/OK)`);
        continue;
      }
      if (gen.challenge === v.challenge) {
        pass(`pkce_generate(${v.id}): ${gen.challenge}`);
      } else {
        fail(`pkce_generate(${v.id}): got "${gen.challenge}" expected "${v.challenge}"`);
      }

      // Also test verify
      const verifyCode = callPkceVerify(v.verifier, v.challenge);
      if (verifyCode === 0) {
        pass(`pkce_verify(${v.id}): OK`);
      } else {
        fail(`pkce_verify(${v.id}): code=${verifyCode} (expected 0/OK)`);
      }
    } catch (e) {
      fail(`pkce(${v.id}): exception: ${e.message}`);
    }
  }

  // Test error vectors
  const VC_INVALID_ARGUMENT = 1;
  const VC_INVALID_CLAIMS = 4;
  const expectedCodes = {
    invalid_argument: VC_INVALID_ARGUMENT,
    invalid_claims: VC_INVALID_CLAIMS,
  };

  for (const v of pkceVectors.error_vectors) {
    try {
      if (v.challenge) {
        // Verify with wrong challenge
        const code = callPkceVerify(v.verifier, v.challenge);
        const expectedCode = expectedCodes[v.expect];
        if (code === expectedCode) {
          pass(`pkce_verify_error(${v.id}): code=${code}`);
        } else {
          fail(`pkce_verify_error(${v.id}): code=${code} (expected ${expectedCode})`);
        }
      } else {
        // Generate with invalid verifier
        const gen = callPkceGenerate(v.verifier);
        const expectedCode = expectedCodes[v.expect];
        if (gen.code === expectedCode) {
          pass(`pkce_generate_error(${v.id}): code=${gen.code}`);
        } else {
          fail(`pkce_generate_error(${v.id}): code=${gen.code} (expected ${expectedCode})`);
        }
      }
    } catch (e) {
      fail(`pkce_error(${v.id}): exception: ${e.message}`);
    }
  }
}

// ── ABI introspection ────────────────────────────────────────────────

console.log("");
console.log("--- ABI introspection ---");

const vcAbiVersion = instance.exports.vc_abi_version;
if (typeof vcAbiVersion === "function") {
  const ver = vcAbiVersion();
  if (ver === 2) {
    pass(`vc_abi_version() → ${ver}`);
  } else {
    fail(`vc_abi_version() → ${ver} (expected 2)`);
  }
} else {
  // Old fixtures pre-date the ABI shim — not a failure
  console.log("  [skip] vc_abi_version not exported (fixture may pre-date ABI shim)");
}

// ���─ Summary ──────────────────────────────────────────────────────────

console.log("");
console.log(
  `=== WASM Equivalence: ${passed}/${passed + failed} passed (${failed} failed) ===`
);
process.exit(failed > 0 ? 1 : 0);
