#!/usr/bin/env node
/**
 * Verified Core WASM functional smoke test.
 *
 * Instantiates the WASM module with mock host callbacks and exercises:
 *   - Module instantiation succeeds
 *   - Memory export is usable
 *   - Pure functions return expected values
 *   - Host callback imports are invoked correctly
 *
 * Usage:
 *   node --experimental-strip-types tests/verified_core_wasm/test_instantiate.ts
 *     [path/to/verified_core.wasm]
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { createHash, generateKeyPairSync, sign as signBytes } from "node:crypto";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

function findRoot() {
  try {
    return execSync("git rev-parse --show-toplevel", { encoding: "utf8" }).trim();
  } catch {
    // Fallback for non-git environments (tarball, Nix build, CI source copy):
    // this file lives at <root>/tests/verified_core_wasm/test_instantiate.ts
    return resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  }
}

const ROOT = findRoot();
const wasmPath = process.argv[2] ||
  resolve(ROOT, "tests/fixtures/verified-core/verified_core.wasm");

let passed = 0;
let failed = 0;
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
  if (heapPtr === 0) heapPtr = 2 * 1024 * 1024;
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

function writeU64(ptr, value) {
  new DataView(wasmMemory.buffer, ptr, 8).setBigUint64(0, BigInt(value), true);
}

function writeBytes(bytes) {
  const ptr = alloc(bytes.length || 1);
  if (bytes.length > 0) {
    new Uint8Array(wasmMemory.buffer, ptr, bytes.length).set(bytes);
  }
  return { ptr, len: bytes.length };
}

function registerHandleBytes(bytes) {
  const { ptr, len } = writeBytes(bytes);
  const handle = nextHandleId++;
  handleTable.set(handle, { ptr, len });
  return handle;
}

function readBytes(ptr, len) {
  return Uint8Array.from(new Uint8Array(wasmMemory.buffer, ptr, len));
}

function readHandleBytes(handle) {
  const entry = handleTable.get(handle);
  if (!entry) return null;
  return readBytes(entry.ptr, entry.len);
}

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (normalized.length % 4)) % 4;
  return Uint8Array.from(Buffer.from(normalized + "=".repeat(padding), "base64"));
}

function sha256(bytes) {
  return Uint8Array.from(createHash("sha256").update(bytes).digest());
}

function utf8(value) {
  return new TextEncoder().encode(value);
}

function combineI64Parts(low, high) {
  return BigInt.asIntN(64, BigInt(low >>> 0) | (BigInt(high >>> 0) << 32n));
}

function combineI128Parts(low, high) {
  return BigInt.asIntN(128, BigInt.asUintN(64, low) | (BigInt.asIntN(64, high) << 64n));
}

function multi3(...args) {
  if (args.length === 5 && wasmMemory) {
    const [outPtr, aLow, aHigh, bLow, bHigh] = args;
    const left = combineI128Parts(aLow, aHigh);
    const right = combineI128Parts(bLow, bHigh);
    const product = BigInt.asIntN(128, left * right);
    new DataView(wasmMemory.buffer, outPtr >>> 0, 16).setBigUint64(
      0,
      BigInt.asUintN(64, product),
      true,
    );
    new DataView(wasmMemory.buffer, (outPtr >>> 0) + 8, 8).setBigInt64(
      0,
      BigInt.asIntN(64, product >> 64n),
      true,
    );
    return;
  }
  if (args.length === 2 && typeof args[0] === "bigint" && typeof args[1] === "bigint") {
    return BigInt.asIntN(64, args[0] * args[1]);
  }
  if (args.length === 4) {
    const left = combineI64Parts(args[0], args[1]);
    const right = combineI64Parts(args[2], args[3]);
    return BigInt.asIntN(64, left * right);
  }
  return 0n;
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

function pass(msg) {
  passed++;
  console.log(`  \x1b[32m✓\x1b[0m ${msg}`);
}

function fail(msg) {
  failed++;
  console.log(`  \x1b[31m✗\x1b[0m ${msg}`);
}

/* Handle table for vc_host_register_bytes / Host_handle_data_ptr/len */
const handleTable = new Map();
const replayStore = new Set();
let nextHandleId = 1;

function clearReplayStore() {
  replayStore.clear();
}

/**
 * Build mock host environment with all required WASM imports.
 * Each import is a stub that returns a sensible default.
 */
function buildMockEnv() {
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
      Pkce_strlen: (s) => 0,
      Pkce_s256: (v) => 0,
      Pkce_Verification_base64url_encode: (v) => 0,
      Pkce_Verification_sha256: (a, b) => {},

      // DPoP host callbacks
      Dpop_Ath_validation_sha256: (a, b) => {},
      Dpop_Signature_verify_signature: (a, b, c, d) => 0,

      // VerifiedCore Claims Runtime host callbacks (Phase D: only replay store remains)
      VerifiedCore_Api_Claims_Runtime_host_replay_store_check_and_store:
        (nsPtrParam, nsLenParam, keyHashPtr, ttlMs) => {
          const namespace = Buffer.from(
            readBytes(nsPtrParam >>> 0, nsLenParam >>> 0),
          ).toString("hex");
          const keyHash = Buffer.from(readBytes(keyHashPtr >>> 0, 32)).toString("hex");
          const cacheKey = `${namespace}:${keyHash}:${ttlMs >>> 0}`;
          if (replayStore.has(cacheKey)) {
            return 1;
          }
          replayStore.add(cacheKey);
          return 0;
        },

      // Parsing host callbacks
      Host_parse_dpop_compact: (handle, resultPtr) => 1, // parse error
      Host_parse_jwt_compact: (handle, resultPtr) => 1,  // parse error
      Host_verify_ath_binding: (atH, athH) => 0,
      Host_check_audience_membership: (expH, audH) => {
        const expected = readHandleBytes(expH);
        const audience = readHandleBytes(audH);
        if (!expected || !audience) return 0;
        const expectedText = Buffer.from(expected).toString("utf8");
        const audienceText = Buffer.from(audience).toString("utf8");
        try {
          const parsed = JSON.parse(audienceText);
          if (Array.isArray(parsed)) {
            return parsed.includes(expectedText) ? 1 : 0;
          }
          return parsed === expectedText ? 1 : 0;
        } catch {
          return audienceText === expectedText ? 1 : 0;
        }
      },

      // vc_* ABI host callbacks (may or may not be present)
      vc_host_register_bytes: (ptr, len) => {
        const id = nextHandleId++;
        handleTable.set(id, { ptr, len });
        return id;
      },
      vc_host_release_handle: (handle) => {
        handleTable.delete(handle);
      },

      // Handle resolution (Phase D: resolve handle → WASM linear memory pointer)
      Host_handle_data_ptr: (handle) => {
        const entry = handleTable.get(handle);
        return entry ? entry.ptr : 0;
      },
      Host_handle_data_len: (handle) => {
        const entry = handleTable.get(handle);
        return entry ? entry.len : 0;
      },

      // memcmp for handle-based byte comparison (Phase D)
      memcmp: (a, b, n) => {
        if (!wasmMemory || n === 0) return 0;
        const mem = new Uint8Array(wasmMemory.buffer);
        for (let i = 0; i < (n >>> 0); i++) {
          const diff = mem[(a >>> 0) + i] - mem[(b >>> 0) + i];
          if (diff !== 0) return diff < 0 ? -1 : 1;
        }
        return 0;
      },

      // 128-bit multiplication intrinsic (used by HACL* bignum)
      __multi3: (...args) => multi3(...args),

      // libc stubs
      fprintf: (stream, fmt, ...args) => 0,
      exit: (code) => { throw new Error(`WASM called exit(${code})`); },
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

console.log("=== Verified Core WASM Functional Tests ===");
console.log(`  artifact: ${wasmPath}`);
console.log("");

// --- Test 1: Load WASM binary ---
let wasmBytes;
try {
  wasmBytes = readFileSync(wasmPath);
  pass(`Loaded WASM binary (${wasmBytes.length} bytes)`);
} catch (e) {
  fail(`Failed to load WASM: ${e.message}`);
  process.exit(1);
}

// --- Test 2: Compile WASM module ---
let wasmModule;
try {
  wasmModule = new WebAssembly.Module(wasmBytes);
  pass("WebAssembly.Module compiled successfully");
} catch (e) {
  fail(`Compilation failed: ${e.message}`);
  process.exit(1);
}

// --- Test 3: Inspect imports ---
const imports = WebAssembly.Module.imports(wasmModule);
if (imports.length > 0) {
  pass(`Module has ${imports.length} imports`);
} else {
  fail("Module has no imports (expected host callbacks)");
}

// --- Test 4: Inspect exports ---
const exportDescs = WebAssembly.Module.exports(wasmModule);
const exportNames = exportDescs.map((e) => e.name);
if (exportNames.length >= 20) {
  pass(`Module has ${exportNames.length} exports`);
} else {
  fail(`Too few exports: ${exportNames.length} (expected >= 20)`);
}

// --- Test 5: Required exports present ---
const requiredExports = [
  "memory",
  "VerifiedCore_dpop_verify_v1",
  "VerifiedCore_jwt_verify_v1",
  "VerifiedCore_dpop_verify_claims_v1",
  "VerifiedCore_jwt_verify_claims_v1",
  "VerifiedCore_Api_Claims_Runtime_status_to_u32",
  "VerifiedCore_Api_Claims_Runtime_dpop_verify_claims_impl",
  "VerifiedCore_Api_Claims_Runtime_jwt_verify_claims_impl",
  "Pkce_verifier_ok",
  "ConstTime_ct_bytes_eq",
];

for (const name of requiredExports) {
  if (exportNames.includes(name)) {
    pass(`Export present: ${name}`);
  } else {
    fail(`Missing export: ${name}`);
  }
}

// --- Test 6: Instantiate with mock environment ---
let instance;
try {
  const mockEnv = buildMockEnv();
  instance = new WebAssembly.Instance(wasmModule, mockEnv);
  pass("WebAssembly.Instance created with mock host");
} catch (e) {
  fail(`Instantiation failed: ${e.message}`);
  console.log("");
  console.log(`=== Results: ${passed}/${passed + failed} passed (${failed} failed) ===`);
  process.exit(failed > 0 ? 1 : 0);
}

// --- Test 7: Memory is accessible ---
const memory = instance.exports.memory;
if (memory instanceof WebAssembly.Memory) {
  wasmMemory = memory;
  const buf = new Uint8Array(memory.buffer);
  pass(
    `Memory accessible (${memory.buffer.byteLength} bytes, ${
      memory.buffer.byteLength / 65536
    } pages)`,
  );
} else {
  fail("Memory export is not a WebAssembly.Memory");
}

// --- Test 8: status_to_u32 pure function ---
const statusToU32 = instance.exports.VerifiedCore_Api_Claims_Runtime_status_to_u32;
if (typeof statusToU32 === "function") {
  // OK = 0 → should return 0
  const okResult = statusToU32(0);
  if (okResult === 0) {
    pass("status_to_u32(OK=0) → 0");
  } else {
    fail(`status_to_u32(OK=0) → ${okResult} (expected 0)`);
  }

  // INVALID_ARGUMENT = 1 → should return 1
  const iaResult = statusToU32(1);
  if (iaResult === 1) {
    pass("status_to_u32(INVALID_ARGUMENT=1) → 1");
  } else {
    fail(`status_to_u32(INVALID_ARGUMENT=1) → ${iaResult} (expected 1)`);
  }

  // UNSUPPORTED = 7 → should return 7
  const usResult = statusToU32(7);
  if (usResult === 7) {
    pass("status_to_u32(UNSUPPORTED=7) → 7");
  } else {
    fail(`status_to_u32(UNSUPPORTED=7) → ${usResult} (expected 7)`);
  }
} else {
  fail("status_to_u32 is not a function");
}

// --- Test 9: iat_in_window pure function ---
const iatInWindow = instance.exports.VerifiedCore_Api_Claims_Runtime_iat_in_window;
if (typeof iatInWindow === "function") {
  // iat=1000, now=1000, max_age=300, max_skew=60 → should be valid (1)
  const result1 = iatInWindow(
    BigInt(1000), BigInt(1000),   // iat, now
    300, 60                       // max_age, max_skew
  );
  if (result1 === 1) {
    pass("iat_in_window(iat=1000, now=1000, age=300, skew=60) → 1 (valid)");
  } else {
    fail(`iat_in_window(iat=1000, now=1000, age=300, skew=60) → ${result1} (expected 1)`);
  }

  // iat=500, now=1000, max_age=300 → should be expired (0)
  const result2 = iatInWindow(
    BigInt(500), BigInt(1000),
    300, 60
  );
  if (result2 === 0) {
    pass("iat_in_window(iat=500, now=1000, age=300, skew=60) → 0 (expired)");
  } else {
    fail(`iat_in_window(iat=500, now=1000, age=300, skew=60) → ${result2} (expected 0)`);
  }
} else {
  fail("iat_in_window is not a function");
}

// --- Test 10: not_expired pure function ---
const notExpired = instance.exports.VerifiedCore_Api_Claims_Runtime_not_expired;
if (typeof notExpired === "function") {
  // exp=2000, now=1000 → not expired (1)
  const result1 = notExpired(BigInt(2000), BigInt(1000));
  if (result1 === 1) {
    pass("not_expired(exp=2000, now=1000) → 1 (valid)");
  } else {
    fail(`not_expired(exp=2000, now=1000) → ${result1} (expected 1)`);
  }

  // exp=500, now=1000 → expired (0)
  const result2 = notExpired(BigInt(500), BigInt(1000));
  if (result2 === 0) {
    pass("not_expired(exp=500, now=1000) → 0 (expired)");
  } else {
    fail(`not_expired(exp=500, now=1000) → ${result2} (expected 0)`);
  }
} else {
  fail("not_expired is not a function");
}

// --- Test 11: is_active pure function ---
const isActive = instance.exports.VerifiedCore_Api_Claims_Runtime_is_active;
if (typeof isActive === "function") {
  // nbf=500, now=1000 → active (1)
  const result1 = isActive(BigInt(500), BigInt(1000));
  if (result1 === 1) {
    pass("is_active(nbf=500, now=1000) → 1 (active)");
  } else {
    fail(`is_active(nbf=500, now=1000) → ${result1} (expected 1)`);
  }

  // nbf=2000, now=1000 → not yet active (0)
  const result2 = isActive(BigInt(2000), BigInt(1000));
  if (result2 === 0) {
    pass("is_active(nbf=2000, now=1000) → 0 (not yet active)");
  } else {
    fail(`is_active(nbf=2000, now=1000) → ${result2} (expected 0)`);
  }
} else {
  fail("is_active is not a function");
}

// --- Test 12: try_verify_signature (Phase D: renamed from try_verify_signature_multi) ---
const tryVerifySig = instance.exports.VerifiedCore_Api_Claims_Runtime_try_verify_signature;
if (typeof tryVerifySig === "function") {
  pass("try_verify_signature export present");
} else {
  fail("try_verify_signature is not a function");
}

// --- Test 13: algorithm_from_bitmask ---
const algFromBitmask = instance.exports.VerifiedCore_Api_Claims_Runtime_algorithm_from_bitmask;
if (typeof algFromBitmask === "function") {
  // bitmask=0x01 (ES256), alg=ES256(0) → true(1)
  const r1 = algFromBitmask(0x01, 0);
  // bitmask=0x01 (ES256), alg=RS256(1) → false(0)
  const r2 = algFromBitmask(0x01, 1);
  // bitmask=0x07 (all), alg=EdDSA(2) → true(1)
  const r3 = algFromBitmask(0x07, 2);
  if (r1 === 1 && r2 === 0 && r3 === 1) {
    pass("algorithm_from_bitmask correctly filters algorithms");
  } else {
    fail(`algorithm_from_bitmask: ES256 in 0x01=${r1}, RS256 in 0x01=${r2}, EdDSA in 0x07=${r3}`);
  }
} else {
  fail("algorithm_from_bitmask is not a function");
}

// --- Test 14: Check new vc_* exports (may not be present in old fixtures) ---
const vcExports = [
  "vc_pkce_challenge_generate",
  "vc_pkce_challenge_verify",
  "vc_dpop_verify",
  "vc_jwt_verify",
  "vc_free_slice",
  "vc_version",
  "vc_abi_version",
];
let vcPresent = 0;
for (const name of vcExports) {
  if (exportNames.includes(name)) {
    vcPresent++;
  }
}
if (vcPresent === vcExports.length) {
  pass(`All ${vcPresent} vc_* public ABI exports present`);
} else if (vcPresent === 0) {
  fail(`vc_* ABI exports missing (0/${vcExports.length}) — fixture may pre-date ABI shim`);
} else {
  fail(`Partial vc_* ABI: ${vcPresent}/${vcExports.length} present`);
}

// --- Test 15: Claims-only JWT verification (EdDSA happy path + constraints) ---
const verifyJwtClaims = instance.exports.VerifiedCore_jwt_verify_claims_v1;
const verifyDpopClaims = instance.exports.VerifiedCore_dpop_verify_claims_v1;
const VC_OK = 0;
const VC_INVALID_SIGNATURE = 3;
const VC_INVALID_CLAIMS = 4;
const VC_REPLAY = 5;
const VC_UNSUPPORTED = 7;
const ALG_RS256 = 1 << 1;
const ALG_EDDSA = 1 << 2;
const JWT_REQUIRE_EXP = 1;
const JWT_SIGNATURE_PREVERIFIED = 1 << 3;
const DPOP_SIGNATURE_PREVERIFIED = 1 << 2;

function writeJwtClaimsInput(fields) {
  const ptr = alloc(72);
  writeU32(ptr + 0, fields.signingInputHandle ?? 0);
  writeU32(ptr + 4, fields.signatureBytesHandle ?? 0);
  writeU32(ptr + 8, fields.publicKeyBytesHandle ?? 0);
  writeU32(ptr + 12, fields.publicKeyFormat ?? 0);
  writeU32(ptr + 16, fields.claimsIssuerHandle ?? 0);
  writeU32(ptr + 20, fields.claimsAudienceHandle ?? 0);
  writeU32(ptr + 24, fields.allowedAlgorithmsBitmask ?? 0);
  writeU32(ptr + 28, fields.flags ?? 0);
  writeU32(ptr + 32, fields.expectedIssuerHandle ?? 0);
  writeU32(ptr + 36, fields.expectedAudienceHandle ?? 0);
  writeU64(ptr + 40, fields.expSeconds ?? 0n);
  writeU64(ptr + 48, fields.nbfSeconds ?? 0n);
  writeU64(ptr + 56, fields.iatSeconds ?? 0n);
  writeU64(ptr + 64, fields.nowUnixTimeSeconds ?? 0n);
  return ptr;
}

function writeDpopClaimsInput(fields) {
  const ptr = alloc(72);
  writeU32(ptr + 0, fields.httpMethodBytesHandle ?? 0);
  writeU32(ptr + 4, fields.httpUriBytesHandle ?? 0);
  writeU32(ptr + 8, fields.signingInputHandle ?? 0);
  writeU32(ptr + 12, fields.signatureBytesHandle ?? 0);
  writeU32(ptr + 16, fields.publicKeyBytesHandle ?? 0);
  writeU32(ptr + 20, fields.publicKeyFormat ?? 0);
  writeU32(ptr + 24, fields.replayNamespaceHandle ?? 0);
  writeU32(ptr + 28, fields.accessTokenHashHandle ?? 0);
  writeU32(ptr + 32, fields.jtiBytesHandle ?? 0);
  writeU32(ptr + 36, fields.allowedAlgorithmsBitmask ?? 0);
  writeU32(ptr + 40, fields.flags ?? 0);
  writeU32(ptr + 44, fields.reserved0 ?? 0);
  writeU64(ptr + 48, fields.iatSeconds ?? 0n);
  writeU64(ptr + 56, fields.nowUnixTimeSeconds ?? 0n);
  writeU32(ptr + 64, fields.maxAgeSeconds ?? 0);
  writeU32(ptr + 68, fields.maxFutureSkewSeconds ?? 0);
  return ptr;
}

function buildEd25519Fixture(messageText) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signingInput = utf8(messageText);
  const signature = new Uint8Array(signBytes(null, Buffer.from(signingInput), privateKey));
  const publicJwk = publicKey.export({ format: "jwk" });
  const publicKeyBytes = decodeBase64Url(publicJwk.x);
  return { signingInput, signature, publicKeyBytes };
}

if (typeof verifyJwtClaims === "function") {
  const now = 1_710_000_000n;
  const fixture = buildEd25519Fixture("eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjMifQ");
  const signingInputHandle = registerHandleBytes(fixture.signingInput);
  const signatureHandle = registerHandleBytes(fixture.signature);
  const publicKeyHandle = registerHandleBytes(fixture.publicKeyBytes);
  const claimsIssuerHandle = registerHandleBytes(utf8("https://issuer.example"));
  const claimsAudienceHandle = registerHandleBytes(utf8('["client-123","other"]'));
  const expectedIssuerHandle = registerHandleBytes(utf8("https://issuer.example"));
  const expectedAudienceHandle = registerHandleBytes(utf8("client-123"));
  const outputPtr = alloc(80);

  const okInputPtr = writeJwtClaimsInput({
    signingInputHandle,
    signatureBytesHandle: signatureHandle,
    publicKeyBytesHandle: publicKeyHandle,
    claimsIssuerHandle,
    claimsAudienceHandle,
    allowedAlgorithmsBitmask: ALG_EDDSA,
    flags: JWT_REQUIRE_EXP,
    expectedIssuerHandle,
    expectedAudienceHandle,
    expSeconds: now + 300n,
    nowUnixTimeSeconds: now,
  });

  const okStatus = verifyJwtClaims(okInputPtr, outputPtr);
  const payloadHash = readBytes(outputPtr, 32);
  if (
    okStatus === VC_OK
    && Buffer.from(payloadHash).equals(Buffer.from(sha256(fixture.signingInput)))
  ) {
    pass("jwt_verify_claims_v1 accepts valid EdDSA input and fills payloadHash");
  } else {
    fail(`jwt_verify_claims_v1 valid path → status=${okStatus}`);
  }

  const badIssuerPtr = writeJwtClaimsInput({
    signingInputHandle,
    signatureBytesHandle: signatureHandle,
    publicKeyBytesHandle: publicKeyHandle,
    claimsIssuerHandle,
    claimsAudienceHandle,
    allowedAlgorithmsBitmask: ALG_EDDSA,
    expectedIssuerHandle: registerHandleBytes(utf8("https://wrong.example")),
    expectedAudienceHandle,
    expSeconds: now + 300n,
    nowUnixTimeSeconds: now,
  });
  if (verifyJwtClaims(badIssuerPtr, outputPtr) === VC_INVALID_CLAIMS) {
    pass("jwt_verify_claims_v1 rejects issuer mismatches");
  } else {
    fail("jwt_verify_claims_v1 should reject issuer mismatches");
  }

  const badAudiencePtr = writeJwtClaimsInput({
    signingInputHandle,
    signatureBytesHandle: signatureHandle,
    publicKeyBytesHandle: publicKeyHandle,
    claimsIssuerHandle,
    claimsAudienceHandle,
    allowedAlgorithmsBitmask: ALG_EDDSA,
    expectedIssuerHandle,
    expectedAudienceHandle: registerHandleBytes(utf8("missing-aud")),
    expSeconds: now + 300n,
    nowUnixTimeSeconds: now,
  });
  if (verifyJwtClaims(badAudiencePtr, outputPtr) === VC_INVALID_CLAIMS) {
    pass("jwt_verify_claims_v1 rejects audience mismatches");
  } else {
    fail("jwt_verify_claims_v1 should reject audience mismatches");
  }

  const tamperedSignature = Uint8Array.from(fixture.signature);
  tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
  const badSigPtr = writeJwtClaimsInput({
    signingInputHandle,
    signatureBytesHandle: registerHandleBytes(tamperedSignature),
    publicKeyBytesHandle: publicKeyHandle,
    claimsIssuerHandle,
    claimsAudienceHandle,
    allowedAlgorithmsBitmask: ALG_EDDSA,
    expectedIssuerHandle,
    expectedAudienceHandle,
    expSeconds: now + 300n,
    nowUnixTimeSeconds: now,
  });
  if (verifyJwtClaims(badSigPtr, outputPtr) === VC_INVALID_SIGNATURE) {
    pass("jwt_verify_claims_v1 rejects tampered signatures");
  } else {
    fail("jwt_verify_claims_v1 should reject tampered signatures");
  }

  const expiredPtr = writeJwtClaimsInput({
    signingInputHandle,
    signatureBytesHandle: signatureHandle,
    publicKeyBytesHandle: publicKeyHandle,
    claimsIssuerHandle,
    claimsAudienceHandle,
    allowedAlgorithmsBitmask: ALG_EDDSA,
    flags: JWT_REQUIRE_EXP,
    expectedIssuerHandle,
    expectedAudienceHandle,
    expSeconds: now - 1n,
    nowUnixTimeSeconds: now,
  });
  if (verifyJwtClaims(expiredPtr, outputPtr) === VC_INVALID_CLAIMS) {
    pass("jwt_verify_claims_v1 enforces exp when required");
  } else {
    fail("jwt_verify_claims_v1 should reject expired claims when exp is required");
  }

  const rs256PreverifiedPtr = writeJwtClaimsInput({
    signingInputHandle: registerHandleBytes(utf8("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ")),
    signatureBytesHandle: registerHandleBytes(utf8("synthetic-rs256-signature")),
    publicKeyBytesHandle: registerHandleBytes(utf8("{\"kty\":\"RSA\"}")),
    publicKeyFormat: 1,
    claimsIssuerHandle,
    claimsAudienceHandle,
    allowedAlgorithmsBitmask: ALG_RS256,
    flags: JWT_REQUIRE_EXP | JWT_SIGNATURE_PREVERIFIED,
    expectedIssuerHandle,
    expectedAudienceHandle,
    expSeconds: now + 300n,
    nowUnixTimeSeconds: now,
  });
  if (verifyJwtClaims(rs256PreverifiedPtr, outputPtr) === VC_OK) {
    pass("jwt_verify_claims_v1 accepts RS256 inputs when the signature-preverified flag is set");
  } else {
    fail("jwt_verify_claims_v1 should accept preverified RS256 inputs");
  }

  const rs256UnsupportedPtr = writeJwtClaimsInput({
    signingInputHandle: registerHandleBytes(utf8("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ")),
    signatureBytesHandle: registerHandleBytes(utf8("synthetic-rs256-signature")),
    publicKeyBytesHandle: registerHandleBytes(utf8("{\"kty\":\"RSA\"}")),
    publicKeyFormat: 1,
    claimsIssuerHandle,
    claimsAudienceHandle,
    allowedAlgorithmsBitmask: ALG_RS256,
    flags: JWT_REQUIRE_EXP,
    expectedIssuerHandle,
    expectedAudienceHandle,
    expSeconds: now + 300n,
    nowUnixTimeSeconds: now,
  });
  if (verifyJwtClaims(rs256UnsupportedPtr, outputPtr) === VC_UNSUPPORTED) {
    pass("jwt_verify_claims_v1 still rejects non-preverified RS256 inputs in the WASM-only path");
  } else {
    fail("jwt_verify_claims_v1 should keep non-preverified RS256 inputs unsupported");
  }
} else {
  fail("VerifiedCore_jwt_verify_claims_v1 is not a function");
}

// --- Test 16: Claims-only DPoP verification (EdDSA + replay semantics) ---
if (typeof verifyDpopClaims === "function") {
  clearReplayStore();
  const now = 1_710_000_100n;
  const fixture = buildEd25519Fixture("eyJ0eXAiOiJkcG9wK2p3dCJ9.eyJqdGkiOiJqLTEifQ");
  const signingInputHandle = registerHandleBytes(fixture.signingInput);
  const signatureHandle = registerHandleBytes(fixture.signature);
  const publicKeyHandle = registerHandleBytes(fixture.publicKeyBytes);
  const namespaceHandle = registerHandleBytes(utf8("issuer-a"));
  const outputPtr = alloc(112);
  const inputPtr = writeDpopClaimsInput({
    httpMethodBytesHandle: registerHandleBytes(utf8("GET")),
    httpUriBytesHandle: registerHandleBytes(utf8("https://rp.example/resource")),
    signingInputHandle,
    signatureBytesHandle: signatureHandle,
    publicKeyBytesHandle: publicKeyHandle,
    replayNamespaceHandle: namespaceHandle,
    allowedAlgorithmsBitmask: ALG_EDDSA,
    iatSeconds: now,
    nowUnixTimeSeconds: now,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
  });

  const firstStatus = verifyDpopClaims(inputPtr, outputPtr);
  const replayKeyHash = readBytes(outputPtr + 32, 32);
  if (
    firstStatus === VC_OK
    && Buffer.from(replayKeyHash).equals(Buffer.from(sha256(fixture.signingInput)))
  ) {
    pass("dpop_verify_claims_v1 accepts valid EdDSA input and fills replayKeyHash");
  } else {
    fail(`dpop_verify_claims_v1 valid path → status=${firstStatus}`);
  }

  const secondStatus = verifyDpopClaims(inputPtr, outputPtr);
  if (secondStatus === VC_REPLAY) {
    pass("dpop_verify_claims_v1 detects replay on the second submission");
  } else {
    fail(`dpop_verify_claims_v1 second submission → status=${secondStatus} (expected replay)`);
  }

  clearReplayStore();
  const tamperedSignature = Uint8Array.from(fixture.signature);
  tamperedSignature[0] ^= 0x01;
  const badSigInputPtr = writeDpopClaimsInput({
    signingInputHandle,
    signatureBytesHandle: registerHandleBytes(tamperedSignature),
    publicKeyBytesHandle: publicKeyHandle,
    replayNamespaceHandle: namespaceHandle,
    allowedAlgorithmsBitmask: ALG_EDDSA,
    iatSeconds: now,
    nowUnixTimeSeconds: now,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
  });
  if (verifyDpopClaims(badSigInputPtr, outputPtr) === VC_INVALID_SIGNATURE) {
    pass("dpop_verify_claims_v1 rejects tampered signatures");
  } else {
    fail("dpop_verify_claims_v1 should reject tampered signatures");
  }

  clearReplayStore();
  const rs256PreverifiedInputPtr = writeDpopClaimsInput({
    httpMethodBytesHandle: registerHandleBytes(utf8("GET")),
    httpUriBytesHandle: registerHandleBytes(utf8("https://rp.example/resource")),
    signingInputHandle: registerHandleBytes(utf8("eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJqLTEifQ")),
    signatureBytesHandle: registerHandleBytes(utf8("synthetic-rs256-signature")),
    publicKeyBytesHandle: registerHandleBytes(utf8("{\"kty\":\"RSA\"}")),
    publicKeyFormat: 1,
    replayNamespaceHandle: namespaceHandle,
    allowedAlgorithmsBitmask: ALG_RS256,
    flags: DPOP_SIGNATURE_PREVERIFIED,
    iatSeconds: now,
    nowUnixTimeSeconds: now,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
  });
  if (verifyDpopClaims(rs256PreverifiedInputPtr, outputPtr) === VC_OK) {
    pass("dpop_verify_claims_v1 accepts preverified RS256 inputs and continues replay protection");
  } else {
    fail("dpop_verify_claims_v1 should accept preverified RS256 inputs");
  }
} else {
  fail("VerifiedCore_dpop_verify_claims_v1 is not a function");
}

// --- Summary ---
console.log("");
console.log(`=== Results: ${passed}/${passed + failed} passed (${failed} failed) ===`);
process.exit(failed > 0 ? 1 : 0);
