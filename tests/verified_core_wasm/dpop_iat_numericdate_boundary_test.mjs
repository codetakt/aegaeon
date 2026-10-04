import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash, webcrypto } from "node:crypto";

export async function checkDpopIatNumericDates(source, fixture, onCheck) {
  const wasmBytes = fs.readFileSync(fixture);
  const manifest = {
    sha256: createHash("sha256").update(wasmBytes).digest("hex"),
    size_bytes: wasmBytes.length,
  };
  const maximum = (1n << 64n) - 1n;
  const claims = (members = "") =>
    `{"htm":"GET","htu":"https://issuer.example.test/resource","jti":"iat-boundary"${members ? `,${members}` : ""}}`;
  const numberClaim = (token) => claims(`"iat":${token}`);
  const manyNines = "9".repeat(4096);
  const manyZeroes = "0".repeat(4096);
  const cases = [
    ["odd-above-2^53", numberClaim("9007199254740993"), 9007199254740993n],
    ["u64-max", numberClaim("18446744073709551615"), maximum],
    ["u64-max-fraction-syntax", numberClaim("18446744073709551615.000"), maximum],
    ["u64-max-exponent", numberClaim("1.8446744073709551615e19"), maximum],
    ["u64-max-negative-exponent", numberClaim("184467440737095516150e-1"), maximum],
    ["u64-overflow", numberClaim("18446744073709551616"), null],
    ["rounds-to-safe-integer", numberClaim("0.99999999999999999"), null],
    ["rounds-to-zero", numberClaim("1e-400"), null],
    ["integer-fraction-syntax", numberClaim("1.0"), 1n],
    ["integer-negative-exponent", numberClaim("10e-1"), 1n],
    ["zero-large-exponent", numberClaim("0e999999999999999999999"), 0n],
    ["negative-zero", numberClaim("-0"), 0n],
    ["negative", numberClaim("-1"), null],
    ["fraction", numberClaim("1.5"), null],
    ["string", claims('"iat":"9007199254740993"'), null],
    ["null", claims('"iat":null'), null],
    ["boolean", claims('"iat":true'), null],
    ["object", claims('"iat":{"iat":1}'), null],
    ["missing", claims('"nested":{"iat":1}'), null],
    ["root-array", "[9007199254740993]", null],
    ["duplicate-last", claims('"iat":1,"iat":9007199254740993'), 9007199254740993n],
    ["escaped-duplicate-last", claims(String.raw`"iat":1,"\u0069at":9007199254740993`), 9007199254740993n],
    ["last-string", claims('"iat":9007199254740993,"iat":"1"'), null],
    ["nested-after-root", claims('"iat":9007199254740993,"nested":{"iat":2}'), 9007199254740993n],
    ["nested-before-root", claims('"nested":{"iat":2},"iat":9007199254740993'), 9007199254740993n],
    ["string-number-decoy", claims(String.raw`"note":"\"iat\":123","iat":9007199254740993`), 9007199254740993n],
    ["invalid-leading-zero", numberClaim("01"), null],
    ["json-proto-member-is-not-iat", claims('"__proto__":{"iat":1}'), null],
    ["prototype-inherited-iat-is-not-own", claims(), null, true],
    ["zero-4096-digit-exponent", numberClaim(`0e${manyNines}`), 0n],
    ["nonzero-4096-digit-positive-exponent", numberClaim(`1e${manyNines}`), null],
    ["nonzero-4096-digit-negative-exponent", numberClaim(`1e-${manyNines}`), null],
    ["positive-exponent-4096-leading-zeroes", numberClaim(`1e+${manyZeroes}19`), 10000000000000000000n],
    ["negative-exponent-4096-leading-zeroes", numberClaim(`10e-${manyZeroes}1`), 1n],
    ["negative-zero-huge-negative-exponent", numberClaim(`-0e-${manyNines}`), 0n],
    ["one-beyond-exponent-upper-bound", numberClaim("1e20"), null],
    ["nonzero-coefficient-over-20-digits", numberClaim("100000000000000000001e-1"), null],
  ];
  const header = Buffer.from(JSON.stringify({
    typ: "dpop+jwt",
    alg: "EdDSA",
    jwk: { kty: "OKP", crv: "Ed25519", x: Buffer.alloc(32, 1).toString("base64url") },
  })).toString("base64url");
  const signature = Buffer.alloc(64, 1).toString("base64url");
  let passed = 0;
  for (const adapter of ["node", "web"]) {
    const module = await import(pathToFileURL(path.join(source, `scripts/sdk/runtime_${adapter}_reference.ts`)));
    const { runtime } = await module.initCore({ wasmBytes, manifest, secureContext: true, subtle: webcrypto.subtle });
    const host = runtime.buildImports().env.Host_parse_dpop_compact;
    assert.equal(typeof host, "function");
    for (const [label, payload, expectedIat, inheritedFixture = false] of cases) {
      runtime.resetScratch();
      const resultPtr = runtime.alloc(48);
      new Uint8Array(runtime.memory.buffer, resultPtr, 48).fill(0xff);
      const signingInput = `${header}.${Buffer.from(payload).toString("base64url")}`;
      const handle = runtime.registerHandleBytes(Buffer.from(`${signingInput}.${signature}`));
      const previous = Object.getOwnPropertyDescriptor(Object.prototype, "iat");
      let returnCode;
      try {
        if (inheritedFixture) {
          Object.defineProperty(Object.prototype, "iat", { value: 1, configurable: true });
        }
        returnCode = host(handle, resultPtr);
      } finally {
        if (inheritedFixture) {
          if (previous) Object.defineProperty(Object.prototype, "iat", previous);
          else delete Object.prototype.iat;
        }
      }
      const view = new DataView(runtime.memory.buffer);
      const iat = view.getBigUint64(resultPtr + 32, true);
      const status = view.getUint32(resultPtr + 40, true);
      const accepted = expectedIat !== null;
      const expectedStatus = accepted ? 0 : 1;
      let signingInputPreserved = null;
      if (returnCode === 0 && status === 0) {
        signingInputPreserved = Buffer.from(runtime.getHandleBytes(view.getUint32(resultPtr, true), "signing input"))
          .equals(Buffer.from(signingInput));
      }
      const context = `${adapter}/${label}`;
      assert.equal(returnCode, expectedStatus, `${context}: return status`);
      assert.equal(status, expectedStatus, `${context}: output status`);
      assert.equal(iat, expectedIat ?? 0n, `${context}: exact integer seconds`);
      if (accepted) assert.equal(signingInputPreserved, true, `${context}: signing input`);
      passed++;
      onCheck?.(context);
    }
  }
  return passed;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const source = path.resolve(process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "../.."));
  const fixture = process.argv[3] ?? path.join(source, "tests/fixtures/verified-core/verified_core.wasm");
  const checks = await checkDpopIatNumericDates(source, fixture);
  console.log(`${checks} DPoP iat checks passed (Node and Web adapters under Node).`);
}
