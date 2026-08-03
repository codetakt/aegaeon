#!/usr/bin/env node
/**
 * Verified Core ABI generator (manual template -> JSON)
 *
 * The Verified Core WASM interface is intentionally described via a
 * hand-maintained schema so that we can reason about host/guest
 * responsibilities, integer widths, and import/export naming without
 * depending on KaRaMeL header structure. This script simply stamps the
 * current template with a `generatedAt` timestamp and writes it to the
 * canonical output path.
 */

import { promises as fs } from "node:fs";
import path from "node:path";

const SCRIPT_DIR = path.dirname(new URL(import.meta.url).pathname);
const ROOT = path.resolve(SCRIPT_DIR, "..", "..");
const OUTPUT_PATH = path.join(ROOT, "generated/lowstar/verified-core/verified_core.abi.json");

/**
 * ABI schema (v1)
 *
 * NOTE:
 *  - The current verified WASM path internalizes SHA-256 and Ed25519.
 *    ES256/RS256 client verification is currently supported through an
 *    adapter-side preverification contract that sets explicit flag bits
 *    before invoking the claims exports.
 *  - Bytes handles follow the host-managed table convention; the host
 *    bridges raw linear-memory slices via `vc_host_register_bytes` and
 *    resolves handles through `Host_handle_data_ptr/len`.
 *  - Replay store operations assume Redis `SET key 1 NX PX ttl` semantics
 *    and MUST fail-close when Redis is unavailable.
 */
const ABI_TEMPLATE = {
  abiSchema: "aegaeon.verified-core.wasm-abi",
  abiSchemaVersion: 1,
  abiVersion: "1.0.0",
  target: {
    architecture: "wasm32",
    endianness: "little",
    pointerWidthBits: 32,
    wasmValueTypes: {
      u8: "i32",
      u32: "i32",
      u64: "i64"
    }
  },
  conventions: {
    bytesRepresentation: {
      kind: "host_handle",
      handleType: "u32",
      handleZeroMeaning: "empty_bytes",
      lifetimeRule:
        "A bytes handle passed into an export call MUST remain valid " +
        "until that export returns. The host may free/recycle handles " +
        "only after the call completes."
    },
    structLayout: {
      repr: "C",
      alignmentBytes: 8,
      paddingRule: "Explicit padding fields are included. Do not rely on implicit padding."
    },
    timeRepresentation: {
      unixTimeSeconds: "u64",
      note: "In JS/TS, pass and receive u64 as BigInt for wasm i64 interoperability."
    },
    signatureFormats: {
      ES256: "JOSE_P1363",
      RS256: "RSASSA_PKCS1_v1_5",
      EdDSA: "Ed25519_raw",
      note:
        "The current verified WASM artifact internalizes SHA-256 and " +
        "Ed25519. ES256/RS256 client verification is supported via " +
        "adapter-side preverification on the claims exports; the " +
        "general verified path remains modern-crypto-first."
    },
    errorHandling: {
      statusCodeType: "VerifiedCoreStatusCode",
      nonZeroMeansError: true
    }
  },
  types: {
    aliases: {
      bytes_handle: {
        type: "u32",
        description: "Host-managed Bytes handle (opaque index into host-side byte array table)."
      },
      wasm_ptr: {
        type: "u32",
        description: "Pointer into wasm linear memory."
      },
      c_string_ptr: {
        type: "u32",
        description:
          "Pointer to null-terminated C string in wasm linear " +
          "memory. Corresponds to KaRaMeL Prims_string type."
      },
      fstar_bytes_struct_ptr: {
        type: "u32",
        description:
          "Pointer to FStar_Bytes_bytes struct in wasm linear " +
          "memory. Struct layout: {u32 length, u32 dataPtr}."
      }
    },
    enums: {
      VerifiedCoreStatusCode: {
        repr: "u32",
        variants: {
          OK: 0,
          INVALID_ARGUMENT: 1,
          INVALID_FORMAT: 2,
          INVALID_SIGNATURE: 3,
          INVALID_CLAIMS: 4,
          REPLAY: 5,
          UNAVAILABLE: 6,
          UNSUPPORTED: 7,
          INTERNAL_ERROR: 8
        }
      },
      ReplayStoreResult: {
        repr: "u32",
        variants: {
          OK: 0,
          REPLAY: 1,
          UNAVAILABLE: 2
        }
      },
      HostCryptoVerifyResult: {
        repr: "u32",
        variants: {
          VALID: 0,
          INVALID: 1,
          UNSUPPORTED: 2,
          ERROR: 3
        }
      },
      SignatureAlgorithm: {
        repr: "u32",
        variants: {
          ES256: 1,
          RS256: 2,
          EdDSA: 3
        }
      },
      PublicKeyFormat: {
        repr: "u32",
        variants: {
          JWK_JSON_UTF8: 1,
          SPKI_DER: 2,
          RAW_EC_P256_UNCOMPRESSED: 3
        }
      }
    },
    structs: {
      FStar_Bytes_bytes: {
        repr: "C",
        sizeBytes: 8,
        description:
          "KaRaMeL representation of FStar.Bytes.bytes. Contains " +
          "length and pointer to data in wasm memory.",
        fields: [
          {
            name: "length",
            type: "u32",
            offsetBytes: 0,
            description: "Number of bytes in the data buffer."
          },
          {
            name: "dataPtr",
            type: "wasm_ptr",
            offsetBytes: 4,
            description: "Pointer to byte data in wasm linear memory."
          }
        ]
      },
      Bytes32: {
        repr: "C",
        sizeBytes: 32,
        fields: [
          {
            name: "bytes",
            type: "u8[32]",
            offsetBytes: 0
          }
        ]
      },
      DpopVerificationInputV1: {
        repr: "C",
        sizeBytes: 56,
        fields: [
          {
            name: "httpMethodBytesHandle",
            type: "bytes_handle",
            offsetBytes: 0,
            description: "Uppercase ASCII, e.g., \"GET\"."
          },
          {
            name: "httpUriBytesHandle",
            type: "bytes_handle",
            offsetBytes: 4,
            description: "Absolute URL UTF-8."
          },
          {
            name: "dpopCompactJwsHandle",
            type: "bytes_handle",
            offsetBytes: 8,
            description: "DPoP proof (JWS compact) UTF-8."
          },
          {
            name: "accessTokenHandle",
            type: "bytes_handle",
            offsetBytes: 12,
            description: "Optional. 0 means absent."
          },
          {
            name: "replayNamespaceHandle",
            type: "bytes_handle",
            offsetBytes: 16,
            description: "Recommended: environment_id canonical string."
          },
          {
            name: "padding0",
            type: "u32",
            offsetBytes: 20,
            description: "Must be 0."
          },
          {
            name: "nowUnixTimeSeconds",
            type: "u64",
            offsetBytes: 24
          },
          {
            name: "maxAgeSeconds",
            type: "u32",
            offsetBytes: 32,
            description: "Recommended default: 300."
          },
          {
            name: "maxFutureSkewSeconds",
            type: "u32",
            offsetBytes: 36,
            description: "Recommended default: 60."
          },
          {
            name: "flags",
            type: "u32",
            offsetBytes: 40,
            description: "Bitmask. See dpopFlags."
          },
          {
            name: "allowedAlgorithmsBitmask",
            type: "u32",
            offsetBytes: 44,
            description: "Bit0 ES256, Bit1 RS256, Bit2 EdDSA."
          },
          {
            name: "reserved0",
            type: "u32",
            offsetBytes: 48,
            description: "Must be 0."
          },
          {
            name: "reserved1",
            type: "u32",
            offsetBytes: 52,
            description: "Must be 0."
          }
        ]
      },
      DpopClaimsInputV1: {
        repr: "C",
        sizeBytes: 72,
        fields: [
          {
            name: "httpMethodBytesHandle",
            type: "bytes_handle",
            offsetBytes: 0,
            description: "Uppercase ASCII method."
          },
          {
            name: "httpUriBytesHandle",
            type: "bytes_handle",
            offsetBytes: 4,
            description: "Absolute URI (UTF-8)."
          },
          {
            name: "signingInputHandle",
            type: "bytes_handle",
            offsetBytes: 8,
            description: "ASCII `base64url(header)`.`base64url(payload)`."
          },
          {
            name: "signatureBytesHandle",
            type: "bytes_handle",
            offsetBytes: 12,
            description: "JOSE/P1363 signature bytes."
          },
          {
            name: "publicKeyBytesHandle",
            type: "bytes_handle",
            offsetBytes: 16,
            description: "Public key material (format specified below)."
          },
          {
            name: "publicKeyFormat",
            type: "PublicKeyFormat",
            offsetBytes: 20
          },
          {
            name: "replayNamespaceHandle",
            type: "bytes_handle",
            offsetBytes: 24,
            description: "Environment/issuer namespace for replay store."
          },
          {
            name: "accessTokenHashHandle",
            type: "bytes_handle",
            offsetBytes: 28,
            description: "Optional `ath` value (base64url). Zero means absent."
          },
          {
            name: "jtiBytesHandle",
            type: "bytes_handle",
            offsetBytes: 32,
            description: "Optional jti string (UTF-8). Zero means absent."
          },
          {
            name: "allowedAlgorithmsBitmask",
            type: "u32",
            offsetBytes: 36,
            description: "Bit0 ES256, Bit1 RS256, Bit2 EdDSA."
          },
          {
            name: "flags",
            type: "u32",
            offsetBytes: 40,
            description: "Bitmask. See dpopFlags."
          },
          {
            name: "reserved0",
            type: "u32",
            offsetBytes: 44,
            description: "Must be 0."
          },
          {
            name: "iatSeconds",
            type: "u64",
            offsetBytes: 48
          },
          {
            name: "nowUnixTimeSeconds",
            type: "u64",
            offsetBytes: 56,
            description: "Current time for iat window validation."
          },
          {
            name: "maxAgeSeconds",
            type: "u32",
            offsetBytes: 64
          },
          {
            name: "maxFutureSkewSeconds",
            type: "u32",
            offsetBytes: 68
          }
        ]
      },
      DpopVerificationOutputV1: {
        repr: "C",
        sizeBytes: 112,
        fields: [
          {
            name: "jktHash",
            type: "Bytes32",
            offsetBytes: 0,
            description:
              "SHA-256(JWK thumbprint) or equivalent key ID hash. Zeroed if proof lacks jwk."
          },
          {
            name: "replayKeyHash",
            type: "Bytes32",
            offsetBytes: 32,
            description: "Fixed 32-byte replay key hash passed to ReplayStore."
          },
          {
            name: "jtiHash",
            type: "Bytes32",
            offsetBytes: 64,
            description: "Optional: SHA-256(jti). Zero if missing."
          },
          {
            name: "proofIatSeconds",
            type: "u64",
            offsetBytes: 96
          },
          {
            name: "flags",
            type: "u32",
            offsetBytes: 104,
            description: "Bitmask. See dpopResultFlags."
          },
          {
            name: "statusCode",
            type: "VerifiedCoreStatusCode",
            offsetBytes: 108
          }
        ]
      },
      JwtClaimsInputV1: {
        repr: "C",
        sizeBytes: 72,
        fields: [
          {
            name: "signingInputHandle",
            type: "bytes_handle",
            offsetBytes: 0,
            description: "ASCII `base64url(header)`.`base64url(payload)`."
          },
          {
            name: "signatureBytesHandle",
            type: "bytes_handle",
            offsetBytes: 4,
            description: "Signature bytes (JOSE/P1363 for ES256)."
          },
          {
            name: "publicKeyBytesHandle",
            type: "bytes_handle",
            offsetBytes: 8
          },
          {
            name: "publicKeyFormat",
            type: "PublicKeyFormat",
            offsetBytes: 12
          },
          {
            name: "claimsIssuerHandle",
            type: "bytes_handle",
            offsetBytes: 16,
            description: "Optional issuer string. Zero means absent."
          },
          {
            name: "claimsAudienceHandle",
            type: "bytes_handle",
            offsetBytes: 20,
            description: "Optional audience (JSON array string). Zero means absent."
          },
          {
            name: "allowedAlgorithmsBitmask",
            type: "u32",
            offsetBytes: 24
          },
          {
            name: "flags",
            type: "u32",
            offsetBytes: 28,
            description: "Bitmask. See jwtFlags."
          },
          {
            name: "expectedIssuerHandle",
            type: "bytes_handle",
            offsetBytes: 32,
            description: "Optional expected issuer string. Zero disables the check."
          },
          {
            name: "expectedAudienceHandle",
            type: "bytes_handle",
            offsetBytes: 36,
            description: "Optional expected audience string. Zero disables the check."
          },
          {
            name: "expSeconds",
            type: "u64",
            offsetBytes: 40,
            description: "Optional. Zero when absent, check flags."
          },
          {
            name: "nbfSeconds",
            type: "u64",
            offsetBytes: 48,
            description: "Optional. Zero when absent."
          },
          {
            name: "iatSeconds",
            type: "u64",
            offsetBytes: 56,
            description: "Optional. Zero when absent."
          },
          {
            name: "nowUnixTimeSeconds",
            type: "u64",
            offsetBytes: 64
          }
        ]
      },
      JwtVerificationInputV1: {
        repr: "C",
        sizeBytes: 40,
        fields: [
          {
            name: "jwtCompactJwsHandle",
            type: "bytes_handle",
            offsetBytes: 0,
            description: "JWT JWS compact UTF-8."
          },
          {
            name: "expectedIssuerHandle",
            type: "bytes_handle",
            offsetBytes: 4,
            description: "Optional. 0 means absent."
          },
          {
            name: "expectedAudienceHandle",
            type: "bytes_handle",
            offsetBytes: 8,
            description: "Optional. 0 means absent."
          },
          {
            name: "publicKeyBytesHandle",
            type: "bytes_handle",
            offsetBytes: 12,
            description: "Public key in format specified by publicKeyFormat."
          },
          {
            name: "nowUnixTimeSeconds",
            type: "u64",
            offsetBytes: 16
          },
          {
            name: "allowedAlgorithmsBitmask",
            type: "u32",
            offsetBytes: 24,
            description: "Bit0 ES256, Bit1 RS256, Bit2 EdDSA."
          },
          {
            name: "publicKeyFormat",
            type: "PublicKeyFormat",
            offsetBytes: 28
          },
          {
            name: "flags",
            type: "u32",
            offsetBytes: 32,
            description: "Bitmask. See jwtFlags."
          },
          {
            name: "reserved0",
            type: "u32",
            offsetBytes: 36,
            description: "Must be 0."
          }
        ]
      },
      JwtVerificationOutputV1: {
        repr: "C",
        sizeBytes: 80,
        fields: [
          {
            name: "payloadHash",
            type: "Bytes32",
            offsetBytes: 0,
            description:
              "SHA-256 of the signing-input bytes " +
              "(`base64url(header).base64url(payload)`), computed " +
              "inside the current verified WASM path for audit " +
              "correlation."
          },
          {
            name: "kidHash",
            type: "Bytes32",
            offsetBytes: 32,
            description: "SHA-256(kid) if present; zero otherwise."
          },
          {
            name: "flags",
            type: "u32",
            offsetBytes: 64,
            description: "Bitmask. See jwtResultFlags."
          },
          {
            name: "statusCode",
            type: "VerifiedCoreStatusCode",
            offsetBytes: 68
          },
          {
            name: "reserved0",
            type: "u32",
            offsetBytes: 72,
            description: "Must be 0."
          },
          {
            name: "reserved1",
            type: "u32",
            offsetBytes: 76,
            description: "Must be 0."
          }
        ]
      }
    },
    bitmasks: {
      dpopFlags: {
        repr: "u32",
        bits: {
          REQUIRE_ACCESS_TOKEN_HASH: 0,
          REQUIRE_JTI: 1,
          SIGNATURE_PREVERIFIED: 2
        }
      },
      dpopResultFlags: {
        repr: "u32",
        bits: {
          HAS_JTI: 0,
          HAS_ATH: 1
        }
      },
      jwtFlags: {
        repr: "u32",
        bits: {
          REQUIRE_EXP: 0,
          REQUIRE_IAT: 1,
          REQUIRE_NBF: 2,
          SIGNATURE_PREVERIFIED: 3
        }
      },
      jwtResultFlags: {
        repr: "u32",
        bits: {
          HAS_KID: 0
        }
      }
    }
  },
  imports: [
    // =====================================================================
    // Stable host contract for the current verified-core WASM artifact
    // =====================================================================
    {
      module: "env",
      name: "VerifiedCore_Api_Claims_Runtime_host_replay_store_check_and_store",
      params: [
        { name: "namespaceHandle", type: "bytes_handle" },
        { name: "keyHashPtr", type: "wasm_ptr" },
        { name: "ttlMilliseconds", type: "u32" }
      ],
      results: [{ type: "ReplayStoreResult" }],
      description: "Atomically check replay and store. Returns OK, REPLAY, or UNAVAILABLE."
    },
    {
      module: "env",
      name: "vc_host_register_bytes",
      params: [
        { name: "dataPtr", type: "wasm_ptr" },
        { name: "len", type: "u32" }
      ],
      results: [{ type: "bytes_handle" }],
      description:
        "Register a byte region from wasm linear memory as a " +
        "host-managed handle. Returns 0 on failure."
    },
    {
      module: "env",
      name: "vc_host_release_handle",
      params: [{ name: "handle", type: "bytes_handle" }],
      results: [],
      description: "Release a handle returned by `vc_host_register_bytes`."
    },
    {
      module: "env",
      name: "Host_parse_dpop_compact",
      params: [
        { name: "compactJwsHandle", type: "bytes_handle" },
        { name: "outputPtr", type: "wasm_ptr" }
      ],
      results: [{ type: "u32" }],
      description: "Parse DPoP compact JWS into components struct. Returns 0 on success."
    },
    {
      module: "env",
      name: "Host_handle_data_ptr",
      params: [{ name: "handle", type: "bytes_handle" }],
      results: [{ type: "wasm_ptr" }],
      description:
        "Resolve a bytes handle to a pointer in wasm linear memory. " +
        "Returns 0 for invalid handles."
    },
    {
      module: "env",
      name: "Host_handle_data_len",
      params: [{ name: "handle", type: "bytes_handle" }],
      results: [{ type: "u32" }],
      description: "Resolve a bytes handle to its byte length. Returns 0 for invalid handles."
    },
    {
      module: "env",
      name: "Host_parse_jwt_compact",
      params: [
        { name: "compactJwsHandle", type: "bytes_handle" },
        { name: "outputPtr", type: "wasm_ptr" }
      ],
      results: [{ type: "u32" }],
      description: "Parse JWT compact JWS into components struct. Returns 0 on success."
    },
  ],

  exports: [
    // =====================================================================
    // PKCE Exports
    // =====================================================================
    {
      name: "Pkce_verifier_ok",
      params: [{ name: "verifierPtr", type: "c_string_ptr" }],
      results: [{ type: "u32", description: "1 (true) if verifier is valid, 0 (false) otherwise" }],
      description:
        "Validate PKCE verifier format: 43-128 characters from unreserved charset [A-Za-z0-9._~-]."
    },
    {
      name: "Pkce_verify_pkce",
      params: [
        {
          name: "methodPtr",
          type: "c_string_ptr",
          description: "Method string: \"S256\" or \"plain\""
        },
        { name: "verifierPtr", type: "c_string_ptr", description: "Code verifier" },
        { name: "challengePtr", type: "c_string_ptr", description: "Code challenge" }
      ],
      results: [
        {
          type: "u32",
          description:
            "1 (true) if challenge matches verifier, 0 (false) otherwise"
        }
      ],
      description:
        "Verify PKCE challenge against verifier using specified " +
        "method. For S256: challenge == " +
        "base64url(sha256(verifier))."
    },
    // =====================================================================
    // DPoP/JWT Exports
    // =====================================================================
    {
      name: "VerifiedCore_dpop_verify_v1",
      params: [
        {
          name: "inputPtr",
          type: "wasm_ptr",
          pointsTo: "DpopVerificationInputV1"
        },
        {
          name: "outputPtr",
          type: "wasm_ptr",
          pointsTo: "DpopVerificationOutputV1"
        }
      ],
      results: [
        {
          type: "VerifiedCoreStatusCode"
        }
      ],
      description:
        "Verify DPoP proof. On success returns OK and fills output. " +
        "On replay returns REPLAY. On store/crypto failure returns " +
        "UNAVAILABLE."
    },
    {
      name: "VerifiedCore_dpop_verify_claims_v1",
      params: [
        {
          name: "inputPtr",
          type: "wasm_ptr",
          pointsTo: "DpopClaimsInputV1"
        },
        {
          name: "outputPtr",
          type: "wasm_ptr",
          pointsTo: "DpopVerificationOutputV1"
        }
      ],
      results: [
        {
          type: "VerifiedCoreStatusCode"
        }
      ],
      description:
        "Verify DPoP proof from pre-parsed claims and signature components. Flags reuse dpopFlags."
    },
    {
      name: "VerifiedCore_jwt_verify_v1",
      params: [
        {
          name: "inputPtr",
          type: "wasm_ptr",
          pointsTo: "JwtVerificationInputV1"
        },
        {
          name: "outputPtr",
          type: "wasm_ptr",
          pointsTo: "JwtVerificationOutputV1"
        }
      ],
      results: [
        {
          type: "VerifiedCoreStatusCode"
        }
      ],
      description:
        "Verify JWT JWS compact using provided public key and claim " +
        "constraints. Returns INVALID_SIGNATURE or INVALID_CLAIMS as " +
        "appropriate."
    },
    {
      name: "VerifiedCore_jwt_verify_claims_v1",
      params: [
        {
          name: "inputPtr",
          type: "wasm_ptr",
          pointsTo: "JwtClaimsInputV1"
        },
        {
          name: "outputPtr",
          type: "wasm_ptr",
          pointsTo: "JwtVerificationOutputV1"
        }
      ],
      results: [
        {
          type: "VerifiedCoreStatusCode"
        }
      ],
      description:
        "Verify JWT signature and standard claims from pre-parsed " +
        "inputs, including optional expected issuer/audience checks."
    }
  ],
  compatibilityRules: {
    addingNewFields:
      "Add new fields only at the end of structs, keep existing " +
      "offsets stable. Prefer reserved fields for forward compatibility.",
    addingNewEnums: "Only append new enum variants; never renumber.",
    breakingChanges:
      "Any change to offsets, sizes, or enum values requires an abiVersion major bump."
  }
};

/**
 * Parse command-line arguments.
 * @returns {{ out?: string }}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const result = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--out" && args[i + 1]) {
      result.out = args[i + 1];
      i++;
    }
  }
  return result;
}

async function main() {
  const args = parseArgs();
  const outputPath = args.out ? path.resolve(args.out) : OUTPUT_PATH;

  const abi = {
    ...ABI_TEMPLATE,
    generatedAt: new Date().toISOString()
  };

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, JSON.stringify(abi, null, 2) + "\n");
  console.log(`ABI written to ${outputPath}`);
}

main().catch((error) => {
  console.error("[generate_verified_core_abi] error:", error);
  process.exitCode = 1;
});
