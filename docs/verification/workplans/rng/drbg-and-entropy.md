# DRBG Scheme And Entropy Input Contract

Last updated: 2026-07-08

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This document is part of the split DRBG and entropy-input workplan.

## 1. DRBG Scheme

**Standard:** NIST SP 800-90A Rev.1, Section 10.1.2 (HMAC_DRBG)

**Algorithm:** HMAC-SHA256

**Rationale:**
- HMAC-SHA256 is already available in the verification suite via `HACL_Wrapper.hmac_sha256`
  (`fstar/HACL_Wrapper.fst:42`) and `EverCrypt.HMAC.compute` (`fstar/EverCrypt.HMAC.fst:41`).
- NIST SP 800-90A HMAC_DRBG is the standard choice for deterministic random
  generation from entropy, widely deployed (OpenSSL, BoringSSL, ring).
- SHA-256 output (32 bytes) aligns with the 256-bit security level required by
  OAuth 2.1 and FIPS 140-3.

### 1.1 DRBG State

```fstar
type drbg_state = {
  key: bytes;   (* 32 bytes — HMAC key *)
  v:   bytes;   (* 32 bytes — chaining value *)
  reseed_counter: nat;
}
```

**Invariant:** `Bytes.length key = 32 /\ Bytes.length v = 32`

### 1.2 Core Operations (per SP 800-90A Section 10.1.2)

**Update** (internal helper — mixes provided_data into state):

```text
Update(K, V, provided_data):
  K = HMAC-SHA256(K, V || 0x00 || provided_data)
  V = HMAC-SHA256(K, V)
  if provided_data is not empty:
    K = HMAC-SHA256(K, V || 0x01 || provided_data)
    V = HMAC-SHA256(K, V)
  return (K, V)
```

**Instantiate** (creates initial state from entropy seed):

SP 800-90A Section 10.1.2.3 defines `seed_material = entropy_input || nonce ||
personalization_string`. In our deployment, the 32-byte `seed` parameter IS the
full `seed_material`: the OS CSPRNG (`getrandom`) provides sufficient entropy
that a separate nonce is not required (per SP 800-90A Section 8.6.7), and no
personalization string is used. This is the "no additional_input" instantiation
path.

```text
Instantiate(seed):
  K = 0x00 repeated 32 times
  V = 0x01 repeated 32 times
  (K, V) = Update(K, V, seed)
  return { key = K; v = V; reseed_counter = 1 }
```

**Generate** (produces `n` bytes of output, updates state):

```text
Generate(state, n):
  assert reseed_counter <= reseed_limit
  blocks_needed = ceil(n / 32)
  temp = empty
  for i = 0 to blocks_needed - 1:   (* F*: recursive with decreasing blocks_needed - i *)
    V = HMAC-SHA256(K, V)
    temp = temp || V
  output = leftmost(temp, n)
  (K, V) = Update(K, V, "")
  reseed_counter += 1
  return (output, { key = K; v = V; reseed_counter })
```

**F\* implementation note:** The while loop is implemented as a recursive function
with termination metric `blocks_needed - produced_blocks` (simpler than
`n - Bytes.length temp`). Length refinement `Bytes.length output = n` requires
lemmas about `Bytes.append` length and `Bytes.sub` truncation.

**Reseed** (re-keys state with fresh entropy):

```text
Reseed(state, entropy):
  (K, V) = Update(state.key, state.v, entropy)
  return { key = K; v = V; reseed_counter = 1 }
```

### 1.3 Parameters

| Parameter | Value | Justification |
|---|---|---|
| Hash algorithm | SHA-256 | 256-bit security, HACL* available |
| Seed length | 32 bytes (256 bits) | SP 800-90A Table 2: security_strength ≤ outlen |
| Key length | 32 bytes | = outlen for HMAC_DRBG |
| V length | 32 bytes | = outlen for HMAC_DRBG |
| Reseed interval | 2^48 | SP 800-90A recommendation |
| Max bytes per request | 2^16 (65536 bytes) | SP 800-90A Table 2: max_number_of_bits_per_request = 2^19 bits = 2^16 bytes |

---

## 2. Entropy Input Specification

### 2.1 Seed Requirements

- **Length:** 32 bytes (256 bits), matching the security strength of SHA-256.
- **Source:** At runtime, the Rust layer acquires entropy from the OS via the
  `getrandom` crate (`crates/crypto/src/rand.rs:11`). The `getrandom` crate
  delegates to the kernel CSPRNG (`/dev/urandom` on Linux, `BCryptGenRandom`
  on Windows, `getentropy` on macOS).
- **Quality:** The seed MUST be fresh output from the OS CSPRNG. Reusing
  seed material across DRBG instantiations violates the no-reuse policy.

### 2.2 No-Reuse Policy

Each entropy seed SHALL be used exactly once:
- One call to `drbg_instantiate` consumes one 32-byte seed.
- One call to `drbg_reseed` consumes one 32-byte seed.
- Seeds MUST NOT be stored, logged, or reused.

**Enforcement in F\*:** The seed is a function parameter with type
`seed:bytes{Bytes.length seed = 32}`. The DRBG operations are `Tot`
(pure), so each invocation with the same seed produces the same state —
this is the modeling limitation (see Section 6). The no-reuse policy is
enforced at the Rust call site, not in the F\* model.

### 2.3 Acquisition Strategy

**Per-request entropy:** Each OAuth flow invocation (authorization code
generation, access token generation, challenge issuance) obtains a fresh
32-byte seed from the OS RNG and passes it into the DRBG. This means:

- No DRBG state is carried across requests.
- Each request instantiates a fresh DRBG, generates the needed output, and
  discards the state.
- This is the simplest correct model: no reseed logic needed at the F\*
  level, no state management, no reseed_counter checks.

**Why per-request (not batch):**
- Aegaeon generates at most 2 random values per request (auth code + access
  token in `token_exchange`). Instantiating a DRBG for 2 × 32 bytes is
  negligible overhead.
- Batch mode would require carrying DRBG state across requests, introducing
  ST effects and complicating the verification story.
- Per-request aligns with the existing calling convention where each function
  call is independent.

**Key generation:** Signing key generation in `aegaeon-crypto` still routes
randomness through `SystemRandom` (ring/aws-lc-rs). This is outside the Phase C
RNG boundary and remains a documented external dependency.

---
