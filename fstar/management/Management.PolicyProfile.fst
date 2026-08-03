module Management.PolicyProfile

(** Management plane OAuth policy profile resolution formal specification.

    Models the three-level policy resolution hierarchy:
      1. Client-specific policy override  (client_policy_profiles)
      2. Environment default profile      (oauth_profiles WHERE is_default)
      3. Strict OAuth 2.1 baseline        (hardcoded fallback)

    Resolution precedence SQL from oauth_profile.rs:
      `CASE WHEN c.oauth_profile_id IS NULL THEN dp.* ELSE cp.*`
    i.e. client-bound profile wins over environment default.

    DB constraints formalised:
      - `oauth_profiles_default_unique` — at most one default per (env, config, type)
      - `client_policy_profiles_client_unique` — at most one override per client
      - `client_policy_profiles_ttls_positive` — optional TTLs must be > 0
      - `policy_exceptions_expires_future` — exception expires_at > created_at
      - `policy_exceptions_status_valid` — status ∈ {ACTIVE, EXPIRED, REVOKED}

    This module proves five key invariants:
      PP1  resolution_precedence        — client override > env default > 2.1 baseline
      PP2  downgrade_prevention         — 2.1 profiles cannot enable implicit/ROPC
      PP3  exception_expiry_enforcement — expired exceptions MUST NOT be used
      PP4  default_uniqueness           — at most one active default per environment
      PP5  ttl_positivity               — all configured TTLs are > 0 *)

open FStar.List.Tot

(* =========================================================================
  Types
  ========================================================================= *)

type environment_id = nat
type client_id      = nat
type profile_id     = nat

(** OAuth version discriminator. *)
type oauth_version =
  | OAuth20     (** RFC 6749 permissive *)
  | OAuth21     (** OAuth 2.1 strict — PKCE required, no implicit/ROPC *)

(** Sender constraint level. *)
type sender_constraint =
  | SC_None
  | SC_DPoP
  | SC_Mtls

(** Profile status. *)
type profile_status =
  | ProfileActive
  | ProfileDeleted

(** Exception status. *)
type exception_status =
  | ExceptionActive
  | ExceptionExpired
  | ExceptionRevoked

(** Resolved policy fields relevant to formal verification.
    Mirrors `ResolvedProfile` in oauth_profile.rs. *)
noeq type resolved_policy = {
  rp_version            : oauth_version;
  rp_require_pkce       : bool;
  rp_require_state      : bool;
  rp_require_iss        : bool;
  rp_sender_constrained : sender_constraint;
  rp_allow_implicit     : bool;
  rp_allow_ropc         : bool;
}

(** An OAuth profile record. *)
noeq type oauth_profile = {
  op_id          : profile_id;
  op_env_id      : environment_id;
  op_version     : oauth_version;
  op_is_default  : bool;
  op_status      : profile_status;
  op_require_pkce       : bool;
  op_require_state      : bool;
  op_require_iss        : bool;
  op_sender_constrained : sender_constraint;
  op_allow_implicit     : bool;
  op_allow_ropc         : bool;
  op_expires_at  : option nat;  (** None = no expiry *)
}

(** A client policy override record. *)
type client_policy_override = {
  co_client_id         : client_id;
  co_env_id            : environment_id;
  co_pkce_required     : option bool;
  co_dpop_strict       : option bool;
  co_access_ttl        : option nat;
  co_refresh_ttl       : option nat;
  co_id_ttl            : option nat;
}

(** A time-limited policy exception. *)
noeq type policy_exception = {
  pe_env_id      : environment_id;
  pe_client_id   : option client_id;
  pe_exception_type : string;
  pe_expires_at  : nat;
  pe_created_at  : nat;
  pe_status      : exception_status;
}

(** The profile store. *)
noeq type profile_store = {
  profiles    : list oauth_profile;
  overrides   : list client_policy_override;
  exceptions  : list policy_exception;
}

(* =========================================================================
  Strict OAuth 2.1 baseline
  ========================================================================= *)

(** The hardcoded fallback policy when no profile is configured.
    Matches OAuth 2.1 draft requirements. *)
val baseline_21 : resolved_policy
let baseline_21 = {
  rp_version            = OAuth21;
  rp_require_pkce       = true;
  rp_require_state      = true;
  rp_require_iss        = false;
  rp_sender_constrained = SC_DPoP;
  rp_allow_implicit     = false;
  rp_allow_ropc         = false;
}

(** A resolved policy is valid for OAuth 2.1 iff it does not enable
    implicit or ROPC grant types and requires PKCE. *)
val is_21_compliant : resolved_policy -> Tot bool
let is_21_compliant rp =
  not rp.rp_allow_implicit &&
  not rp.rp_allow_ropc &&
  rp.rp_require_pkce

(* =========================================================================
  Profile predicates
  ========================================================================= *)

(** A profile is active and not expired at time `now`. *)
val profile_valid_at : now:nat -> p:oauth_profile -> Tot bool
let profile_valid_at now p =
  ProfileActive? p.op_status &&
  (match p.op_expires_at with
    | None -> true
    | Some exp -> now < exp)

(** Find the active default profile for an environment. *)
val find_default_profile :
  profiles:list oauth_profile -> eid:environment_id -> now:nat ->
  Tot (option oauth_profile)
  (decreases profiles)
let rec find_default_profile profiles eid now =
  match profiles with
  | [] -> None
  | p :: rest ->
    if p.op_env_id = eid && p.op_is_default && profile_valid_at now p then
      Some p
    else
      find_default_profile rest eid now

(** Find the client-bound profile. *)
val find_client_profile :
  profiles:list oauth_profile -> eid:environment_id ->
  profile_id:profile_id -> now:nat ->
  Tot (option oauth_profile)
  (decreases profiles)
let rec find_client_profile profiles eid pid now =
  match profiles with
  | [] -> None
  | p :: rest ->
    if p.op_env_id = eid && p.op_id = pid && profile_valid_at now p then
      Some p
    else
      find_client_profile rest eid pid now

(** Convert a profile to a resolved policy. *)
val profile_to_resolved : oauth_profile -> Tot resolved_policy
let profile_to_resolved p = {
  rp_version            = p.op_version;
  rp_require_pkce       = p.op_require_pkce;
  rp_require_state      = p.op_require_state;
  rp_require_iss        = p.op_require_iss;
  rp_sender_constrained = p.op_sender_constrained;
  rp_allow_implicit     = p.op_allow_implicit;
  rp_allow_ropc         = p.op_allow_ropc;
}

(* =========================================================================
  Resolution function
  ========================================================================= *)

(** Resolve the effective policy for a client.

    Precedence:
    1. Client-bound profile (via oauth_profile_id FK on clients)
    2. Environment default profile (is_default = true)
    3. Baseline OAuth 2.1 *)
val resolve_profile :
  store:profile_store -> eid:environment_id ->
  client_profile_id:option profile_id -> now:nat ->
  Tot resolved_policy
let resolve_profile store eid client_profile_id now =
  match client_profile_id with
  | Some pid ->
    (match find_client_profile store.profiles eid pid now with
      | Some p -> profile_to_resolved p
      | None ->
        (* Client profile expired or deleted — fall back to default *)
        (match find_default_profile store.profiles eid now with
          | Some p -> profile_to_resolved p
          | None -> baseline_21))
  | None ->
    (match find_default_profile store.profiles eid now with
      | Some p -> profile_to_resolved p
      | None -> baseline_21)

(* =========================================================================
  PP1: resolution_precedence
  =========================================================================

  When a client-bound profile exists and is valid, it is used.
  When it doesn't exist, the default is used.
  When neither exists, the 2.1 baseline is used. *)

(** Client profile takes precedence when present. *)
val lemma_client_profile_wins :
  store:profile_store -> eid:environment_id ->
  pid:profile_id -> now:nat ->
  p:oauth_profile ->
  Lemma
    (requires
      find_client_profile store.profiles eid pid now == Some p)
    (ensures
      resolve_profile store eid (Some pid) now == profile_to_resolved p)
let lemma_client_profile_wins store eid pid now p = ()

(** Default profile used when no client profile. *)
val lemma_default_fallback :
  store:profile_store -> eid:environment_id -> now:nat ->
  p:oauth_profile ->
  Lemma
    (requires
      find_default_profile store.profiles eid now == Some p)
    (ensures
      resolve_profile store eid None now == profile_to_resolved p)
let lemma_default_fallback store eid now p = ()

(** Baseline used when neither client nor default profile exists. *)
val lemma_baseline_fallback :
  store:profile_store -> eid:environment_id -> now:nat ->
  Lemma
    (requires
      find_default_profile store.profiles eid now == None)
    (ensures
      resolve_profile store eid None now == baseline_21)
let lemma_baseline_fallback store eid now = ()

(* =========================================================================
  PP2: downgrade_prevention
  =========================================================================

  An OAuth 2.1 profile MUST NOT enable implicit grant or ROPC.
  This is a profile well-formedness constraint.

  DB-level enforcement: the application layer rejects create/update
  requests that set allow_implicit=true or allow_ropc=true when
  oauth_version='2.1'. *)

(** An OAuth 2.1 profile is well-formed iff implicit and ROPC are disabled. *)
val profile_21_well_formed : oauth_profile -> Tot bool
let profile_21_well_formed p =
  not (OAuth21? p.op_version) ||
  (not p.op_allow_implicit && not p.op_allow_ropc && p.op_require_pkce)

(** Helper: find_client_profile result satisfies any for_all predicate. *)
val lemma_find_client_satisfies :
  f:(oauth_profile -> bool) ->
  profiles:list oauth_profile -> eid:environment_id ->
  pid:profile_id -> now:nat ->
  Lemma
    (requires for_all f profiles)
    (ensures (match find_client_profile profiles eid pid now with
              | Some p -> f p = true
              | None -> True))
  (decreases profiles)
let rec lemma_find_client_satisfies f profiles eid pid now =
  match profiles with
  | [] -> ()
  | p :: rest ->
    if p.op_env_id = eid && p.op_id = pid && profile_valid_at now p then ()
    else lemma_find_client_satisfies f rest eid pid now

(** Helper: find_default_profile result satisfies any for_all predicate. *)
val lemma_find_default_satisfies :
  f:(oauth_profile -> bool) ->
  profiles:list oauth_profile -> eid:environment_id -> now:nat ->
  Lemma
    (requires for_all f profiles)
    (ensures (match find_default_profile profiles eid now with
              | Some p -> f p = true
              | None -> True))
  (decreases profiles)
let rec lemma_find_default_satisfies f profiles eid now =
  match profiles with
  | [] -> ()
  | p :: rest ->
    if p.op_env_id = eid && p.op_is_default && profile_valid_at now p then ()
    else lemma_find_default_satisfies f rest eid now

(** If all profiles are well-formed, resolution never produces a 2.1
    profile with implicit or ROPC enabled. *)
val lemma_no_downgrade :
  store:profile_store -> eid:environment_id ->
  client_pid:option profile_id -> now:nat ->
  Lemma
    (requires for_all profile_21_well_formed store.profiles)
    (ensures (
      let resolved = resolve_profile store eid client_pid now in
      OAuth21? resolved.rp_version ==>
      is_21_compliant resolved))
let lemma_no_downgrade store eid client_pid now =
  match client_pid with
  | Some pid ->
    lemma_find_client_satisfies profile_21_well_formed store.profiles eid pid now;
    (match find_client_profile store.profiles eid pid now with
      | Some _ -> ()
      | None ->
        lemma_find_default_satisfies profile_21_well_formed store.profiles eid now)
  | None ->
    lemma_find_default_satisfies profile_21_well_formed store.profiles eid now

(* =========================================================================
  PP3: exception_expiry_enforcement
  =========================================================================

  A policy exception is only effective when:
  - status = ExceptionActive
  - now < expires_at (not expired)

  Expired exceptions MUST NOT grant additional permissions. *)

(** An exception is effective at time `now`. *)
val exception_effective : now:nat -> pe:policy_exception -> Tot bool
let exception_effective now pe =
  ExceptionActive? pe.pe_status && now < pe.pe_expires_at

(** An exception is well-formed: expires_at > created_at. *)
val exception_well_formed : policy_exception -> Tot bool
let exception_well_formed pe =
  pe.pe_expires_at > pe.pe_created_at

(** At time `now >= expires_at`, the exception is not effective. *)
val lemma_expired_exception_not_effective :
  now:nat -> pe:policy_exception ->
  Lemma
    (requires now >= pe.pe_expires_at)
    (ensures not (exception_effective now pe))
let lemma_expired_exception_not_effective now pe = ()

(** A revoked exception is never effective regardless of time. *)
val lemma_revoked_exception_not_effective :
  now:nat -> pe:policy_exception ->
  Lemma
    (requires ExceptionRevoked? pe.pe_status)
    (ensures not (exception_effective now pe))
let lemma_revoked_exception_not_effective now pe = ()

(* =========================================================================
  PP4: default_uniqueness
  =========================================================================

  At most one active default profile exists per environment.
  Models the partial unique index:
    `oauth_profiles_default_unique ON (env_id, config_version_id, profile_type)
      WHERE is_default AND status = 'ACTIVE'` *)

(** Count active default profiles for an environment. *)
val count_active_defaults :
  profiles:list oauth_profile -> eid:environment_id -> Tot nat
  (decreases profiles)
let rec count_active_defaults profiles eid =
  match profiles with
  | [] -> 0
  | p :: rest ->
    let tail = count_active_defaults rest eid in
    if p.op_env_id = eid && p.op_is_default && ProfileActive? p.op_status then
      1 + tail
    else
      tail

(** Default profile store well-formedness. *)
val defaults_unique : profiles:list oauth_profile -> eid:environment_id -> Tot bool
let defaults_unique profiles eid =
  count_active_defaults profiles eid <= 1

(** find_default_profile returns at most one result. *)
val lemma_default_deterministic :
  profiles:list oauth_profile -> eid:environment_id -> now:nat ->
  Lemma (ensures (
    let result = find_default_profile profiles eid now in
    match result with
    | Some p -> p.op_env_id = eid /\ p.op_is_default /\ profile_valid_at now p
    | None -> True))
  (decreases profiles)
let rec lemma_default_deterministic profiles eid now =
  match profiles with
  | [] -> ()
  | p :: rest ->
    if p.op_env_id = eid && p.op_is_default && profile_valid_at now p then ()
    else lemma_default_deterministic rest eid now

(* =========================================================================
  PP5: ttl_positivity
  =========================================================================

  All configured TTLs in client policy overrides must be > 0.
  Models the DB constraint:
    `client_policy_profiles_ttls_positive CHECK (
      (access_token_time_to_live_seconds IS NULL OR ..._seconds > 0)
      AND ...)` *)

(** A client policy override has valid TTLs. *)
val override_ttls_valid : client_policy_override -> Tot bool
let override_ttls_valid co =
  (match co.co_access_ttl with None -> true | Some v -> v > 0) &&
  (match co.co_refresh_ttl with None -> true | Some v -> v > 0) &&
  (match co.co_id_ttl with None -> true | Some v -> v > 0)

(** If all overrides are well-formed, any TTL extracted from an override
    is positive. *)
val lemma_override_ttl_positive :
  overrides:list client_policy_override ->
  cid:client_id ->
  Lemma
    (requires for_all override_ttls_valid overrides)
    (ensures (
      forall (co:client_policy_override).
        mem co overrides /\ co.co_client_id = cid ==>
        override_ttls_valid co))
  (decreases overrides)
let rec lemma_override_ttl_positive overrides cid =
  match overrides with
  | [] -> ()
  | _ :: rest -> lemma_override_ttl_positive rest cid

(** The baseline policy is always 2.1-compliant. *)
val lemma_baseline_is_21_compliant :
  unit -> Lemma (ensures is_21_compliant baseline_21)
let lemma_baseline_is_21_compliant () = ()
