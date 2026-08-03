module OidcRp.Types

(** OIDC Relying Party session state machine — type definitions.

    Models the authorize/callback flow for OIDC RP mode.
    Split from the monolithic spec per architect guidance into:
      - OidcRp.Types        (this module)
      - OidcRp.Transitions
      - OidcRp.Properties

    Production code reference:
      `crates/server/src/upstream.rs` — UpstreamAuthRequest
      `crates/server/src/web/mod.rs`  — authorize/callback handlers

    Session record fields match `UpstreamAuthRequest`:
      state, nonce, code_verifier, issuer, client_id,
      token_endpoint, jwks_uri, redirect_uri,
      issued_at, expires_at                                               *)

(* =========================================================================
   Types
   ========================================================================= *)

(** Opaque identifiers — modelled as nat for decidable equality. *)
type session_id   = nat
type timestamp_t  = nat

(** Opaque string-like values — modelled as string. *)
type state_param_t      = string
type nonce_param_t      = string
type code_verifier_t    = string
type issuer_t           = string
type client_id_t        = string
type endpoint_url_t     = string
type redirect_uri_t     = string

(** RP session state enum.

    State machine:
      Idle ─authorize→ PendingCallback ─callback→ Authenticated
                            │                          │
                            ├─timeout─→ Expired         │
                            └─mismatch→ Failed          │
                                                    (terminal) *)
type rp_session_state =
  | Idle
  | PendingCallback
  | Authenticated
  | Failed
  | Expired

(** Full RP session record.

    Fields match `UpstreamAuthRequest` in production code:
      - state/nonce:        random_token(32) at authorize time
      - code_verifier:      random_token(64) when PKCE required
      - token_endpoint:     from OIDC discovery
      - jwks_uri:           from OIDC discovery
      - issued_at/expires_at: session TTL for SM6 enforcement *)
type rp_session = {
  sid            : session_id;
  state          : rp_session_state;
  state_param    : state_param_t;
  nonce_param    : nonce_param_t;
  code_verifier  : option code_verifier_t;
  issuer         : issuer_t;
  client_id      : client_id_t;
  token_endpoint : endpoint_url_t;
  jwks_uri       : endpoint_url_t;
  redirect_uri   : redirect_uri_t;
  issued_at      : timestamp_t;
  expires_at     : timestamp_t;
}

(** The session store is a list of sessions. *)
type session_store = list rp_session

(* =========================================================================
   Well-formedness predicates
   ========================================================================= *)

(** A session is well-formed if expires_at > issued_at.
    Matches the upstream TTL constraint. *)
val session_well_formed : rp_session -> Tot bool
let session_well_formed s =
  s.expires_at > s.issued_at

(** A PendingCallback session is not expired at time `now`.
    Expiration boundary: `now >= expires_at` ⟹ expired
    (matches F* is_expired convention). *)
val session_valid_at : now:timestamp_t -> s:rp_session -> Tot bool
let session_valid_at now s =
  now < s.expires_at

(** A session has non-empty binding parameters. *)
val session_has_bindings : rp_session -> Tot bool
let session_has_bindings s =
  s.state_param <> "" &&
  s.nonce_param <> "" &&
  s.issuer <> ""

(** A session has PKCE verifier when required. *)
val session_has_pkce : rp_session -> Tot bool
let session_has_pkce s =
  Some? s.code_verifier

(** Check if a state_param is already used by a PendingCallback session. *)
val state_in_use : store:session_store -> st:state_param_t -> Tot bool
let state_in_use store st =
  FStar.List.Tot.existsb
    (fun s -> s.state_param = st && PendingCallback? s.state)
    store
