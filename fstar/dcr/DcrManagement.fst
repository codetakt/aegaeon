module DcrManagement

open FStar.String

module Str = FStar.String

/// RFC 7592 Dynamic Client Registration Management Protocol — formal model.
///
/// Models the core security properties of the read/update/delete lifecycle
/// for dynamically registered OAuth 2.0 clients.

/// A simplified client record with the fields relevant to 7592 reasoning.
noeq type client_record = {
  client_id: string;
  registration_access_token: option string;
  is_deleted: bool;
}

/// A management request targeting a specific client.
noeq type management_request = {
  target_client_id: string;
  bearer_token: option string;
}

/// The registration access token is present and non-empty.
let has_valid_rat (c:client_record) : Tot bool =
  match c.registration_access_token with
  | Some tok -> Str.length tok > 0
  | None -> false

/// The request carries a non-empty Bearer token.
let has_bearer_token (req:management_request) : Tot bool =
  match req.bearer_token with
  | Some tok -> Str.length tok > 0
  | None -> false

/// Authentication succeeds when:
///   1. The client exists (not deleted) with a valid RAT,
///   2. The request carries a token,
///   3. The tokens match, and
///   4. The request targets the correct client_id.
let is_authenticated (c:client_record) (req:management_request) : Tot bool =
  not c.is_deleted &&
  has_valid_rat c &&
  has_bearer_token req &&
  req.target_client_id = c.client_id &&
  (match c.registration_access_token, req.bearer_token with
   | Some rat, Some tok -> rat = tok
   | _, _ -> false)

/// Lemma 1: Authentication is fail-closed — missing or invalid token always rejects.
let lemma_auth_fail_closed
  (c:client_record) (req:management_request)
  : Lemma
      (requires not (has_bearer_token req))
      (ensures not (is_authenticated c req))
  = ()

/// Lemma 2: Deleted clients cannot be authenticated.
let lemma_deleted_client_rejects
  (c:client_record) (req:management_request)
  : Lemma
      (requires c.is_deleted)
      (ensures not (is_authenticated c req))
  = ()

/// Simulate an update: client_id is immutable, RAT may rotate.
let apply_update (c:client_record) (new_rat:string) : Tot client_record =
  { c with registration_access_token = Some new_rat }

/// Lemma 3: Update preserves client_id (immutability invariant).
let lemma_update_preserves_client_id
  (c:client_record) (new_rat:string)
  : Lemma
      (ensures (apply_update c new_rat).client_id = c.client_id)
  = ()

/// Simulate a delete.
let apply_delete (c:client_record) : Tot client_record =
  { c with is_deleted = true; registration_access_token = None }

/// Lemma 4: After deletion, subsequent authentication fails.
let lemma_delete_invalidates_auth
  (c:client_record) (req:management_request)
  : Lemma
      (ensures not (is_authenticated (apply_delete c) req))
  = ()

/// Lemma 5: After token rotation via update, old token no longer authenticates.
let lemma_rotation_invalidates_old_token
  (c:client_record) (new_rat:string) (req:management_request)
  : Lemma
      (requires
        is_authenticated c req /\
        new_rat <> (Some?.v c.registration_access_token))
      (ensures not (is_authenticated (apply_update c new_rat) req))
  = ()
