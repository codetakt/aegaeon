module Jose.Dcr

open FStar.UInt32
module U32 = FStar.UInt32

/// Policy evaluation errors.
noeq type policy_error =
  | MissingPkcePublic
  | MissingPkceConfidential
  | MissingSenderConstraint
  | UnsupportedSenderMethod

noeq type validation_result =
  | Success
  | Error of policy_error

let is_success (res:validation_result) : Tot bool =
  match res with
  | Success -> true
  | _ -> false

let is_missing_pkce_public (res:validation_result) : Tot bool =
  match res with
  | Error MissingPkcePublic -> true
  | _ -> false

let is_missing_pkce_confidential (res:validation_result) : Tot bool =
  match res with
  | Error MissingPkceConfidential -> true
  | _ -> false

let is_missing_sender_constraint (res:validation_result) : Tot bool =
  match res with
  | Error MissingSenderConstraint -> true
  | _ -> false

let is_unsupported_sender_method (res:validation_result) : Tot bool =
  match res with
  | Error UnsupportedSenderMethod -> true
  | _ -> false

/// Token endpoint auth method tags consumed by the Low* runtime.
noeq type token_method_tag =
  | TokenMethodNone
  | TokenMethodClientSecretBasic
  | TokenMethodClientSecretPost
  | TokenMethodPrivateKeyJwt
  | TokenMethodTlsClientAuth
  | TokenMethodSelfSignedTls
  | TokenMethodOther

type sender_methods_mask = U32.t

let mask_zero : sender_methods_mask = 0ul
let sender_method_bit_dpop : sender_methods_mask = 0x1ul
let sender_method_bit_mtls : sender_methods_mask = 0x2ul
let sender_methods_supported_mask : sender_methods_mask = 0x3ul

let mask_has_bit (mask:sender_methods_mask) (bit:sender_methods_mask) : Tot bool =
  U32.logand mask bit = bit

let mask_subset (candidate:sender_methods_mask) (sup:sender_methods_mask) : Tot bool =
  U32.logand candidate sup = candidate

let mask_is_zero (mask:sender_methods_mask) : Tot bool =
  mask = mask_zero

let mask_is_supported (mask:sender_methods_mask) : Tot bool =
  mask_subset mask sender_methods_supported_mask

let sanitize_mask (mask:sender_methods_mask) : sender_methods_mask =
  U32.logand mask sender_methods_supported_mask

let is_public_token_method (tag:token_method_tag) : Tot bool =
  match tag with
  | TokenMethodNone -> true
  | _ -> false

let is_confidential_token_method (tag:token_method_tag) : Tot bool =
  not (is_public_token_method tag)

let bool_from_declared (declared:bool) (value:bool) : Tot bool =
  declared && value

noeq type dcr_metadata_c = {
  token_method: token_method_tag;
  pkce_declared: bool;
  pkce_value: bool;
  sender_flag_declared: bool;
  sender_flag_value: bool;
  sender_methods_declared: bool;
  sender_methods_mask: sender_methods_mask;
}

inline_for_extraction let make_metadata_c
  (token_method:token_method_tag)
  (pkce_declared:bool)
  (pkce_value:bool)
  (sender_flag_declared:bool)
  (sender_flag_value:bool)
  (sender_methods_declared:bool)
  (sender_methods_mask_value:sender_methods_mask)
  : Tot dcr_metadata_c =
  let normalized_mask =
    if sender_methods_declared then sender_methods_mask_value else mask_zero in
  {
    token_method;
    pkce_declared;
    pkce_value;
    sender_flag_declared;
    sender_flag_value;
    sender_methods_declared;
    sender_methods_mask = normalized_mask;
  }

let validate_dcr_metadata_core
  (meta:dcr_metadata_c)
  (require_pkce_public:bool)
  (require_pkce_confidential:bool)
  (require_sender:bool)
  (allowed_sender_mask:sender_methods_mask)
  : Tot validation_result
  =
    let pkce_true = bool_from_declared meta.pkce_declared meta.pkce_value in
    let sender_flag_true = bool_from_declared meta.sender_flag_declared meta.sender_flag_value in
    let allowed_mask = sanitize_mask allowed_sender_mask in
    let methods_mask = meta.sender_methods_mask in
    let methods_declared = meta.sender_methods_declared in
    let supported_methods_ok =
      (not methods_declared) || mask_is_supported methods_mask in
    if require_pkce_public && is_public_token_method meta.token_method && not pkce_true then
      Error MissingPkcePublic
    else if require_pkce_confidential && is_confidential_token_method meta.token_method && not pkce_true then
      Error MissingPkceConfidential
    else if require_sender && not sender_flag_true then
      Error MissingSenderConstraint
    else if not supported_methods_ok then
      Error UnsupportedSenderMethod
    else
      let subset_ok =
        if sender_flag_true then
          if methods_declared then mask_subset methods_mask allowed_mask
          else mask_is_zero allowed_mask
        else true
      in
      if not subset_ok then
        Error UnsupportedSenderMethod
      else
        Success

inline_for_extraction val validate_dcr_metadata_c :
  token_method:token_method_tag ->
  pkce_declared:bool ->
  pkce_value:bool ->
  sender_flag_declared:bool ->
  sender_flag_value:bool ->
  sender_methods_declared:bool ->
  sender_methods_mask_value:sender_methods_mask ->
  require_pkce_public:bool ->
  require_pkce_confidential:bool ->
  require_sender:bool ->
  allowed_sender_mask:sender_methods_mask ->
  Tot validation_result

inline_for_extraction let validate_dcr_metadata_c
  (token_method:token_method_tag)
  (pkce_declared:bool)
  (pkce_value:bool)
  (sender_flag_declared:bool)
  (sender_flag_value:bool)
  (sender_methods_declared:bool)
  (sender_methods_mask_value:sender_methods_mask)
  (require_pkce_public:bool)
  (require_pkce_confidential:bool)
  (require_sender:bool)
  (allowed_sender_mask:sender_methods_mask)
  : Tot validation_result
  =
    let meta =
      make_metadata_c
        token_method pkce_declared pkce_value
        sender_flag_declared sender_flag_value
        sender_methods_declared sender_methods_mask_value
    in
    validate_dcr_metadata_core
      meta
      require_pkce_public require_pkce_confidential
      require_sender allowed_sender_mask
