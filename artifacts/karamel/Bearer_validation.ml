open Prims
let (max_ttl : Prims.int) = (Prims.of_int (3600))
type token =
  {
  value: Prims.string ;
  scope: Prims.string ;
  expires_at: Prims.int ;
  used: Prims.bool ;
  revoked: Prims.bool }
let (__proj__Mktoken__item__value : token -> Prims.string) =
  fun projectee ->
    match projectee with
    | { value; scope; expires_at; used; revoked;_} -> value
let (__proj__Mktoken__item__scope : token -> Prims.string) =
  fun projectee ->
    match projectee with
    | { value; scope; expires_at; used; revoked;_} -> scope
let (__proj__Mktoken__item__expires_at : token -> Prims.int) =
  fun projectee ->
    match projectee with
    | { value; scope; expires_at; used; revoked;_} -> expires_at
let (__proj__Mktoken__item__used : token -> Prims.bool) =
  fun projectee ->
    match projectee with
    | { value; scope; expires_at; used; revoked;_} -> used
let (__proj__Mktoken__item__revoked : token -> Prims.bool) =
  fun projectee ->
    match projectee with
    | { value; scope; expires_at; used; revoked;_} -> revoked
let (scope_matches : Prims.string -> Prims.string -> Prims.bool) =
  fun req -> fun tok_scope -> req = tok_scope
let (issue : Prims.string -> Prims.int -> Prims.int -> Prims.string -> token)
  =
  fun value ->
    fun now ->
      fun ttl ->
        fun scope ->
          {
            value;
            scope;
            expires_at = (now + ttl);
            used = false;
            revoked = false
          }
let (verify :
  token -> Prims.int -> Prims.string -> token FStar_Pervasives_Native.option)
  =
  fun tok ->
    fun now ->
      fun req ->
        if
          ((tok.used || tok.revoked) || (now >= tok.expires_at)) ||
            (Prims.op_Negation (scope_matches req tok.scope))
        then FStar_Pervasives_Native.None
        else
          FStar_Pervasives_Native.Some
            {
              value = (tok.value);
              scope = (tok.scope);
              expires_at = (tok.expires_at);
              used = true;
              revoked = (tok.revoked)
            }
let (revoke : token -> token) =
  fun tok ->
    {
      value = (tok.value);
      scope = (tok.scope);
      expires_at = (tok.expires_at);
      used = (tok.used);
      revoked = true
    }
