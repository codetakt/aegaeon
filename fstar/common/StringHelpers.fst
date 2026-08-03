module StringHelpers

open FStar.String
open FStar.Char

/// Shared string-level helpers for URI validation across F* modules.
///
/// Extracted from ResourceIndicators.fst and ProtectedResourceMetadata.fst
/// to eliminate duplicate definitions of `starts_with_chars` and `is_https_url`.

let rec starts_with_chars (s:list char) (prefix:list char) : Tot bool (decreases prefix) =
  match prefix with
  | [] -> true
  | p :: ps ->
    match s with
    | [] -> false
    | c :: cs -> c = p && starts_with_chars cs ps

let is_https_url (u:string) : Tot bool =
  starts_with_chars (list_of_string u) (list_of_string "https://")
