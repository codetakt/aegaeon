module Jose.HeaderPolicy

open FStar.List.Tot
open Jose.StringLemmas

let allow_list : list string =
  ["alg"; "enc"; "kid"; "typ"; "cty"; "zip"; "crit"]

let duplicate_key_msg : string = "duplicate-key"
let invalid_type_msg : string = "invalid-type"
let critical_extension_msg : string = "critical-extension"

let key_allowed (k:string) : Tot bool =
  string_in_list k allow_list

let forbids_extension (k:string) : Tot bool =
  key_allowed k && k <> "crit" && k <> "zip"

// Context-based API (new)
open Jose.Context

/// Header length limit from context
val get_header_max_length_from_context : jose_context -> nat
let get_header_max_length_from_context ctx = header_max_length_nat ctx
