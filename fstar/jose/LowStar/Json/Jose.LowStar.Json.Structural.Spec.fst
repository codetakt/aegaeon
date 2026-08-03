module Jose.LowStar.Json.Structural.Spec

open FStar.UInt8
open FStar.List.Tot

module List = FStar.List.Tot

type top_level_object_scan_result =
  | StructuralTopLevelObjectInvalidJson
  | StructuralTopLevelObjectInvalidShape
  | StructuralTopLevelObjectComplete:
      consumed_len:nat ->
      trailing_bytes:bool ->
      top_level_object_scan_result

let json_quote_byte : UInt8.t = 34uy
let json_backslash_byte : UInt8.t = 92uy
let json_lbrace_byte : UInt8.t = 123uy
let json_rbrace_byte : UInt8.t = 125uy
let json_lbracket_byte : UInt8.t = 91uy
let json_rbracket_byte : UInt8.t = 93uy
let json_colon_byte : UInt8.t = 58uy
let json_comma_byte : UInt8.t = 44uy
let json_minus_byte : UInt8.t = 45uy
let json_plus_byte : UInt8.t = 43uy
let json_dot_byte : UInt8.t = 46uy
let json_zero_byte : UInt8.t = 48uy
let json_nine_byte : UInt8.t = 57uy
let json_lower_e_byte : UInt8.t = 101uy
let json_upper_e_byte : UInt8.t = 69uy
let json_true_bytes : list UInt8.t = [116uy; 114uy; 117uy; 101uy]
let json_false_bytes : list UInt8.t = [102uy; 97uy; 108uy; 115uy; 101uy]
let json_null_bytes : list UInt8.t = [110uy; 117uy; 108uy; 108uy]

type structural_value_kind =
  | StructuralValueString
  | StructuralValueNull
  | StructuralValueNumber
  | StructuralValueBool
  | StructuralValueObject
  | StructuralValueArray

type top_level_object_member_span = {
  member_key_offset: nat;
  member_key_len: nat;
  member_value_kind: structural_value_kind;
  member_value_offset: nat;
  member_value_len: nat
}

type top_level_object_members_scan_result =
  | StructuralTopLevelMembersInvalidJson
  | StructuralTopLevelMembersInvalidShape
  | StructuralTopLevelMembersComplete:
      members:list top_level_object_member_span ->
      consumed_len:nat ->
      trailing_bytes:bool ->
      top_level_object_members_scan_result

let is_ascii_json_whitespace (b:UInt8.t) : Tot bool =
  b = 32uy || b = 9uy || b = 10uy || b = 13uy

let is_ascii_json_digit (b:UInt8.t) : Tot bool =
  UInt8.v json_zero_byte <= UInt8.v b && UInt8.v b <= UInt8.v json_nine_byte

let is_ascii_json_non_zero_digit (b:UInt8.t) : Tot bool =
  UInt8.v 49uy <= UInt8.v b && UInt8.v b <= UInt8.v json_nine_byte

let nat_sub_if_ge (upper:nat) (lower:nat) : Tot nat =
  if lower <= upper then
    upper - lower
  else
    0

let rec all_ascii_json_whitespace (bytes:list UInt8.t) : Tot bool
  (decreases bytes)
  =
    match bytes with
    | [] -> true
    | b :: rest -> is_ascii_json_whitespace b && all_ascii_json_whitespace rest

let rec drop_ascii_json_whitespace
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (list UInt8.t * nat)
  (decreases bytes)
  =
    match bytes with
    | [] -> ([], offset)
    | b :: rest ->
        if is_ascii_json_whitespace b then
          drop_ascii_json_whitespace rest (offset + 1)
        else
          (bytes, offset)

let rec scan_object_boundary_tail
  (bytes:list UInt8.t)
  (offset:nat)
  (depth:nat{depth > 0})
  (in_string:bool)
  (escape:bool)
  : Tot (option (nat * list UInt8.t))
  (decreases bytes)
  =
    match bytes with
    | [] -> None
    | b :: rest ->
        if in_string then
          if escape then
            scan_object_boundary_tail rest (offset + 1) depth true false
          else if b = json_backslash_byte then
            scan_object_boundary_tail rest (offset + 1) depth true true
          else if b = json_quote_byte then
            scan_object_boundary_tail rest (offset + 1) depth false false
          else
            scan_object_boundary_tail rest (offset + 1) depth true false
        else if b = json_quote_byte then
          scan_object_boundary_tail rest (offset + 1) depth true false
        else if b = json_lbrace_byte then
          scan_object_boundary_tail rest (offset + 1) (depth + 1) false false
        else if b = json_rbrace_byte then
          if depth = 1 then
            Some (offset + 1, rest)
          else
            scan_object_boundary_tail rest (offset + 1) (depth - 1) false false
        else
          scan_object_boundary_tail rest (offset + 1) depth false false

let rec scan_json_string_tail
  (bytes:list UInt8.t)
  (offset:nat)
  (escape:bool)
  : Tot (option (nat * list UInt8.t))
  (decreases bytes)
  =
    match bytes with
    | [] -> None
    | b :: rest ->
        if escape then
          scan_json_string_tail rest (offset + 1) false
        else if b = json_backslash_byte then
          scan_json_string_tail rest (offset + 1) true
        else if b = json_quote_byte then
          Some (offset, rest)
        else
          scan_json_string_tail rest (offset + 1) false

let rec scan_container_tail
  (bytes:list UInt8.t)
  (offset:nat)
  (object_depth:nat)
  (array_depth:nat)
  (in_string:bool)
  (escape:bool)
  : Tot (option (nat * list UInt8.t))
  (decreases bytes)
  =
    match bytes with
    | [] -> None
    | b :: rest ->
        if in_string then
          if escape then
            scan_container_tail
              rest
              (offset + 1)
              object_depth
              array_depth
              true
              false
          else if b = json_backslash_byte then
            scan_container_tail
              rest
              (offset + 1)
              object_depth
              array_depth
              true
              true
          else if b = json_quote_byte then
            scan_container_tail
              rest
              (offset + 1)
              object_depth
              array_depth
              false
              false
          else
            scan_container_tail
              rest
              (offset + 1)
              object_depth
              array_depth
              true
              false
        else if b = json_quote_byte then
          scan_container_tail
            rest
            (offset + 1)
            object_depth
            array_depth
            true
            false
        else if b = json_lbrace_byte then
          scan_container_tail
            rest
            (offset + 1)
            (object_depth + 1)
            array_depth
            false
            false
        else if b = json_rbrace_byte then
          if object_depth = 0 then
            None
          else if object_depth = 1 && array_depth = 0 then
            Some (offset + 1, rest)
          else
            scan_container_tail
              rest
              (offset + 1)
              (object_depth - 1)
              array_depth
              false
              false
        else if b = json_lbracket_byte then
          scan_container_tail
            rest
            (offset + 1)
            object_depth
            (array_depth + 1)
            false
            false
        else if b = json_rbracket_byte then
          if array_depth = 0 then
            None
          else if array_depth = 1 && object_depth = 0 then
            Some (offset + 1, rest)
          else
            scan_container_tail
              rest
              (offset + 1)
              object_depth
              (array_depth - 1)
              false
              false
        else
          scan_container_tail
            rest
            (offset + 1)
            object_depth
            array_depth
            false
            false

let rec match_exact_bytes
  (bytes:list UInt8.t)
  (offset:nat)
  (expected:list UInt8.t)
  : Tot (option (nat * list UInt8.t))
  (decreases expected)
  =
    match expected with
    | [] -> Some (offset, bytes)
    | expected_byte :: expected_rest ->
        match bytes with
        | [] -> None
        | b :: rest ->
            if b = expected_byte then
              match_exact_bytes rest (offset + 1) expected_rest
            else
              None

let rec span_ascii_json_digits
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (nat * list UInt8.t)
  (decreases bytes)
  =
    match bytes with
    | b :: rest ->
        if is_ascii_json_digit b then
          span_ascii_json_digits rest (offset + 1)
        else
          (offset, bytes)
    | [] -> (offset, [])

let parse_required_ascii_json_digits
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (option (nat * list UInt8.t))
  =
    match bytes with
    | b :: rest ->
        if is_ascii_json_digit b then
          Some (span_ascii_json_digits rest (offset + 1))
        else
          None
    | [] -> None

let parse_json_number_integer_part
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (option (nat * list UInt8.t))
  =
    match bytes with
    | [] -> None
    | b :: rest ->
        if b = json_zero_byte then
          Some (offset + 1, rest)
        else if is_ascii_json_non_zero_digit b then
          Some (span_ascii_json_digits rest (offset + 1))
        else
          None

let parse_optional_json_fraction
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (option (nat * list UInt8.t))
  =
    match bytes with
    | b :: rest ->
        if b = json_dot_byte then
          parse_required_ascii_json_digits rest (offset + 1)
        else
          Some (offset, bytes)
    | [] -> Some (offset, [])

let parse_optional_json_exponent_sign
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (list UInt8.t * nat)
  =
    match bytes with
    | b :: rest ->
        if b = json_plus_byte || b = json_minus_byte then
          (rest, offset + 1)
        else
          (bytes, offset)
    | [] -> ([], offset)

let parse_optional_json_exponent
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (option (nat * list UInt8.t))
  =
    match bytes with
    | b :: rest ->
        if b = json_lower_e_byte || b = json_upper_e_byte then
          let (after_sign, offset_after_sign) =
            parse_optional_json_exponent_sign rest (offset + 1)
          in
          parse_required_ascii_json_digits after_sign offset_after_sign
        else
          Some (offset, bytes)
    | [] -> Some (offset, [])

let parse_json_number
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (option (nat * list UInt8.t))
  =
    let (bytes_after_minus, offset_after_minus) =
      match bytes with
      | b :: rest ->
          if b = json_minus_byte then
            (rest, offset + 1)
          else
            (bytes, offset)
      | [] -> ([], offset)
    in
    match parse_json_number_integer_part bytes_after_minus offset_after_minus with
    | None -> None
    | Some (offset_after_integer, bytes_after_integer) ->
        match parse_optional_json_fraction
                bytes_after_integer
                offset_after_integer with
        | None -> None
        | Some (offset_after_fraction, bytes_after_fraction) ->
            parse_optional_json_exponent
              bytes_after_fraction
              offset_after_fraction

let parse_json_value
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (option (structural_value_kind * nat * list UInt8.t))
  =
    match bytes with
    | [] -> None
    | b :: rest ->
        if b = json_quote_byte then
          match scan_json_string_tail rest (offset + 1) false with
          | None -> None
          | Some (closing_quote_offset, trailing) ->
              Some (StructuralValueString, closing_quote_offset + 1, trailing)
        else if b = json_lbrace_byte then
          match scan_container_tail rest (offset + 1) 1 0 false false with
          | None -> None
          | Some (end_offset, trailing) ->
              Some (StructuralValueObject, end_offset, trailing)
        else if b = json_lbracket_byte then
          match scan_container_tail rest (offset + 1) 0 1 false false with
          | None -> None
          | Some (end_offset, trailing) ->
              Some (StructuralValueArray, end_offset, trailing)
        else if b = 116uy then
          match match_exact_bytes bytes offset json_true_bytes with
          | None -> None
          | Some (end_offset, trailing) ->
              Some (StructuralValueBool, end_offset, trailing)
        else if b = 102uy then
          match match_exact_bytes bytes offset json_false_bytes with
          | None -> None
          | Some (end_offset, trailing) ->
              Some (StructuralValueBool, end_offset, trailing)
        else if b = 110uy then
          match match_exact_bytes bytes offset json_null_bytes with
          | None -> None
          | Some (end_offset, trailing) ->
              Some (StructuralValueNull, end_offset, trailing)
        else if b = json_minus_byte || is_ascii_json_digit b then
          match parse_json_number bytes offset with
          | None -> None
          | Some (end_offset, trailing) ->
              Some (StructuralValueNumber, end_offset, trailing)
        else
          None

let parse_top_level_object_member
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (option (top_level_object_member_span * nat * list UInt8.t))
  =
    let (after_member_ws, offset_after_member_ws) =
      drop_ascii_json_whitespace bytes offset in
    match after_member_ws with
    | [] -> None
    | opening_quote :: key_tail ->
        if opening_quote <> json_quote_byte then
          None
        else
          let key_offset = offset_after_member_ws + 1 in
          match scan_json_string_tail
                  key_tail
                  (offset_after_member_ws + 1)
                  false with
          | None -> None
          | Some (key_closing_quote_offset, after_key) ->
              let key_len = nat_sub_if_ge key_closing_quote_offset key_offset in
              let (after_key_ws, offset_after_key_ws) =
                drop_ascii_json_whitespace
                  after_key
                  (key_closing_quote_offset + 1) in
              match after_key_ws with
              | b :: after_colon ->
                  if b = json_colon_byte then
                    let (after_value_ws, value_offset) =
                      drop_ascii_json_whitespace
                        after_colon
                        (offset_after_key_ws + 1) in
                    match parse_json_value after_value_ws value_offset with
                    | None -> None
                    | Some (value_kind, value_end_offset, after_value) ->
                        Some ({
                          member_key_offset = key_offset;
                          member_key_len = key_len;
                          member_value_kind = value_kind;
                          member_value_offset = value_offset;
                          member_value_len =
                            nat_sub_if_ge value_end_offset value_offset
                        }, value_end_offset, after_value)
                  else
                    None
              | [] -> None

let rec scan_top_level_object_members_tail
  (bytes:list UInt8.t)
  (offset:nat)
  (members_rev:list top_level_object_member_span)
  (fuel:nat)
  : Tot (option (list top_level_object_member_span * nat * list UInt8.t))
  (decreases fuel)
  =
    if fuel = 0 then
      None
    else
      let (after_ws, offset_after_ws) = drop_ascii_json_whitespace bytes offset in
      match after_ws with
      | [] -> None
      | b :: rest ->
          if b = json_rbrace_byte then
            Some (List.rev members_rev, offset_after_ws + 1, rest)
          else
            match parse_top_level_object_member after_ws offset_after_ws with
            | None -> None
            | Some (member, after_member_offset, after_member) ->
                let (after_member_ws, offset_after_member_ws) =
                  drop_ascii_json_whitespace after_member after_member_offset in
                match after_member_ws with
                | [] -> None
                | separator :: after_separator ->
                    if separator = json_comma_byte then
                      scan_top_level_object_members_tail
                        after_separator
                        (offset_after_member_ws + 1)
                        (member :: members_rev)
                        (fuel - 1)
                    else if separator = json_rbrace_byte then
                      Some (
                        List.rev (member :: members_rev),
                        offset_after_member_ws + 1,
                        after_separator
                      )
                    else
                      None

let scan_top_level_object_boundary
  (bytes:list UInt8.t)
  : Tot top_level_object_scan_result
  =
    let (trimmed, start_offset) = drop_ascii_json_whitespace bytes 0 in
    match trimmed with
    | [] -> StructuralTopLevelObjectInvalidJson
    | first :: rest ->
        if first <> json_lbrace_byte then
          StructuralTopLevelObjectInvalidShape
        else
          match scan_object_boundary_tail rest (start_offset + 1) 1 false false with
          | None -> StructuralTopLevelObjectInvalidJson
          | Some (consumed_len, trailing) ->
              StructuralTopLevelObjectComplete consumed_len
                (not (all_ascii_json_whitespace trailing))

let scan_top_level_object_members
  (bytes:list UInt8.t)
  : Tot top_level_object_members_scan_result
  =
    let (trimmed, start_offset) = drop_ascii_json_whitespace bytes 0 in
    match trimmed with
    | [] -> StructuralTopLevelMembersInvalidJson
    | first :: rest ->
        if first <> json_lbrace_byte then
          StructuralTopLevelMembersInvalidShape
        else
          match scan_top_level_object_members_tail
                  rest
                  (start_offset + 1)
                  []
                  (List.length rest + 1) with
          | None -> StructuralTopLevelMembersInvalidJson
          | Some (members, consumed_len, trailing) ->
              StructuralTopLevelMembersComplete
                members
                consumed_len
                (not (all_ascii_json_whitespace trailing))

let scan_top_level_object_reports_no_trailing_for_exact_object ()
  : Lemma
      (ensures
        (scan_top_level_object_boundary [json_lbrace_byte; json_rbrace_byte] =
          StructuralTopLevelObjectComplete 2 false))
  = ()

let scan_top_level_object_reports_trailing_bytes_after_object ()
  : Lemma
      (ensures
        (scan_top_level_object_boundary
            [json_lbrace_byte; json_rbrace_byte; 120uy] =
          StructuralTopLevelObjectComplete 2 true))
  = ()

let scan_top_level_object_rejects_non_object_shape ()
  : Lemma
      (ensures
        (scan_top_level_object_boundary [91uy; 93uy] =
          StructuralTopLevelObjectInvalidShape))
  = ()

let scan_top_level_object_members_reports_empty_object ()
  : Lemma
      (ensures
        (scan_top_level_object_members [json_lbrace_byte; json_rbrace_byte] =
          StructuralTopLevelMembersComplete [] 2 false))
  = ()

let scan_top_level_object_members_reports_single_string_member ()
  : Lemma
      (ensures
        (scan_top_level_object_members
          [123uy; 34uy; 97uy; 108uy; 103uy; 34uy; 58uy;
          34uy; 72uy; 83uy; 50uy; 53uy; 54uy; 34uy; 125uy] =
          StructuralTopLevelMembersComplete
            [{
              member_key_offset = 2;
              member_key_len = 3;
              member_value_kind = StructuralValueString;
              member_value_offset = 7;
              member_value_len = 7
            }]
            15
            false))
  = ()
