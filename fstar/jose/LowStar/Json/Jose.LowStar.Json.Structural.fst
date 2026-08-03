module Jose.LowStar.Json.Structural

open FStar.List.Tot
open FStar.UInt8
open FStar.UInt32
open FStar.HyperStack.All
open FStar.HyperStack.ST
open LowStar.Buffer
open Jose.Arith.Bounds
open Jose.UInt32Bounds
open Jose.LowStar.Json.Structural.Runtime
open Jose.LowStar.Json.Structural.Types

module Buffer = LowStar.Buffer
module HS = FStar.HyperStack
module U32 = FStar.UInt32
module List = FStar.List.Tot

type structural_object_boundary_result =
  | StructuralObjectBoundaryInvalidJson
  | StructuralObjectBoundaryInvalidShape
  | StructuralObjectBoundaryComplete of trailing_bytes:bool

type structural_json_string_scan_result =
  | StructuralJsonStringInvalid
  | StructuralJsonStringComplete:
      closing_quote_idx32:UInt32.t ->
      had_escape:bool ->
      structural_json_string_scan_result

type structural_supported_value_parse_result =
  | StructuralSupportedValueInvalidJson
  | StructuralSupportedValueParserUnavailable
  | StructuralSupportedValueComplete:
      value_kind:raw_json_structural_value_kind ->
      value_end_idx32:UInt32.t ->
      structural_supported_value_parse_result

noeq
type structural_members_scan_result (max_members:nat) =
  | StructuralMembersInvalidJson
  | StructuralMembersParserUnavailable
  | StructuralMembersComplete:
      member_count32:UInt32.t{UInt32.v member_count32 <= max_members} ->
      consumed_len32:UInt32.t ->
      structural_members_scan_result max_members

noeq
type structural_supported_member_parse_result =
  | StructuralSupportedMemberInvalidJson
  | StructuralSupportedMemberParserUnavailable
  | StructuralSupportedMemberComplete:
      member:raw_json_structural_member_out ->
      after_value_idx32:UInt32.t ->
      structural_supported_member_parse_result

let structural_json_quote_byte : UInt8.t = 34uy
let structural_json_backslash_byte : UInt8.t = 92uy
let structural_json_lbrace_byte : UInt8.t = 123uy
let structural_json_rbrace_byte : UInt8.t = 125uy
let structural_json_lbracket_byte : UInt8.t = 91uy
let structural_json_rbracket_byte : UInt8.t = 93uy
let structural_json_colon_byte : UInt8.t = 58uy
let structural_json_comma_byte : UInt8.t = 44uy
let structural_json_minus_byte : UInt8.t = 45uy
let structural_json_zero_byte : UInt8.t = 48uy
let structural_json_nine_byte : UInt8.t = 57uy

let structural_is_ascii_json_whitespace (b:UInt8.t) : Tot bool =
  b = 32uy || b = 9uy || b = 10uy || b = 13uy

let structural_is_ascii_json_digit (b:UInt8.t) : Tot bool =
  UInt8.v structural_json_zero_byte <= UInt8.v b
  && UInt8.v b <= UInt8.v structural_json_nine_byte

let structural_is_ascii_hex_digit (b:UInt8.t) : Tot bool =
  structural_is_ascii_json_digit b
  || (UInt8.v 65uy <= UInt8.v b && UInt8.v b <= UInt8.v 70uy)
  || (UInt8.v 97uy <= UInt8.v b && UInt8.v b <= UInt8.v 102uy)

let lemma_lt_true_implies_strict
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires UInt32.lt a b = true)
      (ensures UInt32.v a < UInt32.v b)
  =
    if UInt32.lt a b then begin
      assert_norm (UInt32.lt a b);
      assert (UInt32.v a < UInt32.v b);
      ()
    end else begin
      let _ = assert_norm (UInt32.lt a b = false) in
      ()
    end

let structural_u32_succ_bounded
  (idx32:UInt32.t)
  (len32:UInt32.t)
  (_:unit{UInt32.v idx32 < UInt32.v len32})
  : Tot (next_idx32:UInt32.t{UInt32.v next_idx32 <= UInt32.v len32})
  =
    let _ = lemma_u32_succ_within_bound idx32 len32 in
    UInt32.add idx32 1ul

let structural_u32_sub_bounded
  (upper32:UInt32.t)
  (lower32:UInt32.t)
  (_:unit{UInt32.v lower32 <= UInt32.v upper32})
  : Tot UInt32.t
  =
    UInt32.sub upper32 lower32

noextract
let rec structural_all_ascii_json_whitespace
  (bytes:list UInt8.t)
  : Tot bool
  (decreases bytes)
  =
    match bytes with
    | [] -> true
    | b :: rest ->
        structural_is_ascii_json_whitespace b &&
        structural_all_ascii_json_whitespace rest

noextract
let rec structural_drop_ascii_json_whitespace
  (bytes:list UInt8.t)
  : Tot (list UInt8.t)
  (decreases bytes)
  =
    match bytes with
    | [] -> []
    | b :: rest ->
        if structural_is_ascii_json_whitespace b then
          structural_drop_ascii_json_whitespace rest
        else
          bytes

noextract
let rec structural_drop_ascii_json_whitespace_with_offset
  (bytes:list UInt8.t)
  (offset:nat)
  : Tot (list UInt8.t * nat)
  (decreases bytes)
  =
    match bytes with
    | [] -> ([], offset)
    | b :: rest ->
        if structural_is_ascii_json_whitespace b then
          structural_drop_ascii_json_whitespace_with_offset rest (offset + 1)
        else
          (bytes, offset)

noextract
let rec structural_scan_object_boundary_tail
  (bytes:list UInt8.t)
  (depth:nat{depth > 0})
  (in_string:bool)
  (escape:bool)
  : Tot (option (list UInt8.t))
  (decreases bytes)
  =
    match bytes with
    | [] -> None
    | b :: rest ->
        if in_string then
          if escape then
            structural_scan_object_boundary_tail rest depth true false
          else if b = structural_json_backslash_byte then
            structural_scan_object_boundary_tail rest depth true true
          else if b = structural_json_quote_byte then
            structural_scan_object_boundary_tail rest depth false false
          else
            structural_scan_object_boundary_tail rest depth true false
        else if b = structural_json_quote_byte then
          structural_scan_object_boundary_tail rest depth true false
        else if b = structural_json_lbrace_byte then
          structural_scan_object_boundary_tail rest (depth + 1) false false
        else if b = structural_json_rbrace_byte then
          if depth = 1 then
            Some rest
          else
            structural_scan_object_boundary_tail rest (depth - 1) false false
          else
            structural_scan_object_boundary_tail rest depth false false

noextract
let structural_classify_top_level_object_boundary
  (bytes:list UInt8.t)
  : Tot structural_object_boundary_result
  =
    match structural_drop_ascii_json_whitespace bytes with
    | [] -> StructuralObjectBoundaryInvalidJson
    | first :: rest ->
        if first <> structural_json_lbrace_byte then
          StructuralObjectBoundaryInvalidShape
        else
          match structural_scan_object_boundary_tail rest 1 false false with
          | None -> StructuralObjectBoundaryInvalidJson
          | Some trailing ->
              StructuralObjectBoundaryComplete
                (not (structural_all_ascii_json_whitespace trailing))

noextract
let rec structural_input_prefix_to_list
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  (idx32:UInt32.t{UInt32.v idx32 <= UInt32.v len32})
  : Stack (list UInt8.t)
      (requires (fun h -> Buffer.live h input))
      (ensures (fun h0 bytes h1 ->
        h0 == h1 /\
        Buffer.live h1 input /\
        List.length bytes = UInt32.v len32 - UInt32.v idx32))
      (decreases UInt32.v len32 - UInt32.v idx32)
  =
    if UInt32.v idx32 = UInt32.v len32 then
      []
    else
      let _ = lemma_idx_u32_lt_buffer_from_len input len32 idx32 in
      let _ = lemma_u32_succ_within_bound idx32 len32 in
      let byte = Buffer.index input idx32 in
      byte :: structural_input_prefix_to_list input len32 (UInt32.add idx32 1ul)

let rec structural_skip_ascii_json_whitespace_from_input
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  (idx32:UInt32.t{UInt32.v idx32 <= UInt32.v len32})
  : Stack UInt32.t
      (requires (fun h -> Buffer.live h input))
      (ensures (fun h0 next_idx h1 ->
        h0 == h1 /\
        Buffer.live h1 input /\
        UInt32.v idx32 <= UInt32.v next_idx /\
        UInt32.v next_idx <= UInt32.v len32))
  (decreases UInt32.v len32 - UInt32.v idx32)
  =
    if UInt32.lt idx32 len32 then
      let _ = lemma_idx_u32_lt_buffer_from_len input len32 idx32 in
      let byte = Buffer.index input idx32 in
      if structural_is_ascii_json_whitespace byte then
        let _ = lemma_u32_succ_within_bound idx32 len32 in
        let _ = lemma_u32_measure_lt len32 idx32 in
        structural_skip_ascii_json_whitespace_from_input input len32 (UInt32.add idx32 1ul)
      else
        idx32
    else
      idx32

let rec structural_all_ascii_json_whitespace_from_input
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  (idx32:UInt32.t{UInt32.v idx32 <= UInt32.v len32})
  : Stack bool
      (requires (fun h -> Buffer.live h input))
      (ensures (fun h0 all_ws h1 ->
        h0 == h1 /\
        Buffer.live h1 input))
  (decreases UInt32.v len32 - UInt32.v idx32)
  =
    if UInt32.lt idx32 len32 then
      let _ = lemma_idx_u32_lt_buffer_from_len input len32 idx32 in
      let byte = Buffer.index input idx32 in
      if structural_is_ascii_json_whitespace byte then
        let _ = lemma_u32_succ_within_bound idx32 len32 in
        let _ = lemma_u32_measure_lt len32 idx32 in
        structural_all_ascii_json_whitespace_from_input input len32 (UInt32.add idx32 1ul)
      else
        false
    else
      true

let rec structural_scan_json_string_tail_from_input
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  (idx32:UInt32.t{UInt32.v idx32 <= UInt32.v len32})
  (escape:bool)
  (unicode_digits_remaining:nat{unicode_digits_remaining <= 4})
  (had_escape:bool)
  : Stack structural_json_string_scan_result
      (requires (fun h -> Buffer.live h input))
      (ensures (fun h0 scan_result h1 ->
        h0 == h1 /\
        Buffer.live h1 input))
  (decreases UInt32.v len32 - UInt32.v idx32)
  =
    if UInt32.lt idx32 len32 then
      let _ = lemma_idx_u32_lt_buffer_from_len input len32 idx32 in
      let byte = Buffer.index input idx32 in
      if unicode_digits_remaining > 0 then
        if structural_is_ascii_hex_digit byte then
          let _ = lemma_u32_succ_within_bound idx32 len32 in
          let _ = lemma_u32_measure_lt len32 idx32 in
          let remaining' = unicode_digits_remaining - 1 in
          structural_scan_json_string_tail_from_input
            input
            len32
            (UInt32.add idx32 1ul)
            (remaining' > 0)
            remaining'
            had_escape
        else
          StructuralJsonStringInvalid
      else if escape then
        let _ = lemma_u32_succ_within_bound idx32 len32 in
        let _ = lemma_u32_measure_lt len32 idx32 in
        if byte = structural_json_quote_byte
          || byte = structural_json_backslash_byte
          || byte = 47uy
          || byte = 98uy
          || byte = 102uy
          || byte = 110uy
          || byte = 114uy
          || byte = 116uy then
          structural_scan_json_string_tail_from_input
            input
            len32
            (UInt32.add idx32 1ul)
            false
            0
            had_escape
        else if byte = 117uy then
          structural_scan_json_string_tail_from_input
            input
            len32
            (UInt32.add idx32 1ul)
            true
            4
            had_escape
        else
          StructuralJsonStringInvalid
      else if byte = structural_json_backslash_byte then
        let _ = lemma_u32_succ_within_bound idx32 len32 in
        let _ = lemma_u32_measure_lt len32 idx32 in
        structural_scan_json_string_tail_from_input
          input
          len32
          (UInt32.add idx32 1ul)
          true
          0
          true
      else if byte = structural_json_quote_byte then
        StructuralJsonStringComplete idx32 had_escape
      else if UInt8.v byte < 32 then
        StructuralJsonStringInvalid
      else
        let _ = lemma_u32_succ_within_bound idx32 len32 in
        let _ = lemma_u32_measure_lt len32 idx32 in
        structural_scan_json_string_tail_from_input
          input
          len32
          (UInt32.add idx32 1ul)
          false
          0
          had_escape
    else
      StructuralJsonStringInvalid

let structural_parse_supported_value_from_input
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  (value_offset:UInt32.t{UInt32.v value_offset <= UInt32.v len32})
  : Stack structural_supported_value_parse_result
      (requires (fun h -> Buffer.live h input))
      (ensures (fun h0 parse_result h1 ->
        h0 == h1 /\
        Buffer.live h1 input))
  =
    if UInt32.lt value_offset len32 then
      let _ = lemma_lt_true_implies_strict value_offset len32 in
      let _ = lemma_idx_u32_lt_buffer_from_len input len32 value_offset in
      let first = Buffer.index input value_offset in
      if first = structural_json_quote_byte then
        match structural_scan_json_string_tail_from_input
                input
                len32
                (structural_u32_succ_bounded value_offset len32 ())
                false
                0
                false with
        | StructuralJsonStringInvalid ->
            StructuralSupportedValueInvalidJson
        | StructuralJsonStringComplete closing_quote_idx _ ->
            if UInt32.lt closing_quote_idx len32 then
              let _ = lemma_lt_true_implies_strict closing_quote_idx len32 in
              StructuralSupportedValueComplete
                RawJsonStructuralValueString
                (structural_u32_succ_bounded closing_quote_idx len32 ())
            else
              StructuralSupportedValueInvalidJson
      else if first = 110uy then
        let idx1 = structural_u32_succ_bounded value_offset len32 () in
        if UInt32.lt idx1 len32 then
          let _ = lemma_lt_true_implies_strict idx1 len32 in
          let _ = lemma_idx_u32_lt_buffer_from_len input len32 idx1 in
          let second = Buffer.index input idx1 in
          if second = 117uy then
            let idx2 = structural_u32_succ_bounded idx1 len32 () in
            if UInt32.lt idx2 len32 then
              let _ = lemma_lt_true_implies_strict idx2 len32 in
              let _ = lemma_idx_u32_lt_buffer_from_len input len32 idx2 in
              let third = Buffer.index input idx2 in
              if third = 108uy then
                let idx3 = structural_u32_succ_bounded idx2 len32 () in
                if UInt32.lt idx3 len32 then
                  let _ = lemma_lt_true_implies_strict idx3 len32 in
                  let _ = lemma_idx_u32_lt_buffer_from_len input len32 idx3 in
                  let fourth = Buffer.index input idx3 in
                  if fourth = 108uy then
                    StructuralSupportedValueComplete
                      RawJsonStructuralValueNull
                      (structural_u32_succ_bounded idx3 len32 ())
                  else
                    StructuralSupportedValueInvalidJson
                else
                  StructuralSupportedValueInvalidJson
              else
                StructuralSupportedValueInvalidJson
            else
              StructuralSupportedValueInvalidJson
          else
            StructuralSupportedValueInvalidJson
        else
          StructuralSupportedValueInvalidJson
      else if first = structural_json_lbrace_byte
        || first = structural_json_lbracket_byte
        || first = 116uy
        || first = 102uy
        || first = structural_json_minus_byte
        || structural_is_ascii_json_digit first then
        StructuralSupportedValueParserUnavailable
      else
        StructuralSupportedValueInvalidJson
    else
      StructuralSupportedValueInvalidJson

let rec structural_scan_object_boundary_tail_from_input
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  (idx32:UInt32.t{UInt32.v idx32 <= UInt32.v len32})
  (depth32:UInt32.t{UInt32.v depth32 > 0})
  (in_string:bool)
  (escape:bool)
  : Stack structural_object_boundary_result
      (requires (fun h -> Buffer.live h input))
      (ensures (fun h0 boundary h1 ->
        h0 == h1 /\
        Buffer.live h1 input))
  (decreases UInt32.v len32 - UInt32.v idx32)
  =
    if UInt32.lt idx32 len32 then
      let _ = lemma_idx_u32_lt_buffer_from_len input len32 idx32 in
      let byte = Buffer.index input idx32 in
      if in_string then
        let _ = lemma_u32_succ_within_bound idx32 len32 in
        let _ = lemma_u32_measure_lt len32 idx32 in
        if escape then
          structural_scan_object_boundary_tail_from_input
            input
            len32
            (UInt32.add idx32 1ul)
            depth32
            true
            false
        else if byte = structural_json_backslash_byte then
          structural_scan_object_boundary_tail_from_input
            input
            len32
            (UInt32.add idx32 1ul)
            depth32
            true
            true
        else if byte = structural_json_quote_byte then
          structural_scan_object_boundary_tail_from_input
            input
            len32
            (UInt32.add idx32 1ul)
            depth32
            false
            false
        else
          structural_scan_object_boundary_tail_from_input
            input
            len32
            (UInt32.add idx32 1ul)
            depth32
            true
            false
      else if byte = structural_json_quote_byte then
        let _ = lemma_u32_succ_within_bound idx32 len32 in
        let _ = lemma_u32_measure_lt len32 idx32 in
        structural_scan_object_boundary_tail_from_input
          input
          len32
          (UInt32.add idx32 1ul)
          depth32
          true
          false
      else if byte = structural_json_lbrace_byte then
        if UInt32.lt depth32 len32 then
          let _ = lemma_u32_succ_within_bound idx32 len32 in
          let _ = lemma_u32_measure_lt len32 idx32 in
          let _ = lemma_u32_succ_within_bound depth32 len32 in
          structural_scan_object_boundary_tail_from_input
            input
            len32
            (UInt32.add idx32 1ul)
            (UInt32.add depth32 1ul)
            false
            false
        else
          StructuralObjectBoundaryInvalidJson
      else if byte = structural_json_rbrace_byte then
        if UInt32.eq depth32 1ul then
          let _ = lemma_u32_succ_within_bound idx32 len32 in
          let trailing_idx = UInt32.add idx32 1ul in
          StructuralObjectBoundaryComplete
            (not (structural_all_ascii_json_whitespace_from_input input len32 trailing_idx))
        else
          let _ = lemma_u32_succ_within_bound idx32 len32 in
          let _ = lemma_u32_measure_lt len32 idx32 in
          structural_scan_object_boundary_tail_from_input
            input
            len32
            (UInt32.add idx32 1ul)
            (UInt32.sub depth32 1ul)
            false
            false
      else
        let _ = lemma_u32_succ_within_bound idx32 len32 in
        let _ = lemma_u32_measure_lt len32 idx32 in
        structural_scan_object_boundary_tail_from_input
          input
          len32
          (UInt32.add idx32 1ul)
          depth32
          false
          false
    else
      StructuralObjectBoundaryInvalidJson

let classify_top_level_object_boundary_from_input
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  : Stack structural_object_boundary_result
      (requires (fun h -> Buffer.live h input))
      (ensures (fun h0 boundary h1 ->
        h0 == h1 /\
        Buffer.live h1 input))
  =
    let start_idx = structural_skip_ascii_json_whitespace_from_input input len32 0ul in
    if UInt32.lt start_idx len32 then
      let _ = lemma_idx_u32_lt_buffer_from_len input len32 start_idx in
      let first = Buffer.index input start_idx in
      if first <> structural_json_lbrace_byte then
        StructuralObjectBoundaryInvalidShape
      else
        let _ = lemma_u32_succ_within_bound start_idx len32 in
        structural_scan_object_boundary_tail_from_input
          input
          len32
          (UInt32.add start_idx 1ul)
          1ul
          false
          false
    else
      StructuralObjectBoundaryInvalidJson

noextract
let structural_match_empty_top_level_object
  (bytes:list UInt8.t)
  : Tot (option nat)
  =
    let (trimmed, start_offset) =
      structural_drop_ascii_json_whitespace_with_offset bytes 0 in
    match trimmed with
    | [] -> None
    | first :: rest ->
        if first <> structural_json_lbrace_byte then
          None
        else
          let (after_inner_ws, inner_offset) =
            structural_drop_ascii_json_whitespace_with_offset rest (start_offset + 1) in
          match after_inner_ws with
          | [] -> None
          | b :: trailing ->
              if b = structural_json_rbrace_byte
              && structural_all_ascii_json_whitespace trailing
              then
                Some (inner_offset + 1)
              else
                None

let match_empty_top_level_object_from_input
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  : Stack bool
      (requires (fun h -> Buffer.live h input))
      (ensures (fun h0 is_empty h1 ->
        h0 == h1 /\
        Buffer.live h1 input))
  =
    let start_idx = structural_skip_ascii_json_whitespace_from_input input len32 0ul in
    if UInt32.lt start_idx len32 then
      let _ = lemma_idx_u32_lt_buffer_from_len input len32 start_idx in
      let first = Buffer.index input start_idx in
      if first <> structural_json_lbrace_byte then
        false
      else
        let _ = lemma_u32_succ_within_bound start_idx len32 in
        let inner_idx =
          structural_skip_ascii_json_whitespace_from_input input len32 (UInt32.add start_idx 1ul) in
        if UInt32.lt inner_idx len32 then
          let _ = lemma_idx_u32_lt_buffer_from_len input len32 inner_idx in
          let next_byte = Buffer.index input inner_idx in
          if next_byte = structural_json_rbrace_byte then
            let _ = lemma_u32_succ_within_bound inner_idx len32 in
            structural_all_ascii_json_whitespace_from_input input len32 (UInt32.add inner_idx 1ul)
          else
            false
        else
          false
    else
      false

let write_structural_member_at_u32
  (buf:buffer raw_json_structural_member_out)
  (idx32:UInt32.t)
  (entry:raw_json_structural_member_out)
  : Stack unit
      (requires (fun h ->
        Buffer.live h buf /\
        UInt32.v idx32 < Buffer.length buf /\
        Buffer.length buf <= pow2 32))
      (ensures (fun h0 _ h1 ->
        modifies (loc_buffer buf) h0 h1 /\
        Buffer.live h1 buf))
  =
    Buffer.upd buf idx32 entry

let structural_parse_supported_member_from_input
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  (member_start_idx32:UInt32.t{UInt32.v member_start_idx32 <= UInt32.v len32})
  : Stack structural_supported_member_parse_result
      (requires (fun h -> Buffer.live h input))
      (ensures (fun h0 parse_result h1 ->
        h0 == h1 /\
        Buffer.live h1 input))
  =
    if UInt32.lt member_start_idx32 len32 then
      let _ = lemma_lt_true_implies_strict member_start_idx32 len32 in
      let _ = lemma_idx_u32_lt_buffer_from_len input len32 member_start_idx32 in
      let first = Buffer.index input member_start_idx32 in
      if first <> structural_json_quote_byte then
        StructuralSupportedMemberInvalidJson
      else
        let key_start = structural_u32_succ_bounded member_start_idx32 len32 () in
        match structural_scan_json_string_tail_from_input
                input
                len32
                key_start
                false
                0
                false with
        | StructuralJsonStringInvalid ->
            StructuralSupportedMemberInvalidJson
        | StructuralJsonStringComplete key_end _ ->
            if UInt32.lt key_end len32 then
              let _ = lemma_lt_true_implies_strict key_end len32 in
              let _ = lemma_idx_u32_lt_buffer_from_len input len32 key_end in
              if UInt32.gte key_end key_start then
                let _ = lemma_gte_true_implies_nonstrict key_end key_start in
                assert (UInt32.v key_start <= UInt32.v key_end);
                let key_len = structural_u32_sub_bounded key_end key_start () in
                let after_key_start = structural_u32_succ_bounded key_end len32 () in
                let after_key_idx =
                  structural_skip_ascii_json_whitespace_from_input
                    input
                    len32
                    after_key_start in
                if UInt32.lt after_key_idx len32 then
                  let _ = lemma_lt_true_implies_strict after_key_idx len32 in
                  let _ = lemma_idx_u32_lt_buffer_from_len input len32 after_key_idx in
                  let separator = Buffer.index input after_key_idx in
                  if separator = structural_json_colon_byte then
                    let after_colon_start = structural_u32_succ_bounded after_key_idx len32 () in
                    let value_offset =
                      structural_skip_ascii_json_whitespace_from_input
                        input
                        len32
                        after_colon_start in
                    match structural_parse_supported_value_from_input
                            input
                            len32
                            value_offset with
                    | StructuralSupportedValueInvalidJson ->
                        StructuralSupportedMemberInvalidJson
                    | StructuralSupportedValueParserUnavailable ->
                        StructuralSupportedMemberParserUnavailable
                    | StructuralSupportedValueComplete value_kind value_end ->
                        if UInt32.gte value_end value_offset then
                          let _ =
                            lemma_gte_true_implies_nonstrict value_end value_offset in
                          if UInt32.gte len32 value_end then
                            let _ = lemma_gte_true_implies_nonstrict len32 value_end in
                            assert (UInt32.v value_offset <= UInt32.v value_end);
                            let value_len =
                              structural_u32_sub_bounded value_end value_offset () in
                            let after_value_idx =
                              structural_skip_ascii_json_whitespace_from_input
                                input
                                len32
                                value_end in
                            StructuralSupportedMemberComplete
                              {
                                member_key_offset = key_start;
                                member_key_len = key_len;
                                member_value_kind_repr =
                                  raw_json_structural_value_kind_to_repr value_kind;
                                member_reserved0 = 0uy;
                                member_reserved1 = 0uy;
                                member_reserved2 = 0uy;
                                member_value_offset = value_offset;
                                member_value_len = value_len
                              }
                              after_value_idx
                          else
                            StructuralSupportedMemberInvalidJson
                        else
                          StructuralSupportedMemberInvalidJson
                  else
                    StructuralSupportedMemberInvalidJson
                else
                  StructuralSupportedMemberInvalidJson
              else
                StructuralSupportedMemberInvalidJson
            else
              StructuralSupportedMemberInvalidJson
    else
      StructuralSupportedMemberInvalidJson

let rec structural_fill_supported_members_tail_from_input
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  (idx32:UInt32.t{UInt32.v idx32 <= UInt32.v len32})
  (members_buf:buffer raw_json_structural_member_out{
    Buffer.length members_buf = UInt32.v len32 /\ Buffer.length members_buf > 0
  })
  (member_idx32:UInt32.t{UInt32.v member_idx32 <= UInt32.v len32})
  (fuel:nat)
  : Stack (structural_members_scan_result (UInt32.v len32))
      (requires (fun h ->
        Buffer.live h input /\
        Buffer.live h members_buf))
      (ensures (fun h0 scan_result h1 ->
        Buffer.live h1 input /\
        Buffer.live h1 members_buf))
  (decreases fuel)
  =
    if fuel = 0 then
      StructuralMembersInvalidJson
    else
      let next_idx = structural_skip_ascii_json_whitespace_from_input input len32 idx32 in
      if UInt32.lt next_idx len32 then
        let _ = lemma_lt_true_implies_strict next_idx len32 in
        let _ = lemma_idx_u32_lt_buffer_from_len input len32 next_idx in
        let byte = Buffer.index input next_idx in
        if byte = structural_json_rbrace_byte then
          let _ = lemma_u32_succ_within_bound next_idx len32 in
          StructuralMembersComplete member_idx32 (UInt32.add next_idx 1ul)
        else if UInt32.lt member_idx32 len32 then
          let _ = lemma_lt_true_implies_strict member_idx32 len32 in
          let _ = lemma_idx_u32_lt_buffer_from_len members_buf len32 member_idx32 in
          match structural_parse_supported_member_from_input
                  input
                  len32
                  next_idx with
          | StructuralSupportedMemberInvalidJson ->
              StructuralMembersInvalidJson
          | StructuralSupportedMemberParserUnavailable ->
              StructuralMembersParserUnavailable
          | StructuralSupportedMemberComplete member after_value_idx ->
              if UInt32.lt after_value_idx len32 then
                let _ = lemma_lt_true_implies_strict after_value_idx len32 in
                let _ =
                  lemma_idx_u32_lt_buffer_from_len input len32 after_value_idx in
                let next_separator = Buffer.index input after_value_idx in
                if next_separator = structural_json_comma_byte then
                  let _ = lemma_u32_succ_within_bound after_value_idx len32 in
                  write_structural_member_at_u32 members_buf member_idx32 member;
                  let _ = lemma_u32_succ_within_bound member_idx32 len32 in
                  structural_fill_supported_members_tail_from_input
                    input
                    len32
                    (UInt32.add after_value_idx 1ul)
                    members_buf
                    (UInt32.add member_idx32 1ul)
                    (fuel - 1)
                else if next_separator = structural_json_rbrace_byte then
                  let _ = lemma_u32_succ_within_bound after_value_idx len32 in
                  let _ = lemma_u32_succ_within_bound member_idx32 len32 in
                  write_structural_member_at_u32 members_buf member_idx32 member;
                  StructuralMembersComplete
                    (UInt32.add member_idx32 1ul)
                    (UInt32.add after_value_idx 1ul)
                else
                  StructuralMembersInvalidJson
              else
                StructuralMembersInvalidJson
        else
          StructuralMembersInvalidJson
      else
        StructuralMembersInvalidJson

let malloc_structural_member_array
  : len32:UInt32.t{UInt32.v len32 > 0}
  -> ST (Buffer.buffer raw_json_structural_member_out)
        (requires (fun _ -> True))
        (ensures (fun h0 buf h1 ->
                    Buffer.live h1 buf /\
                    Buffer.length buf = UInt32.v len32 /\
                    modifies loc_none h0 h1 /\
                    Buffer.freeable buf /\
                    Buffer.unused_in buf h0))
  =
  fun len32 -> Buffer.malloc HS.root default_raw_json_structural_member_out len32

let malloc_structural_key_bytes
  : len32:UInt32.t{UInt32.v len32 > 0}
  -> ST (Buffer.buffer UInt8.t)
        (requires (fun _ -> True))
        (ensures (fun h0 buf h1 ->
                    Buffer.live h1 buf /\
                    Buffer.length buf = UInt32.v len32 /\
                    modifies loc_none h0 h1 /\
                    Buffer.freeable buf /\
                    Buffer.unused_in buf h0))
  =
  fun len32 -> Buffer.malloc HS.root 0uy len32

let build_structural_error_result
  (err:raw_json_structural_parse_error{err <> RawJsonStructuralParseOk})
  : ST raw_json_structural_parse_result_c
      (requires (fun _ -> True))
      (ensures (fun h0 res h1 ->
        Buffer.live h1 res.result_members /\
        Buffer.freeable res.result_members /\
        Buffer.length res.result_members > 0 /\
        Buffer.live h1 res.result_key_bytes /\
        Buffer.freeable res.result_key_bytes /\
        Buffer.length res.result_key_bytes > 0 /\
        loc_disjoint (loc_buffer res.result_members) (loc_buffer res.result_key_bytes) /\
        res.result_error = err /\
        U32.v res.result_consumed_len = 0 /\
        U32.v res.result_member_count = 0 /\
        U32.v res.result_member_count <= Buffer.length res.result_members /\
        U32.v res.result_key_bytes_len = 0 /\
        U32.v res.result_key_bytes_len <= Buffer.length res.result_key_bytes))
  =
    let members_buf = malloc_structural_member_array 1ul in
    let key_bytes_buf = malloc_structural_key_bytes 1ul in
    let member_count_le : squash (U32.v 0ul <= Buffer.length members_buf) = () in
    let key_bytes_len_le : squash (U32.v 0ul <= Buffer.length key_bytes_buf) = () in
    {
      result_members = members_buf;
      result_member_count = 0ul;
      result_member_count_le = member_count_le;
      result_consumed_len = 0ul;
      result_error = err;
      result_key_bytes = key_bytes_buf;
      result_key_bytes_len = 0ul;
      result_key_bytes_len_le = key_bytes_len_le
    }

let build_structural_empty_success_result
  (consumed_len32:UInt32.t)
  : ST raw_json_structural_parse_result_c
      (requires (fun _ -> True))
      (ensures (fun h0 res h1 ->
        Buffer.live h1 res.result_members /\
        Buffer.freeable res.result_members /\
        Buffer.length res.result_members > 0 /\
        Buffer.live h1 res.result_key_bytes /\
        Buffer.freeable res.result_key_bytes /\
        Buffer.length res.result_key_bytes > 0 /\
        loc_disjoint (loc_buffer res.result_members) (loc_buffer res.result_key_bytes) /\
        res.result_error = RawJsonStructuralParseOk /\
        res.result_consumed_len = consumed_len32 /\
        U32.v res.result_member_count = 0 /\
        U32.v res.result_member_count <= Buffer.length res.result_members /\
        U32.v res.result_key_bytes_len = 0 /\
        U32.v res.result_key_bytes_len <= Buffer.length res.result_key_bytes))
  =
    let members_buf = malloc_structural_member_array 1ul in
    let key_bytes_buf = malloc_structural_key_bytes 1ul in
    let member_count_le : squash (U32.v 0ul <= Buffer.length members_buf) = () in
    let key_bytes_len_le : squash (U32.v 0ul <= Buffer.length key_bytes_buf) = () in
    {
      result_members = members_buf;
      result_member_count = 0ul;
      result_member_count_le = member_count_le;
      result_consumed_len = consumed_len32;
      result_error = RawJsonStructuralParseOk;
      result_key_bytes = key_bytes_buf;
      result_key_bytes_len = 0ul;
      result_key_bytes_len_le = key_bytes_len_le
    }

let build_structural_supported_success_result
  (members_buf:buffer raw_json_structural_member_out{Buffer.length members_buf > 0})
  (member_count32:UInt32.t{UInt32.v member_count32 <= Buffer.length members_buf})
  (consumed_len32:UInt32.t)
  : ST raw_json_structural_parse_result_c
      (requires (fun h ->
        Buffer.live h members_buf /\
        Buffer.freeable members_buf))
      (ensures (fun h0 res h1 ->
        Buffer.live h1 res.result_members /\
        Buffer.freeable res.result_members /\
        Buffer.length res.result_members = Buffer.length members_buf /\
        Buffer.live h1 res.result_key_bytes /\
        Buffer.freeable res.result_key_bytes /\
        Buffer.length res.result_key_bytes > 0 /\
        loc_disjoint (loc_buffer res.result_members) (loc_buffer res.result_key_bytes) /\
        res.result_members == members_buf /\
        res.result_error = RawJsonStructuralParseOk /\
        res.result_consumed_len = consumed_len32 /\
        res.result_member_count = member_count32 /\
        U32.v res.result_member_count <= Buffer.length res.result_members /\
        U32.v res.result_key_bytes_len = 0 /\
        U32.v res.result_key_bytes_len <= Buffer.length res.result_key_bytes))
  =
    let key_bytes_buf = malloc_structural_key_bytes 1ul in
    let result_member_count_le :
      squash (U32.v member_count32 <= Buffer.length members_buf) = () in
    let key_bytes_len_le : squash (U32.v 0ul <= Buffer.length key_bytes_buf) = () in
    {
      result_members = members_buf;
      result_member_count = member_count32;
      result_member_count_le = result_member_count_le;
      result_consumed_len = consumed_len32;
      result_error = RawJsonStructuralParseOk;
      result_key_bytes = key_bytes_buf;
      result_key_bytes_len = 0ul;
      result_key_bytes_len_le = key_bytes_len_le
    }

/// Structural parser entry point for a narrow supported subset.
///
/// The current extracted implementation accepts exact top-level objects and
/// populates member spans for raw key bodies whose values are strings or null.
/// Valid but unsupported value shapes still fail closed via
/// `RawJsonStructuralParseErrorParserUnavailable`.
inline_for_extraction let raw_json_structural_parse_to_c
  (input:buffer UInt8.t)
  (len32:UInt32.t{UInt32.v len32 <= Buffer.length input})
  : ST raw_json_structural_parse_result_c
      (requires (fun h -> Buffer.live h input))
      (ensures (fun h0 res h1 ->
        Buffer.live h1 res.result_members /\
        Buffer.freeable res.result_members /\
        Buffer.length res.result_members > 0 /\
        Buffer.live h1 res.result_key_bytes /\
        Buffer.freeable res.result_key_bytes /\
        Buffer.length res.result_key_bytes > 0 /\
        loc_disjoint (loc_buffer res.result_members) (loc_buffer res.result_key_bytes) /\
        U32.v res.result_member_count <= Buffer.length res.result_members /\
        U32.v res.result_key_bytes_len <= Buffer.length res.result_key_bytes))
  =
    match classify_top_level_object_boundary_from_input input len32 with
    | StructuralObjectBoundaryInvalidJson ->
        build_structural_error_result RawJsonStructuralParseErrorInvalidJson
    | StructuralObjectBoundaryInvalidShape ->
        build_structural_error_result RawJsonStructuralParseErrorInvalidShape
    | StructuralObjectBoundaryComplete trailing_bytes ->
        if trailing_bytes then
          build_structural_error_result RawJsonStructuralParseErrorTrailingBytes
        else
          if match_empty_top_level_object_from_input input len32 then
            build_structural_empty_success_result len32
          else if UInt32.eq len32 0ul then
            build_structural_error_result RawJsonStructuralParseErrorInvalidJson
          else
            let _ = assert (UInt32.v len32 > 0) in
            let members_buf = malloc_structural_member_array len32 in
            let _ = assert (Buffer.length members_buf = UInt32.v len32) in
            let _ = assert (Buffer.length members_buf > 0) in
            let start_idx = structural_skip_ascii_json_whitespace_from_input input len32 0ul in
            if UInt32.lt start_idx len32 then
              let _ = lemma_lt_true_implies_strict start_idx len32 in
              let _ = lemma_idx_u32_lt_buffer_from_len input len32 start_idx in
              let first = Buffer.index input start_idx in
              if first = structural_json_lbrace_byte then
                let start_members_idx = structural_u32_succ_bounded start_idx len32 () in
                let fuel:nat = UInt32.v len32 + 1 in
                let scan_result =
                  structural_fill_supported_members_tail_from_input
                    input
                    len32
                    start_members_idx
                    members_buf
                    0ul
                    fuel in
                match scan_result with
                | StructuralMembersInvalidJson ->
                    let _ = Buffer.free members_buf in
                    build_structural_error_result RawJsonStructuralParseErrorInvalidJson
                | StructuralMembersParserUnavailable ->
                    let _ = Buffer.free members_buf in
                    build_structural_error_result RawJsonStructuralParseErrorParserUnavailable
                | StructuralMembersComplete member_count32 consumed_len32 ->
                    build_structural_supported_success_result
                      members_buf
                      member_count32
                      consumed_len32
              else
                let _ = Buffer.free members_buf in
                build_structural_error_result RawJsonStructuralParseErrorInvalidShape
            else
              let _ = Buffer.free members_buf in
              build_structural_error_result RawJsonStructuralParseErrorInvalidJson

#push-options "--z3rlimit 100 --fuel 0 --ifuel 0 --z3refresh"
inline_for_extraction let raw_json_structural_free_result_data
  (res:raw_json_structural_parse_result_c)
  : ST unit
      (requires (fun h ->
        Buffer.freeable res.result_members /\
        Buffer.length res.result_members > 0 /\
        Buffer.live h res.result_members /\
        Buffer.freeable res.result_key_bytes /\
        Buffer.length res.result_key_bytes > 0 /\
        Buffer.live h res.result_key_bytes /\
        loc_disjoint (loc_buffer res.result_members)
          (loc_buffer res.result_key_bytes)))
      (ensures (fun _ _ _ -> True))
  =
    Buffer.freeable_disjoint' res.result_key_bytes res.result_members;
    loc_disjoint_includes
      (loc_addr_of_buffer res.result_key_bytes)
      (loc_addr_of_buffer res.result_members)
      (loc_addr_of_buffer res.result_key_bytes)
      (loc_buffer res.result_members);
    Buffer.free res.result_key_bytes;
    let h_mid = FStar.HyperStack.ST.get () in
    assert (Buffer.live h_mid res.result_members);
    Buffer.free res.result_members
#pop-options

#push-options "--z3rlimit 100 --fuel 0 --ifuel 0 --z3refresh"
inline_for_extraction let raw_json_structural_free_result
  (res:buffer raw_json_structural_parse_result_c)
  : ST unit
      (requires (fun h ->
        Buffer.live h res /\
        Buffer.length res >= 1 /\
        (let result_value = Seq.index (Buffer.as_seq h res) 0 in
          Buffer.freeable result_value.result_members /\
          Buffer.length result_value.result_members > 0 /\
          Buffer.live h result_value.result_members /\
          Buffer.freeable result_value.result_key_bytes /\
          Buffer.length result_value.result_key_bytes > 0 /\
          Buffer.live h result_value.result_key_bytes /\
          loc_disjoint (loc_buffer result_value.result_members)
            (loc_buffer result_value.result_key_bytes))))
      (ensures (fun _ _ _ -> True))
  =
    let result_value = Buffer.index res 0ul in
    raw_json_structural_free_result_data result_value
#pop-options
