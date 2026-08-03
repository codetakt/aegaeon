#[cfg(all(kani, feature = "kani"))]
mod verification {

    // Verify that verify_dpop enforces non-empty inputs regardless of timestamp.
    #[kani::proof]
    fn verify_dpop_handles_empty_and_valid_inputs() {
        let proof_empty: bool = kani::any();
        let method_empty: bool = kani::any();
        let uri_empty: bool = kani::any();
        let now: u64 = kani::any();

        let proof = if proof_empty { "" } else { "p" };
        let method = if method_empty { "" } else { "m" };
        let uri = if uri_empty { "" } else { "u" };

        let res = crate::verify_dpop(proof, method, uri, now, None);
        if proof_empty || method_empty || uri_empty {
            assert!(res.is_none());
        } else {
            assert!(res.is_some());
        }
    }

    // Verify that verify_pkce accepts only matching non-empty inputs.
    #[kani::proof]
    fn verify_pkce_edge_cases() {
        let verifier_empty: bool = kani::any();
        let challenge_empty: bool = kani::any();
        let match_pair: bool = kani::any();

        let verifier = if verifier_empty { "" } else { "v" };
        let challenge = if challenge_empty {
            ""
        } else if match_pair {
            "v"
        } else {
            "c"
        };

        let res = crate::verify_pkce(verifier, challenge);
        if verifier_empty || challenge_empty {
            assert!(!res);
        } else if match_pair {
            assert!(res);
        } else {
            assert!(!res);
        }
    }

    // =========================================================================
    // JSON FFI and bytes_block Stack module verification
    // =========================================================================

    #[kani::proof]
    fn verify_json_member_c_layout() {
        // Verify JsonMemberC structure has correct size and alignment
        // Critical for FFI safety with Low* C code
        use crate::JsonMemberC;
        use std::mem::{align_of, size_of};

        // Structure should be 32 bytes (verified against C layout)
        kani::assert(
            size_of::<JsonMemberC>() == 32,
            "JsonMemberC size must be 32 bytes",
        );

        // Alignment should be 8 bytes (pointer alignment)
        kani::assert(
            align_of::<JsonMemberC>() == 8,
            "JsonMemberC alignment must be 8 bytes",
        );
    }

    #[kani::proof]
    fn verify_utf8_decode_null_safety() {
        // Verify that aegaeon_ffi_decode_utf8 handles null pointers safely
        let mut out_ptr: *mut std::ffi::c_char = std::ptr::null_mut();

        // Null bytes pointer should return error
        let result1 = crate::aegaeon_ffi_decode_utf8(
            std::ptr::null(),
            0,
            &mut out_ptr as *mut *mut std::ffi::c_char,
        );
        kani::assert(
            result1 == 6,
            "Null bytes pointer should return INTERNAL error",
        );

        // Null out_string pointer should return error
        let data = b"test";
        let result2 =
            crate::aegaeon_ffi_decode_utf8(data.as_ptr(), data.len(), std::ptr::null_mut());
        kani::assert(
            result2 == 6,
            "Null out_string pointer should return INTERNAL error",
        );
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_utf8_decode_valid_input() {
        // Verify that valid UTF-8 strings are decoded correctly
        let choice: u8 = kani::any();
        kani::assume(choice < 3);

        let data = match choice {
            0 => b"" as &[u8],
            1 => b"a" as &[u8],
            _ => b"test" as &[u8],
        };

        let mut out_ptr: *mut std::ffi::c_char = std::ptr::null_mut();
        let result = crate::aegaeon_ffi_decode_utf8(
            data.as_ptr(),
            data.len(),
            &mut out_ptr as *mut *mut std::ffi::c_char,
        );

        if data.is_empty() || data.iter().all(|&b| b < 128) {
            // Valid UTF-8 should return OK
            kani::assert(result == 0, "Valid UTF-8 should return OK");

            // Should allocate non-null string
            if result == 0 {
                kani::assert(!out_ptr.is_null(), "Should allocate string on success");

                // Free the allocated string
                unsafe {
                    crate::aegaeon_ffi_free_string(out_ptr);
                }
            }
        }
    }

    #[kani::proof]
    fn verify_free_string_null_safety() {
        // Verify that aegaeon_ffi_free_string handles null pointer safely
        crate::aegaeon_ffi_free_string(std::ptr::null_mut());
        // Should not panic or crash
        kani::assert(true, "Free null pointer should be safe");
    }

    #[kani::proof]
    fn verify_jose_context_bounds() {
        use crate::JoseContext;

        // Default context should have valid bounds
        let default_ctx = JoseContext::default();
        let max_len = default_ctx.header_max_length();

        kani::assert(
            max_len > 0,
            "Default context should have positive max length",
        );
        kani::assert(max_len <= i32::MAX as usize, "Max length should fit in i32");
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn verify_parse_json_entries_null_pointer() {
        // Verify that parse_json_entries handles null pointer safely
        let result = unsafe { crate::parse_json_entries(std::ptr::null(), 0) };

        // Should return error for null pointer
        kani::assert(result.is_err(), "Null pointer should return error");

        if let Err(e) = result {
            // Error should be Internal type
            match e {
                crate::JsonError::Internal(_) => {
                    kani::assert(true, "Null pointer should return Internal error");
                }
                _ => {
                    kani::assert(false, "Expected Internal error for null pointer");
                }
            }
        }
    }

    #[kani::proof]
    fn verify_parse_json_entries_count_overflow() {
        use crate::JsonMemberC;

        // Create a valid member to get valid pointer
        let member = JsonMemberC {
            key_buf: b"test".as_ptr(),
            key_len: 4,
            value_kind: 0,
            padding: [0; 3],
            value_buf: b"value".as_ptr(),
            value_len: 5,
        };

        // Try with count that exceeds i64::MAX
        let result = unsafe {
            crate::parse_json_entries(&member as *const JsonMemberC, (i64::MAX as usize) + 1)
        };

        // Should return error for overflow
        kani::assert(result.is_err(), "Count overflow should return error");
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn verify_json_member_c_pointer_validity() {
        use crate::JsonMemberC;

        // Verify that JsonMemberC fields maintain their values
        let key = b"test";
        let value = b"data";

        let member = JsonMemberC {
            key_buf: key.as_ptr(),
            key_len: key.len() as u32,
            value_kind: 0,
            padding: [0; 3],
            value_buf: value.as_ptr(),
            value_len: value.len() as u32,
        };

        // Fields should preserve their values
        kani::assert(member.key_len == 4, "Key length should be 4");
        kani::assert(member.value_len == 4, "Value length should be 4");
        kani::assert(member.value_kind == 0, "Value kind should be 0");

        // Pointers should not be null for valid data
        kani::assert(!member.key_buf.is_null(), "Key buffer should not be null");
        kani::assert(
            !member.value_buf.is_null(),
            "Value buffer should not be null",
        );
    }
}
