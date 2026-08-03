#![forbid(unsafe_code)]
#![no_main]

use ffi::dcr::{self, SenderMethod, SenderMethodsMask, TokenMethodTag};
use ffi::dcr_parser;
use ffi::jose_header;
use libfuzzer_sys::fuzz_target;

fn push_bytes_from_input(out: &mut Vec<u8>, data: &[u8], cursor: &mut usize, len: usize) {
    if data.is_empty() {
        return;
    }
    for _ in 0..len {
        out.push(data[*cursor % data.len()]);
        *cursor += 1;
    }
}

fn bool_from_byte(byte: u8, bit: u8) -> bool {
    ((byte >> bit) & 1) == 1
}

fuzz_target!(|data: &[u8]| {
    // Keep execution bounded under libFuzzer.
    if data.len() > 16 * 1024 {
        return;
    }

    let selector = data.first().copied().unwrap_or(0);
    match selector % 3 {
        // EverParse: JOSE header entry micro-language.
        0 => {
            if data.is_empty() {
                return;
            }

            let mut cursor = 1usize;
            let key_len = data.get(cursor).copied().unwrap_or(0) as usize % 32;
            cursor += 1;
            let value_len = data.get(cursor).copied().unwrap_or(0) as usize % 128;
            cursor += 1;

            let mut buf = Vec::with_capacity(4 + key_len + 4 + value_len);
            buf.extend_from_slice(&(key_len as u32).to_le_bytes());
            push_bytes_from_input(&mut buf, data, &mut cursor, key_len);
            buf.extend_from_slice(&(value_len as u32).to_le_bytes());
            push_bytes_from_input(&mut buf, data, &mut cursor, value_len);

            let _ = jose_header::check_jose_header_entry(&buf);
        }

        // EverParse: DCR binary schemas (defense-in-depth self-check).
        1 => {
            let _ = dcr_parser::check_registration_request(data);
            let _ = dcr_parser::check_registration_response(data);
            let _ = dcr_parser::check_update_request(data);
            let _ = dcr_parser::check_error_response(data);
        }

        // Low*: DCR policy enforcement helper (token/sender posture).
        _ => {
            let flags0 = *data.get(1).unwrap_or(&0);
            let flags1 = *data.get(2).unwrap_or(&0);
            let flags2 = *data.get(3).unwrap_or(&0);

            let token_method = match selector % 7 {
                0 => TokenMethodTag::None,
                1 => TokenMethodTag::ClientSecretBasic,
                2 => TokenMethodTag::ClientSecretPost,
                3 => TokenMethodTag::PrivateKeyJwt,
                4 => TokenMethodTag::TlsClientAuth,
                5 => TokenMethodTag::SelfSignedTls,
                _ => TokenMethodTag::Other,
            };

            let pkce_declared = bool_from_byte(flags0, 0);
            let pkce_value = bool_from_byte(flags0, 1);
            let sender_flag_declared = bool_from_byte(flags0, 2);
            let sender_flag_value = bool_from_byte(flags0, 3);
            let sender_methods_declared = bool_from_byte(flags0, 4);

            let mut sender_methods_mask = SenderMethodsMask::empty();
            if bool_from_byte(flags1, 0) {
                sender_methods_mask = sender_methods_mask.with(SenderMethod::Dpop);
            }
            if bool_from_byte(flags1, 1) {
                sender_methods_mask = sender_methods_mask.with(SenderMethod::Mtls);
            }

            let require_pkce_public = bool_from_byte(flags2, 0);
            let require_pkce_confidential = bool_from_byte(flags2, 1);
            let require_sender = bool_from_byte(flags2, 2);

            let mut allowed_sender_mask = SenderMethodsMask::empty();
            if bool_from_byte(flags1, 2) {
                allowed_sender_mask = allowed_sender_mask.with(SenderMethod::Dpop);
            }
            if bool_from_byte(flags1, 3) {
                allowed_sender_mask = allowed_sender_mask.with(SenderMethod::Mtls);
            }

            let _ = dcr::validate_metadata(
                token_method,
                pkce_declared,
                pkce_value,
                sender_flag_declared,
                sender_flag_value,
                sender_methods_declared,
                sender_methods_mask,
                require_pkce_public,
                require_pkce_confidential,
                require_sender,
                allowed_sender_mask,
            );
        }
    }
});
