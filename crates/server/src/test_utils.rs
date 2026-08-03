/// Test utilities for mocking `DPoP` verification
#[cfg(test)]
pub mod mock_dpop {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ffi::DpopVerification;
    use serde::de::{self, IgnoredAny, MapAccess, Visitor};
    use serde::{Deserialize, Deserializer};
    use std::collections::HashSet;

    /// Mock implementation with a configurable `iat` acceptance window.
    pub fn verify_dpop_with_iat_window(
        proof: &str,
        method: &str,
        uri: &str,
        now: u64,
        expected_ath: Option<&str>,
        iat_window_secs: u64,
    ) -> Option<DpopVerification> {
        struct Claims {
            htm: String,
            htu: String,
            iat: i64,
            jti: String,
            ath: Option<String>,
            nonce: Option<String>,
        }

        impl<'de> Deserialize<'de> for Claims {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct ClaimsVisitor;

                impl<'de> Visitor<'de> for ClaimsVisitor {
                    type Value = Claims;

                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str("a DPoP claims object")
                    }

                    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
                    where
                        M: MapAccess<'de>,
                    {
                        let mut seen = HashSet::new();
                        let mut htm = None;
                        let mut htu = None;
                        let mut iat = None;
                        let mut jti = None;
                        let mut ath = None;
                        let mut nonce = None;

                        while let Some(key) = map.next_key::<String>()? {
                            if !seen.insert(key.clone()) {
                                return Err(de::Error::custom("duplicate DPoP claim"));
                            }
                            match key.as_str() {
                                "htm" => htm = Some(map.next_value()?),
                                "htu" => htu = Some(map.next_value()?),
                                "iat" => iat = Some(map.next_value()?),
                                "jti" => jti = Some(map.next_value()?),
                                "ath" => ath = Some(map.next_value()?),
                                "nonce" => nonce = Some(map.next_value()?),
                                _ => {
                                    let _: IgnoredAny = map.next_value()?;
                                }
                            }
                        }

                        Ok(Claims {
                            htm: htm.ok_or_else(|| de::Error::missing_field("htm"))?,
                            htu: htu.ok_or_else(|| de::Error::missing_field("htu"))?,
                            iat: iat.ok_or_else(|| de::Error::missing_field("iat"))?,
                            jti: jti.ok_or_else(|| de::Error::missing_field("jti"))?,
                            ath: ath.flatten(),
                            nonce: nonce.flatten(),
                        })
                    }
                }

                deserializer.deserialize_map(ClaimsVisitor)
            }
        }

        let parts: Vec<&str> = proof.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
        let claims: Claims = serde_json::from_slice(&payload_bytes).ok()?;

        if claims.htm != method {
            return None;
        }

        // RFC 9449: htu claim MUST NOT include query or fragment parts.
        if claims.htu.contains('?') || claims.htu.contains('#') {
            return None;
        }

        // RFC 9449 Section 4.3: compare htu ignoring query/fragment parts of the request URI.
        let expected_htu = strip_query_and_fragment(uri);
        if claims.htu != expected_htu {
            return None;
        }

        if claims.iat < 0 {
            return None;
        }
        let iat = claims.iat.cast_unsigned();
        let diff = now.abs_diff(iat);
        if diff > iat_window_secs {
            return None;
        }

        match (claims.ath.as_deref(), expected_ath) {
            (Some(claim), Some(expected)) if claim == expected => {}
            (Some(_) | None, Some(_)) | (Some(_), None) => return None,
            (None, None) => {}
        }

        Some(DpopVerification {
            jti: claims.jti,
            nonce: claims.nonce,
        })
    }

    fn strip_query_and_fragment(uri: &str) -> &str {
        let query_idx = uri.find('?');
        let fragment_idx = uri.find('#');
        let cut = match (query_idx, fragment_idx) {
            (Some(q), Some(f)) => q.min(f),
            (Some(q), None) => q,
            (None, Some(f)) => f,
            (None, None) => return uri,
        };
        &uri[..cut]
    }
}

pub mod env_inventory {
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum EnvAuthority {
        SystemBootstrap,
        SharedRuntimeStore,
        RemovedSystemBootstrap,
        RemovedRuntimePolicy,
    }

    impl EnvAuthority {
        pub const fn is_allowed_with_management_database(self) -> bool {
            matches!(self, Self::SystemBootstrap | Self::SharedRuntimeStore)
        }
    }

    pub fn inventory_map(
        inventory: &[(&'static str, EnvAuthority)],
    ) -> BTreeMap<&'static str, EnvAuthority> {
        inventory.iter().copied().collect()
    }

    pub fn keys_with_authority(
        inventory: &[(&'static str, EnvAuthority)],
        authority: EnvAuthority,
    ) -> BTreeSet<&'static str> {
        inventory
            .iter()
            .filter_map(|(key, candidate)| (*candidate == authority).then_some(*key))
            .collect()
    }

    pub fn env_literals_excluding(
        source: &'static str,
        ignored_prefixes: &[&str],
        ignored_exact: &[&str],
    ) -> BTreeSet<&'static str> {
        env_literals(source)
            .into_iter()
            .filter(|value| {
                !ignored_exact.contains(value)
                    && !ignored_prefixes
                        .iter()
                        .any(|prefix| value.starts_with(prefix))
            })
            .collect()
    }

    pub fn assert_env_inventory_complete(
        source: &'static str,
        inventory: &[(&'static str, EnvAuthority)],
        ignored_prefixes: &[&str],
        ignored_exact: &[&str],
    ) {
        assert_env_inventory_complete_for_sources(
            &[source],
            inventory,
            ignored_prefixes,
            ignored_exact,
        );
    }

    pub fn assert_env_inventory_complete_for_sources(
        sources: &[&'static str],
        inventory: &[(&'static str, EnvAuthority)],
        ignored_prefixes: &[&str],
        ignored_exact: &[&str],
    ) {
        let actual = sources
            .iter()
            .flat_map(|source| env_literals_excluding(source, ignored_prefixes, ignored_exact))
            .collect::<BTreeSet<_>>();
        let expected = inventory
            .iter()
            .map(|(key, _)| *key)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "environment variable literals must be reviewed in the module env inventory"
        );
    }

    fn env_literals(source: &'static str) -> BTreeSet<&'static str> {
        let mut literals = BTreeSet::new();
        let mut index = 0usize;
        let bytes = source.as_bytes();
        while index < bytes.len() {
            if bytes[index] != b'"' {
                index += 1;
                continue;
            }

            let start = index + 1;
            index = start;
            let mut escaped = false;
            while index < bytes.len() {
                match (bytes[index], escaped) {
                    (_, true) => {
                        escaped = false;
                        index += 1;
                    }
                    (b'\\', false) => {
                        escaped = true;
                        index += 1;
                    }
                    (b'"', false) => {
                        if let Some(literal) = source.get(start..index) {
                            if is_env_literal(literal) {
                                literals.insert(literal);
                            }
                        }
                        index += 1;
                        break;
                    }
                    _ => index += 1,
                }
            }
        }
        literals
    }

    fn is_env_literal(value: &str) -> bool {
        let has_env_prefix = value == "AWS_REGION"
            || value == "BASE_URL"
            || value == "DATABASE_URL"
            || value.starts_with("AEGAEON_");
        has_env_prefix
            && !value.is_empty()
            && value.chars().all(|ch| {
                ch.is_ascii_uppercase()
                    || ch.is_ascii_digit()
                    || ch == '_'
                    || ch == '{'
                    || ch == '}'
                    || ch.is_ascii_lowercase()
            })
    }
}
