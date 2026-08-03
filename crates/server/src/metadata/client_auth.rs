use aegaeon_jose::algorithms::{Algorithm, CryptoProfile};

pub(crate) fn alg_allowed_with_promoted_rsa(name: &str, crypto_profile: CryptoProfile) -> bool {
    if matches!(name, "RS256" | "PS256") {
        return true;
    }
    // Client-auth and request-object surfaces dispatch non-promoted
    // algorithms to the compat backend, so advertisement mirrors that admission.
    Algorithm::from_string(name).is_ok_and(|alg| crypto_profile.allows_on_compat_dispatch(&alg))
}

pub(crate) fn advertised_client_auth_methods(include_private_key_jwt: bool) -> Vec<String> {
    let mut methods = vec![
        "client_secret_basic".to_string(),
        "client_secret_post".to_string(),
    ];
    if include_private_key_jwt {
        methods.push("private_key_jwt".to_string());
    }
    methods
}
