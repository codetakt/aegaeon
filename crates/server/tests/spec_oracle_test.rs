use aegaeon_server::{
    authcode::store::authorization_code_not_expired_for_spec_oracle,
    authcode::token::validate_pkce_binding_for_spec_oracle,
    middleware::dpop::{validate_dpop_ath_for_spec_oracle, validate_dpop_typ_for_spec_oracle},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ffi::{
    validate_dpop_htm_for_spec_oracle, validate_dpop_htu_for_spec_oracle,
    validate_dpop_iat_for_spec_oracle,
};
use sha2::{Digest, Sha256};

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next() as usize) % bound
    }
}

fn random_ascii_string(rng: &mut Lcg, max_len: usize, alphabet: &[u8]) -> String {
    let len = rng.next_usize(max_len + 1);
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        out.push(alphabet[rng.next_usize(alphabet.len())] as char);
    }
    out
}

fn oracle_validate_typ(t: &str) -> bool {
    t == "dpop+jwt"
}

fn oracle_validate_equal(expected: &str, actual: &str) -> bool {
    expected == actual
}

fn oracle_validate_iat(now: u64, iat: u64, window: u64) -> bool {
    now.abs_diff(iat) <= window
}

fn oracle_code_not_expired(current_time: u64, expires_at: u64) -> bool {
    current_time < expires_at
}

fn is_pkce_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn oracle_validate_code_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len()) && verifier.bytes().all(is_pkce_unreserved)
}

fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn dpop_ath_claim(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn oracle_verify_pkce(method: &str, verifier: &str, challenge: &str) -> bool {
    method == "S256"
        && oracle_validate_code_verifier(verifier)
        && challenge == s256_challenge(verifier)
}

#[test]
fn dpop_typ_matches_fstar_oracle() {
    // F* correspondence: fstar/dpop/Dpop.Header.fst, validate_typ.
    assert!(validate_dpop_typ_for_spec_oracle("dpop+jwt"));
    assert_eq!(
        validate_dpop_typ_for_spec_oracle("dpop+jwt"),
        oracle_validate_typ("dpop+jwt")
    );

    let mut reject_cases: Vec<String> = vec![
        "DPoP+JWT",
        "DPOP+JWT",
        "dpop+JWT",
        "Dpop+jwt",
        "dpop+jwt ",
        " dpop+jwt",
        "jwt",
        "",
        "dpop",
        "dpop+jw",
        "dpop+jwtt",
        "dpop+jwt.",
        "dpop-jwt",
        "dpop jwt",
        "dpop%2Bjwt",
        "application/dpop+jwt",
        "dpop+jwt;v=1",
        "dpop+jwt\n",
        "dpop+jwt\0",
        "dpop+jwt\u{00e9}",
        "\u{ff44}pop+jwt",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    reject_cases.push("dpop+jwt".repeat(64));
    assert!(reject_cases.len() >= 20);

    for candidate in reject_cases {
        assert!(
            !oracle_validate_typ(&candidate),
            "oracle accepted {candidate:?}"
        );
        assert_eq!(
            validate_dpop_typ_for_spec_oracle(&candidate),
            oracle_validate_typ(&candidate),
            "candidate {candidate:?}"
        );
    }

    let mut rng = Lcg::new(0xd909_9449_d909_9449);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-._~ %\t";
    for _ in 0..1000 {
        let candidate = random_ascii_string(&mut rng, 48, alphabet);
        assert_eq!(
            validate_dpop_typ_for_spec_oracle(&candidate),
            oracle_validate_typ(&candidate),
            "candidate {candidate:?}"
        );
    }
}

#[test]
fn dpop_htm_matches_fstar_oracle() {
    // F* correspondence: fstar/dpop/Dpop.Htm_validation.fst, validate_htm.
    assert!(validate_dpop_htm_for_spec_oracle("GET", "GET"));
    assert_eq!(
        validate_dpop_htm_for_spec_oracle("GET", "GET"),
        oracle_validate_equal("GET", "GET")
    );
    for (expected, actual) in [
        ("GET", "get"),
        ("GET", "POST"),
        ("", "GET"),
        ("GET", ""),
        ("PATCH", "PATCH "),
        ("DELETE", " DELETE"),
    ] {
        assert_eq!(
            validate_dpop_htm_for_spec_oracle(expected, actual),
            oracle_validate_equal(expected, actual),
            "expected {expected:?}, actual {actual:?}"
        );
    }

    let mut rng = Lcg::new(0x9449_0005_9449_0005);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/";
    for index in 0..1000 {
        let expected = random_ascii_string(&mut rng, 24, alphabet);
        let actual = if index % 7 == 0 {
            expected.clone()
        } else {
            random_ascii_string(&mut rng, 24, alphabet)
        };
        assert_eq!(
            validate_dpop_htm_for_spec_oracle(&expected, &actual),
            oracle_validate_equal(&expected, &actual),
            "expected {expected:?}, actual {actual:?}"
        );
    }
}

#[test]
fn dpop_htu_matches_fstar_oracle() {
    // F* correspondence: fstar/dpop/Dpop.Htu_validation.fst, validate_htu.
    assert!(validate_dpop_htu_for_spec_oracle(
        "https://example.com/resource",
        "https://example.com/resource"
    ));
    for (expected, actual) in [
        (
            "https://example.com/resource",
            "https://example.com/resource",
        ),
        (
            "https://example.com/resource",
            "https://example.com/resource?x=1",
        ),
        ("https://example.com/resource", "https://example.com/other"),
        (
            "https://example.com/resource",
            "HTTPS://example.com/resource",
        ),
        ("", ""),
        ("", "https://example.com/resource"),
    ] {
        assert_eq!(
            validate_dpop_htu_for_spec_oracle(expected, actual),
            oracle_validate_equal(expected, actual),
            "expected {expected:?}, actual {actual:?}"
        );
    }

    let mut rng = Lcg::new(0x9449_0006_9449_0006);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/:?#=&";
    for index in 0..1000 {
        let expected = random_ascii_string(&mut rng, 72, alphabet);
        let actual = if index % 7 == 0 {
            expected.clone()
        } else {
            random_ascii_string(&mut rng, 72, alphabet)
        };
        assert_eq!(
            validate_dpop_htu_for_spec_oracle(&expected, &actual),
            oracle_validate_equal(&expected, &actual),
            "expected {expected:?}, actual {actual:?}"
        );
    }
}

#[test]
fn dpop_iat_matches_fstar_oracle() {
    // F* correspondence: fstar/dpop/Dpop.Iat_validation.fst, validate_iat.
    let now = 1_700_000_000u64;
    let window = 300u64;
    for (iat, expected) in [
        (now, true),
        (now - window, true),
        (now + window, true),
        (now - window - 1, false),
        (now + window + 1, false),
        (0, false),
    ] {
        assert_eq!(oracle_validate_iat(now, iat, window), expected);
        assert_eq!(
            validate_dpop_iat_for_spec_oracle(now, iat, window),
            oracle_validate_iat(now, iat, window),
            "now {now}, iat {iat}, window {window}"
        );
    }

    let mut rng = Lcg::new(0x9449_0007_9449_0007);
    for _ in 0..1000 {
        let now = rng.next() % 10_000_000;
        let delta = rng.next() % 2_000;
        let iat = if rng.next().is_multiple_of(2) {
            now.saturating_add(delta)
        } else {
            now.saturating_sub(delta)
        };
        let window = rng.next() % 1_000;
        assert_eq!(
            validate_dpop_iat_for_spec_oracle(now, iat, window),
            oracle_validate_iat(now, iat, window),
            "now {now}, iat {iat}, window {window}"
        );
    }
}

#[test]
fn dpop_ath_matches_fstar_oracle() {
    // F* correspondence: fstar/dpop/Dpop.Ath_validation.fst, validate_ath.
    for token in ["access-token", "", "token with spaces", "nonascii-\u{00e9}"] {
        let claim = dpop_ath_claim(token);
        assert!(validate_dpop_ath_for_spec_oracle(token, &claim));
        assert_eq!(
            validate_dpop_ath_for_spec_oracle(token, &claim),
            oracle_validate_equal(&dpop_ath_claim(token), &claim),
            "token {token:?}"
        );
        let tampered = format!("{claim}A");
        assert_eq!(
            validate_dpop_ath_for_spec_oracle(token, &tampered),
            oracle_validate_equal(&dpop_ath_claim(token), &tampered),
            "tampered token {token:?}"
        );
    }

    let mut rng = Lcg::new(0x9449_0008_9449_0008);
    let token_alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~ ";
    let claim_alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for index in 0..1000 {
        let token = random_ascii_string(&mut rng, 96, token_alphabet);
        let claim = if index % 5 == 0 {
            dpop_ath_claim(&token)
        } else {
            random_ascii_string(&mut rng, 64, claim_alphabet)
        };
        assert_eq!(
            validate_dpop_ath_for_spec_oracle(&token, &claim),
            oracle_validate_equal(&dpop_ath_claim(&token), &claim),
            "token {token:?}, claim {claim:?}"
        );
    }
}

#[test]
fn authorization_code_expiry_matches_fstar_oracle() {
    // F* correspondence: fstar/authcode/AuthCode.Store.fst, code_not_expired.
    for (current_time, expires_at) in [
        (0, 1),
        (99, 100),
        (100, 100),
        (101, 100),
        (u64::MAX - 1, u64::MAX),
        (u64::MAX, u64::MAX),
    ] {
        assert_eq!(
            authorization_code_not_expired_for_spec_oracle(current_time, expires_at),
            oracle_code_not_expired(current_time, expires_at),
            "current_time {current_time}, expires_at {expires_at}"
        );
    }

    let mut rng = Lcg::new(0x6749_0005_6749_0005);
    for _ in 0..1000 {
        let current_time = rng.next();
        let expires_at = rng.next();
        assert_eq!(
            authorization_code_not_expired_for_spec_oracle(current_time, expires_at),
            oracle_code_not_expired(current_time, expires_at),
            "current_time {current_time}, expires_at {expires_at}"
        );
    }
}

#[test]
fn pkce_binding_matches_fstar_oracle() {
    // F* correspondence: fstar/pkce/Pkce.Verifier.fst
    // code_verifier_charset_ok / validate_code_verifier, and
    // fstar/pkce/Pkce.fst verify_pkce.
    let verifier_42 = "A".repeat(42);
    let verifier_43 = "A".repeat(43);
    let verifier_128 = "B".repeat(128);
    let verifier_129 = "C".repeat(129);

    for verifier in [&verifier_43, &verifier_128] {
        let challenge = s256_challenge(verifier);
        assert!(oracle_verify_pkce("S256", verifier, &challenge));
        assert_eq!(
            validate_pkce_binding_for_spec_oracle("S256", verifier, &challenge),
            oracle_verify_pkce("S256", verifier, &challenge),
            "verifier length {}",
            verifier.len()
        );
    }

    for verifier in [&verifier_42, &verifier_129] {
        let challenge = s256_challenge(verifier);
        assert!(!oracle_verify_pkce("S256", verifier, &challenge));
        assert_eq!(
            validate_pkce_binding_for_spec_oracle("S256", verifier, &challenge),
            oracle_verify_pkce("S256", verifier, &challenge),
            "verifier length {}",
            verifier.len()
        );
    }

    for verifier in [
        format!("{}+", "A".repeat(42)),
        format!("{}/", "A".repeat(42)),
        format!("{}=", "A".repeat(42)),
        format!("{} ", "A".repeat(42)),
        format!("{}\u{00e9}", "A".repeat(42)),
    ] {
        let challenge = s256_challenge(&verifier);
        assert!(!oracle_verify_pkce("S256", &verifier, &challenge));
        assert_eq!(
            validate_pkce_binding_for_spec_oracle("S256", &verifier, &challenge),
            oracle_verify_pkce("S256", &verifier, &challenge),
            "verifier {verifier:?}"
        );
    }

    let verifier = "Z".repeat(64);
    let challenge = s256_challenge(&verifier);
    assert_eq!(
        validate_pkce_binding_for_spec_oracle("plain", &verifier, &challenge),
        oracle_verify_pkce("plain", &verifier, &challenge)
    );
    assert_eq!(
        validate_pkce_binding_for_spec_oracle("S256", &verifier, &format!("{challenge}A")),
        oracle_verify_pkce("S256", &verifier, &format!("{challenge}A"))
    );

    let mut rng = Lcg::new(0x7636_7636_7636_7636);
    let verifier_alphabet =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/= \t";
    let challenge_alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let methods = ["S256", "plain", "", "s256", "S256 "];
    for index in 0..1000 {
        let verifier = random_ascii_string(&mut rng, 150, verifier_alphabet);
        let method = methods[rng.next_usize(methods.len())];
        let challenge = if index % 5 == 0 {
            s256_challenge(&verifier)
        } else {
            random_ascii_string(&mut rng, 80, challenge_alphabet)
        };
        assert_eq!(
            validate_pkce_binding_for_spec_oracle(method, &verifier, &challenge),
            oracle_verify_pkce(method, &verifier, &challenge),
            "method {method:?}, verifier {verifier:?}, challenge {challenge:?}"
        );
    }
}
