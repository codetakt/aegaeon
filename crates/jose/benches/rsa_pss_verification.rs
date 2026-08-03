use aegaeon_jose::jws::{__encode_rsa_spki_for_tests, __verify_rsa_pss_sha256_for_tests};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[serde(rename = "testGroups")]
    groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    #[serde(rename = "publicKey")]
    public_key: PublicKey,
    tests: Vec<Test>,
}

#[derive(Deserialize)]
struct PublicKey {
    modulus: String,
    #[serde(rename = "publicExponent")]
    exponent: String,
}

#[derive(Deserialize)]
struct Test {
    msg: String,
    sig: String,
    result: String,
}

fn decode_hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).expect("valid hex vector"))
        .collect()
}

fn rsa_pss_verification(c: &mut Criterion) {
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../../tests/vectors/wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json"
    ))
    .expect("valid Wycheproof fixture");
    let group = &vectors.groups[0];
    let test = group
        .tests
        .iter()
        .find(|test| test.result == "valid")
        .expect("fixture contains a valid vector");
    let modulus = decode_hex(&group.public_key.modulus);
    let exponent = decode_hex(&group.public_key.exponent);
    let message = decode_hex(&test.msg);
    let signature = decode_hex(&test.sig);
    let spki = __encode_rsa_spki_for_tests(&modulus, &exponent).expect("valid RSA SPKI");

    let mut group = c.benchmark_group("ps256_verify_2048");
    group.bench_function("hacl_rsapss", |b| {
        b.iter(|| {
            __verify_rsa_pss_sha256_for_tests(
                black_box(&modulus),
                black_box(&exponent),
                black_box(&message),
                black_box(&signature),
            )
            .expect("valid HACL* verification")
        });
    });
    group.bench_function("aws_lc_rs", |b| {
        b.iter(|| {
            aegaeon_crypto::signature::verify_rsa_pss_sha256(
                black_box(&spki),
                black_box(&message),
                black_box(&signature),
            )
            .expect("valid aws-lc-rs verification")
        });
    });
    group.finish();
}

criterion_group!(benches, rsa_pss_verification);
criterion_main!(benches);
