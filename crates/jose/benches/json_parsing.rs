use aegaeon_jose::json_lowstar::parse_json_header_lowstar;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_parse_minimal_header(c: &mut Criterion) {
    let json = br#"{"alg":"HS256"}"#;

    c.bench_function("parse_minimal_header", |b| {
        b.iter(|| parse_json_header_lowstar(black_box(json)));
    });
}

fn bench_parse_typical_jws_header(c: &mut Criterion) {
    let json = br#"{"alg":"HS256","typ":"JWT"}"#;

    c.bench_function("parse_typical_jws_header", |b| {
        b.iter(|| parse_json_header_lowstar(black_box(json)));
    });
}

fn bench_parse_complex_header(c: &mut Criterion) {
    let json =
        br#"{"alg":"RS256","typ":"JWT","kid":"key-2024-01","jku":"https://example.com/jwks"}"#;

    c.bench_function("parse_complex_header", |b| {
        b.iter(|| parse_json_header_lowstar(black_box(json)));
    });
}

fn bench_parse_headers_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_by_size");

    // Small: ~30 bytes
    let small = br#"{"alg":"HS256"}"#;
    group.bench_with_input(BenchmarkId::new("small", small.len()), small, |b, json| {
        b.iter(|| parse_json_header_lowstar(black_box(json)));
    });

    // Medium: ~60 bytes
    let medium = br#"{"alg":"RS256","typ":"JWT","kid":"key-123"}"#;
    group.bench_with_input(
        BenchmarkId::new("medium", medium.len()),
        medium,
        |b, json| {
            b.iter(|| parse_json_header_lowstar(black_box(json)));
        },
    );

    // Large: ~120 bytes
    let large = br#"{"alg":"RS256","typ":"JWT","kid":"key-2024-01-very-long-identifier","jku":"https://example.com/jwks","x5u":"https://example.com/certs"}"#;
    group.bench_with_input(BenchmarkId::new("large", large.len()), large, |b, json| {
        b.iter(|| parse_json_header_lowstar(black_box(json)));
    });

    group.finish();
}

fn bench_parse_multiple_fields(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_by_field_count");

    // 1 field
    let json1 = br#"{"alg":"HS256"}"#;
    group.bench_with_input(BenchmarkId::from_parameter(1), json1, |b, json| {
        b.iter(|| parse_json_header_lowstar(black_box(json)));
    });

    // 2 fields
    let json2 = br#"{"alg":"HS256","typ":"JWT"}"#;
    group.bench_with_input(BenchmarkId::from_parameter(2), json2, |b, json| {
        b.iter(|| parse_json_header_lowstar(black_box(json)));
    });

    // 3 fields
    let json3 = br#"{"alg":"RS256","typ":"JWT","kid":"key-1"}"#;
    group.bench_with_input(BenchmarkId::from_parameter(3), json3, |b, json| {
        b.iter(|| parse_json_header_lowstar(black_box(json)));
    });

    // 5 fields
    let json5 = br#"{"alg":"RS256","typ":"JWT","kid":"key-1","jku":"https://example.com/jwks","x5u":"https://example.com/certs"}"#;
    group.bench_with_input(BenchmarkId::from_parameter(5), json5, |b, json| {
        b.iter(|| parse_json_header_lowstar(black_box(json)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_minimal_header,
    bench_parse_typical_jws_header,
    bench_parse_complex_header,
    bench_parse_headers_by_size,
    bench_parse_multiple_fields
);
criterion_main!(benches);
