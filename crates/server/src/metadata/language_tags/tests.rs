use super::*;

#[test]
fn full_form_and_pinned_validity_discriminators() {
    // RFC 5646 domain groups: form and dated validity are separate predicates.
    let cases: &[(&str, bool, bool)] = &[
        // grandfathered_all
        ("en-GB-oed", true, true),
        ("i-ami", true, true),
        ("i-bnn", true, true),
        ("i-default", true, true),
        ("i-enochian", true, true),
        ("i-hak", true, true),
        ("i-klingon", true, true),
        ("i-lux", true, true),
        ("i-mingo", true, true),
        ("i-navajo", true, true),
        ("i-pwn", true, true),
        ("i-tao", true, true),
        ("i-tay", true, true),
        ("i-tsu", true, true),
        ("sgn-BE-FR", true, true),
        ("sgn-BE-NL", true, true),
        ("sgn-CH-DE", true, true),
        ("art-lojban", true, true),
        ("cel-gaulish", true, true),
        ("no-bok", true, true),
        ("no-nyn", true, true),
        ("zh-guoyu", true, true),
        ("zh-hakka", true, true),
        ("zh-min", true, true),
        ("zh-min-nan", true, true),
        ("zh-xiang", true, true),
        // private_only
        ("x-private", true, true),
        ("X-A", true, true),
        ("x-x", true, true),
        ("x-a-a", true, true),
        // normal
        ("en", true, true),
        ("cmn", true, true),
        ("en-Latn-US", true, true),
        ("es-419", true, true),
        ("sl-rozaj-biske-1994", true, true),
        ("de-1901", true, true),
        // primary_lengths
        ("abcd", true, false),
        ("abcde", true, false),
        ("abcdefgh", true, false),
        // registered_not_same_as_iso
        ("eng", true, false),
        // private_ranges
        ("qaa-Qaaa-QM", true, true),
        ("qtz-Qabx-ZZ", true, true),
        // primary_wrong_lengths
        ("a", false, false),
        ("abcdefghi", false, false),
        // extlang
        ("zh-cmn", true, true),
        ("zh-cmn-Hans-CN", true, true),
        // extlang_reserved
        ("zh-cmn-yue", false, false),
        ("zh-cmn-yue-gan", false, false),
        // extlang_prefix
        ("en-cmn", true, false),
        // variant_boundaries
        ("en-1234", true, false),
        ("en-abcde", true, false),
        ("en-abcdefgh", true, false),
        // bad_variant_and_regions
        ("en-abcd", true, false),
        ("en-12", false, false),
        ("en-1234abcde", false, false),
        // registered_extensions
        ("en-u-ca-gregory", true, true),
        ("en-t-en-us", true, true),
        // unallocated_extensions
        ("en-a-foo", true, false),
        ("en-0-abc", true, false),
        ("en-a-foo-b-bar", true, false),
        // extension_payload_order
        ("en-a", false, false),
        ("en-a-b-foo", false, false),
        ("a-foo", false, false),
        ("en-US-Latn", false, false),
        // case_duplicate_variant
        ("de-1901-1901", false, false),
        ("sl-rozaj-ROZAJ", false, false),
        // case_duplicate_singleton
        ("en-a-foo-A-bar", false, false),
        // private_boundary
        ("en-a-foo-x-a-a", true, false),
        ("en-x-1901-1901", true, true),
        ("en-u-foo-foo", true, true),
        // long_private
        ("x-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh-abcdefgh", true, true),
        // malformed
        ("", false, false),
        ("x", false, false),
        ("en-", false, false),
        ("-en", false, false),
        ("en--US", false, false),
        ("en_US", false, false),
        ("en US", false, false),
        (" en", false, false),
        ("en\tUS", false, false),
        ("en\n", false, false),
        ("ｅｎ", false, false),
        ("en–US", false, false),
        ("en-ä", false, false),
        ("en-abcdefghi", false, false),
        // grandfathered_prefix_not_exception
        ("i-default-x-foo", false, false),
        ("en-GB-oed-extra", false, false),
    ];
    for &(tag, form, valid) in cases {
        assert_eq!(is_well_formed(tag), form, "form: {tag}");
        assert_eq!(is_valid(tag), valid, "dated validity: {tag}");
        assert_eq!(
            is_well_formed(&tag.to_ascii_uppercase()),
            form,
            "uppercase form: {tag}"
        );
        assert_eq!(
            is_valid(&tag.to_ascii_uppercase()),
            valid,
            "uppercase dated: {tag}"
        );
    }
}

#[test]
fn dated_categories_ranges_deprecations_and_extlang_prefixes() {
    for tag in [
        "iw",
        "en-BU",
        "en-ZZ",
        "qaa-Qaaa-QM",
        "qtz-Qabx-QZ",
        "en-XA",
        "en-XZ",
        "zh-yue",
        "ar-aao",
        "en-u-foo-foo",
        "en-t-aa-u-bb",
        "en-x-u-u",
    ] {
        assert!(is_valid(tag), "{tag}");
    }
    for tag in [
        "eng", "us", "abcd", "abcdefgh", "en-Qaby", "en-cmn", "en-aaa", "en-AAA", "en-abcde",
        "zh-aao", "ar-yue", "en-a-foo", "en-0-abc",
    ] {
        assert!(is_well_formed(tag), "{tag}");
        assert!(!is_valid(tag), "{tag}");
    }
}

#[test]
fn long_private_and_variant_domains_have_no_new_length_or_count_cap() {
    let private = format!("x{}", "-abcdefgh".repeat(10_000));
    assert!(is_valid(&private));
    let variants = format!("en-{}", registry::VARIANT.join("-"));
    assert!(variants.len() > 255);
    assert!(is_valid(&variants));
    assert!(!is_well_formed(&format!(
        "{variants}-{}",
        registry::VARIANT[0].to_ascii_uppercase()
    )));
    assert!(!is_well_formed(&format!("{private}-")));
}

#[test]
fn every_registered_category_and_extlang_is_retained() {
    for language in registry::LANGUAGE {
        assert!(is_valid(language), "{language}");
    }
    for script in registry::SCRIPT {
        assert!(is_valid(&format!("en-{script}")), "{script}");
    }
    for region in registry::REGION {
        assert!(is_valid(&format!("en-{region}")), "{region}");
    }
    for variant in registry::VARIANT {
        assert!(is_valid(&format!("en-{variant}")), "{variant}");
    }
    for (extlang, primary) in registry::EXTLANG {
        assert!(is_valid(&format!("{primary}-{extlang}")), "{extlang}");
    }
}
