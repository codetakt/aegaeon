use super::resource_urls::mapped_value;

#[test]
fn mapped_standard_claims_reject_invalid_wire_values() {
    for (name, values) in [
        (
            "email",
            vec![
                "not-an-address",
                "a..b@example.com",
                "@example.com",
                "a@",
                "a@b@c",
                "Name <a@example.com>",
                "a@example.com\r\nBcc:b@example.com",
                "a@例.example",
                "\"unclosed@example.com",
                "\"bad\\\"@example.com",
            ],
        ),
        (
            "locale",
            vec![
                "",
                "en_US",
                "en--US",
                "en-abcdefghi",
                "not a language",
                "en-u",
                "zz-ZZ",
            ],
        ),
        (
            "zoneinfo",
            vec![
                "",
                "Mars/Olympus",
                "america/new_york",
                "../UTC",
                "/usr/share/zoneinfo/UTC",
                "UTC\n",
            ],
        ),
    ] {
        for value in values {
            assert!(mapped_value(name, value).is_err(), "{name}: {value:?}");
        }
    }
}

#[test]
fn mapped_standard_claims_preserve_valid_strings_and_aliases() {
    for (name, values) in [
        (
            "email",
            vec![
                "User+tag@example.com",
                "o'connor@example.com",
                "\"Jane Doe\"@example.com",
                "\"a@b\"@example.com",
                "user@[192.0.2.1]",
                "user@[IPv6:2001:db8::1]",
                "\"quoted\\\"name\"@example.com",
            ],
        ),
        (
            "locale",
            vec![
                "en-US",
                "ja-JP",
                "zh-Hant-TW",
                "de-CH-1901",
                "en-US-u-ca-gregory",
                "i-klingon",
                "x-private",
            ],
        ),
        (
            "zoneinfo",
            vec![
                "Asia/Tokyo",
                "America/New_York",
                "Etc/UTC",
                "UTC",
                "US/Eastern",
            ],
        ),
    ] {
        for value in values {
            let mapped = mapped_value(name, value).expect("admitted standard claim");
            assert_eq!(mapped.claims[name].value, value);
        }
    }
}
