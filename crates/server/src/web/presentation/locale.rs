//! UI locale selection for hosted end-user pages.
//!
//! The effective OIDC `ui_locales` value is consulted first, then the
//! browser's `Accept-Language`, then the Environment default. Each source is a
//! preference list; the first entry that a bundled catalog supports wins.
//! Matching follows RFC 4647 section 3.4 lookup, so `ja-JP` selects the `ja`
//! catalog. Unsupported, malformed and zero-weight entries fall through.

/// A language with a complete bundled message catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Locale {
    En,
    Ja,
}

impl Locale {
    /// Supported catalogs in the order `ui_locales_supported` advertises them.
    pub(crate) const SUPPORTED: [Self; 2] = [Self::En, Self::Ja];

    /// The BCP 47 tag used for `lang`, `ui_locales_supported` and storage.
    pub(crate) const fn tag(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ja => "ja",
        }
    }

    /// Parse an exact supported tag, ignoring ASCII case.
    pub(crate) fn from_tag(tag: &str) -> Option<Self> {
        Self::SUPPORTED
            .into_iter()
            .find(|locale| locale.tag().eq_ignore_ascii_case(tag))
    }

    /// RFC 4647 lookup: progressively truncate the range until a supported
    /// tag remains. Single-character subtags are removed with the subtag that
    /// follows them, and `*` never matches.
    fn lookup(range: &str) -> Option<Self> {
        if !well_formed_range(range) {
            return None;
        }
        let mut candidate = range;
        loop {
            if let Some(locale) = Self::from_tag(candidate) {
                return Some(locale);
            }
            let (prefix, _) = candidate.rsplit_once('-')?;
            candidate = prefix;
            if let Some((shorter, last)) = candidate.rsplit_once('-') {
                if last.len() == 1 {
                    candidate = shorter;
                }
            }
        }
    }
}

/// Upper bounds keep negotiation linear in a small, fixed amount of input.
const MAX_PREFERENCES: usize = 32;
const MAX_HEADER_BYTES: usize = 1024;

/// A language range: ASCII letters/digits in `-`-separated subtags of 1..=8,
/// the first alphabetic. Wildcards are not language preferences here.
fn well_formed_range(range: &str) -> bool {
    let mut subtags = range.split('-');
    let primary_ok = subtags.next().is_some_and(|primary| {
        (1..=8).contains(&primary.len()) && primary.bytes().all(|b| b.is_ascii_alphabetic())
    });
    primary_ok
        && subtags.all(|subtag| {
            (1..=8).contains(&subtag.len()) && subtag.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

/// OIDC `ui_locales`: space-separated BCP 47 tags in preference order.
fn from_ui_locales(value: &str) -> Option<Locale> {
    value
        .split(' ')
        .filter(|tag| !tag.is_empty())
        .take(MAX_PREFERENCES)
        .find_map(Locale::lookup)
}

/// Parse an HTTP quality value (RFC 9110 section 12.4.2) as thousandths.
fn quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let thousandths = fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(3)
        .fold(0_u16, |total, digit| total * 10 + u16::from(digit - b'0'));
    match whole {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}

/// `Accept-Language` (RFC 9110 section 12.5.4), ordered by descending weight
/// and then by position. Entries with `q=0` or malformed parameters are not
/// preferences.
fn from_accept_language(value: &str) -> Option<Locale> {
    if value.len() > MAX_HEADER_BYTES {
        return None;
    }
    let mut ranges: Vec<(u16, usize, &str)> = Vec::new();
    for (position, entry) in value.split(',').take(MAX_PREFERENCES).enumerate() {
        let mut parts = entry.split(';').map(str::trim);
        let Some(range) = parts.next().filter(|range| !range.is_empty()) else {
            continue;
        };
        let mut weight = Some(1000);
        for parameter in parts {
            weight = match parameter.split_once('=') {
                Some((name, value)) if name.trim().eq_ignore_ascii_case("q") => {
                    weight.and(quality(value.trim()))
                }
                _ => None,
            };
        }
        if let Some(weight) = weight.filter(|weight| *weight > 0) {
            ranges.push((weight, position, range));
        }
    }
    ranges.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    ranges
        .into_iter()
        .find_map(|(_, _, range)| Locale::lookup(range))
}

/// Select the page locale. `ui_locales` is the effective OIDC parameter, if
/// any; `accept_language` is the raw request header, if present and ASCII.
pub(crate) fn negotiate(
    ui_locales: Option<&str>,
    accept_language: Option<&str>,
    default: Locale,
) -> Locale {
    ui_locales
        .and_then(from_ui_locales)
        .or_else(|| accept_language.and_then(from_accept_language))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_locales_precede_accept_language_and_default() {
        assert_eq!(negotiate(Some("ja"), Some("en"), Locale::En), Locale::Ja);
        assert_eq!(negotiate(Some("fr de"), Some("ja"), Locale::En), Locale::Ja);
        assert_eq!(negotiate(Some("fr"), Some("de"), Locale::Ja), Locale::Ja);
        assert_eq!(negotiate(None, None, Locale::Ja), Locale::Ja);
        assert_eq!(negotiate(Some(""), Some(""), Locale::En), Locale::En);
    }

    #[test]
    fn preference_order_and_regional_lookup() {
        assert_eq!(negotiate(Some("ja-JP en"), None, Locale::En), Locale::Ja);
        assert_eq!(
            negotiate(Some("fr-CA en-GB ja"), None, Locale::Ja),
            Locale::En
        );
        assert_eq!(
            negotiate(Some("ja-Jpan-JP-x-private"), None, Locale::En),
            Locale::Ja
        );
        assert_eq!(negotiate(Some("JA-jp"), None, Locale::En), Locale::Ja);
        // A singleton is removed with its following subtag during lookup.
        assert_eq!(Locale::lookup("en-a-bbb-x-a"), Some(Locale::En));
        assert_eq!(Locale::lookup("jav"), None);
    }

    #[test]
    fn accept_language_honors_quality_weights_and_position() {
        assert_eq!(from_accept_language("en;q=0.5, ja"), Some(Locale::Ja));
        assert_eq!(from_accept_language("ja;q=0.8, en;q=0.8"), Some(Locale::Ja));
        assert_eq!(
            from_accept_language("fr, ja-JP;q=0.9, en;q=0.1"),
            Some(Locale::Ja)
        );
        assert_eq!(from_accept_language("ja;q=0, en;q=0.001"), Some(Locale::En));
        assert_eq!(from_accept_language("ja;Q=1.000 , en"), Some(Locale::Ja));
        assert_eq!(from_accept_language("*, ja;q=0.1"), Some(Locale::Ja));
    }

    #[test]
    fn malformed_and_unsupported_preferences_fall_through() {
        for header in [
            "ja;q=1.5",
            "ja;q=0.1234",
            "ja;q=",
            "ja;q=abc",
            "ja;level=1",
            "ja_JP",
            "-ja",
            "ja--JP",
            "123",
            "ja-toolongsubtag",
            "*",
            "fr, de;q=0.5",
        ] {
            assert_eq!(from_accept_language(header), None, "{header}");
            assert_eq!(negotiate(None, Some(header), Locale::En), Locale::En);
        }
        assert_eq!(
            negotiate(Some("ja\u{3000}JP"), None, Locale::En),
            Locale::En
        );
        assert_eq!(negotiate(Some("*"), None, Locale::En), Locale::En);
    }

    #[test]
    fn oversized_or_long_inputs_are_bounded() {
        let long = format!("{}ja", "fr, ".repeat(300));
        assert_eq!(from_accept_language(&long), None);
        let many = format!("{}ja", "fr ".repeat(MAX_PREFERENCES));
        assert_eq!(from_ui_locales(&many), None);
    }

    #[test]
    fn supported_tags_round_trip() {
        for locale in Locale::SUPPORTED {
            assert_eq!(Locale::from_tag(locale.tag()), Some(locale));
        }
        assert_eq!(Locale::from_tag("ja-JP"), None);
    }
}
