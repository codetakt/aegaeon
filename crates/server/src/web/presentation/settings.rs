//! Environment presentation settings for hosted end-user pages.
//!
//! The settings come from the active runtime configuration document and are
//! validated before use. An Environment without them shows the built-in
//! Aegaeon identity in English.

use super::locale::Locale;

/// Longest accepted service name, in Unicode scalar values.
pub(crate) const MAX_SERVICE_NAME_CHARS: usize = 64;

/// Validated presentation settings held in memory by each replica.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PresentationSettings {
    service_name: Option<String>,
    default_locale: Locale,
}

impl Default for PresentationSettings {
    fn default() -> Self {
        Self {
            service_name: None,
            default_locale: Locale::En,
        }
    }
}

/// Characters that can reorder or hide surrounding text (Unicode bidi and
/// invisible format controls). A service name must read as written.
const fn is_format_control(character: char) -> bool {
    matches!(
        character,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
    )
}

impl PresentationSettings {
    /// Validate the document's `presentation.serviceName` and
    /// `presentation.defaultLocale` values. Absent values use the defaults.
    ///
    /// # Errors
    ///
    /// Returns a message naming the invalid field.
    pub(crate) fn new(
        service_name: Option<&str>,
        default_locale: Option<&str>,
    ) -> Result<Self, &'static str> {
        if let Some(name) = service_name {
            let length = name.chars().count();
            if length == 0
                || length > MAX_SERVICE_NAME_CHARS
                || name.trim() != name
                || name.chars().any(|c| c.is_control() || is_format_control(c))
            {
                return Err("presentation.serviceName must be 1 to 64 visible characters without surrounding whitespace or control characters");
            }
        }
        let default_locale = match default_locale {
            None => Locale::En,
            Some(tag) => Locale::SUPPORTED
                .into_iter()
                .find(|locale| locale.tag() == tag)
                .ok_or("presentation.defaultLocale must be a supported UI locale")?,
        };
        Ok(Self {
            service_name: service_name.map(str::to_owned),
            default_locale,
        })
    }

    /// The operator's service name, if configured. It is plain text.
    pub(crate) fn service_name(&self) -> Option<&str> {
        self.service_name.as_deref()
    }

    pub(crate) const fn default_locale(&self) -> Locale {
        self.default_locale
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_settings_use_the_built_in_identity_and_english() {
        let settings = PresentationSettings::new(None, None).unwrap();
        assert_eq!(settings, PresentationSettings::default());
        assert_eq!(settings.service_name(), None);
        assert_eq!(settings.default_locale(), Locale::En);
    }

    #[test]
    fn accepts_a_named_japanese_deployment() {
        let settings = PresentationSettings::new(Some("サンプル学園 ID"), Some("ja")).unwrap();
        assert_eq!(settings.service_name(), Some("サンプル学園 ID"));
        assert_eq!(settings.default_locale(), Locale::Ja);
        let limit = "名".repeat(MAX_SERVICE_NAME_CHARS);
        assert!(PresentationSettings::new(Some(&limit), None).is_ok());
    }

    #[test]
    fn rejects_unsupported_default_locales() {
        for tag in ["", "fr", "ja-JP", "JA", "en-US", "*"] {
            assert!(PresentationSettings::new(None, Some(tag)).is_err(), "{tag}");
        }
    }

    #[test]
    fn rejects_empty_padded_oversized_and_control_names() {
        let oversized = "a".repeat(MAX_SERVICE_NAME_CHARS + 1);
        for name in [
            "",
            " ",
            " Example",
            "Example ",
            "Ex\tample",
            "Ex\nample",
            "Ex\u{7f}ample",
            "Example\u{202E}moc.evil",
            "Exa\u{200B}mple",
            "\u{FEFF}Example",
            oversized.as_str(),
        ] {
            assert!(
                PresentationSettings::new(Some(name), None).is_err(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn markup_is_ordinary_text() {
        let settings = PresentationSettings::new(Some("<b>Example & Co</b>"), None).unwrap();
        assert_eq!(settings.service_name(), Some("<b>Example & Co</b>"));
    }
}
