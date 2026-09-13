//! OIDC Core 3.1.2.1: one interpretation of the space-delimited prompt values.

use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(transparent)]
pub(super) struct Prompt(String);

impl Prompt {
    pub(super) fn parse(raw: String) -> Result<Self, &'static str> {
        // Do not treat tabs, line breaks or Unicode whitespace as separators.
        // They must not make consent and authentication interpret different lists.
        if !raw
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
        {
            return Err("prompt must contain ASCII values separated by spaces");
        }
        let prompt = Self(raw);
        for value in prompt.0.split(' ').filter(|value| !value.is_empty()) {
            // No account selector is implemented. Reject select_account rather
            // than silently reusing a session without the requested choice.
            if !matches!(value, "none" | "login" | "consent") {
                return Err("unsupported prompt value");
            }
            if value != "none" && prompt.contains("none") {
                return Err("prompt=none cannot be combined with other prompt values");
            }
        }
        Ok(prompt)
    }

    pub(super) fn contains(&self, value: &str) -> bool {
        self.0.split(' ').any(|part| part == value)
    }
}

impl std::fmt::Display for Prompt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::Prompt;

    #[test]
    fn prompt_preserves_space_delimited_actions() -> Result<(), &'static str> {
        for raw in ["login consent", " login  consent ", "consent login"] {
            let prompt = Prompt::parse(raw.into())?;
            assert!(prompt.contains("login"));
            assert!(prompt.contains("consent"));
            assert!(!prompt.contains("none"));
        }
        assert!(Prompt::parse("none".into())?.contains("none"));
        assert!(!Prompt::parse(String::new())?.contains("consent"));
        Ok(())
    }

    #[test]
    fn prompt_rejects_conflicts_and_alternative_separators() {
        for raw in [
            "none consent",
            "login none",
            "none select_account",
            "login\tconsent",
            "none\nconsent",
            "login\rconsent",
            "none\u{00a0}consent",
            "consent\0",
            "Consent",
            "unknown",
            "login,consent",
        ] {
            assert!(Prompt::parse(raw.into()).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn prompt_rejects_unsupported_account_selection() {
        for raw in [
            "select_account",
            "login select_account",
            "select_account consent",
        ] {
            assert_eq!(
                Prompt::parse(raw.into()).err(),
                Some("unsupported prompt value")
            );
        }
    }
}
