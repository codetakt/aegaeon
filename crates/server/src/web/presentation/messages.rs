//! Bundled English and Japanese message catalogs for hosted pages.
//!
//! Each catalog is a `Messages` value, so the compiler rejects a catalog that
//! omits a message ID. A constant assertion compares the `{placeholder}` names
//! of every message across catalogs, so a translation that drops, renames or
//! adds a placeholder fails the build. Templates are plain text: rendering
//! escapes them, and callers supply placeholder values as HTML they have
//! already escaped.

use super::{escape, locale::Locale};

mod en;
mod ja;

macro_rules! catalog {
    ($($id:ident),* $(,)?) => {
        /// One catalog. Every field is a plain-text template.
        pub(crate) struct Messages {
            $(pub(crate) $id: &'static str,)*
        }

        /// Whether every message has the same placeholder names in both.
        const fn consistent(a: &Messages, b: &Messages) -> bool {
            true $(&& same_placeholders(a.$id, b.$id))*
        }

        #[cfg(test)]
        fn templates(messages: &Messages) -> Vec<(&'static str, &'static str)> {
            vec![$((stringify!($id), messages.$id),)*]
        }
    };
}

catalog! {
    attribution,
    sign_in_heading,
    sign_in_intro,
    identifier_label,
    password_label,
    sign_in_submit,
    activate_account,
    reset_password,
    password_form_intro,
    one_time_token_label,
    new_password_label,
    confirm_password_label,
    password_rule,
    continue_link,
    consent_heading,
    application_label,
    resource_label,
    permissions_label,
    offline_notice,
    organization_access_heading,
    administrative_access_notice,
    organization_scope_notice,
    invitation_access_heading,
    signed_in_account_label,
    account_subject_label,
    invitation_access_notice,
    allow_access,
    deny_access,
    select_organization_heading,
    select_organization_intro,
    no_eligible_organizations,
    next_page,
    cancel,
    sign_out_heading,
    signed_in_as,
    no_active_sign_in,
    sign_out_requested,
    confirm_sign_out,
    sign_out_cancelled_heading,
    sign_out_cancelled,
    signed_out_heading,
    signed_out,
    continue_heading,
    unable_to_continue_heading,
    unable_to_continue,
    identity_heading,
    identity_intro,
    request_proof_heading,
    purpose_label,
    create_account_option,
    reset_password_option,
    invitation_code_label,
    login_identifier_label,
    send_proof,
    complete_request_heading,
    request_id_label,
    address_proof_label,
    save_credentials,
    invitation_heading,
    opening_invitation,
    enable_javascript,
}

const _: () = assert!(consistent(&en::MESSAGES, &ja::MESSAGES));

impl Locale {
    pub(crate) const fn messages(self) -> &'static Messages {
        match self {
            Self::En => &en::MESSAGES,
            Self::Ja => &ja::MESSAGES,
        }
    }
}

/// Find `needle` in `haystack` at or after `from`.
const fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let mut start = from;
    while start + needle.len() <= haystack.len() {
        let mut offset = 0;
        while offset < needle.len() && haystack[start + offset] == needle[offset] {
            offset += 1;
        }
        if offset == needle.len() {
            return Some(start);
        }
        start += 1;
    }
    None
}

/// Whether `bytes[start..end]` occurs in `other` as a `{name}` placeholder.
const fn has_placeholder(other: &[u8], bytes: &[u8], start: usize, end: usize) -> bool {
    let mut position = 0;
    while let Some(open) = find(other, b"{", position) {
        let mut offset = 0;
        while start + offset < end
            && open + 1 + offset < other.len()
            && other[open + 1 + offset] == bytes[start + offset]
        {
            offset += 1;
        }
        if start + offset == end
            && open + 1 + offset < other.len()
            && other[open + 1 + offset] == b'}'
        {
            return true;
        }
        position = open + 1;
    }
    false
}

/// Every placeholder of `a` is well formed (`{` ASCII name `}`) and occurs in
/// `b`. Braces are reserved for placeholders.
const fn placeholders_within(a: &[u8], b: &[u8]) -> bool {
    let mut index = 0;
    while index < a.len() {
        if a[index] == b'}' {
            return false;
        }
        if a[index] == b'{' {
            let start = index + 1;
            let mut end = start;
            while end < a.len() && (a[end].is_ascii_lowercase() || a[end] == b'_') {
                end += 1;
            }
            if end == start
                || end == a.len()
                || a[end] != b'}'
                || !has_placeholder(b, a, start, end)
            {
                return false;
            }
            index = end;
        }
        index += 1;
    }
    true
}

const fn same_placeholders(a: &str, b: &str) -> bool {
    placeholders_within(a.as_bytes(), b.as_bytes())
        && placeholders_within(b.as_bytes(), a.as_bytes())
}

/// Render a template as HTML: escape its text and substitute each
/// `{name}` with the matching pre-escaped HTML value.
///
/// # Panics
///
/// In debug builds, when a placeholder has no value.
pub(crate) fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut html = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        html.push_str(&escape(&rest[..open]));
        let after = &rest[open + 1..];
        let close = after.find('}').unwrap_or(after.len());
        let name = &after[..close];
        let value = values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value);
        debug_assert!(value.is_some(), "missing placeholder {name}");
        html.push_str(value.unwrap_or_default());
        rest = after.get(close + 1..).unwrap_or_default();
    }
    html.push_str(&escape(rest));
    html
}

/// Render a template without placeholders as HTML text.
pub(crate) fn text(template: &str) -> String {
    debug_assert!(!template.contains('{'), "template has placeholders");
    escape(template)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_check_detects_missing_renamed_added_and_malformed_names() {
        assert!(same_placeholders("Hi {name}.", "こんにちは、{name}。"));
        assert!(same_placeholders("{a} then {b}", "{b} の前に {a}"));
        assert!(same_placeholders("{a} {a}", "{a}"));
        assert!(!same_placeholders("Hi {name}.", "こんにちは。"));
        assert!(!same_placeholders("Hi {name}.", "Hi {user}."));
        assert!(!same_placeholders("Hi {name}.", "Hi {name} {extra}."));
        assert!(!same_placeholders("Hi {unclosed", "Hi {unclosed"));
        assert!(!same_placeholders("Hi {Name}", "Hi {Name}"));
        assert!(!same_placeholders("a } b", "a } b"));
        assert!(!same_placeholders("{}", "{}"));
    }

    #[test]
    fn catalogs_are_complete_nonempty_and_consistent() {
        let english = templates(&en::MESSAGES);
        let japanese = templates(&ja::MESSAGES);
        assert_eq!(english.len(), japanese.len());
        for ((id, en), (_, ja)) in english.into_iter().zip(japanese) {
            assert!(!en.trim().is_empty() && !ja.trim().is_empty(), "{id}");
            assert_eq!(en.trim(), en, "{id}");
            assert_eq!(ja.trim(), ja, "{id}");
            assert!(same_placeholders(en, ja), "{id}");
            assert!(
                !en.contains('<') && !ja.contains('<'),
                "{id} must be plain text"
            );
        }
    }

    #[test]
    fn japanese_catalog_is_translated() {
        // Brand and identifier-like messages may coincide; everything else
        // must differ from English.
        let same: Vec<_> = templates(&en::MESSAGES)
            .into_iter()
            .zip(templates(&ja::MESSAGES))
            .filter(|((_, en), (_, ja))| en == ja)
            .map(|((id, _), _)| id)
            .collect();
        assert!(same.is_empty(), "{same:?}");
    }

    #[test]
    fn fill_escapes_template_text_and_inserts_escaped_values() {
        assert_eq!(
            fill("A & {who} <b>", &[("who", "<strong>x</strong>")]),
            "A &amp; <strong>x</strong> &lt;b&gt;"
        );
        assert_eq!(text("Tom & \"Jerry\""), "Tom &amp; &quot;Jerry&quot;");
    }
}
