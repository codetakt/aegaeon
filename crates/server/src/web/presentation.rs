//! Shared document shell for Aegaeon-hosted end-user pages.
//!
//! Sign-in, consent, organization selection, sign-out, browser continuation
//! and hosted invitation pages render through one shell so that the recipient
//! sees the same identity, typography, controls, focus and error styles across
//! a journey. The stylesheet and brand mark are compiled into the server; the
//! document requests no external assets. Callers keep their route's own
//! security headers and supply only trusted template HTML for the main region.

const STYLE: &str = include_str!("presentation/page.css");
// The repository's canonical mark; inline SVG is markup, not an image fetch.
const MARK: &str = include_str!("../../../../assets/brand/aegaeon-mark.svg");
const BRAND_NAME: &str = "Aegaeon";

/// Escape text for HTML element content and quoted attribute values.
pub(in crate::web) fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// A complete hosted page. `main` and `after_main` are trusted template HTML.
pub(in crate::web) struct Page<'a> {
    /// Plain-text document title; escaped when rendered.
    pub(in crate::web) title: &'a str,
    /// Main region, normally starting with the `h1` naming the action.
    pub(in crate::web) main: &'a str,
    /// Nonce for routes whose CSP does not permit inline styles.
    pub(in crate::web) style_nonce: Option<&'a str>,
    /// Trusted markup after the main region, such as a nonce-bound script.
    pub(in crate::web) after_main: &'a str,
    /// Document referrer policy for pages whose own requests must not leak
    /// the URL. Form pages relying on a same-origin `Origin` leave it unset.
    pub(in crate::web) referrer: Option<&'static str>,
}

impl<'a> Page<'a> {
    pub(in crate::web) const fn new(title: &'a str, main: &'a str) -> Self {
        Self {
            title,
            main,
            style_nonce: None,
            after_main: "",
            referrer: None,
        }
    }

    pub(in crate::web) fn render(&self) -> String {
        let referrer = self.referrer.map_or_else(String::new, |policy| {
            format!("<meta name=\"referrer\" content=\"{}\">\n", escape(policy))
        });
        let nonce = self.style_nonce.map_or_else(String::new, |nonce| {
            format!(r#" nonce="{}""#, escape(nonce))
        });
        format!(
            r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
{referrer}<title>{title}</title>
<link rel="icon" href="data:,">
<style{nonce}>{STYLE}</style>
</head>
<body>
<div class="page">
<header class="brand">{mark}<span class="brand-name">{BRAND_NAME}</span></header>
<main class="card">
{main}
</main>
</div>
{after_main}
</body>
</html>"#,
            title = escape(self.title),
            mark = mark(),
            main = self.main,
            after_main = self.after_main,
        )
    }
}

fn mark() -> String {
    // The header names the brand in text, so the symbol is decorative.
    MARK.trim().replacen(
        "<svg ",
        r#"<svg class="brand-mark" aria-hidden="true" focusable="false" "#,
        1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_covers_text_and_attribute_delimiters() {
        assert_eq!(
            escape(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
        assert_eq!(escape("日本語 ok"), "日本語 ok");
    }

    #[test]
    fn page_is_self_contained_and_shows_the_built_in_identity() {
        let html = Page::new("Sign <in>", "<h1>Sign in</h1>").render();
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains(r#"<html lang="en">"#));
        assert!(html.contains("<title>Sign &lt;in&gt;</title>"));
        assert!(html.contains(
            r#"<svg class="brand-mark" aria-hidden="true" focusable="false" viewBox="0 0 33 33""#
        ));
        assert!(html.contains(r#"<span class="brand-name">Aegaeon</span>"#));
        assert!(html.contains("<main class=\"card\">\n<h1>Sign in</h1>\n</main>"));
        assert!(html.contains("<style>"));
        assert!(!html.contains("name=\"referrer\""));
        // No document-level fetches: no external stylesheet, script, image or font.
        // The SVG namespace URI is an identifier, not a fetch.
        for reference in [
            "src=",
            "url(",
            "@import",
            "@font-face",
            "https://",
            "stylesheet",
        ] {
            assert!(!html.contains(reference), "{reference}");
        }
        assert!(html.contains(r#"<link rel="icon" href="data:,">"#));
    }

    #[test]
    fn style_nonce_is_bound_to_the_inline_stylesheet() {
        let mut page = Page::new("Continue", "<h1>Continue</h1>");
        page.style_nonce = Some("abc_-");
        page.after_main = "<script nonce=\"abc_-\"></script>";
        page.referrer = Some("no-referrer");
        let html = page.render();
        assert!(html.contains("<meta name=\"referrer\" content=\"no-referrer\">\n<title>"));
        assert!(html.contains(r#"<style nonce="abc_-">"#));
        assert!(html.contains("</main>\n</div>\n<script nonce=\"abc_-\"></script>\n</body>"));
    }

    #[test]
    fn canonical_mark_is_inline_svg_without_external_references() {
        assert!(MARK.trim_start().starts_with("<svg viewBox=\"0 0 33 33\""));
        for forbidden in ["href", "<script", "<image", "<style", "url("] {
            assert!(!MARK.contains(forbidden), "{forbidden}");
        }
    }
}
