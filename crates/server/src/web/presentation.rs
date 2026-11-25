//! Shared document shell for Aegaeon-hosted end-user pages.
//!
//! Sign-in, consent, organization selection, sign-out, browser continuation
//! and hosted invitation pages render through one shell so that the recipient
//! sees the same identity, typography, controls, focus and error styles across
//! a journey. The stylesheet and brand mark are compiled into the server; the
//! document requests no external assets. Callers keep their route's own
//! security headers and supply only trusted template HTML for the main region.

const STYLE: &str = include_str!("presentation/page.css");
// A byte-identical copy of the canonical `assets/brand/aegaeon-mark.svg`, kept
// inside the crate so Cargo packages and the Docker build context include it.
// Inline SVG is markup, not an image fetch.
const MARK: &str = include_str!("presentation/aegaeon-mark.svg");
const BRAND_NAME: &str = "Aegaeon";

mod locale;
mod messages;
mod settings;

pub(crate) use locale::{negotiate, Locale};
pub(crate) use messages::{fill, text, Messages};
pub(crate) use settings::PresentationSettings;

/// The language and identity one response is rendered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Presentation<'a> {
    pub(crate) locale: Locale,
    /// The operator's service name; plain text rendered literally.
    pub(crate) service_name: Option<&'a str>,
}

#[cfg(test)]
impl Presentation<'static> {
    /// The built-in identity in English.
    pub(crate) const DEFAULT: Self = Self {
        locale: Locale::En,
        service_name: None,
    };
}

impl Presentation<'_> {
    pub(crate) const fn messages(&self) -> &'static Messages {
        self.locale.messages()
    }

    /// The name of the service the recipient is signing in to.
    pub(crate) fn service(&self) -> &str {
        self.service_name.unwrap_or(BRAND_NAME)
    }
}

impl PresentationSettings {
    /// Select the locale for one response. `ui_locales` is the effective OIDC
    /// parameter, when the flow has one; `accept_language` is the raw header.
    pub(crate) fn for_request(
        &self,
        ui_locales: Option<&str>,
        accept_language: Option<&str>,
    ) -> Presentation<'_> {
        Presentation {
            locale: negotiate(ui_locales, accept_language, self.default_locale()),
            service_name: self.service_name(),
        }
    }
}

/// Escape text for HTML element content and quoted attribute values.
pub(crate) fn escape(value: &str) -> String {
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
    /// Language and identity of the document.
    pub(in crate::web) presentation: Presentation<'a>,
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
    /// Declare an empty favicon to suppress the implicit `/favicon.ico`
    /// request. Only for routes whose CSP permits `img-src data:`; elsewhere
    /// the browser would report a CSP violation.
    pub(in crate::web) data_icon: bool,
}

impl<'a> Page<'a> {
    pub(in crate::web) const fn new(
        presentation: Presentation<'a>,
        title: &'a str,
        main: &'a str,
    ) -> Self {
        Self {
            presentation,
            title,
            main,
            style_nonce: None,
            after_main: "",
            referrer: None,
            data_icon: false,
        }
    }

    pub(in crate::web) fn render(&self) -> String {
        let referrer = self.referrer.map_or_else(String::new, |policy| {
            format!("<meta name=\"referrer\" content=\"{}\">\n", escape(policy))
        });
        let icon = if self.data_icon {
            "<link rel=\"icon\" href=\"data:,\">\n"
        } else {
            ""
        };
        let nonce = self.style_nonce.map_or_else(String::new, |nonce| {
            format!(r#" nonce="{}""#, escape(nonce))
        });
        // A configured service name is the primary identity. The Aegaeon
        // attribution then names the authentication provider, below the card.
        let (header, attribution) = match self.presentation.service_name {
            None => (
                format!(r#"{}<span class="brand-name">{BRAND_NAME}</span>"#, mark()),
                String::new(),
            ),
            Some(name) => (
                format!(r#"<span class="brand-name">{}</span>"#, escape(name)),
                format!(
                    "<footer class=\"attribution\">{}<span>{}</span></footer>\n",
                    mark(),
                    text(self.presentation.messages().attribution)
                ),
            ),
        };
        format!(
            r#"<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
{referrer}<title>{title}</title>
{icon}<style{nonce}>{STYLE}</style>
</head>
<body>
<div class="page">
<header class="brand">{header}</header>
<main class="card">
{main}
</main>
{attribution}</div>
{after_main}
</body>
</html>"#,
            lang = self.presentation.locale.tag(),
            title = escape(self.title),
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
        let html = Page::new(Presentation::DEFAULT, "Sign <in>", "<h1>Sign in</h1>").render();
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains(r#"<html lang="en">"#));
        assert!(html.contains("<title>Sign &lt;in&gt;</title>"));
        assert!(!html.contains("<footer"));
        assert!(html.contains(
            r#"<svg class="brand-mark" aria-hidden="true" focusable="false" viewBox="0 0 33 33""#
        ));
        assert!(html.contains(r#"<span class="brand-name">Aegaeon</span>"#));
        assert!(html.contains("<main class=\"card\">\n<h1>Sign in</h1>\n</main>"));
        assert!(html.contains("<style>"));
        assert!(!html.contains("name=\"referrer\""));
        // No document-level fetches: no external stylesheet, script, image or font.
        // The SVG namespace URI is an identifier, not a fetch. The default
        // shell also loads no data: URL, which `img-src 'none'` would refuse.
        for reference in [
            "src=",
            "url(",
            "@import",
            "@font-face",
            "https://",
            "stylesheet",
            "data:",
            "<link",
        ] {
            assert!(!html.contains(reference), "{reference}");
        }
    }

    #[test]
    fn named_deployment_is_primary_and_aegaeon_attribution_is_secondary() {
        let presentation = Presentation {
            locale: Locale::Ja,
            service_name: Some("<サンプル> & ID"),
        };
        let html = Page::new(presentation, "サインイン", "<h1>サインイン</h1>").render();
        assert!(html.contains(r#"<html lang="ja">"#));
        let header = html.split("<header class=\"brand\">").nth(1).unwrap();
        let header = header.split("</header>").next().unwrap();
        assert_eq!(
            header,
            r#"<span class="brand-name">&lt;サンプル&gt; &amp; ID</span>"#
        );
        let footer = html.split("<footer class=\"attribution\">").nth(1).unwrap();
        assert!(footer.starts_with("<svg class=\"brand-mark\""));
        assert!(footer.contains("<span>認証基盤: Aegaeon</span></footer>"));
        assert!(html.find("</main>") < html.find("<footer"));
    }

    #[test]
    fn request_locale_uses_the_environment_default_last() {
        let settings = PresentationSettings::new(Some("Example"), Some("ja")).unwrap();
        assert_eq!(settings.for_request(None, None).locale, Locale::Ja);
        assert_eq!(settings.for_request(None, Some("en")).locale, Locale::En);
        assert_eq!(
            settings.for_request(Some("ja"), Some("en")).locale,
            Locale::Ja
        );
        assert_eq!(settings.for_request(None, None).service(), "Example");
        assert_eq!(Presentation::DEFAULT.service(), "Aegaeon");
    }

    #[test]
    fn style_nonce_is_bound_to_the_inline_stylesheet() {
        let mut page = Page::new(Presentation::DEFAULT, "Continue", "<h1>Continue</h1>");
        page.style_nonce = Some("abc_-");
        page.after_main = "<script nonce=\"abc_-\"></script>";
        page.referrer = Some("no-referrer");
        page.data_icon = true;
        let html = page.render();
        assert!(
            html.contains("<title>Continue</title>\n<link rel=\"icon\" href=\"data:,\">\n<style")
        );
        assert!(html.contains("<meta name=\"referrer\" content=\"no-referrer\">\n<title>"));
        assert!(html.contains(r#"<style nonce="abc_-">"#));
        assert!(html.contains("</main>\n</div>\n<script nonce=\"abc_-\"></script>\n</body>"));
    }

    fn tokens(block: &str) -> std::collections::HashMap<&str, [f64; 3]> {
        block
            .split(';')
            .filter_map(|declaration| {
                let (name, value) = declaration.split_once(':')?;
                let hex = value.trim().strip_prefix('#')?;
                let hex = if hex.len() == 3 {
                    hex.chars().flat_map(|c| [c, c]).collect::<String>()
                } else {
                    hex.to_owned()
                };
                let channel = |i: usize| {
                    let c = f64::from(u8::from_str_radix(&hex[i..i + 2], 16).ok()?) / 255.0;
                    Some(if c <= 0.039_28 {
                        c / 12.92
                    } else {
                        ((c + 0.055) / 1.055).powf(2.4)
                    })
                };
                Some((name.trim(), [channel(0)?, channel(2)?, channel(4)?]))
            })
            .collect()
    }

    fn contrast(a: [f64; 3], b: [f64; 3]) -> f64 {
        let luminance = |c: [f64; 3]| 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
        let (x, y) = (luminance(a), luminance(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn text_focus_and_field_colors_meet_wcag_aa_in_both_schemes() {
        let light = STYLE
            .split(":root {")
            .nth(1)
            .unwrap()
            .split('}')
            .next()
            .unwrap();
        let dark = STYLE
            .split("@media (prefers-color-scheme: dark) {")
            .nth(1)
            .unwrap();
        let dark = dark
            .split(":root {")
            .nth(1)
            .unwrap()
            .split('}')
            .next()
            .unwrap();
        let light = tokens(light);
        let mut dark_scheme = light.clone();
        dark_scheme.extend(tokens(dark));
        for (scheme, colors) in [("light", light), ("dark", dark_scheme)] {
            for (text, background, minimum) in [
                ("--fg", "--panel", 4.5),
                ("--fg", "--bg", 4.5),
                ("--fg", "--subtle", 4.5),
                ("--link", "--panel", 4.5),
                ("--on-primary", "--primary", 4.5),
                ("--on-primary", "--primary-hover", 4.5),
                ("--error-fg", "--error-bg", 4.5),
                ("--focus", "--panel", 3.0),
                // WCAG 1.4.11: an unfocused field is identified by its border.
                ("--input-border", "--panel", 3.0),
            ] {
                let ratio = contrast(colors[text], colors[background]);
                assert!(
                    ratio >= minimum,
                    "{scheme} {text} on {background}: {ratio:.2}"
                );
            }
        }
    }

    #[test]
    fn embedded_mark_matches_the_canonical_brand_asset() {
        let canonical = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../assets/brand/aegaeon-mark.svg");
        assert_eq!(std::fs::read_to_string(canonical).unwrap(), MARK);
    }

    #[test]
    fn canonical_mark_is_inline_svg_without_external_references() {
        assert!(MARK.trim_start().starts_with("<svg viewBox=\"0 0 33 33\""));
        for forbidden in ["href", "<script", "<image", "<style", "url("] {
            assert!(!MARK.contains(forbidden), "{forbidden}");
        }
    }
}
