use crate::web::presentation::{escape as html_escape, fill, text, Page, Presentation};

fn hidden_input(name: &str, value: Option<&str>) -> String {
    match value {
        Some(value) if !value.is_empty() => format!(
            r#"<input type="hidden" name="{name}" value="{value}">"#,
            name = html_escape(name),
            value = html_escape(value)
        ),
        _ => String::new(),
    }
}

fn render_local_auth_shell(presentation: Presentation<'_>, title: &str, body: &str) -> String {
    Page::new(presentation, title, body).render()
}

pub(in crate::web) fn render_local_login_form(
    presentation: Presentation<'_>,
    return_to: Option<&str>,
    acr: Option<&str>,
    csrf_token: &str,
    error: Option<&str>,
) -> String {
    let error_block = error.map_or_else(String::new, |message| {
        format!(
            r#"<div class="error" role="alert">{}</div>"#,
            html_escape(message)
        )
    });
    let messages = presentation.messages();
    render_local_auth_shell(
        presentation,
        messages.sign_in_heading,
        &format!(
            r#"<h1>{heading}</h1>
<p>{intro}</p>
{error_block}
<form method="post" action="/auth/login">
  {return_to_input}
  {acr_input}
  {csrf_input}
  <label for="identifier">{identifier}</label>
  <input id="identifier" name="identifier" type="text" autocomplete="username" required>
  <label for="password">{password}</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">{submit}</button>
</form>"#,
            heading = text(messages.sign_in_heading),
            intro = fill(
                messages.sign_in_intro,
                &[("service", &html_escape(presentation.service()))]
            ),
            identifier = text(messages.identifier_label),
            password = text(messages.password_label),
            submit = text(messages.sign_in_submit),
            error_block = error_block,
            return_to_input = hidden_input("return_to", return_to),
            acr_input = hidden_input("acr", acr),
            csrf_input = hidden_input("csrf_token", Some(csrf_token))
        ),
    )
}

#[derive(Clone, Copy)]
pub(in crate::web) struct LocalPasswordForm<'a> {
    pub(in crate::web) presentation: Presentation<'a>,
    pub(in crate::web) title: &'a str,
    pub(in crate::web) heading: &'a str,
    pub(in crate::web) action: &'a str,
    pub(in crate::web) submit_label: &'a str,
    pub(in crate::web) token: Option<&'a str>,
    pub(in crate::web) return_to: Option<&'a str>,
    pub(in crate::web) csrf_token: &'a str,
    pub(in crate::web) error: Option<&'a str>,
}

pub(in crate::web) fn render_local_password_form(form: LocalPasswordForm<'_>) -> String {
    let error_block = form.error.map_or_else(String::new, |message| {
        format!(
            r#"<div class="error" role="alert">{}</div>"#,
            html_escape(message)
        )
    });
    let messages = form.presentation.messages();
    render_local_auth_shell(
        form.presentation,
        form.title,
        &format!(
            r#"<h1>{heading}</h1>
<p>{intro}</p>
{error_block}
<form method="post" action="{action}">
  {token_input}
  {return_to_input}
  {csrf_input}
  <label for="token">{token_label}</label>
  <input id="token" name="token" type="text" value="{token_value}" autocomplete="one-time-code" required>
  <label for="password">{new_password}</label>
  <input id="password" name="password" type="password" autocomplete="new-password" required>
  <label for="password_confirmation">{confirm_password}</label>
  <input id="password_confirmation" name="password_confirmation" type="password" autocomplete="new-password" required>
  <button type="submit">{submit_label}</button>
</form>
<p class="meta">{rule}</p>"#,
            heading = html_escape(form.heading),
            intro = text(messages.password_form_intro),
            token_label = text(messages.one_time_token_label),
            new_password = text(messages.new_password_label),
            confirm_password = text(messages.confirm_password_label),
            rule = text(messages.password_rule),
            error_block = error_block,
            action = html_escape(form.action),
            token_input = String::new(),
            return_to_input = hidden_input("return_to", form.return_to),
            csrf_input = hidden_input("csrf_token", Some(form.csrf_token)),
            token_value = html_escape(form.token.unwrap_or("")),
            submit_label = html_escape(form.submit_label)
        ),
    )
}

/// Status and error texts are English until they move into the catalogs, so
/// result pages keep the configured identity but render in English.
pub(in crate::web) fn render_local_result_page(
    presentation: Presentation<'_>,
    title: &str,
    message: &str,
    next_href: Option<&str>,
) -> String {
    let presentation = Presentation {
        locale: crate::web::Locale::En,
        ..presentation
    };
    let next_link = next_href.map_or_else(String::new, |href| {
        format!(
            r#"<p><a href="{href}">{label}</a></p>"#,
            href = html_escape(href),
            label = text(presentation.messages().continue_link)
        )
    });
    render_local_auth_shell(
        presentation,
        title,
        &format!(
            r"<h1>{title}</h1>
<p>{message}</p>
{next_link}",
            title = html_escape(title),
            message = html_escape(message),
            next_link = next_link
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::Locale;

    const NAMED_JAPANESE: Presentation<'static> = Presentation {
        locale: Locale::Ja,
        service_name: Some("サンプル <学園>"),
    };

    #[test]
    fn login_form_is_localized_and_names_the_service_literally() {
        let html = render_local_login_form(
            NAMED_JAPANESE,
            Some("/authorize?x=1"),
            None,
            "csrf",
            Some("Sign-in failed."),
        );
        assert!(html.contains(r#"<html lang="ja">"#));
        assert!(html.contains("<title>サインイン</title>"));
        assert!(html.contains("<h1>サインイン</h1>"));
        assert!(html.contains(
            "<p>続行するには サンプル &lt;学園&gt; のアカウントでサインインしてください。</p>"
        ));
        assert!(
            html.contains(r#"<label for="identifier">メールアドレスまたはサブジェクト</label>"#)
        );
        assert!(html.contains(r#"<button type="submit">サインイン</button>"#));
        assert!(html.contains(r#"<span class="brand-name">サンプル &lt;学園&gt;</span>"#));
        // Field names and the stable form contract do not change with language.
        for contract in [
            r#"name="identifier""#,
            r#"name="password""#,
            r#"name="csrf_token" value="csrf""#,
            r#"name="return_to" value="/authorize?x=1""#,
        ] {
            assert!(html.contains(contract), "{contract}");
        }
    }

    #[test]
    fn default_login_form_names_aegaeon_in_english() {
        let html = render_local_login_form(Presentation::DEFAULT, None, None, "csrf", None);
        assert!(html.contains(r#"<html lang="en">"#));
        assert!(html.contains("<p>Sign in with your Aegaeon account to continue.</p>"));
    }

    #[test]
    fn result_pages_keep_the_identity_but_stay_english_until_cataloged() {
        let html = render_local_result_page(NAMED_JAPANESE, "Server error", "Try again.", None);
        assert!(html.contains(r#"<html lang="en">"#));
        assert!(html.contains(r#"<span class="brand-name">サンプル &lt;学園&gt;</span>"#));
        assert!(html.contains("Sign-in powered by Aegaeon"));
    }

    #[test]
    fn password_form_uses_catalog_labels() {
        let messages = NAMED_JAPANESE.messages();
        let html = render_local_password_form(LocalPasswordForm {
            presentation: NAMED_JAPANESE,
            title: messages.reset_password,
            heading: messages.reset_password,
            action: "/auth/password/reset",
            submit_label: messages.reset_password,
            token: None,
            return_to: None,
            csrf_token: "csrf",
            error: None,
        });
        assert!(html.contains("<h1>パスワードを再設定</h1>"));
        assert!(
            html.contains(r#"<label for="password_confirmation">新しいパスワード（確認）</label>"#)
        );
        assert!(html.contains("パスワードは12バイト以上にしてください。"));
    }
}
