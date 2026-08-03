fn html_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

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

fn render_local_auth_shell(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <style>
      :root {{
        color-scheme: light;
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }}
      body {{
        margin: 0;
        background: #f4f7fb;
        color: #102033;
      }}
      main {{
        max-width: 30rem;
        margin: 3rem auto;
        padding: 2rem;
        background: #fff;
        border: 1px solid #d8e1ec;
        border-radius: 1rem;
        box-shadow: 0 16px 40px rgba(16, 32, 51, 0.08);
      }}
      h1 {{
        margin-top: 0;
        font-size: 1.6rem;
      }}
      p {{
        line-height: 1.5;
      }}
      label {{
        display: block;
        margin-top: 1rem;
        font-weight: 600;
      }}
      input[type="text"],
      input[type="password"] {{
        width: 100%;
        box-sizing: border-box;
        margin-top: 0.4rem;
        padding: 0.75rem 0.85rem;
        border: 1px solid #b8c6d8;
        border-radius: 0.6rem;
        font: inherit;
      }}
      button {{
        margin-top: 1.25rem;
        width: 100%;
        padding: 0.85rem 1rem;
        border: none;
        border-radius: 0.7rem;
        background: #0f4fbf;
        color: #fff;
        font: inherit;
        font-weight: 600;
        cursor: pointer;
      }}
      .error {{
        margin-top: 1rem;
        padding: 0.85rem 1rem;
        border-radius: 0.7rem;
        background: #fdeceb;
        color: #8a1c1c;
      }}
      .meta {{
        margin-top: 1rem;
        color: #516173;
        font-size: 0.95rem;
      }}
      a {{
        color: #0f4fbf;
      }}
    </style>
  </head>
  <body>
    <main>
      {body}
    </main>
  </body>
</html>"#,
        title = html_escape(title),
        body = body
    )
}

pub(in crate::web) fn render_local_login_form(
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
    render_local_auth_shell(
        "Sign in",
        &format!(
            r#"<h1>Sign in</h1>
<p>Use your local Aegaeon account to continue.</p>
{error_block}
<form method="post" action="/auth/login">
  {return_to_input}
  {acr_input}
  {csrf_input}
  <label for="identifier">Email or subject</label>
  <input id="identifier" name="identifier" type="text" autocomplete="username" required>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
</form>"#,
            error_block = error_block,
            return_to_input = hidden_input("return_to", return_to),
            acr_input = hidden_input("acr", acr),
            csrf_input = hidden_input("csrf_token", Some(csrf_token))
        ),
    )
}

#[derive(Clone, Copy)]
pub(in crate::web) struct LocalPasswordForm<'a> {
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
    render_local_auth_shell(
        form.title,
        &format!(
            r#"<h1>{heading}</h1>
<p>Enter the one-time token and choose a new password.</p>
{error_block}
<form method="post" action="{action}">
  {token_input}
  {return_to_input}
  {csrf_input}
  <label for="token">One-time token</label>
  <input id="token" name="token" type="text" value="{token_value}" autocomplete="one-time-code" required>
  <label for="password">New password</label>
  <input id="password" name="password" type="password" autocomplete="new-password" required>
  <label for="password_confirmation">Confirm password</label>
  <input id="password_confirmation" name="password_confirmation" type="password" autocomplete="new-password" required>
  <button type="submit">{submit_label}</button>
</form>
<p class="meta">Passwords must be at least 12 bytes long.</p>"#,
            heading = html_escape(form.heading),
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

pub(in crate::web) fn render_local_result_page(
    title: &str,
    message: &str,
    next_href: Option<&str>,
) -> String {
    let next_link = next_href.map_or_else(String::new, |href| {
        format!(
            r#"<p><a href="{href}">Continue</a></p>"#,
            href = html_escape(href)
        )
    });
    render_local_auth_shell(
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
