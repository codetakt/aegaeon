pub(super) fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Render the user code entry form (GET /device).
#[must_use]
pub fn render_user_code_form(
    csrf_token: &str,
    user_code: Option<&str>,
    error: Option<&str>,
) -> String {
    let prefill = user_code.unwrap_or("");
    let error_html = match error {
        Some(msg) => format!(
            r#"<div style="color:#c00;margin:0 0 16px;padding:8px 12px;border:1px solid #c00;border-radius:4px;background:#fff5f5">{}</div>"#,
            escape_html(msg)
        ),
        None => String::new(),
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Device Authorization</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;max-width:420px;margin:40px auto;padding:0 20px;color:#333}}
h1{{font-size:1.4em;margin-bottom:8px}}
p{{color:#666;line-height:1.5}}
form{{margin-top:24px}}
label{{display:block;font-weight:600;margin-bottom:6px}}
input[type=text]{{width:100%;padding:12px;font-size:1.3em;letter-spacing:0.15em;text-transform:uppercase;border:2px solid #ccc;border-radius:6px;box-sizing:border-box;text-align:center}}
input[type=text]:focus{{border-color:#0066cc;outline:none}}
button{{margin-top:16px;width:100%;padding:12px;font-size:1em;font-weight:600;color:#fff;background:#0066cc;border:none;border-radius:6px;cursor:pointer}}
button:hover{{background:#0052a3}}
</style>
</head>
<body>
<h1>Device Authorization</h1>
<p>Enter the code shown on your device to authorize access.</p>
{error_html}
<form method="post" action="/device">
<input type="hidden" name="csrf_token" value="{csrf}">
<label for="user_code">User Code</label>
<input type="text" id="user_code" name="user_code" value="{prefill}" placeholder="XXXX-XXXX" maxlength="10" autocomplete="off" autofocus required>
<button type="submit">Continue</button>
</form>
</body>
</html>"#,
        error_html = error_html,
        csrf = escape_html(csrf_token),
        prefill = escape_html(prefill),
    )
}

/// Render the confirmation page showing `client_id` and scope, with approve/deny buttons.
#[must_use]
pub fn render_confirm_page(
    csrf_token: &str,
    user_code: &str,
    client_id: &str,
    scope: Option<&str>,
    resource: Option<&str>,
) -> String {
    let scope_html = match scope {
        Some(s) => format!(
            r#"<div style="margin-bottom:16px"><strong>Scope:</strong> <code>{}</code></div>"#,
            escape_html(s)
        ),
        None => String::new(),
    };
    let resource_html = match resource {
        Some(resource) => format!(
            r#"<div style="margin-bottom:16px"><strong>Resource:</strong> <code>{}</code></div>"#,
            escape_html(resource)
        ),
        None => String::new(),
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Confirm Device Authorization</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;max-width:420px;margin:40px auto;padding:0 20px;color:#333}}
h1{{font-size:1.4em;margin-bottom:8px}}
p{{color:#666;line-height:1.5}}
.info{{background:#f0f4ff;border:1px solid #cce;border-radius:6px;padding:16px;margin:16px 0}}
code{{background:#e8e8e8;padding:2px 6px;border-radius:3px;font-size:0.95em}}
.actions{{display:flex;gap:12px;margin-top:20px}}
button{{flex:1;padding:12px;font-size:1em;font-weight:600;border:none;border-radius:6px;cursor:pointer}}
.approve{{color:#fff;background:#0a0}}
.approve:hover{{background:#080}}
.deny{{color:#fff;background:#c00}}
.deny:hover{{background:#a00}}
</style>
</head>
<body>
<h1>Confirm Device Authorization</h1>
<p>A device is requesting access to your account.</p>
<div class="info">
<div style="margin-bottom:8px"><strong>Application:</strong> <code>{client_id}</code></div>
{scope_html}
{resource_html}
<div><strong>Code:</strong> <code>{user_code}</code></div>
</div>
<div class="actions">
<form method="post" action="/device/approve" style="flex:1;display:flex">
<input type="hidden" name="csrf_token" value="{csrf}">
<input type="hidden" name="user_code" value="{user_code}">
<button type="submit" class="approve" style="flex:1">Approve</button>
</form>
<form method="post" action="/device/deny" style="flex:1;display:flex">
<input type="hidden" name="csrf_token" value="{csrf}">
<input type="hidden" name="user_code" value="{user_code}">
<button type="submit" class="deny" style="flex:1">Deny</button>
</form>
</div>
</body>
</html>"#,
        csrf = escape_html(csrf_token),
        user_code = escape_html(user_code),
        client_id = escape_html(client_id),
        scope_html = scope_html,
        resource_html = resource_html,
    )
}

/// Render a success result page.
#[must_use]
pub fn render_result_page(title: &str, message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;max-width:420px;margin:40px auto;padding:0 20px;color:#333;text-align:center}}
h1{{font-size:1.4em;margin-bottom:8px}}
p{{color:#666;line-height:1.5}}
</style>
</head>
<body>
<h1>{title}</h1>
<p>{message}</p>
</body>
</html>"#,
        title = escape_html(title),
        message = escape_html(message),
    )
}
