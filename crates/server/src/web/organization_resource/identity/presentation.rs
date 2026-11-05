use super::*;

pub(super) async fn form(
    state: &AppState,
    domain: Uuid,
    invitation: Uuid,
) -> Result<Response, Response> {
    let token = state
        .device
        .local_auth_csrf_store
        .clone()
        .try_generate_async()
        .await
        .map_err(|_| unavailable(state))?;
    // CSRF is generated as hexadecimal/base64, and paths contain parsed UUIDs.
    // No invitation capability, email or password is read from the URL.
    let token = token
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let path = format!("/organization-invitations/{domain}/{invitation}/identity");
    let html = format!(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><title>Account registration or recovery</title>
<h1>Account registration or recovery</h1><p>This changes your sign-in credentials. You will sign in separately to accept the invitation.</p>
<h2>Request an address proof</h2><form method="post" action="{path}">
<input type="hidden" name="action" value="request"><input type="hidden" name="csrf_token" value="{token}">
<label>Purpose <select name="purpose"><option value="registration">Create an account</option><option value="password_recovery">Reset a password</option></select></label>
<label>Invitation code <input type="password" name="invitation_capability" required maxlength="43" autocomplete="off"></label>
<label>Login identifier (password recovery only) <input name="login_identifier" maxlength="255" autocomplete="username"></label>
<input type="hidden" name="request_key" value="{}"><button type="submit">Send proof</button></form>
<h2>Complete a request</h2><form method="post" action="{path}">
<input type="hidden" name="action" value="complete"><input type="hidden" name="csrf_token" value="{token}">
<label>Request ID <input name="request_id" required maxlength="36" autocomplete="off"></label>
<label>Address proof <input type="password" name="proof" required maxlength="43" autocomplete="off"></label>
<label>New password <input type="password" name="password" required minlength="12" maxlength="1024" autocomplete="new-password"></label>
<label>Confirm password <input type="password" name="password_confirmation" required minlength="12" maxlength="1024" autocomplete="new-password"></label>
<button type="submit">Save credentials</button></form></html>"#,
        Uuid::new_v4()
    );
    let mut response =
        super::super::super::local_auth_support::local_auth_response(StatusCode::OK, html);
    super::super::super::append_csrf_cookie(&mut response, COOKIE, "/", &token);
    Ok(response)
}
