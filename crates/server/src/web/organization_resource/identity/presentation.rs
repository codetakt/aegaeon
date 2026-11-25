use super::*;

pub(super) async fn form(
    state: &AppState,
    headers: &http::HeaderMap,
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
    let presentation = state.presentation_for(headers, None);
    let m = presentation.messages();
    let t = crate::web::presentation::text;
    let main = format!(
        r#"<h1>{heading}</h1><p>{intro}</p>
<h2>{request_heading}</h2><form method="post" action="{path}">
<input type="hidden" name="action" value="request"><input type="hidden" name="csrf_token" value="{token}">
<label>{purpose} <select name="purpose"><option value="registration">{create}</option><option value="password_recovery">{reset}</option></select></label>
<label>{invitation_code} <input type="password" name="invitation_capability" required maxlength="43" autocomplete="off"></label>
<label>{login_identifier} <input name="login_identifier" maxlength="255" autocomplete="username"></label>
<input type="hidden" name="request_key" value="{request_key}"><button type="submit">{send}</button></form>
<h2>{complete_heading}</h2><form method="post" action="{path}">
<input type="hidden" name="action" value="complete"><input type="hidden" name="csrf_token" value="{token}">
<label>{request_id} <input name="request_id" required maxlength="36" autocomplete="off"></label>
<label>{proof} <input type="password" name="proof" required maxlength="43" autocomplete="off"></label>
<label>{new_password} <input type="password" name="password" required minlength="12" maxlength="1024" autocomplete="new-password"></label>
<label>{confirm_password} <input type="password" name="password_confirmation" required minlength="12" maxlength="1024" autocomplete="new-password"></label>
<button type="submit">{save}</button></form>"#,
        heading = t(m.identity_heading),
        intro = t(m.identity_intro),
        request_heading = t(m.request_proof_heading),
        purpose = t(m.purpose_label),
        create = t(m.create_account_option),
        reset = t(m.reset_password_option),
        invitation_code = t(m.invitation_code_label),
        login_identifier = t(m.login_identifier_label),
        request_key = Uuid::new_v4(),
        send = t(m.send_proof),
        complete_heading = t(m.complete_request_heading),
        request_id = t(m.request_id_label),
        proof = t(m.address_proof_label),
        new_password = t(m.new_password_label),
        confirm_password = t(m.confirm_password_label),
        save = t(m.save_credentials),
    );
    let html =
        crate::web::presentation::Page::new(presentation, m.identity_heading, &main).render();
    let mut response =
        super::super::super::local_auth_support::local_auth_response(StatusCode::OK, html);
    super::super::super::append_csrf_cookie(&mut response, COOKIE, "/", &token);
    Ok(response)
}
