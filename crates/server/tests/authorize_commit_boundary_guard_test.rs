#[path = "support/source_guard.rs"]
mod source_guard;

use source_guard::{assert_ordered_markers, function_body, server_source, TestContext, TestResult};

#[test]
fn authorize_audit_records_precommit_approval_not_code_issuance_success() -> TestResult {
    let source = server_source(
        "src/web/authorize_endpoint/issue.rs",
        "authorize endpoint issue source",
    )?;
    let body = function_body(&source, "async fn audit_authorize_code_issue_approval(")
        .test_context("authorize code approval audit helper should exist")?;

    assert!(
        body.contains("\"oauth.authorization_code.issue.approved.v1\""),
        "authorization audit must describe the resource-owner approval phase"
    );
    assert!(
        body.contains("outcome: \"approved\""),
        "authorization audit outcome must not claim code issuance success before one-time input consumption and code storage"
    );
    assert!(
        body.contains("\"phase\": \"pre_commit\""),
        "authorization audit data must mark that the event is emitted before code-issue commit"
    );
    assert!(
        !source.contains("oauth.authorization_code.issue.authorized.v1"),
        "authorization audit must not use the old overbroad issue.authorized event name"
    );
    Ok(())
}

#[test]
fn authorize_one_time_input_commit_errors_keep_standard_error_codes() -> TestResult {
    let source = server_source(
        "src/web/authorize_endpoint/issue.rs",
        "authorize endpoint issue source",
    )?;
    let body = function_body(&source, "async fn issue_authorize_code_response(")
        .test_context("authorize code response helper should exist")?;

    assert_ordered_markers(
        body,
        &[
            "AuthorizationCodeIssueError::PushedAuthorizationRequestMissing",
            "\"invalid_request_uri\"",
            "AuthorizationCodeIssueError::RequestObjectJtiReplay",
            "\"invalid_request\"",
            "\"access_denied\"",
        ],
        "authorization-code one-time input commit errors should be mapped before fallback denial",
    )?;
    Ok(())
}

#[test]
fn token_authorization_code_errors_do_not_depend_on_internal_messages() -> TestResult {
    let source = server_source(
        "src/web/token_authorization_code.rs",
        "token authorization-code handler source",
    )?;
    let body = function_body(
        &source,
        "pub(super) async fn handle_token_authorization_code_grant(",
    )
    .test_context("authorization-code token handler should exist")?;

    assert!(
        body.contains("exchange_code_for_tokens_bound_with_grant_policy_for_token_endpoint_async("),
        "token handler must call the typed authorization-code exchange API"
    );
    assert!(
        body.contains("error.oauth_error_code()")
            && body.contains("error.oauth_error_description()"),
        "token handler must map typed authorization-code exchange errors structurally"
    );
    assert!(
        !body.contains(".contains(")
            && !body.contains("Missing code")
            && !body.contains("Invalid or expired code"),
        "token handler must not branch on internal error message strings"
    );
    Ok(())
}
