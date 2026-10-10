#[path = "support/source_guard.rs"]
mod source_guard;

use source_guard::{assert_ordered_markers, function_body, server_source, TestContext, TestResult};

#[test]
fn upstream_callback_database_mutations_use_one_transaction() -> TestResult {
    let callback_source = server_source("src/web/upstream_callback.rs", "upstream callback")?;
    let callback_body = function_body(&callback_source, "pub(super) async fn upstream_callback(")
        .test_context("upstream callback handler should exist")?;

    assert!(
        callback_body.contains("complete_bound_upstream_callback("),
        "the outer callback handler must invoke the bound callback completion helper"
    );
    let completion_body = function_body(
        &callback_source,
        "async fn complete_bound_upstream_callback(",
    )
    .test_context("bound callback completion helper should exist")?;
    assert!(
        completion_body.contains("persist_bound_upstream_callback("),
        "bound callback completion must invoke the persistence helper"
    );
    let persistence_body = function_body(
        &callback_source,
        "async fn persist_bound_upstream_callback(",
    )
    .test_context("bound callback persistence helper should exist")?;

    assert_ordered_markers(
        persistence_body,
        &[
            "state.db_pool.begin().await",
            "resolve_upstream_callback_user(&mut tx,",
            "record_upstream_callback_audit(&mut tx,",
            "persist_upstream_callback_refresh_token(&mut tx,",
            "sync_upstream_callback_projection(\n        &mut tx,",
            "tx.commit().await",
            "finalize_upstream_callback_response(",
        ],
        "upstream callback database mutations should be committed before session creation",
    )?;

    for (relative_path, description) in [
        (
            "src/web/upstream_callback_users/resolution.rs",
            "upstream callback user resolution",
        ),
        (
            "src/web/upstream_callback_users/account_link.rs",
            "upstream callback account link persistence",
        ),
        (
            "src/web/upstream_callback_users/audit.rs",
            "upstream callback audit persistence",
        ),
        (
            "src/web/upstream_callback_users/jit.rs",
            "upstream callback JIT persistence",
        ),
        (
            "src/web/upstream_callback_users/refresh.rs",
            "upstream callback refresh persistence",
        ),
        (
            "src/web/upstream_callback_users/projection.rs",
            "upstream callback projection persistence",
        ),
        ("src/web/upstream_users.rs", "upstream user persistence"),
    ] {
        let source = server_source(relative_path, description)?;
        assert!(
            !source.contains("PgPool"),
            "{description} must not perform callback database mutations through PgPool"
        );
        assert!(
            source.contains("Transaction<'_, Postgres>"),
            "{description} must accept the callback PostgreSQL transaction"
        );
    }
    Ok(())
}
