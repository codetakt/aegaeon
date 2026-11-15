//! Test connection origins for the existing bounded cleanup diagnostic.
//! Labels carry only a connection kind and a source location, never SQL or URLs.
use sqlx::postgres::PgConnectOptions;
use std::panic::Location;

#[track_caller]
pub(super) fn options(base: &PgConnectOptions, kind: &str) -> PgConnectOptions {
    let caller = Location::caller();
    base.clone()
        .application_name(&label(kind, caller.file(), caller.line(), caller.column()))
}

fn label(kind: &str, file: &str, line: u32, column: u32) -> String {
    let prefix = format!("witness-test:{kind}:");
    let suffix = format!(":{line}:{column}");
    // PostgreSQL's standard application_name limit is 63 bytes. Keep the kind,
    // line and column intact and retain the longest UTF-8 source-path suffix.
    // This is diagnostic context, not a globally unique connection identity;
    // the cleanup report also includes PID and backend_start.
    let available = 63 - prefix.len() - suffix.len();
    let mut start = file.len().saturating_sub(available);
    while !file.is_char_boundary(start) {
        start += 1;
    }
    format!("{prefix}{}{suffix}", &file[start..])
}

#[test]
fn witness_connection_labels_keep_coordinates_within_postgres_limit() {
    for kind in ["owner", "control", "deployment"] {
        for file in [
            "short.rs".to_owned(),
            format!("{}終端.rs", "長い/".repeat(80)),
        ] {
            let value = label(kind, &file, u32::MAX, u32::MAX);
            assert!(value.len() <= 63);
            assert!(value.starts_with(&format!("witness-test:{kind}:")));
            assert!(value.ends_with(":4294967295:4294967295"));
            assert!(value.contains(if file == "short.rs" {
                "short.rs"
            } else {
                "終端.rs"
            }));
        }
    }
}
