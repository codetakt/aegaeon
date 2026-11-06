//! Transport loss is not evidence of a changed configuration or a rolled-back write.

pub(crate) fn is_temporarily_unavailable(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut => true,
        sqlx::Error::Database(database) => database.code().is_some_and(|code| {
            code.starts_with("08")
                || matches!(
                    code.as_ref(),
                    "57P01" | "57P02" | "57P03" | "53300" | "55P03" | "57014"
                )
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_transport_loss_is_distinct_from_invalid_or_closed_authority() {
        assert!(is_temporarily_unavailable(&sqlx::Error::Io(
            std::io::ErrorKind::ConnectionReset.into()
        )));
        assert!(is_temporarily_unavailable(&sqlx::Error::PoolTimedOut));
        for error in [
            sqlx::Error::PoolClosed,
            sqlx::Error::RowNotFound,
            sqlx::Error::Protocol("selected generation refused".into()),
            sqlx::Error::Configuration("invalid configuration".into()),
        ] {
            assert!(!is_temporarily_unavailable(&error));
        }
    }
}
