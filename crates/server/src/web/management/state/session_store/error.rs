/// Preserve SQL failure classes without exposing driver text or SQL parameters.
#[derive(Debug)]
pub(in crate::web::management) enum SessionStoreError {
    Database(sqlx::Error),
    Unavailable,
    InvalidState,
}

impl SessionStoreError {
    pub(in crate::web::management) fn is_unavailable(&self) -> bool {
        match self {
            Self::Database(error) => {
                crate::db::is_temporarily_unavailable(error)
                    || matches!(error, sqlx::Error::PoolClosed)
            }
            Self::Unavailable => true,
            Self::InvalidState => false,
        }
    }

    pub(super) fn sqlstate(&self) -> Option<std::borrow::Cow<'_, str>> {
        match self {
            Self::Database(error) => error.as_database_error().and_then(|error| error.code()),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for SessionStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl std::fmt::Display for SessionStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.is_unavailable() {
            "management session store unavailable"
        } else {
            "management session store operation failed"
        })
    }
}

impl std::error::Error for SessionStoreError {}
