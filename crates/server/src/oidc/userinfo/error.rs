pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
    InvalidRequest(String),
    InvalidToken,
    InsufficientScope,
    ServerError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(msg) => write!(f, "Invalid request: {msg}"),
            Self::InvalidToken => write!(f, "Invalid token"),
            Self::InsufficientScope => write!(f, "Insufficient scope"),
            Self::ServerError(msg) => write!(f, "Server error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}
