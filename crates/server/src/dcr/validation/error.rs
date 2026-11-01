use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RegistrationValidationError {
    RedirectUri(String),
    Metadata(String),
}

impl fmt::Display for RegistrationValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RedirectUri(message) | Self::Metadata(message) => formatter.write_str(message),
        }
    }
}
