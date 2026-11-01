//! Presentation grammar shared by protected-resource callers.
//! Token validity and sender binding are checked separately after admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResourceScheme {
    Bearer,
    Dpop,
}

impl ResourceScheme {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "Bearer",
            Self::Dpop => "DPoP",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ResourceCredentials<'a> {
    pub(crate) scheme: ResourceScheme,
    pub(crate) token: &'a str,
}

impl ResourceCredentials<'_> {
    pub(crate) fn normalized_authorization(self) -> String {
        format!("Bearer {}", self.token)
    }
}

pub(crate) enum ResourcePresentation<'a> {
    Missing,
    Unsupported,
    Malformed(ResourceScheme),
    Credentials(ResourceCredentials<'a>),
}

pub(crate) fn classify_resource_presentation(header: Option<&str>) -> ResourcePresentation<'_> {
    let mut words = header.unwrap_or("").split_whitespace();
    let Some(scheme) = words.next() else {
        return ResourcePresentation::Missing;
    };
    let scheme = if scheme.eq_ignore_ascii_case("Bearer") {
        ResourceScheme::Bearer
    } else if scheme.eq_ignore_ascii_case("DPoP") {
        ResourceScheme::Dpop
    } else {
        return ResourcePresentation::Unsupported;
    };
    match (words.next(), words.next()) {
        (Some(token), None) => {
            ResourcePresentation::Credentials(ResourceCredentials { scheme, token })
        }
        _ => ResourcePresentation::Malformed(scheme),
    }
}
