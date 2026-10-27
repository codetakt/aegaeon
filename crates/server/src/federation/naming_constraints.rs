//! Federation URI host constraints. DNS comparison never rewrites signed identities.
use super::{EntityStatement, FederationError, NamingConstraints};
use url::{Host, Url};

fn invalid(reason: &str) -> FederationError {
    FederationError::Validation(format!("naming_constraints {reason}"))
}

/// Return an ASCII comparison view, leaving the retained claim untouched.
fn dns_name(name: &str) -> Result<String, FederationError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty()
        || name.len() > 253
        || !name.is_ascii()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || !matches!(Host::parse(name), Ok(Host::Domain(_)))
    {
        return Err(invalid("requires a DNS name"));
    }
    Ok(name.to_ascii_lowercase())
}

struct Name {
    domain: String,
    subtree: bool,
}

impl Name {
    fn parse(value: &str) -> Result<Self, FederationError> {
        let subtree = value.starts_with('.');
        let name = value.strip_prefix('.').unwrap_or(value);
        Ok(Self {
            domain: dns_name(name)?,
            subtree,
        })
    }

    fn matches(&self, host: &str) -> bool {
        if self.subtree {
            host.strip_suffix(&self.domain)
                .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
        } else {
            host == self.domain
        }
    }
}

impl NamingConstraints {
    pub(in crate::federation) fn validate(&self) -> Result<(), FederationError> {
        for name in self.permitted.iter().chain(&self.excluded).flatten() {
            Name::parse(name)?;
        }
        Ok(())
    }

    fn permits(&self, identifier: &str) -> Result<(), FederationError> {
        if self.permitted.is_none() && self.excluded.as_ref().is_none_or(Vec::is_empty) {
            return Ok(());
        }
        let uri = Url::parse(identifier).map_err(|_| invalid("requires a URI host"))?;
        let Some(Host::Domain(host)) = uri.host() else {
            return Err(invalid("requires a DNS URI host"));
        };
        let host = dns_name(host)?;
        for excluded in self.excluded.iter().flatten() {
            if Name::parse(excluded)?.matches(&host) {
                return Err(invalid("excluded subordinate name"));
            }
        }
        if let Some(permitted) = &self.permitted {
            for name in permitted {
                if Name::parse(name)?.matches(&host) {
                    return Ok(());
                }
            }
            return Err(invalid("subordinate name is not permitted"));
        }
        Ok(())
    }
}

/// The caller has checked the alternating C/S/C identity layout. This check is
/// also used by pure metadata resolution; it does not authenticate signatures.
pub(super) fn validate_chain_names(chain: &[EntityStatement]) -> Result<(), FederationError> {
    for (index, statement) in chain.iter().enumerate() {
        let Some(naming) = statement
            .constraints
            .as_ref()
            .and_then(|constraints| constraints.naming_constraints.as_ref())
        else {
            continue;
        };
        if index % 2 == 0 {
            return Err(invalid("is subordinate-only"));
        }
        naming.validate()?;
        for subordinate in chain[..index].iter().step_by(2) {
            naming.permits(&subordinate.sub)?;
        }
    }
    Ok(())
}
