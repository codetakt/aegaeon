//! Request-only Organization selection. This value is never a token credential.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const TYPE: &str = "https://github.com/codetakt/aegaeon/spec/organization-selection/v1";
pub const DISCOVERY_SCOPE: &str = "organizations:discover";
pub const DISCOVERY_TTL_SECONDS: u64 = 300;
const GRANT_TYPE: &str = "https://github.com/codetakt/aegaeon/spec/organization-grant/v1";

#[cfg(test)]
mod resolved_budget_tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSelection;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionRequest {
    #[serde(rename = "type")]
    pub detail_type: String,
    pub locations: Vec<String>,
    pub privileges: Vec<String>,
    pub selection: String,
}

impl SelectionRequest {
    pub fn parse(value: &Value) -> Result<Self, InvalidSelection> {
        if serde_json::to_vec(value)
            .map_err(|_| InvalidSelection)?
            .len()
            > 16 * 1024
        {
            return Err(InvalidSelection);
        }
        let [detail] = value.as_array().ok_or(InvalidSelection)?.as_slice() else {
            return Err(InvalidSelection);
        };
        let request: Self = serde_json::from_value(detail.clone()).map_err(|_| InvalidSelection)?;
        let unique: BTreeSet<_> = request.privileges.iter().collect();
        if request.detail_type != TYPE
            || request.selection != "interactive"
            || request.locations.len() != 1
            || request.locations[0].is_empty()
            || request.locations[0].len() > 2048
            || crate::util::validate_resource_indicator(&request.locations[0]).is_err()
            || request.privileges.is_empty()
            || request.privileges.len() > 256
            || unique.len() != request.privileges.len()
            || request.privileges.iter().any(|value| !privilege(value))
        {
            return Err(InvalidSelection);
        }
        Ok(request)
    }

    /// Resolve only after the server has authenticated the subject and read current
    /// membership/client authority. Approval of the returned exact grant is separate.
    pub fn resolve(
        &self,
        identifier: &str,
        available: &BTreeSet<String>,
    ) -> Result<Value, InvalidSelection> {
        self.resolve_if_representable(identifier, available)?
            .ok_or(InvalidSelection)
    }

    /// An otherwise valid choice may exceed the explicit grant's encoded budget.
    /// Only that case returns `None`; malformed input remains an error.
    pub(crate) fn resolve_if_representable(
        &self,
        identifier: &str,
        available: &BTreeSet<String>,
    ) -> Result<Option<Value>, InvalidSelection> {
        Self::parse(&serde_json::json!([self]))?;
        if identifier.is_empty()
            || identifier.len() > 256
            || identifier.chars().any(char::is_control)
        {
            return Err(InvalidSelection);
        }
        let approved: BTreeSet<_> = self
            .privileges
            .iter()
            .filter(|value| available.contains(*value))
            .cloned()
            .collect();
        if approved.is_empty() {
            return Err(InvalidSelection);
        }
        let resolved = serde_json::json!([{
            "type": GRANT_TYPE,
            "locations": self.locations,
            "organizations": [{"identifier": identifier, "privileges": approved}],
        }]);
        if serde_json::to_vec(&resolved)
            .map_err(|_| InvalidSelection)?
            .len()
            > super::consent::MAX_GRANT_REQUEST_BYTES
        {
            return Ok(None);
        }
        super::consent::GrantRequest::parse(&resolved).map_err(|_| InvalidSelection)?;
        Ok(Some(resolved))
    }

    /// A server-held resolution may narrow the request, never change its audience,
    /// add administrative access, or substitute an unresolved selection credential.
    pub fn permits(&self, resolved: &Value) -> bool {
        let Some([detail]) = resolved.as_array().map(Vec::as_slice) else {
            return false;
        };
        let Some([organization]) = detail
            .get("organizations")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
        else {
            return false;
        };
        let Some(identifier) = organization.get("identifier").and_then(Value::as_str) else {
            return false;
        };
        let Ok(privileges) = serde_json::from_value::<BTreeSet<String>>(
            organization
                .get("privileges")
                .cloned()
                .unwrap_or(Value::Null),
        ) else {
            return false;
        };
        self.resolve(identifier, &privileges)
            .is_ok_and(|expected| expected == *resolved)
    }
}

fn privilege(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

pub fn requested(details: &Value) -> bool {
    details.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("type").and_then(Value::as_str).map(str::trim) == Some(TYPE))
    })
}

pub fn discovery_scope(scope: Option<&str>) -> bool {
    scope.is_some_and(|scope| scope.split(' ').any(|part| part == DISCOVERY_SCOPE))
}

pub fn valid_discovery_scopes(scope: Option<&str>) -> bool {
    discovery_scope(scope)
        && scope.is_some_and(|scope| {
            scope
                .split(' ')
                .all(|part| matches!(part, DISCOVERY_SCOPE | "openid"))
        })
}

pub fn valid_discovery_scope_composition(scope: Option<&str>) -> bool {
    !discovery_scope(scope) || valid_discovery_scopes(scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Value {
        serde_json::json!([{"type": TYPE, "locations": ["https://api.example.test"],
            "privileges": ["documents.read", "documents.write"], "selection": "interactive"}])
    }

    #[test]
    fn selection_requires_one_audience_explicit_ceiling_and_interaction() {
        assert!(SelectionRequest::parse(&request()).is_ok());
        for (field, value) in [
            ("locations", serde_json::json!([])),
            ("locations", serde_json::json!(["a", "b"])),
            ("locations", serde_json::json!(["*"])),
            (
                "locations",
                serde_json::json!(["https://api.example/#fragment"]),
            ),
            (
                "locations",
                serde_json::json!(["https://api.example/ whitespace"]),
            ),
            ("privileges", serde_json::json!([])),
            ("privileges", serde_json::json!(["*"])),
            ("privileges", serde_json::json!(["read", "read"])),
            ("selection", serde_json::json!("automatic")),
            ("organizations", serde_json::json!([])),
            ("identifier", serde_json::json!("*")),
            ("administrative_access", serde_json::json!(true)),
            ("type", serde_json::json!(GRANT_TYPE)),
        ] {
            let mut invalid = request();
            invalid[0][field] = value;
            assert!(SelectionRequest::parse(&invalid).is_err(), "{field}");
        }
        assert!(SelectionRequest::parse(&serde_json::json!([request()[0], request()[0]])).is_err());
    }

    #[test]
    fn resolution_is_an_explicit_single_organization_subset_without_mutating_input() {
        let original = request();
        let selection = SelectionRequest::parse(&original).unwrap();
        let available = BTreeSet::from(["documents.read".into(), "unrequested".into()]);
        let resolved = selection.resolve("exact <identifier>", &available).unwrap();
        assert_eq!(original, request());
        assert_eq!(
            resolved[0]["organizations"][0]["privileges"],
            serde_json::json!(["documents.read"])
        );
        assert!(selection.permits(&resolved));
        for (path, value) in [
            ("type", serde_json::json!(TYPE)),
            (
                "locations",
                serde_json::json!(["https://other.example.test"]),
            ),
            ("organizations", serde_json::json!([])),
        ] {
            let mut changed = resolved.clone();
            changed[0][path] = value;
            assert!(!selection.permits(&changed));
        }
        let mut elevated = resolved.clone();
        elevated[0]["organizations"][0]["privileges"] = serde_json::json!(["unrequested"]);
        assert!(!selection.permits(&elevated));
        elevated = resolved.clone();
        elevated[0]["organizations"][0]["administrative_access"] = serde_json::json!(true);
        assert!(!selection.permits(&elevated));
        assert!(selection.resolve("org", &BTreeSet::new()).is_err());
    }

    #[test]
    fn discovery_scope_excludes_refresh_and_business_authority() {
        for scope in [DISCOVERY_SCOPE, "openid organizations:discover"] {
            assert!(valid_discovery_scopes(Some(scope)));
        }
        for scope in [
            "",
            "openid",
            "organizations:discover offline_access",
            "organizations:discover documents.read",
        ] {
            assert!(!valid_discovery_scopes(Some(scope)));
        }
    }
}
