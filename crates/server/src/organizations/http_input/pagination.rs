use super::{InputError, Uuid};
use crate::organizations::Scope;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

pub const MAX_CURSOR_BYTES: usize = 512;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    environment: Uuid,
    domain: Uuid,
    after: Uuid,
}

pub fn encode(scope: Scope, after: Uuid) -> Result<String, InputError> {
    if scope.environment_id.is_nil() || scope.domain_id.is_nil() || after.is_nil() {
        return Err(InputError::Invalid);
    }
    let bytes = serde_json::to_vec(&Cursor {
        version: 1,
        environment: scope.environment_id,
        domain: scope.domain_id,
        after,
    })
    .map_err(|_| InputError::Invalid)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn decode(scope: Scope, token: Option<&str>) -> Result<Option<Uuid>, InputError> {
    let Some(token) = token else {
        return Ok(None);
    };
    if token.is_empty() || token.len() > MAX_CURSOR_BYTES {
        return Err(InputError::Invalid);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| InputError::Invalid)?;
    let cursor: Cursor = super::decode_json(&bytes)?;
    if cursor.version != 1
        || cursor.environment != scope.environment_id
        || cursor.domain != scope.domain_id
        || encode(scope, cursor.after)? != token
    {
        return Err(InputError::Invalid);
    }
    Ok(Some(cursor.after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organizations_cursor_is_bounded_canonical_and_scoped_without_authority() {
        let scope = Scope {
            environment_id: Uuid::new_v4(),
            domain_id: Uuid::new_v4(),
        };
        let after = Uuid::new_v4();
        let token = encode(scope, after).unwrap();
        assert_eq!(decode(scope, Some(&token)), Ok(Some(after)));
        assert_eq!(decode(scope, None), Ok(None));
        assert!(decode(
            Scope {
                domain_id: Uuid::new_v4(),
                ..scope
            },
            Some(&token)
        )
        .is_err());
        assert!(decode(
            Scope {
                environment_id: Uuid::new_v4(),
                ..scope
            },
            Some(&token)
        )
        .is_err());
        for bad in [
            String::new(),
            "x".repeat(MAX_CURSOR_BYTES + 1),
            format!("{token}="),
            URL_SAFE_NO_PAD.encode(br#"{"version":1,"version":2}"#),
        ] {
            assert!(decode(scope, Some(&bad)).is_err());
        }
        assert!(encode(scope, Uuid::nil()).is_err());
        assert!(encode(
            Scope {
                domain_id: Uuid::nil(),
                ..scope
            },
            after
        )
        .is_err());
    }
}
