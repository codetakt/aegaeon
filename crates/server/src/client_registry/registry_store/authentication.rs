use base64::Engine;

use super::super::{
    log_client_registry_state_error, verify_client_secret_material, verify_dummy_client_secret,
    ClientRegistry, ClientRegistryStateError, RegisteredClient,
};

impl ClientRegistry {
    #[must_use]
    pub(in crate::client_registry) fn registered_auth_method_matches(
        client: &RegisteredClient,
        expected: &str,
    ) -> bool {
        client
            .token_endpoint_auth_method
            .trim()
            .eq_ignore_ascii_case(expected)
    }

    #[must_use]
    fn basic_auth_payload(auth_header: &str) -> Option<&str> {
        let trimmed = auth_header.trim_start();
        let (scheme, rest) = trimmed.as_bytes().split_at_checked("Basic".len())?;
        if !scheme.eq_ignore_ascii_case(b"Basic")
            || !rest.first().is_some_and(|byte| byte.is_ascii_whitespace())
        {
            return None;
        }
        let payload = trimmed["Basic".len()..].trim_start();
        (!payload.is_empty()).then_some(payload)
    }

    #[must_use]
    pub fn basic_auth_present(auth_header: &str) -> bool {
        Self::basic_auth_payload(auth_header).is_some()
    }

    #[must_use]
    pub fn decode_basic_auth_credentials(auth_header: &str) -> Option<(String, String)> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(Self::basic_auth_payload(auth_header)?)
            .ok()?;
        let credentials = String::from_utf8(decoded).ok()?;
        let mut parts = credentials.splitn(2, ':');
        let client_id = parts.next()?.to_string();
        let client_secret = parts.next()?.to_string();
        Some((client_id, client_secret))
    }

    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_validate_basic_auth(
        &self,
        auth_header: &str,
    ) -> Result<Option<(String, String)>, ClientRegistryStateError> {
        let Some((client_id, client_secret)) = Self::decode_basic_auth_credentials(auth_header)
        else {
            return Ok(None);
        };
        let Some((client, credentials)) =
            self.try_get_with_client_secret_credentials(&client_id)?
        else {
            verify_dummy_client_secret(&client_secret);
            return Ok(None);
        };
        if !Self::registered_auth_method_matches(&client, "client_secret_basic") {
            verify_dummy_client_secret(&client_secret);
            return Ok(None);
        }
        if verify_client_secret_material(
            client.client_secret.as_deref(),
            &credentials,
            &client_secret,
        ) {
            Ok(Some((client_id, client_secret)))
        } else {
            Ok(None)
        }
    }

    #[must_use]
    pub fn validate_basic_auth(&self, auth_header: &str) -> Option<(String, String)> {
        self.try_validate_basic_auth(auth_header)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("validate_basic_auth", &error);
                None
            })
    }

    pub fn try_validate_client_secret_post(
        &self,
        client_id: Option<&str>,
        client_secret: Option<&str>,
    ) -> Result<Option<String>, ClientRegistryStateError> {
        let Some(csec) = client_secret else {
            return Ok(None);
        };
        let Some(cid) = client_id else {
            verify_dummy_client_secret(csec);
            return Ok(None);
        };
        let Some((client, credentials)) = self.try_get_with_client_secret_credentials(cid)? else {
            verify_dummy_client_secret(csec);
            return Ok(None);
        };
        if !Self::registered_auth_method_matches(&client, "client_secret_post") {
            verify_dummy_client_secret(csec);
            return Ok(None);
        }
        if verify_client_secret_material(client.client_secret.as_deref(), &credentials, csec) {
            Ok(Some(cid.to_string()))
        } else {
            Ok(None)
        }
    }

    #[must_use]
    pub fn validate_client_secret_post(
        &self,
        client_id: Option<&str>,
        client_secret: Option<&str>,
    ) -> Option<String> {
        self.try_validate_client_secret_post(client_id, client_secret)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("validate_client_secret_post", &error);
                None
            })
    }

    pub fn try_is_confidential(&self, client_id: &str) -> Result<bool, ClientRegistryStateError> {
        Ok(self
            .try_get(client_id)?
            .is_some_and(|c| !Self::registered_auth_method_matches(&c, "none")))
    }

    #[must_use]
    pub fn is_confidential(&self, client_id: &str) -> bool {
        self.try_is_confidential(client_id).unwrap_or_else(|error| {
            log_client_registry_state_error("is_confidential", &error);
            false
        })
    }

    pub fn try_is_registered_public_client(
        &self,
        client_id: &str,
    ) -> Result<bool, ClientRegistryStateError> {
        Ok(self
            .try_get(client_id)?
            .is_some_and(|c| Self::registered_auth_method_matches(&c, "none")))
    }

    #[must_use]
    pub fn is_registered_public_client(&self, client_id: &str) -> bool {
        self.try_is_registered_public_client(client_id)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("is_registered_public_client", &error);
                false
            })
    }
}
