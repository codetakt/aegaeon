//! Test/debug key-rotation metrics harness.
//!
//! This module intentionally does not provide production key management. Runtime
//! JWK DTOs live in `jwk_types`; production signing keys are selected through the
//! management-database runtime key set and the OIDC/federation key managers.

use crate::jwk_types::{Jwk, Jwks};
use crate::metrics_integration::MetricsIntegration;
use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;

/// Mock key rotation manager for metrics tests and debug harnesses.
pub struct KeyRotationManager {
    metrics: Arc<MetricsIntegration>,
    current_keys: Arc<tokio::sync::RwLock<Jwks>>,
}

impl KeyRotationManager {
    #[must_use]
    pub fn new(metrics: Arc<MetricsIntegration>) -> Self {
        Self {
            metrics,
            current_keys: Arc::new(tokio::sync::RwLock::new(Jwks { keys: vec![] })),
        }
    }

    /// Rotate signing keys.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or state update fails.
    pub async fn rotate_signing_keys(&self) -> Result<()> {
        let start = Instant::now();
        let key_type = "signing";

        // Simulate key generation (in production, this would use KMS or HSM)
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let new_key = Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            kid: format!("sig-{}", uuid::Uuid::new_v4()),
            alg: Some("RS256".to_string()),
            n: Some("mock_modulus".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        };

        // Update keys atomically
        let mut keys = self.current_keys.write().await;
        keys.keys.retain(|k| k.use_ != Some("sig".to_string()));
        keys.keys.push(new_key);

        // Record the rotation time
        let duration = start.elapsed().as_secs_f64();
        self.metrics.metrics.record_key_rotation(key_type, duration);

        Ok(())
    }

    /// Rotate encryption keys.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or state update fails.
    pub async fn rotate_encryption_keys(&self) -> Result<()> {
        let start = Instant::now();
        let key_type = "encryption";

        // Simulate key generation
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

        let new_key = Jwk {
            kty: "RSA".to_string(),
            use_: Some("enc".to_string()),
            kid: format!("enc-{}", uuid::Uuid::new_v4()),
            alg: Some("RSA-OAEP".to_string()),
            n: Some("mock_modulus".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        };

        // Update keys atomically
        let mut keys = self.current_keys.write().await;
        keys.keys.retain(|k| k.use_ != Some("enc".to_string()));
        keys.keys.push(new_key);

        // Record the rotation time
        let duration = start.elapsed().as_secs_f64();
        self.metrics.metrics.record_key_rotation(key_type, duration);

        Ok(())
    }

    /// Rotate `DPoP` keys.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or state update fails.
    pub async fn rotate_dpop_keys(&self) -> Result<()> {
        let start = Instant::now();
        let key_type = "dpop";

        // Simulate EC key generation
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        let new_key = Jwk {
            kty: "EC".to_string(),
            use_: Some("sig".to_string()),
            kid: format!("dpop-{}", uuid::Uuid::new_v4()),
            alg: Some("ES256".to_string()),
            n: None,
            e: None,
            x: Some("mock_x_coordinate".to_string()),
            y: Some("mock_y_coordinate".to_string()),
            crv: Some("P-256".to_string()),
        };

        // Update keys atomically
        let mut keys = self.current_keys.write().await;
        keys.keys.retain(|k| !k.kid.starts_with("dpop-"));
        keys.keys.push(new_key);

        // Record the rotation time
        let duration = start.elapsed().as_secs_f64();
        self.metrics.metrics.record_key_rotation(key_type, duration);

        Ok(())
    }

    /// Get current JWKS
    pub async fn get_jwks(&self) -> Jwks {
        self.current_keys.read().await.clone()
    }

    /// Perform full key rotation.
    ///
    /// # Errors
    ///
    /// Returns an error if any individual rotation step fails.
    pub async fn rotate_all_keys(&self) -> Result<()> {
        let start = Instant::now();

        // Rotate all key types
        self.rotate_signing_keys().await?;
        self.rotate_encryption_keys().await?;
        self.rotate_dpop_keys().await?;

        // Record overall rotation time
        let duration = start.elapsed().as_secs_f64();
        self.metrics.metrics.record_key_rotation("all", duration);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegaeon_observability::metrics::OAuthMetrics;
    use prometheus::Registry;

    #[tokio::test]
    async fn test_key_rotation_metrics() {
        let registry = Registry::new();
        let oauth_metrics_result = OAuthMetrics::new(&registry);
        assert!(
            oauth_metrics_result.is_ok(),
            "OAuth metrics should initialize for key rotation tests"
        );
        let Ok(oauth_metrics) = oauth_metrics_result else {
            return;
        };
        let oauth_metrics = Arc::new(oauth_metrics);
        let integration = Arc::new(MetricsIntegration::new(oauth_metrics.clone()));
        MetricsIntegration::register_global(&integration);
        let manager = KeyRotationManager::new(integration);

        // Test signing key rotation
        let rotate_result = manager.rotate_signing_keys().await;
        assert!(
            rotate_result.is_ok(),
            "signing key rotation should succeed during metrics test"
        );

        // Check that metrics were recorded
        let metric_families = registry.gather();
        let mut found_rotation_metric = false;

        for family in &metric_families {
            if family.name() == "oauth_key_rotation_seconds" {
                found_rotation_metric = true;
                assert!(
                    !family.get_metric().is_empty(),
                    "Key rotation metrics should be recorded"
                );
            }
        }

        assert!(found_rotation_metric, "Key rotation histogram should exist");
    }

    #[tokio::test]
    async fn test_all_keys_rotation() {
        let registry = Registry::new();
        let oauth_metrics_result = OAuthMetrics::new(&registry);
        assert!(
            oauth_metrics_result.is_ok(),
            "OAuth metrics should initialize for all-keys rotation test"
        );
        let Ok(oauth_metrics) = oauth_metrics_result else {
            return;
        };
        let oauth_metrics = Arc::new(oauth_metrics);
        let integration = Arc::new(MetricsIntegration::new(oauth_metrics.clone()));
        MetricsIntegration::register_global(&integration);
        let manager = KeyRotationManager::new(integration);

        // Rotate all keys
        let rotate_result = manager.rotate_all_keys().await;
        assert!(
            rotate_result.is_ok(),
            "all-key rotation should succeed during rotation test"
        );

        // Verify keys were updated
        let jwks = manager.get_jwks().await;
        assert!(
            jwks.keys.len() >= 3,
            "Should have at least 3 keys after rotation"
        );

        // Check different key types
        let has_signing = jwks
            .keys
            .iter()
            .any(|k| k.use_ == Some("sig".to_string()) && !k.kid.starts_with("dpop"));
        let has_encryption = jwks.keys.iter().any(|k| k.use_ == Some("enc".to_string()));
        let has_dpop = jwks.keys.iter().any(|k| k.kid.starts_with("dpop"));

        assert!(has_signing, "Should have signing key");
        assert!(has_encryption, "Should have encryption key");
        assert!(has_dpop, "Should have DPoP key");
    }
}
