use super::{try_env_num_with, ConfigError};

/// Deployment resource budgets; these do not grant issuer/client permissions.
#[derive(Clone, Debug)]
pub struct AuthorizationAdmissionLimits {
    capacity: i64,
    per_minute: i64,
    per_source: u32,
}

impl Default for AuthorizationAdmissionLimits {
    fn default() -> Self {
        Self {
            capacity: 4096,
            per_minute: 300,
            per_source: 60,
        }
    }
}

impl AuthorizationAdmissionLimits {
    /// Validate storage bounds and leave headroom beyond one source's windows.
    pub fn new(capacity: i64, per_minute: i64, per_source: u32) -> Result<Self, ConfigError> {
        let source = i64::from(per_source);
        if !(1..=1_000_000).contains(&capacity)
            || !(1..=1_000_000).contains(&per_minute)
            || source == 0
            || source * 2 >= per_minute
            || source * 6 >= capacity
        {
            return Err(ConfigError::InvalidValue {
                key: "authorization admission budgets".to_string(),
                value: format!("capacity={capacity}, per_minute={per_minute}, per_source={per_source}"),
                reason: "capacity and minute budget must be 1..=1000000, source budget positive, 2*source < minute budget and 6*source < capacity".to_string(),
            });
        }
        Ok(Self {
            capacity,
            per_minute,
            per_source,
        })
    }

    pub(super) fn try_from_env() -> Result<Self, ConfigError> {
        let capacity = try_env_num_with(
            "AEGAEON_AUTHORIZATION_TRANSACTION_CAPACITY",
            4096_i64,
            |v| (1..=1_000_000).contains(&v),
            "1..=1000000",
        )?;
        let minute = try_env_num_with(
            "AEGAEON_AUTHORIZATION_TRANSACTIONS_PER_MINUTE",
            300_i64,
            |v| (1..=1_000_000).contains(&v),
            "1..=1000000",
        )?;
        let source = try_env_num_with(
            "AEGAEON_AUTHORIZATION_REQUESTS_PER_SOURCE_MINUTE",
            60_u32,
            |v| (1..=1_000_000).contains(&v),
            "1..=1000000",
        )?;
        Self::new(capacity, minute, source)
    }

    #[must_use]
    pub const fn capacity(&self) -> i64 {
        self.capacity
    }
    #[must_use]
    pub const fn per_minute(&self) -> i64 {
        self.per_minute
    }
    #[must_use]
    pub const fn per_source(&self) -> u32 {
        self.per_source
    }
}
