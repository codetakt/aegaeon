//! HTTP attempts and scenario legs are distinct reporting units.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HttpAccounting {
    pub attempts: u64,
    pub responses: u64,
    pub transport_failures: u64,
    pub body_failures: u64,
    /// Keys are METHOD endpoint; URLs, credentials and response bodies are excluded.
    pub methods_endpoints: BTreeMap<String, u64>,
    /// Keys are METHOD endpoint HTTP-status.
    pub statuses: BTreeMap<String, u64>,
    pub nonce_challenges: BTreeMap<String, u64>,
    pub nonce_retries: BTreeMap<String, u64>,
}

fn merge_map(target: &mut BTreeMap<String, u64>, source: BTreeMap<String, u64>) -> Result<()> {
    for (key, count) in source {
        let value = target.entry(key).or_default();
        *value = value
            .checked_add(count)
            .ok_or_else(|| anyhow::anyhow!("HTTP counter overflow"))?;
    }
    Ok(())
}

impl HttpAccounting {
    pub fn merge(&mut self, source: Self) -> Result<()> {
        for (target, count) in [
            (&mut self.attempts, source.attempts),
            (&mut self.responses, source.responses),
            (&mut self.transport_failures, source.transport_failures),
            (&mut self.body_failures, source.body_failures),
        ] {
            *target = target
                .checked_add(count)
                .ok_or_else(|| anyhow::anyhow!("HTTP counter overflow"))?;
        }
        merge_map(&mut self.methods_endpoints, source.methods_endpoints)?;
        merge_map(&mut self.statuses, source.statuses)?;
        merge_map(&mut self.nonce_challenges, source.nonce_challenges)?;
        merge_map(&mut self.nonce_retries, source.nonce_retries)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        let sum = |map: &BTreeMap<String, u64>| {
            map.values()
                .try_fold(0u64, |a, b| a.checked_add(*b))
                .ok_or_else(|| anyhow::anyhow!("HTTP counter overflow"))
        };
        ensure!(
            self.responses.checked_add(self.transport_failures) == Some(self.attempts)
                && sum(&self.methods_endpoints)? == self.attempts
                && sum(&self.statuses)? == self.responses
                && self.body_failures <= self.responses,
            "inconsistent HTTP accounting"
        );
        for (role, retries) in &self.nonce_retries {
            ensure!(
                *retries <= *self.nonce_challenges.get(role).unwrap_or(&0),
                "retry without a recorded challenge"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegAccounting {
    pub invocations: u64,
    pub positive_successes: u64,
    pub expected_rejections: u64,
    pub failures: u64,
}

impl LegAccounting {
    pub fn record(&mut self, success: bool, rejection: bool) {
        self.invocations += 1;
        if !success {
            self.failures += 1;
        } else if rejection {
            self.expected_rejections += 1;
        } else {
            self.positive_successes += 1;
        }
    }
    pub fn valid(&self) -> bool {
        self.positive_successes
            .checked_add(self.expected_rejections)
            .and_then(|v| v.checked_add(self.failures))
            == Some(self.invocations)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PhaseAccounting {
    pub legs: BTreeMap<String, LegAccounting>,
    pub http: HttpAccounting,
    pub errors: Vec<String>,
}

impl PhaseAccounting {
    pub fn positive_successes(&self) -> u64 {
        self.legs.values().map(|v| v.positive_successes).sum()
    }
    pub fn validate(&self, required_legs: &[String]) -> Result<()> {
        self.http.validate()?;
        ensure!(
            self.http.attempts > 0 && self.positive_successes() > 0,
            "no HTTP traffic or successful positive consumption"
        );
        ensure!(
            self.errors.is_empty(),
            "phase has setup/join/accounting failures"
        );
        ensure!(
            self.legs.values().all(|v| v.valid()),
            "inconsistent leg accounting"
        );
        for leg in required_legs {
            let counts = self
                .legs
                .get(leg)
                .ok_or_else(|| anyhow::anyhow!("missing selected leg: {leg}"))?;
            ensure!(
                counts.invocations > 0
                    && counts.failures == 0
                    && counts.positive_successes + counts.expected_rejections > 0,
                "failed or unconsumed selected leg: {leg}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_traffic_and_wrong_http_partitions_are_rejected() {
        let mut phase = PhaseAccounting::default();
        let required = vec!["positive".into(), "rejection".into()];
        assert!(phase.validate(&required).is_err());
        phase.http.attempts = 1;
        phase.http.responses = 1;
        phase
            .http
            .methods_endpoints
            .insert("GET /userinfo".into(), 1);
        phase.http.statuses.insert("GET /userinfo 200".into(), 1);
        phase
            .legs
            .entry("positive".into())
            .or_default()
            .record(true, false);
        assert!(phase.validate(&required).is_err());
        phase
            .legs
            .entry("rejection".into())
            .or_default()
            .record(true, true);
        assert!(phase.validate(&required).is_ok());
        phase.http.transport_failures = 1;
        assert!(phase.validate(&required).is_err());
    }
}
