use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::{challenge_valid, request_key, StepUpChallenge};

#[derive(Clone)]
pub(super) struct ProcessLocalStepUpStoreBackend {
    challenges: Arc<RwLock<HashMap<String, StepUpChallenge>>>,
    by_request: Arc<RwLock<HashMap<String, String>>>,
}

impl ProcessLocalStepUpStoreBackend {
    pub(super) fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            by_request: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub(super) fn issue_challenge(&self, challenge: &StepUpChallenge) -> Result<(), String> {
        let key = request_key(
            &challenge.client_id,
            &challenge.session_id,
            &challenge.request_id,
        );
        let mut by_request = self
            .by_request
            .write()
            .map_err(|_| poisoned_lock_error("by_request"))?;
        let mut challenges = self
            .challenges
            .write()
            .map_err(|_| poisoned_lock_error("challenges"))?;
        if let Some(previous) = by_request.insert(key, challenge.id.clone()) {
            challenges.remove(&previous);
        }
        challenges.insert(challenge.id.clone(), challenge.clone());
        Ok(())
    }

    pub(super) fn complete_for_request(
        &self,
        client_id: &str,
        session_id: &str,
        request_id: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<StepUpChallenge>, String> {
        let key = request_key(client_id, session_id, request_id);
        let challenge_id = {
            let by_request = self
                .by_request
                .read()
                .map_err(|_| poisoned_lock_error("by_request"))?;
            let Some(challenge_id) = by_request.get(&key) else {
                return Ok(None);
            };
            challenge_id.clone()
        };
        self.complete_challenge(&challenge_id, now_epoch_secs)
    }

    pub(super) fn consume_completed(
        &self,
        client_id: &str,
        session_id: &str,
        request_id: &str,
        now_epoch_secs: u64,
    ) -> Result<bool, String> {
        let key = request_key(client_id, session_id, request_id);
        let mut by_request = self
            .by_request
            .write()
            .map_err(|_| poisoned_lock_error("by_request"))?;
        let Some(challenge_id) = by_request.get(&key).cloned() else {
            return Ok(false);
        };
        let mut challenges = self
            .challenges
            .write()
            .map_err(|_| poisoned_lock_error("challenges"))?;
        let Some(challenge) = challenges.get(&challenge_id) else {
            by_request.remove(&key);
            return Ok(false);
        };

        if !challenge.completed || !challenge_valid(challenge, now_epoch_secs) {
            return Ok(false);
        }

        challenges.remove(&challenge_id);
        by_request.remove(&key);
        Ok(true)
    }

    pub(super) fn cleanup_expired(&self, now_epoch_secs: u64) -> Result<(), String> {
        let mut by_request = self
            .by_request
            .write()
            .map_err(|_| poisoned_lock_error("by_request"))?;
        let mut challenges = self
            .challenges
            .write()
            .map_err(|_| poisoned_lock_error("challenges"))?;
        let expired_keys = challenges
            .iter()
            .filter(|(_, challenge)| challenge.expires_at_epoch_secs <= now_epoch_secs)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        if expired_keys.is_empty() {
            return Ok(());
        }
        expired_keys.iter().for_each(|id| {
            challenges.remove(id);
        });
        by_request.retain(|_, id| !expired_keys.contains(id));
        Ok(())
    }

    fn complete_challenge(
        &self,
        challenge_id: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<StepUpChallenge>, String> {
        let mut challenges = self
            .challenges
            .write()
            .map_err(|_| poisoned_lock_error("challenges"))?;
        let Some(challenge) = challenges.get_mut(challenge_id) else {
            return Ok(None);
        };
        if challenge.completed {
            return Ok(None);
        }
        if !challenge_valid(challenge, now_epoch_secs) {
            return Ok(None);
        }
        challenge.completed = true;
        Ok(Some(challenge.clone()))
    }
}

fn poisoned_lock_error(name: &str) -> String {
    format!("step-up store lock poisoned: {name}")
}
