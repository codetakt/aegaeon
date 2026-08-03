use std::collections::HashMap;

use super::{filter_claims_by_scope, Result, Userinfo};

/// User information provider trait
pub trait UserProvider: Send + Sync {
    /// Get user information for a subject
    ///
    /// # Errors
    ///
    /// Returns an error when the backing store cannot provide a filtered
    /// userinfo document for the supplied subject and scopes.
    fn get_user_info(&self, sub: &str, scopes: &[String]) -> Result<Userinfo>;
}

/// In-memory user provider for testing
#[derive(Default)]
pub struct InMemoryUserProvider {
    users: HashMap<String, Userinfo>,
}

impl InMemoryUserProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    pub fn add_user(&mut self, user: Userinfo) {
        self.users.insert(user.sub.clone(), user);
    }
}

impl UserProvider for InMemoryUserProvider {
    fn get_user_info(&self, sub: &str, scopes: &[String]) -> Result<Userinfo> {
        let user = self.users.get(sub).cloned().unwrap_or_else(|| Userinfo {
            sub: sub.to_string(),
            ..Default::default()
        });

        Ok(filter_claims_by_scope(user, scopes))
    }
}

/// Minimal provider that returns only the subject claim.
#[derive(Default, Clone)]
pub struct SubjectOnlyUserProvider;

impl UserProvider for SubjectOnlyUserProvider {
    fn get_user_info(&self, sub: &str, _scopes: &[String]) -> Result<Userinfo> {
        Ok(Userinfo {
            sub: sub.to_string(),
            ..Default::default()
        })
    }
}
