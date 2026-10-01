use super::*;

pub(super) struct Context<'a> {
    pub cfg: &'a OidcConfig,
    pub clients: &'a ClientRegistry,
    pub sessions: &'a OidcSessionStore,
    pub http: &'a reqwest::Client,
    pub clock: Clock,
    pub event: &'a OidcLogoutEvent,
}

impl Context<'_> {
    fn identity(&self, client: &str) -> Identity {
        Identity {
            sid: self.event.sid.clone(),
            event_jti: self.event.jti.clone(),
            subject: self.event.user_id.clone(),
            client_id: client.to_string(),
        }
    }

    fn target(
        &self,
        client: &str,
        report: &mut BackchannelLogoutDispatchReport,
    ) -> Result<Option<Binding>, String> {
        if !self.cfg.backchannel_logout_enabled {
            return Ok(None);
        }
        let registered = self
            .clients
            .try_get(client)
            .map_err(|_| "client registration unavailable".to_string())?;
        let Some(registered) = registered else {
            report.skipped_unregistered_clients += 1;
            return Ok(None);
        };
        if registered.client_id != client {
            return Err("client registration identity mismatch".to_string());
        }
        let Some(uri) = registered.backchannel_logout_uri else {
            report.skipped_without_logout_uri += 1;
            return Ok(None);
        };
        if validate_backchannel_logout_dispatch_uri(&uri).is_err() {
            report.rejected_logout_uri += 1;
            return Ok(None);
        }
        Ok(Some(Binding {
            issuer: self.cfg.issuer.clone(),
            uri,
            session_required: registered.backchannel_logout_session_required,
        }))
    }

    async fn state(
        &self,
        client: &str,
        binding: Option<Binding>,
        command: Command,
    ) -> Result<Outcome, String> {
        self.sessions
            .delivery_transition_async(self.clock.request(
                self.identity(client),
                binding,
                command,
            )?)
            .await
    }

    async fn candidate(&self, client: &str, binding: &Binding) -> Result<Candidate, String> {
        let jti = aegaeon_crypto::rand::random_base64url(32);
        let sub = (!binding.session_required).then_some(self.event.user_id.as_str());
        let claims = build_backchannel_logout_claims_at(
            self.cfg,
            client,
            &self.event.sid,
            sub,
            &jti,
            self.clock.now(),
        )?;
        let iat = claims["iat"]
            .as_u64()
            .ok_or_else(|| "invalid logout issuance time".to_string())?;
        let exp = claims["exp"]
            .as_u64()
            .ok_or_else(|| "invalid logout expiry".to_string())?;
        let token = self
            .cfg
            .signing_key
            .sign_logout_token_async(&claims)
            .await
            .map_err(|_| "logout signing unavailable".to_string())?;
        Ok(Candidate::new(token, jti, iat, exp))
    }

    pub(super) async fn dispatch(
        &self,
        client: &str,
        report: &mut BackchannelLogoutDispatchReport,
    ) -> Result<(), String> {
        let binding = self.target(client, report)?;
        let status = self.state(client, binding.clone(), Command::Probe).await?;
        let Outcome::Ready { needs_candidate } = status else {
            record_outcome(&status, report);
            return Ok(());
        };
        let Some(binding) = binding else {
            report.terminal_undelivered += 1;
            return Ok(());
        };
        let candidate = if needs_candidate {
            match self.candidate(client, &binding).await {
                Ok(value) => Some(value),
                Err(_) => {
                    report.token_build_failures += 1;
                    return Ok(());
                }
            }
        } else {
            None
        };
        // Resolve again after potentially slow signing; do not reserve the network interval during KMS work.
        let current = self.target(client, report)?;
        if current.as_ref() != Some(&binding) {
            let outcome = self.state(client, None, Command::Probe).await?;
            record_outcome(&outcome, report);
            return Ok(());
        }
        let claim = Command::Claim {
            candidate,
            owner: aegaeon_crypto::rand::random_base64url(32),
            timeout: self.cfg.backchannel_logout_timeout_secs,
        };
        let outcome = self.state(client, current, claim).await?;
        let Outcome::Granted(permit) = outcome else {
            record_outcome(&outcome, report);
            return Ok(());
        };
        self.send(client, &binding, permit, report).await
    }

    async fn send(
        &self,
        client: &str,
        binding: &Binding,
        permit: Permit,
        report: &mut BackchannelLogoutDispatchReport,
    ) -> Result<(), String> {
        let current = self.target(client, report)?;
        let outcome = self
            .state(client, current, Command::Check(permit.clone()))
            .await?;
        let Outcome::Granted(permit) = outcome else {
            record_outcome(&outcome, report);
            return Ok(());
        };
        let Some(_timeout) = http::request_timeout(self.cfg, &permit, self.clock.now()) else {
            report.deferred += 1;
            return Ok(());
        };
        let result = self.request(binding, &permit, report).await?;
        let acknowledged = matches!(result, Completion::Delivered);
        let outcome = match self
            .state(
                client,
                Some(binding.clone()),
                Command::Complete(permit, result),
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                report.unknown_outcomes += 1;
                return Err(error);
            }
        };
        if acknowledged && matches!(outcome, Outcome::Completed) {
            report.delivered += 1;
        } else {
            if acknowledged {
                report.unknown_outcomes += 1;
            }
            report.delivery_failures += 1;
            record_outcome(&outcome, report);
        }
        Ok(())
    }
    async fn request(
        &self,
        binding: &Binding,
        permit: &Permit,
        report: &mut BackchannelLogoutDispatchReport,
    ) -> Result<Completion, String> {
        let timeout = http::request_timeout(self.cfg, permit, self.clock.now())
            .ok_or_else(|| "logout network interval exhausted".to_string())?;
        let request = self
            .http
            .post(&binding.uri)
            .timeout(timeout)
            .form(&[("logout_token", &permit.token)])
            .build();
        Ok(match request {
            Err(_) => Completion::Terminal,
            Ok(request) => {
                report.sent += 1;
                let response = self.http.execute(request).await;
                let now = self.clock.now();
                if now.duration_since(UNIX_EPOCH).ok().is_none_or(|time| {
                    time.as_secs() < permit.checked_at || time.as_secs() > i64::MAX as u64
                }) {
                    report.unknown_outcomes += 1;
                    return Err("logout response clock unavailable".to_string());
                }
                match response {
                    Ok(response) => {
                        http::classify(response.status().as_u16(), response.headers(), now)
                    }
                    Err(error) if error.is_builder() || error.is_redirect() => Completion::Terminal,
                    Err(_) => Completion::Recoverable { retry_after: None },
                }
            }
        })
    }
}
