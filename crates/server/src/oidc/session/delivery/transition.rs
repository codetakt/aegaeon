use super::*;

pub(crate) fn transition(
    parent: &Parent,
    raw: Option<&str>,
    request: &Request,
    now: u64,
    fractional: bool,
) -> Result<Transition, String> {
    let identity = &request.identity;
    validation::validate_parent(parent, identity, now)?;
    let mut record: Option<Record> = raw
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| STORAGE_ERROR.to_string())?;
    if let Some(record) = &record {
        validation::validate_record(record, identity, parent, now)?;
    }
    // Retained success is still known after token expiry. This read-only result
    // is fenced by the original parent deadline and never authorizes a send.
    if now < parent.deadline
        && matches!(request.command, Command::Probe | Command::Claim { .. })
        && record.as_ref().is_some_and(|r| r.phase == Phase::Delivered)
    {
        return Ok(Transition {
            record: None,
            outcome: Outcome::AlreadyDelivered,
            valid_before: parent.deadline,
        });
    }
    let prior_record = record.clone();
    let horizon = record
        .as_ref()
        .and_then(|r| r.candidate.as_ref())
        .map_or(parent.deadline, |c| c.exp.min(parent.deadline));
    if now >= horizon {
        return Ok(Transition {
            record: None,
            outcome: Outcome::Terminal,
            valid_before: horizon,
        });
    }
    // Fence owner-driven operations before descriptor or budget mutations. A stale
    // preflight/completion must not change a newer owner's result or observation time.
    if let Command::Check(permit) | Command::Complete(permit, _) = &request.command {
        if !record
            .as_ref()
            .is_some_and(|r| matches_permit(r, permit, parent))
        {
            return Ok(Transition {
                record: None,
                outcome: Outcome::Deferred,
                valid_before: horizon,
            });
        }
    }
    if matches!(&request.command, Command::Check(permit) if now >= permit.deadline) {
        return Ok(Transition {
            record: None,
            outcome: Outcome::Deferred,
            valid_before: horizon,
        });
    }
    let mut valid_before = horizon;
    let outcome = if matches!(request.command, Command::Probe | Command::Claim { .. }) && record.as_ref().is_some_and(|r| r.phase == Phase::Terminal) {
        Outcome::Terminal
    } else if request.binding.is_none() || record.as_ref().is_some_and(|r| r.binding != request.binding) {
        let r = record.get_or_insert_with(|| Record { identity: identity.clone(), binding: None, candidate: None,
            phase: Phase::Terminal, attempts: 0, observed_at: now });
        r.phase = Phase::Terminal;
        r.observed_at = now;
        Outcome::Terminal
    } else if matches!(request.command, Command::Probe | Command::Claim { .. }) && record.as_ref().is_some_and(|r| r.attempts == 3 && matches!(r.phase, Phase::InFlight { deadline, .. } if deadline.checked_add(5).is_some_and(|due| now >= due))) {
        if let Some(r) = &mut record { r.phase = Phase::Terminal; }
        Outcome::Terminal
    } else {
        apply_command(&mut record, request, parent, now, fractional, &mut valid_before)?
    };
    if matches!(request.command, Command::Check(_) | Command::Complete(_, _))
        && matches!(outcome, Outcome::Deferred)
        && record == prior_record
    {
        return Ok(Transition {
            record: None,
            outcome,
            valid_before,
        });
    }
    if let Some(record) = &mut record {
        record.observed_at = now;
    }
    let serialized = record
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| STORAGE_ERROR.to_string())?;
    Ok(Transition {
        record: serialized,
        outcome,
        valid_before,
    })
}

fn apply_command(
    record: &mut Option<Record>,
    request: &Request,
    parent: &Parent,
    now: u64,
    fractional: bool,
    valid_before: &mut u64,
) -> Result<Outcome, String> {
    match &request.command {
        Command::Probe => Ok(if eligible(record.as_ref(), now)? {
            Outcome::Ready {
                needs_candidate: record.is_none(),
            }
        } else {
            Outcome::Deferred
        }),
        Command::Claim { .. } => claim(record, request, parent, now, valid_before),
        Command::Check(permit) => {
            let Some(record) = record.as_ref() else {
                return Ok(Outcome::Missing);
            };
            if matches_permit(record, permit, parent) && now < permit.deadline {
                *valid_before = permit.deadline;
                let mut permit = permit.clone();
                permit.checked_at = now;
                Ok(Outcome::Granted(permit))
            } else {
                Ok(Outcome::Deferred)
            }
        }
        Command::Complete(permit, result) => {
            let Some(record) = record.as_mut() else {
                return Ok(Outcome::Missing);
            };
            if !matches_permit(record, permit, parent) {
                return Ok(Outcome::Deferred);
            }
            record.phase =
                completion_phase(result, record.attempts, now, fractional, permit.horizon)?;
            record.observed_at = now;
            Ok(match record.phase {
                Phase::Delivered => Outcome::Completed,
                Phase::Retry { .. } => Outcome::Deferred,
                _ => Outcome::Terminal,
            })
        }
    }
}

fn claim(
    record: &mut Option<Record>,
    request: &Request,
    parent: &Parent,
    now: u64,
    valid_before: &mut u64,
) -> Result<Outcome, String> {
    let Command::Claim {
        candidate,
        owner,
        timeout,
    } = &request.command
    else {
        return Err(STORAGE_ERROR.to_string());
    };

    if !eligible(record.as_ref(), now)? {
        return Ok(Outcome::Deferred);
    }
    if owner.trim().is_empty() || *timeout == 0 || *timeout > 60 {
        return Err(STORAGE_ERROR.to_string());
    }
    if record.is_none() {
        let Some(candidate) = candidate.clone() else {
            return Ok(Outcome::Deferred);
        };
        let binding = request
            .binding
            .clone()
            .ok_or_else(|| STORAGE_ERROR.to_string())?;
        validation::validate_candidate(&candidate, &request.identity, &binding)?;
        if candidate.iat > now || candidate.iat < parent.logged_out_at || candidate.exp <= now {
            return Err(STORAGE_ERROR.to_string());
        }
        *record = Some(Record {
            identity: request.identity.clone(),
            binding: Some(binding),
            candidate: Some(candidate),
            phase: Phase::Terminal,
            attempts: 0,
            observed_at: now,
        });
    }
    let record = record.as_mut().ok_or_else(|| STORAGE_ERROR.to_string())?;
    let candidate = record
        .candidate
        .as_ref()
        .ok_or_else(|| STORAGE_ERROR.to_string())?;
    let horizon = candidate.exp.min(parent.deadline);
    let deadline = now
        .checked_add(*timeout)
        .and_then(|n| n.checked_add(5))
        .ok_or_else(|| STORAGE_ERROR.to_string())?
        .min(horizon);
    if deadline <= now {
        return Ok(Outcome::Terminal);
    }
    record.attempts = record
        .attempts
        .checked_add(1)
        .filter(|n| *n <= 3)
        .ok_or_else(|| STORAGE_ERROR.to_string())?;
    record.observed_at = now;
    record.phase = Phase::InFlight {
        owner: owner.clone(),
        deadline,
    };
    *valid_before = deadline;
    Ok(Outcome::Granted(Permit {
        owner: owner.clone(),
        attempt: record.attempts,
        deadline,
        horizon,
        checked_at: now,
        token: candidate.token.clone(),
        retention_deadline: None,
    }))
}

fn eligible(record: Option<&Record>, now: u64) -> Result<bool, String> {
    let Some(record) = record else {
        return Ok(true);
    };
    if record.attempts >= 3 {
        return Ok(false);
    }
    Ok(match record.phase {
        Phase::Retry { due } => now >= due,
        Phase::InFlight { deadline, .. } => {
            now >= deadline
                .checked_add(5)
                .ok_or_else(|| STORAGE_ERROR.to_string())?
        }
        _ => false,
    })
}

fn matches_permit(record: &Record, permit: &Permit, parent: &Parent) -> bool {
    record.attempts == permit.attempt
        && record.candidate.as_ref().is_some_and(|c| {
            c.token == permit.token && permit.horizon == c.exp.min(parent.deadline)
        })
        && matches!(&record.phase, Phase::InFlight { owner, deadline } if *owner == permit.owner && *deadline == permit.deadline)
}

fn completion_phase(
    result: &Completion,
    attempt: u8,
    now: u64,
    fractional: bool,
    horizon: u64,
) -> Result<Phase, String> {
    Ok(match result {
        Completion::Delivered => Phase::Delivered,
        Completion::Terminal => Phase::Terminal,
        Completion::Recoverable { retry_after } if attempt < 3 => {
            let minimum = now
                .checked_add(u64::from(fractional))
                .and_then(|n| n.checked_add(if attempt == 1 { 5 } else { 10 }))
                .ok_or_else(|| STORAGE_ERROR.to_string())?;
            let due = retry_after.map_or(minimum, |date| date.max(minimum));
            if due < horizon {
                Phase::Retry { due }
            } else {
                Phase::Terminal
            }
        }
        Completion::Recoverable { .. } => Phase::Terminal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_delivery_fractional_failure_preserves_minimum_delay() {
        let failure = Completion::Recoverable { retry_after: None };
        for (attempt, delay) in [(1, 5), (2, 10)] {
            assert!(
                matches!(completion_phase(&failure, attempt, 100, false, 200), Ok(Phase::Retry { due }) if due == 100 + delay)
            );
            assert!(
                matches!(completion_phase(&failure, attempt, 100, true, 200), Ok(Phase::Retry { due }) if due == 101 + delay)
            );
            assert!(matches!(
                completion_phase(&failure, attempt, 100, true, 101 + delay),
                Ok(Phase::Terminal)
            ));
        }
    }
}
