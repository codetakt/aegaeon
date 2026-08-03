use super::*;

#[test]
fn removed_unshared_runtime_state_acknowledgement_env_is_rejected() -> ConfigTestResult {
    let _lock = env_lock();
    let _removed = EnvVarGuard::new(REMOVED_UNSHARED_RUNTIME_STATE_ENV, Some("1"));

    let err = must_err!(
        RuntimeStateBoundaryConfig::try_from_env(),
        "removed unshared runtime-state acknowledgement must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, reason, .. }
            if key == REMOVED_UNSHARED_RUNTIME_STATE_ENV
                && reason.contains("legacy acknowledgement was removed")
    ));
    Ok(())
}

#[test]
fn removed_ephemeral_runtime_state_acknowledgement_env_is_rejected() -> ConfigTestResult {
    let _lock = env_lock();
    let _removed = EnvVarGuard::new(REMOVED_EPHEMERAL_RUNTIME_STATE_ENV, Some("1"));

    let err = must_err!(
        RuntimeStateBoundaryConfig::try_from_env(),
        "removed ephemeral runtime-state acknowledgement must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, reason, .. }
            if key == REMOVED_EPHEMERAL_RUNTIME_STATE_ENV
                && reason.contains("legacy ephemeral runtime-state acknowledgement was removed")
    ));
    Ok(())
}
