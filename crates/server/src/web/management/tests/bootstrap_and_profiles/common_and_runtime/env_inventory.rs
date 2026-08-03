#[test]
fn management_env_literals_are_classified() {
    assert_env_inventory_complete_for_sources(
        &[
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/web/management.rs")),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/web/management/state.rs"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/web/management/state/config.rs"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/web/management/state/config/bootstrap_env.rs"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/web/management/state/runtime.rs"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/web/management/state/session_store.rs"
            )),
        ],
        MANAGEMENT_ENV_INVENTORY,
        &["AEGAEON_TEST_"],
        &[],
    );
}

#[test]
fn management_env_inventory_has_no_removed_runtime_policy_keys() {
    assert_eq!(
        keys_with_authority(
            MANAGEMENT_ENV_INVENTORY,
            EnvAuthority::RemovedRuntimePolicy,
        ),
        BTreeSet::new()
    );
}

#[test]
fn management_env_inventory_classifies_removed_cookie_secure_override() {
    assert_eq!(
        keys_with_authority(
            MANAGEMENT_ENV_INVENTORY,
            EnvAuthority::RemovedSystemBootstrap,
        ),
        BTreeSet::from(["AEGAEON_MANAGEMENT_COOKIE_SECURE"])
    );
}
