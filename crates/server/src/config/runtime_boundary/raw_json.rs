use crate::config::ConfigError;
use aegaeon_jose::raw_json::{
    raw_json_backend_env_var, raw_json_backend_env_var_for_surface, ALL_RAW_JSON_SURFACES,
};
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

const RAW_JSON_BACKEND_ENV_PREFIX: &str = "AEGAEON_RAW_JSON_BACKEND";
const RAW_JSON_BACKEND_GENERIC_OBJECT_ENV: &str = "AEGAEON_RAW_JSON_BACKEND_GENERIC_OBJECT";

fn raw_json_backend_override_env_keys() -> BTreeSet<&'static str> {
    [
        raw_json_backend_env_var(),
        RAW_JSON_BACKEND_GENERIC_OBJECT_ENV,
    ]
    .into_iter()
    .chain(
        ALL_RAW_JSON_SURFACES
            .iter()
            .copied()
            .map(raw_json_backend_env_var_for_surface),
    )
    .collect()
}

fn configured_known_raw_json_backend_override_env_keys(
    keys: &BTreeSet<&'static str>,
) -> Result<Vec<&'static str>, ConfigError> {
    keys.iter()
        .copied()
        .filter_map(|key| match env::var(key) {
            Ok(_) => Some(Ok(key)),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => Some(Err(ConfigError::NonUnicode {
                key: key.to_string(),
            })),
        })
        .collect()
}

#[cfg(unix)]
fn raw_json_backend_env_key_has_prefix(key: &OsStr) -> bool {
    key.as_bytes()
        .starts_with(RAW_JSON_BACKEND_ENV_PREFIX.as_bytes())
}

#[cfg(not(unix))]
fn raw_json_backend_env_key_has_prefix(key: &OsStr) -> bool {
    key.to_str()
        .is_some_and(|key| key.starts_with(RAW_JSON_BACKEND_ENV_PREFIX))
}

fn configured_raw_json_backend_override_env_key(
    keys: &BTreeSet<&'static str>,
    key: &OsStr,
) -> Option<String> {
    if !raw_json_backend_env_key_has_prefix(key) {
        return None;
    }

    let display_key = key.to_string_lossy();
    (!keys.contains(display_key.as_ref())).then(|| display_key.into_owned())
}

fn configured_unknown_raw_json_backend_override_env_keys(
    keys: &BTreeSet<&'static str>,
    env_keys: impl Iterator<Item = impl AsRef<OsStr>>,
) -> Vec<String> {
    env_keys
        .filter_map(|key| configured_raw_json_backend_override_env_key(keys, key.as_ref()))
        .collect()
}

pub(in crate::config) fn reject_raw_json_backend_override_envs() -> Result<(), ConfigError> {
    let known_keys = raw_json_backend_override_env_keys();
    let mut configured = configured_known_raw_json_backend_override_env_keys(&known_keys)?
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let process_env_keys = env::vars_os().map(|(key, _)| key).collect::<Vec<_>>();
    configured.extend(configured_unknown_raw_json_backend_override_env_keys(
        &known_keys,
        process_env_keys.iter(),
    ));
    configured.sort();
    configured.dedup();

    if configured.is_empty() {
        return Ok(());
    }

    Err(ConfigError::InvalidValue {
        key: configured[0].clone(),
        value: "<configured>".to_string(),
        reason: format!(
            "raw JSON backend selection is fixed by the server release claim boundary; remove raw JSON backend override environment variables: {}",
            configured.join(", ")
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn inventory_includes_global_generic_and_all_jose_surface_overrides() {
        let keys = raw_json_backend_override_env_keys();

        assert!(keys.contains(raw_json_backend_env_var()));
        assert!(keys.contains(RAW_JSON_BACKEND_GENERIC_OBJECT_ENV));
        for surface in ALL_RAW_JSON_SURFACES {
            assert!(keys.contains(raw_json_backend_env_var_for_surface(surface)));
        }
    }

    #[test]
    fn unknown_prefixed_overrides_are_rejected_by_inventory_scan() {
        let known = raw_json_backend_override_env_keys();
        let future_surface = format!("{}_FUTURE_SURFACE", RAW_JSON_BACKEND_ENV_PREFIX);
        let unrelated = format!("{}_OTHER", "AEGAEON");
        let configured = configured_unknown_raw_json_backend_override_env_keys(
            &known,
            [
                OsStr::new(future_surface.as_str()),
                OsStr::new("AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER"),
                OsStr::new(unrelated.as_str()),
            ]
            .into_iter(),
        );

        assert_eq!(configured, vec![future_surface]);
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_prefixed_override_names_are_rejected_by_inventory_scan() {
        let _lock = crate::util::SERVER_TEST_ENV_GUARD
            .lock()
            .expect("server test env guard should not be poisoned");
        let known = raw_json_backend_override_env_keys();
        let key =
            OsString::from_vec([RAW_JSON_BACKEND_ENV_PREFIX.as_bytes(), b"_", &[0x80_u8]].concat());
        std::env::set_var(&key, "serde-compat");

        let result = reject_raw_json_backend_override_envs();

        std::env::remove_var(&key);

        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidValue { key: err_key, reason, .. })
                    if err_key.starts_with(RAW_JSON_BACKEND_ENV_PREFIX)
                        && !known.contains(err_key.as_str())
                        && reason.contains("raw JSON backend selection is fixed")
            ),
            "non-Unicode prefixed raw JSON backend env names must fail closed"
        );
    }
}
