use super::{RuntimeRedisAtomicGroup, RuntimeStateNamespace};
use uuid::Uuid;

#[test]
fn redis_prefix_hash_tag_is_surface_local_by_default() {
    let namespace = RuntimeStateNamespace::from_environment_id(Uuid::nil());

    assert_eq!(
        namespace.redis_prefix("authcode", "v2"),
        "aegaeon:{runtime:00000000-0000-0000-0000-000000000000:surface:authcode}:v2"
    );
    assert_eq!(
        namespace.redis_prefix("token-store", "v3"),
        "aegaeon:{runtime:00000000-0000-0000-0000-000000000000:surface:token-store}:v3"
    );
    assert_ne!(
        redis_hash_tag(&namespace.redis_prefix("authcode", "v2")),
        redis_hash_tag(&namespace.redis_prefix("token-store", "v3"))
    );
}

#[test]
fn redis_atomic_group_prefix_co_locates_authorization_code_grant_surfaces() {
    let namespace = RuntimeStateNamespace::from_environment_id(Uuid::nil());
    let group = RuntimeRedisAtomicGroup::AuthorizationCodeGrant;

    let prefixes = [
        namespace.redis_atomic_group_prefix(group, "authcode", "v2"),
        namespace.redis_atomic_group_prefix(group, "token-store", "v3"),
        namespace.redis_atomic_group_prefix(group, "par", "v1"),
        namespace.redis_atomic_group_prefix(group, "request-object-jti", "replay:v1"),
        namespace.redis_atomic_group_prefix(group, "oidc-logout-session", "v3"),
    ];

    assert_eq!(
        prefixes[0],
        "aegaeon:{runtime:00000000-0000-0000-0000-000000000000:atomic:authorization-code-grant}:authcode:v2"
    );
    for prefix in prefixes.iter().skip(1) {
        assert_eq!(redis_hash_tag(&prefixes[0]), redis_hash_tag(prefix));
    }
}

fn redis_hash_tag(key: &str) -> &str {
    let start = key.find('{').expect("test key should contain hash tag") + 1;
    let end = key[start..]
        .find('}')
        .map(|offset| start + offset)
        .expect("test key should close hash tag");
    &key[start..end]
}
