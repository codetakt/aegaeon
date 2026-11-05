//! A diagnostic label; never an authority, completion or recovery capability.
use super::Scope;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use uuid::Uuid;

pub(super) fn label(
    scope: Scope,
    epoch: Uuid,
    worker: Uuid,
    slot: i32,
    generation: i64,
    principal: &str,
) -> String {
    let mut input = b"aegaeon-work-attribution-v1\0".to_vec();
    for id in [scope.environment_id, scope.deployment_id, epoch, worker] {
        input.extend_from_slice(id.as_bytes());
    }
    input.extend_from_slice(&slot.to_be_bytes());
    input.extend_from_slice(&generation.to_be_bytes());
    input.extend_from_slice(principal.as_bytes());
    URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(&input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_attribution_v1_matches_independent_utf8_and_maximum_counter_vector() {
        let scope = Scope {
            environment_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            deployment_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
        };
        let actual = label(
            scope,
            Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
            Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
            63,
            i64::MAX,
            "実行者",
        );
        assert_eq!(actual, "KXdX88ktPTXCCcWVUqHF8ig3q9VBEF07rrb1Vm8GmH0");
    }
}
