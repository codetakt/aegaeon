use aegaeon_jose::algorithms::CryptoProfile;
use aegaeon_jose::REQUEST_OBJECT_SIGNING_ALGORITHMS;

use super::alg_allowed_with_promoted_rsa;

pub(crate) fn advertised_request_object_signing_algs(profile: CryptoProfile) -> Vec<String> {
    REQUEST_OBJECT_SIGNING_ALGORITHMS
        .iter()
        .map(|algorithm| algorithm.name())
        .filter(|name| alg_allowed_with_promoted_rsa(name, profile))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use aegaeon_jose::{
        request_object_signing_algorithm_supported, REQUEST_OBJECT_SIGNING_ALGORITHMS,
    };

    #[test]
    fn advertised_request_object_inventory_matches_verifier_inventory() {
        for algorithm in REQUEST_OBJECT_SIGNING_ALGORITHMS {
            assert!(request_object_signing_algorithm_supported(
                algorithm.jwt_algorithm()
            ));
        }
    }
}
