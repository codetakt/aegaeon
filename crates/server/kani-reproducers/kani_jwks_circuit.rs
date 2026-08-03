#![cfg(kani)]

mod verification {
    use aegaeon_server::client_registry::{
        __circuit_allow_fetch, __circuit_force_half_open, __circuit_on_failure,
        __circuit_on_success, __circuit_phase, __circuit_reset,
    };

    // Invariants to check:
    // - After a failure over threshold, phase becomes Open (1)
    // - HalfOpen allows exactly one in-flight probe until success/failure resolves it
    // - allow_fetch implies phase is either Closed(0) or HalfOpen(2)
    #[kani::proof]
    fn jwks_circuit_basic_invariants() {
        // Configure aggressive thresholds to keep state space small
        std::env::set_var("AEGAEON_JWKS_CIRCUIT_OPEN_FAILS", "1");
        std::env::set_var("AEGAEON_JWKS_CIRCUIT_RESET_SECS", "1");

        let uri = "https://example.com/jwks.json";
        __circuit_reset(uri);

        // Single failure opens the circuit
        __circuit_on_failure(uri);
        let p = __circuit_phase(uri);
        kani::assert!(p == 1, "circuit should open after failure threshold");

        __circuit_force_half_open(uri);
        let allowed = __circuit_allow_fetch(uri);
        kani::assert!(allowed, "half-open circuit should allow the first probe");
        kani::assert!(
            !__circuit_allow_fetch(uri),
            "half-open circuit should reject a concurrent second probe"
        );
        __circuit_on_failure(uri);
        kani::assert!(__circuit_phase(uri) == 1, "half-open failure should reopen");

        __circuit_force_half_open(uri);
        let allowed_after_reopen = __circuit_allow_fetch(uri);
        kani::assert!(
            allowed_after_reopen,
            "new half-open probe should be available after reopening"
        );

        // Success should close the circuit
        __circuit_on_success(uri);
        let p2 = __circuit_phase(uri);
        kani::assert!(p2 == 0, "circuit should close after success");

        // Safety: whenever allow_fetch is true, phase is Closed or HalfOpen
        let allowed2 = __circuit_allow_fetch(uri);
        if allowed2 {
            let pp = __circuit_phase(uri);
            kani::assert!(pp == 0 || pp == 2, "allow_fetch implies Closed or HalfOpen");
        }
    }
}
