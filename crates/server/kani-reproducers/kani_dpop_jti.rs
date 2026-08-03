#![cfg(kani)]

mod verification {
    use aegaeon_server::middleware::dpop::{DpopError, DpopMiddleware};

    #[kani::proof]
    fn dpop_jti_replay_rejected() {
        let mw = DpopMiddleware::new_process_local_for_tests();
        // First use succeeds
        let r1 = mw.check_and_store_jti("jti-1");
        kani::assert!(r1.is_ok(), "first use should succeed");

        // Replay is rejected
        let r2 = mw.check_and_store_jti("jti-1");
        kani::assert!(
            matches!(r2, Err(DpopError::Replay)),
            "replay must be rejected"
        );

        // Different JTI still succeeds
        let r3 = mw.check_and_store_jti("jti-2");
        kani::assert!(r3.is_ok(), "different jti should succeed");
    }
}
