#[cfg(kani)]
mod kani_tests {
    use crate::config::{
        valid_client_assertion_replay_window_secs, MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS,
    };
    use crate::oidc::session::{
        normalize_logout_session_ttl_secs, BoundedKaniSessionStore, MAX_LOGOUT_SESSION_TTL_SECS,
    };
    use kani::proof;

    #[proof]
    fn verify_client_assertion_replay_window_bounds() {
        let value: i64 = kani::any();
        let valid = valid_client_assertion_replay_window_secs(value);
        kani::assert(
            valid == (value > 0 && value <= MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS),
            "client assertion replay window admits exactly the bounded positive range",
        );
    }

    #[proof]
    fn verify_oidc_logout_ttl_normalization_bounds() {
        let value: u64 = kani::any();
        let normalized = normalize_logout_session_ttl_secs(value);
        kani::assert(normalized >= 1, "normalized logout TTL is positive");
        kani::assert(
            normalized <= MAX_LOGOUT_SESSION_TTL_SECS,
            "normalized logout TTL is bounded",
        );
        if value >= 1 && value <= MAX_LOGOUT_SESSION_TTL_SECS {
            kani::assert(
                normalized == value,
                "in-range logout TTL values are preserved",
            );
        }
    }

    #[proof]
    #[kani::unwind(8)]
    fn verify_oidc_logout_idempotent_jti() {
        let mut store = BoundedKaniSessionStore::new_with_ttl(10);
        let user_id = 1;
        let Some(sid) = store.get_or_create_session(user_id, 1) else {
            kani::assert(false, "bounded model has capacity for one session");
            return;
        };

        kani::assert(store.add_client(sid, 1), "first client insert succeeds");
        kani::assert(store.add_client(sid, 2), "second client insert succeeds");

        let Some(first) = store.logout_by_sid_at(sid, 0) else {
            kani::assert(false, "initial logout must succeed");
            return;
        };

        let Some(second) = store.logout_by_sid_at(sid, 1) else {
            kani::assert(false, "logout retry must succeed");
            return;
        };

        kani::assert(first.jti == second.jti, "logout jti must be stable per sid");
        kani::assert(
            first.client_ids == second.client_ids,
            "client list must be stable",
        );

        let by_user = store.logout_by_user(user_id);
        kani::assert(
            by_user.is_none(),
            "auth-session mapping is removed after sid logout",
        );
    }

    #[proof]
    #[kani::unwind(8)]
    fn verify_oidc_same_user_distinct_auth_sessions_have_distinct_sids() {
        let mut store = BoundedKaniSessionStore::new_with_ttl(10);
        let user_id = 1;

        let Some(sid1) = store.get_or_create_session(user_id, 1) else {
            kani::assert(false, "bounded model has capacity for initial auth session");
            return;
        };
        let Some(sid2) = store.get_or_create_session(user_id, 2) else {
            kani::assert(false, "bounded model has capacity for second auth session");
            return;
        };
        let Some(sid1_again) = store.get_or_create_session(user_id, 1) else {
            kani::assert(false, "bounded model can reload initial auth session");
            return;
        };

        kani::assert(
            sid1 != sid2,
            "different auth sessions for the same user receive different OIDC sids",
        );
        kani::assert(
            sid1 == sid1_again,
            "same auth session reuses its OIDC sid while live",
        );
    }

    #[proof]
    #[kani::unwind(8)]
    fn verify_oidc_logout_session_rotates_after_logout() {
        let mut store = BoundedKaniSessionStore::new_with_ttl(10);
        let user_id = 1;

        let Some(sid1) = store.get_or_create_session(user_id, 1) else {
            kani::assert(false, "bounded model has capacity for initial session");
            return;
        };
        kani::assert(
            store.logout_by_sid_at(sid1, 0).is_some(),
            "logout must succeed",
        );

        let Some(sid2) = store.get_or_create_session(user_id, 1) else {
            kani::assert(false, "bounded model has capacity for rotated session");
            return;
        };
        kani::assert(sid1 != sid2, "new session must rotate sid after logout");
    }

    #[proof]
    #[kani::unwind(8)]
    fn verify_oidc_logout_session_ttl_prunes_logged_out_entries() {
        let ttl = 10;
        let mut store = BoundedKaniSessionStore::new_with_ttl(ttl);
        let user_id = 1;

        let Some(sid) = store.get_or_create_session(user_id, 1) else {
            kani::assert(false, "bounded model has capacity for one session");
            return;
        };
        kani::assert(
            store.logout_by_sid_at(sid, 0).is_some(),
            "logout must succeed",
        );

        store.prune_expired_at(ttl + 1);

        let after_prune = store.logout_by_sid_at(sid, ttl + 2);
        kani::assert(
            after_prune.is_none(),
            "logged-out session must be pruned after ttl",
        );
    }

    #[proof]
    #[kani::unwind(8)]
    fn verify_oidc_logout_future_timestamp_prunes_fail_closed() {
        let ttl = 10;
        let mut store = BoundedKaniSessionStore::new_with_ttl(ttl);
        let user_id = 1;

        let Some(sid) = store.get_or_create_session(user_id, 1) else {
            kani::assert(false, "bounded model has capacity for one session");
            return;
        };
        kani::assert(
            store.logout_by_sid_at(sid, ttl).is_some(),
            "logout must succeed",
        );

        store.prune_expired_at(ttl - 1);

        let after_prune = store.logout_by_sid_at(sid, ttl);
        kani::assert(
            after_prune.is_none(),
            "future-dated logged-out session must be pruned fail-closed",
        );
    }

    #[proof]
    #[kani::unwind(8)]
    fn verify_oidc_logout_capacity_fails_closed_without_overwrite() {
        let mut store = BoundedKaniSessionStore::new_with_ttl(10);

        let Some(sid1) = store.get_or_create_session(1, 1) else {
            kani::assert(false, "first bounded session insert succeeds");
            return;
        };
        let Some(sid2) = store.get_or_create_session(2, 2) else {
            kani::assert(false, "second bounded session insert succeeds");
            return;
        };
        let Some(sid3) = store.get_or_create_session(3, 3) else {
            kani::assert(false, "third bounded session insert succeeds");
            return;
        };
        let Some(sid4) = store.get_or_create_session(4, 4) else {
            kani::assert(false, "fourth bounded session insert succeeds");
            return;
        };

        kani::assert(
            store.get_or_create_session(5, 5).is_none(),
            "full bounded model must fail closed",
        );
        kani::assert(
            store.mapped_sid(1) == Some(sid1) && store.session_exists(sid1),
            "first session mapping is preserved when full",
        );
        kani::assert(
            store.mapped_sid(2) == Some(sid2) && store.session_exists(sid2),
            "second session mapping is preserved when full",
        );
        kani::assert(
            store.mapped_sid(3) == Some(sid3) && store.session_exists(sid3),
            "third session mapping is preserved when full",
        );
        kani::assert(
            store.mapped_sid(4) == Some(sid4) && store.session_exists(sid4),
            "fourth session mapping is preserved when full",
        );
    }

    #[proof]
    #[kani::unwind(8)]
    fn verify_oidc_logout_client_capacity_fails_closed_without_overwrite() {
        let mut store = BoundedKaniSessionStore::new_with_ttl(10);
        let Some(sid) = store.get_or_create_session(1, 1) else {
            kani::assert(false, "bounded model has capacity for one session");
            return;
        };

        kani::assert(store.add_client(sid, 1), "first client insert succeeds");
        kani::assert(store.add_client(sid, 2), "second client insert succeeds");
        kani::assert(store.add_client(sid, 3), "third client insert succeeds");
        kani::assert(store.add_client(sid, 4), "fourth client insert succeeds");
        let before = store.client_ids_for(sid);

        kani::assert(
            !store.add_client(sid, 5),
            "full client set must fail closed",
        );
        kani::assert(
            before == store.client_ids_for(sid),
            "full client set preserves existing clients",
        );
    }
}
