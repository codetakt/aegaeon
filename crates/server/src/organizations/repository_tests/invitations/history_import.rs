use super::super::import::{export, inspect, records, reframe};
use super::*;
use serde_json::json;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; actual invitation/challenge/acceptance history"]
async fn pg_organizations_import_historical_invitation_and_challenge_bindings() -> TestResult {
    let f = InvitationFixture::new().await?;
    let result = async {
        let (id, secret, challenge, proof) = f.prepared().await?;
        let pending = export(&f.base).await?;
        assert!(inspect(&f.base, &pending).await.is_ok());
        let input = f.acceptance(id, &secret, challenge, &proof);
        let mut tx = f.base.pool.begin().await?;
        invite::accept_first_admin(&mut tx, &input).await?;
        tx.commit().await?;
        let bytes = export(&f.base).await?;
        assert!(
            inspect(&f.base, &bytes).await.is_ok(),
            "completed history remains valid without live credentials"
        );
        for (section, pointer, value) in [
            ("invitations", "/data/authority/grant", json!(Uuid::nil())),
            ("invitations", "/data/authority/grant_revision", json!(0)),
            ("invitations", "/data/authority/actor/kind", json!("member")),
            (
                "invitations",
                "/data/authority/role_versions/admin",
                json!(0),
            ),
            ("invitations", "/data/result/state", json!("removed")),
            (
                "invitations",
                "/data/result/roles",
                json!(["admin", "admin"]),
            ),
            (
                "challenges",
                "/data/recipient_binding/identity_revision",
                json!(0),
            ),
            (
                "challenges",
                "/data/recipient_binding/binding/scope/domain_id",
                json!(Uuid::new_v4()),
            ),
            (
                "challenges",
                "/data/recipient_binding/auth_time",
                json!(500),
            ),
            (
                "challenges",
                "/data/recipient_binding/expires_at",
                json!(103),
            ),
        ] {
            let mut changed = records(&bytes);
            let (position, row) = changed
                .iter_mut()
                .enumerate()
                .find(|(_, r)| r["section"] == section)
                .unwrap();
            *row.pointer_mut(pointer)
                .expect("actual serialized history field") = value;
            let error = inspect(&f.base, &reframe(changed))
                .await
                .expect_err("corrupt retained authority");
            let diagnostic = error.to_string();
            assert!(
                diagnostic.contains(&format!("row {} ({section})", position + 1)),
                "{diagnostic}"
            );
            assert!(diagnostic.contains("source row semantics"), "{diagnostic}");
            assert!(!diagnostic.contains(&f.recipient.binding.subject));
            assert!(!diagnostic.contains("Invitee+Test"));
        }
        assert!(inspect(&f.base, &bytes).await.is_ok());
        Ok(())
    }
    .await;
    f.base.cleanup(result).await
}
