use super::super::import::{export, inspect, records, reframe};
use super::*;
use serde_json::json;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; inactive pending and completed capability history round trip"]
async fn pg_organizations_import_inactive_invitation_history_round_trip() -> TestResult {
    use super::super::import::{export_scope, inactive};
    let f = InvitationFixture::new().await?;
    let result = async {
        let (id, secret, challenge, proof) = f.prepared().await?;
        let original_hash: Vec<u8> = sqlx::query_scalar(
            "SELECT capability_hash FROM aegaeon.organization_invitations WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&f.base.pool)
        .await?;
        for accepted in [false, true] {
            if accepted {
                let mut tx = f.base.pool.begin().await?;
                invite::accept_first_admin(&mut tx, &f.acceptance(id, &secret, challenge, &proof))
                    .await?;
                tx.commit().await?;
            }
            let (bytes, scope) = inactive::prospective(&f.base).await?;
            inactive::prepare(&bytes, scope, Uuid::new_v4()).await?;
            // An explicitly owned fixture read compares stored nonsecret data;
            // it does not bypass or represent the authenticated export endpoint.
            let restored = records(&export_scope(&f.base.pool, scope).await?);
            let mut expected = records(&bytes);
            for row in &mut expected {
                if row["section"] == "domain" {
                    row["data"]["enabled"] = json!(false);
                }
            }
            let rows = |records: Vec<serde_json::Value>| {
                records
                    .into_iter()
                    .filter(|r| r["record"] == "row")
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                rows(restored),
                rows(expected.clone()),
                "all disclosed fields and permanent dependencies survive"
            );
            let invitation = expected
                .iter()
                .find(|r| r["section"] == "invitations")
                .ok_or("invitation")?;
            assert_eq!(
                invitation["data"]["state"],
                if accepted { "accepted" } else { "pending" }
            );
            let destination_id = invitation["data"]["id"]
                .as_str()
                .ok_or("id")?
                .parse::<Uuid>()?;
            let destination_hash: Vec<u8> = sqlx::query_scalar(
                "SELECT capability_hash FROM aegaeon.organization_invitations WHERE id=$1",
            )
            .bind(destination_id)
            .fetch_one(&f.base.pool)
            .await?;
            assert_eq!(destination_hash.len(), 32);
            assert_ne!(
                destination_hash, original_hash,
                "no original capability hash transfer"
            );
            assert!(!String::from_utf8(bytes)?.contains(&secret));
        }
        Ok(())
    }
    .await;
    f.base.cleanup(result).await
}

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
