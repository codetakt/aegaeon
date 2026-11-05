use super::*;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; real operator receipt sentinel survives export/import"]
async fn pg_organizations_import_source_preserves_operator_receipt_registration_sentinel(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        super::super::operators::principal(&f).await?;
        super::super::operators::grant(&f, json!(["provision"])).await?;
        let mut tx = f.pool.begin().await?;
        crate::organizations::commands::apply_operator_command(
            &mut tx,
            f.organization.scope,
            f.env.team_id,
            &f.actor,
            "retained-import-receipt",
            &crate::organizations::commands::Command::Create {
                external_id: "import-receipt-É".into(),
            },
        )
        .await?;
        tx.commit().await?;
        let bytes = export(&f).await?;
        let original = records(&bytes);
        let receipt = original
            .iter()
            .find(|r| r["section"] == "receipts")
            .expect("real command stored receipt");
        assert_eq!(receipt["data"]["actor_kind"], "operator");
        assert_eq!(
            receipt["data"]["client_registration_id"],
            Uuid::nil().to_string()
        );
        assert!(
            inspect(&f, &bytes).await.is_ok(),
            "producer's operator sentinel is a valid retained record"
        );
        for (field, value) in [
            ("client_registration_id", json!(Uuid::new_v4())),
            ("client_registration_id", Value::Null),
            ("actor_kind", json!("member")),
        ] {
            let mut changed = original.clone();
            changed
                .iter_mut()
                .find(|r| r["section"] == "receipts")
                .unwrap()["data"][field] = value;
            assert!(
                inspect(&f, &reframe(changed)).await.is_err(),
                "sentinel is exclusive to operator receipts"
            );
        }
        assert!(inspect(&f, &bytes).await.is_ok());
        Ok(())
    }
    .await;
    f.cleanup(result).await
}
