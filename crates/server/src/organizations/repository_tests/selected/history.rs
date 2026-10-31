use super::*;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and actual witness; historical custody without authority"]
async fn pg_organizations_retained_history_validates_without_live_authority() -> TestResult {
    let f = Fixture::new().await?;
    let result = exercise(&f).await;
    f.cleanup(result).await
}

async fn exercise(f: &Fixture) -> TestResult {
    let records = crate::organizations::witness::tests::scope_fixture::with_environment(
        f.env.environment_id,
        async {
            consent::setup(f).await?;
            let root = consent::capture(f, &consent::request(f))
                .await?
                .bind("history", 1000)?;
            let selection = select(f, &root).await?;
            Ok::<_, Box<dyn std::error::Error>>((root, selection))
        },
    )
    .await
    .map_err(|error| format!("{error:#}"))??;
    let (root, selection) = records;
    assert!(crate::organizations::request_work::async_store::current_owner().is_err());
    for version in [1, 2] {
        let mut historical_root = root.clone();
        let mut historical = selection.clone();
        if version == 1 {
            historical_root.consent.version = 1;
            historical_root.consent.epoch = None;
            historical.version = 1;
            historical.epoch = None;
            assert!(historical_root.consent.bind("new-root", 1000).is_err());
        }
        let before = serde_json::to_value((&historical_root, &historical))?;
        historical.validate_history_binding(
            &historical_root,
            &historical_root.ceiling.binding,
            120,
        )?;
        assert!(historical
            .validate_binding(&historical_root, &historical_root.ceiling.binding, 120)
            .is_err());
        assert_eq!(
            before,
            serde_json::to_value((&historical_root, &historical))?
        );
        historical
            .decision
            .privileges
            .insert("documents.write".into());
        assert!(historical
            .validate_history_binding(&historical_root, &historical_root.ceiling.binding, 120)
            .is_err());
    }
    let mut mismatched = selection.clone();
    mismatched.version = 1;
    assert!(mismatched
        .validate_history_binding(&root, &root.ceiling.binding, 120)
        .is_err());
    Ok(())
}
