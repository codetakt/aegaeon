use super::*;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

pub(in crate::organizations) fn offsets(bytes: &[u8]) -> Vec<u8> {
    let mut rows = records(bytes);
    for row in &mut rows {
        if row["record"] != "row" {
            continue;
        }
        for name in ["created_at", "updated_at", "recorded_at"] {
            if let Some(text) = row["data"][name].as_str() {
                let date = OffsetDateTime::parse(text, &Rfc3339).unwrap();
                row["data"][name] = json!(date
                    .to_offset(UtcOffset::from_hms(9, 0, 0).unwrap())
                    .format(&Rfc3339)
                    .unwrap());
            }
        }
    }
    reframe(rows)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; export works independently of session date presentation"]
async fn pg_organizations_snapshot_timestamps_ignore_session_presentation() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let mut tx = f.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql("SET LOCAL timezone='Asia/Tokyo'; SET LOCAL datestyle='SQL, DMY'")
            .execute(&mut *tx)
            .await?;
        let mut reader = Reader::start(&mut tx, f.organization.scope).await?;
        let mut bytes = reader.header_line()?;
        while let Some(page) = reader.next(&mut tx).await? {
            for row in page {
                bytes.extend(row);
            }
        }
        bytes.extend(reader.manifest_line()?);
        tx.rollback().await?;
        let rows = records(&bytes);
        let mut timestamps = 0;
        for row in &rows {
            if row["record"] != "row" {
                continue;
            }
            for key in ["created_at", "updated_at", "recorded_at"] {
                if let Some(text) = row["data"][key].as_str() {
                    let parsed = OffsetDateTime::parse(text, &Rfc3339)?;
                    assert_eq!(
                        parsed.offset(),
                        UtcOffset::UTC,
                        "native export has stable UTC values"
                    );
                    timestamps += 1;
                }
            }
        }
        assert!(timestamps > 0);
        inspect(&f, &bytes).await?;
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; historical RFC3339 offsets retain instants without accepting drift"]
async fn pg_organizations_snapshot_timestamps_compare_instants_and_reject_drift() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let (original, scope) = target::prospective(&f).await?;
        let source = offsets(&original);
        let (connection, runtime) = target::maintenance().await?;
        let input = Input::new(Cursor::new(&source), scope, &sha256_hex(&source))?;
        staging::inspect_target(connection, input, &runtime).await?;
        let mut changed = records(&source);
        let row = changed
            .iter_mut()
            .find(|r| r["section"] == "identities")
            .ok_or("identity")?;
        let date = OffsetDateTime::parse(
            row["data"]["created_at"].as_str().ok_or("timestamp")?,
            &Rfc3339,
        )?;
        row["data"]["created_at"] =
            json!((date + time::Duration::microseconds(1)).format(&Rfc3339)?);
        let changed = reframe(changed);
        let (connection, runtime) = target::maintenance().await?;
        let input = Input::new(Cursor::new(&changed), scope, &sha256_hex(&changed))?;
        assert!(
            staging::inspect_target(connection, input, &runtime)
                .await
                .is_err(),
            "one microsecond is real drift"
        );
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; refuse sub-microsecond source before inactive writes"]
async fn pg_organizations_snapshot_timestamps_refuse_unrepresentable_precision() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let source = export(&f).await?;
        let mut rows = records(&source);
        let row = rows
            .iter_mut()
            .find(|r| r["section"] == "organizations")
            .ok_or("organization")?;
        let date = OffsetDateTime::parse(
            row["data"]["created_at"].as_str().ok_or("timestamp")?,
            &Rfc3339,
        )?;
        row["data"]["created_at"] =
            json!((date + time::Duration::nanoseconds(1)).format(&Rfc3339)?);
        assert!(
            inspect(&f, &reframe(rows)).await.is_err(),
            "database rounding cannot preserve this instant"
        );
        inspect(&f, &source).await?;
        Ok(())
    }
    .await;
    f.cleanup(result).await
}
