use super::*;
use crate::organizations::{
    request_work::{async_store, CapacityClass},
    witness::creation::{
        primary::{self, Mutation, MutationFuture},
        Input, Kind, Receipt,
    },
};
use sqlx::{Postgres, Transaction};

struct Create {
    environment: Uuid,
    reject: bool,
}
impl Mutation for Create {
    type Output = Uuid;
    type Error = sqlx::Error;
    fn apply<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipt: &'a Receipt,
    ) -> MutationFuture<'a, Uuid, sqlx::Error> {
        Box::pin(async move {
            sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')")
                .bind(receipt.owner_id()).bind(self.environment).bind(receipt.subject()).execute(&mut **tx).await?;
            Ok(receipt.owner_id())
        })
    }
    fn recheck<'a>(
        &'a self,
        _tx: &'a mut Transaction<'_, Postgres>,
    ) -> MutationFuture<'a, (), sqlx::Error> {
        Box::pin(async move {
            if self.reject {
                Err(sqlx::Error::Protocol("fixture final refusal".into()))
            } else {
                Ok(())
            }
        })
    }
    fn replay<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipt: &'a Receipt,
    ) -> MutationFuture<'a, Uuid, sqlx::Error> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT id FROM aegaeon.end_users WHERE id=$1 AND environment_id=$2 AND status='ACTIVE'")
                .bind(receipt.owner_id()).bind(self.environment).fetch_one(&mut **tx).await
        })
    }
}
fn input(selector: u8, payload: u8) -> Input {
    Input::new(
        Kind::ManagementCreate,
        [selector; 32],
        [7; 32],
        [payload; 32],
        None,
    )
    .unwrap()
}
async fn create(
    runtime: &std::sync::Arc<Runtime>,
    environment: Uuid,
    selector: u8,
    reject: bool,
) -> anyhow::Result<Uuid> {
    let pool = runtime.pool().clone();
    runtime
        .start(
            Some(environment),
            CapacityClass::Ordinary,
            move || async move {
                let owner = async_store::current_epoch_owner(environment)?;
                let input = input(selector, 8);
                let receipt = owner.prepare_creation(environment, &input).await?;
                primary::execute(
                    &pool,
                    &owner,
                    &input,
                    &receipt,
                    &Create {
                        environment,
                        reject,
                    },
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e:?}"))
            },
        )?
        .result()
        .await?
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL full-schema runtime supplier"]
async fn pg_lifecycle_current_creation_converges_races_rollback_and_generation_change(
) -> crate::web::test_support::TestResult {
    let f = crate::organizations::repository_tests::Fixture::new().await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let previous: Option<(Uuid, Uuid)> =
        sqlx::query_as("SELECT deployment_id,generation FROM aegaeon_lifecycle.current")
            .fetch_optional(&admin)
            .await?;
    let deployment = previous.map_or_else(Uuid::new_v4, |x| x.0);
    let selected = Selection::new(deployment, Uuid::new_v4())?;
    sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4)")
        .bind(deployment)
        .bind(previous.map(|x| x.1))
        .bind(selected.generation())
        .bind(Uuid::new_v4())
        .execute(&admin)
        .await?;
    let environment = f.env.environment_id;
    let make = |selected| {
        Runtime::checked(
            selected,
            PgPoolOptions::new()
                .max_connections(4)
                .acquire_timeout(Duration::from_secs(5)),
            f.pool.connect_options().as_ref().clone(),
            vec![(environment, f.env.issuer_url.clone())],
            Limits {
                ordinary: 64,
                revocation: 1,
                snapshot: 1,
            },
        )
    };
    let runtime = make(selected).await?;
    let result: crate::web::test_support::TestResult = async {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let runtime = runtime.clone();
            tasks.spawn(async move { create(&runtime, environment, 1, false).await });
        }
        let mut owners = std::collections::BTreeSet::new();
        while let Some(value) = tasks.join_next().await {
            owners.insert(value??);
        }
        assert_eq!(owners.len(), 1);
        let owner = *owners.first().unwrap();
        assert!(create(&runtime, environment, 2, true).await.is_err());
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.organization_creation_receipts WHERE environment_id=$1",
        )
        .bind(environment)
        .fetch_one(&admin)
        .await?;
        assert_eq!(
            count, 1,
            "failed final authorization rolls back both user and receipt"
        );
        assert_ne!(create(&runtime, environment, 2, false).await?, owner);
        runtime
            .start(
                Some(environment),
                CapacityClass::Ordinary,
                move || async move {
                    let local = async_store::current_epoch_owner(environment).unwrap();
                    assert!(matches!(
                        local.prepare_creation(environment, &input(1, 9)).await,
                        Err(crate::organizations::witness::Error::Conflict)
                    ));
                    local
                        .check_identity(environment, owner, &owner.to_string())
                        .await
                        .unwrap();
                },
            )?
            .result()
            .await?;
        runtime.close().await;
        wait_runtime_release(&admin).await?;
        let next = Selection::new(deployment, Uuid::new_v4())?;
        sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4)")
            .bind(deployment)
            .bind(selected.generation())
            .bind(next.generation())
            .bind(Uuid::new_v4())
            .execute(&admin)
            .await?;
        let current = make(next).await?;
        let replay = create(&current, environment, 1, false).await;
        current.close().await;
        assert_eq!(
            replay?, owner,
            "current DB receipt survives generation replacement"
        );
        Ok(())
    }
    .await;
    runtime.close().await;
    admin.close().await;
    f.cleanup(result).await
}
