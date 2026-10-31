use crate::local_credentials as credentials;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use crate::web::test_support::{
    cleanup_test_environment, setup_test_environment, test_pg_pool, TestEnvironment, TestResult,
};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const PASSWORD: &str = "credential-scope-fixture-password";
#[derive(Clone, Copy, Debug)]
enum Call {
    Environment,
    Subject,
    Email,
    Recovery,
    State,
    Issue,
    RevokePassword,
    RevokeToken,
}
struct User {
    id: Uuid,
    subject: String,
    email: String,
    token: String,
    token_id: Uuid,
}
impl Call {
    async fn run(self, pool: &PgPool, env: &TestEnvironment, user: &User) -> TestResult {
        match self {
            Self::Environment => {
                let found = credentials::load_runtime_environment_context(pool, &env.issuer_url)
                    .await?
                    .ok_or("environment absent")?;
                if found.environment_id != env.environment_id {
                    return Err("wrong Environment".into());
                }
            }
            Self::Subject | Self::Email => {
                let identifier = if matches!(self, Self::Subject) {
                    &user.subject
                } else {
                    &user.email
                };
                let found = credentials::authenticate_local_user(
                    pool,
                    &env.issuer_url,
                    identifier,
                    PASSWORD,
                )
                .await?
                .ok_or("authentication refused")?;
                if found.end_user_id != user.id
                    || found.environment.environment_id != env.environment_id
                {
                    return Err("wrong authenticated identity".into());
                }
            }
            Self::Recovery => {
                let found = credentials::redeem_recovery_token(
                    pool,
                    &env.issuer_url,
                    &user.token,
                    credentials::RecoveryTokenPurpose::PasswordReset,
                    "replacement-credential-fixture",
                    "credential-scope",
                )
                .await?
                .ok_or("recovery refused")?;
                if found.subject != user.subject {
                    return Err("wrong recovered identity".into());
                }
            }
            Self::State => {
                let found = credentials::load_user_credential_state(pool, user.id).await?;
                if found.password.is_none() || found.recovery_tokens.is_empty() {
                    return Err("credential state absent".into());
                }
            }
            _ => return self.in_tx(pool, user).await,
        }
        Ok(())
    }
    async fn in_tx(self, pool: &PgPool, user: &User) -> TestResult {
        let mut tx = pool.begin().await?;
        let result: TestResult = async {
            match self {
                Self::Issue => {
                    credentials::issue_recovery_token(
                        &mut tx,
                        user.id,
                        credentials::RecoveryTokenPurpose::PasswordReset,
                        300,
                        None,
                        None,
                    )
                    .await?;
                }
                Self::RevokePassword => {
                    credentials::revoke_password_credential(&mut tx, user.id, None)
                        .await?
                        .ok_or("password revocation absent")?;
                }
                Self::RevokeToken => {
                    credentials::revoke_recovery_token(&mut tx, user.token_id, user.id, None)
                        .await?
                        .ok_or("token revocation absent")?;
                }
                _ => return Err("unexpected transaction variant".into()),
            }
            Ok(())
        }
        .await;
        tx.rollback().await?;
        result
    }
}
struct Fixture {
    pool: PgPool,
    own: TestEnvironment,
    foreign: TestEnvironment,
    users: [User; 2],
    witness: CallerFixture,
}
impl Fixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
        let own = setup_test_environment(&pool).await?;
        let foreign = setup_test_environment(&pool).await?;
        let subject = format!("credential-{}", Uuid::new_v4());
        let email = format!("{subject}@example.test");
        let make = || User {
            id: Uuid::new_v4(),
            subject: subject.clone(),
            email: email.clone(),
            token: String::new(),
            token_id: Uuid::nil(),
        };
        let users = [make(), make()];
        for (env, user) in [own.environment_id, foreign.environment_id]
            .into_iter()
            .zip(&users)
        {
            sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,email,status) VALUES($1,$2,$3,$4,'ACTIVE')").bind(user.id).bind(env).bind(&user.subject).bind(&user.email).execute(&pool).await?;
        }
        let witness = CallerFixture::new(own.environment_id).await?;
        let mut f = Self {
            pool,
            own,
            foreign,
            users,
            witness,
        };
        f.reset().await?;
        Ok(f)
    }
    async fn reset(&mut self) -> TestResult {
        let hash = credentials::hash_password(PASSWORD)?;
        for user in &mut self.users {
            let mut tx = self.pool.begin().await?;
            sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash,status) VALUES($1,$2,'ACTIVE') ON CONFLICT(end_user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash,status='ACTIVE',last_used_at=NULL,revoked_by_administrator_id=NULL").bind(user.id).bind(&hash).execute(&mut *tx).await?;
            let token = credentials::issue_recovery_token(
                &mut tx,
                user.id,
                credentials::RecoveryTokenPurpose::PasswordReset,
                300,
                None,
                None,
            )
            .await?;
            user.token = token.token;
            user.token_id = token.id.parse()?;
            tx.commit().await?;
        }
        Ok(())
    }
    async fn foreign_snapshot(&self) -> Result<Value, sqlx::Error> {
        sqlx::query_scalar("SELECT jsonb_build_array((SELECT to_jsonb(c) FROM aegaeon.end_user_password_credentials c WHERE end_user_id=$1),(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM aegaeon.end_user_recovery_tokens t WHERE end_user_id=$1),(SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$2))")
            .bind(self.users[1].id).bind(self.foreign.environment_id).fetch_one(&self.pool).await
    }
    async fn finish(self, result: TestResult) -> TestResult {
        let owner_cleanup = self.witness.finish().await.map_err(Into::into);
        let own_cleanup = cleanup_test_environment(&self.pool, &self.own)
            .await
            .map_err(Into::into);
        let foreign_cleanup = cleanup_test_environment(&self.pool, &self.foreign)
            .await
            .map_err(Into::into);
        self.pool.close().await;
        result
            .and(owner_cleanup)
            .and(own_cleanup)
            .and(foreign_cleanup)
    }
}
async fn scoped(call: Call) -> TestResult {
    let mut f = Fixture::new().await?;
    let result: TestResult = async {
        call.run(&f.pool, &f.own, &f.users[0]).await?;
        call.run(&f.pool, &f.foreign, &f.users[1]).await?;
        f.reset().await?;
        f.witness
            .run(call.run(&f.pool, &f.own, &f.users[0]))
            .await??;
        let before = f.foreign_snapshot().await?;
        if f.witness
            .run(call.run(&f.pool, &f.foreign, &f.users[1]))
            .await?
            .is_ok()
        {
            return Err(format!("{call:?} accepted foreign credential authority").into());
        }
        if before != f.foreign_snapshot().await? {
            return Err("foreign credentials changed after refusal".into());
        }
        // The valid foreign password/token still works in its ordinary context.
        call.run(&f.pool, &f.foreign, &f.users[1]).await?;
        if f.witness.pending().await? != 0 {
            return Err("completed credential call remains pending".into());
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}
macro_rules! scope_test {
    ($name:ident,$case:ident) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL; actual credential Environment ownership"]
        async fn $name() -> TestResult {
            scoped(Call::$case).await
        }
    };
}
scope_test!(pg_organizations_credential_environment_scope, Environment);
scope_test!(pg_organizations_credential_subject_scope, Subject);
scope_test!(pg_organizations_credential_email_scope, Email);
scope_test!(pg_organizations_credential_recovery_scope, Recovery);
scope_test!(pg_organizations_credential_state_scope, State);
scope_test!(pg_organizations_credential_issue_scope, Issue);
scope_test!(
    pg_organizations_credential_password_revoke_scope,
    RevokePassword
);
scope_test!(pg_organizations_credential_token_revoke_scope, RevokeToken);
