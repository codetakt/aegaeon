use super::*;
use crate::authcode::token::AccessTokenAudiencePolicy;
use crate::device_authz::{normalize_user_code, DevicePollResult, DeviceUserCodeLookup};
pub(in crate::device_authz) struct PollRequest<'a> {
    pub device: &'a str,
    pub client: &'a str,
    pub environment: Option<&'a str>,
    pub resource: Option<&'a str>,
    pub policy: Option<&'a AccessTokenAudiencePolicy>,
    pub consume: bool,
}
impl PostgresDeviceCodeStore {
    pub(in crate::device_authz) async fn poll(
        &self,
        input: PollRequest<'_>,
    ) -> Result<(DevicePollResult, Option<PostgresDeviceGrantCommit>), String> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
            let mut tx=connection.as_mut().map_err(|_|unavailable())?.begin().await.map_err(|_|unavailable())?;
            let Some(mut row)=sqlx::query_as::<_,Record>("SELECT * FROM aegaeon.runtime_device_codes WHERE namespace=$1 AND device_digest=$2 FOR UPDATE")
                .bind(self.database.namespace.as_ref()).bind(sha256_digest(input.device.as_bytes()).as_slice()).fetch_optional(&mut *tx).await.map_err(|_|unavailable())? else {return Ok((DevicePollResult::ExpiredToken,None));};
            let now=clock(&mut tx).await?;
            if row.environment_id.as_deref()!=input.environment {return Ok((DevicePollResult::ExpiredToken,None));}
            if now>=row.expires_us {return Ok((DevicePollResult::ExpiredToken,None));}
            if row.client_id!=input.client {return Ok((DevicePollResult::InvalidGrant,None));}
            if input.resource.is_some_and(|r|row.resource.as_deref()!=Some(r)) {return Ok((DevicePollResult::InvalidTarget,None));}
            let interval=row.interval_secs.checked_mul(1_000_000).ok_or_else(unavailable)?;
            let fast=row.last_poll_us.is_some_and(|last|now.saturating_sub(last)<interval);
            if fast {row.interval_secs=row.interval_secs.saturating_add(5).min(i64::MAX/1_000_000);}
            sqlx::query("UPDATE aegaeon.runtime_device_codes SET last_poll_us=$3,interval_secs=$4 WHERE namespace=$1 AND device_digest=$2")
                .bind(self.database.namespace.as_ref()).bind(&row.device_digest).bind(now).bind(row.interval_secs).execute(&mut *tx).await.map_err(|_|unavailable())?;
            let mut receipt=None;
            let outcome=if fast {DevicePollResult::SlowDown} else {match row.status {
                0=>DevicePollResult::AuthorizationPending,
                2=>{sqlx::query("DELETE FROM aegaeon.runtime_device_codes WHERE namespace=$1 AND device_digest=$2").bind(self.database.namespace.as_ref()).bind(&row.device_digest).execute(&mut *tx).await.map_err(|_|unavailable())?;DevicePollResult::AccessDenied},
                1=> {
                    let audience=match input.policy.map(|p|p.resolve(&row.client_id,row.scope.as_deref(),row.resource.as_deref())).transpose() {
                        Ok(audience)=>audience,
                        Err(_)=>{tx.commit().await.map_err(|_|unavailable())?;return Ok((DevicePollResult::InvalidTarget,None));}
                    };
                    let approved=DevicePollResult::Approved{user_id:row.subject.clone().ok_or_else(unavailable)?,scope:row.scope.clone(),resource:row.resource.clone(),client_id:row.client_id.clone()};
                    if input.consume {
                        sqlx::query("DELETE FROM aegaeon.runtime_device_codes WHERE namespace=$1 AND device_digest=$2").bind(self.database.namespace.as_ref()).bind(&row.device_digest).execute(&mut *tx).await.map_err(|_|unavailable())?;
                    } else {receipt=Some(PostgresDeviceGrantCommit{database:self.database.clone(),expected:row.clone(),audience:audience.ok_or_else(unavailable)?});}
                    approved
                },
                _=>return Err(unavailable()),
            }};
            if clock(&mut tx).await?>=row.expires_us {return Ok((DevicePollResult::ExpiredToken,None));}
            tx.commit().await.map_err(|_|unavailable())?;
            Ok((outcome,receipt))
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }

    pub(in crate::device_authz) async fn decide(
        &self,
        user_code: &str,
        subject: Option<&str>,
    ) -> Result<bool, String> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
            let mut tx=connection.as_mut().map_err(|_|unavailable())?.begin().await.map_err(|_|unavailable())?;
            let key=sha256_digest(normalize_user_code(user_code).as_bytes());
            let Some(row)=sqlx::query_as::<_,Record>("SELECT * FROM aegaeon.runtime_device_codes WHERE namespace=$1 AND user_digest=$2 FOR UPDATE").bind(self.database.namespace.as_ref()).bind(key.as_slice()).fetch_optional(&mut *tx).await.map_err(|_|unavailable())? else {return Ok(false);};
            if row.status!=0 || clock(&mut tx).await?>=row.expires_us {return Ok(false);}
            sqlx::query("UPDATE aegaeon.runtime_device_codes SET status=$3,subject=$4 WHERE namespace=$1 AND user_digest=$2")
                .bind(self.database.namespace.as_ref()).bind(key.as_slice()).bind(if subject.is_some(){1i16}else{2i16}).bind(subject).execute(&mut *tx).await.map_err(|_|unavailable())?;
            if clock(&mut tx).await?>=row.expires_us {return Ok(false);}
            tx.commit().await.map_err(|_|unavailable())?;Ok(true)
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }
    pub(in crate::device_authz) async fn lookup(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceUserCodeLookup>, String> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            let row=sqlx::query_as::<_,(String,Option<String>,Option<String>)>("SELECT client_id,scope,resource FROM aegaeon.runtime_device_codes WHERE namespace=$1 AND user_digest=$2 AND status=0 AND expires_us>floor(extract(epoch from clock_timestamp())*1000000)::bigint")
                .bind(self.database.namespace.as_ref()).bind(sha256_digest(normalize_user_code(user_code).as_bytes()).as_slice()).fetch_optional(connection.as_mut().map_err(|_|unavailable())?).await.map_err(|_|unavailable())?;
            Ok(row.map(|(client_id,scope,resource)|DeviceUserCodeLookup{client_id,scope,resource}))
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }
}
