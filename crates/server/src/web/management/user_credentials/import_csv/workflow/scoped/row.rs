use super::*;
impl Import<'_> {
    pub(super) async fn insert(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        receipt: &Receipt,
        row: &ParsedCsvUserRow,
        issuer: &str,
        ttl: Option<i64>,
    ) -> Result<ImportedUserRow, Response> {
        sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,email,status) VALUES($1,$2,$3,$4,'INVITED')")
            .bind(receipt.owner_id()).bind(self.context.environment_id).bind(receipt.subject()).bind(row.email.as_deref())
            .execute(&mut **tx).await.map_err(|_| management_internal_error(self.request_id,"Failed to import user"))?;
        crate::end_user_profiles::ensure_profile_row(tx, receipt.owner_id())
            .await
            .map_err(|_| {
                management_internal_error(self.request_id, "Failed to initialize user profile")
            })?;
        let user = self.current(tx, receipt).await?;
        let activation = if let Some(ttl) = ttl {
            let (issued,redeem_url) = crate::web::management::user_credentials::recovery_issuance::issue_recovery_token_with_redeem_url(
                tx,issuer,receipt.owner_id(),RecoveryTokenPurpose::Activation,ttl,self.context.session.administrator_id,self.request_id).await?;
            Some(
                crate::web::management::user_credentials::responses::issued_in_transaction::load(
                    tx,
                    receipt.owner_id(),
                    issued,
                    redeem_url,
                    self.request_id,
                )
                .await?,
            )
        } else {
            None
        };
        write_user_management_audit_event(tx,self.context,self.request_id,EndUserAuditEvent{
            event_type:"management.user.imported.v1",target_id:receipt.owner_id(),
            data:serde_json::json!({"rowNumber":row.row_number,"userId":user.id,"subject":user.subject,"email":user.email,"status":user.status,"issuedActivation":activation.is_some()}),
        }).await?;
        Ok(ImportedUserRow {
            row_number: row.row_number,
            user,
            activation,
        })
    }
}
