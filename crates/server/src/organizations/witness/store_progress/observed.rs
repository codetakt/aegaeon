//! Actual data connections share the exact retained checkpoint of one work owner.
use super::*;
use std::sync::Arc;

pub(in crate::organizations) struct DataObservations {
    record: Record,
    pub(in crate::organizations::witness) stores: Arc<ObservedStores>,
}

impl Observation<'_> {
    pub(in crate::organizations::witness) async fn into_observed(
        self,
        primary: Postgres,
        token: Redis,
    ) -> Result<Arc<DataObservations>> {
        let stores = ObservedStores::connect(
            self.record.checkpoint.primary_incarnation.clone(),
            self.record.checkpoint.token_incarnation.clone(),
            self.record.observation.minimum_wal,
            primary,
            token,
        )
        .await?;
        Ok(Arc::new(DataObservations {
            record: self.record,
            stores,
        }))
    }
}

impl DataObservations {
    pub(in crate::organizations) async fn finish(
        &self,
        control: &mut Control,
        admission: &Admission,
    ) -> Result<()> {
        let (primary_value, token_value) = self.stores.finish_values().await?;
        finish(control, admission, &self.record, primary_value, token_value).await?;
        Ok(())
    }
}
