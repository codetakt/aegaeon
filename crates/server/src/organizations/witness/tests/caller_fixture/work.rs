//! Test owner retaining the real deployment work through child completion.
use super::*;
use crate::organizations::witness::deployment::work::Work as ParentWork;

pub(crate) struct CallerWork {
    child: Work,
    parent: ParentWork,
}

impl std::ops::Deref for CallerWork {
    type Target = Work;
    fn deref(&self) -> &Work {
        &self.child
    }
}

impl CallerWork {
    pub(in crate::organizations::witness::tests) fn observed(
        child: Work,
        parent: ParentWork,
    ) -> Self {
        Self { child, parent }
    }

    pub(crate) async fn complete(self) -> Result<State> {
        let state = self.child.complete().await?;
        self.parent.complete().await?;
        Ok(state)
    }

    pub(crate) async fn execute<T, F>(self, future: F) -> Result<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + self.admission().execution_budget();
        tokio::spawn(async move {
            tokio::time::timeout_at(deadline, async move {
                let result = self.store_scope(future).await?;
                self.complete().await?;
                Ok(result)
            })
            .await
            .map_err(|_| Error::Deadline)?
        })
        .await
        .map_err(|_| Error::Refused)?
    }
}
