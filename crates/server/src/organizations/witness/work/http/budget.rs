//! Account response storage until the last transport-held byte clone is dropped.
use super::*;
use std::sync::{Arc, LazyLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const FRAME_OVERHEAD: usize = 256;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
static RESPONSE_BUDGET: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(RESPONSE_BYTES)));

pub(super) fn copy(data: &[u8]) -> Result<Bytes> {
    copy_with(&RESPONSE_BUDGET, data)
}
fn copy_with(budget: &Arc<Semaphore>, data: &[u8]) -> Result<Bytes> {
    if data.is_empty() {
        return Ok(Bytes::new());
    }
    if data.len() > MAX_FRAME_BYTES {
        return Err(super::super::super::Error::Refused);
    }
    let charge = u32::try_from(data.len() + FRAME_OVERHEAD)
        .map_err(|_| super::super::super::Error::CapacityExhausted)?;
    let permit = budget
        .clone()
        .try_acquire_many_owned(charge)
        .map_err(|_| super::super::super::Error::CapacityExhausted)?;
    // Copy into an exact-sized owner: a tiny slice cannot retain an arbitrarily
    // large producer allocation in the completed response. This budget accounts
    // payload and frame overhead, not allocator metadata or whole-process RSS.
    Ok(Bytes::from_owner(Owned {
        data: data.into(),
        _permit: permit,
    }))
}
struct Owned {
    data: Box<[u8]>,
    _permit: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for Owned {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn response_budget_follows_transport_bytes_and_clones() {
        let capacity = FRAME_OVERHEAD + 32;
        let budget = Arc::new(Semaphore::new(capacity));
        let bytes = copy_with(&budget, &[7; 32]).unwrap();
        let mut body = Body::from(bytes);
        let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        drop(body);
        let bytes = frame.into_data().unwrap();
        assert_eq!(budget.available_permits(), 0);
        let clone = bytes.clone();
        drop(bytes);
        assert!(copy_with(&budget, &[1]).is_err());
        drop(clone);
        assert_eq!(budget.available_permits(), capacity);
        assert!(copy_with(&budget, &[1]).is_ok());
    }
    #[test]
    fn response_budget_bounds_tiny_frames_and_releases_refused_work() {
        let budget = Arc::new(Semaphore::new(2 * (FRAME_OVERHEAD + 1)));
        let first = copy_with(&budget, &[1]).unwrap();
        let second = copy_with(&budget, &[2]).unwrap();
        assert!(copy_with(&budget, &[3]).is_err());
        assert!(copy_with(&budget, &[]).is_ok());
        drop((first, second));
        assert_eq!(budget.available_permits(), 2 * (FRAME_OVERHEAD + 1));
    }
}
