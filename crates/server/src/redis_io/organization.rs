//! This context exists only on an owned synchronous store worker. It is never
//! held across an async suspension or shared with another request's thread.
use crate::organizations::request_work::Admission;
use std::cell::RefCell;

thread_local! {
    static CURRENT: RefCell<Option<Admission>> = const { RefCell::new(None) };
}

pub(crate) fn current_admission() -> Option<Admission> {
    CURRENT.with_borrow(Clone::clone)
}

/// A returned lock retains its original owner through synchronous or detached
/// release. Reuse an existing matching scope instead of entering a nested one.
pub(crate) fn with_owner<T>(
    owner: Admission,
    function: impl FnOnce() -> T,
) -> Result<T, sqlx::Error> {
    owner.ensure_open()?;
    if let Some(current) = current_admission() {
        if !current.same_work(&owner) {
            return Err(sqlx::Error::Protocol(
                "foreign Organizations cleanup owner".into(),
            ));
        }
        Ok(function())
    } else {
        scope(owner, function)
    }
}

pub(crate) fn scope<T>(
    admission: Admission,
    function: impl FnOnce() -> T,
) -> Result<T, sqlx::Error> {
    admission.ensure_open()?;
    CURRENT.with_borrow_mut(|current| {
        if current.is_some() {
            return Err(sqlx::Error::Protocol(
                "nested Organizations store work".into(),
            ));
        }
        *current = Some(admission);
        Ok(())
    })?;
    struct Exit;
    impl Drop for Exit {
        fn drop(&mut self) {
            CURRENT.with_borrow_mut(|current| {
                if let Some(owner) = current.take() {
                    if std::thread::panicking() {
                        owner.close_until_restart();
                    }
                }
            });
        }
    }
    let _exit = Exit;
    Ok(function())
}

#[derive(Clone)]
pub(super) struct Owner(Option<Admission>);
impl Owner {
    pub fn capture() -> Self {
        Self(CURRENT.with_borrow(Clone::clone))
    }
    pub fn scoped(&self) -> bool {
        self.0.is_some()
    }
    pub fn ensure_open(&self) -> redis::RedisResult<()> {
        let compatible = CURRENT.with_borrow(|current| match (current, &self.0) {
            (Some(expected), Some(actual)) => expected.same_work(actual),
            (Some(_), None) => false,
            (None, _) => true,
        });
        if !compatible
            || self
                .0
                .as_ref()
                .is_some_and(|owner| owner.ensure_open().is_err())
        {
            return Err(super::unavailable(
                "Organizations store admission unavailable",
            ));
        }
        Ok(())
    }
    pub fn close(&self) {
        if let Some(owner) = &self.0 {
            owner.close_until_restart();
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.close();
        }
    }
}

pub(super) struct Pending<'a> {
    owner: &'a Owner,
    confirmed: bool,
}
impl<'a> Pending<'a> {
    pub fn new(owner: &'a Owner) -> Self {
        Self {
            owner,
            confirmed: false,
        }
    }
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }
}
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.owner.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organizations_store_scope_refuses_foreign_owners_and_clears_after_panic() {
        let first = Admission::isolated_for_test().unwrap();
        let second = Admission::isolated_for_test().unwrap();
        let foreign = scope(first.clone(), Owner::capture).unwrap();
        let unscoped = Owner::capture();
        scope(second.clone(), || {
            assert!(foreign.ensure_open().is_err());
            assert!(unscoped.ensure_open().is_err());
            assert!(Owner::capture().ensure_open().is_ok());
            assert!(scope(first.clone(), || ()).is_err());
            assert!(!std::thread::spawn(|| Owner::capture().scoped())
                .join()
                .unwrap());
        })
        .unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = scope(first.clone(), || panic!("interrupted store work"));
        }));
        assert!(panic.is_err());
        assert!(first.ensure_open().is_err());
        assert!(second.ensure_open().is_ok());
        assert!(!Owner::capture().scoped());
        assert!(foreign.ensure_open().is_err());
    }
}
