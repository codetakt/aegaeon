//! Observe real dummy verification on the current test thread without replacing it.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

struct Observation {
    secret: String,
    calls: Rc<Cell<usize>>,
}

thread_local! {
    static OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
}

pub(crate) struct VerificationObserver {
    previous: Option<Observation>,
    calls: Rc<Cell<usize>>,
}

impl VerificationObserver {
    pub(crate) fn for_secret(secret: &str) -> Self {
        let calls = Rc::new(Cell::new(0));
        let previous = OBSERVATION.replace(Some(Observation {
            secret: secret.to_owned(),
            calls: calls.clone(),
        }));
        Self { previous, calls }
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl Drop for VerificationObserver {
    fn drop(&mut self) {
        OBSERVATION.set(self.previous.take());
    }
}

pub(super) fn record_verification(provided_secret: &str) {
    OBSERVATION.with_borrow(|observation| {
        if let Some(observation) = observation {
            if observation.secret == provided_secret {
                observation.calls.set(observation.calls.get() + 1);
            }
        }
    });
}
