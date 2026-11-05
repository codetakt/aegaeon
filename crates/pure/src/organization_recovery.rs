//! Current SQL capacity partition and retained predecessor admission model.
//! Neither kernel proves I/O, database durability or recovery composition.

/// Reserve revocation capacity within, rather than in addition to, the total.
pub fn connection_partition(total: u32, revocation: u32) -> Option<(u32, u32)> {
    if total < 2 || revocation == 0 || revocation > 64 {
        return None;
    }
    let reserved = revocation.min((total / 4).max(1));
    Some((total - reserved, reserved))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    ReadOnly,
    MayHaveMutated,
    Finished,
}

#[derive(Clone, Copy, Debug)]
pub struct Preflight {
    stage: Stage,
}

impl Default for Preflight {
    fn default() -> Self {
        Self {
            stage: Stage::ReadOnly,
        }
    }
}

impl Preflight {
    /// A finished attempt cannot be reused for another mutation.
    pub fn begin_mutation(&mut self) -> bool {
        if self.stage == Stage::Finished {
            return false;
        }
        self.stage = Stage::MayHaveMutated;
        true
    }

    pub fn finish(&mut self) {
        self.stage = Stage::Finished;
    }

    pub fn requires_fence(&self) -> bool {
        self.stage == Stage::MayHaveMutated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_loss_needs_no_mutation_fence() {
        assert!(!Preflight::default().requires_fence());
    }

    #[test]
    fn an_unfinished_mutation_remains_uncertain() {
        let mut attempt = Preflight::default();
        assert!(attempt.begin_mutation());
        assert!(attempt.requires_fence());
        assert!(attempt.begin_mutation());
        assert!(attempt.requires_fence());
        attempt.finish();
        assert!(!attempt.requires_fence());
        assert!(!attempt.begin_mutation());
    }
}
