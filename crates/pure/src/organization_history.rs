//! Finite journal input/page arithmetic used by the native history client.
//! These predicates do not establish SQL atomicity or source completeness.

pub const HISTORY_ENTRIES: u64 = 1_000_000;
pub const HISTORY_BATCH: u64 = 256;

pub fn batch_end(from: u64, count: u64) -> Option<u64> {
    if count == 0 || count > HISTORY_BATCH {
        return None;
    }
    from.checked_add(count)
        .filter(|end| *end <= HISTORY_ENTRIES)
}

pub fn page_length(total: u64, after: u64, limit: u64) -> Option<u64> {
    if total > HISTORY_ENTRIES || limit == 0 || limit > HISTORY_BATCH {
        return None;
    }
    total
        .checked_sub(after)
        .map(|remaining| remaining.min(limit))
}
