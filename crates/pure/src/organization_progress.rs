//! Unsigned progress checks used directly by observed Organizations work.
//! Store identity, freshness, ownership and durability remain separate premises.

pub fn retain(minimum: u64, maximum: u64, observed: u64) -> Option<u64> {
    if maximum < minimum || observed < minimum {
        return None;
    }
    Some(maximum.max(observed))
}

pub fn can_complete(minimum: u64, maximum: u64, final_position: u64) -> bool {
    maximum >= minimum && final_position >= maximum
}
