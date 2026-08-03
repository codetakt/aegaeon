#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::authcode::store::redis_backend::scripts) struct LuaSlot {
    pub(in crate::authcode::store::redis_backend::scripts) index: usize,
    pub(in crate::authcode::store::redis_backend::scripts) name: &'static str,
}

impl LuaSlot {
    pub(in crate::authcode::store::redis_backend::scripts) const fn new(
        index: usize,
        name: &'static str,
    ) -> Self {
        Self { index, name }
    }
}

pub(super) enum RedisScriptArg<'a> {
    Str(&'a str),
    U64(u64),
    Bool(bool),
}

pub(super) fn redis_bool(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::LuaSlot;
    use std::collections::BTreeSet;

    pub(in crate::authcode::store::redis_backend::scripts) fn referenced_indexes(
        script: &str,
        prefix: &str,
    ) -> Vec<usize> {
        let marker = format!("{prefix}[");
        script
            .match_indices(&marker)
            .filter_map(|(offset, _)| {
                let start = offset + marker.len();
                let digits: String = script[start..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect();
                digits.parse::<usize>().ok()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub(in crate::authcode::store::redis_backend::scripts) fn expected_indexes(
        slots: &[LuaSlot],
    ) -> Vec<usize> {
        slots.iter().map(|slot| slot.index).collect()
    }

    pub(in crate::authcode::store::redis_backend::scripts) fn assert_contiguous_slots(
        slots: &[LuaSlot],
    ) {
        for (expected, slot) in (1..).zip(slots) {
            assert_eq!(
                slot.index, expected,
                "slot `{}` has an unexpected index",
                slot.name
            );
            assert!(!slot.name.trim().is_empty(), "slot name must not be empty");
        }
    }

    pub(in crate::authcode::store::redis_backend::scripts) fn assert_referenced_slots(
        script: &str,
        prefix: &str,
        slots: &[LuaSlot],
    ) {
        assert_contiguous_slots(slots);
        assert_eq!(referenced_indexes(script, prefix), expected_indexes(slots));
    }

    pub(in crate::authcode::store::redis_backend::scripts) fn invocation_body<'a>(
        source: &'a str,
        name: &str,
        invoke_marker: &str,
    ) -> &'a str {
        let start = source
            .find(name)
            .expect("script invocation function should exist");
        let rest = &source[start..];
        let end = rest
            .find(invoke_marker)
            .expect("script invocation should end with Redis invoke");
        &rest[..end]
    }
}
