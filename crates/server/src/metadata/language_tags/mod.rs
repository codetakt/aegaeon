//! RFC 5646 form and a separately pinned IANA consumer admission profile.
//!
//! This checks extension allocation and structure, not extension payload
//! semantics, canonical generation, truthful support, or language negotiation.
//! Received text is never rewritten. See docs/specs/language-metadata.md.
use std::collections::HashSet;

mod registry;

fn alpha(value: &str, low: usize, high: usize) -> bool {
    (low..=high).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphabetic())
}

fn folded(value: &str) -> [u8; 8] {
    let mut key = [0; 8];
    for (target, source) in key.iter_mut().zip(value.bytes()) {
        *target = source.to_ascii_lowercase();
    }
    key
}

fn member(table: &[&str], value: &str) -> bool {
    let key = folded(value);
    table
        .binary_search_by(|candidate| candidate.as_bytes().cmp(&key[..value.len()]))
        .is_ok()
}

fn registered(category: &str, table: &[&str], value: &str) -> bool {
    let key = folded(value);
    member(table, value)
        || registry::RANGES.iter().any(|(kind, low, high)| {
            *kind == category
                && low.len() == value.len()
                && low.as_bytes() <= &key[..value.len()]
                && &key[..value.len()] <= high.as_bytes()
        })
}

fn registered_extlang(extlang: &str, primary: &str) -> bool {
    let key = folded(extlang);
    let Ok(index) =
        registry::EXTLANG.binary_search_by(|(name, _)| name.as_bytes().cmp(&key[..extlang.len()]))
    else {
        return false;
    };
    registry::EXTLANG[index].1.eq_ignore_ascii_case(primary)
}

fn parse(tag: &str, dated: bool) -> bool {
    if !tag.is_ascii()
        || tag.split('-').any(|part| {
            !(1..=8).contains(&part.len()) || !part.bytes().all(|b| b.is_ascii_alphanumeric())
        })
    {
        return false;
    }
    // RFC 5646's 26 grandfathered alternatives are whole tags, not prefixes.
    if registry::GRANDFATHERED
        .iter()
        .any(|value| value.eq_ignore_ascii_case(tag))
    {
        return true;
    }
    let mut parts = tag.split('-').peekable();
    let Some(primary) = parts.next() else {
        return false;
    };
    if primary.eq_ignore_ascii_case("x") {
        return parts.next().is_some();
    }
    if !alpha(primary, 2, 8) || (dated && !registered("language", registry::LANGUAGE, primary)) {
        return false;
    }
    if primary.len() <= 3 && parts.peek().is_some_and(|s| alpha(s, 3, 3)) {
        let Some(extlang) = parts.next() else {
            return false;
        };
        if dated && !registered_extlang(extlang, primary) {
            return false;
        }
        // Second/third extlangs exist in ABNF but are permanently invalid
        // under RFC 5646 section 2.2.2, independently of the dated registry.
        if parts.peek().is_some_and(|s| alpha(s, 3, 3)) {
            return false;
        }
    }
    if parts.peek().is_some_and(|s| alpha(s, 4, 4)) {
        let Some(script) = parts.next() else {
            return false;
        };
        if dated && !registered("script", registry::SCRIPT, script) {
            return false;
        }
    }
    if parts
        .peek()
        .is_some_and(|s| alpha(s, 2, 2) || (s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit())))
    {
        let Some(region) = parts.next() else {
            return false;
        };
        if dated && !registered("region", registry::REGION, region) {
            return false;
        }
    }
    let mut variants = HashSet::new();
    while parts.peek().is_some_and(|s| {
        (5..=8).contains(&s.len()) || (s.len() == 4 && s.as_bytes()[0].is_ascii_digit())
    }) {
        let Some(variant) = parts.next() else {
            return false;
        };
        if variants.try_reserve(1).is_err()
            || !variants.insert(folded(variant))
            || (dated && !member(registry::VARIANT, variant))
        {
            return false;
        }
    }
    let mut singletons = 0_u64;
    while let Some(singleton) = parts.next() {
        if singleton.len() != 1 {
            return false;
        }
        let singleton = singleton.as_bytes()[0].to_ascii_lowercase();
        if singleton == b'x' {
            // Remaining private-use items are opaque (including repetitions).
            return parts.next().is_some();
        }
        let index = if singleton.is_ascii_digit() {
            singleton - b'0'
        } else {
            singleton - b'a' + 10
        };
        let bit = 1_u64 << index;
        if singletons & bit != 0 || (dated && !registry::EXTENSIONS.contains(&singleton)) {
            return false;
        }
        singletons |= bit;
        let mut payload = false;
        while parts.peek().is_some_and(|s| s.len() >= 2) {
            parts.next();
            payload = true;
        }
        if !payload {
            return false;
        }
    }
    true
}

/// Full normal/private/grandfathered form plus structural prohibitions.
/// Future/reserved forms can pass while failing the dated admission predicate.
pub(crate) fn is_well_formed(tag: &str) -> bool {
    parse(tag, false)
}

/// Local consumer profile: form plus dated ordinary-subtag membership,
/// extlang enclosing-primary Prefix, and allocated extension singletons.
/// Rejection is relative to the bundled snapshots, not global invalidity.
pub(crate) fn is_valid(tag: &str) -> bool {
    is_well_formed(tag) && parse(tag, true)
}

#[cfg(test)]
mod tests;
