use ring::digest::{digest, SHA256};

/// Length-delimited UTF8/binary field in the version-one history supplier contract.
#[must_use]
pub fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(8 + bytes.len());
    framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    framed.extend_from_slice(bytes);
    framed
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest(&SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA256 has exactly 32 bytes")
}

/// Bounded-memory, ordered collection digest; this does not canonicalize JSON.
pub struct HashChain {
    state: [u8; 32],
    count: u64,
}

impl HashChain {
    #[must_use]
    pub fn new(collection: &str) -> Self {
        let mut initial = frame(b"aegaeon-subject-inventory-v1");
        initial.extend(frame(collection.as_bytes()));
        Self {
            state: sha256(&initial),
            count: 0,
        }
    }

    /// Add the next exact supplier row, with an unambiguous row identity.
    ///
    /// # Errors
    /// Refuses counts outside PostgreSQL bigint instead of wrapping.
    pub fn push(&mut self, key: &str, row: &[u8]) -> Result<(), &'static str> {
        let count = self
            .count
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or("inventory row count exceeds PostgreSQL bigint")?;
        let mut input = Vec::with_capacity(81 + key.len());
        input.push(1);
        input.extend(self.state);
        input.extend(count.to_be_bytes());
        input.extend(frame(key.as_bytes()));
        input.extend(sha256(&frame(row)));
        self.state = sha256(&input);
        self.count = count;
        Ok(())
    }

    #[must_use]
    pub fn finish(&self) -> (u64, [u8; 32]) {
        let mut final_input = Vec::with_capacity(41);
        final_input.push(2);
        final_input.extend(self.state);
        final_input.extend(self.count.to_be_bytes());
        (self.count, sha256(&final_input))
    }
}

/// Lowercase SHA256 of exact bytes, without JSON canonicalization.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(&sha256(bytes))
}

pub(super) fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}

/// Typed, nullable fields have explicit tags. Their order is part of version one.
#[must_use]
pub fn content_id(domain: &str, fields: &[(&str, Option<&str>)]) -> String {
    let mut bytes = frame(domain.as_bytes());
    for (tag, value) in fields {
        match value {
            None => bytes.push(0),
            Some(value) => {
                bytes.push(1);
                bytes.extend(frame(tag.as_bytes()));
                bytes.extend(frame(value.as_bytes()));
            }
        }
    }
    sha256_hex(&bytes)
}

/// PostgreSQL JSONB text ordering for bounded inventory metadata. Source rows
/// are hashed from the exact server-returned text instead of being reserialized.
pub(super) fn metadata_text(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Object(object) => {
            let mut fields: Vec<_> = object.iter().collect();
            fields.sort_by(|(a, _), (b, _)| {
                a.len()
                    .cmp(&b.len())
                    .then_with(|| a.as_bytes().cmp(b.as_bytes()))
            });
            let contents: Vec<_> = fields
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}: {}",
                        serde_json::to_string(key).expect("JSON string serialization"),
                        metadata_text(value)
                    )
                })
                .collect();
            format!("{{{}}}", contents.join(", "))
        }
        Value::Array(array) => format!(
            "[{}]",
            array
                .iter()
                .map(metadata_text)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => serde_json::to_string(value).expect("JSON value serialization"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_supplier_vectors_include_controls_and_non_ascii_catalog_text() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../spec/subject-ownership/digest-vectors-v1.json"
        ))
        .unwrap();
        for vector in vectors["vectors"].as_array().unwrap() {
            let mut chain = HashChain::new(vector["collection"].as_str().unwrap());
            for row in vector["rows"].as_array().unwrap() {
                chain
                    .push(
                        row["key"].as_str().unwrap(),
                        row["text"].as_str().unwrap().as_bytes(),
                    )
                    .unwrap();
            }
            assert_eq!(
                hex_digest(&chain.finish().1),
                vector["sha256"].as_str().unwrap()
            );
        }
        assert_ne!(
            content_id("domain", &[("text", None)]),
            content_id("domain", &[("text", Some(""))])
        );
        assert_ne!(
            content_id("domain", &[("text", Some("true"))]),
            content_id("domain", &[("boolean", Some("true"))])
        );
    }

    #[test]
    fn framing_and_order_do_not_alias() {
        let mut left = HashChain::new("test");
        left.push("a", b"bc").unwrap();
        let mut right = HashChain::new("test");
        right.push("ab", b"c").unwrap();
        assert_ne!(left.finish(), right.finish());
        let mut other_domain = HashChain::new("other");
        other_domain.push("a", b"bc").unwrap();
        assert_ne!(left.finish(), other_domain.finish());
        assert_ne!(HashChain::new("test").finish(), left.finish());
    }
}
