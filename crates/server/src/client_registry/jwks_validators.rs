use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ETAG, LAST_MODIFIED};

mod date;
pub(super) use date::DateContext;
pub(super) use date::{parse_http_date, DateError, HttpDate};

#[derive(Clone, Debug, Default)]
pub(super) enum Metadata<T> {
    #[default]
    Absent,
    Invalid,
    Multiple,
    ClockOutOfRange,
    Valid(T),
}

impl<T> Metadata<T> {
    fn usable(&self) -> Option<&T> {
        match self {
            Self::Valid(value) => Some(value),
            _ => None,
        }
    }

    fn unusable_present(&self) -> bool {
        matches!(self, Self::Invalid | Self::Multiple | Self::ClockOutOfRange)
    }
}

#[derive(Clone, Debug)]
pub(super) struct EntityTag {
    header: HeaderValue,
    weak: bool,
}

impl EntityTag {
    fn parse(header: HeaderValue) -> Option<Self> {
        let raw = header.as_bytes();
        let weak = raw.starts_with(b"W/");
        let quoted = if weak { &raw[2..] } else { raw };
        if quoted.len() < 2
            || quoted[0] != b'"'
            || quoted[quoted.len() - 1] != b'"'
            || !quoted[1..quoted.len() - 1]
                .iter()
                .all(|byte| matches!(*byte, 0x21 | 0x23..=0x7e | 0x80..=0xff))
        {
            return None;
        }
        Some(Self { header, weak })
    }

    fn opaque(&self) -> &[u8] {
        let raw = self.header.as_bytes();
        &raw[if self.weak { 3 } else { 1 }..raw.len() - 1]
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct JwksValidators {
    etag: Metadata<EntityTag>,
    last_modified: Metadata<HttpDate>,
}

fn singleton(headers: &HeaderMap, name: HeaderName) -> Metadata<HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Metadata::Absent;
    };
    if values.next().is_some() {
        return Metadata::Multiple;
    }
    let raw = first.as_bytes();
    let start = raw
        .iter()
        .position(|b| !matches!(*b, b' ' | b'\t'))
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|b| !matches!(*b, b' ' | b'\t'))
        .map_or(start, |i| i + 1);
    match HeaderValue::from_bytes(&raw[start..end]) {
        Ok(value) => Metadata::Valid(value),
        Err(_) => Metadata::Invalid,
    }
}

impl JwksValidators {
    pub(super) fn from_headers(headers: &HeaderMap, context: DateContext) -> Self {
        let etag = match singleton(headers, ETAG) {
            Metadata::Valid(value) => {
                EntityTag::parse(value).map_or(Metadata::Invalid, Metadata::Valid)
            }
            Metadata::Absent => Metadata::Absent,
            Metadata::Multiple => Metadata::Multiple,
            _ => Metadata::Invalid,
        };
        let last_modified = match singleton(headers, LAST_MODIFIED) {
            Metadata::Valid(value) => match parse_http_date(value, context) {
                Ok(date) => Metadata::Valid(date),
                Err(DateError::Invalid) => Metadata::Invalid,
                Err(DateError::ClockOutOfRange) => Metadata::ClockOutOfRange,
            },
            Metadata::Absent => Metadata::Absent,
            Metadata::Multiple => Metadata::Multiple,
            _ => Metadata::Invalid,
        };
        Self {
            etag,
            last_modified,
        }
    }

    pub(super) fn conditional_headers(&self) -> Option<(Option<HeaderValue>, Option<HeaderValue>)> {
        let etag = self.etag.usable().map(|tag| tag.header.clone());
        let date = self
            .last_modified
            .usable()
            .and_then(|date| date.request_header().ok());
        if etag.is_none() && date.is_none() {
            None
        } else {
            Some((etag, date))
        }
    }

    pub(super) fn identifies(&self, candidate: &Self) -> bool {
        if self.etag.unusable_present() || self.last_modified.unusable_present() {
            return false;
        }
        if let Some(returned) = self.etag.usable() {
            let Some(saved) = candidate.etag.usable() else {
                return false;
            };
            // Sent If-None-Match must weak-match; a strong returned validator
            // additionally needs the same strong history for the update rule.
            return returned.opaque() == saved.opaque() && (returned.weak || !saved.weak);
        }
        match (
            self.last_modified.usable(),
            candidate.last_modified.usable(),
        ) {
            (Some(returned), Some(saved)) => returned.same_instant(saved),
            _ => false,
        }
    }

    pub(super) fn update_selected(self, candidate: &mut Self) {
        if !matches!(self.etag, Metadata::Absent) {
            candidate.etag = self.etag;
        }
        if !matches!(self.last_modified, Metadata::Absent) {
            candidate.last_modified = self.last_modified;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata(etags: &[&[u8]], dates: &[&[u8]]) -> JwksValidators {
        let mut headers = HeaderMap::new();
        for value in etags {
            headers.append(ETAG, HeaderValue::from_bytes(value).unwrap());
        }
        for value in dates {
            headers.append(LAST_MODIFIED, HeaderValue::from_bytes(value).unwrap());
        }
        JwksValidators::from_headers(&headers, DateContext::capture())
    }
    #[test]
    fn entity_tag_all_byte_classes_and_exact_grammar() {
        for byte in 0..=255u8 {
            let raw = [b'"', byte, b'"'];
            let legal = matches!(byte,0x21|0x23..=0x7e|0x80..=0xff);
            let parsed = HeaderValue::from_bytes(&raw)
                .ok()
                .and_then(EntityTag::parse);
            assert_eq!(parsed.is_some(), legal, "byte {byte:02x}");
        }
        for raw in [
            b"\"\"".as_slice(),
            b"W/\"\"",
            b"\"a,b\"",
            b"\"a\\b\"",
            b"\"\x80\xff\"",
        ] {
            assert!(EntityTag::parse(HeaderValue::from_bytes(raw).unwrap()).is_some());
        }
        for raw in [
            b"w/\"a\"".as_slice(),
            b"*",
            b"a",
            b"\"a\"x",
            b"\"a\",\"b\"",
            b"\"a b\"",
            b"\"a\tb\"",
            b"W/W/\"a\"",
        ] {
            assert!(EntityTag::parse(HeaderValue::from_bytes(raw).unwrap()).is_none());
        }
        let raw = metadata(&[b" \tW/\"\x80\"\t "], &[])
            .conditional_headers()
            .unwrap()
            .0
            .unwrap();
        assert_eq!(raw.as_bytes(), b"W/\"\x80\"");
        assert!(!metadata(&[b"\"\x80\""], &[]).identifies(&metadata(&[b"\"\xff\""], &[])));
    }
    #[test]
    fn singleton_states_and_invalid_present_fields_are_distinct() {
        assert!(matches!(metadata(&[], &[]).etag, Metadata::Absent));
        assert!(matches!(metadata(&[b"bad"], &[]).etag, Metadata::Invalid));
        assert!(matches!(
            metadata(&[b"\"A\"", b"\"A\""], &[]).etag,
            Metadata::Multiple
        ));
        assert!(matches!(
            metadata(&[], &[b"bad"]).last_modified,
            Metadata::Invalid
        ));
        assert!(matches!(
            metadata(&[], &[b"bad", b"bad"]).last_modified,
            Metadata::Multiple
        ));
        assert!(metadata(
            &[],
            &[b"Sun, 06 Nov 1994 08:49:37 GMT, Sun, 06 Nov 1994 08:49:37 GMT"]
        )
        .conditional_headers()
        .is_none());
        assert!(metadata(&[b"bad"], &[b"Sun, 06 Nov 1994 08:49:37 GMT"])
            .conditional_headers()
            .unwrap()
            .0
            .is_none());
    }
}
