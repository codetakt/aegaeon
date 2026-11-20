//! RFC 9110 media ranges with an explicitly requested alternative to JSON and conservative duplicate ties.
use axum::http::{header, HeaderMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Representation {
    Json,
    Alternate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NegotiationError {
    Malformed,
    NotAcceptable,
}

type ParseResult<T> = Result<T, NegotiationError>;

pub(super) fn select(
    headers: &HeaderMap,
    alternative: Option<&[u8]>,
) -> ParseResult<Representation> {
    if !headers.contains_key(header::ACCEPT) {
        return Ok(Representation::Json);
    }
    // Combining raw bytes preserves quoted commas, obs-text and repeated field order.
    let mut combined = Vec::new();
    for (index, value) in headers.get_all(header::ACCEPT).iter().enumerate() {
        if index != 0 {
            combined.push(b',');
        }
        combined.extend_from_slice(value.as_bytes());
    }
    select_present(&combined, alternative)
}

#[derive(Default)]
struct Preference(Option<(u8, u16)>);

impl Preference {
    fn include(&mut self, specificity: u8, quality: u16) {
        match self.0 {
            Some((previous, _)) if previous > specificity => {}
            Some((previous, old_quality)) if previous == specificity => {
                self.0 = Some((specificity, quality.min(old_quality)));
            }
            _ => self.0 = Some((specificity, quality)),
        }
    }

    fn quality(&self) -> u16 {
        self.0.map_or(0, |(_, quality)| quality)
    }
}

fn select_present(bytes: &[u8], alternative: Option<&[u8]>) -> ParseResult<Representation> {
    let mut cursor = Cursor(bytes);
    let mut json = Preference::default();
    let mut alt = Preference::default();
    let mut explicit_alternative = false;
    loop {
        cursor.ows();
        if cursor.0.is_empty() {
            break;
        }
        if cursor.take(b',') {
            continue;
        }
        let type_ = cursor.token()?;
        cursor.require(b'/')?;
        let subtype = cursor.token()?;
        let (quality, constrained) = cursor.parameters()?;
        if !cursor.0.is_empty() && !cursor.take(b',') {
            return Err(NegotiationError::Malformed);
        }
        if constrained {
            continue;
        }
        if type_ == b"*" && subtype == b"*" {
            json.include(0, quality);
            alt.include(0, quality);
        } else if type_.eq_ignore_ascii_case(b"application") {
            if subtype == b"*" {
                json.include(1, quality);
                alt.include(1, quality);
            } else if subtype.eq_ignore_ascii_case(b"json") {
                json.include(2, quality);
            } else if alternative.is_some_and(|name| subtype.eq_ignore_ascii_case(name)) {
                explicit_alternative = true;
                alt.include(2, quality);
            }
        }
    }
    let json_quality = json.quality();
    let alternative_quality = if explicit_alternative {
        alt.quality()
    } else {
        0
    };
    if alternative_quality > 0 && alternative_quality >= json_quality {
        Ok(Representation::Alternate)
    } else if json_quality > 0 {
        Ok(Representation::Json)
    } else {
        Err(NegotiationError::NotAcceptable)
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, byte: u8) -> bool {
        if self.0.first() == Some(&byte) {
            self.0 = &self.0[1..];
            true
        } else {
            false
        }
    }

    fn require(&mut self, byte: u8) -> ParseResult<()> {
        self.take(byte)
            .then_some(())
            .ok_or(NegotiationError::Malformed)
    }

    fn ows(&mut self) {
        while matches!(self.0.first(), Some(b' ' | b'\t')) {
            self.0 = &self.0[1..];
        }
    }

    fn token(&mut self) -> ParseResult<&'a [u8]> {
        let length = self.0.iter().take_while(|byte| is_token(**byte)).count();
        if length == 0 {
            return Err(NegotiationError::Malformed);
        }
        let value = &self.0[..length];
        self.0 = &self.0[length..];
        Ok(value)
    }

    fn value(&mut self) -> ParseResult<Vec<u8>> {
        if !self.take(b'"') {
            return self.token().map(<[u8]>::to_vec);
        }
        let mut value = Vec::new();
        while let Some((&byte, rest)) = self.0.split_first() {
            self.0 = rest;
            match byte {
                b'"' => return Ok(value),
                b'\\' => {
                    let (&escaped, rest) =
                        self.0.split_first().ok_or(NegotiationError::Malformed)?;
                    if !matches!(escaped, b'\t' | b' '..=b'~' | 0x80..=0xff) {
                        return Err(NegotiationError::Malformed);
                    }
                    self.0 = rest;
                    value.push(escaped);
                }
                b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff => value.push(byte),
                _ => return Err(NegotiationError::Malformed),
            }
        }
        Err(NegotiationError::Malformed)
    }

    fn parameters(&mut self) -> ParseResult<(u16, bool)> {
        let mut quality = None;
        let mut constrained = false;
        loop {
            self.ows();
            if !self.take(b';') {
                break;
            }
            self.ows();
            // RFC 9110 parameters permits an empty parameter after a semicolon.
            if matches!(self.0.first(), None | Some(b';' | b',')) {
                continue;
            }
            let name = self.token()?;
            self.require(b'=')?;
            let value = self.value()?;
            if name.eq_ignore_ascii_case(b"q") {
                if quality.is_some() {
                    return Err(NegotiationError::Malformed);
                }
                quality = Some(parse_quality(&value)?);
            } else {
                constrained = true;
            }
        }
        Ok((quality.unwrap_or(1000), constrained))
    }
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn parse_quality(value: &[u8]) -> ParseResult<u16> {
    let (&whole, tail) = value.split_first().ok_or(NegotiationError::Malformed)?;
    if !matches!(whole, b'0' | b'1') {
        return Err(NegotiationError::Malformed);
    }
    let fraction = if tail.is_empty() {
        tail
    } else {
        tail.strip_prefix(b".").ok_or(NegotiationError::Malformed)?
    };
    if fraction.len() > 3
        || !fraction.iter().all(u8::is_ascii_digit)
        || (whole == b'1' && fraction.iter().any(|byte| *byte != b'0'))
    {
        return Err(NegotiationError::Malformed);
    }
    let mut quality = u16::from(whole - b'0') * 1000;
    for (digit, weight) in fraction.iter().zip([100, 10, 1]) {
        quality += u16::from(digit - b'0') * weight;
    }
    Ok(quality)
}

#[cfg(test)]
mod tests;
