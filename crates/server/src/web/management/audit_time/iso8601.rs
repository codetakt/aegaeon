const MAX_ISO8601_TIMESTAMP_BYTES: usize = 64;

pub(in crate::web::management) fn is_valid_iso8601(s: &str) -> bool {
    parse_iso8601_epoch_secs(s).is_some()
}

fn parse_ascii_u32(bytes: &[u8], start: usize, end: usize) -> Option<u32> {
    bytes.get(start..end)?.iter().try_fold(0u32, |acc, b| {
        b.is_ascii_digit()
            .then_some(acc.saturating_mul(10) + u32::from(*b - b'0'))
    })
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn days_since_unix_epoch(year: i32, month: u32, day: u32) -> Option<i64> {
    let adjusted_year = year - i32::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = i32::try_from(month).ok()? + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i32::try_from(day).ok()? - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(i64::from(era) * 146_097 + i64::from(day_of_era) - 719_468)
}

fn parse_iso8601_timezone_offset(bytes: &[u8], pos: usize) -> Option<i64> {
    match bytes.get(pos).copied()? {
        b'Z' | b'z' if pos + 1 == bytes.len() => Some(0),
        sign @ (b'+' | b'-') if pos + 6 == bytes.len() && bytes.get(pos + 3) == Some(&b':') => {
            let hours = parse_ascii_u32(bytes, pos + 1, pos + 3)?;
            let minutes = parse_ascii_u32(bytes, pos + 4, pos + 6)?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let offset = i64::from(hours) * 3600 + i64::from(minutes) * 60;
            Some(if sign == b'+' { offset } else { -offset })
        }
        _ => None,
    }
}

pub(in crate::web::management::audit_time) fn parse_iso8601_epoch_secs(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() < 20
        || bytes.len() > MAX_ISO8601_TIMESTAMP_BYTES
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }

    let year = i32::try_from(parse_ascii_u32(bytes, 0, 4)?).ok()?;
    let month = parse_ascii_u32(bytes, 5, 7)?;
    let day = parse_ascii_u32(bytes, 8, 10)?;
    let hour = parse_ascii_u32(bytes, 11, 13)?;
    let minute = parse_ascii_u32(bytes, 14, 16)?;
    let second = parse_ascii_u32(bytes, 17, 19)?;
    if day == 0 || day > days_in_month(year, month)? || hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut tz_pos = 19;
    if bytes.get(tz_pos) == Some(&b'.') {
        tz_pos += 1;
        let fraction_start = tz_pos;
        while bytes.get(tz_pos).is_some_and(u8::is_ascii_digit) {
            tz_pos += 1;
        }
        if tz_pos == fraction_start {
            return None;
        }
    }
    let offset_secs = parse_iso8601_timezone_offset(bytes, tz_pos)?;
    let local_epoch = days_since_unix_epoch(year, month, day)? * 86_400
        + i64::from(hour) * 3600
        + i64::from(minute) * 60
        + i64::from(second);
    Some(local_epoch - offset_secs)
}

#[cfg(test)]
pub(in crate::web::management) fn approx_day_span(from: &str, to: &str) -> Option<u64> {
    audit_time_span_seconds(from, to).map(|seconds| seconds / 86_400)
}

pub(in crate::web::management::audit_time) fn audit_time_span_seconds(
    from: &str,
    to: &str,
) -> Option<u64> {
    let from_epoch = parse_iso8601_epoch_secs(from)?;
    let to_epoch = parse_iso8601_epoch_secs(to)?;
    let span = to_epoch.checked_sub(from_epoch)?;
    u64::try_from(span).ok()
}
