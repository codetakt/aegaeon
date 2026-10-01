use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::header::HeaderValue;
use time::format_description::{modifier, BorrowedFormatItem as Item, Component};
use time::parsing::Parsed;
use time::{Date, OffsetDateTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::client_registry) enum DateError {
    Invalid,
    ClockOutOfRange,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::client_registry) struct DateContext {
    now: Result<OffsetDateTime, DateError>,
}

impl DateContext {
    pub(in crate::client_registry) fn capture() -> Self {
        Self::from_system_time(SystemTime::now())
    }

    pub(in crate::client_registry) fn from_system_time(now: SystemTime) -> Self {
        let nanos = match now.duration_since(UNIX_EPOCH) {
            Ok(duration) => i128::try_from(duration.as_nanos()).ok(),
            Err(error) => i128::try_from(error.duration().as_nanos())
                .ok()
                .and_then(i128::checked_neg),
        };
        Self {
            now: nanos
                .and_then(|value| OffsetDateTime::from_unix_timestamp_nanos(value).ok())
                .ok_or(DateError::ClockOutOfRange),
        }
    }

    pub(in crate::client_registry) fn unix_nanos(&self) -> Option<i128> {
        self.now.ok().map(OffsetDateTime::unix_timestamp_nanos)
    }

    fn year_for(&self, short_year: u8, fields: (u8, u8, u8, u8, u8)) -> Result<i32, DateError> {
        let now = self.now?;
        let boundary_year = now
            .year()
            .checked_add(50)
            .ok_or(DateError::ClockOutOfRange)?;
        let mut year = boundary_year
            .div_euclid(100)
            .checked_mul(100)
            .and_then(|century| century.checked_add(i32::from(short_year)))
            .ok_or(DateError::ClockOutOfRange)?;
        let (month, day, hour, minute, second) = fields;
        let proposed = (year, month, day, hour, minute, second, 0);
        // This is an ordered calendar boundary, including a possible February 29
        // in a non-leap boundary year; it is deliberately not constructed as Date.
        let boundary = (
            boundary_year,
            now.month() as u8,
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            now.nanosecond(),
        );
        if proposed > boundary {
            year = year.checked_sub(100).ok_or(DateError::ClockOutOfRange)?;
        }
        if !(1900..=9999).contains(&year) {
            return Err(DateError::ClockOutOfRange);
        }
        Ok(year)
    }
}

#[derive(Clone, Debug)]
pub(in crate::client_registry) struct HttpDate {
    date: Date,
    hour: u8,
    minute: u8,
    second: u8,
    // Retain the original field and, for two-digit dates, interpretation context.
    // They are provenance, not operands of UTC civil-date equality.
    _received: HeaderValue,
    _interpreted_at: Option<DateContext>,
}

impl HttpDate {
    pub(in crate::client_registry) fn unix_nanos(&self) -> Option<i128> {
        // Leap seconds remain valid parsed metadata with unavailable projection.
        Some(
            self.date
                .with_hms(self.hour, self.minute, self.second)
                .ok()?
                .assume_utc()
                .unix_timestamp_nanos(),
        )
    }

    pub(in crate::client_registry) fn same_instant(&self, other: &Self) -> bool {
        (self.date, self.hour, self.minute, self.second)
            == (other.date, other.hour, other.minute, other.second)
    }

    pub(in crate::client_registry) fn request_header(&self) -> Result<HeaderValue, DateError> {
        const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let value = format!(
            "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
            WEEKDAYS[usize::from(self.date.weekday().number_days_from_monday())],
            self.date.day(),
            MONTHS[usize::from(self.date.month() as u8) - 1],
            self.date.year(),
            self.hour,
            self.minute,
            self.second,
        );
        HeaderValue::from_str(&value).map_err(|_| DateError::Invalid)
    }
}

const DAY: Item<'static> = Item::Component(Component::Day(
    modifier::Day::default().with_padding(modifier::Padding::Zero),
));
const SPACE_DAY: Item<'static> = Item::Component(Component::Day(
    modifier::Day::default().with_padding(modifier::Padding::Space),
));
const MONTH: Item<'static> = Item::Component(Component::Month(
    modifier::Month::default()
        .with_repr(modifier::MonthRepr::Short)
        .with_case_sensitive(false),
));
const SHORT_WEEKDAY: Item<'static> = Item::Component(Component::Weekday(
    modifier::Weekday::default()
        .with_repr(modifier::WeekdayRepr::Short)
        .with_case_sensitive(false),
));
const LONG_WEEKDAY: Item<'static> = Item::Component(Component::Weekday(
    modifier::Weekday::default()
        .with_repr(modifier::WeekdayRepr::Long)
        .with_case_sensitive(false),
));
const YEAR: Item<'static> = Item::Component(Component::Year(
    modifier::Year::default()
        .with_padding(modifier::Padding::Zero)
        .with_repr(modifier::YearRepr::Full)
        .with_range(modifier::YearRange::Standard)
        .with_iso_week_based(false)
        .with_sign_is_mandatory(false),
));
const SHORT_YEAR: Item<'static> = Item::Component(Component::Year(
    modifier::Year::default().with_repr(modifier::YearRepr::LastTwo),
));
const HOUR: Item<'static> = Item::Component(Component::Hour(
    modifier::Hour::default().with_is_12_hour_clock(false),
));
const MINUTE: Item<'static> = Item::Component(Component::Minute(modifier::Minute::default()));
const SECOND: Item<'static> = Item::Component(Component::Second(modifier::Second::default()));
const SP: Item<'static> = Item::Literal(b" ");
const COLON: Item<'static> = Item::Literal(b":");
const IMF: &[Item<'static>] = &[
    SHORT_WEEKDAY,
    Item::Literal(b", "),
    DAY,
    SP,
    MONTH,
    SP,
    YEAR,
    SP,
    HOUR,
    COLON,
    MINUTE,
    COLON,
    SECOND,
    Item::Literal(b" GMT"),
];
const RFC850: &[Item<'static>] = &[
    LONG_WEEKDAY,
    Item::Literal(b", "),
    DAY,
    Item::Literal(b"-"),
    MONTH,
    Item::Literal(b"-"),
    SHORT_YEAR,
    SP,
    HOUR,
    COLON,
    MINUTE,
    COLON,
    SECOND,
    Item::Literal(b" GMT"),
];
const ASCTIME: &[Item<'static>] = &[
    SHORT_WEEKDAY,
    SP,
    MONTH,
    SP,
    SPACE_DAY,
    SP,
    HOUR,
    COLON,
    MINUTE,
    COLON,
    SECOND,
    SP,
    YEAR,
];

fn digits(bytes: &[u8], start: usize, end: usize) -> bool {
    bytes
        .get(start..end)
        .is_some_and(|part| part.iter().all(u8::is_ascii_digit))
}

pub(in crate::client_registry) fn parse_http_date(
    value: HeaderValue,
    context: DateContext,
) -> Result<HttpDate, DateError> {
    let raw = value.as_bytes();
    if !raw.is_ascii() {
        return Err(DateError::Invalid);
    }
    let comma = raw.iter().position(|byte| *byte == b',');
    let (description, short_year) = if raw.len() == 29 && comma == Some(3) {
        if ![(5, 7), (12, 16), (17, 19), (20, 22), (23, 25)]
            .iter()
            .all(|&(a, b)| digits(raw, a, b))
        {
            return Err(DateError::Invalid);
        }
        (IMF, false)
    } else if let Some(comma) = comma {
        if !(6..=9).contains(&comma)
            || raw.len() != comma + 24
            || ![(2, 4), (9, 11), (12, 14), (15, 17), (18, 20)]
                .iter()
                .all(|&(a, b)| digits(raw, comma + a, comma + b))
        {
            return Err(DateError::Invalid);
        }
        (RFC850, true)
    } else if raw.len() == 24 {
        if !(digits(raw, 8, 10) || (raw[8] == b' ' && raw[9].is_ascii_digit()))
            || ![(11, 13), (14, 16), (17, 19), (20, 24)]
                .iter()
                .all(|&(a, b)| digits(raw, a, b))
        {
            return Err(DateError::Invalid);
        }
        (ASCTIME, false)
    } else {
        return Err(DateError::Invalid);
    };
    let mut buffer = [0u8; 33];
    let normalized = buffer.get_mut(..raw.len()).ok_or(DateError::Invalid)?;
    normalized.copy_from_slice(raw);
    if comma.is_some() {
        let suffix = normalized.len() - 3;
        if !normalized[suffix..].eq_ignore_ascii_case(b"GMT") {
            return Err(DateError::Invalid);
        }
        normalized[suffix..].copy_from_slice(b"GMT");
    }
    let mut parsed = Parsed::new();
    let remainder = parsed
        .parse_items(normalized, description)
        .map_err(|_| DateError::Invalid)?;
    if !remainder.is_empty() {
        return Err(DateError::Invalid);
    }
    let month = parsed.month().ok_or(DateError::Invalid)?;
    let day = parsed.day().ok_or(DateError::Invalid)?.get();
    let hour = parsed.hour_24().ok_or(DateError::Invalid)?;
    let minute = parsed.minute().ok_or(DateError::Invalid)?;
    let second = parsed.second().ok_or(DateError::Invalid)?;
    if hour > 23 || minute > 59 || second > 60 {
        return Err(DateError::Invalid);
    }
    let year = if short_year {
        context.year_for(
            parsed.year_last_two().ok_or(DateError::Invalid)?,
            (month as u8, day, hour, minute, second),
        )?
    } else {
        parsed.year().ok_or(DateError::Invalid)?
    };
    if !(1900..=9999).contains(&year) {
        return Err(DateError::Invalid);
    }
    let date = Date::from_calendar_date(year, month, day).map_err(|_| DateError::Invalid)?;
    if Some(date.weekday()) != parsed.weekday() {
        return Err(DateError::Invalid);
    }
    Ok(HttpDate {
        date,
        hour,
        minute,
        second,
        _received: value,
        _interpreted_at: short_year.then_some(context),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(y: i32, m: u8, d: u8, h: u8, min: u8, s: u8, n: u32) -> DateContext {
        DateContext {
            now: Ok(Date::from_calendar_date(y, m.try_into().unwrap(), d)
                .unwrap()
                .with_hms_nano(h, min, s, n)
                .unwrap()
                .assume_utc()),
        }
    }
    fn parse(raw: &str, ctx: DateContext) -> Result<HttpDate, DateError> {
        parse_http_date(HeaderValue::from_str(raw).unwrap(), ctx)
    }
    #[test]
    fn all_forms_case_relaxation_historical_and_four_digit_bounds() {
        let ctx = context(2026, 7, 1, 12, 0, 0, 0);
        let canonical = parse("Sun, 06 Nov 1994 08:49:37 GMT", ctx).unwrap();
        for text in [
            "sUn, 06 nOv 1994 08:49:37 gMt",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "sUnDaY, 06-nOv-94 08:49:37 gMt",
            "Sun Nov  6 08:49:37 1994",
            "Sun Nov 06 08:49:37 1994",
        ] {
            let date = parse(text, ctx).unwrap();
            assert!(date.same_instant(&canonical));
            let emitted = date.request_header().unwrap();
            assert_eq!(emitted.as_bytes(), b"Sun, 06 Nov 1994 08:49:37 GMT");
            assert!(parse_http_date(emitted, ctx).unwrap().same_instant(&date));
        }
        for raw in [
            "Mon, 01 Jan 1900 00:00:00 GMT",
            "Wed, 31 Dec 1969 23:59:59 GMT",
            "Fri, 31 Dec 9999 23:59:59 GMT",
        ] {
            let date = parse(raw, ctx).unwrap();
            assert_eq!(date.request_header().unwrap().as_bytes(), raw.as_bytes());
        }
        for raw in [
            "Sun, 31 Dec 1899 23:59:59 GMT",
            "Mon, 06 Nov 1994 08:49:37 GMT",
            "Wed, 29 Feb 2023 00:00:00 GMT",
            "Sun, 31 Apr 1994 08:49:37 GMT",
        ] {
            assert!(matches!(parse(raw, ctx), Err(DateError::Invalid)));
        }
    }
    #[test]
    fn second_sixty_is_a_distinct_civil_label() {
        let ctx = context(2026, 1, 1, 0, 0, 0, 0);
        let leap = parse("Sat, 31 Dec 2016 23:59:60 GMT", ctx).unwrap();
        for raw in [
            "Saturday, 31-Dec-16 23:59:60 GMT",
            "Sat Dec 31 23:59:60 2016",
        ] {
            assert!(parse(raw, ctx).unwrap().same_instant(&leap));
        }
        assert_eq!(
            leap.request_header().unwrap().as_bytes(),
            b"Sat, 31 Dec 2016 23:59:60 GMT"
        );
        for raw in [
            "Sat, 31 Dec 2016 23:59:59 GMT",
            "Sun, 01 Jan 2017 00:00:00 GMT",
        ] {
            assert!(!parse(raw, ctx).unwrap().same_instant(&leap));
        }
        for raw in [
            "Sat, 31 Dec 2016 23:59:61 GMT",
            "Sat, 31 Dec 2016 24:00:00 GMT",
            "Sat, 31 Dec 2016 23:60:00 GMT",
        ] {
            assert!(parse(raw, ctx).is_err());
        }
    }
    #[test]
    fn exact_shapes_reject_email_and_coalesced_extensions() {
        let ctx = context(2026, 7, 1, 12, 0, 0, 0);
        for raw in [
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov +1994 08:49:37 GMT",
            "Sun, 06 Nov -1994 08:49:37 GMT",
            "Sun, 06 Nov 01994 08:49:37 GMT",
            "Sun, 06  Nov 1994 08:49:37 GMT",
            "Sun, 06\tNov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 +0000",
            "Sun, 06 Nov 1994 08:49 GMT",
            "Sun, 06 Nov 1994 08:49:37 GMT (date)",
            "Sun, 06 Nov 1994 08:49:37 GMT, Sun, 06 Nov 1994 08:49:37 GMT",
            "Sun Nov   6 08:49:37 1994",
        ] {
            assert!(parse(raw, ctx).is_err(), "accepted {raw}");
        }
        assert!(parse_http_date(
            HeaderValue::from_bytes(b"Sun, 06 Nov 1994 08:49:37 GM\x80").unwrap(),
            ctx
        )
        .is_err());
    }
    #[test]
    fn rolling_fifty_year_calendar_fraction_and_leap_boundary() {
        let ctx = context(2026, 7, 1, 12, 0, 0, 0);
        // Direct interpretation assertions independently specify the adopted ordered boundary.
        for (short, fields, year) in [
            (76, (7, 1, 12, 0, 0), 2076),
            (76, (7, 1, 12, 0, 1), 1976),
            (76, (6, 30, 23, 59, 60), 2076),
            (76, (7, 2, 0, 0, 0), 1976),
            (75, (12, 31, 23, 59, 59), 2075),
            (77, (1, 1, 0, 0, 0), 1977),
        ] {
            assert_eq!(ctx.year_for(short, fields).unwrap(), year);
        }
        let fractional = context(2026, 7, 1, 12, 0, 0, 500_000_000);
        assert_eq!(fractional.year_for(76, (7, 1, 12, 0, 0)).unwrap(), 2076);
        assert_eq!(fractional.year_for(76, (7, 1, 12, 0, 1)).unwrap(), 1976);
        assert_eq!(
            context(2050, 1, 1, 0, 0, 0, 0)
                .year_for(0, (1, 1, 0, 0, 0))
                .unwrap(),
            2100
        );
        assert_eq!(
            context(2050, 1, 1, 0, 0, 0, 0)
                .year_for(0, (1, 1, 0, 0, 1))
                .unwrap(),
            2000
        );
        let feb = context(2024, 2, 29, 0, 0, 0, 0);
        assert_eq!(feb.year_for(74, (2, 28, 0, 0, 0)).unwrap(), 2074);
        assert_eq!(feb.year_for(74, (3, 1, 0, 0, 0)).unwrap(), 1974);
        assert!(matches!(
            parse("Thursday, 29-Feb-74 00:00:00 GMT", feb),
            Err(DateError::Invalid)
        ));
        // Parsing, not just the interpretation helper, respects weekdays after selection.
        assert_eq!(
            parse("Wednesday, 01-Jul-76 12:00:00 GMT", ctx)
                .unwrap()
                .date
                .year(),
            2076
        );
        assert_eq!(
            parse("Thursday, 01-Jul-76 12:00:01 GMT", ctx)
                .unwrap()
                .date
                .year(),
            1976
        );
    }
    #[test]
    fn checked_preepoch_and_unavailable_clock_do_not_narrow_full_dates() {
        let ctx = DateContext::from_system_time(UNIX_EPOCH - std::time::Duration::from_millis(500));
        let now = ctx.now.unwrap();
        assert_eq!(now.unix_timestamp(), -1);
        assert_eq!(now.nanosecond(), 500_000_000);
        let unavailable = DateContext::from_system_time(
            UNIX_EPOCH + std::time::Duration::from_secs(253_402_300_800),
        );
        assert!(matches!(unavailable.now, Err(DateError::ClockOutOfRange)));
        assert!(matches!(
            parse("Sunday, 06-Nov-94 08:49:37 GMT", unavailable),
            Err(DateError::ClockOutOfRange)
        ));
        assert!(parse("Sun, 06 Nov 1994 08:49:37 GMT", unavailable).is_ok());
        assert!(parse("Sun Nov  6 08:49:37 1994", unavailable).is_ok());
        assert!(matches!(
            context(9999, 1, 1, 0, 0, 0, 0).year_for(40, (1, 1, 0, 0, 0)),
            Err(DateError::ClockOutOfRange)
        ));
    }
}
