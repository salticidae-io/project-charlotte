//! Formatting and parsing of HTTP dates (RFC 7231 / RFC 9110, "HTTP-date").
//!
//! Dates are always produced in the preferred IMF-fixdate form, e.g.
//! `Sun, 06 Nov 1994 08:49:37 GMT`. When parsing, the two obsolete formats that
//! recipients are required to accept are also supported:
//!
//! * RFC 850: `Sunday, 06-Nov-94 08:49:37 GMT`
//! * ANSI C `asctime()`: `Sun Nov  6 08:49:37 1994`
//!
//! All times are interpreted as UTC (GMT), with calendar conversions handled
//! by the `chrono` crate.

// Only static file serving parses dates (for conditional requests); every
// build formats them.
#![cfg_attr(not(feature = "hosting"), allow(dead_code))]

use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, TimeDelta, Utc};

/// Abbreviated weekday names, indexed from Sunday (`0`) to Saturday (`6`).
const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
/// Full weekday names used by the obsolete RFC 850 format, indexed like [`WEEKDAYS`].
const FULL_WEEKDAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
/// Abbreviated month names, indexed from January (`0`) to December (`11`).
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Formats `time` as an IMF-fixdate HTTP date, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// Sub-second precision is truncated.
pub fn format_http_date(time: DateTime<Utc>) -> String {
    time.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Parses an HTTP date in any of the three formats accepted by RFC 7231:
/// IMF-fixdate, RFC 850, or ANSI C `asctime()`.
///
/// Returns `None` if the value is not ASCII, does not match one of the formats,
/// names a non-existent calendar date (e.g. 31 Feb), has a weekday that does
/// not match the date, or is outside Chrono's supported date range.
pub fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    // Rejecting non-ASCII input up front guarantees that the byte-index slicing
    // performed by the format-specific parsers always lands on char boundaries.
    if !value.is_ascii() {
        return None;
    }

    // Dispatch on the shape of the input: IMF-fixdate is always exactly 29
    // characters, other values containing ", " are treated as RFC 850 dates,
    // and anything else is attempted as an asctime() date.
    if value.len() == 29 {
        return parse_imf_fixdate(value);
    }
    if let Some((weekday, remainder)) = value.split_once(", ") {
        return parse_rfc850_date(weekday, remainder);
    }
    parse_asctime_date(value)
}

/// Parses an IMF-fixdate such as `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// The caller must ensure `value` is ASCII and exactly 29 bytes long; the
/// fixed-position separators are validated here before fields are extracted.
fn parse_imf_fixdate(value: &str) -> Option<DateTime<Utc>> {
    let bytes = value.as_bytes();
    if &bytes[3..5] != b", "
        || &bytes[7..8] != b" "
        || &bytes[11..12] != b" "
        || &bytes[16..17] != b" "
        || &bytes[25..] != b" GMT"
    {
        return None;
    }

    let weekday = &value[..3];
    let day = u32::try_from(parse_digits(&bytes[5..7])?).ok()?;
    let month = MONTHS.iter().position(|month| *month == &value[8..11])? as u32 + 1;
    let year = i64::try_from(parse_digits(&bytes[12..16])?).ok()?;
    let (hour, minute, second) = parse_clock(&value[17..25])?;
    make_time(weekday, day, month, year, hour, minute, second)
}

/// Parses an obsolete RFC 850 date such as `Sunday, 06-Nov-94 08:49:37 GMT`.
///
/// `weekday` is the text before the `", "` separator (which must be a full
/// weekday name) and `remainder` is everything after it.
///
/// The two-digit year is resolved as recommended by RFC 7231 §7.1.1.1: it is
/// placed in the current century unless that would put it more than 50 years
/// in the future, in which case the previous century is used.
fn parse_rfc850_date(weekday: &str, remainder: &str) -> Option<DateTime<Utc>> {
    if !FULL_WEEKDAYS.contains(&weekday) {
        return None;
    }
    let mut fields = remainder.split_whitespace();
    let date = fields.next()?;
    let clock = fields.next()?;
    if fields.next()? != "GMT" || fields.next().is_some() {
        return None;
    }
    let mut date_fields = date.split('-');
    let day = u32::try_from(parse_digits(date_fields.next()?.as_bytes())?).ok()?;
    let month = month_number(date_fields.next()?)?;
    let short_year = u32::try_from(parse_digits(date_fields.next()?.as_bytes())?).ok()?;
    if date_fields.next().is_some() || short_year > 99 {
        return None;
    }
    let current_year = i64::from(Utc::now().year());
    let mut year = current_year.div_euclid(100) * 100 + i64::from(short_year);
    if year > current_year + 50 {
        year -= 100;
    }
    let (hour, minute, second) = parse_clock(clock)?;
    make_time(weekday, day, month, year, hour, minute, second)
}

/// Parses an ANSI C `asctime()` date such as `Sun Nov  6 08:49:37 1994`.
///
/// Fields are split on whitespace, so the space-padded single-digit day used
/// by `asctime()` is accepted.
fn parse_asctime_date(value: &str) -> Option<DateTime<Utc>> {
    let mut fields = value.split_whitespace();
    let weekday = fields.next()?;
    let month = month_number(fields.next()?)?;
    let day = u32::try_from(parse_digits(fields.next()?.as_bytes())?).ok()?;
    let (hour, minute, second) = parse_clock(fields.next()?)?;
    let year = i64::try_from(parse_digits(fields.next()?.as_bytes())?).ok()?;
    if fields.next().is_some() {
        return None;
    }
    make_time(weekday, day, month, year, hour, minute, second)
}

/// Parses an `HH:MM:SS` time of day into `(hour, minute, second)`.
///
/// Only the shape is checked here; range validation happens in [`make_time`].
fn parse_clock(value: &str) -> Option<(u32, u32, u32)> {
    if value.len() != 8 || value.as_bytes()[2] != b':' || value.as_bytes()[5] != b':' {
        return None;
    }
    Some((
        parse_digits(&value.as_bytes()[0..2])? as u32,
        parse_digits(&value.as_bytes()[3..5])? as u32,
        parse_digits(&value.as_bytes()[6..8])? as u32,
    ))
}

/// Maps an abbreviated, case-sensitive month name (`"Jan"`..`"Dec"`) to `1..=12`.
fn month_number(value: &str) -> Option<u32> {
    MONTHS
        .iter()
        .position(|month| *month == value)
        .map(|month| month as u32 + 1)
}

/// Validates the parsed date/time fields and converts them into a [`DateTime<Utc>`].
///
/// `weekday` may be either an abbreviated or full name and must match the
/// actual weekday of the given date. A `second` value of `60` is accepted to
/// allow for leap seconds; it is folded into the following minute. Returns
/// `None` for out-of-range fields, impossible dates, or dates outside Chrono's
/// supported range.
fn make_time(
    weekday: &str,
    day: u32,
    month: u32,
    year: i64,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<DateTime<Utc>> {
    if hour > 23
        || minute > 59
        || second > 60
        || (!WEEKDAYS.contains(&weekday) && !FULL_WEEKDAYS.contains(&weekday))
    {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, day)?;
    let actual_weekday = date.weekday().num_days_from_sunday() as usize;
    if WEEKDAYS[actual_weekday] != weekday && FULL_WEEKDAYS[actual_weekday] != weekday {
        return None;
    }
    let time = NaiveTime::from_hms_opt(hour, minute, second.min(59))?;
    let date_time = date.and_time(time).and_utc();
    if second == 60 {
        date_time.checked_add_signed(TimeDelta::seconds(1))
    } else {
        Some(date_time)
    }
}

/// Parses a non-empty run of ASCII digits as an unsigned integer.
///
/// Unlike `str::parse`, this rejects signs (`+`/`-`) and any other non-digit
/// characters. Returns `None` on overflow.
fn parse_digits(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{format_http_date, parse_http_date};
    use chrono::{DateTime, Utc};

    #[test]
    fn formats_and_parses_rfc_7231_date() {
        let time = DateTime::<Utc>::from_timestamp(784_111_777, 0).unwrap();
        let date = format_http_date(time);
        assert_eq!(date, "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(parse_http_date(&date), Some(time));
    }

    #[test]
    fn rejects_invalid_calendar_dates_and_weekdays() {
        assert_eq!(parse_http_date("Sun, 31 Feb 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Mon, 06 Nov 1994 08:49:37 GMT"), None);
    }

    #[test]
    fn accepts_the_two_obsolete_http_date_formats() {
        let expected = DateTime::<Utc>::from_timestamp(784_111_777, 0).unwrap();
        assert_eq!(
            parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(expected)
        );
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), Some(expected));
    }

    #[test]
    fn formats_and_parses_dates_before_the_unix_epoch() {
        let time = DateTime::<Utc>::from_timestamp(-1, 0).unwrap();
        let date = format_http_date(time);
        assert_eq!(date, "Wed, 31 Dec 1969 23:59:59 GMT");
        assert_eq!(parse_http_date(&date), Some(time));
    }

    #[test]
    fn folds_leap_seconds_into_the_following_minute() {
        let time = parse_http_date("Sun, 06 Nov 1994 08:49:60 GMT").unwrap();
        assert_eq!(format_http_date(time), "Sun, 06 Nov 1994 08:50:00 GMT");
    }

    #[test_fuzz::test_fuzz]
    fn http_date(value: &str) {
        if let Some(time) = parse_http_date(value) {
            let formatted = format_http_date(time);
            assert_eq!(parse_http_date(&formatted), Some(time));
        }
    }

    #[test]
    fn fuzz_seed_http_date() {
        http_date("Sun, 06 Nov 1994 08:49:37 GMT");
        http_date("not a date");
    }
}
