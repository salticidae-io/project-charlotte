use std::time::{Duration, SystemTime, UNIX_EPOCH};

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const FULL_WEEKDAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn format_http_date(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (seconds / 86_400) as i64;
    let seconds_in_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let weekday = ((days + 4).rem_euclid(7)) as usize;
    let hour = seconds_in_day / 3_600;
    let minute = (seconds_in_day % 3_600) / 60;
    let second = seconds_in_day % 60;

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[weekday],
        day,
        MONTHS[(month - 1) as usize],
        year,
        hour,
        minute,
        second
    )
}

pub fn parse_http_date(value: &str) -> Option<SystemTime> {
    if !value.is_ascii() {
        return None;
    }

    if value.len() == 29 {
        return parse_imf_fixdate(value);
    }
    if let Some((weekday, remainder)) = value.split_once(", ") {
        return parse_rfc850_date(weekday, remainder);
    }
    parse_asctime_date(value)
}

fn parse_imf_fixdate(value: &str) -> Option<SystemTime> {
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

fn parse_rfc850_date(weekday: &str, remainder: &str) -> Option<SystemTime> {
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
    let current_year = civil_from_days(
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 86_400) as i64,
    )
    .0;
    let mut year = current_year.div_euclid(100) * 100 + i64::from(short_year);
    if year > current_year + 50 {
        year -= 100;
    }
    let (hour, minute, second) = parse_clock(clock)?;
    make_time(weekday, day, month, year, hour, minute, second)
}

fn parse_asctime_date(value: &str) -> Option<SystemTime> {
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

fn month_number(value: &str) -> Option<u32> {
    MONTHS
        .iter()
        .position(|month| *month == value)
        .map(|month| month as u32 + 1)
}

fn make_time(
    weekday: &str,
    day: u32,
    month: u32,
    year: i64,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<SystemTime> {
    if hour > 23
        || minute > 59
        || second > 60
        || (!WEEKDAYS.contains(&weekday) && !FULL_WEEKDAYS.contains(&weekday))
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let actual_weekday = ((days + 4).rem_euclid(7)) as usize;
    if WEEKDAYS[actual_weekday] != weekday && FULL_WEEKDAYS[actual_weekday] != weekday {
        return None;
    }
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))?;
    if seconds < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
}

fn parse_digits(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > month_days {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::{format_http_date, parse_http_date};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn formats_and_parses_rfc_7231_date() {
        let time = UNIX_EPOCH + Duration::from_secs(784_111_777);
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
        let expected = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(
            parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(expected)
        );
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), Some(expected));
    }
}
