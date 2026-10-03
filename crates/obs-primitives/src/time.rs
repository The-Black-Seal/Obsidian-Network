//! Calendar helpers for protocol timestamps.
//!
//! Protocol time is a 64-bit count of seconds since the Unix epoch (UTC, no
//! leap seconds — the same convention block timestamps use).  These helpers
//! only convert between that integer and ISO-8601 text for display and API
//! output; they never influence consensus.

/// Number of seconds in one minute.
pub const MINUTE: u64 = 60;
/// Number of seconds in one hour.
pub const HOUR: u64 = 60 * MINUTE;
/// Number of seconds in one day.
pub const DAY: u64 = 24 * HOUR;

/// Converts days since 1970-01-01 into a `(year, month, day)` triple.
///
/// Algorithm from Howard Hinnant's `civil_from_days`, valid for the entire
/// range of `i64` days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Converts a `(year, month, day)` triple into days since 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as u64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
}

/// Formats a Unix timestamp as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn unix_to_iso8601(secs: u64) -> String {
    let days = (secs / DAY) as i64;
    let rem = secs % DAY;
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (rem / HOUR, (rem % HOUR) / MINUTE, rem % MINUTE);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hh, mm, ss
    )
}

/// Parses `YYYY-MM-DDTHH:MM:SSZ` (the only accepted form) into a Unix timestamp.
pub fn iso8601_to_unix(s: &str) -> Option<u64> {
    let bytes = s.as_bytes();
    if bytes.len() != 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T'
        || bytes[13] != b':' || bytes[16] != b':' || bytes[19] != b'Z'
    {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<u64> {
        let slice = s.get(a..b)?;
        if !slice.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        slice.parse().ok()
    };
    let year = num(0, 4)? as i64;
    let month = num(5, 7)? as u32;
    let day = num(8, 10)? as u32;
    let hour = num(11, 13)?;
    let minute = num(14, 16)?;
    let second = num(17, 19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60
    {
        return None;
    }
    // Validate the day against the month (including leap years).
    let dim = days_in_month(year, month);
    if day > dim {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    Some(days as u64 * DAY + hour * HOUR + minute * MINUTE + second)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_timestamps() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_iso8601(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(unix_to_iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(unix_to_iso8601(2_147_483_647), "2038-01-19T03:14:07Z");
    }

    #[test]
    fn roundtrip() {
        for secs in [0u64, 1, 86_399, 86_400, 1_700_000_000, 4_102_444_800] {
            let s = unix_to_iso8601(secs);
            assert_eq!(iso8601_to_unix(&s), Some(secs), "roundtrip {}", s);
        }
    }

    #[test]
    fn invalid_timestamps_are_rejected() {
        assert_eq!(iso8601_to_unix("2023-11-14T22:13:20"), None);
        assert_eq!(iso8601_to_unix("2023-13-14T22:13:20Z"), None);
        assert_eq!(iso8601_to_unix("2023-02-30T22:13:20Z"), None);
        assert_eq!(iso8601_to_unix("2023-11-14T25:13:20Z"), None);
        assert_eq!(iso8601_to_unix("nonsense"), None);
        // 2024 is a leap year, so February 29 exists.
        assert!(iso8601_to_unix("2024-02-29T00:00:00Z").is_some());
        assert!(iso8601_to_unix("2023-02-29T00:00:00Z").is_none());
    }
}
