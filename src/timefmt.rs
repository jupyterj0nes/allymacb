use chrono::{DateTime, Utc};

/// Windows ticks (100-nanosecond units) per second.
const WINDOWS_TICK_100NS: i64 = 10_000_000;
/// Number of seconds between 1601-01-01 (Windows epoch) and 1970-01-01 (Unix epoch).
const SECS_BETWEEN_1601_AND_1970: i64 = 11_644_473_600;

/// Formats a `DateTime<Utc>` into the standard UTC ISO 8601 string used by `masstin` and `caarea`.
/// e.g. "2024-02-04T12:35:00Z" or "2025-01-24T13:56:57.745546Z".
pub fn format_utc_iso(dt: DateTime<Utc>) -> String {
    if dt.timestamp_subsec_nanos() == 0 {
        dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        dt.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string()
    }
}

/// Converts Unix seconds and nanoseconds to the standard UTC ISO 8601 string.
pub fn format_unix_timestamp(secs: i64, nsecs: u32) -> Option<String> {
    DateTime::from_timestamp(secs, nsecs).map(format_utc_iso)
}

/// Converts a 64-bit Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC)
/// into a `DateTime<Utc>`.
pub fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    let ticks = filetime as i64;
    let secs_since_1601 = ticks / WINDOWS_TICK_100NS;
    let subsec_ticks = (ticks % WINDOWS_TICK_100NS) as u32;
    let nsecs = subsec_ticks * 100;
    let unix_secs = secs_since_1601 - SECS_BETWEEN_1601_AND_1970;

    DateTime::from_timestamp(unix_secs, nsecs)
}

/// Converts a 64-bit Windows FILETIME to the standard UTC ISO 8601 string.
#[allow(dead_code)]
pub fn filetime_to_utc_iso(filetime: u64) -> Option<String> {
    filetime_to_datetime(filetime).map(format_utc_iso)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_utc_iso_round_seconds() {
        let dt = DateTime::from_timestamp(1707050100, 0).unwrap();
        assert_eq!(format_utc_iso(dt), "2024-02-04T12:35:00Z");
    }

    #[test]
    fn test_format_utc_iso_subseconds() {
        let dt = DateTime::from_timestamp(1737727017, 745546000).unwrap();
        assert_eq!(format_utc_iso(dt), "2025-01-24T13:56:57.745546Z");
    }

    #[test]
    fn test_filetime_conversion() {
        // 133515045000000000 -> 2024-02-04 12:35:00 UTC
        let ft: u64 = (1707050100 + SECS_BETWEEN_1601_AND_1970) as u64 * 10_000_000;
        let iso = filetime_to_utc_iso(ft);
        assert_eq!(iso, Some("2024-02-04T12:35:00Z".to_string()));
    }
}
