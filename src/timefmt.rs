use chrono::{DateTime, Utc};
use crate::error::{AllyError, ErrorCode};

/// Windows ticks (100-nanosecond units) per second.
const WINDOWS_TICK_100NS: i64 = 10_000_000;
/// Number of seconds between 1601-01-01 (Windows epoch) and 1970-01-01 (Unix epoch).
pub const SECS_BETWEEN_1601_AND_1970: i64 = 11_644_473_600;

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

/// Checked version of format_unix_timestamp returning AllyError on out of range.
#[allow(dead_code)]
pub fn format_unix_timestamp_checked(secs: i64, nsecs: u32) -> Result<String, AllyError> {
    DateTime::from_timestamp(secs, nsecs)
        .map(format_utc_iso)
        .ok_or_else(|| AllyError::Timestamp {
            code: ErrorCode::TimestampOutOfRange,
            raw_value: secs,
            message: format!("Unix timestamp {}s + {}ns is out of supported range", secs, nsecs),
        })
}

/// Converts a 64-bit Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC)
/// into a `DateTime<Utc>`.
///
/// Returns `None` for 0 (NTFS "unset") and for any value with the high bit
/// set: those are not valid FILETIMEs (Windows treats FILETIME as a signed
/// 64-bit quantity) and would otherwise overflow the conversion.
pub fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    let ticks = i64::try_from(filetime).ok()?;
    let secs_since_1601 = ticks / WINDOWS_TICK_100NS;
    let subsec_ticks = (ticks % WINDOWS_TICK_100NS) as u32;
    let nsecs = subsec_ticks.checked_mul(100)?;
    let unix_secs = secs_since_1601.checked_sub(SECS_BETWEEN_1601_AND_1970)?;

    DateTime::from_timestamp(unix_secs, nsecs)
}

/// Checked version of filetime_to_datetime returning AllyError on invalid ticks.
#[allow(dead_code)]
pub fn filetime_to_datetime_checked(filetime: u64) -> Result<DateTime<Utc>, AllyError> {
    filetime_to_datetime(filetime).ok_or_else(|| AllyError::Timestamp {
        code: ErrorCode::FiletimeInvalid,
        raw_value: i64::try_from(filetime).unwrap_or(i64::MAX),
        message: format!("Windows FILETIME ticks {} are invalid or represent year < 1601", filetime),
    })
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
        // 1707050100 unix = 2024-02-04 12:35:00 UTC
        let ft: u64 = (1707050100 + SECS_BETWEEN_1601_AND_1970) as u64 * 10_000_000;
        let iso = filetime_to_utc_iso(ft);
        assert_eq!(iso, Some("2024-02-04T12:35:00Z".to_string()));
    }

    #[test]
    fn test_filetime_zero_returns_none() {
        assert_eq!(filetime_to_datetime(0), None);
    }

    #[test]
    fn test_filetime_high_bit_returns_none_without_panic() {
        assert_eq!(filetime_to_datetime(u64::MAX), None);
        assert_eq!(filetime_to_datetime(0x8000_0000_0000_0000), None);
        assert_eq!(filetime_to_datetime(0x8000_0000_0000_0000 + 4_775_808), None);
        // Largest valid FILETIME still converts (or is out of chrono range -> None), never panics.
        let _ = filetime_to_datetime(i64::MAX as u64);
    }

    #[test]
    fn test_format_unix_timestamp_checked_err() {
        let err = format_unix_timestamp_checked(i64::MAX, 0).unwrap_err();
        assert_eq!(err.code(), ErrorCode::TimestampOutOfRange);
    }
}
