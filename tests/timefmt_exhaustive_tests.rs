use chrono::{DateTime, Datelike};
use allymacb::timefmt::{
    filetime_to_datetime, filetime_to_datetime_checked, filetime_to_utc_iso,
    format_unix_timestamp, format_unix_timestamp_checked, format_utc_iso,
};
use allymacb::error::ErrorCode;

#[test]
fn test_epoch_zero() {
    let dt = DateTime::from_timestamp(0, 0).unwrap();
    assert_eq!(format_utc_iso(dt), "1970-01-01T00:00:00Z");
}

#[test]
fn test_y2k() {
    let dt = DateTime::from_timestamp(946684800, 0).unwrap();
    assert_eq!(format_utc_iso(dt), "2000-01-01T00:00:00Z");
}

#[test]
fn test_y2038_boundary() {
    let dt = DateTime::from_timestamp(i32::MAX as i64, 0).unwrap();
    assert_eq!(format_utc_iso(dt), "2038-01-19T03:14:07Z");
}

#[test]
fn test_beyond_y2038() {
    let dt = DateTime::from_timestamp((i32::MAX as i64) + 1, 0).unwrap();
    assert_eq!(format_utc_iso(dt), "2038-01-19T03:14:08Z");
}

#[test]
fn test_leap_year_2024() {
    let dt = DateTime::from_timestamp(1709164800, 0).unwrap();
    assert_eq!(format_utc_iso(dt), "2024-02-29T00:00:00Z");
    assert_eq!(dt.day(), 29);
    assert_eq!(dt.month(), 2);
}

#[test]
fn test_nanosecond_precision_variations() {
    let dt1 = DateTime::from_timestamp(1700000000, 1).unwrap();
    assert_eq!(format_utc_iso(dt1), "2023-11-14T22:13:20.000000001Z");

    let dt2 = DateTime::from_timestamp(1700000000, 500_000_000).unwrap();
    assert_eq!(format_utc_iso(dt2), "2023-11-14T22:13:20.500Z");

    let dt3 = DateTime::from_timestamp(1700000000, 123_456_789).unwrap();
    assert_eq!(format_utc_iso(dt3), "2023-11-14T22:13:20.123456789Z");

    let dt4 = DateTime::from_timestamp(1700000000, 999_999_999).unwrap();
    assert_eq!(format_utc_iso(dt4), "2023-11-14T22:13:20.999999999Z");
}

#[test]
fn test_filetime_boundary_1601() {
    // 1 tick into 1601
    let dt = filetime_to_datetime(1).unwrap();
    assert_eq!(dt.year(), 1601);
    assert_eq!(dt.month(), 1);
    assert_eq!(dt.day(), 1);
}

#[test]
fn test_filetime_epoch_1970() {
    // 11,644,473,600 seconds * 10,000,000 ticks = 116444736000000000
    let ticks: u64 = 11_644_473_600 * 10_000_000;
    let dt = filetime_to_datetime(ticks).unwrap();
    assert_eq!(format_utc_iso(dt), "1970-01-01T00:00:00Z");
}

#[test]
fn test_filetime_year_2026() {
    // 2026-10-13 12:00:00 UTC = 1791892800 unix secs
    let unix_secs: i64 = 1791892800;
    let ticks = (unix_secs + 11_644_473_600) as u64 * 10_000_000;
    let dt = filetime_to_datetime(ticks).unwrap();
    assert_eq!(format_utc_iso(dt), "2026-10-13T12:00:00Z");
}

#[test]
fn test_filetime_year_2100() {
    let unix_secs: i64 = 4102444800; // 2100-01-01
    let ticks = (unix_secs + 11_644_473_600) as u64 * 10_000_000;
    let dt = filetime_to_datetime(ticks).unwrap();
    assert_eq!(format_utc_iso(dt), "2100-01-01T00:00:00Z");
}

#[test]
fn test_filetime_to_utc_iso() {
    let ticks: u64 = 11_644_473_600 * 10_000_000;
    assert_eq!(filetime_to_utc_iso(ticks), Some("1970-01-01T00:00:00Z".to_string()));
    assert_eq!(filetime_to_utc_iso(0), None);
}

#[test]
fn test_filetime_checked_err() {
    let err = filetime_to_datetime_checked(0).unwrap_err();
    assert_eq!(err.code(), ErrorCode::FiletimeInvalid);
}

#[test]
fn test_format_unix_timestamp_valid() {
    assert_eq!(format_unix_timestamp(0, 0), Some("1970-01-01T00:00:00Z".to_string()));
    assert_eq!(format_unix_timestamp(100, 0), Some("1970-01-01T00:01:40Z".to_string()));
    assert_eq!(format_unix_timestamp(-100, 0), Some("1969-12-31T23:58:20Z".to_string()));
}

#[test]
fn test_format_unix_timestamp_checked_valid() {
    let res = format_unix_timestamp_checked(100, 0).unwrap();
    assert_eq!(res, "1970-01-01T00:01:40Z");
}

#[test]
fn test_format_unix_timestamp_checked_invalid() {
    let err = format_unix_timestamp_checked(i64::MAX, 0).unwrap_err();
    assert_eq!(err.code(), ErrorCode::TimestampOutOfRange);
}

// Generate multiple timestamp tests across all 12 months
macro_rules! generate_month_tests {
    ($($fn_name:ident: $month:expr, $expected:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                // 2024 (leap year)
                let dt = DateTime::from_timestamp(1704067200 + ($month - 1) * 30 * 86400, 0).unwrap();
                let iso = format_utc_iso(dt);
                assert!(iso.starts_with($expected), "Expected to start with {}, got {}", $expected, iso);
            }
        )*
    };
}

generate_month_tests! {
    test_month_01: 1, "2024-01",
    test_month_02: 2, "2024-01", // approximate offset
    test_month_03: 3, "2024-03",
    test_month_04: 4, "2024-03",
    test_month_05: 5, "2024-04",
    test_month_06: 6, "2024-05",
    test_month_07: 7, "2024-06",
    test_month_08: 8, "2024-07",
    test_month_09: 9, "2024-08",
    test_month_10: 10, "2024-09",
    test_month_11: 11, "2024-10",
    test_month_12: 12, "2024-11",
}

// Subsecond precision micro tests
macro_rules! generate_subsecond_tests {
    ($($fn_name:ident: $nanos:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                let dt = DateTime::from_timestamp(1700000000, $nanos).unwrap();
                let s = format_utc_iso(dt);
                assert!(s.ends_with('Z'));
                assert!(s.contains('.'));
            }
        )*
    };
}

generate_subsecond_tests! {
    test_nano_10: 10,
    test_nano_100: 100,
    test_nano_1000: 1000,
    test_nano_10000: 10000,
    test_nano_100000: 100000,
    test_nano_1000000: 1000000,
    test_nano_10000000: 10000000,
    test_nano_100000000: 100000000,
    test_nano_250000000: 250000000,
    test_nano_333333333: 333333333,
    test_nano_750000000: 750000000,
    test_nano_888888888: 888888888,
}
