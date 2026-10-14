use allymacb::error::{AllyError, ErrorCode};
use std::io::{Error, ErrorKind};

#[test]
fn test_error_code_strings() {
    assert_eq!(ErrorCode::IoError.as_str(), "ERR_IO_1001");
    assert_eq!(ErrorCode::FileNotFound.as_str(), "ERR_FILE_NOT_FOUND_1002");
    assert_eq!(ErrorCode::PermissionDenied.as_str(), "ERR_PERMISSION_DENIED_1003");
    assert_eq!(ErrorCode::MftInitFailed.as_str(), "ERR_MFT_INIT_2001");
    assert_eq!(ErrorCode::MftEntryCorrupt.as_str(), "ERR_MFT_ENTRY_CORRUPT_2002");
    assert_eq!(ErrorCode::MftAttributeInvalid.as_str(), "ERR_MFT_ATTR_INVALID_2003");
    assert_eq!(ErrorCode::MftResidentExtractionFailed.as_str(), "ERR_MFT_RESIDENT_DUMP_2004");
    assert_eq!(ErrorCode::UsnTruncated.as_str(), "ERR_USN_TRUNCATED_3001");
    assert_eq!(ErrorCode::UsnInvalidRecordLength.as_str(), "ERR_USN_INVALID_LENGTH_3002");
    assert_eq!(ErrorCode::UsnUnsupportedVersion.as_str(), "ERR_USN_UNSUPPORTED_VERSION_3003");
    assert_eq!(ErrorCode::Ext4SuperblockInvalid.as_str(), "ERR_EXT4_SUPERBLOCK_4001");
    assert_eq!(ErrorCode::Ext4DirectoryTraversalFailed.as_str(), "ERR_EXT4_TRAVERSAL_4002");
    assert_eq!(ErrorCode::Ext4MetadataReadFailed.as_str(), "ERR_EXT4_METADATA_4003");
    assert_eq!(ErrorCode::ArchiveDecompressionFailed.as_str(), "ERR_ARCHIVE_DECOMPRESS_5001");
    assert_eq!(ErrorCode::ArchiveCorrupt.as_str(), "ERR_ARCHIVE_CORRUPT_5002");
    assert_eq!(ErrorCode::ArchiveUnsupportedFormat.as_str(), "ERR_ARCHIVE_UNSUPPORTED_5003");
    assert_eq!(ErrorCode::ImageReadFailed.as_str(), "ERR_IMAGE_READ_6001");
    assert_eq!(ErrorCode::ImagePartitionTableCorrupt.as_str(), "ERR_IMAGE_PARTITION_6002");
    assert_eq!(ErrorCode::ImageUnsupportedFormat.as_str(), "ERR_IMAGE_UNSUPPORTED_6003");
    assert_eq!(ErrorCode::BodyfileInvalidFieldCount.as_str(), "ERR_BODYFILE_FIELDS_7001");
    assert_eq!(ErrorCode::BodyfileTimestampInvalid.as_str(), "ERR_BODYFILE_TIMESTAMP_7002");
    assert_eq!(ErrorCode::TimestampOutOfRange.as_str(), "ERR_TIMESTAMP_RANGE_8001");
    assert_eq!(ErrorCode::FiletimeInvalid.as_str(), "ERR_FILETIME_INVALID_8002");
    assert_eq!(ErrorCode::CsvExportFailed.as_str(), "ERR_CSV_EXPORT_9001");
}

#[test]
fn test_error_code_display() {
    assert_eq!(format!("{}", ErrorCode::IoError), "ERR_IO_1001");
    assert_eq!(format!("{}", ErrorCode::CsvExportFailed), "ERR_CSV_EXPORT_9001");
}

#[test]
fn test_ally_error_io_conversion() {
    let not_found = Error::new(ErrorKind::NotFound, "file not found");
    let ally_err: AllyError = not_found.into();
    assert_eq!(ally_err.code(), ErrorCode::FileNotFound);
    assert!(format!("{}", ally_err).contains("ERR_FILE_NOT_FOUND_1002"));

    let perm_denied = Error::new(ErrorKind::PermissionDenied, "access denied");
    let ally_err2: AllyError = perm_denied.into();
    assert_eq!(ally_err2.code(), ErrorCode::PermissionDenied);
    assert!(format!("{}", ally_err2).contains("ERR_PERMISSION_DENIED_1003"));

    let other_err = Error::new(ErrorKind::Other, "disk failure");
    let ally_err3: AllyError = other_err.into();
    assert_eq!(ally_err3.code(), ErrorCode::IoError);
}

#[test]
fn test_ally_error_variants_code() {
    let err_mft = AllyError::Mft {
        code: ErrorCode::MftInitFailed,
        entry: Some(10),
        message: "bad record".to_string(),
    };
    assert_eq!(err_mft.code(), ErrorCode::MftInitFailed);
    assert!(format!("{}", err_mft).contains("MFT Entry #10"));

    let err_usn = AllyError::Usn {
        code: ErrorCode::UsnTruncated,
        offset: 0x1000,
        message: "truncated".to_string(),
    };
    assert_eq!(err_usn.code(), ErrorCode::UsnTruncated);
    assert!(format!("{}", err_usn).contains("0x1000"));

    let err_ext4 = AllyError::Ext4 {
        code: ErrorCode::Ext4SuperblockInvalid,
        message: "bad magic".to_string(),
    };
    assert_eq!(err_ext4.code(), ErrorCode::Ext4SuperblockInvalid);

    let err_arch = AllyError::Archive {
        code: ErrorCode::ArchiveCorrupt,
        path: "test.zip".to_string(),
        message: "crc error".to_string(),
    };
    assert_eq!(err_arch.code(), ErrorCode::ArchiveCorrupt);

    let err_img = AllyError::Image {
        code: ErrorCode::ImageReadFailed,
        path: "test.dd".to_string(),
        message: "read error".to_string(),
    };
    assert_eq!(err_img.code(), ErrorCode::ImageReadFailed);

    let err_bf = AllyError::Bodyfile {
        code: ErrorCode::BodyfileInvalidFieldCount,
        line: 12,
        message: "missing field".to_string(),
    };
    assert_eq!(err_bf.code(), ErrorCode::BodyfileInvalidFieldCount);

    let err_ts = AllyError::Timestamp {
        code: ErrorCode::TimestampOutOfRange,
        raw_value: -9999999999999,
        message: "prehistoric".to_string(),
    };
    assert_eq!(err_ts.code(), ErrorCode::TimestampOutOfRange);

    let err_csv = AllyError::Csv {
        code: ErrorCode::CsvExportFailed,
        message: "disk full".to_string(),
    };
    assert_eq!(err_csv.code(), ErrorCode::CsvExportFailed);
}
