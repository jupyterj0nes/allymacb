use std::fmt;

/// Standardized error codes for DFIR forensic auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum ErrorCode {
    // I/O & Filesystem (E1xxx)
    IoError = 1001,
    FileNotFound = 1002,
    PermissionDenied = 1003,

    // Windows NTFS & MFT (E2xxx)
    MftInitFailed = 2001,
    MftEntryCorrupt = 2002,
    MftAttributeInvalid = 2003,
    MftResidentExtractionFailed = 2004,

    // USN Journal (E3xxx)
    UsnTruncated = 3001,
    UsnInvalidRecordLength = 3002,
    UsnUnsupportedVersion = 3003,

    // Linux Ext4 (E4xxx)
    Ext4SuperblockInvalid = 4001,
    Ext4DirectoryTraversalFailed = 4002,
    Ext4MetadataReadFailed = 4003,

    // Archives (E5xxx)
    ArchiveDecompressionFailed = 5001,
    ArchiveCorrupt = 5002,
    ArchiveUnsupportedFormat = 5003,

    // Disk Images (E6xxx)
    ImageReadFailed = 6001,
    ImagePartitionTableCorrupt = 6002,
    ImageUnsupportedFormat = 6003,

    // Bodyfile (E7xxx)
    BodyfileInvalidFieldCount = 7001,
    BodyfileTimestampInvalid = 7002,
    BodyfileNumericFieldInvalid = 7003,

    // Timestamps (E8xxx)
    TimestampOutOfRange = 8001,
    FiletimeInvalid = 8002,

    // Export & Formatting (E9xxx)
    CsvExportFailed = 9001,

    // Evidence ingestion (E10xxx)
    EvidenceUnrecognized = 10001,
    EvidenceNothingParsed = 10002,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::IoError => "ERR_IO_1001",
            ErrorCode::FileNotFound => "ERR_FILE_NOT_FOUND_1002",
            ErrorCode::PermissionDenied => "ERR_PERMISSION_DENIED_1003",
            ErrorCode::MftInitFailed => "ERR_MFT_INIT_2001",
            ErrorCode::MftEntryCorrupt => "ERR_MFT_ENTRY_CORRUPT_2002",
            ErrorCode::MftAttributeInvalid => "ERR_MFT_ATTR_INVALID_2003",
            ErrorCode::MftResidentExtractionFailed => "ERR_MFT_RESIDENT_DUMP_2004",
            ErrorCode::UsnTruncated => "ERR_USN_TRUNCATED_3001",
            ErrorCode::UsnInvalidRecordLength => "ERR_USN_INVALID_LENGTH_3002",
            ErrorCode::UsnUnsupportedVersion => "ERR_USN_UNSUPPORTED_VERSION_3003",
            ErrorCode::Ext4SuperblockInvalid => "ERR_EXT4_SUPERBLOCK_4001",
            ErrorCode::Ext4DirectoryTraversalFailed => "ERR_EXT4_TRAVERSAL_4002",
            ErrorCode::Ext4MetadataReadFailed => "ERR_EXT4_METADATA_4003",
            ErrorCode::ArchiveDecompressionFailed => "ERR_ARCHIVE_DECOMPRESS_5001",
            ErrorCode::ArchiveCorrupt => "ERR_ARCHIVE_CORRUPT_5002",
            ErrorCode::ArchiveUnsupportedFormat => "ERR_ARCHIVE_UNSUPPORTED_5003",
            ErrorCode::ImageReadFailed => "ERR_IMAGE_READ_6001",
            ErrorCode::ImagePartitionTableCorrupt => "ERR_IMAGE_PARTITION_6002",
            ErrorCode::ImageUnsupportedFormat => "ERR_IMAGE_UNSUPPORTED_6003",
            ErrorCode::BodyfileInvalidFieldCount => "ERR_BODYFILE_FIELDS_7001",
            ErrorCode::BodyfileTimestampInvalid => "ERR_BODYFILE_TIMESTAMP_7002",
            ErrorCode::BodyfileNumericFieldInvalid => "ERR_BODYFILE_NUMERIC_7003",
            ErrorCode::TimestampOutOfRange => "ERR_TIMESTAMP_RANGE_8001",
            ErrorCode::FiletimeInvalid => "ERR_FILETIME_INVALID_8002",
            ErrorCode::CsvExportFailed => "ERR_CSV_EXPORT_9001",
            ErrorCode::EvidenceUnrecognized => "ERR_EVIDENCE_UNRECOGNIZED_10001",
            ErrorCode::EvidenceNothingParsed => "ERR_EVIDENCE_NOTHING_PARSED_10002",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Rich, contextual error type carrying forensic error codes.
#[derive(Debug)]
#[allow(dead_code)]
pub enum AllyError {
    Io {
        code: ErrorCode,
        source: std::io::Error,
        context: String,
    },
    Mft {
        code: ErrorCode,
        entry: Option<u64>,
        message: String,
    },
    Usn {
        code: ErrorCode,
        offset: u64,
        message: String,
    },
    Ext4 {
        code: ErrorCode,
        message: String,
    },
    Archive {
        code: ErrorCode,
        path: String,
        message: String,
    },
    Image {
        code: ErrorCode,
        path: String,
        message: String,
    },
    Bodyfile {
        code: ErrorCode,
        line: usize,
        message: String,
    },
    Timestamp {
        code: ErrorCode,
        raw_value: i64,
        message: String,
    },
    Csv {
        code: ErrorCode,
        message: String,
    },
    Evidence {
        code: ErrorCode,
        path: String,
        message: String,
    },
}

impl AllyError {
    #[allow(dead_code)]
    pub fn code(&self) -> ErrorCode {
        match self {
            AllyError::Io { code, .. } => *code,
            AllyError::Mft { code, .. } => *code,
            AllyError::Usn { code, .. } => *code,
            AllyError::Ext4 { code, .. } => *code,
            AllyError::Archive { code, .. } => *code,
            AllyError::Image { code, .. } => *code,
            AllyError::Bodyfile { code, .. } => *code,
            AllyError::Timestamp { code, .. } => *code,
            AllyError::Csv { code, .. } => *code,
            AllyError::Evidence { code, .. } => *code,
        }
    }

    /// Builds an I/O error with a path-bearing context, mapping the
    /// `ErrorKind` to the matching forensic code.
    pub fn io_with_context(err: std::io::Error, context: impl Into<String>) -> Self {
        let code = match err.kind() {
            std::io::ErrorKind::NotFound => ErrorCode::FileNotFound,
            std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
            _ => ErrorCode::IoError,
        };
        AllyError::Io {
            code,
            source: err,
            context: context.into(),
        }
    }
}

impl fmt::Display for AllyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllyError::Io { code, source, context } => {
                write!(f, "[{}] I/O Error: {} (Context: {})", code, source, context)
            }
            AllyError::Mft { code, entry, message } => {
                if let Some(e) = entry {
                    write!(f, "[{}] MFT Entry #{}: {}", code, e, message)
                } else {
                    write!(f, "[{}] MFT: {}", code, message)
                }
            }
            AllyError::Usn { code, offset, message } => {
                write!(f, "[{}] USN Journal at offset 0x{:X}: {}", code, offset, message)
            }
            AllyError::Ext4 { code, message } => {
                write!(f, "[{}] Linux ext4 Error: {}", code, message)
            }
            AllyError::Archive { code, path, message } => {
                write!(f, "[{}] Archive '{}': {}", code, path, message)
            }
            AllyError::Image { code, path, message } => {
                write!(f, "[{}] Forensic Image '{}': {}", code, path, message)
            }
            AllyError::Bodyfile { code, line, message } => {
                write!(f, "[{}] Bodyfile line {}: {}", code, line, message)
            }
            AllyError::Timestamp { code, raw_value, message } => {
                write!(f, "[{}] Timestamp (raw: {}): {}", code, raw_value, message)
            }
            AllyError::Csv { code, message } => {
                write!(f, "[{}] CSV Timeline: {}", code, message)
            }
            AllyError::Evidence { code, path, message } => {
                write!(f, "[{}] Evidence '{}': {}", code, path, message)
            }
        }
    }
}

impl std::error::Error for AllyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AllyError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AllyError {
    fn from(err: std::io::Error) -> Self {
        AllyError::io_with_context(err, "Standard filesystem I/O")
    }
}

pub type Result<T> = std::result::Result<T, AllyError>;
