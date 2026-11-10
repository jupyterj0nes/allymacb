//! What the virtual-disk readers ([`super::vmdk`], [`super::vhd`]) share: the error they
//! return (an [`ErrorCode`] and a message, turned into an [`AllyError::Image`] by the image
//! walker), positioned reads and the seek arithmetic of a `Read + Seek` disk.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{AllyError, ErrorCode};

/// Why a virtual disk could not be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskError {
    pub code: ErrorCode,
    pub message: String,
}

impl DiskError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        DiskError { code, message: message.into() }
    }

    /// A header, footer, table or extent that cannot be trusted (E6004).
    pub fn damaged(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ImageContainerDamaged, message)
    }

    /// A disk that only holds the changes over a parent (E6005).
    pub fn has_parent(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ImageHasParent, message)
    }

    /// A file of the disk that is not there (E6006).
    pub fn missing(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ImageExtentMissing, message)
    }

    /// Reading the container itself failed (E6001).
    pub fn read(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ImageReadFailed, message)
    }

    /// The error the image walker reports for `path`.
    pub fn into_ally(self, path: &str) -> AllyError {
        AllyError::Image { code: self.code, path: path.to_string(), message: self.message }
    }
}

impl std::fmt::Display for DiskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Opens a file of the evidence without touching its access time (see
/// [`crate::evidence::open`]).
pub fn open_evidence(path: &Path) -> io::Result<File> {
    crate::evidence::open(path)
}

/// Reads exactly `buf.len()` bytes at `offset`.
pub fn read_at(file: &mut File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)
}

/// The seek of a disk of `total` bytes: any position at or past the end reads nothing,
/// a negative one is an error.
pub fn seek_to(position: &mut u64, total: u64, pos: SeekFrom) -> io::Result<u64> {
    let new_pos = match pos {
        SeekFrom::Start(o) => i128::from(o),
        SeekFrom::End(o) => i128::from(total) + i128::from(o),
        SeekFrom::Current(o) => i128::from(*position) + i128::from(o),
    };
    if new_pos < 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek to a negative position"));
    }
    *position = u64::try_from(new_pos).unwrap_or(u64::MAX);
    Ok(*position)
}

pub fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn be64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_be_bytes(a)
}

pub fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn le64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seek_arithmetic() {
        let mut p = 0u64;
        assert_eq!(seek_to(&mut p, 100, SeekFrom::Start(40)).unwrap(), 40);
        assert_eq!(seek_to(&mut p, 100, SeekFrom::Current(10)).unwrap(), 50);
        assert_eq!(seek_to(&mut p, 100, SeekFrom::End(-1)).unwrap(), 99);
        assert_eq!(seek_to(&mut p, 100, SeekFrom::End(5)).unwrap(), 105, "past the end is allowed, reads nothing");
        assert!(seek_to(&mut p, 100, SeekFrom::Current(-1000)).is_err());
        assert_eq!(p, 105, "a failed seek leaves the position");
    }

    #[test]
    fn errors_carry_their_codes() {
        assert_eq!(DiskError::damaged("x").code, ErrorCode::ImageContainerDamaged);
        assert_eq!(DiskError::has_parent("x").code, ErrorCode::ImageHasParent);
        assert_eq!(DiskError::missing("x").code, ErrorCode::ImageExtentMissing);
        assert_eq!(DiskError::read("x").code, ErrorCode::ImageReadFailed);
        let e = DiskError::damaged("bad footer").into_ally("disk.vmdk");
        assert_eq!(e.code(), ErrorCode::ImageContainerDamaged);
        let text = e.to_string();
        assert!(text.contains("disk.vmdk") && text.contains("bad footer"), "{text}");
        assert!(DiskError::missing("gone").to_string().contains("6006"));
    }

    #[test]
    fn integer_helpers() {
        let b = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(be32(&b, 0), 0x0102_0304);
        assert_eq!(le32(&b, 0), 0x0403_0201);
        assert_eq!(be64(&b, 0), 0x0102_0304_0506_0708);
        assert_eq!(le64(&b, 0), 0x0807_0605_0403_0201);
    }
}
