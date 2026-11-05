//! One image reader shared by several readers of its volumes.
//!
//! The XFS driver wants a device it can keep (`Arc<dyn BlockRead>`) and read
//! at any offset; LVM wants a `Read + Seek` it can clone for every logical
//! volume it opens. Both are views on the same image reader, so the reader
//! lives behind a mutex and each view keeps its own base and position.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

/// A window on a shared reader: `base` is where the window starts in the
/// image, `len` how far it reaches (`u64::MAX` when unknown).
pub struct SharedReader<R> {
    inner: Arc<Mutex<R>>,
    base: u64,
    len: u64,
    pos: u64,
}

impl<R> Clone for SharedReader<R> {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner), base: self.base, len: self.len, pos: 0 }
    }
}

impl<R: Read + Seek> SharedReader<R> {
    pub fn new(inner: Arc<Mutex<R>>, base: u64, len: u64) -> Self {
        Self { inner, base, len, pos: 0 }
    }

    /// The same reader, from `offset` on (relative to this window).
    pub fn at(&self, offset: u64, len: u64) -> Self {
        Self { inner: Arc::clone(&self.inner), base: self.base + offset, len, pos: 0 }
    }

    /// Reads `buf.len()` bytes at `offset` of the window.
    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.checked_add(buf.len() as u64).is_none_or(|end| end > self.len) {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the volume"));
        }
        let mut r = self.inner.lock().map_err(|_| io::Error::other("image reader poisoned"))?;
        r.seek(SeekFrom::Start(self.base + offset))?;
        r.read_exact(buf)
    }
}

impl<R: Read + Seek> Read for SharedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.len.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(left) as usize;
        if n == 0 {
            return Ok(0);
        }
        let mut r = self.inner.lock().map_err(|_| io::Error::other("image reader poisoned"))?;
        r.seek(SeekFrom::Start(self.base + self.pos))?;
        let got = r.read(&mut buf[..n])?;
        self.pos += got as u64;
        Ok(got)
    }
}

impl<R: Read + Seek> Seek for SharedReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
            SeekFrom::End(d) => {
                if self.len == u64::MAX {
                    return Err(io::Error::new(io::ErrorKind::Unsupported, "volume of unknown length"));
                }
                self.len.checked_add_signed(d)
            }
        };
        self.pos = new.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?;
        Ok(self.pos)
    }
}

impl<R: Read + Seek + Send> fs_core::BlockRead for SharedReader<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        self.read_exact_at(offset, buf).map_err(fs_core::Error::Io)
    }

    fn size_bytes(&self) -> u64 {
        self.len
    }
}

/// A logical volume as a device: every read opens the LV on the physical
/// volume again, which is how `lvm2` maps LV offsets to PV extents.
pub struct LvDevice<R> {
    pub lvm: Arc<lvm2::Lvm2>,
    pub name: String,
    pub pv: SharedReader<R>,
    pub len: u64,
}

impl<R: Read + Seek + Send> fs_core::BlockRead for LvDevice<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        let mut lv = self
            .lvm
            .open_lv_by_name(&self.name, self.pv.clone())
            .ok_or_else(|| fs_core::Error::Io(io::Error::new(io::ErrorKind::NotFound, format!("logical volume {} not on this PV", self.name))))?;
        lv.seek(SeekFrom::Start(offset)).map_err(fs_core::Error::Io)?;
        lv.read_exact(buf).map_err(fs_core::Error::Io)
    }

    fn size_bytes(&self) -> u64 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn windows_read_their_own_range() {
        let data: Vec<u8> = (0u8..=255).collect();
        let shared = Arc::new(Mutex::new(Cursor::new(data)));
        let w = SharedReader::new(shared, 16, 32);
        let mut b = [0u8; 4];
        w.read_exact_at(0, &mut b).unwrap();
        assert_eq!(b, [16, 17, 18, 19]);
        assert!(w.read_exact_at(30, &mut b).is_err(), "past the window");
        let mut r = w.at(8, 8);
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, (24u8..32).collect::<Vec<_>>());
        assert_eq!(r.seek(SeekFrom::End(-2)).unwrap(), 6);
    }
}
