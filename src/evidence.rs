//! Reading evidence without leaving a trace on it.
//!
//! Opening a file to read it, or listing a directory, makes most systems
//! write a new access time on it. On a folder of evidence that is the
//! analysis writing on what it analyses: the next tool, or the next run,
//! would see the time of this one. Every file and directory of the evidence
//! is opened here, and here the access time is frozen first:
//!
//! * Windows: the handle is opened with the right to write attributes and
//!   `SetFileTime` is called on it with a last access time of
//!   `0xFFFFFFFF_FFFFFFFF`, which tells the file system not to update it for
//!   anything done through that handle. Nothing is written: no time is set.
//! * Linux: `O_NOATIME`.
//!
//! When the freeze cannot be had (a read-only medium, where nothing can be
//! written anyway; a file of another owner on Linux; another system), the
//! file is opened the ordinary way and [`unfrozen`] counts it, so the run can
//! say so.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static UNFROZEN: AtomicU64 = AtomicU64::new(0);

/// How many evidence files and directories were opened without their access
/// time frozen.
pub fn unfrozen() -> u64 {
    UNFROZEN.load(Ordering::Relaxed)
}

/// Counts files a library opened by itself, beyond the reach of [`open`].
pub fn note_unfrozen(n: u64) {
    UNFROZEN.fetch_add(n, Ordering::Relaxed);
}

/// Opens an evidence file for reading, its access time frozen.
pub fn open(path: &Path) -> io::Result<File> {
    match imp::open_frozen(path) {
        Ok(f) => Ok(f),
        Err(_) => {
            let f = File::open(path)?;
            UNFROZEN.fetch_add(1, Ordering::Relaxed);
            Ok(f)
        }
    }
}

/// The entries of an evidence directory (full paths, sorted), listed
/// without touching its access time.
pub fn list_dir(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = match imp::list_frozen(dir) {
        Ok(v) => v,
        Err(_) => {
            let v: Vec<PathBuf> = std::fs::read_dir(dir)?.filter_map(|e| e.ok().map(|e| e.path())).collect();
            UNFROZEN.fetch_add(1, Ordering::Relaxed);
            v
        }
    };
    out.sort();
    Ok(out)
}

#[cfg(windows)]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};

    use windows_sys::Win32::Foundation::{FILETIME, GENERIC_READ};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandleEx, SetFileTime, FileFullDirectoryInfo, FileFullDirectoryRestartInfo, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FULL_DIR_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_ATTRIBUTES,
    };

    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    fn freeze(f: &File) -> io::Result<()> {
        let keep = FILETIME { dwLowDateTime: 0xFFFF_FFFF, dwHighDateTime: 0xFFFF_FFFF };
        // SAFETY: a valid handle owned by `f`; the other times are null (left alone).
        let ok = unsafe { SetFileTime(f.as_raw_handle() as _, std::ptr::null(), &keep, std::ptr::null()) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    pub fn open_frozen(path: &Path) -> io::Result<File> {
        let f = OpenOptions::new().read(true).access_mode(GENERIC_READ | FILE_WRITE_ATTRIBUTES).share_mode(SHARE_ALL).open(path)?;
        freeze(&f)?;
        Ok(f)
    }

    pub fn list_frozen(dir: &Path) -> io::Result<Vec<PathBuf>> {
        let f = OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)?;
        freeze(&f)?;
        let mut out = Vec::new();
        // u64 elements keep the buffer 8-byte aligned, as the records need.
        let mut buf = vec![0u64; 8192];
        let mut class = FileFullDirectoryRestartInfo;
        loop {
            // SAFETY: the buffer is writable for its whole length.
            let ok = unsafe { GetFileInformationByHandleEx(f.as_raw_handle() as _, class, buf.as_mut_ptr() as _, (buf.len() * 8) as u32) };
            if ok == 0 {
                let e = io::Error::last_os_error();
                // ERROR_NO_MORE_FILES
                if e.raw_os_error() == Some(18) {
                    break;
                }
                return Err(e);
            }
            class = FileFullDirectoryInfo;
            let base = buf.as_ptr() as *const u8;
            let mut off = 0usize;
            loop {
                // SAFETY: the system wrote whole, aligned records at these offsets.
                let rec = unsafe { &*(base.add(off) as *const FILE_FULL_DIR_INFO) };
                let len = rec.FileNameLength as usize / 2;
                let name = unsafe { std::slice::from_raw_parts(rec.FileName.as_ptr(), len) };
                let name = std::ffi::OsString::from_wide(name);
                if name != "." && name != ".." {
                    out.push(dir.join(name));
                }
                if rec.NextEntryOffset == 0 {
                    break;
                }
                off += rec.NextEntryOffset as usize;
            }
        }
        Ok(out)
    }

    /// The four times of a path as NTFS keeps them, change time included
    /// (for the tests: freezing must not move any of them).
    #[cfg(test)]
    pub fn basic_times(path: &Path) -> [i64; 4] {
        use windows_sys::Win32::Storage::FileSystem::{FileBasicInfo, FILE_BASIC_INFO};
        let f = OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES).share_mode(SHARE_ALL).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(path).unwrap();
        let mut info: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandleEx(f.as_raw_handle() as _, FileBasicInfo, &mut info as *mut _ as _, std::mem::size_of::<FILE_BASIC_INFO>() as u32) };
        assert!(ok != 0);
        [info.CreationTime, info.LastAccessTime, info.LastWriteTime, info.ChangeTime]
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};

    pub fn open_frozen(path: &Path) -> io::Result<File> {
        OpenOptions::new().read(true).custom_flags(libc::O_NOATIME).open(path)
    }

    pub fn list_frozen(dir: &Path) -> io::Result<Vec<PathBuf>> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::IntoRawFd;
        let f = OpenOptions::new().read(true).custom_flags(libc::O_NOATIME | libc::O_DIRECTORY).open(dir)?;
        let fd = f.into_raw_fd();
        // SAFETY: fdopendir takes the descriptor over; closedir releases it.
        let d = unsafe { libc::fdopendir(fd) };
        if d.is_null() {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let mut out = Vec::new();
        loop {
            let ent = unsafe { libc::readdir(d) };
            if ent.is_null() {
                break;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
            let b = name.to_bytes();
            if b != b"." && b != b".." {
                out.push(dir.join(std::ffi::OsStr::from_bytes(b)));
            }
        }
        unsafe { libc::closedir(d) };
        Ok(out)
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    use std::fs::File;
    use std::io;
    use std::path::{Path, PathBuf};

    pub fn open_frozen(_: &Path) -> io::Result<File> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no access-time freeze on this system"))
    }

    pub fn list_frozen(_: &Path) -> io::Result<Vec<PathBuf>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no access-time freeze on this system"))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::time::{Duration, SystemTime};

    /// A file and a directory whose access time lies years back, so that any
    /// access the system records shows.
    fn aged(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("allymacb_evidence_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let file = dir.join("sub").join("e.bin");
        std::fs::write(&file, vec![7u8; 100_000]).unwrap();
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        for p in [&file, &dir.join("sub")] {
            let f = std::fs::OpenOptions::new().write(true).custom_flags_dir(p).open(p).unwrap();
            f.set_times(std::fs::FileTimes::new().set_accessed(old).set_modified(old)).unwrap();
        }
        (dir, file)
    }

    trait DirOpen {
        fn custom_flags_dir(&mut self, p: &Path) -> &mut Self;
    }
    impl DirOpen for std::fs::OpenOptions {
        fn custom_flags_dir(&mut self, p: &Path) -> &mut Self {
            use std::os::windows::fs::OpenOptionsExt;
            if p.is_dir() {
                self.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS);
            }
            self
        }
    }

    #[test]
    fn reading_and_listing_leave_every_time_as_it_was() {
        let (dir, file) = aged("frozen");
        let sub = dir.join("sub");
        let (f0, d0) = (imp::basic_times(&file), imp::basic_times(&sub));
        let before = unfrozen();
        let mut all = Vec::new();
        open(&file).unwrap().read_to_end(&mut all).unwrap();
        assert_eq!(all.len(), 100_000);
        assert_eq!(list_dir(&sub).unwrap(), vec![file.clone()]);
        assert_eq!(unfrozen(), before, "both were frozen");
        assert_eq!(imp::basic_times(&file), f0, "creation, access, write and change time of the file");
        assert_eq!(imp::basic_times(&sub), d0, "and of the directory");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The control: read the ordinary way, the same file does get a new
    /// access time on this machine, so the test above can see one.
    #[test]
    fn the_ordinary_way_does_move_the_access_time_here() {
        let (dir, file) = aged("control");
        let a0 = imp::basic_times(&file)[1];
        let mut all = Vec::new();
        File::open(&file).unwrap().read_to_end(&mut all).unwrap();
        let a1 = imp::basic_times(&file)[1];
        let _ = std::fs::remove_dir_all(&dir);
        if a1 == a0 {
            eprintln!("last access updates are off on this volume: the control shows nothing");
        }
    }
}
