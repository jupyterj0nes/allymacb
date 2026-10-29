use std::path::PathBuf;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "allymacb",
    author = "DFIR Rust Team",
    version,
    about = "Pure Rust MFT, USN, and Linux Filesystem MACB Timeline Generator\nSupports Forensic Images (E01, RAW, DD, split RAW, fixed VHD), Archives (ZIP, TAR, TAR.GZ), Triages & Loose Files"
)]
pub struct Cli {
    /// Input file(s): $MFT, $UsnJrnl:$J, bodyfile, forensic disk image (E01, DD, RAW), archive (ZIP, TAR.GZ), etc.
    #[arg(short = 'f', long = "file", num_args = 0..)]
    pub files: Vec<PathBuf>,

    /// Evidence directory or triage folder (KAPE, Velociraptor, UAC, or loose files)
    #[arg(short = 'd', long = "dir", num_args = 0..)]
    pub directories: Vec<PathBuf>,

    /// Path to USN Journal ($UsnJrnl:$J) file
    #[arg(short = 'u', long = "usn")]
    pub usn: Option<PathBuf>,

    /// Output CSV timeline file (prints to stdout if omitted; all status messages go to stderr)
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Drive letter for Windows paths (default: 'C')
    #[arg(short = 'm', long = "drive", default_value = "C")]
    pub drive: char,

    /// Include $FILE_NAME (0x30) timestamp entries in the timeline
    #[arg(short = 'n', long = "file-name")]
    pub include_file_name: bool,

    /// Directory to dump resident files extracted from MFT
    #[arg(short = 'r', long = "resident")]
    pub resident: Option<PathBuf>,

    /// Path to output resident file extraction summary report
    #[arg(long = "resident-report")]
    pub resident_report: Option<PathBuf>,

    /// Suppress progress bars, banner and informational messages (warnings are still printed)
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Carve NTFS FILE records and $I30 index entries from the raw sectors of disk images
    /// and unrecognised files (old $MFT copies, VSS remnants, unallocated space).
    /// Off by default. Recovered rows say `carved` in the source column and carry the image offset.
    #[arg(long = "carve")]
    pub carve: bool,
}
