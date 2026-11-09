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

    /// Dump the resident $DATA streams of the MFT into this folder. Off unless given;
    /// the folder must be new or empty, and no file is ever overwritten (a second
    /// record with the same path gets `.rec<N>`)
    #[arg(short = 'r', long = "resident", value_name = "DIR")]
    pub resident: Option<PathBuf>,

    /// Summary of the resident dump of the whole run (needs --resident; the file must not exist)
    #[arg(long = "resident-report", value_name = "FILE")]
    pub resident_report: Option<PathBuf>,

    /// Suppress progress bars, banner and informational messages (warnings are still printed)
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Carve NTFS FILE records and $I30 index entries from the raw sectors of disk images
    /// and unrecognised files (old $MFT copies, VSS remnants, unallocated space).
    /// Off by default. Recovered rows say `carved` in the source column and carry the image offset.
    #[arg(long = "carve")]
    pub carve: bool,

    /// Statistical hunt for manipulated timestamps. Records active at or after this
    /// time (UTC: "YYYY-MM-DD", "YYYY-MM-DD HH:MM:SS" or RFC 3339) are tested against
    /// the earlier records of the same volume; every row gets the verdict on its record
    /// in the hunt, hunt_score and hunt_why columns. Off unless given.
    #[arg(long = "investigation-from", value_name = "TIME")]
    pub investigation_from: Option<String>,

    /// False discovery rate of the hunt (Benjamini-Hochberg)
    #[arg(long = "alpha", default_value_t = 0.05, value_name = "RATE")]
    pub alpha: f64,

    /// Write the hunt's findings table (19 columns, laid out like masstin's) to this CSV
    #[arg(long = "hunt-out", value_name = "CSV")]
    pub hunt_out: Option<PathBuf>,

    /// Threads to use; 0 (the default) uses every logical processor of the system.
    /// The output is byte for byte the same with any number
    #[arg(long = "threads", value_name = "N", default_value_t = 0)]
    pub threads: usize,
}
