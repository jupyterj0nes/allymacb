use std::process::ExitCode;
use std::time::Instant;
use clap::Parser;

use allymacb::anomaly;
use allymacb::cli::Cli;
use allymacb::ingest::process_evidence_inputs;
use allymacb::parsers::mft::MftParseOptions;
use allymacb::timeline::{source, TimelineEntry, TimelineWriter};

/// Exit codes, documented in the README:
/// 0 = every evidence source parsed, 1 = usage error, 2 = nothing could be
/// parsed (no CSV written), 3 = CSV written but at least one source failed.
const EXIT_USAGE: u8 = 1;
const EXIT_NOTHING_PARSED: u8 = 2;
const EXIT_PARTIAL: u8 = 3;

fn print_banner() {
    // Everything informational goes to stderr so the CSV on stdout stays clean.
    eprintln!(r#"
    _    _     _ __   __   __  __    _    ____ ____
   / \  | |   | |\ \ / /  |  \/  |  / \  / ___| __ )
  / _ \ | |   | | \ V /   | |\/| | / _ \| |   |  _ \
 / ___ \| |___| |__| |    | |  | |/ ___ \ |___| |_) |
/_/   \_\_____|_____|_|    |_|  |_/_/   \_\____|____/
       ⚖️  Ally MACB — The DFIR Courtroom Attorney ⚖️
    "Objection! The timeline proves file timestomping."
    "#);
}

/// How many `[ALERT]` files are listed one by one before the rest is summed up.
const MAX_ALERT_LINES: usize = 40;

/// Prints the anti-forensics findings: every file with an ALERT on its own
/// line (capped), then one line of counts for the WARN-level indicators.
/// Always printed, quiet or not: an alert is not progress chatter.
fn report_anomalies(timeline: &[TimelineEntry]) {
    use std::collections::{BTreeMap, BTreeSet};

    // One entry per file: (meta, name without row tags) -> indicators.
    let mut alerts: BTreeMap<(String, String), BTreeSet<&str>> = BTreeMap::new();
    let mut warn_files: BTreeMap<&str, BTreeSet<(String, String)>> = BTreeMap::new();
    for e in timeline {
        if e.flags.is_empty() {
            continue;
        }
        let flags = anomaly::parse_column(&e.flags);
        let name = base_name(&e.file_name);
        let key = (e.meta.clone(), name);
        match anomaly::severity(&flags) {
            Some(anomaly::Severity::Alert) => {
                alerts.entry(key).or_default().extend(flags);
            }
            Some(anomaly::Severity::Warn) => {
                for f in flags {
                    warn_files.entry(f).or_default().insert(key.clone());
                }
            }
            None => {}
        }
    }

    if !alerts.is_empty() {
        eprintln!();
        eprintln!("[ALERT] {} file(s) with anti-forensics indicators (timestomping, name tricks). flags column says ALERT:", alerts.len());
        for ((meta, name), flags) in alerts.iter().take(MAX_ALERT_LINES) {
            let joined: Vec<&str> = flags.iter().copied().collect();
            eprintln!("[ALERT]   {:<34} {}  (meta {})", joined.join("+"), name, meta);
        }
        if alerts.len() > MAX_ALERT_LINES {
            eprintln!("[ALERT]   ... and {} more; filter the flags column for ALERT", alerts.len() - MAX_ALERT_LINES);
        }
    }
    if !warn_files.is_empty() {
        let detail: Vec<String> = warn_files.iter().map(|(f, s)| format!("{} {}", f, s.len())).collect();
        let total: BTreeSet<&(String, String)> = warn_files.values().flatten().collect();
        eprintln!(
            "[!] {} file(s) with WARN-level indicators ({}): also produced by preserved-timestamp copies and installers; filter the flags column for WARN",
            total.len(),
            detail.join(", ")
        );
    }
}

/// File name without the per-row tags, so the rows of one file collapse.
fn base_name(file_name: &str) -> String {
    let mut s = file_name;
    for tag in [" ($FILE_NAME: ", " (carved @0x", " ($I30)", " (deleted)", " (USN: "] {
        if let Some(i) = s.find(tag) {
            s = &s[..i];
        }
    }
    // An ADS row names the host file.
    s.to_string()
}

fn main() -> ExitCode {
    let args = Cli::parse();
    let start_time = Instant::now();

    if !args.quiet {
        print_banner();
    }

    if args.files.is_empty() && args.directories.is_empty() && args.usn.is_none() {
        eprintln!("[!] No input evidence provided. Use -f, -d, or -u.");
        eprintln!("    Run with --help for usage details.");
        return ExitCode::from(EXIT_USAGE);
    }

    let mft_options = MftParseOptions {
        include_file_name_timestamps: args.include_file_name,
        resident_dir: args.resident.clone(),
        resident_report: args.resident_report.clone(),
        drive_letter: Some(args.drive),
        quiet: args.quiet,
        carve: args.carve,
    };

    if !args.quiet {
        eprintln!("[*] Starting evidence ingestion...");
    }

    let mut report = match process_evidence_inputs(
        &args.files,
        &args.directories,
        args.usn.as_ref(),
        &mft_options,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[!] Fatal: {}", e);
            return ExitCode::from(EXIT_NOTHING_PARSED);
        }
    };

    if report.sources_ok == 0 {
        eprintln!(
            "[!] No evidence could be parsed ({} source(s) failed). No timeline written.",
            report.sources_failed
        );
        return ExitCode::from(EXIT_NOTHING_PARSED);
    }

    if !args.quiet {
        eprintln!(
            "[*] Sorting and writing {} timeline entries (UTC ISO 8601)...",
            report.timeline.len()
        );
    }

    let carved = report.timeline.iter().filter(|e| e.source == source::CARVED).count();

    report_anomalies(&report.timeline);

    let count = match TimelineWriter::write_entries(&mut report.timeline, args.output.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] Fatal: {}", e);
            return ExitCode::from(EXIT_NOTHING_PARSED);
        }
    };

    if !args.quiet {
        eprintln!();
        eprintln!("==================== Summary ====================");
        eprintln!("  Timeline entries written : {}", count);
        if args.carve {
            eprintln!("  Carved entries           : {}", carved);
        }
        eprintln!("  Evidence sources parsed  : {}", report.sources_ok);
        eprintln!("  Evidence sources failed  : {}", report.sources_failed);
        if let Some(ref out) = args.output {
            eprintln!("  Output destination       : {}", out.display());
        } else {
            eprintln!("  Output destination       : stdout");
        }
        if args.resident.is_some() {
            eprintln!("  Resident files dumped    : {}", report.resident_stats.total_extracted);
            eprintln!("  Resident total bytes     : {} bytes", report.resident_stats.total_bytes);
            if report.resident_stats.total_failed > 0 || report.resident_stats.total_unsafe_paths > 0 {
                eprintln!(
                    "  Resident dump problems   : {} failed, {} unsafe paths refused",
                    report.resident_stats.total_failed, report.resident_stats.total_unsafe_paths
                );
            }
        }
        eprintln!("  Elapsed time             : {:.2?}", start_time.elapsed());
        eprintln!("=================================================");
    }

    if report.sources_failed > 0 {
        eprintln!(
            "[!] Timeline is PARTIAL: {} evidence source(s) failed (see warnings above).",
            report.sources_failed
        );
        return ExitCode::from(EXIT_PARTIAL);
    }

    ExitCode::SUCCESS
}
