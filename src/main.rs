use std::process::ExitCode;
use std::time::Instant;
use clap::Parser;

use allymacb::cli::Cli;
use allymacb::ingest::process_evidence_inputs;
use allymacb::parsers::mft::MftParseOptions;
use allymacb::timeline::TimelineWriter;

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
