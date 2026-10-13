mod cli;
mod ingest;
mod parsers;
mod timefmt;
mod timeline;

use std::time::Instant;
use clap::Parser;

use cli::Cli;
use ingest::process_evidence_inputs;
use parsers::mft::MftParseOptions;
use timeline::TimelineWriter;

fn print_banner() {
    println!(r#"
    ___    __    __    __  __ ___  ___   ______ _____ 
   /   |  / /   / /    \ \/ //   |/   | / ____// __  \
  / /| | / /   / /      \  // /| / /| |/ /    / __  < 
 / ___ |/ /___/ /___    / // ___/ ___ / /___ / /_/  / 
/_/  |_/_____/_____/   /_//_/  /_/  |_\____//_____/  
    Lateral MACB Filesystem Timeline Generator (Pure Rust)
    "#);
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Cli::parse();
    let start_time = Instant::now();

    if !args.quiet {
        print_banner();
    }

    if args.files.is_empty() && args.directories.is_empty() && args.usn.is_none() {
        eprintln!("[!] No input evidence provided. Use -f, -d, or -u.");
        eprintln!("    Run with --help for usage details.");
        std::process::exit(1);
    }

    let mft_options = MftParseOptions {
        include_file_name_timestamps: args.include_file_name,
        resident_dir: args.resident.clone(),
        resident_report: args.resident_report.clone(),
        drive_letter: Some(args.drive),
        quiet: args.quiet,
    };

    if !args.quiet {
        println!("[*] Starting evidence ingestion...");
    }

    let (mut timeline, resident_stats) = process_evidence_inputs(
        &args.files,
        &args.directories,
        args.usn.as_ref(),
        &mft_options,
    )?;

    if !args.quiet {
        println!(
            "[*] Sorting and writing {} timeline entries (UTC ISO 8601)...",
            timeline.len()
        );
    }

    let count = TimelineWriter::write_entries(&mut timeline, args.output.as_deref())?;

    if !args.quiet {
        println!();
        println!("==================== Summary ====================");
        println!("  Timeline entries written : {}", count);
        if let Some(ref out) = args.output {
            println!("  Output destination       : {}", out.display());
        } else {
            println!("  Output destination       : stdout");
        }
        if args.resident.is_some() {
            println!("  Resident files dumped    : {}", resident_stats.total_extracted);
            println!("  Resident total bytes     : {} bytes", resident_stats.total_bytes);
        }
        println!("  Elapsed time             : {:.2?}", start_time.elapsed());
        println!("=================================================");
    }

    Ok(())
}
