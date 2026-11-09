use std::process::ExitCode;
use std::time::Instant;
use clap::Parser;

use allymacb::anomaly;
use allymacb::context;
use allymacb::hunt;
use allymacb::timeline;
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
/// line (capped), then one line of counts for the records the rules make
/// `candidate`, then what the volume vouched for or folded.
/// Always printed, quiet or not: an alert is not progress chatter.
fn report_anomalies(timeline: &[TimelineEntry], volumes: &[context::VolumeContext]) {
    use std::collections::{BTreeMap, BTreeSet};

    // One entry per file: (meta, name without row tags) -> indicators.
    let mut alerts: BTreeMap<(String, String), BTreeSet<&str>> = BTreeMap::new();
    let mut warn_files: BTreeMap<&str, BTreeSet<(String, String)>> = BTreeMap::new();
    let mut installed: BTreeSet<(String, String)> = BTreeSet::new();
    let mut folded: BTreeSet<(String, String)> = BTreeSet::new();
    let mut chance: BTreeSet<(String, String)> = BTreeSet::new();
    for e in timeline {
        if e.flags.is_empty() {
            continue;
        }
        let flags = anomaly::parse_column(&e.flags);
        let name = match e.host.as_deref() {
            Some(h) => format!("[{}] {}", h, base_name(&e.file_name)),
            None => base_name(&e.file_name),
        };
        let key = (e.meta.clone(), name);
        match (e.context.as_deref(), timeline::rule_word(e)) {
            (Some(context::Context::Installed(_)), "baseline") => {
                installed.insert(key);
            }
            (Some(context::Context::Burst { leader: false, .. }), "habitual") => {
                folded.insert(key);
            }
            (Some(context::Context::Chance(_)), "habitual") => {
                chance.insert(key);
            }
            (_, "significant") => {
                alerts.entry(key).or_default().extend(flags);
            }
            (_, "candidate") => {
                for f in flags {
                    warn_files.entry(f).or_default().insert(key.clone());
                }
            }
            _ => {}
        }
    }

    if !alerts.is_empty() {
        eprintln!();
        eprintln!("[ALERT] {} file(s) `significant` by their rules (timestomping, name tricks), `rule <id> (high)` in hunt_why:", alerts.len());
        for ((meta, name), flags) in alerts.iter().take(MAX_ALERT_LINES) {
            let joined: Vec<&str> = flags.iter().copied().collect();
            eprintln!("[ALERT]   {:<34} {}  (meta {})", joined.join("+"), name, meta);
        }
        if alerts.len() > MAX_ALERT_LINES {
            eprintln!("[ALERT]   ... and {} more; filter hunt for significant and hunt_why for \"rule \"", alerts.len() - MAX_ALERT_LINES);
        }
    }
    if !warn_files.is_empty() {
        let detail: Vec<String> = warn_files.iter().map(|(f, s)| format!("{} {}", f, s.len())).collect();
        let total: BTreeSet<&(String, String)> = warn_files.values().flatten().collect();
        eprintln!(
            "[!] {} file(s) `candidate` by their rules ({}): also produced by preserved-timestamp copies and installers; `rule <id> (medium)` in hunt_why",
            total.len(),
            detail.join(", ")
        );
    }
    for v in volumes {
        if let Some(w) = &v.install {
            eprintln!("[*] {}: installed from {} to {}, {} of {} records", v.place, w.from, w.to, w.records, w.total);
        }
        if v.bursts > 0 {
            eprintln!(
                "[*] {}: {} burst(s) of records with the same rules changed in the same hour, a share no clean hour reaches; the first of each keeps its state, the other {} are `habitual`",
                v.place, v.bursts, v.folded
            );
        }
    }
    if !installed.is_empty() {
        eprintln!("[*] {} file(s) installed with their volume: the rules that fired on them add nothing, `baseline` in the hunt column", installed.len());
    }
    if !folded.is_empty() {
        eprintln!("[*] {} file(s) folded into a burst: `habitual`, `same burst as record` in hunt_why points at the first", folded.len());
    }
    if !chance.is_empty() {
        eprintln!("[*] {} file(s) whose rules clean hours also show at that share of the records changed in their hour: `habitual`", chance.len());
    }
}

/// How many significant hunt records are listed one by one on stderr.
const MAX_HUNT_LINES: usize = 40;

/// Runs the statistical hunt, writes its verdict into the analysis tail of
/// every row and reports. Returns false when the hunt CSV could not be written.
fn run_hunt(timeline: &mut [TimelineEntry], from: i64, args: &Cli) -> bool {
    let rep = hunt::run(timeline, &hunt::HuntOptions { from, alpha: args.alpha });
    let mut outside = 0usize;
    for e in timeline.iter_mut() {
        e.mark = e.hunt.as_deref().and_then(|h| rep.mark(h));
        outside += usize::from(e.mark.is_none());
    }

    if !args.quiet {
        eprintln!();
        eprintln!("[*] Hunt: records active from {} UTC tested against the earlier records of their volume, FDR {}", fmt_cutoff(from), args.alpha);
        for n in &rep.notes {
            eprintln!("    {}", n);
        }
        let c = rep.counts();
        eprintln!(
            "    records: {} significant, {} candidate, {} not evaluated, {} habitual, {} baseline; {} row(s) outside the hunt",
            c[0], c[1], c[2], c[3], c[4], outside
        );
    }
    let significant: Vec<&hunt::Finding> = rep.findings.iter().filter(|f| f.significant).collect();
    let tested = rep.findings.iter().filter(|f| f.state != hunt::State::NotEvaluated).count();
    if significant.is_empty() {
        eprintln!("[*] Hunt: no record significant at FDR {} among {} tested", args.alpha, tested);
    } else {
        eprintln!(
            "[ALERT] Hunt: {} of {} tested record(s) significant at FDR {}; `significant` in the hunt column",
            significant.len(),
            tested,
            args.alpha
        );
        for f in significant.iter().take(MAX_HUNT_LINES) {
            eprintln!("[ALERT]   {}", hunt::describe(f));
        }
        if significant.len() > MAX_HUNT_LINES {
            eprintln!("[ALERT]   ... and {} more; see --hunt-out", significant.len() - MAX_HUNT_LINES);
        }
    }
    if let Some(path) = &args.hunt_out {
        if let Err(e) = hunt::write_csv(&rep, path) {
            eprintln!("[!] {}", e);
            return false;
        }
        if !args.quiet {
            eprintln!("[*] Hunt CSV: {} ({} rows)", path.display(), rep.findings.len());
        }
    }
    true
}

fn fmt_cutoff(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_default()
}

/// File name without the per-row tags, so the rows of one file collapse.
fn base_name(file_name: &str) -> String {
    let mut s = file_name;
    for tag in [" ($FILE_NAME: ", " (carved @0x", " ($I30)", " (USN: "] {
        if let Some(i) = s.find(tag) {
            s = &s[..i];
        }
    }
    // An ADS row names the host file.
    s.to_string()
}

/// The resident dump goes to a folder the analyst names, new or empty, so the
/// files in it are those of this run and nothing already there is touched.
fn resident_destination_ok(dir: &std::path::Path) -> Result<(), String> {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => match entries.next() {
            None => Ok(()),
            Some(_) => Err("the folder is not empty; name a new or empty folder for the dump".to_string()),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) if dir.is_file() => Err("is a file; name a new or empty folder for the dump".to_string()),
        Err(e) => Err(format!("cannot be read ({})", e)),
    }
}

fn main() -> ExitCode {
    let args = Cli::parse();
    let start_time = Instant::now();
    let threads = allymacb::par::init(args.threads);
    // One thread reads the inputs as the code always did, one after another.
    // The resident dump names files in the order the sources are read.
    allymacb::par::one_input_at_a_time(threads == 1 || args.resident.is_some());

    if !args.quiet {
        print_banner();
    }

    let cutoff = match args.investigation_from.as_deref().map(|s| (s, hunt::parse_cutoff(s))) {
        Some((s, None)) => {
            eprintln!("[!] --investigation-from: cannot read '{}' as a UTC time (YYYY-MM-DD, YYYY-MM-DD HH:MM:SS or RFC 3339)", s);
            return ExitCode::from(EXIT_USAGE);
        }
        Some((_, Some(t))) => Some(t),
        None => None,
    };
    if !(args.alpha > 0.0 && args.alpha < 1.0) {
        eprintln!("[!] --alpha must be between 0 and 1 (exclusive)");
        return ExitCode::from(EXIT_USAGE);
    }
    if cutoff.is_none() && args.hunt_out.is_some() {
        eprintln!("[!] --hunt-out needs --investigation-from");
        return ExitCode::from(EXIT_USAGE);
    }

    if args.resident_report.is_some() && args.resident.is_none() {
        eprintln!("[!] --resident-report needs --resident <DIR>");
        return ExitCode::from(EXIT_USAGE);
    }
    if let Some(dir) = &args.resident
        && let Err(why) = resident_destination_ok(dir)
    {
        eprintln!("[!] --resident {}: {}", dir.display(), why);
        return ExitCode::from(EXIT_USAGE);
    }
    if let Some(rep) = &args.resident_report
        && rep.exists()
    {
        eprintln!("[!] --resident-report {}: the file exists; name a new one", rep.display());
        return ExitCode::from(EXIT_USAGE);
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

    let unfrozen = allymacb::evidence::unfrozen();
    if unfrozen > 0 {
        eprintln!(
            "[!] {} evidence file(s) or folder(s) were read without their access time frozen (read-only medium, another owner, or a reader that opens files itself): the system may have written a new access time on them",
            unfrozen
        );
    }

    let mut resident_report_failed = false;
    if let (Some(rep), Some(dir)) = (&args.resident_report, &args.resident)
        && let Err(e) = allymacb::parsers::mft::write_resident_report(rep, dir, &report.resident_stats)
    {
        eprintln!("[!] {}", e);
        resident_report_failed = true;
    }

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

    let volumes = context::attach(&mut report.timeline, args.alpha);

    let mut hunt_failed = false;
    if let Some(from) = cutoff {
        hunt_failed = !run_hunt(&mut report.timeline, from, &args);
    }

    report_anomalies(&report.timeline, &volumes);

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
        eprintln!("  Threads                  : {}", threads);
        eprintln!("=================================================");
    }

    if hunt_failed || resident_report_failed {
        return ExitCode::from(EXIT_PARTIAL);
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
