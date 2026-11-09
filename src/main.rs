//! lagwatch — spots the usual reasons a Mac feels slow: runaway processes,
//! swap build-up, piles of long-lived helpers and forgotten dev servers.
//!
//! Run it with no arguments for the window, or `lagwatch check` for a
//! one-off report in the terminal.

mod dev;
mod gui;
mod scan;

use std::io::IsTerminal;

use scan::{Severity, Snapshot};

fn main() {
    match std::env::args().nth(1).as_deref() {
        None => gui::run(),
        Some("check") => print_report(),
        Some(_) => {
            eprintln!("usage: lagwatch [check]");
            std::process::exit(2);
        }
    }
}

fn print_report() {
    let snap = Snapshot::take();
    let findings = snap.findings(&Default::default());

    let color = std::io::stdout().is_terminal();
    let paint = |code: &str, text: &str| {
        if color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    };

    println!(
        "uptime {}   swap {} / {}   memory pressure {}   {} processes",
        scan::dur(snap.uptime),
        scan::size(snap.swap_used),
        scan::size(snap.swap_total),
        snap.pressure_name(),
        snap.process_count()
    );
    println!();

    if findings.is_empty() {
        println!("{}", paint("32", "Nothing unusual found."));
        return;
    }
    for f in &findings {
        let tag = match f.severity {
            Severity::Warn => paint("1;31", "WARN"),
            Severity::Info => paint("33", "INFO"),
        };
        println!("{tag}  {}", paint("1", &f.title));
        println!("      {}", f.detail);
        println!("      {}", paint("2", &f.hint));
        const SHOWN: usize = 5;
        for line in f.processes.iter().take(SHOWN) {
            println!("        {}", paint("2", line));
        }
        if f.processes.len() > SHOWN {
            println!("        {}", paint("2", &format!("… and {} more", f.processes.len() - SHOWN)));
        }
        println!();
    }
}
