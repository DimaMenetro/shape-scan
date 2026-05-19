//! shape-scan CLI entry point.
//!
//! Routes to subcommands: scan, entropy, shape, intent.

use std::process;

fn main() {
    // Ensure cargo PATH is loaded
    let result = shape_scan::cli::run();

    match result {
        Ok(exit_code) => process::exit(exit_code),
        Err(e) => {
            eprintln!("[TEM] Fatal error: {e}");
            process::exit(2);
        }
    }
}
