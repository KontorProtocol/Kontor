// Compile only linker tooling into this executable, keeping its cache identity
// independent of the CLI and other compiler wrappers.
#[path = "../linker_record.rs"]
mod linker_record;

use std::process;

use anyhow::Result;
use linker_record::run;

fn main() -> Result<()> {
    let status = run()?;
    if status != 0 {
        process::exit(status);
    }
    Ok(())
}
