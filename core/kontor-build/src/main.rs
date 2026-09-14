use anyhow::Result;
use clap::{Parser, Subcommand};
use kontor_build::{BuildArgs, run};

#[derive(Parser)]
#[command(name = "kontor", about = "Repository build bootstrap")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build reproducible contracts and SDK bindings in the pinned container.
    Build(BuildArgs),
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Build(args) => run(args),
    }
}
