mod convert;
mod parse;

use std::{
    error::Error,
    fs,
    io::{self, Write},
    path::PathBuf,
};

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "nginx2charlotte",
    version,
    about = "Convert nginx configuration to project-charlotte YAML"
)]
struct Cli {
    /// nginx configuration file to convert
    input: PathBuf,
    /// Write output to this file instead of stdout
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Omit explanatory and review comments from the generated YAML
    #[arg(long)]
    no_comments: bool,
    /// Set each vhost's user and group from its root directory owner
    #[arg(long)]
    user_from_root: bool,
    /// Prefix used to resolve relative include paths
    #[arg(long, value_name = "DIRECTORY")]
    prefix: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nginx2charlotte: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let nodes = parse::parse(&cli.input, &parse::ParseOptions { prefix: cli.prefix })?;
    let converted = convert::convert(&nodes, !cli.no_comments, cli.user_from_root);
    if let Some(output) = cli.output {
        fs::write(output, converted)?;
    } else {
        io::stdout().lock().write_all(converted.as_bytes())?;
    }
    Ok(())
}
