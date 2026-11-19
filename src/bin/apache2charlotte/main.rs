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
    name = "apache2charlotte",
    version,
    about = "Convert Apache HTTP Server configuration to project-charlotte YAML"
)]
struct Cli {
    /// Apache configuration file to convert
    input: PathBuf,
    /// Write output to this file instead of stdout
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Omit explanatory and review comments from the generated YAML
    #[arg(long)]
    no_comments: bool,
    /// Set each vhost's user and group from its document root owner
    #[arg(long)]
    user_from_root: bool,
    /// ServerRoot used to resolve relative Include paths
    #[arg(long, value_name = "DIRECTORY")]
    server_root: Option<PathBuf>,
    /// Define an Apache variable (NAME or NAME=VALUE); may be repeated
    #[arg(short = 'D', value_name = "NAME[=VALUE]", action = clap::ArgAction::Append)]
    defines: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("apache2charlotte: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let nodes = parse::parse(
        &cli.input,
        &parse::ParseOptions {
            server_root: cli.server_root,
            defines: cli.defines,
        },
    )?;
    let converted = convert::convert(&nodes, !cli.no_comments, cli.user_from_root);
    if let Some(output) = cli.output {
        fs::write(output, converted)?;
    } else {
        io::stdout().lock().write_all(converted.as_bytes())?;
    }
    Ok(())
}
