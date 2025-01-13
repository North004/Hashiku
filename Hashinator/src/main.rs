mod output;
mod patterns;

use clap::{Arg, Command};
use colored::Colorize;
use output::output_complete;
use patterns::{HashIdentifier, IdentifiedHashes};
use std::{fs, path::PathBuf};

fn main() {
    let args = Command::new("Hashinator")
        .version("1.0")
        .author("NorthSky <northsky.dev@pm.me>")
        .about("A program to identify hashes blazingly fast")
        .arg(
            Arg::new("text")
                .allow_hyphen_values(true)
                .short('t')
                .long("text")
                .value_name("TEXT")
                .help("User supplied hash to detect")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .value_name("FILE")
                .help("User supplied file with hashes on each line to detect")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("nobanner")
                .short('n')
                .long("no-banner")
                .help("Disables banner")
                .action(clap::ArgAction::SetFalse),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Sets verbosity level")
                .action(clap::ArgAction::Count),
        )
        .group(
            clap::ArgGroup::new("input")
                .args(["text", "file"]) // Grouping the arguments
                .required(true)
                .multiple(false), // Ensures at least one is provided
        )
        .get_matches();

    if args.get_flag("nobanner") {
        println!("{}", output::get_bannter().red());
    }

    let hash = HashIdentifier::new();

    if let Some(file_path) = args.get_one::<PathBuf>("file") {
        match fs::read_to_string(file_path) {
            Ok(content) => {
                let lines = content.lines();
                for line in lines {
                    let output: IdentifiedHashes = hash.is_match(line.trim());
                    output_complete(output, args.get_count("verbose"));
                }
            }
            Err(e) => {
                eprintln!("Error reading file: {}", e);
                std::process::exit(1)
            }
        }
    } else if let Some(text) = &args.get_one::<String>("text") {
        let output: IdentifiedHashes = hash.is_match(text);
        output_complete(output, args.get_count("verbose"));
    } else {
        eprintln!("No valid input provided.");
        std::process::exit(1);
    }
    std::process::exit(0)
}
