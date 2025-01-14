/*
    Hashinator a Blazingly fast hash identificaiton tool written in rust
    Copyright (C) 2025 Jamie G. (@North004)  north004@pm.me

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
mod output;
mod patterns;

use clap::{Arg, Command};
use colored::Colorize;
use output::output_complete;
use patterns::{HashIdentifier, IdentifiedHashes};
use std::{fs, path::PathBuf};

fn main() {
    let args = Command::new("Hashinator")
        .version("1.0.1")
        .author("North004 <north004@pm.me>")
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
