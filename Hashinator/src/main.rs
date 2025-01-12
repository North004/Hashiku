mod output;
mod patterns;
use std::{fs, path::PathBuf};
use clap::{ArgGroup, Parser};
use output::output_complete;
use patterns::{HashIdentifier, IdentifiedHashes};
use output::BANNER;

#[derive(Parser, Debug)]
#[command(version = "0.0.1", about = "Identify hashes blazingly fast", long_about = format!("{}\nA tool written in rust used to identify over 3000+ at blazingly fast speeds",BANNER))]
#[command(group(
    ArgGroup::new("input")
        .required(true)
        .args(&["text", "file"])
))]
pub struct Args {
    #[arg(short = 't', long = "text")]
    pub text: Option<String>,
    #[arg(short = 'f', long = "file")]
    pub file: Option<PathBuf>,
    #[arg(short = 'n', long = "no-banner")]
    pub nobanner: bool,
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbosity: u8,
}


fn main() {
    let hash = HashIdentifier::new();
    let args = Args::parse();
    println!("{}",args.verbosity);
    match args.nobanner {
        false => output::banner(),
        _ => (),
    };

    if let Some(file_path) = args.file {
        match fs::read_to_string(file_path) {
            Ok(content) => {
                let lines = content.lines();
                for line in lines {
                    let output: IdentifiedHashes = hash.is_match(line.trim());
                    output_complete(output,args.verbosity);
                }
            }
            Err(e) =>  {
                eprintln!("Error reading file: {}",e);
                std::process::exit(1)
            }
        }
        } else if let Some(ref text) = args.text {
            let output: IdentifiedHashes = hash.is_match(text);
            output_complete(output,args.verbosity);
        } else {
            eprintln!("No valid input provided.");
            std::process::exit(1);
        }
        std::process::exit(0)
}
