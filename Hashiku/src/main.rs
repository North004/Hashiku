mod patterns;
mod commands;
mod output; 
use clap::Parser;
use patterns::{PATTERNS,HashIdentifier,HashInfo};
use commands::Args;

fn main() {
    let args = Args::parse();
    let identifier = HashIdentifier::new(&*PATTERNS);
    let (outputpos, outputprob) = identifier.match_pattern(&args.hash);
    if !args.nobanner { println!("{}",BANNER) }
    println!("{RED}{BOLD}CHECKING PATTERNS THAT MATCH: {ITALIC}{GREEN}\"{}\"{RESET}\n",args.hash);
    display(outputpos,outputprob);
    std::process::exit(0);
}
