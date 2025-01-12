mod output;
mod patterns;
use clap::Parser;
use output::{output_complete, welcome};
use patterns::HashIdentifier;

#[derive(Parser, Debug)]
#[command(version = "0.0.1", about = "Identify hashes", long_about = None)]
pub struct Args {
    #[arg(short = 't', long = "text")]
    pub hash: String,
    #[arg(long = "no-banner")]
    pub nobanner: bool,
}

fn main() {
    let args = Args::parse();
    welcome(args.nobanner, &args.hash);
    let hash = HashIdentifier::new();
    let output = hash.match_pattern(&args.hash);
    output_complete(output);
    std::process::exit(0);
}
