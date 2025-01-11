mod patterns;
use clap::Parser;
use once_cell::sync::Lazy;
use regex::Regex;
use std::time::Instant;
use std::process::exit;

#[derive(Debug)]
struct HashInfo {
    name: &'static str,
    john: Option<&'static str>,
    hashcat: Option<&'static str>,
    variation: bool,
    description: Option<&'static str>,
}
#[derive(Debug)]
struct Pattern {
    regex: &'static Regex,
    modes: Vec<HashInfo>,
}

struct HashIdentifier {
    patterns: Vec<Pattern>,
}

impl<'a> HashIdentifier {
    fn new(patterns: Vec<Pattern>) -> Self {
        Self { patterns }
    }
    fn match_pattern(&self, input: &str) -> Vec<&HashInfo> {
        let mut possible = vec![];
        for pattern in &self.patterns {
            if pattern.regex.is_match(input) {
                possible.extend(&pattern.modes);
            }
        }
        possible
    }
}

fn output_results(results: Vec<&HashInfo>) {
    for x in results {
        println!(
            "[+] {:<40}{:<20}{:<20}{:<20}{:<20}",
            x.name,
            x.john.unwrap_or("____"),
            x.hashcat.unwrap_or("____"),
            x.variation,
            x.description.unwrap_or("____")
        );
    }
}

fn main() {
    std::thread::spawn(||)
    let start = Instant::now();
    #[derive(Parser, Debug)]
    #[command(version = "0.0.1", about = "Simple and small rust tool to identify hashes", long_about = None)]
    struct Args {
        #[arg(short = 't', long = "text")]
        hash: String,
        #[arg(short, long, default_value_t = 1)]
        count: u8,
    }
    println!("{:?}",start.elapsed());
    let args = Args::parse();
    let hash_identifer = HashIdentifier::new(patterns::get_patterns());
    println!("{:?}",start.elapsed());
    let possibilities = hash_identifer.match_pattern(&args.hash);
    println!("{:?}",start.elapsed());
    output_results(possibilities);
    println!("{:?}",start.elapsed());
    exit(0);
}
