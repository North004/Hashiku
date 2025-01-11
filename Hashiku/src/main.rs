mod patterns;
use clap::Parser;
use regex::Regex;

#[derive(Debug)]
struct HashInfo {
    name: &'static str,
    john: Option<&'static str>,
    hashcat: Option<&'static str>,
    variation: bool,
    description: Option<&'static str>,
}
#[derive(Debug)]
struct Pattern<'a> {
    regex: &'a Regex,
    modes: Vec<HashInfo>,
}

struct HashIdentifier<'a> {
    patterns: Vec<Pattern<'a>>,
}

impl<'a> HashIdentifier<'a> {
    fn new(patterns: Vec<Pattern<'a>>) -> Self {
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
    #[derive(Parser, Debug)]
    #[command(version = "0.0.1", about = "Simple and small rust tool to identify hashes", long_about = None)]
    struct Args {
        #[arg(short = 't', long = "text")]
        hash: String,
        #[arg(short, long, default_value_t = 1)]
        count: u8,
    }
    let args = Args::parse();
    let hash_identifer = HashIdentifier::new(patterns::get_patterns());
    let possibilities = hash_identifer.match_pattern(&args.hash);
    output_results(possibilities);
}
