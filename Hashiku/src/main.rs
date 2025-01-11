mod patterns;
use clap::Parser;
use std::process::exit;
use patterns::{PATTERNS,HashIdentifier,HashInfo};

const TOP: u8 = 5;
const BANNER: &str = "
\x1b[31m
██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗███╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗ 
██║  ██║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████║███████║███████╗███████║██║██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝
██╔══██║██╔══██║╚════██║██╔══██║██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║███████║██║  ██║██║██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝                                                                
\x1b[0m";

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const ITALIC: &str = "\x1b[3m";


// Text Colors
const BLACK: &str = "\x1b[30m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";
const WHITE: &str = "\x1b[37m";

#[derive(Parser, Debug)]
#[command(version = "0.0.1", about = "IDENTIFY HASHES", long_about = None)]
struct Args {
        #[arg(short = 't', long = "text")]
        hash: String,
} 
    
fn  display(output: Vec<&HashInfo>,popular: Vec<&HashInfo>){ 
    println!("{RED}{BOLD}[o] {:<40}{:<15}{:<15}{:<30}\n","HASHING ALGORITHM NAME","HASHCAT","JOHN","DESCRIPTION");
    if !popular.is_empty() {
        println!("{RED}{BOLD}[*] MOST LIKLEY MATCHES\n");
        for i in popular{
            println!("{BOLD}{RED}[+]{RESET} {:<40}{:<15}{:<15}{:<30}",i.name,i.hashcat.unwrap_or("......."),i.john.unwrap_or("...."),i.description.unwrap_or("..........."));
        }
        println!("");
    }
    if !output.is_empty() {
        println!("{RED}{BOLD}[-] LIKLEY MATCHES\n");
        for i in output {
            println!("{BOLD}{RED}[+]{RESET} {:<40}{:<15}{:<15}{:<30}",i.name,i.hashcat.unwrap_or("......."),i.john.unwrap_or("...."),i.description.unwrap_or("..........."));
    }
    }
}

fn main() {
    let args = Args::parse();
    let identifier = HashIdentifier::new(&*PATTERNS);
    let (outputpos, outputprob) = identifier.match_pattern(&args.hash);
    println!("{}",BANNER);
    println!("{RED}{BOLD}CHECKING PATTERNS THAT MATCH: {ITALIC}{GREEN}\"{}\"{RESET}\n",args.hash);
    display(outputpos,outputprob);
    exit(0);
}
