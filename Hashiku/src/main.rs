mod patterns;
use clap::Parser;
use std::process::exit;
use patterns::{PATTERNS,HashIdentifier,HashInfo};

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
const UNDERLINE: &str = "\x1b[4m";


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
        #[arg(long = "no-banner")]
        nobanner: bool,
} 
    
fn  display(output: Vec<&HashInfo>,popular: Vec<&HashInfo>){ 
    if !popular.is_empty() {
        println!("{RED}{BOLD}{UNDERLINE}[*] MOST LIKLEY MATCHES\n{RESET}");
        for i in popular{
            print_line("[+]",i.name,i.hashcat,i.john,i.description); 
        }
        println!("");
    }
    if !output.is_empty() {
        println!("{RED}{BOLD}{UNDERLINE}[*] LIKLEY MATCHES\n{RESET}");
        for i in output {
            print_line("[-]",i.name,i.hashcat,i.john,i.description);
        }
    }
}

fn print_line(icon: &str, name: &str,hashcat: Option<&str>,john: Option<&str>,description: Option<&str>) {
    println!("{} {RED}{BOLD}{:<30}{RESET}{RED}{BOLD}Hashcat:{RESET} {:<20}{RED}{BOLD}John: {RESET}{:<20}{RED}{BOLD}Summary: {RESET}{:<20}",icon,name,hashcat.unwrap_or(""),john.unwrap_or(""),description.unwrap_or(""));
}

fn main() {
    let args = Args::parse();
    let identifier = HashIdentifier::new(&*PATTERNS);
    let (outputpos, outputprob) = identifier.match_pattern(&args.hash);
    if !args.nobanner { println!("{}",BANNER) }
    println!("{RED}{BOLD}CHECKING PATTERNS THAT MATCH: {ITALIC}{GREEN}\"{}\"{RESET}\n",args.hash);
    display(outputpos,outputprob);
    exit(0);
}
