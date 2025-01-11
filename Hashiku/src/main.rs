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
const DIM: &str = "\x1b[2m";
const ITALIC: &str = "\x1b[3m";
const UNDERLINE: &str = "\x1b[4m";
const BLINK: &str = "\x1b[5m";
const RAPID_BLINK: &str = "\x1b[6m";
const INVERSE: &str = "\x1b[7m";
const HIDDEN: &str = "\x1b[8m";
const STRIKETHROUGH: &str = "\x1b[9m";

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
        #[arg(short, long, default_value_t = 1)]
        count: u8,
} 
    
fn  display(output: Vec<&HashInfo>){ 
    for i in output{
        println!("{RED}[+]{RESET
        } {:<35}{:<25}{:<25}{:<25},",i.name,i.hashcat.unwrap_or("----"),i.john.unwrap_or("----"),i.description.unwrap_or("----"));
    }
}

fn main() {
    let args = Args::parse();
    let identifier = HashIdentifier::new(&*PATTERNS);
    let output = identifier.match_pattern(&args.hash);
    println!("{}",BANNER);
    println!("{RED}{BOLD}CHECKING PATTERNS THAT MATCH: {ITALIC}{GREEN}\"{}\"{RESET}\n",args.hash);
    display(output);
    exit(0);
}
