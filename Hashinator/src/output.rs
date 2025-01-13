use crate::patterns::{HashInfo, IdentifiedHashes};
use colored::*;

const BANNER: &str = "
██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗███╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗ 
██║  ██║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████║███████║███████╗███████║██║██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝
██╔══██║██╔══██║╚════██║██╔══██║██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║███████║██║  ██║██║██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
Github: https://github.com/North004/Hashinator
Author: northsky.dev@pm.me
";

pub fn get_bannter() -> &'static str {
    BANNER
}

pub fn print_hash_info_tags(hash: &HashInfo) {
    let hashcat = hash.hashcat.unwrap_or("N/A");
    let john = hash.john.unwrap_or("N/A");
    let summary = hash.description.unwrap_or("N/A");

    println!(
        "{}     Hashcat: {}     John: {}     Summary: {}",
        hash.name.red().bold(),
        hashcat.magenta(),
        john.cyan(),
        summary.dimmed()
    );
}

pub fn print_hash_info(hash: &HashInfo) {
    print!("{}", hash.name.red());
}

pub fn output_complete(total: IdentifiedHashes, verbosity: u8) {
    if total.popular.is_empty() && total.unpopular.is_empty() {
        println!("{}: {}", "NO MATCHES FOUND FOR".bold().blue(), total.hashname.red());
    }
    else { 
        println!("{}: {}", "Hash".bold().blue(), total.hashname.red());
    }
    if !total.popular.is_empty() {
        println!("\n{}", "Most likely Hash functions".bold().underline().blue()); // Title in bold, underlined green
        for hash in total.popular {
            print_hash_info_tags(hash);
        }
    }
    println!("");
    if !total.unpopular.is_empty() {
        println!("{}", "Likely Hash functions".bold().underline().blue()); // Title in bold, underlined yellow
        match verbosity {
            0 => {
                let mut split = false;
                for hash in total.unpopular {
                    if split {
                        print!(", ");
                    }
                    print_hash_info(hash);
                    split = true;
                }
                println!("\n");
            }
            _ => {
                for hash in total.unpopular {
                    print_hash_info_tags(hash);
                }
            }
        };
    }
}
