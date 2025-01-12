use crate::patterns::{HashInfo, IdentifiedHashes};

pub const BANNER: &str = "
██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗███╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗ 
██║  ██║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████║███████║███████╗███████║██║██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝
██╔══██║██╔══██║╚════██║██╔══██║██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║███████║██║  ██║██║██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
https://github.com/North004/Hashinator
";

pub fn banner() {
    println!("{BANNER}");
}

pub fn print_hash_info_tags(hash: &HashInfo) {
    let hashcat = hash.hashcat.unwrap_or("N/A");
    let john = hash.john.unwrap_or("N/A"); 
    let summary = hash.description.unwrap_or("N/A"); 

    println!(
        "[+] {}     Hashcat: {}     John: {}     Summary: {}",
        hash.name, hashcat, john, summary
    );
}

pub fn print_hash_info_tags_align(hash: &HashInfo) {
    let hashcat = hash.hashcat.unwrap_or("N/A");
    let john = hash.john.unwrap_or("N/A"); 
    let summary = hash.description.unwrap_or("N/A"); 

    println!(
        "[+] {:<30}Hashcat: {:<10}John: {:<20}Summary: {:<30}",
        hash.name, hashcat, john, summary
    );
}

pub fn print_hash_info(hash: &HashInfo) {
    print!("{}",hash.name);
}
pub fn output_complete(total: IdentifiedHashes,verbosity: u8) {
    println!("Identifying matches for: {}",total.hashname);
    if !total.popular.is_empty() {
        println!();
        println!("Most likley Hash functions");
        println!("--------------------------");
        match verbosity {
            0 => {
                let mut split = false;
                for hash in total.popular{
                    if split { print!(", ")}
                    print_hash_info(hash);
                    split = true;
                }
            },
            1 => {
                for hash in total.popular {
                    print_hash_info_tags(hash);
                }
            }
            _ => {
                for hash in total.popular {
                    print_hash_info_tags_align(hash);
                }
            }
    };
    }
    println!();
    if !total.unpopular.is_empty() {
        println!("Likley Hashes functions");
        println!("-----------------------");
        match verbosity {
                0 => {
                    let mut split = false;
                    for hash in total.unpopular {
                        if split { print!(", ")}
                        print_hash_info(hash);
                        split = true;
                    }
                },
                1 => {
                    for hash in total.unpopular {
                        print_hash_info_tags(hash);
                    }
                }
                _ => {
                    for hash in total.unpopular {
                        print_hash_info_tags_align(hash);
                    }
                }
        };
    }
        
    
    println!();
}
