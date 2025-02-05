/*
    Hashinator a Blazingly fast hash identificaiton tool written in rust
    Copyright (C) 2025 NorthMatrix contact@northmatrix.co.uk

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
use crate::patterns::{HashInfo, IdentifiedHashes};
use colored::*;

const BANNER: &str = "
██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗███╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗ 
██║  ██║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████║███████║███████╗███████║██║██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝
██╔══██║██╔══██║╚════██║██╔══██║██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║███████║██║  ██║██║██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
Github: https://github.com/NorthMatrix/Hashinator
Author: NorthMatrix northmatrix@pm.me
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
        println!(
            "{}: {}",
            "NO MATCHES FOUND FOR".bold().blue(),
            total.hashname.red()
        );
    } else {
        println!("{}: {}", "Hash".bold().blue(), total.hashname.red());
    }
    if !total.popular.is_empty() {
        println!(
            "\n{}",
            "Most likely Hash functions".bold().underline().blue()
        ); // Title in bold, underlined green
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
