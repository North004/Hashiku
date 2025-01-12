use crate::patterns::HashInfo;

const BANNER: &str = "
██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗███╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗ 
██║  ██║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████║███████║███████╗███████║██║██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝
██╔══██║██╔══██║╚════██║██╔══██║██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║███████║██║  ██║██║██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝";

pub fn welcome(banner: bool, hash: &str) {
    if !banner {
        println!("{BANNER}")
    }
    println!("Hash: {hash}")
}

pub fn output_line(hash: &HashInfo, symbol: &str) {
    println!("[{}] {}", symbol, hash.name,);
}

pub fn output_line_tags(hash: &HashInfo, symbol: &str) {
    let hashcat: String = match hash.hashcat {
        Some(x) => format!("Hashcat: {}", x),
        _ => "".to_string(),
    };
    let john: String = match hash.john {
        Some(x) => format!("John: {}", x),
        _ => "".to_string(),
    };
    let summary: String = match hash.description {
        Some(x) => format!("Summary: {}", x),
        _ => "".to_string(),
    };
    println!(
        "[{}] {}  {}  {}  {}",
        symbol, hash.name, hashcat, john, summary
    );
}

pub fn output_collection<F: Fn(&HashInfo, &str)>(
    collection: Vec<&HashInfo>,
    symbol: &str,
    func: F,
) {
    for hash in collection {
        func(hash, symbol);
    }
}

pub fn output_complete(total: (Vec<&HashInfo>, Vec<&HashInfo>)) {
    println!();
    if !total.0.is_empty() {
        println!("Most likley Hash functions");
        output_collection(total.0, "+", output_line_tags);
    }
    println!();
    if !total.1.is_empty() {
        println!("Likley Hashes functions");
        output_collection(total.1, "-", output_line);
    }
}
