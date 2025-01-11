use clap::Parser;

#[derive(Parser, Debug)]
#[command(version = "0.0.1", about = "IDENTIFY HASHES", long_about = None)]
pub struct Args {
        #[arg(short = 't', long = "text")]
        pub hash: String,
        #[arg(long = "no-banner")]
        pub nobanner: bool,
} 