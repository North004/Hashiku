use std::hash::Hash;

use clap::Parser;
use regex::Regex;

static NONE: &'static str = "None";

#[derive(Debug)]
struct HashInfo {
    name: &'static str,
    john: Option<&'static str>,
    hashcat: Option<&'static str>,
    variation: bool,
    description: Option<&'static str>,
}

struct Pattern<'a> {
    regex: Regex,
    modes: Vec<&'a HashInfo>,
}

struct HashIdentifier<'a> {
    patterns: Vec<Pattern<'a>>,
}

impl<'a> HashIdentifier<'a> {
    fn new(patterns: Vec<Pattern<'a>>,popular: Vec<&'static str>) -> Self {
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

fn output_results(results: Vec<&HashInfo>) -> () {
    let top: u8 = 5;
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
    let pattern: Vec<Pattern> = vec![
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{4}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "CRC-16", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "CRC-16-CCITT", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "FCS-16", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{8}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Adler-32", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "CRC-32B", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "FCS-32", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "GHash-32-3", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "GHash-32-5", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "FNV-132", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Fletcher-32", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Joaat", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "ELF-32", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "XOR-32", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{6}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "CRC-24", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$crc32\$)?([a-f0-9]{8}.)?[a-f0-9]{8}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "CRC-32", john: Some("crc32") ,hashcat: Some("11500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\+[a-z0-9\/.]{12}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Eggdrop IRC Bot", john: Some("bfegg") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9\/.]{12}[.26AEIMQUYcgkosw]{1}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "DES(Unix)", john: Some("descrypt") ,hashcat: Some("1500") ,variation: false ,description: None },
          &HashInfo{ name: "Traditional DES", john: Some("descrypt") ,hashcat: Some("1500") ,variation: false ,description: None },
          &HashInfo{ name: "DEScrypt", john: Some("descrypt") ,hashcat: Some("1500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{16}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MySQL323", john: Some("mysql") ,hashcat: Some("200") ,variation: false ,description: None },
          &HashInfo{ name: "Half MD5", john: None ,hashcat: Some("5100") ,variation: false ,description: None },
          &HashInfo{ name: "FNV-164", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "CRC-64", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{16}:[a-f0-9]{0,30}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Oracle H: Type (Oracle 7+), DES(Oracle)", john: None ,hashcat: Some("3100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9\/.]{16}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Cisco-PIX(MD5)", john: Some("pix-md5") ,hashcat: Some("2400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\([a-z0-9\/+]{20}\)$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Lotus Notes/Domino 6", john: Some("dominosec") ,hashcat: Some("8700") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^_[a-z0-9\/.]{19}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "BSDi Crypt", john: Some("bsdicrypt") ,hashcat: Some("12400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{24}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "CRC-96(ZIP)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "PKZIP Master Key", john: None ,hashcat: Some("20500") ,variation: false ,description: None },
          &HashInfo{ name: "PKZIP Master Key (6 byte optimization)", john: None ,hashcat: Some("20510") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"^\$keepass\$\*1\*50000\*(0|1)\*([a-f0-9]{32})\*([a-f0-9]{64})\*([a-f0-9]{32})\*([a-f0-9]{64})\*1\*(192|1360)\*([a-f0-9]{384})$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Keepass 1 AES / without keyfile", john: None ,hashcat: Some("13400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"^\$keepass\$\*1\*6000\*(0|1)\*([a-f0-9]{32})\*([a-f0-9]{64})\*([a-f0-9]{32})\*([a-f0-9]{64})\*1\*(192|1360)\*([a-f0-9]{2720})\*1\*64\*([a-f0-9]{64})$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Keepass 1 Twofish / with keyfile", john: None ,hashcat: Some("13400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"^\$keepass\$\*2\*6000\*222(\*[a-f0-9]{64}){2}(\*[a-f0-9]{32}){1}(\*[a-f0-9]{64}){2}\*1\*64(\*[a-f0-9]{64}){1}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Keepass 2 AES / with keyfile", john: None ,hashcat: Some("13400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"^\$keepass\$\*2\*6000\*222\*(([a-f0-9]{32,64})(\*)?)+$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Keepass 2 AES / without keyfile", john: None ,hashcat: Some("13400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9\/.]{24}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Crypt16", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MD5", john: Some("raw-md5") ,hashcat: Some("0") ,variation: false ,description: None },
          &HashInfo{ name: "MD4", john: Some("raw-md4") ,hashcat: Some("900") ,variation: false ,description: None },
          &HashInfo{ name: "Double MD5", john: None ,hashcat: Some("2600") ,variation: false ,description: None },
          &HashInfo{ name: "Tiger-128", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Skein-256(128)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Skein-512(128)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Lotus Notes/Domino 5", john: Some("lotus5") ,hashcat: Some("8600") ,variation: false ,description: None },
          &HashInfo{ name: "md5(md5(md5($pass)))", john: None ,hashcat: Some("3500") ,variation: true ,description: None },
          &HashInfo{ name: "md5(uppercase(md5($pass)))", john: None ,hashcat: Some("4300") ,variation: true ,description: None },
          &HashInfo{ name: "md5(sha1($pass))", john: None ,hashcat: Some("4400") ,variation: true ,description: None },
          &HashInfo{ name: "md5(utf16($pass))", john: Some("dynamic_29") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "md4(utf16($pass))", john: Some("dynamic_33") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "md5(md4($pass))", john: Some("dynamic_34") ,hashcat: None ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)(?:\$haval\$)?[a-f0-9]{32,64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Haval-128", john: Some("haval-128-4") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)(?:\$ripemd\$)?[a-f0-9]{32,40}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "RIPEMD-128", john: Some("ripemd-128") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{16}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "LM", john: Some("lm") ,hashcat: Some("3000") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)(?:\$dynamic_39\$)?[a-f0-9]{32}\$[a-z0-9]{1,32}\$?[a-z0-9]{1,500}"##).unwrap(), modes: vec![
          &HashInfo{ name: "net-md5", john: Some("dynamic_39") ,hashcat: None ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}:[a-z0-9]+$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Skype", john: None ,hashcat: Some("23") ,variation: false ,description: None },
          &HashInfo{ name: "ZipMonster", john: None ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "md5(md5(md5($pass)))", john: None ,hashcat: Some("3500") ,variation: true ,description: None },
          &HashInfo{ name: "md5(uppercase(md5($pass)))", john: None ,hashcat: Some("4300") ,variation: true ,description: None },
          &HashInfo{ name: "md5(sha1($pass))", john: None ,hashcat: Some("4400") ,variation: true ,description: None },
          &HashInfo{ name: "md5($pass.$salt)", john: None ,hashcat: Some("10") ,variation: true ,description: None },
          &HashInfo{ name: "md5($salt.$pass)", john: None ,hashcat: Some("20") ,variation: true ,description: None },
          &HashInfo{ name: "md5(unicode($pass).$salt)", john: None ,hashcat: Some("30") ,variation: true ,description: None },
          &HashInfo{ name: "md5($salt.unicode($pass))", john: None ,hashcat: Some("40") ,variation: true ,description: None },
          &HashInfo{ name: "HMAC-MD5 (key = $pass)", john: Some("hmac-md5") ,hashcat: Some("50") ,variation: true ,description: None },
          &HashInfo{ name: "HMAC-MD5 (key = $salt)", john: Some("hmac-md5") ,hashcat: Some("60") ,variation: true ,description: None },
          &HashInfo{ name: "md5(md5($salt).$pass)", john: None ,hashcat: Some("3610") ,variation: true ,description: None },
          &HashInfo{ name: "md5($salt.md5($pass))", john: None ,hashcat: Some("3710") ,variation: true ,description: None },
          &HashInfo{ name: "md5($pass.md5($salt))", john: None ,hashcat: Some("3720") ,variation: true ,description: None },
          &HashInfo{ name: "WebEdition CMS", john: None ,hashcat: Some("3721") ,variation: false ,description: None },
          &HashInfo{ name: "md5($username.0.$pass)", john: None ,hashcat: Some("4210") ,variation: true ,description: None },
          &HashInfo{ name: "md5($salt.$pass.$salt)", john: None ,hashcat: Some("3800") ,variation: true ,description: None },
          &HashInfo{ name: "md5(md5($pass).md5($salt))", john: None ,hashcat: Some("3910") ,variation: true ,description: None },
          &HashInfo{ name: "md5($salt.md5($salt.$pass))", john: None ,hashcat: Some("4010") ,variation: true ,description: None },
          &HashInfo{ name: "md5($salt.md5($pass.$salt))", john: None ,hashcat: Some("4110") ,variation: true ,description: None },
          &HashInfo{ name: "md4($salt.$pass)", john: Some("dynamic_31") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "md4($pass.$salt)", john: Some("dynamic_32") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "md5($salt.pad16($pass))", john: Some("dynamic_39") ,hashcat: None ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}:[a-z0-9]{56}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PrestaShop", john: None ,hashcat: Some("11000") ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$md2\$)?[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MD2", john: Some("md2") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$snefru\$)?[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Snefru-128", john: Some("snefru-128") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$NT\$)?[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "NTLM", john: Some("nt") ,hashcat: Some("1000") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Domain Cached Credentials", john: Some("mscash") ,hashcat: Some("1100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Domain Cached Credentials 2", john: Some("mscash2") ,hashcat: Some("2100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\{SHA}[a-z0-9\/+]{27}=$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SHA-1(Base64)", john: Some("nsldap") ,hashcat: Some("101") ,variation: false ,description: None },
          &HashInfo{ name: "Netscape LDAP SHA", john: Some("nsldap") ,hashcat: Some("101") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MD5 Crypt", john: Some("md5crypt") ,hashcat: Some("500") ,variation: false ,description: None },
          &HashInfo{ name: "Cisco-IOS(MD5)", john: Some("md5crypt") ,hashcat: Some("500") ,variation: false ,description: None },
          &HashInfo{ name: "FreeBSD MD5", john: Some("md5crypt") ,hashcat: Some("500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^0x[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Lineage II C4", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$H\$[a-z0-9\/.]{31}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "phpBB v3.x", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None },
          &HashInfo{ name: "Wordpress v2.6.0/2.6.1", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None },
          &HashInfo{ name: "PHPass' Portable Hash", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$P\$[a-z0-9\/.]{31}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Wordpress ≥ v2.6.2", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None },
          &HashInfo{ name: "Joomla ≥ v2.5.18", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None },
          &HashInfo{ name: "PHPass' Portable Hash", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}:[a-z0-9]{2}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "osCommerce", john: None ,hashcat: Some("21") ,variation: false ,description: None },
          &HashInfo{ name: "xt:Commerce", john: None ,hashcat: Some("21") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MD5(APR)", john: None ,hashcat: Some("1600") ,variation: false ,description: None },
          &HashInfo{ name: "Apache MD5", john: None ,hashcat: Some("1600") ,variation: false ,description: None },
          &HashInfo{ name: "md5apr1", john: None ,hashcat: Some("1600") ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\{smd5}[a-z0-9$\/.]{31}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "AIX(smd5)", john: Some("aix-smd5") ,hashcat: Some("6300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}:.{5}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "IP.Board ≥ v2+", john: None ,hashcat: Some("2811") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}:.{8}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MyBB ≥ v1.2+", john: None ,hashcat: Some("2811") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9]{34}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "CryptoCurrency(Adress)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{40}(:.+)?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SHA-1", john: Some("raw-sha1") ,hashcat: Some("100") ,variation: false ,description: None },
          &HashInfo{ name: "Double SHA-1", john: None ,hashcat: Some("4500") ,variation: false ,description: None },
          &HashInfo{ name: "RIPEMD-160", john: Some("ripemd-160") ,hashcat: Some("6000") ,variation: false ,description: None },
          &HashInfo{ name: "Haval-160 (3 rounds)", john: Some("dynamic_190") ,hashcat: Some("6000") ,variation: false ,description: None },
          &HashInfo{ name: "Haval-160 (4 rounds)", john: Some("dynamic_200") ,hashcat: Some("6000") ,variation: false ,description: None },
          &HashInfo{ name: "Haval-160 (5 rounds)", john: Some("dynamic_210") ,hashcat: Some("6000") ,variation: false ,description: None },
          &HashInfo{ name: "Haval-192 (3 rounds)", john: Some("dynamic_220") ,hashcat: Some("6000") ,variation: false ,description: None },
          &HashInfo{ name: "Haval-192 (4 rounds)", john: Some("dynamic_230") ,hashcat: Some("6000") ,variation: false ,description: None },
          &HashInfo{ name: "Haval-192 (5 rounds)", john: Some("dynamic_240") ,hashcat: Some("6000") ,variation: false ,description: None },
          &HashInfo{ name: "Haval-224 (4 rounds)", john: Some("dynamic_260") ,hashcat: Some("6000") ,variation: false ,description: None },
          &HashInfo{ name: "Haval-224 (5 rounds)", john: Some("dynamic_270") ,hashcat: Some("6000") ,variation: false ,description: None },
          &HashInfo{ name: "Haval-160", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Tiger-160", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "HAS-160", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "LinkedIn", john: Some("raw-sha1-linkedin") ,hashcat: Some("190") ,variation: false ,description: None },
          &HashInfo{ name: "Skein-256(160)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Skein-512(160)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "MangosWeb Enhanced CMS", john: None ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha1(sha1(sha1($pass)))", john: None ,hashcat: Some("4600") ,variation: true ,description: None },
          &HashInfo{ name: "sha1(md5($pass))", john: None ,hashcat: Some("4700") ,variation: true ,description: None },
          &HashInfo{ name: "sha1($pass.$salt)", john: None ,hashcat: Some("110") ,variation: true ,description: None },
          &HashInfo{ name: "sha1($salt.$pass)", john: None ,hashcat: Some("120") ,variation: true ,description: None },
          &HashInfo{ name: "sha1(unicode($pass).$salt)", john: None ,hashcat: Some("130") ,variation: true ,description: None },
          &HashInfo{ name: "sha1($salt.unicode($pass))", john: None ,hashcat: Some("140") ,variation: true ,description: None },
          &HashInfo{ name: "HMAC-SHA1 (key = $pass)", john: Some("hmac-sha1") ,hashcat: Some("150") ,variation: true ,description: None },
          &HashInfo{ name: "HMAC-SHA1 (key = $salt)", john: Some("hmac-sha1") ,hashcat: Some("160") ,variation: true ,description: None },
          &HashInfo{ name: "sha1($salt.$pass.$salt)", john: None ,hashcat: Some("4710") ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{40}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MySQL5.x", john: Some("mysql-sha1") ,hashcat: Some("300") ,variation: false ,description: None },
          &HashInfo{ name: "MySQL4.1", john: Some("mysql-sha1") ,hashcat: Some("300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9]{43}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Cisco-IOS(SHA-256)", john: None ,hashcat: Some("5700") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\{SSHA}[a-z0-9\/+]{38}==$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SSHA-1(Base64)", john: Some("nsldaps") ,hashcat: Some("111") ,variation: false ,description: None },
          &HashInfo{ name: "Netscape LDAP SSHA", john: Some("nsldaps") ,hashcat: Some("111") ,variation: false ,description: None },
          &HashInfo{ name: "nsldaps", john: Some("nsldaps") ,hashcat: Some("111") ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9=]{47}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Fortigate(FortiOS)", john: Some("fortigate") ,hashcat: Some("7000") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{48}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Haval-192", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Tiger-192", john: Some("tiger") ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "SHA-1(Oracle)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "OSX v10.4", john: Some("xsha") ,hashcat: Some("122") ,variation: false ,description: None },
          &HashInfo{ name: "OSX v10.5", john: Some("xsha") ,hashcat: Some("122") ,variation: false ,description: None },
          &HashInfo{ name: "OSX v10.6", john: Some("xsha") ,hashcat: Some("122") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{51}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Palshop CMS", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9]{51}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "CryptoCurrency(PrivateKey)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "AIX(ssha1)", john: Some("aix-ssha1") ,hashcat: Some("6700") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^0x0100[a-f0-9]{48}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MSSQL(2005)", john: Some("mssql05") ,hashcat: Some("132") ,variation: false ,description: None },
          &HashInfo{ name: "MSSQL(2008)", john: Some("mssql05") ,hashcat: Some("132") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Sun MD5 Crypt", john: Some("sunmd5") ,hashcat: Some("3300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{56}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SHA-224", john: Some("raw-sha224") ,hashcat: Some("1300") ,variation: false ,description: None },
          &HashInfo{ name: "sha224($salt.$pass)", john: Some("dynamic_51") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha224($pass.$salt))", john: Some("dynamic_52") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha224(sha224($pass))", john: Some("dynamic_53") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha224(sha224_raw($pass))", john: Some("dynamic_54") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha224(sha224($pass).$salt)", john: Some("dynamic_55") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha224($salt.sha224($pass))", john: Some("dynamic_56") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha224(sha224($salt).sha224($pass))", john: Some("dynamic_57") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha224(sha224($pass).sha224($pass))", john: Some("dynamic_58") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "Haval-224", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "SHA3-224", john: None ,hashcat: Some("17300") ,variation: false ,description: None },
          &HashInfo{ name: "Skein-256(224)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Skein-512(224)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Skein-224", john: Some("dynamic_330") ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Keccak-224", john: None ,hashcat: Some("17700") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$2[abxy]?|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Blowfish(OpenBSD)", john: Some("bcrypt") ,hashcat: Some("3200") ,variation: false ,description: None },
          &HashInfo{ name: "Woltlab Burning Board 4.x", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "bcrypt", john: Some("bcrypt") ,hashcat: Some("3200") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$y\$[.\/A-Za-z0-9]+\$[.\/a-zA-Z0-9]+\$[.\/A-Za-z0-9]{43}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "yescrypt", john: Some("On systems that use libxcrypt, you may use --format=crypt to use JtR in passthrough mode which uses the system's crypt function.") ,hashcat: Some("Not yet supported, see notes in summary.") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{40}:[a-f0-9]{16}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Android PIN", john: None ,hashcat: Some("5800") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Oracle 11g/12c", john: Some("oracle11") ,hashcat: Some("112") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "bcrypt(SHA-256)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}:.{3}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "vBulletin < v3.8.5", john: None ,hashcat: Some("2611") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}:.{30}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "vBulletin ≥ v3.8.5", john: None ,hashcat: Some("2711") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$snefru\$)?[a-f0-9]{64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Snefru-256", john: Some("snefru-256") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{64}(:.+)?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SHA-256", john: Some("raw-sha256") ,hashcat: Some("1400") ,variation: false ,description: None },
          &HashInfo{ name: "RIPEMD-256", john: Some("dynamic_140") ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Haval-256 (3 rounds)", john: Some("dynamic_140") ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Haval-256 (4 rounds)", john: Some("dynamic_290") ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Haval-256 (5 rounds)", john: Some("dynamic_300") ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "GOST R 34.11-94", john: Some("gost") ,hashcat: Some("6900") ,variation: false ,description: None },
          &HashInfo{ name: "GOST CryptoPro S-Box", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Blake2b-256", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "SHA3-256", john: Some("dynamic_380") ,hashcat: Some("17400") ,variation: false ,description: None },
          &HashInfo{ name: "PANAMA", john: Some("dynamic_320") ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "BLAKE2-256", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "BLAKE2-384", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Skein-256", john: Some("skein-256") ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Skein-512(256)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Ventrilo", john: None ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha256($pass.$salt)", john: Some("dynamic_62") ,hashcat: Some("1410") ,variation: true ,description: None },
          &HashInfo{ name: "sha256($salt.$pass)", john: Some("dynamic_61") ,hashcat: Some("1420") ,variation: true ,description: None },
          &HashInfo{ name: "sha256(sha256($pass))", john: Some("dynamic_63") ,hashcat: Some("1420") ,variation: true ,description: None },
          &HashInfo{ name: "sha256(sha256_raw($pass)))", john: Some("dynamic_64") ,hashcat: Some("1420") ,variation: true ,description: None },
          &HashInfo{ name: "sha256(sha256($pass).$salt)", john: Some("dynamic_65") ,hashcat: Some("1420") ,variation: true ,description: None },
          &HashInfo{ name: "sha256($salt.sha256($pass))", john: Some("dynamic_66") ,hashcat: Some("1420") ,variation: true ,description: None },
          &HashInfo{ name: "sha256(sha256($salt).sha256($pass))", john: Some("dynamic_67") ,hashcat: Some("1420") ,variation: true ,description: None },
          &HashInfo{ name: "sha256(sha256($pass).sha256($pass))", john: Some("dynamic_68") ,hashcat: Some("1420") ,variation: true ,description: None },
          &HashInfo{ name: "sha256(unicode($pass).$salt)", john: None ,hashcat: Some("1430") ,variation: true ,description: None },
          &HashInfo{ name: "sha256($salt.unicode($pass))", john: None ,hashcat: Some("1440") ,variation: true ,description: None },
          &HashInfo{ name: "HMAC-SHA256 (key = $pass)", john: Some("hmac-sha256") ,hashcat: Some("1450") ,variation: true ,description: None },
          &HashInfo{ name: "HMAC-SHA256 (key = $salt)", john: Some("hmac-sha256") ,hashcat: Some("1460") ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}:[a-z0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Joomla < v2.5.18", john: None ,hashcat: Some("11") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}:[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SAM(LM_Hash:NT_Hash)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MD5(Chap)", john: Some("chap") ,hashcat: Some("4800") ,variation: false ,description: None },
          &HashInfo{ name: "iSCSI CHAP Authentication", john: Some("chap") ,hashcat: Some("4800") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "EPiServer 6.x < v4", john: Some("episerver") ,hashcat: Some("141") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "AIX(ssha256)", john: Some("aix-ssha256") ,hashcat: Some("6400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{80}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "RIPEMD-320", john: Some("dynamic_150") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "EPiServer 6.x ≥ v4", john: Some("episerver") ,hashcat: Some("1441") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^0x0100[a-f0-9]{88}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MSSQL(2000)", john: Some("mssql") ,hashcat: Some("131") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{96}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SHA-384", john: Some("raw-sha384") ,hashcat: Some("10800") ,variation: false ,description: None },
          &HashInfo{ name: "SHA3-384", john: Some("dynamic_390") ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Skein-512(384)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Skein-1024(384)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "sha384($salt.$pass)", john: Some("dynamic_71") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha384($pass.$salt)", john: Some("dynamic_72") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha384(sha384($pass))", john: Some("dynamic_73") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha384(sha384_raw($pass))", john: Some("dynamic_74") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha384(sha384($pass).$salt)", john: Some("dynamic_75") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha384($salt.sha384($pass))", john: Some("dynamic_76") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha384(sha384($salt).sha384($pass))", john: Some("dynamic_77") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "sha384(sha384($pass).sha384($pass))", john: Some("dynamic_78") ,hashcat: None ,variation: true ,description: None },
          &HashInfo{ name: "Skein-384", john: Some("dynamic_350") ,hashcat: None ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\{SSHA512}[a-z0-9\/+]{96}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SSHA-512(Base64)", john: Some("ssha512") ,hashcat: Some("1711") ,variation: false ,description: None },
          &HashInfo{ name: "LDAP(SSHA-512)", john: Some("ssha512") ,hashcat: Some("1711") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "AIX(ssha512)", john: Some("aix-ssha512") ,hashcat: Some("6500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{128}(:.+)?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SHA-512", john: Some("raw-sha512") ,hashcat: Some("1700") ,variation: false ,description: None },
          &HashInfo{ name: "Keccak-512", john: None ,hashcat: Some("1800") ,variation: false ,description: None },
          &HashInfo{ name: "Whirlpool", john: Some("whirlpool") ,hashcat: Some("6100") ,variation: false ,description: None },
          &HashInfo{ name: "Salsa10", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Salsa20", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Blake2", john: Some("raw-blake2") ,hashcat: Some("600") ,variation: false ,description: None },
          &HashInfo{ name: "SHA3-512", john: Some("raw-sha3") ,hashcat: Some("17600") ,variation: false ,description: None },
          &HashInfo{ name: "Skein-512", john: Some("skein-512") ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "Skein-1024(512)", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "sha512($pass.$salt)", john: None ,hashcat: Some("1710") ,variation: true ,description: None },
          &HashInfo{ name: "sha512($salt.$pass)", john: None ,hashcat: Some("1720") ,variation: true ,description: None },
          &HashInfo{ name: "sha512(unicode($pass).$salt)", john: None ,hashcat: Some("1730") ,variation: true ,description: None },
          &HashInfo{ name: "sha512($salt.unicode($pass))", john: None ,hashcat: Some("1740") ,variation: true ,description: None },
          &HashInfo{ name: "HMAC-SHA512 (key = $pass)", john: Some("hmac-sha512") ,hashcat: Some("1750") ,variation: true ,description: None },
          &HashInfo{ name: "BLAKE2-224", john: None ,hashcat: None ,variation: false ,description: None },
          &HashInfo{ name: "HMAC-SHA512 (key = $salt)", john: Some("hmac-sha512") ,hashcat: Some("1760") ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Keccak-256", john: None ,hashcat: Some("17800") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{96}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Keccak-384", john: None ,hashcat: Some("17900") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{136}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "OSX v10.7", john: Some("xsha512") ,hashcat: Some("1722") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^0x0200[a-f0-9]{136}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MSSQL(2012)", john: Some("mssql12") ,hashcat: Some("1731") ,variation: false ,description: None },
          &HashInfo{ name: "MSSQL(2014)", john: Some("mssql12") ,hashcat: Some("1731") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "OSX v10.8", john: Some("pbkdf2-hmac-sha512") ,hashcat: Some("7100") ,variation: false ,description: None },
          &HashInfo{ name: "OSX v10.9", john: Some("pbkdf2-hmac-sha512") ,hashcat: Some("7100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{256}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Skein-1024", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "GRUB 2", john: None ,hashcat: Some("7200") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^sha1\$[a-z0-9]+\$[a-f0-9]{40}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Django(SHA-1)", john: None ,hashcat: Some("124") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{49}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Citrix Netscaler", john: Some("citrix_ns10") ,hashcat: Some("8100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$S\$[a-z0-9\/.]{52}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Drupal > v7.x", john: Some("drupal7") ,hashcat: Some("7900") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SHA-256 Crypt", john: Some("sha256crypt") ,hashcat: Some("7400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Sybase ASE", john: Some("sybasease") ,hashcat: Some("8000") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SHA-512 Crypt", john: Some("sha512crypt") ,hashcat: Some("1800") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Minecraft(AuthMe Reloaded)", john: None ,hashcat: Some("20711") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^sha256\$[a-z0-9]+\$[a-f0-9]{64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Django(SHA-256)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^sha384\$[a-z0-9]+\$[a-f0-9]{96}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Django(SHA-384)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Clavister Secure Gateway", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{112}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Cisco VPN Client(PCF-File)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{1329}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Microsoft MSTSC(RDP-File)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "NetNTLMv1-VANILLA / NetNTLMv1+ESS", john: Some("netntlm") ,hashcat: Some("5500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$"##).unwrap(), modes: vec![
          &HashInfo{ name: "NetNTLMv2", john: Some("netntlmv2") ,hashcat: Some("5600") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$(krb5pa|mskrb5)\$(23)?\$.+\$[a-f0-9]{1,}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Kerberos 5 AS-REQ Pre-Auth", john: Some("krb5pa-md5") ,hashcat: Some("7500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SCRAM Hash", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{40}:[a-f0-9]{0,32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Redmine Project Management Web App", john: None ,hashcat: Some("4521") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^([^$]+)?\$[a-f0-9]{16}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SAP CODVN B (BCODE)", john: Some("sapb") ,hashcat: Some("7700") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(.+)?\$[a-f0-9]{40}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SAP CODVN F/G (PASSCODE)", john: Some("sapg") ,hashcat: Some("7800") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Juniper Netscreen/SSG(ScreenOS)", john: Some("md5ns") ,hashcat: Some("22") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^0x(?:[a-f0-9]{60}|[a-f0-9]{40})$"##).unwrap(), modes: vec![
          &HashInfo{ name: "EPi", john: None ,hashcat: Some("123") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{40}:[^*]{1,25}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SMF ≥ v1.1", john: None ,hashcat: Some("121") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Woltlab Burning Board 3.x", john: Some("wbb3") ,hashcat: Some("8400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{130}(:[a-f0-9]{40})?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "IPMI2 RAKP HMAC-SHA1", john: None ,hashcat: Some("7300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Lastpass", john: None ,hashcat: Some("6800") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9\/.]{16}([:$].{1,})?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Cisco-ASA(MD5)", john: Some("asa-md5") ,hashcat: Some("2410") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "VNC", john: Some("vnc") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "DNSSEC(NSEC3)", john: None ,hashcat: Some("8300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "RACF", john: Some("racf") ,hashcat: Some("8500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$3\$\$[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "NTHash(FreeBSD Variant)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SHA-1 Crypt", john: Some("sha1crypt") ,hashcat: Some("15100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{70}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "hMailServer", john: Some("hmailserver") ,hashcat: Some("1421") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MediaWiki", john: Some("mediawiki") ,hashcat: Some("3711") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{140}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Minecraft(xAuth)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PBKDF2-SHA1(Generic)", john: None ,hashcat: Some("20400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PBKDF2-SHA256(Generic)", john: Some("pbkdf2-hmac-sha256") ,hashcat: Some("20300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PBKDF2-SHA512(Generic)", john: None ,hashcat: Some("20200") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PBKDF2(Cryptacular)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PBKDF2(Dwayne Litzenberger)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Fairly Secure Hashed Password", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$PHPS\$.+\$[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PHPS", john: Some("phps") ,hashcat: Some("2612") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "1Password(Agile Keychain)", john: None ,hashcat: Some("6600") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "1Password(Cloud Keychain)", john: None ,hashcat: Some("8200") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "IKE-PSK MD5", john: None ,hashcat: Some("5300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "IKE-PSK SHA1", john: None ,hashcat: Some("5400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9\/+]{27}=$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PeopleSoft", john: None ,hashcat: Some("133") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Django(DES Crypt Wrapper)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Django(PBKDF2-HMAC-SHA256)", john: Some("django") ,hashcat: Some("10000") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Django(PBKDF2-HMAC-SHA1)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Django(bcrypt)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^md5\$[a-f0-9]+\$[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Django(MD5)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\{PKCS5S2\}[a-z0-9\/+]{64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PBKDF2(Atlassian)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^md5[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PostgreSQL MD5", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\([a-z0-9\/+]{49}\)$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Lotus Notes/Domino 8", john: None ,hashcat: Some("9100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "scrypt", john: None ,hashcat: Some("8900") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Cisco Type 8", john: Some("cisco8") ,hashcat: Some("9200") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Cisco Type 9", john: Some("cisco9") ,hashcat: Some("9300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Microsoft Office 2007", john: Some("office") ,hashcat: Some("9400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Microsoft Office 2010", john: Some("office") ,hashcat: Some("9500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\\$office\\$2016\\$[0-9]\\$[0-9]{6}\\$[^$]{24}\\$[^$]{88}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Microsoft Office 2016 - SheetProtection", john: None ,hashcat: Some("25300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Microsoft Office 2013", john: Some("office") ,hashcat: Some("9600") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Android FDE ≤ 4.3", john: Some("fde") ,hashcat: Some("8800") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$krb5tgs\$23\$\*[^*]*\*\$[a-f0-9]{32}\$[a-f0-9]{64,40960}"##).unwrap(), modes: vec![
          &HashInfo{ name: "Kerberos 5 TGS-REP etype 23", john: Some("krb5tgs") ,hashcat: Some("13100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Microsoft Office ≤ 2003 (MD5+RC4)", john: Some("oldoffice") ,hashcat: Some("9700") ,variation: false ,description: None },
          &HashInfo{ name: "Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1", john: Some("oldoffice") ,hashcat: Some("9710") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Microsoft Office ≤ 2003 (SHA1+RC4)", john: Some("oldoffice") ,hashcat: Some("9800") ,variation: false ,description: None },
          &HashInfo{ name: "Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1", john: Some("oldoffice") ,hashcat: Some("9810") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}:[a-f0-9]{10}"##).unwrap(), modes: vec![
          &HashInfo{ name: "MS Office ⇐ 2003 $3, SHA1 + RC4, collider #2", john: Some("oldoffice") ,hashcat: Some("9820") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$radmin2\$)?[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "RAdmin v2.x", john: Some("radmin") ,hashcat: Some("9900") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SAP CODVN H (PWDSALTEDHASH) iSSHA-1", john: Some("saph") ,hashcat: Some("10300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "CRAM-MD5", john: None ,hashcat: Some("10200") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{16}:2:4:[a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "SipHash", john: None ,hashcat: Some("10100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-f0-9]{4,}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Cisco Type 7", john: None ,hashcat: None ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[a-z0-9\/.]{13,}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "BigCrypt", john: Some("bigcrypt") ,hashcat: None ,variation: true ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$cisco4\$)?[a-z0-9\/.]{43}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Cisco Type 4", john: Some("cisco4") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Django(bcrypt-SHA256)", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PostgreSQL Challenge-Response Authentication (MD5)", john: Some("postgres") ,hashcat: Some("11100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$siemens-s7\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Siemens-S7", john: Some("siemens-s7") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$pst\$)?[a-f0-9]{8}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Microsoft Outlook PST", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^sha256[:$][0-9]+[:$][a-z0-9\/+=]+[:$][a-z0-9\/+]{32,128}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PBKDF2-HMAC-SHA256(PHP)", john: None ,hashcat: Some("10900") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^(\$dahua\$)?[a-z0-9]{8}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Dahua", john: Some("dahua") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "MySQL Challenge-Response Authentication (SHA1)", john: None ,hashcat: Some("11200") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$pdf\$1\*[2|3]\*[0-9]{2}\*[-0-9]{1,6}\*[0-9]\*[0-9]{2}\*[a-f0-9]{32,32}\*[0-9]{2}\*[a-f0-9]{64}\*[0-9]{2}\*[a-f0-9]{64}"##).unwrap(), modes: vec![
          &HashInfo{ name: "PDF 1.1 - 1.3 (Acrobat 2 - 4)", john: Some("pdf") ,hashcat: Some("10400") ,variation: false ,description: None },
          &HashInfo{ name: "PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1", john: Some("pdf") ,hashcat: Some("10410") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$pdf\$1\*[2|3]\*[0-9]{2}\*[-0-9]{1,6}\*[0-9]\*[0-9]{2}\*[a-f0-9]{32}\*[0-9]{2}\*[a-f0-9]{64}\*[0-9]{2}\*[a-f0-9]{64}:[a-f0-9]{10}"##).unwrap(), modes: vec![
          &HashInfo{ name: "PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2", john: None ,hashcat: Some("10420") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PDF 1.4 - 1.6 (Acrobat 5 - 8)", john: Some("pdf") ,hashcat: Some("10500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$pdf\$5\*[5|6]\*[0-9]{3}\*[-0-9]{1,6}\*[0-9]\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}"##).unwrap(), modes: vec![
          &HashInfo{ name: "PDF 1.7 Level 3 (Acrobat 9)", john: Some("pdf") ,hashcat: Some("10600") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$pdf\$5\*[5|6]\*[0-9]{3}\*[-0-9]{1,6}\*[0-9]\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}"##).unwrap(), modes: vec![
          &HashInfo{ name: "PDF 1.7 Level 8 (Acrobat 10 - 11)", john: Some("pdf") ,hashcat: Some("10700") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$krb5asrep\$23\$[^:]+:[a-f0-9]{32,32}\$[a-f0-9]{64,40960}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Kerberos 5 AS-REP etype 23", john: Some("krb5pa-sha1") ,hashcat: Some("18200") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$krb5tgs\$17\$[^$]{1,512}\$[^$]{1,512}\$[^$]{1,4}?\$?[a-f0-9]{1,32}\$[a-f0-9]{64,40960}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96)", john: None ,hashcat: Some("19600") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$krb5tgs\$18\$[^$]{1,512}\$[^$]{1,512}\$[^$]{1,4}?\$?[a-f0-9]{1,32}\$[a-f0-9]{64,40960}"##).unwrap(), modes: vec![
          &HashInfo{ name: "Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96)", john: None ,hashcat: Some("19700") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$krb5pa\$17\$[^$]{1,512}\$[^$]{1,512}\$[a-f0-9]{104,112}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Kerberos 5, etype 17, Pre-Auth", john: None ,hashcat: Some("19800") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$krb5pa\$17\$[^$]{1,512}\$[^$]{1,512}\$[^$]{0,512}\$[a-f0-9]{104,112}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Kerberos 5, etype 17, Pre-Auth (with salt)", john: Some("krb5pa-sha1") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$krb5pa\$18\$[^$]{1,512}\$[^$]{1,512}\$[^$]{0,512}\$[a-f0-9]{104,112}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Kerberos 5, etype 18, Pre-Auth (with salt)", john: Some("krb5pa-sha1") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$krb5pa\$18\$[^$]{1,512}\$[^$]{1,512}\$[a-f0-9]{104,112}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Kerberos 5, etype 18, Pre-Auth", john: None ,hashcat: Some("19900") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$bitcoin\$[0-9]{2,4}\$[a-f0-9$]{250,350}"##).unwrap(), modes: vec![
          &HashInfo{ name: "Bitcoin / Litecoin", john: Some("bitcoin") ,hashcat: Some("11300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$ethereum\$[a-z0-9*]{150,250}"##).unwrap(), modes: vec![
          &HashInfo{ name: "Ethereum Wallet, PBKDF2-HMAC-SHA256", john: Some("ethereum-opencl") ,hashcat: Some("15600") ,variation: false ,description: None },
          &HashInfo{ name: "Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256", john: Some("ethereum-presale-opencl") ,hashcat: Some("16300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$monero\$(0)\*[a-f0-9]{32,3196}"##).unwrap(), modes: vec![
          &HashInfo{ name: "Monero", john: Some("monero") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$electrum\$[1-3]\*[a-f0-9]{32,32}\*[a-f0-9]{32,32}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Electrum Wallet (Salt-Type 1-3)", john: Some("electrum") ,hashcat: Some("16600") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$electrum\$4\*[a-f0-9]{1,66}\*[a-f0-9]{128,32768}\*[a-f0-9]{64,64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Electrum Wallet (Salt-Type 4)", john: Some("electrum") ,hashcat: Some("21700") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$electrum\$5\*[a-f0-9]{66,66}\*[a-f0-9]{2048,2048}\*[a-f0-9]{64,64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Electrum Wallet (Salt-Type 5)", john: Some("electrum") ,hashcat: Some("21800") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$ab\$[0-9]{1}\*[0-9]{1}\*[0-9]{1,6}\*[a-f0-9]{128}\*[a-f0-9]{128}\*[a-f0-9]{32}\*[a-f0-9]{192}"##).unwrap(), modes: vec![
          &HashInfo{ name: "Android Backup", john: Some("androidbackup") ,hashcat: Some("18900") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$zip2\$\*[0-9]{1}\*[0-9]{1}\*[0-9]{1}\*[a-f0-9]{16,32}\*[a-f0-9]{1,6}\*[a-f0-9]{1,6}\*[a-f0-9]+\*[a-f0-9]{20}\*\$\/zip2\$"##).unwrap(), modes: vec![
          &HashInfo{ name: "WinZip", john: Some("zip") ,hashcat: Some("13600") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$itunes_backup\$\*[0-9]{1,2}\*[a-f0-9]{80}\*[0-9]{1,6}\*[a-f0-9]{40}\*[0-9]{0,10}\*[a-f0-9]{0,40}"##).unwrap(), modes: vec![
          &HashInfo{ name: "iTunes backup >= 10.0", john: Some("itunes-backup") ,hashcat: Some("14800") ,variation: false ,description: None },
          &HashInfo{ name: "iTunes backup < 10.0", john: Some("itunes-backup") ,hashcat: Some("14700") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$telegram\$[a-f0-9*]{99}"##).unwrap(), modes: vec![
          &HashInfo{ name: "Telegram Mobile App Passcode (SHA256)", john: Some("Telegram") ,hashcat: Some("22301") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\\$telegram\\$1\\*4000\\*[a-f0-9]{64}\\*[a-f0-9]{576}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Telegram Desktop 1.3.9", john: Some("telegram") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\\$telegram\\$2\\*100000\\*[a-f0-9]{64}\\*[a-f0-9]{576}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Telegram Desktop >= 2.1.14-beta / 2.2.0", john: Some("telegram") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$BLAKE2\$[a-f0-9]{128}"##).unwrap(), modes: vec![
          &HashInfo{ name: "BLAKE2b-512", john: None ,hashcat: Some("600") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$oldoffice\$[a-f0-9*]{100}:[a-f0-9]{10}"##).unwrap(), modes: vec![
          &HashInfo{ name: "MS Office ⇐ 2003 $0/$1, MD5 + RC4, collider #2", john: Some("oldoffice") ,hashcat: Some("9720") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$office\$2016\$[0-9]\$[0-9]{6}\$[^$]{24}\$[^$]{88}"##).unwrap(), modes: vec![
          &HashInfo{ name: "MS Office 2016 - SheetProtection", john: None ,hashcat: Some("25300") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$7z\$[0-9]\$[0-9]{1,2}\$[0-9]{1}\$[^$]{0,64}\$[0-9]{1,2}\$[a-f0-9]{32}\$[0-9]{1,10}\$[0-9]{1,6}\$[0-9]{1,6}\$[a-f0-9]{2,}"##).unwrap(), modes: vec![
          &HashInfo{ name: "7-zip", john: Some("7z") ,hashcat: Some("11600") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$zip3\$\*[0-9]\*[0-9]\*256\*[0-9]\*[a-f0-9]{0,32}\*[a-f0-9]{288}\*[0-9]\*[0-9]\*[0-9]\*[^\s]{0,64}"##).unwrap(), modes: vec![
          &HashInfo{ name: "SecureZIP AES-256", john: Some("securezip") ,hashcat: Some("23003") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$zip3\$\*[0-9]\*[0-9]\*192\*[0-9]\*[a-f0-9]{0,32}\*[a-f0-9]{288}\*[0-9]\*[0-9]\*[0-9]\*[^\s]{0,64}"##).unwrap(), modes: vec![
          &HashInfo{ name: "SecureZIP AES-192", john: Some("securezip") ,hashcat: Some("23002") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$zip3\$\*[0-9]\*[0-9]\*128\*[0-9]\*[a-f0-9]{0,32}\*[a-f0-9]{288}\*[0-9]\*[0-9]\*[0-9]\*[^\s]{0,64}"##).unwrap(), modes: vec![
          &HashInfo{ name: "SecureZIP AES-128", john: Some("securezip") ,hashcat: Some("23001") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$pkzip2?\$(1)\*[0-9]{1}\*[0-9]{1}\*[0-9a-f]{1,3}\*[0-9a-f]{1,8}\*[0-9a-f]{1,4}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*(8)\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PKZIP (Compressed)", john: Some("pkzip") ,hashcat: Some("17200") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$pkzip2?\$(1)\*[0-9]{1}\*[0-9]{1}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*(0)\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PKZIP (Uncompressed)", john: Some("pkzip") ,hashcat: Some("17210") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$pkzip2?\$([2-8])\*[0-9]{1}(\*[0-9]{1}\*[0-9a-f]{1,3}\*([^0*][0-9a-f]{0,2})\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[0-9a-f]+)+\*(8)\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PKZIP (Compressed Multi-File)", john: Some("pkzip") ,hashcat: Some("17220") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$pkzip2?\$([2-8])\*[0-9]{1}(\*[0-9]{1}\*[0-9a-f]{1,8}\*([0-9a-f]{1,8})\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[0-9a-f]+)+\*([08])\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PKZIP (Mixed Multi-File)", john: Some("pkzip") ,hashcat: Some("17225") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$pkzip2?\$([2-8])\*[0-9]{1}(\*[0-9]{1}\*[0-9a-f]{1,3}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[0-9a-f]+)+\*\$\/pkzip2?\$$"##).unwrap(), modes: vec![
          &HashInfo{ name: "PKZIP (Mixed Multi-File Checksum-Only)", john: Some("pkzip") ,hashcat: Some("17230") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$argon2i\$v=19\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\$[^$]+\$[^\s]{6,134}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Argon2i", john: Some("argon2") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$argon2id\$v=19\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\$[^$]+\$[^\s]{6,134}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Argon2id", john: None ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$argon2d\$v=19\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\$[^$]+\$[^\s]{6,134}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Argon2d", john: Some("argon2") ,hashcat: None ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$bitlocker\$[0-9]\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{7}\$[a-f0-9]{2}\$[a-f0-9]{24}\$[a-f0-9]{2}\$[a-f0-9]{120}"##).unwrap(), modes: vec![
          &HashInfo{ name: "BitLocker", john: Some("bitlocker") ,hashcat: Some("22100") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)\$racf\$\*.{1,}\*[A-F0-9]{16}"##).unwrap(), modes: vec![
          &HashInfo{ name: "RACF", john: None ,hashcat: Some("8500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$sshng\$4\$16\$[0-9]{32}\$1232\$[a-f0-9]{2464}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "RSA/DSA/EC/OpenSSH Private Keys ($4$)", john: None ,hashcat: Some("22941") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$RAR3\$\*(1)\*[0-9a-f]{1,16}\*[0-9a-f]{1,8}\*[0-9a-f]{1,16}\*[0-9a-f]{1,16}\*[01]\*([0-9a-f]+|[^*]{1,64}\*[0-9a-f]{1,16})\*30$"##).unwrap(), modes: vec![
          &HashInfo{ name: "RAR3-p (Uncompressed)", john: Some("rar") ,hashcat: Some("23700") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$RAR3\$\*(1)\*[0-9a-f]{1,16}\*[0-9a-f]{1,8}\*[0-9a-f]{1,16}\*[0-9a-f]{1,16}\*[01]\*([0-9a-f]+|[^*]{1,64}\*[0-9a-f]{1,16})\*(31|32|33|34|35)$"##).unwrap(), modes: vec![
          &HashInfo{ name: "RAR3-p (Compressed)", john: Some("rar") ,hashcat: Some("23800") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$RAR3\$\*0\*[0-9a-f]{1,16}\*[0-9a-f]+$"##).unwrap(), modes: vec![
          &HashInfo{ name: "RAR3-hp", john: Some("rar") ,hashcat: Some("12500") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$rar5\$[0-9a-f]{1,2}\$[0-9a-f]{1,32}\$[0-9a-f]{1,2}\$[0-9a-f]{1,32}\$[0-9a-f]{1,2}\$[0-9a-f]{1,16}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "RAR5", john: Some("rar5") ,hashcat: Some("13000") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$keepass\$\*1\*\d+\*\d\*[0-9a-f]{32}\*[0-9a-f]{64}\*[0-9a-f]{32}\*[0-9a-f]{64}\*\d\*[^*]*(\*[0-9a-f]+)?$"##).unwrap(), modes: vec![
          &HashInfo{ name: "KeePass 1 AES (without keyfile)", john: Some("KeePass") ,hashcat: Some("13400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$keepass\$\*1\*\d+\*\d\*[0-9a-f]{32}\*[0-9a-f]{64}\*[0-9a-f]{32}\*[0-9a-f]{64}\*\d\*[^*]*(\*[0-9a-f]+)?\*\d+\*\d+\*[0-9a-f]{64}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "KeePass 1 TwoFish (with keyfile)", john: Some("KeePass") ,hashcat: Some("13400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$keepass\$\*2\*\d+\*\d+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+$"##).unwrap(), modes: vec![
          &HashInfo{ name: "KeePass 2 AES (without keyfile)", john: Some("KeePass") ,hashcat: Some("13400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$keepass\$\*2\*\d+\*\d+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*\d+\*\d+\*[0-9a-f]+$"##).unwrap(), modes: vec![
          &HashInfo{ name: "KeePass 2 AES (with keyfile)", john: Some("KeePass") ,hashcat: Some("13400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^\$odf\$\*1\*1\*100000\*32\*[a-f0-9]{64}\*16\*[a-f0-9]{32}\*16\*[a-f0-9]{32}\*0\*[a-f0-9]{2048}$"##).unwrap(), modes: vec![
          &HashInfo{ name: "Open Document Format (ODF) 1.2 (SHA-256, AES)", john: None ,hashcat: Some("18400") ,variation: false ,description: None },
]},
     Pattern { regex: Regex::new(r##"(?i)^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$"##).unwrap(), modes: vec![
          &HashInfo{ name: "JWT (JSON Web Token)", john: None ,hashcat: Some("16500") ,variation: false ,description: None },
]}];
    let popular: Vec<&'static str> = vec![
        "MD5",
        "MD4",
        "NTLM",
        "SHA-256",
        "SHA-512",
        "Keccak-256",
        "Keccak-512",
        "Blake2",
        "bcrypt",
        "SHA-1",
        "HMAC-SHA1 (key = $salt)",
        "CryptoCurrency(PrivateKey)",
        "SHA-338",
        "Domain Cached Credentials",
        "Domain Cached Credentials 2",
    ];
    let hash_identifer = HashIdentifier::new(pattern,popular);
    let possibilities = hash_identifer.match_pattern(&args.hash);
    output_results(possibilities);
}
