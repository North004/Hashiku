use regex::Regex;

pub struct HashIdentifier {
    patterns: Vec<(Regex, &'static str)>,
}

impl Default for HashIdentifier {
    fn default() -> Self {
        Self::new()
    }
}
impl HashIdentifier {
    pub fn new() -> Self {
        let patterns = vec![
            (Regex::new(r"^[a-fA-F0-9]{4}$").unwrap(), "CRC16"),
            (Regex::new(r"^[a-fA-F0-9]{4}$").unwrap(), "CRC16CCITT"),
            (Regex::new(r"^[a-fA-F0-9]{4}$").unwrap(), "FCS16"),
            (Regex::new(r"^[a-fA-F0-9]{8}$").unwrap(), "CRC32"),
            (Regex::new(r"^[a-fA-F0-9]{8}$").unwrap(), "ADLER32"),
            (Regex::new(r"^[a-fA-F0-9]{8}$").unwrap(), "CRC32B"),
            (Regex::new(r"^[a-fA-F0-9]{8}$").unwrap(), "XOR32"),
            (Regex::new(r"^[0-9]{8}$").unwrap(), "GHash323"),
            (Regex::new(r"^[0-9]{8}$").unwrap(), "GHash325"),
            (Regex::new(r"^[a-zA-Z0-9+/=]{13,}").unwrap(), "DESUnix"),
            (Regex::new(r"^[a-fA-F0-9]{16}$").unwrap(), "MD5Half"),
            (Regex::new(r"^[a-fA-F0-9]{16}$").unwrap(), "MD5Middle"),
            (Regex::new(r"^[a-fA-F0-9]{16}$").unwrap(), "MySQL"),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "DomainCachedCredentials",
            ),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "Haval128"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "Haval128HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "MD2"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "MD2HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "MD4"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "MD4HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "MD5"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "MD5HMAC"),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "MD5HMACWordpress",
            ),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "NTLM"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "RAdminv2x"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "RipeMD128"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "RipeMD128HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "SNEFRU128"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "SNEFRU128HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "Tiger128"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "Tiger128HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5passsalt"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5saltmd5pass"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5saltpass"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5saltpasssalt"),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5saltpassusername",
            ),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5saltmd5pass"),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5saltmd5passsalt",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5saltmd5passsalt",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5saltmd5saltpass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5saltmd5md5passsalt",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5username0pass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5usernameLFpass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5usernamemd5passsalt",
            ),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5md5pass"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5md5passsalt"),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5md5passmd5salt",
            ),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5md5saltpass"),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5md5saltmd5pass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5md5usernamepasssalt",
            ),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5md5md5pass"),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5md5md5md5pass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5md5md5md5md5pass",
            ),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5sha1pass"),
            (Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(), "md5sha1md5pass"),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5sha1md5sha1pass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                "md5strtouppermd5pass",
            ),
            (Regex::new(r"^0x[a-fA-F0-9]{32}$").unwrap(), "LineageIIC4"),
            (Regex::new(r"^\$H\$.{8,32}$").unwrap(), "MD5phpBB3"),
            (Regex::new(r"^\$1\$.{8,32}$").unwrap(), "MD5Unix"),
            (Regex::new(r"^\$P\$.{8,32}$").unwrap(), "MD5Wordpress"),
            (Regex::new(r"^\$apr1\$.{8,32}$").unwrap(), "MD5APR"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "Haval160"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "Haval160HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "MySQL5"),
            (Regex::new(r"^\*[a-fA-F0-9]{40}$").unwrap(), "MySQL160bit"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "RipeMD160"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "RipeMD160HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "SHA1"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "SHA1HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "SHA1MaNGOS"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "SHA1MaNGOS2"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "Tiger160"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "Tiger160HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "sha1passsalt"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "sha1saltpass"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "sha1saltmd5pass"),
            (
                Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                "sha1saltmd5passsalt",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                "sha1saltsha1pass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                "sha1saltsha1saltsha1pass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                "sha1usernamepass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                "sha1usernamepasssalt",
            ),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "sha1md5pass"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "sha1md5passsalt"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "sha1md5sha1pass"),
            (Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(), "sha1sha1pass"),
            (
                Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                "sha1sha1passsalt",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                "sha1sha1passsubstrpass03",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                "sha1sha1saltpass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                "sha1sha1sha1pass",
            ),
            (
                Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                "sha1strtolowerusernamepass",
            ),
            (Regex::new(r"^[a-fA-F0-9]{56}$").unwrap(), "Haval192"),
            (Regex::new(r"^[a-fA-F0-9]{56}$").unwrap(), "Haval192HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{56}$").unwrap(), "Tiger192"),
            (Regex::new(r"^[a-fA-F0-9]{56}$").unwrap(), "Tiger192HMAC"),
            (
                Regex::new(r"^[a-fA-F0-9]{32}:[A-Za-z0-9+/=]+$").unwrap(),
                "MD5passsaltjoomla1",
            ),
            (
                Regex::new(r"^sha1\$[A-Za-z0-9]+\$[a-fA-F0-9]{40}$").unwrap(),
                "SHA1Django",
            ),
            (Regex::new(r"^[a-fA-F0-9]{56}$").unwrap(), "Haval224"),
            (Regex::new(r"^[a-fA-F0-9]{56}$").unwrap(), "Haval224HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{56}$").unwrap(), "SHA224"),
            (Regex::new(r"^[a-fA-F0-9]{56}$").unwrap(), "SHA224HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "SHA256"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "SHA256HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "Haval256"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "Haval256HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "GOSTR341194"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "RipeMD256"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "RipeMD256HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "SNEFRU256"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "SNEFRU256HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "SHA256md5pass"),
            (Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(), "SHA256sha1pass"),
            (
                Regex::new(r"^[a-fA-F0-9]{32}:[A-Za-z0-9+/=]+$").unwrap(),
                "MD5passsaltjoomla2",
            ),
            (Regex::new(r"^[A-F0-9]{32}:[A-F0-9]{32}$").unwrap(), "SAM"),
            (
                Regex::new(r"^sha256\$[A-Za-z0-9]+\$[a-fA-F0-9]{64}$").unwrap(),
                "SHA256Django",
            ),
            (Regex::new(r"^[a-fA-F0-9]{80}$").unwrap(), "RipeMD320"),
            (Regex::new(r"^[a-fA-F0-9]{80}$").unwrap(), "RipeMD320HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{96}$").unwrap(), "SHA384"),
            (Regex::new(r"^[a-fA-F0-9]{96}$").unwrap(), "SHA384HMAC"),
            (
                Regex::new(r"^\$6\$.{8}\$[A-Za-z0-9./]{22,43}$").unwrap(),
                "SHA256s",
            ),
            (
                Regex::new(r"^sha384\$[A-Za-z0-9]+\$[a-fA-F0-9]{96}$").unwrap(),
                "SHA384Django",
            ),
            (Regex::new(r"^[a-fA-F0-9]{128}$").unwrap(), "SHA512"),
            (Regex::new(r"^[a-fA-F0-9]{128}$").unwrap(), "SHA512HMAC"),
            (Regex::new(r"^[a-fA-F0-9]{128}$").unwrap(), "Whirlpool"),
            (Regex::new(r"^[a-fA-F0-9]{128}$").unwrap(), "WhirlpoolHMAC"),
        ];
        Self { patterns }
    }

    pub fn identify_hash(&self, input: &str) -> Vec<&'static str> {
        self.patterns
            .iter()
            .filter_map(|(regex, name)| {
                if regex.is_match(input) {
                    Some(*name)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn add_pattern(&mut self, regex: &str, name: &'static str) {
        if let Ok(re) = Regex::new(regex) {
            self.patterns.push((re, name));
        }
    }
}

fn main() {
    let identifier = HashIdentifier::new();
    let matches = identifier.identify_hash("d41d8cd98f00b204e9800998ecf8427e");
    println!("{:?}", matches);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_identify_hash() {
        let identifier = HashIdentifier::new();
        assert_eq!(
            identifier.identify_hash("5d41402abc4b2a76b9719d911017c592"),
            vec!["MD5"]
        );
        assert_eq!(
            identifier.identify_hash("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"),
            vec!["SHA-1"]
        );
        assert!(identifier.identify_hash("invalidhash").is_empty());
    }

    #[test]
    fn test_add_pattern() {
        let mut identifier = HashIdentifier::new();
        identifier.add_pattern(r"^[0-9a-f]{40}$", "CustomHash");
        assert_eq!(
            identifier.identify_hash("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"),
            vec!["SHA-1", "CustomHash"]
        );
    }
}
