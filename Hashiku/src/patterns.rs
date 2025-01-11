use pcre2::bytes::{Regex,RegexBuilder};
use once_cell::sync::Lazy;

fn regex_no_u(pattern: &str, case_insensitive: bool) -> Regex {
    RegexBuilder::new().ucp(false).utf(true).caseless(case_insensitive).build(pattern).unwrap()
}

static PATTERN0 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{4}$"##,true));
static PATTERN1 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{8}$"##,true));
static PATTERN2 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{6}$"##,true));
static PATTERN3 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$crc32\$)?([a-f0-9]{8}.)?[a-f0-9]{8}$"##,true));
static PATTERN4 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\+[a-z0-9\/.]{12}$"##,true));
static PATTERN5 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9\/.]{12}[.26AEIMQUYcgkosw]{1}$"##,true));
static PATTERN6 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{16}$"##,true));
static PATTERN7 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{16}:[a-f0-9]{0,30}$"##,true));
static PATTERN8 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9\/.]{16}$"##,true));
static PATTERN9 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\([a-z0-9\/+]{20}\)$"##,true));
static PATTERN10 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^_[a-z0-9\/.]{19}$"##,true));
static PATTERN11 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{24}$"##,true));
static PATTERN12 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$keepass\$\*1\*50000\*(0|1)\*([a-f0-9]{32})\*([a-f0-9]{64})\*([a-f0-9]{32})\*([a-f0-9]{64})\*1\*(192|1360)\*([a-f0-9]{384})$"##,false));
static PATTERN13 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$keepass\$\*1\*6000\*(0|1)\*([a-f0-9]{32})\*([a-f0-9]{64})\*([a-f0-9]{32})\*([a-f0-9]{64})\*1\*(192|1360)\*([a-f0-9]{2720})\*1\*64\*([a-f0-9]{64})$"##,false));
static PATTERN14 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$keepass\$\*2\*6000\*222(\*[a-f0-9]{64}){2}(\*[a-f0-9]{32}){1}(\*[a-f0-9]{64}){2}\*1\*64(\*[a-f0-9]{64}){1}$"##,false));
static PATTERN15 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$keepass\$\*2\*6000\*222\*(([a-f0-9]{32,64})(\*)?)+$"##,false));
static PATTERN16 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9\/.]{24}$"##,true));
static PATTERN17 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}$"##,true));
static PATTERN18 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"(?:\$haval\$)?[a-f0-9]{32,64}$"##,true));
static PATTERN19 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"(?:\$ripemd\$)?[a-f0-9]{32,40}$"##,true));
static PATTERN20 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{16}$"##,true));
static PATTERN21 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"(?:\$dynamic_39\$)?[a-f0-9]{32}\$[a-z0-9]{1,32}\$?[a-z0-9]{1,500}"##,true));
static PATTERN22 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}:[a-z0-9]+$"##,true));
static PATTERN23 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}:[a-z0-9]{56}$"##,true));
static PATTERN24 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$md2\$)?[a-f0-9]{32}$"##,true));
static PATTERN25 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$snefru\$)?[a-f0-9]{32}$"##,true));
static PATTERN26 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$NT\$)?[a-f0-9]{32}$"##,true));
static PATTERN27 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$"##,true));
static PATTERN28 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$"##,true));
static PATTERN29 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\{SHA}[a-z0-9\/+]{27}=$"##,true));
static PATTERN30 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$"##,true));
static PATTERN31 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^0x[a-f0-9]{32}$"##,true));
static PATTERN32 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$H\$[a-z0-9\/.]{31}$"##,true));
static PATTERN33 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$P\$[a-z0-9\/.]{31}$"##,true));
static PATTERN34 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}:[a-z0-9]{2}$"##,true));
static PATTERN35 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$"##,true));
static PATTERN36 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\{smd5}[a-z0-9$\/.]{31}$"##,true));
static PATTERN37 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}:.{5}$"##,true));
static PATTERN38 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}:.{8}$"##,true));
static PATTERN39 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9]{34}$"##,true));
static PATTERN40 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{40}(:.+)?$"##,true));
static PATTERN41 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{40}$"##,true));
static PATTERN42 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9]{43}$"##,true));
static PATTERN43 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\{SSHA}[a-z0-9\/+]{38}==$"##,true));
static PATTERN44 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9=]{47}$"##,true));
static PATTERN45 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{48}$"##,true));
static PATTERN46 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{51}$"##,true));
static PATTERN47 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9]{51}$"##,true));
static PATTERN48 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}$"##,true));
static PATTERN49 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^0x0100[a-f0-9]{48}$"##,true));
static PATTERN50 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$"##,true));
static PATTERN51 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{56}$"##,true));
static PATTERN52 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$2[abxy]?|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$"##,true));
static PATTERN53 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$y\$[.\/A-Za-z0-9]+\$[.\/a-zA-Z0-9]+\$[.\/A-Za-z0-9]{43}$"##,true));
static PATTERN54 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{40}:[a-f0-9]{16}$"##,true));
static PATTERN55 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$"##,true));
static PATTERN56 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$"##,true));
static PATTERN57 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}:.{3}$"##,true));
static PATTERN58 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}:.{30}$"##,true));
static PATTERN59 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$snefru\$)?[a-f0-9]{64}$"##,true));
static PATTERN60 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{64}(:.+)?$"##,true));
static PATTERN61 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}:[a-z0-9]{32}$"##,true));
static PATTERN62 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}:[a-f0-9]{32}$"##,true));
static PATTERN63 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$"##,true));
static PATTERN64 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$"##,true));
static PATTERN65 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}$"##,true));
static PATTERN66 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{80}$"##,true));
static PATTERN67 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$"##,true));
static PATTERN68 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^0x0100[a-f0-9]{88}$"##,true));
static PATTERN69 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{96}$"##,true));
static PATTERN70 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\{SSHA512}[a-z0-9\/+]{96}$"##,true));
static PATTERN71 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$"##,true));
static PATTERN72 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{128}(:.+)?$"##,true));
static PATTERN73 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{64}$"##,true));
static PATTERN74 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{96}$"##,true));
static PATTERN75 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{136}$"##,true));
static PATTERN76 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^0x0200[a-f0-9]{136}$"##,true));
static PATTERN77 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$"##,true));
static PATTERN78 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{256}$"##,true));
static PATTERN79 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$"##,true));
static PATTERN80 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^sha1\$[a-z0-9]+\$[a-f0-9]{40}$"##,true));
static PATTERN81 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{49}$"##,true));
static PATTERN82 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$S\$[a-z0-9\/.]{52}$"##,true));
static PATTERN83 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$"##,true));
static PATTERN84 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$"##,true));
static PATTERN85 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$"##,true));
static PATTERN86 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$"##,true));
static PATTERN87 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^sha256\$[a-z0-9]+\$[a-f0-9]{64}$"##,true));
static PATTERN88 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^sha384\$[a-z0-9]+\$[a-f0-9]{96}$"##,true));
static PATTERN89 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$"##,true));
static PATTERN90 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{112}$"##,true));
static PATTERN91 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{1329}$"##,true));
static PATTERN92 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$"##,true));
static PATTERN93 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$"##,true));
static PATTERN94 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$(krb5pa|mskrb5)\$(23)?\$.+\$[a-f0-9]{1,}$"##,true));
static PATTERN95 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$"##,true));
static PATTERN96 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{40}:[a-f0-9]{0,32}$"##,true));
static PATTERN97 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^([^$]+)?\$[a-f0-9]{16}$"##,true));
static PATTERN98 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(.+)?\$[a-f0-9]{40}$"##,true));
static PATTERN99 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$"##,true));
static PATTERN100 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^0x(?:[a-f0-9]{60}|[a-f0-9]{40})$"##,true));
static PATTERN101 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{40}:[^*]{1,25}$"##,true));
static PATTERN102 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$"##,true));
static PATTERN103 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{130}(:[a-f0-9]{40})?$"##,true));
static PATTERN104 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$"##,true));
static PATTERN105 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9\/.]{16}([:$].{1,})?$"##,true));
static PATTERN106 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$"##,true));
static PATTERN107 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$"##,true));
static PATTERN108 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$"##,true));
static PATTERN109 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$3\$\$[a-f0-9]{32}$"##,true));
static PATTERN110 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$"##,true));
static PATTERN111 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{70}$"##,true));
static PATTERN112 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$"##,true));
static PATTERN113 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{140}$"##,true));
static PATTERN114 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$"##,true));
static PATTERN115 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$"##,true));
static PATTERN116 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$"##,true));
static PATTERN117 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$"##,true));
static PATTERN118 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$"##,true));
static PATTERN119 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$"##,true));
static PATTERN120 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$PHPS\$.+\$[a-f0-9]{32}$"##,true));
static PATTERN121 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$"##,true));
static PATTERN122 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$"##,true));
static PATTERN123 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$"##,true));
static PATTERN124 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$"##,true));
static PATTERN125 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9\/+]{27}=$"##,true));
static PATTERN126 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$"##,true));
static PATTERN127 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$"##,true));
static PATTERN128 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$"##,true));
static PATTERN129 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$"##,true));
static PATTERN130 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^md5\$[a-f0-9]+\$[a-f0-9]{32}$"##,true));
static PATTERN131 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\{PKCS5S2\}[a-z0-9\/+]{64}$"##,true));
static PATTERN132 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^md5[a-f0-9]{32}$"##,true));
static PATTERN133 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\([a-z0-9\/+]{49}\)$"##,true));
static PATTERN134 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$"##,true));
static PATTERN135 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$"##,true));
static PATTERN136 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$"##,true));
static PATTERN137 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$"##,true));
static PATTERN138 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$"##,true));
static PATTERN139 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\\$office\\$2016\\$[0-9]\\$[0-9]{6}\\$[^$]{24}\\$[^$]{88}$"##,true));
static PATTERN140 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$"##,true));
static PATTERN141 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$"##,true));
static PATTERN142 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$krb5tgs\$23\$\*[^*]*\*\$[a-f0-9]{32}\$[a-f0-9]{64,40960}"##,true));
static PATTERN143 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$"##,true));
static PATTERN144 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$"##,true));
static PATTERN145 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}:[a-f0-9]{10}"##,true));
static PATTERN146 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$radmin2\$)?[a-f0-9]{32}$"##,true));
static PATTERN147 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+$"##,true));
static PATTERN148 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$"##,true));
static PATTERN149 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{16}:2:4:[a-f0-9]{32}$"##,true));
static PATTERN150 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-f0-9]{4,}$"##,true));
static PATTERN151 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[a-z0-9\/.]{13,}$"##,true));
static PATTERN152 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$cisco4\$)?[a-z0-9\/.]{43}$"##,true));
static PATTERN153 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$"##,true));
static PATTERN154 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$"##,true));
static PATTERN155 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$siemens-s7\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$"##,true));
static PATTERN156 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$pst\$)?[a-f0-9]{8}$"##,true));
static PATTERN157 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^sha256[:$][0-9]+[:$][a-z0-9\/+=]+[:$][a-z0-9\/+]{32,128}$"##,true));
static PATTERN158 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^(\$dahua\$)?[a-z0-9]{8}$"##,true));
static PATTERN159 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$"##,true));
static PATTERN160 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$pdf\$1\*[2|3]\*[0-9]{2}\*[-0-9]{1,6}\*[0-9]\*[0-9]{2}\*[a-f0-9]{32,32}\*[0-9]{2}\*[a-f0-9]{64}\*[0-9]{2}\*[a-f0-9]{64}"##,true));
static PATTERN161 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$pdf\$1\*[2|3]\*[0-9]{2}\*[-0-9]{1,6}\*[0-9]\*[0-9]{2}\*[a-f0-9]{32}\*[0-9]{2}\*[a-f0-9]{64}\*[0-9]{2}\*[a-f0-9]{64}:[a-f0-9]{10}"##,true));
static PATTERN162 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$"##,true));
static PATTERN163 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$pdf\$5\*[5|6]\*[0-9]{3}\*[-0-9]{1,6}\*[0-9]\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}"##,true));
static PATTERN164 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$pdf\$5\*[5|6]\*[0-9]{3}\*[-0-9]{1,6}\*[0-9]\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}"##,true));
static PATTERN165 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$krb5asrep\$23\$[^:]+:[a-f0-9]{32,32}\$[a-f0-9]{64,40960}$"##,true));
static PATTERN166 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$krb5tgs\$17\$[^$]{1,512}\$[^$]{1,512}\$[^$]{1,4}?\$?[a-f0-9]{1,32}\$[a-f0-9]{64,40960}$"##,true));
static PATTERN167 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$krb5tgs\$18\$[^$]{1,512}\$[^$]{1,512}\$[^$]{1,4}?\$?[a-f0-9]{1,32}\$[a-f0-9]{64,40960}"##,true));
static PATTERN168 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$krb5pa\$17\$[^$]{1,512}\$[^$]{1,512}\$[a-f0-9]{104,112}$"##,true));
static PATTERN169 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$krb5pa\$17\$[^$]{1,512}\$[^$]{1,512}\$[^$]{0,512}\$[a-f0-9]{104,112}$"##,true));
static PATTERN170 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$krb5pa\$18\$[^$]{1,512}\$[^$]{1,512}\$[^$]{0,512}\$[a-f0-9]{104,112}$"##,true));
static PATTERN171 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$krb5pa\$18\$[^$]{1,512}\$[^$]{1,512}\$[a-f0-9]{104,112}$"##,true));
static PATTERN172 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$bitcoin\$[0-9]{2,4}\$[a-f0-9$]{250,350}"##,true));
static PATTERN173 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$ethereum\$[a-z0-9*]{150,250}"##,true));
static PATTERN174 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$monero\$(0)\*[a-f0-9]{32,3196}"##,true));
static PATTERN175 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$electrum\$[1-3]\*[a-f0-9]{32,32}\*[a-f0-9]{32,32}$"##,true));
static PATTERN176 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$electrum\$4\*[a-f0-9]{1,66}\*[a-f0-9]{128,32768}\*[a-f0-9]{64,64}$"##,true));
static PATTERN177 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$electrum\$5\*[a-f0-9]{66,66}\*[a-f0-9]{2048,2048}\*[a-f0-9]{64,64}$"##,true));
static PATTERN178 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$ab\$[0-9]{1}\*[0-9]{1}\*[0-9]{1,6}\*[a-f0-9]{128}\*[a-f0-9]{128}\*[a-f0-9]{32}\*[a-f0-9]{192}"##,true));
static PATTERN179 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$zip2\$\*[0-9]{1}\*[0-9]{1}\*[0-9]{1}\*[a-f0-9]{16,32}\*[a-f0-9]{1,6}\*[a-f0-9]{1,6}\*[a-f0-9]+\*[a-f0-9]{20}\*\$\/zip2\$"##,true));
static PATTERN180 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$itunes_backup\$\*[0-9]{1,2}\*[a-f0-9]{80}\*[0-9]{1,6}\*[a-f0-9]{40}\*[0-9]{0,10}\*[a-f0-9]{0,40}"##,true));
static PATTERN181 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$telegram\$[a-f0-9*]{99}"##,true));
static PATTERN182 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\\$telegram\\$1\\*4000\\*[a-f0-9]{64}\\*[a-f0-9]{576}$"##,true));
static PATTERN183 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\\$telegram\\$2\\*100000\\*[a-f0-9]{64}\\*[a-f0-9]{576}$"##,true));
static PATTERN184 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$BLAKE2\$[a-f0-9]{128}"##,true));
static PATTERN185 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$oldoffice\$[a-f0-9*]{100}:[a-f0-9]{10}"##,true));
static PATTERN186 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$office\$2016\$[0-9]\$[0-9]{6}\$[^$]{24}\$[^$]{88}"##,true));
static PATTERN187 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$7z\$[0-9]\$[0-9]{1,2}\$[0-9]{1}\$[^$]{0,64}\$[0-9]{1,2}\$[a-f0-9]{32}\$[0-9]{1,10}\$[0-9]{1,6}\$[0-9]{1,6}\$[a-f0-9]{2,}"##,true));
static PATTERN188 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$zip3\$\*[0-9]\*[0-9]\*256\*[0-9]\*[a-f0-9]{0,32}\*[a-f0-9]{288}\*[0-9]\*[0-9]\*[0-9]\*[^\s]{0,64}"##,true));
static PATTERN189 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$zip3\$\*[0-9]\*[0-9]\*192\*[0-9]\*[a-f0-9]{0,32}\*[a-f0-9]{288}\*[0-9]\*[0-9]\*[0-9]\*[^\s]{0,64}"##,true));
static PATTERN190 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$zip3\$\*[0-9]\*[0-9]\*128\*[0-9]\*[a-f0-9]{0,32}\*[a-f0-9]{288}\*[0-9]\*[0-9]\*[0-9]\*[^\s]{0,64}"##,true));
static PATTERN191 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$pkzip2?\$(1)\*[0-9]{1}\*[0-9]{1}\*[0-9a-f]{1,3}\*[0-9a-f]{1,8}\*[0-9a-f]{1,4}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*(8)\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$"##,true));
static PATTERN192 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$pkzip2?\$(1)\*[0-9]{1}\*[0-9]{1}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*(0)\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$"##,true));
static PATTERN193 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$pkzip2?\$([2-8])\*[0-9]{1}(\*[0-9]{1}\*[0-9a-f]{1,3}\*([^0*][0-9a-f]{0,2})\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[0-9a-f]+)+\*(8)\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$"##,true));
static PATTERN194 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$pkzip2?\$([2-8])\*[0-9]{1}(\*[0-9]{1}\*[0-9a-f]{1,8}\*([0-9a-f]{1,8})\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[0-9a-f]+)+\*([08])\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$"##,true));
static PATTERN195 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$pkzip2?\$([2-8])\*[0-9]{1}(\*[0-9]{1}\*[0-9a-f]{1,3}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[0-9a-f]+)+\*\$\/pkzip2?\$$"##,true));
static PATTERN196 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$argon2i\$v=19\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\$[^$]+\$[^\s]{6,134}$"##,true));
static PATTERN197 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$argon2id\$v=19\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\$[^$]+\$[^\s]{6,134}$"##,true));
static PATTERN198 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$argon2d\$v=19\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\$[^$]+\$[^\s]{6,134}$"##,true));
static PATTERN199 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$bitlocker\$[0-9]\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{7}\$[a-f0-9]{2}\$[a-f0-9]{24}\$[a-f0-9]{2}\$[a-f0-9]{120}"##,true));
static PATTERN200 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"\$racf\$\*.{1,}\*[A-F0-9]{16}"##,true));
static PATTERN201 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$sshng\$4\$16\$[0-9]{32}\$1232\$[a-f0-9]{2464}$"##,true));
static PATTERN202 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$RAR3\$\*(1)\*[0-9a-f]{1,16}\*[0-9a-f]{1,8}\*[0-9a-f]{1,16}\*[0-9a-f]{1,16}\*[01]\*([0-9a-f]+|[^*]{1,64}\*[0-9a-f]{1,16})\*30$"##,true));
static PATTERN203 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$RAR3\$\*(1)\*[0-9a-f]{1,16}\*[0-9a-f]{1,8}\*[0-9a-f]{1,16}\*[0-9a-f]{1,16}\*[01]\*([0-9a-f]+|[^*]{1,64}\*[0-9a-f]{1,16})\*(31|32|33|34|35)$"##,true));
static PATTERN204 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$RAR3\$\*0\*[0-9a-f]{1,16}\*[0-9a-f]+$"##,true));
static PATTERN205 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$rar5\$[0-9a-f]{1,2}\$[0-9a-f]{1,32}\$[0-9a-f]{1,2}\$[0-9a-f]{1,32}\$[0-9a-f]{1,2}\$[0-9a-f]{1,16}$"##,true));
static PATTERN206 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$keepass\$\*1\*\d+\*\d\*[0-9a-f]{32}\*[0-9a-f]{64}\*[0-9a-f]{32}\*[0-9a-f]{64}\*\d\*[^*]*(\*[0-9a-f]+)?$"##,true));
static PATTERN207 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$keepass\$\*1\*\d+\*\d\*[0-9a-f]{32}\*[0-9a-f]{64}\*[0-9a-f]{32}\*[0-9a-f]{64}\*\d\*[^*]*(\*[0-9a-f]+)?\*\d+\*\d+\*[0-9a-f]{64}$"##,true));
static PATTERN208 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$keepass\$\*2\*\d+\*\d+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+$"##,true));
static PATTERN209 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$keepass\$\*2\*\d+\*\d+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*\d+\*\d+\*[0-9a-f]+$"##,true));
static PATTERN210 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^\$odf\$\*1\*1\*100000\*32\*[a-f0-9]{64}\*16\*[a-f0-9]{32}\*16\*[a-f0-9]{32}\*0\*[a-f0-9]{2048}$"##,true));
static PATTERN211 : Lazy<Regex> = Lazy::new(|| regex_no_u(r##"^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$"##,true));

pub static PATTERNS : Lazy<Vec<Pattern>> = Lazy::new(|| vec![
        Pattern { regex: &*PATTERN0, modes: vec![
                HashInfo{ name: "CRC-16", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "CRC-16-CCITT", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "FCS-16", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN1, modes: vec![
                HashInfo{ name: "Adler-32", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "CRC-32B", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "FCS-32", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "GHash-32-3", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "GHash-32-5", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "FNV-132", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Fletcher-32", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Joaat", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "ELF-32", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "XOR-32", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN2, modes: vec![
                HashInfo{ name: "CRC-24", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN3, modes: vec![
                HashInfo{ name: "CRC-32", john: Some("crc32") ,hashcat: Some("11500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN4, modes: vec![
                HashInfo{ name: "Eggdrop IRC Bot", john: Some("bfegg") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN5, modes: vec![
                HashInfo{ name: "DES(Unix)", john: Some("descrypt") ,hashcat: Some("1500") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Traditional DES", john: Some("descrypt") ,hashcat: Some("1500") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "DEScrypt", john: Some("descrypt") ,hashcat: Some("1500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN6, modes: vec![
                HashInfo{ name: "MySQL323", john: Some("mysql") ,hashcat: Some("200") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Half MD5", john: None ,hashcat: Some("5100") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "FNV-164", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "CRC-64", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN7, modes: vec![
                HashInfo{ name: "Oracle H: Type (Oracle 7+), DES(Oracle)", john: None ,hashcat: Some("3100") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN8, modes: vec![
                HashInfo{ name: "Cisco-PIX(MD5)", john: Some("pix-md5") ,hashcat: Some("2400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN9, modes: vec![
                HashInfo{ name: "Lotus Notes/Domino 6", john: Some("dominosec") ,hashcat: Some("8700") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN10, modes: vec![
                HashInfo{ name: "BSDi Crypt", john: Some("bsdicrypt") ,hashcat: Some("12400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN11, modes: vec![
                HashInfo{ name: "CRC-96(ZIP)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "PKZIP Master Key", john: None ,hashcat: Some("20500") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "PKZIP Master Key (6 byte optimization)", john: None ,hashcat: Some("20510") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN12, modes: vec![
                HashInfo{ name: "Keepass 1 AES / without keyfile", john: None ,hashcat: Some("13400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN13, modes: vec![
                HashInfo{ name: "Keepass 1 Twofish / with keyfile", john: None ,hashcat: Some("13400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN14, modes: vec![
                HashInfo{ name: "Keepass 2 AES / with keyfile", john: None ,hashcat: Some("13400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN15, modes: vec![
                HashInfo{ name: "Keepass 2 AES / without keyfile", john: None ,hashcat: Some("13400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN16, modes: vec![
                HashInfo{ name: "Crypt16", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN17, modes: vec![
                HashInfo{ name: "MD5", john: Some("raw-md5") ,hashcat: Some("0") ,variation: false ,description: Some("Used to be in linux shadow and was used for SSL/TLS"), popular: true },
                HashInfo{ name: "MD4", john: Some("raw-md4") ,hashcat: Some("900") ,variation: false ,description: None, popular: true },
                HashInfo{ name: "Double MD5", john: None ,hashcat: Some("2600") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Tiger-128", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-256(128)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-512(128)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Lotus Notes/Domino 5", john: Some("lotus5") ,hashcat: Some("8600") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "md5(md5(md5($pass)))", john: None ,hashcat: Some("3500") ,variation: true ,description: Some("Hashcat legacy only"), popular: false },
                HashInfo{ name: "md5(uppercase(md5($pass)))", john: None ,hashcat: Some("4300") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5(sha1($pass))", john: None ,hashcat: Some("4400") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5(utf16($pass))", john: Some("dynamic_29") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md4(utf16($pass))", john: Some("dynamic_33") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5(md4($pass))", john: Some("dynamic_34") ,hashcat: None ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN18, modes: vec![
                HashInfo{ name: "Haval-128", john: Some("haval-128-4") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN19, modes: vec![
                HashInfo{ name: "RIPEMD-128", john: Some("ripemd-128") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN20, modes: vec![
                HashInfo{ name: "LM", john: Some("lm") ,hashcat: Some("3000") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN21, modes: vec![
                HashInfo{ name: "net-md5", john: Some("dynamic_39") ,hashcat: None ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN22, modes: vec![
                HashInfo{ name: "Skype", john: None ,hashcat: Some("23") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "ZipMonster", john: None ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5(md5(md5($pass)))", john: None ,hashcat: Some("3500") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5(uppercase(md5($pass)))", john: None ,hashcat: Some("4300") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5(sha1($pass))", john: None ,hashcat: Some("4400") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5($pass.$salt)", john: None ,hashcat: Some("10") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5($salt.$pass)", john: None ,hashcat: Some("20") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5(unicode($pass).$salt)", john: None ,hashcat: Some("30") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5($salt.unicode($pass))", john: None ,hashcat: Some("40") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "HMAC-MD5 (key = $pass)", john: Some("hmac-md5") ,hashcat: Some("50") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "HMAC-MD5 (key = $salt)", john: Some("hmac-md5") ,hashcat: Some("60") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5(md5($salt).$pass)", john: None ,hashcat: Some("3610") ,variation: true ,description: Some("Hashcat legacy only"), popular: false },
                HashInfo{ name: "md5($salt.md5($pass))", john: None ,hashcat: Some("3710") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5($pass.md5($salt))", john: None ,hashcat: Some("3720") ,variation: true ,description: Some("Hashcat legacy only"), popular: false },
                HashInfo{ name: "WebEdition CMS", john: None ,hashcat: Some("3721") ,variation: false ,description: Some("Hashcat legacy only"), popular: false },
                HashInfo{ name: "md5($username.0.$pass)", john: None ,hashcat: Some("4210") ,variation: true ,description: Some("Hashcat legacy only"), popular: false },
                HashInfo{ name: "md5($salt.$pass.$salt)", john: None ,hashcat: Some("3800") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5(md5($pass).md5($salt))", john: None ,hashcat: Some("3910") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5($salt.md5($salt.$pass))", john: None ,hashcat: Some("4010") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5($salt.md5($pass.$salt))", john: None ,hashcat: Some("4110") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md4($salt.$pass)", john: Some("dynamic_31") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md4($pass.$salt)", john: Some("dynamic_32") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "md5($salt.pad16($pass))", john: Some("dynamic_39") ,hashcat: None ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN23, modes: vec![
                HashInfo{ name: "PrestaShop", john: None ,hashcat: Some("11000") ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN24, modes: vec![
                HashInfo{ name: "MD2", john: Some("md2") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN25, modes: vec![
                HashInfo{ name: "Snefru-128", john: Some("snefru-128") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN26, modes: vec![
                HashInfo{ name: "NTLM", john: Some("nt") ,hashcat: Some("1000") ,variation: false ,description: Some("Used to be used in active directory and SAM database"), popular: true },
      ]},
        Pattern { regex: &*PATTERN27, modes: vec![
                HashInfo{ name: "Domain Cached Credentials", john: Some("mscash") ,hashcat: Some("1100") ,variation: false ,description: None, popular: true },
      ]},
        Pattern { regex: &*PATTERN28, modes: vec![
                HashInfo{ name: "Domain Cached Credentials 2", john: Some("mscash2") ,hashcat: Some("2100") ,variation: false ,description: None, popular: true },
      ]},
        Pattern { regex: &*PATTERN29, modes: vec![
                HashInfo{ name: "SHA-1(Base64)", john: Some("nsldap") ,hashcat: Some("101") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Netscape LDAP SHA", john: Some("nsldap") ,hashcat: Some("101") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN30, modes: vec![
                HashInfo{ name: "MD5 Crypt", john: Some("md5crypt") ,hashcat: Some("500") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Cisco-IOS(MD5)", john: Some("md5crypt") ,hashcat: Some("500") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "FreeBSD MD5", john: Some("md5crypt") ,hashcat: Some("500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN31, modes: vec![
                HashInfo{ name: "Lineage II C4", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN32, modes: vec![
                HashInfo{ name: "phpBB v3.x", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Wordpress v2.6.0/2.6.1", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "PHPass' Portable Hash", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN33, modes: vec![
                HashInfo{ name: "Wordpress ≥ v2.6.2", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Joomla ≥ v2.5.18", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "PHPass' Portable Hash", john: Some("phpass") ,hashcat: Some("400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN34, modes: vec![
                HashInfo{ name: "osCommerce", john: None ,hashcat: Some("21") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "xt:Commerce", john: None ,hashcat: Some("21") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN35, modes: vec![
                HashInfo{ name: "MD5(APR)", john: None ,hashcat: Some("1600") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Apache MD5", john: None ,hashcat: Some("1600") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "md5apr1", john: None ,hashcat: Some("1600") ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN36, modes: vec![
                HashInfo{ name: "AIX(smd5)", john: Some("aix-smd5") ,hashcat: Some("6300") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN37, modes: vec![
                HashInfo{ name: "IP.Board ≥ v2+", john: None ,hashcat: Some("2811") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN38, modes: vec![
                HashInfo{ name: "MyBB ≥ v1.2+", john: None ,hashcat: Some("2811") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN39, modes: vec![
                HashInfo{ name: "CryptoCurrency(Adress)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN40, modes: vec![
                HashInfo{ name: "SHA-1", john: Some("raw-sha1") ,hashcat: Some("100") ,variation: false ,description: Some("Used for checsums"), popular: true },
                HashInfo{ name: "Double SHA-1", john: None ,hashcat: Some("4500") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "RIPEMD-160", john: Some("ripemd-160") ,hashcat: Some("6000") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-160 (3 rounds)", john: Some("dynamic_190") ,hashcat: Some("6000") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-160 (4 rounds)", john: Some("dynamic_200") ,hashcat: Some("6000") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-160 (5 rounds)", john: Some("dynamic_210") ,hashcat: Some("6000") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-192 (3 rounds)", john: Some("dynamic_220") ,hashcat: Some("6000") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-192 (4 rounds)", john: Some("dynamic_230") ,hashcat: Some("6000") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-192 (5 rounds)", john: Some("dynamic_240") ,hashcat: Some("6000") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-224 (4 rounds)", john: Some("dynamic_260") ,hashcat: Some("6000") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-224 (5 rounds)", john: Some("dynamic_270") ,hashcat: Some("6000") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-160", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Tiger-160", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "HAS-160", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "LinkedIn", john: Some("raw-sha1-linkedin") ,hashcat: Some("190") ,variation: false ,description: Some("Hashcat legacy only"), popular: false },
                HashInfo{ name: "Skein-256(160)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-512(160)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "MangosWeb Enhanced CMS", john: None ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha1(sha1(sha1($pass)))", john: None ,hashcat: Some("4600") ,variation: true ,description: Some("Hashcat legacy only"), popular: false },
                HashInfo{ name: "sha1(md5($pass))", john: None ,hashcat: Some("4700") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha1($pass.$salt)", john: None ,hashcat: Some("110") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha1($salt.$pass)", john: None ,hashcat: Some("120") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha1(unicode($pass).$salt)", john: None ,hashcat: Some("130") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha1($salt.unicode($pass))", john: None ,hashcat: Some("140") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "HMAC-SHA1 (key = $pass)", john: Some("hmac-sha1") ,hashcat: Some("150") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "HMAC-SHA1 (key = $salt)", john: Some("hmac-sha1") ,hashcat: Some("160") ,variation: true ,description: None, popular: true },
                HashInfo{ name: "sha1($salt.$pass.$salt)", john: None ,hashcat: Some("4710") ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN41, modes: vec![
                HashInfo{ name: "MySQL5.x", john: Some("mysql-sha1") ,hashcat: Some("300") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "MySQL4.1", john: Some("mysql-sha1") ,hashcat: Some("300") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN42, modes: vec![
                HashInfo{ name: "Cisco-IOS(SHA-256)", john: None ,hashcat: Some("5700") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN43, modes: vec![
                HashInfo{ name: "SSHA-1(Base64)", john: Some("nsldaps") ,hashcat: Some("111") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Netscape LDAP SSHA", john: Some("nsldaps") ,hashcat: Some("111") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "nsldaps", john: Some("nsldaps") ,hashcat: Some("111") ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN44, modes: vec![
                HashInfo{ name: "Fortigate(FortiOS)", john: Some("fortigate") ,hashcat: Some("7000") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN45, modes: vec![
                HashInfo{ name: "Haval-192", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Tiger-192", john: Some("tiger") ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "SHA-1(Oracle)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "OSX v10.4", john: Some("xsha") ,hashcat: Some("122") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "OSX v10.5", john: Some("xsha") ,hashcat: Some("122") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "OSX v10.6", john: Some("xsha") ,hashcat: Some("122") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN46, modes: vec![
                HashInfo{ name: "Palshop CMS", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN47, modes: vec![
                HashInfo{ name: "CryptoCurrency(PrivateKey)", john: None ,hashcat: None ,variation: false ,description: None, popular: true },
      ]},
        Pattern { regex: &*PATTERN48, modes: vec![
                HashInfo{ name: "AIX(ssha1)", john: Some("aix-ssha1") ,hashcat: Some("6700") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN49, modes: vec![
                HashInfo{ name: "MSSQL(2005)", john: Some("mssql05") ,hashcat: Some("132") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "MSSQL(2008)", john: Some("mssql05") ,hashcat: Some("132") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN50, modes: vec![
                HashInfo{ name: "Sun MD5 Crypt", john: Some("sunmd5") ,hashcat: Some("3300") ,variation: false ,description: Some("Hashcat legacy only"), popular: false },
      ]},
        Pattern { regex: &*PATTERN51, modes: vec![
                HashInfo{ name: "SHA-224", john: Some("raw-sha224") ,hashcat: Some("1300") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "sha224($salt.$pass)", john: Some("dynamic_51") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha224($pass.$salt))", john: Some("dynamic_52") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha224(sha224($pass))", john: Some("dynamic_53") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha224(sha224_raw($pass))", john: Some("dynamic_54") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha224(sha224($pass).$salt)", john: Some("dynamic_55") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha224($salt.sha224($pass))", john: Some("dynamic_56") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha224(sha224($salt).sha224($pass))", john: Some("dynamic_57") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha224(sha224($pass).sha224($pass))", john: Some("dynamic_58") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "Haval-224", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "SHA3-224", john: None ,hashcat: Some("17300") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-256(224)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-512(224)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-224", john: Some("dynamic_330") ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Keccak-224", john: None ,hashcat: Some("17700") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN52, modes: vec![
                HashInfo{ name: "Blowfish(OpenBSD)", john: Some("bcrypt") ,hashcat: Some("3200") ,variation: false ,description: Some("Can be seen in shadow files"), popular: false },
                HashInfo{ name: "Woltlab Burning Board 4.x", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "bcrypt", john: Some("bcrypt") ,hashcat: Some("3200") ,variation: false ,description: None, popular: true },
      ]},
        Pattern { regex: &*PATTERN53, modes: vec![
                HashInfo{ name: "yescrypt", john: Some("On systems that use libxcrypt, you may use --format=crypt to use JtR in passthrough mode which uses the system's crypt function.") ,hashcat: None ,variation: false ,description: Some("Can be used in shadow files"), popular: false },
      ]},
        Pattern { regex: &*PATTERN54, modes: vec![
                HashInfo{ name: "Android PIN", john: None ,hashcat: Some("5800") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN55, modes: vec![
                HashInfo{ name: "Oracle 11g/12c", john: Some("oracle11") ,hashcat: Some("112") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN56, modes: vec![
                HashInfo{ name: "bcrypt(SHA-256)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN57, modes: vec![
                HashInfo{ name: "vBulletin < v3.8.5", john: None ,hashcat: Some("2611") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN58, modes: vec![
                HashInfo{ name: "vBulletin ≥ v3.8.5", john: None ,hashcat: Some("2711") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN59, modes: vec![
                HashInfo{ name: "Snefru-256", john: Some("snefru-256") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN60, modes: vec![
                HashInfo{ name: "SHA-256", john: Some("raw-sha256") ,hashcat: Some("1400") ,variation: false ,description: Some("Can be used in shadow files, and digital signatures Openssl tls"), popular: true },
                HashInfo{ name: "RIPEMD-256", john: Some("dynamic_140") ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-256 (3 rounds)", john: Some("dynamic_140") ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-256 (4 rounds)", john: Some("dynamic_290") ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Haval-256 (5 rounds)", john: Some("dynamic_300") ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "GOST R 34.11-94", john: Some("gost") ,hashcat: Some("6900") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "GOST CryptoPro S-Box", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Blake2b-256", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "SHA3-256", john: Some("dynamic_380") ,hashcat: Some("17400") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "PANAMA", john: Some("dynamic_320") ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "BLAKE2-256", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "BLAKE2-384", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-256", john: Some("skein-256") ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-512(256)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Ventrilo", john: None ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha256($pass.$salt)", john: Some("dynamic_62") ,hashcat: Some("1410") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha256($salt.$pass)", john: Some("dynamic_61") ,hashcat: Some("1420") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha256(sha256($pass))", john: Some("dynamic_63") ,hashcat: Some("1420") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha256(sha256_raw($pass)))", john: Some("dynamic_64") ,hashcat: Some("1420") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha256(sha256($pass).$salt)", john: Some("dynamic_65") ,hashcat: Some("1420") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha256($salt.sha256($pass))", john: Some("dynamic_66") ,hashcat: Some("1420") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha256(sha256($salt).sha256($pass))", john: Some("dynamic_67") ,hashcat: Some("1420") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha256(sha256($pass).sha256($pass))", john: Some("dynamic_68") ,hashcat: Some("1420") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha256(unicode($pass).$salt)", john: None ,hashcat: Some("1430") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha256($salt.unicode($pass))", john: None ,hashcat: Some("1440") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "HMAC-SHA256 (key = $pass)", john: Some("hmac-sha256") ,hashcat: Some("1450") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "HMAC-SHA256 (key = $salt)", john: Some("hmac-sha256") ,hashcat: Some("1460") ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN61, modes: vec![
                HashInfo{ name: "Joomla < v2.5.18", john: None ,hashcat: Some("11") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN62, modes: vec![
                HashInfo{ name: "SAM(LM_Hash:NT_Hash)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN63, modes: vec![
                HashInfo{ name: "MD5(Chap)", john: Some("chap") ,hashcat: Some("4800") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "iSCSI CHAP Authentication", john: Some("chap") ,hashcat: Some("4800") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN64, modes: vec![
                HashInfo{ name: "EPiServer 6.x < v4", john: Some("episerver") ,hashcat: Some("141") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN65, modes: vec![
                HashInfo{ name: "AIX(ssha256)", john: Some("aix-ssha256") ,hashcat: Some("6400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN66, modes: vec![
                HashInfo{ name: "RIPEMD-320", john: Some("dynamic_150") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN67, modes: vec![
                HashInfo{ name: "EPiServer 6.x ≥ v4", john: Some("episerver") ,hashcat: Some("1441") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN68, modes: vec![
                HashInfo{ name: "MSSQL(2000)", john: Some("mssql") ,hashcat: Some("131") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN69, modes: vec![
                HashInfo{ name: "SHA-384", john: Some("raw-sha384") ,hashcat: Some("10800") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "SHA3-384", john: Some("dynamic_390") ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-512(384)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-1024(384)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "sha384($salt.$pass)", john: Some("dynamic_71") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha384($pass.$salt)", john: Some("dynamic_72") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha384(sha384($pass))", john: Some("dynamic_73") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha384(sha384_raw($pass))", john: Some("dynamic_74") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha384(sha384($pass).$salt)", john: Some("dynamic_75") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha384($salt.sha384($pass))", john: Some("dynamic_76") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha384(sha384($salt).sha384($pass))", john: Some("dynamic_77") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha384(sha384($pass).sha384($pass))", john: Some("dynamic_78") ,hashcat: None ,variation: true ,description: None, popular: false },
                HashInfo{ name: "Skein-384", john: Some("dynamic_350") ,hashcat: None ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN70, modes: vec![
                HashInfo{ name: "SSHA-512(Base64)", john: Some("ssha512") ,hashcat: Some("1711") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "LDAP(SSHA-512)", john: Some("ssha512") ,hashcat: Some("1711") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN71, modes: vec![
                HashInfo{ name: "AIX(ssha512)", john: Some("aix-ssha512") ,hashcat: Some("6500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN72, modes: vec![
                HashInfo{ name: "SHA-512", john: Some("raw-sha512") ,hashcat: Some("1700") ,variation: false ,description: Some("Used in Bitcoin Blockchain and Shadow Files"), popular: true },
                HashInfo{ name: "Keccak-512", john: None ,hashcat: Some("1800") ,variation: false ,description: None, popular: true },
                HashInfo{ name: "Whirlpool", john: Some("whirlpool") ,hashcat: Some("6100") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Salsa10", john: None ,hashcat: None ,variation: false ,description: Some("Not a hash function"), popular: false },
                HashInfo{ name: "Salsa20", john: None ,hashcat: None ,variation: false ,description: Some("Not a hash function"), popular: false },
                HashInfo{ name: "Blake2", john: Some("raw-blake2") ,hashcat: Some("600") ,variation: false ,description: Some("Used in Wireguard, Zcash, IPFS"), popular: true },
                HashInfo{ name: "SHA3-512", john: Some("raw-sha3") ,hashcat: Some("17600") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-512", john: Some("skein-512") ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Skein-1024(512)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "sha512($pass.$salt)", john: None ,hashcat: Some("1710") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha512($salt.$pass)", john: None ,hashcat: Some("1720") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha512(unicode($pass).$salt)", john: None ,hashcat: Some("1730") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "sha512($salt.unicode($pass))", john: None ,hashcat: Some("1740") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "HMAC-SHA512 (key = $pass)", john: Some("hmac-sha512") ,hashcat: Some("1750") ,variation: true ,description: None, popular: false },
                HashInfo{ name: "BLAKE2-224", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
                HashInfo{ name: "HMAC-SHA512 (key = $salt)", john: Some("hmac-sha512") ,hashcat: Some("1760") ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN73, modes: vec![
                HashInfo{ name: "Keccak-256", john: None ,hashcat: Some("17800") ,variation: false ,description: None, popular: true },
      ]},
        Pattern { regex: &*PATTERN74, modes: vec![
                HashInfo{ name: "Keccak-384", john: None ,hashcat: Some("17900") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN75, modes: vec![
                HashInfo{ name: "OSX v10.7", john: Some("xsha512") ,hashcat: Some("1722") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN76, modes: vec![
                HashInfo{ name: "MSSQL(2012)", john: Some("mssql12") ,hashcat: Some("1731") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "MSSQL(2014)", john: Some("mssql12") ,hashcat: Some("1731") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN77, modes: vec![
                HashInfo{ name: "OSX v10.8", john: Some("pbkdf2-hmac-sha512") ,hashcat: Some("7100") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "OSX v10.9", john: Some("pbkdf2-hmac-sha512") ,hashcat: Some("7100") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN78, modes: vec![
                HashInfo{ name: "Skein-1024", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN79, modes: vec![
                HashInfo{ name: "GRUB 2", john: None ,hashcat: Some("7200") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN80, modes: vec![
                HashInfo{ name: "Django(SHA-1)", john: None ,hashcat: Some("124") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN81, modes: vec![
                HashInfo{ name: "Citrix Netscaler", john: Some("citrix_ns10") ,hashcat: Some("8100") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN82, modes: vec![
                HashInfo{ name: "Drupal > v7.x", john: Some("drupal7") ,hashcat: Some("7900") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN83, modes: vec![
                HashInfo{ name: "SHA-256 Crypt", john: Some("sha256crypt") ,hashcat: Some("7400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN84, modes: vec![
                HashInfo{ name: "Sybase ASE", john: Some("sybasease") ,hashcat: Some("8000") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN85, modes: vec![
                HashInfo{ name: "SHA-512 Crypt", john: Some("sha512crypt") ,hashcat: Some("1800") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN86, modes: vec![
                HashInfo{ name: "Minecraft(AuthMe Reloaded)", john: None ,hashcat: Some("20711") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN87, modes: vec![
                HashInfo{ name: "Django(SHA-256)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN88, modes: vec![
                HashInfo{ name: "Django(SHA-384)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN89, modes: vec![
                HashInfo{ name: "Clavister Secure Gateway", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN90, modes: vec![
                HashInfo{ name: "Cisco VPN Client(PCF-File)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN91, modes: vec![
                HashInfo{ name: "Microsoft MSTSC(RDP-File)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN92, modes: vec![
                HashInfo{ name: "NetNTLMv1-VANILLA / NetNTLMv1+ESS", john: Some("netntlm") ,hashcat: Some("5500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN93, modes: vec![
                HashInfo{ name: "NetNTLMv2", john: Some("netntlmv2") ,hashcat: Some("5600") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN94, modes: vec![
                HashInfo{ name: "Kerberos 5 AS-REQ Pre-Auth", john: Some("krb5pa-md5") ,hashcat: Some("7500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN95, modes: vec![
                HashInfo{ name: "SCRAM Hash", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN96, modes: vec![
                HashInfo{ name: "Redmine Project Management Web App", john: None ,hashcat: Some("4521") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN97, modes: vec![
                HashInfo{ name: "SAP CODVN B (BCODE)", john: Some("sapb") ,hashcat: Some("7700") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN98, modes: vec![
                HashInfo{ name: "SAP CODVN F/G (PASSCODE)", john: Some("sapg") ,hashcat: Some("7800") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN99, modes: vec![
                HashInfo{ name: "Juniper Netscreen/SSG(ScreenOS)", john: Some("md5ns") ,hashcat: Some("22") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN100, modes: vec![
                HashInfo{ name: "EPi", john: None ,hashcat: Some("123") ,variation: false ,description: Some("Hashcat mode is no longer supported."), popular: false },
      ]},
        Pattern { regex: &*PATTERN101, modes: vec![
                HashInfo{ name: "SMF ≥ v1.1", john: None ,hashcat: Some("121") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN102, modes: vec![
                HashInfo{ name: "Woltlab Burning Board 3.x", john: Some("wbb3") ,hashcat: Some("8400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN103, modes: vec![
                HashInfo{ name: "IPMI2 RAKP HMAC-SHA1", john: None ,hashcat: Some("7300") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN104, modes: vec![
                HashInfo{ name: "Lastpass", john: None ,hashcat: Some("6800") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN105, modes: vec![
                HashInfo{ name: "Cisco-ASA(MD5)", john: Some("asa-md5") ,hashcat: Some("2410") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN106, modes: vec![
                HashInfo{ name: "VNC", john: Some("vnc") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN107, modes: vec![
                HashInfo{ name: "DNSSEC(NSEC3)", john: None ,hashcat: Some("8300") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN108, modes: vec![
                HashInfo{ name: "RACF", john: Some("racf") ,hashcat: Some("8500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN109, modes: vec![
                HashInfo{ name: "NTHash(FreeBSD Variant)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN110, modes: vec![
                HashInfo{ name: "SHA-1 Crypt", john: Some("sha1crypt") ,hashcat: Some("15100") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN111, modes: vec![
                HashInfo{ name: "hMailServer", john: Some("hmailserver") ,hashcat: Some("1421") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN112, modes: vec![
                HashInfo{ name: "MediaWiki", john: Some("mediawiki") ,hashcat: Some("3711") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN113, modes: vec![
                HashInfo{ name: "Minecraft(xAuth)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN114, modes: vec![
                HashInfo{ name: "PBKDF2-SHA1(Generic)", john: None ,hashcat: Some("20400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN115, modes: vec![
                HashInfo{ name: "PBKDF2-SHA256(Generic)", john: Some("pbkdf2-hmac-sha256") ,hashcat: Some("20300") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN116, modes: vec![
                HashInfo{ name: "PBKDF2-SHA512(Generic)", john: None ,hashcat: Some("20200") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN117, modes: vec![
                HashInfo{ name: "PBKDF2(Cryptacular)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN118, modes: vec![
                HashInfo{ name: "PBKDF2(Dwayne Litzenberger)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN119, modes: vec![
                HashInfo{ name: "Fairly Secure Hashed Password", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN120, modes: vec![
                HashInfo{ name: "PHPS", john: Some("phps") ,hashcat: Some("2612") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN121, modes: vec![
                HashInfo{ name: "1Password(Agile Keychain)", john: None ,hashcat: Some("6600") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN122, modes: vec![
                HashInfo{ name: "1Password(Cloud Keychain)", john: None ,hashcat: Some("8200") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN123, modes: vec![
                HashInfo{ name: "IKE-PSK MD5", john: None ,hashcat: Some("5300") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN124, modes: vec![
                HashInfo{ name: "IKE-PSK SHA1", john: None ,hashcat: Some("5400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN125, modes: vec![
                HashInfo{ name: "PeopleSoft", john: None ,hashcat: Some("133") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN126, modes: vec![
                HashInfo{ name: "Django(DES Crypt Wrapper)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN127, modes: vec![
                HashInfo{ name: "Django(PBKDF2-HMAC-SHA256)", john: Some("django") ,hashcat: Some("10000") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN128, modes: vec![
                HashInfo{ name: "Django(PBKDF2-HMAC-SHA1)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN129, modes: vec![
                HashInfo{ name: "Django(bcrypt)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN130, modes: vec![
                HashInfo{ name: "Django(MD5)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN131, modes: vec![
                HashInfo{ name: "PBKDF2(Atlassian)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN132, modes: vec![
                HashInfo{ name: "PostgreSQL MD5", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN133, modes: vec![
                HashInfo{ name: "Lotus Notes/Domino 8", john: None ,hashcat: Some("9100") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN134, modes: vec![
                HashInfo{ name: "scrypt", john: None ,hashcat: Some("8900") ,variation: false ,description: Some("Used in Dogecoin and Litecoin."), popular: false },
      ]},
        Pattern { regex: &*PATTERN135, modes: vec![
                HashInfo{ name: "Cisco Type 8", john: Some("cisco8") ,hashcat: Some("9200") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN136, modes: vec![
                HashInfo{ name: "Cisco Type 9", john: Some("cisco9") ,hashcat: Some("9300") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN137, modes: vec![
                HashInfo{ name: "Microsoft Office 2007", john: Some("office") ,hashcat: Some("9400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN138, modes: vec![
                HashInfo{ name: "Microsoft Office 2010", john: Some("office") ,hashcat: Some("9500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN139, modes: vec![
                HashInfo{ name: "Microsoft Office 2016 - SheetProtection", john: None ,hashcat: Some("25300") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN140, modes: vec![
                HashInfo{ name: "Microsoft Office 2013", john: Some("office") ,hashcat: Some("9600") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN141, modes: vec![
                HashInfo{ name: "Android FDE ≤ 4.3", john: Some("fde") ,hashcat: Some("8800") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN142, modes: vec![
                HashInfo{ name: "Kerberos 5 TGS-REP etype 23", john: Some("krb5tgs") ,hashcat: Some("13100") ,variation: false ,description: Some("Used in windows active directory"), popular: false },
      ]},
        Pattern { regex: &*PATTERN143, modes: vec![
                HashInfo{ name: "Microsoft Office ≤ 2003 (MD5+RC4)", john: Some("oldoffice") ,hashcat: Some("9700") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1", john: Some("oldoffice") ,hashcat: Some("9710") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN144, modes: vec![
                HashInfo{ name: "Microsoft Office ≤ 2003 (SHA1+RC4)", john: Some("oldoffice") ,hashcat: Some("9800") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1", john: Some("oldoffice") ,hashcat: Some("9810") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN145, modes: vec![
                HashInfo{ name: "MS Office ⇐ 2003 $3, SHA1 + RC4, collider #2", john: Some("oldoffice") ,hashcat: Some("9820") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN146, modes: vec![
                HashInfo{ name: "RAdmin v2.x", john: Some("radmin") ,hashcat: Some("9900") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN147, modes: vec![
                HashInfo{ name: "SAP CODVN H (PWDSALTEDHASH) iSSHA-1", john: Some("saph") ,hashcat: Some("10300") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN148, modes: vec![
                HashInfo{ name: "CRAM-MD5", john: None ,hashcat: Some("10200") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN149, modes: vec![
                HashInfo{ name: "SipHash", john: None ,hashcat: Some("10100") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN150, modes: vec![
                HashInfo{ name: "Cisco Type 7", john: None ,hashcat: None ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN151, modes: vec![
                HashInfo{ name: "BigCrypt", john: Some("bigcrypt") ,hashcat: None ,variation: true ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN152, modes: vec![
                HashInfo{ name: "Cisco Type 4", john: Some("cisco4") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN153, modes: vec![
                HashInfo{ name: "Django(bcrypt-SHA256)", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN154, modes: vec![
                HashInfo{ name: "PostgreSQL Challenge-Response Authentication (MD5)", john: Some("postgres") ,hashcat: Some("11100") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN155, modes: vec![
                HashInfo{ name: "Siemens-S7", john: Some("siemens-s7") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN156, modes: vec![
                HashInfo{ name: "Microsoft Outlook PST", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN157, modes: vec![
                HashInfo{ name: "PBKDF2-HMAC-SHA256(PHP)", john: None ,hashcat: Some("10900") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN158, modes: vec![
                HashInfo{ name: "Dahua", john: Some("dahua") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN159, modes: vec![
                HashInfo{ name: "MySQL Challenge-Response Authentication (SHA1)", john: None ,hashcat: Some("11200") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN160, modes: vec![
                HashInfo{ name: "PDF 1.1 - 1.3 (Acrobat 2 - 4)", john: Some("pdf") ,hashcat: Some("10400") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1", john: Some("pdf") ,hashcat: Some("10410") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN161, modes: vec![
                HashInfo{ name: "PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2", john: None ,hashcat: Some("10420") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN162, modes: vec![
                HashInfo{ name: "PDF 1.4 - 1.6 (Acrobat 5 - 8)", john: Some("pdf") ,hashcat: Some("10500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN163, modes: vec![
                HashInfo{ name: "PDF 1.7 Level 3 (Acrobat 9)", john: Some("pdf") ,hashcat: Some("10600") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN164, modes: vec![
                HashInfo{ name: "PDF 1.7 Level 8 (Acrobat 10 - 11)", john: Some("pdf") ,hashcat: Some("10700") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN165, modes: vec![
                HashInfo{ name: "Kerberos 5 AS-REP etype 23", john: Some("krb5pa-sha1") ,hashcat: Some("18200") ,variation: false ,description: Some("Used in windows active directory"), popular: false },
      ]},
        Pattern { regex: &*PATTERN166, modes: vec![
                HashInfo{ name: "Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96)", john: None ,hashcat: Some("19600") ,variation: false ,description: Some("Used in windows active directory"), popular: false },
      ]},
        Pattern { regex: &*PATTERN167, modes: vec![
                HashInfo{ name: "Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96)", john: None ,hashcat: Some("19700") ,variation: false ,description: Some("Used in windows active directory"), popular: false },
      ]},
        Pattern { regex: &*PATTERN168, modes: vec![
                HashInfo{ name: "Kerberos 5, etype 17, Pre-Auth", john: None ,hashcat: Some("19800") ,variation: false ,description: Some("Used in windows active directory"), popular: false },
      ]},
        Pattern { regex: &*PATTERN169, modes: vec![
                HashInfo{ name: "Kerberos 5, etype 17, Pre-Auth (with salt)", john: Some("krb5pa-sha1") ,hashcat: None ,variation: false ,description: Some("Used in windows active directory"), popular: false },
      ]},
        Pattern { regex: &*PATTERN170, modes: vec![
                HashInfo{ name: "Kerberos 5, etype 18, Pre-Auth (with salt)", john: Some("krb5pa-sha1") ,hashcat: None ,variation: false ,description: Some("Used in windows active directory"), popular: false },
      ]},
        Pattern { regex: &*PATTERN171, modes: vec![
                HashInfo{ name: "Kerberos 5, etype 18, Pre-Auth", john: None ,hashcat: Some("19900") ,variation: false ,description: Some("Used in windows active directory"), popular: false },
      ]},
        Pattern { regex: &*PATTERN172, modes: vec![
                HashInfo{ name: "Bitcoin / Litecoin", john: Some("bitcoin") ,hashcat: Some("11300") ,variation: false ,description: Some("Use Bitcoin2John.py to extract the hash for cracking."), popular: false },
      ]},
        Pattern { regex: &*PATTERN173, modes: vec![
                HashInfo{ name: "Ethereum Wallet, PBKDF2-HMAC-SHA256", john: Some("ethereum-opencl") ,hashcat: Some("15600") ,variation: false ,description: Some("Use ethereum2john.py to crack."), popular: false },
                HashInfo{ name: "Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256", john: Some("ethereum-presale-opencl") ,hashcat: Some("16300") ,variation: false ,description: Some("Use ethereum2john.py to crack."), popular: false },
      ]},
        Pattern { regex: &*PATTERN174, modes: vec![
                HashInfo{ name: "Monero", john: Some("monero") ,hashcat: None ,variation: false ,description: Some("Use monero2john.py to crack."), popular: false },
      ]},
        Pattern { regex: &*PATTERN175, modes: vec![
                HashInfo{ name: "Electrum Wallet (Salt-Type 1-3)", john: Some("electrum") ,hashcat: Some("16600") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN176, modes: vec![
                HashInfo{ name: "Electrum Wallet (Salt-Type 4)", john: Some("electrum") ,hashcat: Some("21700") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN177, modes: vec![
                HashInfo{ name: "Electrum Wallet (Salt-Type 5)", john: Some("electrum") ,hashcat: Some("21800") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN178, modes: vec![
                HashInfo{ name: "Android Backup", john: Some("androidbackup") ,hashcat: Some("18900") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN179, modes: vec![
                HashInfo{ name: "WinZip", john: Some("zip") ,hashcat: Some("13600") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN180, modes: vec![
                HashInfo{ name: "iTunes backup >= 10.0", john: Some("itunes-backup") ,hashcat: Some("14800") ,variation: false ,description: None, popular: false },
                HashInfo{ name: "iTunes backup < 10.0", john: Some("itunes-backup") ,hashcat: Some("14700") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN181, modes: vec![
                HashInfo{ name: "Telegram Mobile App Passcode (SHA256)", john: Some("Telegram") ,hashcat: Some("22301") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN182, modes: vec![
                HashInfo{ name: "Telegram Desktop 1.3.9", john: Some("telegram") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN183, modes: vec![
                HashInfo{ name: "Telegram Desktop >= 2.1.14-beta / 2.2.0", john: Some("telegram") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN184, modes: vec![
                HashInfo{ name: "BLAKE2b-512", john: None ,hashcat: Some("600") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN185, modes: vec![
                HashInfo{ name: "MS Office ⇐ 2003 $0/$1, MD5 + RC4, collider #2", john: Some("oldoffice") ,hashcat: Some("9720") ,variation: false ,description: Some("Use office2john.py to grab the hash."), popular: false },
      ]},
        Pattern { regex: &*PATTERN186, modes: vec![
                HashInfo{ name: "MS Office 2016 - SheetProtection", john: None ,hashcat: Some("25300") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN187, modes: vec![
                HashInfo{ name: "7-zip", john: Some("7z") ,hashcat: Some("11600") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN188, modes: vec![
                HashInfo{ name: "SecureZIP AES-256", john: Some("securezip") ,hashcat: Some("23003") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN189, modes: vec![
                HashInfo{ name: "SecureZIP AES-192", john: Some("securezip") ,hashcat: Some("23002") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN190, modes: vec![
                HashInfo{ name: "SecureZIP AES-128", john: Some("securezip") ,hashcat: Some("23001") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN191, modes: vec![
                HashInfo{ name: "PKZIP (Compressed)", john: Some("pkzip") ,hashcat: Some("17200") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN192, modes: vec![
                HashInfo{ name: "PKZIP (Uncompressed)", john: Some("pkzip") ,hashcat: Some("17210") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN193, modes: vec![
                HashInfo{ name: "PKZIP (Compressed Multi-File)", john: Some("pkzip") ,hashcat: Some("17220") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN194, modes: vec![
                HashInfo{ name: "PKZIP (Mixed Multi-File)", john: Some("pkzip") ,hashcat: Some("17225") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN195, modes: vec![
                HashInfo{ name: "PKZIP (Mixed Multi-File Checksum-Only)", john: Some("pkzip") ,hashcat: Some("17230") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN196, modes: vec![
                HashInfo{ name: "Argon2i", john: Some("argon2") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN197, modes: vec![
                HashInfo{ name: "Argon2id", john: None ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN198, modes: vec![
                HashInfo{ name: "Argon2d", john: Some("argon2") ,hashcat: None ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN199, modes: vec![
                HashInfo{ name: "BitLocker", john: Some("bitlocker") ,hashcat: Some("22100") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN200, modes: vec![
                HashInfo{ name: "RACF", john: None ,hashcat: Some("8500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN201, modes: vec![
                HashInfo{ name: "RSA/DSA/EC/OpenSSH Private Keys ($4$)", john: None ,hashcat: Some("22941") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN202, modes: vec![
                HashInfo{ name: "RAR3-p (Uncompressed)", john: Some("rar") ,hashcat: Some("23700") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN203, modes: vec![
                HashInfo{ name: "RAR3-p (Compressed)", john: Some("rar") ,hashcat: Some("23800") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN204, modes: vec![
                HashInfo{ name: "RAR3-hp", john: Some("rar") ,hashcat: Some("12500") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN205, modes: vec![
                HashInfo{ name: "RAR5", john: Some("rar5") ,hashcat: Some("13000") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN206, modes: vec![
                HashInfo{ name: "KeePass 1 AES (without keyfile)", john: Some("KeePass") ,hashcat: Some("13400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN207, modes: vec![
                HashInfo{ name: "KeePass 1 TwoFish (with keyfile)", john: Some("KeePass") ,hashcat: Some("13400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN208, modes: vec![
                HashInfo{ name: "KeePass 2 AES (without keyfile)", john: Some("KeePass") ,hashcat: Some("13400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN209, modes: vec![
                HashInfo{ name: "KeePass 2 AES (with keyfile)", john: Some("KeePass") ,hashcat: Some("13400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN210, modes: vec![
                HashInfo{ name: "Open Document Format (ODF) 1.2 (SHA-256, AES)", john: None ,hashcat: Some("18400") ,variation: false ,description: None, popular: false },
      ]},
        Pattern { regex: &*PATTERN211, modes: vec![
                HashInfo{ name: "JWT (JSON Web Token)", john: None ,hashcat: Some("16500") ,variation: false ,description: None, popular: false },
      ]}]);

#[derive(Debug)]
pub struct HashInfo {
    pub name: &'static str,
    pub john: Option<&'static str>,
    pub hashcat: Option<&'static str>,
    pub variation: bool,
    pub description: Option<&'static str>,
    pub popular: bool,
}
#[derive(Debug)]
pub struct Pattern {
    pub regex: &'static Regex,
    pub modes: Vec<HashInfo>,
}
#[derive(Debug)]
pub struct HashIdentifier<'a> {
    pub patterns: &'a Vec<Pattern>,
}

impl<'a> HashIdentifier<'a> {
    pub fn new(patterns: &'a Vec<Pattern>) -> Self {
        Self { patterns }
    }
    pub fn match_pattern(&self, input: &str) -> (Vec<&HashInfo>,Vec<&HashInfo>) {
        let mut possible = vec![];
        let mut probable: Vec<&HashInfo> = vec![];
        for pattern in self.patterns {
            if pattern.regex.is_match(input.as_bytes()).expect("regex error") {
                for x in &pattern.modes {
                        if x.popular {
                                probable.push(x);
                        }
                        else {
                                possible.push(x);
                        }
                }
            }
        }
        (possible,probable)
    }
}