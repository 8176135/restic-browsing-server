extern crate walkdir;
extern crate zip;

extern crate base64;
extern crate diesel;
extern crate regex;

extern crate lettre;

use ::db_tables;
use crate::LOGGER;

use ::std;
use std::path::Path;
use std::io::{Write, Read};

use diesel::prelude::*;

use std::process::Command;
use std::sync::{Mutex, RwLock};
use std::time::SystemTime;
use ring::rand::{SystemRandom, SecureRandom};

use self::regex::Regex;

lazy_static! {
   static ref EMAIL_DOMAIN_CACHE: RwLock<(SystemTime, Vec<String>)> = RwLock::new((SystemTime::UNIX_EPOCH, Vec::new()));
   static ref DUPLICATE_KEY_MSG_SEPERATOR: Regex = Regex::new(r#"Duplicate entry '(.*?[^\\]?)' for key '(.*?[^\\]?)'"#).unwrap();
   pub static ref SECURE_RANDOM_GEN: SystemRandom = ring::rand::SystemRandom::new();
   pub static ref ANALYTICS_ENTRIES: Mutex<Vec<String>> = Mutex::new(Vec::new());
}

pub fn zip_dir<T>(path: &str, writer: &mut T) -> bool
    where T: std::io::Write + std::io::Seek {
    zip_dir_internal(
        &mut walkdir::WalkDir::new(&path)
            .into_iter().filter_map(|e| e.ok()),
        path, writer).map_err(|err| {
        error!(*LOGGER, "Failed to zip up dir: {}", err);
        err
    }).is_err()
}

fn zip_dir_internal<T>(it: &mut Iterator<Item=walkdir::DirEntry>, prefix: &str, writer: &mut T)
                       -> zip::result::ZipResult<()>
    where T: ::std::io::Write + std::io::Seek
{
    use std::fs::File;

    let mut zip = zip::ZipWriter::new(writer);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Bzip2)
        .unix_permissions(0o755);

    let mut buffer = Vec::new();
    for entry in it {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(prefix))
            .unwrap()
            .to_str()
            .unwrap();

        if path.is_file() {
            println!("adding {:?} as {:?} ...", path, name);
            zip.start_file(name, options)?;
            let mut f = File::open(path)?;

            f.read_to_end(&mut buffer)?;
            zip.write_all(&*buffer)?;
            buffer.clear();
        }
    }
    zip.finish()?;
    Result::Ok(())
}

pub fn delete_dir_contents(read_dir_res: Result<std::fs::ReadDir, std::io::Error>) {
    if let Ok(dir) = read_dir_res {
        for entry in dir {
            if let Ok(entry) = entry {
                let path = entry.path();

                if path.is_dir() {
                    std::fs::remove_dir_all(path).expect("Failed to remove a dir");
                } else {
                    std::fs::remove_file(path).expect("Failed to remove a file");
                }
            };
        }
    };
}

//pub fn encrypt(cipher_txt: &str, password: &str)

pub fn encrypt_base64(plain_txt: &str, password: &str, nonce: &str) -> String {
    use ring::aead::CHACHA20_POLY1305;

    let mut nonce = base64::decode(&nonce).unwrap();
    let mut key = [0; 32];
//    let temp = nonce.last_mut()
    {
        let temp = nonce.first_mut().unwrap();
        *temp = temp.wrapping_add(1);
    };

    ring::pbkdf2::derive(&ring::digest::SHA256, 100_000, nonce.as_ref(), password.as_bytes(), &mut key);
    let sealing_key = ring::aead::SealingKey::new(&CHACHA20_POLY1305, &key).unwrap();

    let mut data = Vec::from(plain_txt.as_bytes());
    data.extend(vec![0u8; ring::aead::CHACHA20_POLY1305.tag_len()]);

    {
        let temp = nonce.first_mut().unwrap();
        *temp = temp.wrapping_add(1);
    };

    ring::aead::seal_in_place(&sealing_key, &nonce[..CHACHA20_POLY1305.nonce_len()], &[], data.as_mut(), CHACHA20_POLY1305.tag_len()).expect("a_64");

    base64::encode(&data)
}

// Adds one to the salt..?
pub fn decrypt_base64(cipher_txt: &str, password: &str, nonce: &str) -> String {
    use ring::aead::CHACHA20_POLY1305;

    let mut nonce = base64::decode(&nonce).unwrap();
    let mut key = [0; 32];
//    let temp = nonce.last_mut()
    {
        let temp = nonce.first_mut().unwrap();
        *temp = temp.wrapping_add(1);
    };

    ring::pbkdf2::derive(&ring::digest::SHA256, 100_000, nonce.as_ref(), password.as_bytes(), &mut key);

    let opening_key = ring::aead::OpeningKey::new(&CHACHA20_POLY1305, &key).unwrap();
    let mut data = base64::decode(cipher_txt).unwrap();

    {
        let temp = nonce.first_mut().unwrap();
        *temp = temp.wrapping_add(1);
    }

    let out = ring::aead::open_in_place(&opening_key, &nonce[..CHACHA20_POLY1305.nonce_len()], &[], 0, data.as_mut()).expect("b_64");

    String::from_utf8_lossy(out).to_string()
}

pub fn encrypt(plain_txt: &str, key: &str) -> String {
    use ring::rand::SecureRandom;
    use ring::aead::CHACHA20_POLY1305;

    let key = base64::decode(key).unwrap();
    println!("{:?}", key.len());
    let mut nonce = vec![0u8; CHACHA20_POLY1305.nonce_len()];
    SECURE_RANDOM_GEN.fill(&mut nonce).unwrap();
    let sealing_key = ring::aead::SealingKey::new(&CHACHA20_POLY1305, &key).unwrap();

    let mut data = Vec::from(plain_txt.as_bytes());
    data.extend(vec![0u8; CHACHA20_POLY1305.tag_len()]);

    ring::aead::seal_in_place(&sealing_key, nonce.as_ref(), &[], data.as_mut(), ring::aead::CHACHA20_POLY1305.tag_len()).expect("a");

    data.extend(&nonce);
    base64::encode(&data)
}

pub fn decrypt(cipher_txt: &str, key: &str) -> String {
    use ring::aead::CHACHA20_POLY1305;

    let key = base64::decode(key).unwrap();

    let opening_key = ring::aead::OpeningKey::new(&CHACHA20_POLY1305, &key).unwrap();

    let mut data = base64::decode(cipher_txt).unwrap();

    let len = data.len();
    let (in_place, nonce) = data.split_at_mut(len - CHACHA20_POLY1305.nonce_len());

    let out = ring::aead::open_in_place(&opening_key, nonce, &[], 0, in_place).expect("decryption failed");
    String::from_utf8_lossy(out).to_string()
}

pub fn restic(env_vars: &std::collections::HashMap<String, String>, service_type: &str, link: &str, path: &str, pass: &str) -> Command {
    let mut b2_command = std::process::Command::new("restic");

    b2_command.env("RESTIC_PASSWORD", pass)
        .envs(env_vars)
        .arg("-r").arg(format!("{}:{}{}", service_type, link, path));
//        .arg("--no-cache");
    b2_command
}

pub fn est_db_con() -> Result<diesel::MysqlConnection, ()> {
    diesel::MysqlConnection::establish(&crate::SERVER_CONFIG.database_url).map_err(|err| error!(*LOGGER, "Failed to connect to database"))
}

pub fn encrypt_password(password: &str) -> (String, String) {
    use ring::rand::SecureRandom;

    let mut salt_buffer = Vec::new();
    let mut output = [0u8; ring::digest::SHA256_OUTPUT_LEN];
    salt_buffer.resize(16, 0u8);
    SECURE_RANDOM_GEN.fill(salt_buffer.as_mut()).expect("Not generating random salt");
    ring::pbkdf2::derive(&ring::digest::SHA256, 100_000, salt_buffer.as_ref(), password.as_bytes(), output.as_mut());
    (base64::encode(&output), base64::encode(&salt_buffer))
}

pub fn verify_user(db_entry: &db_tables::DbUserLogin, password_candi: &str) -> bool {
    ring::pbkdf2::verify(&ring::digest::SHA256, 100_000,
                         base64::decode(&db_entry.salt).unwrap().as_ref(),
                         password_candi.as_bytes(),
                         base64::decode(&db_entry.password).unwrap().as_ref()).is_ok()
}

pub fn restic_db(con: &MysqlConnection, repo_name: &str, user: &::User) -> Result<Command, ()> {
    use db_tables::QueryView;

    //let con = est_db_con()?;

    let data: Vec<db_tables::DbQueryView> = QueryView::dsl::QueryView
        .filter(QueryView::owning_user.eq(user.id))
        .filter(QueryView::name.eq(repo_name))
        .load::<db_tables::DbQueryView>(con).expect("Can't select QueryView");

    if data.is_empty() {
        return Err(());
    }
    let first = &data[0];

    Ok(restic(
        &data.iter().filter_map(|c| {
            if let Some(ref enc_env_value) = c.encrypted_env_value {
                Some((c.env_name.clone().unwrap(), decrypt(enc_env_value, &user.encryption_password)))
            } else {
                None
            }
        }).collect(),
        &first.service_type,
        &decrypt(&first.enc_addr_part, &user.encryption_password),
        &first.path,
        &decrypt(&first.encryption_password, &user.encryption_password)))
}

pub fn get_used_kilos(con: &diesel::MysqlConnection, user_id: i32) -> i32 {
    use db_tables::Users;

    Users::table
        .select(Users::kilobytes_downloaded)
        .filter(Users::id.eq(user_id))
        .first::<i32>(con).expect("Failed to load used kilobytes")
}

pub fn get_random_stuff(length: usize) -> String {
    use ring::rand::SecureRandom;

    let mut store: Vec<u8> = Vec::new();
    store.resize(length, 0u8);

    SECURE_RANDOM_GEN.fill(store.as_mut()).unwrap();

    base64::encode(&store)
}

pub fn get_random_stuff_b32(length: usize) -> String {
    use ring::rand::SecureRandom;

    let mut store: Vec<u8> = Vec::new();
    store.resize(length, 0u8);

    SECURE_RANDOM_GEN.fill(store.as_mut()).unwrap();

    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &store)
}

//#[derive(PartialEq)]
pub enum IsUnique<T> {
    NonUnique(String),
    Unique(T),
}

pub fn check_for_unique_error<T>(res: Result<T, diesel::result::Error>) -> Result<IsUnique<T>, diesel::result::Error> {
    match res {
        Ok(c) => Ok(IsUnique::Unique(c)),
        Err(e) => {
            match e {
                diesel::result::Error::DatabaseError(de, de_info) => {
                    if let diesel::result::DatabaseErrorKind::UniqueViolation = de {
                        Ok(IsUnique::NonUnique(
                            DUPLICATE_KEY_MSG_SEPERATOR.captures(de_info.message()).expect("Database unique error message changed")
                                .get(2).expect("Key name in msg empty").as_str().to_owned()))
                    } else {
                        Err(diesel::result::Error::DatabaseError(de, de_info))
                    }
                }
                _ => Err(e)
            }
        }
    }
}

pub fn check_email_domain(domain: &str) -> bool {
    let email_domains_last_modified =
        if let Ok(c) = std::fs::metadata(&crate::SERVER_CONFIG.invalid_email_domain_list_path) {
            c.modified().unwrap()
        } else {
            error!(*LOGGER, "Failed to load email domain list");
            return true;
        };

    let cache_lock = EMAIL_DOMAIN_CACHE.read().unwrap();

    if email_domains_last_modified.duration_since(cache_lock.0).unwrap_or_else(|_| {
        error!(*LOGGER, "Metadata email duration not later than cache");
        std::time::Duration::from_secs(999)
    }).as_secs() > 60 {
        drop(cache_lock);
        let mut cache_lock = EMAIL_DOMAIN_CACHE.write().unwrap();
        *cache_lock = (email_domains_last_modified, std::fs::read_to_string(&crate::SERVER_CONFIG.invalid_email_domain_list_path)
            .unwrap_or_else(|_| {
                error!(*LOGGER, "Failed to read email domain to string");
                String::new()
            }).lines()
            .map(|c| c.to_owned())
            .collect::<Vec<String>>());
        cache_lock.1.binary_search(&domain.to_owned()).is_err()
    } else {
        cache_lock.1.binary_search(&domain.to_owned()).is_err()
    }
}

pub fn send_email(email: &str, title: &str, contents: &str) -> Result<self::lettre::smtp::response::Response, lettre::smtp::error::Error> {
    use self::lettre::{SendableEmail, Envelope, SmtpTransport, EmailAddress, SmtpClient, Transport};
    let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let time = base64::encode(&[((time >> 56) & 0xff) as u8,
        ((time >> 48) & 0xff) as u8,
        ((time >> 40) & 0xff) as u8,
        ((time >> 32) & 0xff) as u8,
        ((time >> 24) & 0xff) as u8,
        ((time >> 16) & 0xff) as u8,
        ((time >> 8) & 0xff) as u8,
        ((time) & 0xff) as u8,
    ]);

    let random_part = get_random_stuff(8);

    SmtpTransport::new(
        //TODO: Re-add security after I figure out how lettre works
        SmtpClient::new("127.0.0.1:25", lettre::ClientSecurity::None).expect("Failed to construct SmtpClient"))
        .send(SendableEmail::new(
            Envelope::new(
                Some(EmailAddress::new("noreply@handofcthulhu.com".to_owned()).unwrap()),
                vec![EmailAddress::new(email.to_owned()).unwrap()]).unwrap(),
            format!("<{}.{}@handofcthulhu.com>", time, random_part),
            format!("Subject: {}\n\n{}", title, contents).into_bytes(),
        ))

//    format!(r#"Subject: Account Activation - Restic Browser
//
//Hello {}, copy and paste the link below into your url bar to activate your account (I haven't figured out html emails yet)
//Activation link: {}"#,).to_vec()
}

pub fn totp_check(secret: &[u8], guess: u32) -> bool {
    totp_internal(secret, SystemTime::now(), std::time::Duration::from_secs(::account_management::TWO_FACTOR_AUTH_TIME_WINDOW as u64), ::account_management::TWO_FACTOR_AUTH_DIGITS, guess)
}

fn totp_internal(secret: &[u8], time: SystemTime, window_seconds: std::time::Duration, digits: u32, guess: u32) -> bool {
    let counter = time.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / window_seconds.as_secs();

    let key = ring::hmac::SigningKey::new(&ring::digest::SHA1, secret);
    (-1..=1).any(|offset| {
        let counter = (counter as i64 + offset) as u64;
        let hmac_message: &[u8; 8] = &[
            ((counter >> 56) & 0xff) as u8,
            ((counter >> 48) & 0xff) as u8,
            ((counter >> 40) & 0xff) as u8,
            ((counter >> 32) & 0xff) as u8,
            ((counter >> 24) & 0xff) as u8,
            ((counter >> 16) & 0xff) as u8,
            ((counter >> 8) & 0xff) as u8,
            ((counter >> 0) & 0xff) as u8,
        ];
        println!("WOO: {}", offset);
        let data = ring::hmac::sign(&key, hmac_message);
        let data = data.as_ref();

        let dynamic_offset = (data[data.len() - 1] & (0xf as u8)) as usize;

        let truncated: u32 = (((data[dynamic_offset] as u32) & 0x7f) << 24
            | (data[dynamic_offset + 1] as u32) << 16
            | (data[dynamic_offset + 2] as u32) << 8
            | (data[dynamic_offset + 3] as u32)
        ) as u32 % 10u32.pow(digits);

        truncated == guess
    })
}

use crate::account_management::User;
use crate::UserConInfo;
use time::Duration;

pub enum AnalyticsEvent {
    Event(Events),
    Page(Pages),
}

pub enum Events {
    LoginSuccess,
    LoginFail,
    EmailChange,
    PasswordChange,
    Download,
    PreviewCommand,
}

pub enum Pages {
    Login,
    Index,
    Home,
    Bucket,
    Account,
    Register,
}

pub fn google_analytics_update(user: Option<&User>, user_info: &UserConInfo, ae: AnalyticsEvent) {
    if let Some(ref tid) = crate::SERVER_CONFIG.google_analytics_tid {
        let mut guard = ANALYTICS_ENTRIES.lock().unwrap();
        match ae {
            AnalyticsEvent::Event(ev) => {
                let uniform = format!("v=1&t={kind}&dh={host}&tid={tid}&cid={cid}&uid={uid}&uip={ip}",
                                      kind = "event",
                                      tid = tid,
                                      host = crate::SERVER_CONFIG.domain,
                                      uid = user.map(|user| user.id).unwrap_or(std::i32::MAX),
                                      cid = user_info.session,
                                      ip = get_masked_ip(&user_info.ip));
                match ev {
                    Events::LoginSuccess => {
                        guard.push(format!("{uniform}&ec={event_category}&ea={event_action}",
                                           uniform = uniform,
                                           event_category = "Auth",
                                           event_action = "Login Success"));
                    }
                    Events::LoginFail => {
                        guard.push(format!("{uniform}&ec={event_category}&ea={event_action}",
                                           uniform = uniform,
                                           event_category = "Auth",
                                           event_action = "Login Fail"));
                    }
                    Events::PasswordChange => {
                        guard.push(format!("{uniform}&ec={event_category}&ea={event_action}",
                                           uniform = uniform,
                                           event_category = "Account",
                                           event_action = "Password Change"));
                    }
                    Events::EmailChange => {
                        guard.push(format!("{uniform}&ec={event_category}&ea={event_action}",
                                           uniform = uniform,
                                           event_category = "Account",
                                           event_action = "Email Change"));
                    }
                    Events::Download => {
                        guard.push(format!("{uniform}&ec={event_category}&ea={event_action}",
                                           uniform = uniform,
                                           event_category = "Service Action",
                                           event_action = "Download"));
                    }
                    Events::PreviewCommand => {
                        guard.push(format!("{uniform}&ec={event_category}&ea={event_action}",
                                           uniform = uniform,
                                           event_category = "Service Action",
                                           event_action = "Preview Command"));
                    }
                }
            }
            AnalyticsEvent::Page(pg) => {
                let uniform = format!("v=1&t={kind}&dh={host}&tid={tid}&cid={cid}&uid={uid}&uip={ip}",
                                      kind = "pageview",
                                      tid = tid,
                                      host = crate::SERVER_CONFIG.domain,
                                      uid = user.map(|user| user.id).unwrap_or(std::i32::MAX),
                                      cid = user_info.session,
                                      ip = get_masked_ip(&user_info.ip));

                match pg {
                    Pages::Login => {
                        guard.push(format!("{uniform}&dt={document_title}&dp={document_path}",
                                           uniform = uniform,
                                           document_path = urlencoding::encode("/login"),
                                           document_title = urlencoding::encode("Login")
                        ))
                    }
                    Pages::Home => {
                        guard.push(format!("{uniform}&dt={document_title}&dp={document_path}",
                                           uniform = uniform,
                                           document_path = urlencoding::encode("/home"),
                                           document_title = urlencoding::encode("Home")
                        ))
                    }
                    Pages::Account => {
                        guard.push(format!("{uniform}&dt={document_title}&dp={document_path}",
                                           uniform = uniform,
                                           document_path = urlencoding::encode("/account"),
                                           document_title = urlencoding::encode("Account Management")
                        ))
                    }
                    Pages::Index => {
                        guard.push(format!("{uniform}&dt={document_title}&dp={document_path}",
                                           uniform = uniform,
                                           document_path = urlencoding::encode("/"),
                                           document_title = urlencoding::encode("Main Page")
                        ))
                    }
                    Pages::Bucket => {
                        guard.push(format!("{uniform}&dt={document_title}&dp={document_path}",
                                           uniform = uniform,
                                           document_path = urlencoding::encode("/bucket/"),
                                           document_title = urlencoding::encode("Bucket")
                        ))
                    }
                    Pages::Register => {
                        guard.push(format!("{uniform}&dt={document_title}&dp={document_path}",
                                           uniform = uniform,
                                           document_path = urlencoding::encode("/register/"),
                                           document_title = urlencoding::encode("Register")
                        ))
                    }
                }
            }
        }
    }
}

pub fn google_analytics_send() -> Result<(), ()> {
    let mut guard = ANALYTICS_ENTRIES.lock().unwrap();

    if guard.is_empty() {
        return Ok(());
    }
    // Max 20 hits can be in one batch
    for chunk in guard.chunks(20) {
        let mut client = reqwest::Client::new()
            .post("https://www.google-analytics.com/batch")
            .body(chunk.iter().fold(String::new(), |acc, current| {
                println!("{}", current);
                acc + "\n" + current
            })).send().map_err(|err| ())?;
        println!("{:?}", client);
    }

    guard.clear();
    Ok(())
}

fn get_masked_ip(ip: &std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let mut original_ip = u32::from(*ip);
            original_ip &= 0xFF_FF_FF;
            original_ip.to_string()
        }
        std::net::IpAddr::V6(ip) => {
            let mut original_ip = u128::from(*ip);
            original_ip &= 0xFF_FF_FF;
            original_ip.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_same_thing() {
        let original = get_random_stuff(32);
        let pass = get_random_stuff(32);
        assert_eq!(decrypt(&encrypt(&original, &pass), &pass), original);
    }

    #[test]
    fn totp_test() {
        let secret = base32::decode(base32::Alphabet::RFC4648 { padding: false }, "JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(
            totp_internal(&secret,
                          SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1550201023),
                          std::time::Duration::from_secs(::account_management::TWO_FACTOR_AUTH_TIME_WINDOW as u64),
                          ::account_management::TWO_FACTOR_AUTH_DIGITS,
                          211437),
            true);
    }
}

//pub fn extract_form_array_data() -> Vec<db_tables::ServiceContentIns> {
//
//}