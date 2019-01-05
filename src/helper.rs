extern crate walkdir;
extern crate zip;

extern crate ring;
extern crate base64;
extern crate diesel;
extern crate regex;

extern crate lettre;

use ::db_tables;

use ::std;
use std::path::Path;
use std::io::{Write, Read};

use diesel::prelude::*;

use std::process::Command;
use std::sync::RwLock;
use std::time::SystemTime;

use self::regex::Regex;

const DATABASE_URL: &str = include_str!("../database_url");

lazy_static! {
   static ref EMAIL_DOMAIN_CACHE: RwLock<(SystemTime, Vec<String>)> = RwLock::new((SystemTime::UNIX_EPOCH, Vec::new()));
   static ref DUPLICATE_KEY_MSG_SEPERATOR: Regex = Regex::new(r#"Duplicate entry '(.*?[^\\]?)' for key '(.*?[^\\]?)'"#).unwrap();
}

pub fn zip_dir<T>(path: &str, writer: &mut T)
    where T: std::io::Write + std::io::Seek {
    zip_dir_internal(
        &mut walkdir::WalkDir::new(&path)
            .into_iter().filter_map(|e| e.ok()),
        path, writer).expect("WTF");
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
    use self::ring::aead::CHACHA20_POLY1305;

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

pub fn decrypt_base64(cipher_txt: &str, password: &str, nonce: &str) -> String {
    use self::ring::aead::CHACHA20_POLY1305;

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
    use self::ring::rand::SecureRandom;
    use self::ring::aead::CHACHA20_POLY1305;

    let key = base64::decode(key).unwrap();
    let mut nonce = vec![0u8; CHACHA20_POLY1305.nonce_len()];
    ring::rand::SystemRandom::new().fill(&mut nonce).unwrap();
    let sealing_key = ring::aead::SealingKey::new(&CHACHA20_POLY1305, &key).unwrap();

    let mut data = Vec::from(plain_txt.as_bytes());
    data.extend(vec![0u8; CHACHA20_POLY1305.tag_len()]);

    ring::aead::seal_in_place(&sealing_key, nonce.as_ref(), &[], data.as_mut(), ring::aead::CHACHA20_POLY1305.tag_len()).expect("a");

    data.extend(&nonce);
    base64::encode(&data)
}

pub fn decrypt(cipher_txt: &str, key: &str) -> String {
    use self::ring::aead::CHACHA20_POLY1305;

    let key = base64::decode(key).unwrap();

    let opening_key = ring::aead::OpeningKey::new(&CHACHA20_POLY1305, &key).unwrap();

    let mut data = base64::decode(cipher_txt).unwrap();

    let len = data.len();
    let (in_place, nonce) = data.split_at_mut(len - CHACHA20_POLY1305.nonce_len());

    let out = ring::aead::open_in_place(&opening_key, nonce, &[], 0, in_place).expect("b");
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

pub fn est_db_con() -> diesel::MysqlConnection {
    diesel::MysqlConnection::establish(DATABASE_URL).expect("Can't connect to database")
}

pub fn encrypt_password(password: &str) -> (String, String) {
    use self::ring::rand::SecureRandom;

    let mut salt_buffer = Vec::new();
    let mut output = [0u8; ring::digest::SHA256_OUTPUT_LEN];
    salt_buffer.resize(16, 0u8);
    ring::rand::SystemRandom::new().fill(salt_buffer.as_mut()).expect("Not generating random salt");
    ring::pbkdf2::derive(&ring::digest::SHA256, 100_000, salt_buffer.as_ref(), password.as_bytes(), output.as_mut());
    (base64::encode(&output), base64::encode(&salt_buffer))
}

pub fn verify_user(db_entry: &db_tables::DbUserLogin, password_candi: &str) -> bool {
    ring::pbkdf2::verify(&ring::digest::SHA256, 100_000,
                         base64::decode(&db_entry.salt).unwrap().as_ref(),
                         password_candi.as_bytes(),
                         base64::decode(&db_entry.password).unwrap().as_ref()).is_ok()
}

pub fn restic_db(repo_name: &str, user: &::User) -> Result<Command, ()> {
    use db_tables::QueryView;

    let con = est_db_con();

    let data: Vec<db_tables::DbQueryView> = QueryView::dsl::QueryView
        .filter(QueryView::owning_user.eq(user.id))
        .filter(QueryView::name.eq(repo_name))
        .load::<db_tables::DbQueryView>(&con).expect("Can't select QueryView");

    if data.is_empty() {
        return Err(());
    }
    let first = &data[0];

    Ok(restic(
        &data.iter().map(|c| (c.env_name.clone(), decrypt(&c.encrypted_env_value, &user.encryption_password))).collect(),
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
    use self::ring::rand::SecureRandom;

    let mut store: Vec<u8> = Vec::new();
    store.resize(length, 0u8);

    ring::rand::SystemRandom::new().fill(store.as_mut()).unwrap();

    base64::encode(&store)
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

const INVALID_EMAIL_DOMAINS: &str = "disposable-email-domains/disposable_email_blocklist.conf";

pub fn check_email_domain(email: &str) -> bool {
    let domain: &str = email.split("@").nth(1).unwrap();

    let email_domains_last_modified = std::fs::metadata(INVALID_EMAIL_DOMAINS)
        .expect("Failed to load email domains metadata").modified()
        .unwrap();

    let cache_lock = EMAIL_DOMAIN_CACHE.read().unwrap();

    if email_domains_last_modified.duration_since(cache_lock.0).expect("Metadata email duration not later than cache").as_secs() > 60 {
        drop(cache_lock);
        let mut cache_lock = EMAIL_DOMAIN_CACHE.write().unwrap();
        *cache_lock = (email_domains_last_modified, std::fs::read_to_string(INVALID_EMAIL_DOMAINS).expect("Failed to read email blacklist").lines().map(|c| c.to_owned()).collect::<Vec<String>>());
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
        SmtpClient::new_simple("handofcthulhu.com").expect("Failed to construct simple SmtpClient"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_same_thing() {
        let original = get_random_stuff(123);
        let pass = get_random_stuff(50);
        assert_eq!(decrypt(&encrypt(&original, &pass), &pass), original);
    }
}

//pub fn extract_form_array_data() -> Vec<db_tables::ServiceContentIns> {
//
//}