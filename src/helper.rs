extern crate walkdir;
extern crate zip;

extern crate ring;
extern crate base64;
extern crate diesel;

use ::db_tables;

use ::std;
use std::path::Path;
use std::io::{Write, Read};

use diesel::prelude::*;

use std::process::Command;

const DATABASE_URL: &str = include_str!("../database_url");

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
    use helper::ring::aead::CHACHA20_POLY1305;

    let mut nonce = base64::decode(&nonce).unwrap();
    let mut key = [0; 32];
//    let temp = nonce.last_mut()
    {
        let temp = nonce.last_mut().unwrap();
        *temp = temp.wrapping_add(1);
    };

    let sealing_key = ring::aead::SealingKey::new(&CHACHA20_POLY1305, &key).unwrap();

    let mut data = Vec::from(plain_txt.as_bytes());
    data.extend(vec![0u8; ring::aead::CHACHA20_POLY1305.tag_len()]);

    ring::pbkdf2::derive(&ring::digest::SHA256, 100_000, nonce.as_ref(), password.as_bytes(), &mut key);

    {
        let temp = nonce.last_mut().unwrap();
        *temp = temp.wrapping_add(1);
    };

    let len = ring::aead::seal_in_place(&sealing_key, nonce.as_ref(), &[], data.as_mut(), ring::aead::CHACHA20_POLY1305.tag_len()).expect("a");

    base64::encode(&data)
}

pub fn decrypt_base64(cipher_txt: &str, password: &str, nonce: &str) -> String {
    use helper::ring::aead::CHACHA20_POLY1305;

    let mut nonce = base64::decode(&nonce).unwrap();
    let mut key = [0; 32];
//    let temp = nonce.last_mut()
    {
        let temp = nonce.last_mut().unwrap();
        *temp = temp.wrapping_add(1);
    };

    ring::pbkdf2::derive(&ring::digest::SHA256, 100_000, nonce.as_ref(), password.as_bytes(), &mut key);

    let opening_key = ring::aead::OpeningKey::new(&CHACHA20_POLY1305, &key).unwrap();
    let mut data = base64::decode(cipher_txt).unwrap();

    {
        let temp = nonce.last_mut().unwrap();
        *temp = temp.wrapping_add(1);
    }

    let out = ring::aead::open_in_place(&opening_key, nonce.as_ref(), &[], 0, data.as_mut()).expect("b");

    String::from_utf8_lossy(out).to_string()
}

pub fn encrypt(plain_txt: &str, key: &str) -> String {
    use helper::ring::rand::SecureRandom;
    use helper::ring::aead::CHACHA20_POLY1305;

    let key = base64::decode(key).unwrap();
    let mut nonce = [0u8; 8];
    ring::rand::SystemRandom::new().fill(&mut nonce).unwrap();
    let sealing_key = ring::aead::SealingKey::new(&CHACHA20_POLY1305, &key).unwrap();

    let mut data = Vec::from(plain_txt.as_bytes());
    data.extend(vec![0u8; ring::aead::CHACHA20_POLY1305.tag_len()]);

    let len = ring::aead::seal_in_place(&sealing_key, nonce.as_ref(), &[], data.as_mut(), ring::aead::CHACHA20_POLY1305.tag_len()).expect("a");

    data.extend(&nonce);
    base64::encode(&data)
}

pub fn decrypt(cipher_txt: &str, key: &str) -> String {
    use helper::ring::rand::SecureRandom;
    use helper::ring::aead::CHACHA20_POLY1305;

    let key = base64::decode(key).unwrap();

    let opening_key = ring::aead::OpeningKey::new(&CHACHA20_POLY1305, &key).unwrap();

    let mut data = base64::decode(cipher_txt).unwrap();
    let mut nonce = Vec::new();
    nonce.copy_from_slice(&data[data.len() - 8..]);
    let len = data.len();
    let out = ring::aead::open_in_place(&opening_key, nonce.as_ref(), &[], 0, data[..len - 8].as_mut()).expect("b");
    String::from_utf8_lossy(out).to_string()
}

pub fn restic(b2_acc_key: &str, b2_acc_id: &str, b2_bucket_name: &str, folder: &str, pass: &str) -> Command {
    let mut b2_command = std::process::Command::new("restic");
    b2_command.env("B2_ACCOUNT_KEY", b2_acc_key)
        .env("B2_ACCOUNT_ID", b2_acc_id)
        .env("RESTIC_PASSWORD", pass)
        .arg("-r").arg(format!("b2:{}:{}", b2_bucket_name, folder));

    b2_command
}

pub fn est_db_con() -> diesel::MysqlConnection {
    diesel::MysqlConnection::establish(DATABASE_URL).expect("Can't connect to database")
}

pub fn encrypt_password(password: &str) -> (String, String) {
    use helper::ring::rand::SecureRandom;

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

pub fn restic_db(folder_name: &str,user: &::User) -> Result<Command, ()> {
    use db_tables::{Users, ConnectionInfo};

    let con = est_db_con();
    let data: Vec<db_tables::DbEncryptedData> = Users::dsl::Users.inner_join(ConnectionInfo::table)
        .select((Users::b2_bucket_name, Users::b2_acc_key, Users::b2_acc_id, ConnectionInfo::name, ConnectionInfo::encryption_password))
        .filter(Users::id.eq(user.id as i32))
        .filter(&ConnectionInfo::name.eq(folder_name))
        .load::<db_tables::DbEncryptedData>(&con).expect("Failed to connect with db");

    if data.is_empty() {
        return Err(());
    }

    let data = data.first().unwrap();

    Ok(restic(&data.b2_acc_key,
              &data.b2_acc_id,
              &data.b2_bucket_name,
              &folder_name,
              &decrypt(&data.encryption_password, &user.encryption_password)))
}

pub fn get_random_stuff(length: usize) -> String {
    use helper::ring::rand::SecureRandom;

    let mut store: Vec<u8> = Vec::new();
    store.resize(length, 0u8);

    ring::rand::SystemRandom::new().fill(store.as_mut()).unwrap();

    base64::encode(&store)
}