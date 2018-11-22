#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
extern crate rocket_contrib;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate serde_derive;
extern crate serde;

#[macro_use]
extern crate lazy_static;

extern crate regex;

mod helper;
mod db_tables;
mod handlebar_helpers;

use rocket::response::{Redirect, Flash, status::NotFound};
use rocket::request::{self, Form, FlashMessage, FromRequest, Request};
use rocket::http::{Cookie, Cookies};

use rocket_contrib::{templates::Template, json::Json};

use std::collections::HashMap;
use std::sync::Mutex;

use diesel::prelude::*;
use rocket::response::NamedFile;

use regex::Regex;

#[derive(FromForm)]
struct Login {
    username: String,
    password: String,
}

#[derive(FromForm)]
struct Registration {
    username: String,
    password: String,
    email: String,
    b2_acc_key: String,
    b2_acc_id: String,
    b2_bucket_name: String,
}

#[derive(FromForm)]
struct AddNewForm {
    new_repo_name: String,
    new_repo_password: String,
}

#[derive(FromForm)]
struct EditRepoForm {
    edit_repo_name: String,
    edit_repo_password: String,
}

#[derive(Debug)]
pub struct User {
    pub id: i32,
    pub encryption_password: String,
}

const TEMP_STORAGE_PATH: &str = "temp_download/";

lazy_static! {
    static ref PATH_CACHE: Mutex<HashMap<(i16,String),Vec<String>>> = Mutex::new(HashMap::new());
    static ref B2_APP_KEY_TEST: Regex = Regex::new("[^\\w\\/+=-]").unwrap();
    static ref B2_APP_ID_TEST: Regex = Regex::new("[^\\da-fA-F]").unwrap();
    static ref B2_BUCKET_NAME_TEST: Regex = Regex::new("[^\\w-.\\/]").unwrap();
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> request::Outcome<User, ()> {
        use rocket::Outcome;

        let encryption_password = request.cookies().get_private("repo_encryption_password")
            .and_then(|cookie| cookie.value().parse().ok());
        let id = request.cookies().get_private("user_id")
            .and_then(|cookie| cookie.value().parse().ok());

        if encryption_password.is_none() || id.is_none() {
            Outcome::Forward(())
        } else {
            Outcome::Success(User {
                id: id.unwrap(),
                encryption_password: encryption_password.unwrap(),
            })
        }
    }
}

#[post("/login", data = "<login>")]
fn login(mut cookies: Cookies, login: Form<Login>) -> Flash<Redirect> {
    use db_tables::Users;

    let con = helper::est_db_con();
    let login_candidate: Option<db_tables::DbUserLogin> =
        Users::dsl::Users.filter(Users::username.eq(&login.username))
            .select((Users::id, Users::password, Users::salt, Users::enced_enc_pass))
            .load::<db_tables::DbUserLogin>(&con).expect("Failed to connect with db").first().cloned();

    if let Some(login_candidate) = login_candidate {
        if helper::verify_user(&login_candidate, &login.password) {
            cookies.add_private(Cookie::new("user_id", login_candidate.id.to_string()));
            cookies.add_private(Cookie::new("repo_encryption_password",
                                            helper::decrypt_base64(
                                                &login_candidate.enced_enc_pass,
                                                &login.password,
                                                &login_candidate.salt)));
            Flash::success(Redirect::to("/"), "Successfully logged in.")
        } else {
            Flash::error(Redirect::to("/login"), "Username exists, invalid password though.")
        }
    } else {
        Flash::error(Redirect::to("/login"), "Invalid username, register with the link below!.")
    }
}

#[get("/login", rank = 2)]
fn login_page(flash: Option<FlashMessage>) -> Template {
    let mut context = HashMap::new();
    if let Some(ref msg) = flash {
        context.insert("flash", msg.msg());
    }
    Template::render("login", context)
}

#[get("/login")]
fn already_logged_in(_user: User) -> Redirect {
    Redirect::to("/")
}

#[get("/")]
fn user_index(user: User, flash: Option<FlashMessage>) -> Template {
    use db_tables::ConnectionInfo;

    #[derive(Serialize)]
    struct Item {
        id: i32,
        error_msg: String,
        configs: Vec<String>,
        flash: Option<String>,
        status: Option<String>,
    }

    let (flash, status) = match flash {
        None => (None, None),
        Some(c) => (Some(c.msg().to_owned()), Some(c.name().to_owned()))
    };
    let mut item = Item {
        id: user.id,
        error_msg: String::new(),
        configs: Vec::new(),
        flash,
        status,
    };
    item.configs = ConnectionInfo::dsl::ConnectionInfo.select(ConnectionInfo::name)
        .filter(ConnectionInfo::owning_user.eq(user.id))
        .load::<String>(&helper::est_db_con()).expect("Folder name query not going through");

    Template::render("index", &item)
}

#[get("/bucket/<_folder_name>", rank = 2)]
fn get_bucket_not_logged(_folder_name: String) -> Redirect {
    Redirect::to("/")
}

#[get("/bucket/<folder_name>")]
fn get_bucket_data(user: User, folder_name: String) -> Result<Template, Flash<Redirect>> {
    use std::path::PathBuf;
    #[derive(Serialize)]
    struct BucketsData {
        repo_name: String,
        status_msg: String,
        files: String,
    }
    if let Ok(mut cmd) = helper::restic_db(&folder_name, &user) {
        let out = cmd.arg("ls")
            .arg("-l")
            .arg("latest")
            .output().unwrap();

        let error_str = String::from_utf8_lossy(&out.stderr);
        println!("Error str: {}", error_str);
        if error_str.find("b2_download_file_by_name: 404:").is_some() {
            return Err(Flash::error(
                Redirect::to("/"),
                "Repository not found on B2, are you sure you spelt the name correctly? (Case Sensitive)"));
        }
        if error_str.find("wrong password").is_some() {
            return Err(Flash::error(
                Redirect::to("/"),
                "Repository password is incorrect"));
        }
        let mut all_files: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines().skip(1).map(|c| {
            let mut path_started = false;
            let mut folder_path = String::new();
            for item in c.split(" ") {
                if path_started || item.chars().next().unwrap_or('-') == '/' {
                    if path_started {
                        folder_path.push(' ');
                    }
                    path_started = true;
                    folder_path.push_str(item);
                }
            }
            if c.chars().next().unwrap() == 'd' {
                folder_path.push('/');
            }
//            println!("folder_path: {}", folder_path);
            folder_path.trim().to_owned()
        }).collect();

        let mut final_html = String::new();
        {
            let first_item = all_files.first().expect("No files in backup");
            let mut cur_folder = PathBuf::from(first_item);
            if !cur_folder.is_dir() {
                cur_folder.pop();
            }
            let mut counter = 0;

            for (idx, path_str) in all_files.iter().enumerate() {
                let path = PathBuf::from(path_str);

                while counter != 0 && !path.starts_with(&cur_folder) {
                    if cur_folder.file_name().unwrap() != std::ffi::OsStr::new(" ") {
                        final_html.push_str("</ul></li>");
                        counter -= 1;
                    }
                    cur_folder.pop();
                }
                if path_str.ends_with('/') {
                    path.strip_prefix(&cur_folder).unwrap().components().for_each(|c| {
                        final_html.push_str(
                            &format!("<li><label><input type=\"checkbox\" data-folder-num=\"{}\"><span>{}</span></label><ul>",
                                     idx, c.as_os_str().to_str().unwrap()));
                        counter += 1;
                    });
                    cur_folder = path;
                } else {
                    final_html.push_str(
                        &format!("<li><label><input type=\"checkbox\" data-folder-num=\"{}\"><span>{}</span></label></li>",
                                 idx, path.file_name().unwrap().to_str().unwrap()));
                }
            }
            for _ in 0..counter {
                final_html.push_str("</ul></li>");
            }
        }

        let mut guard = PATH_CACHE.lock().unwrap();
        guard.insert((user.id as i16, folder_name.clone()), all_files);

        Ok(Template::render("bucket",
                            BucketsData {
                                repo_name: folder_name.to_owned(),
                                status_msg: String::new(),
                                files: final_html,
                            }))
    } else {
        Err(Flash::error(
            Redirect::to("/"),
            format!("Repository [{}] not in repo list, add the repo in the <Add new repository> box!", folder_name)))
    }
}

#[post("/bucket/<folder_name>/download", data = "<file_paths>")]
fn download_data(user: User, folder_name: String, file_paths: Json<Vec<usize>>) -> Result<Vec<u8>, NotFound<String>> {
    use std::fs;
    let guard = PATH_CACHE.lock().unwrap();
    if let Some(all_paths) = guard.get(&(user.id as i16, folder_name.clone())) {
        let file_paths: Vec<usize> = file_paths.into_inner();

        if let Ok(mut cmd) = helper::restic_db(&folder_name, &user) {
            helper::delete_dir_contents(fs::read_dir(TEMP_STORAGE_PATH));

            cmd.arg("restore").arg("latest").arg(&format!("--target={}", TEMP_STORAGE_PATH));
            for path_idx in file_paths {
                let path = &all_paths[path_idx];
                cmd.arg("--include=".to_owned() + path);
            }

            println!("{}", String::from_utf8_lossy(&cmd.output().unwrap().stderr));
            let mut data_to_send = std::io::Cursor::new(Vec::<u8>::new());
            helper::zip_dir(TEMP_STORAGE_PATH, &mut data_to_send);

            Ok(data_to_send.into_inner())
        } else {
            Err(NotFound("No bucket by this number".to_owned()))
        }
    } else {
        Err(NotFound("Woop".to_owned()))
    }
}

#[post("/logout")]
fn logout(_user: User, mut cookies: Cookies) -> Flash<Redirect> {
    cookies.remove_private(Cookie::named("user_id"));
    Flash::success(Redirect::to("/login"), "Successfully logged out.")
}

#[get("/", rank = 2)]
fn index() -> Redirect {
    Redirect::to("/login")
}

#[get("/register")]
fn register() -> Template {
    Template::render("signup", ())
}

#[post("/register_submit", data = "<registration>")]
fn register_submit(registration: Form<Registration>) -> Flash<Redirect> {
    let con = helper::est_db_con();
    let (password, salt) = helper::encrypt_password(&registration.password);

    let enc = helper::get_random_stuff(32);

    if B2_APP_KEY_TEST.is_match(&registration.b2_acc_key) {
        return Flash::error(Redirect::to("/register"), "Invalid characters in Account/App Key");
    }

    if B2_APP_ID_TEST.is_match(&registration.b2_acc_id) {
        return Flash::error(Redirect::to("/register"), "Invalid characters in Account/App ID");
    }

    if B2_BUCKET_NAME_TEST.is_match(&registration.b2_bucket_name) {
        return Flash::error(Redirect::to("/register"), "Invalid characters in Bucket Name");
    }

    diesel::insert_into(db_tables::Users::table)
        .values(&db_tables::DbUserIns {
            email: registration.email.clone(),
            username: registration.username.clone(),
            enced_enc_pass: helper::encrypt_base64(&enc, &registration.password, &salt),
            b2_acc_id: helper::encrypt(&registration.b2_acc_id, &enc),
            b2_acc_key: helper::encrypt(&registration.b2_acc_key, &enc),
            password,
            salt,
            b2_bucket_name: registration.b2_bucket_name.clone(),
        }).execute(&con).expect("Not inserting into database");

    Flash::success(Redirect::to("/login"), "Successfully Registered")
}

#[post("/edit_repo/<repo_name>", data = "<new_data>")]
fn edit_repo(user: User, repo_name: String, new_data: Form<EditRepoForm>) -> Flash<Redirect> {
    let con = helper::est_db_con();
    if repo_name.trim().is_empty() || new_data.edit_repo_name.trim().is_empty() {
        return Flash::error(Redirect::to("/"), "Error: repo name can not be empty");
    }
    use db_tables::ConnectionInfo::dsl::*;
    let update_statement = diesel::update(
        ConnectionInfo.filter(owning_user.eq(user.id)).filter(name.eq(&repo_name)));

    let update_result;

    if new_data.edit_repo_password.is_empty() {
        if repo_name == new_data.edit_repo_name {
            return Flash::error(Redirect::to("/"), "Repo name and password is the same, so nothing happened");
        }
        update_result = update_statement.set(name.eq(&new_data.edit_repo_name)).execute(&con)
    } else {
        update_result = update_statement.set((name.eq(&new_data.edit_repo_name),
                                              encryption_password.eq(&helper::encrypt(
                                                  &new_data.edit_repo_password, &user.encryption_password)))).execute(&con)
    }

    match update_result {
        Ok(_) => Flash::success(Redirect::to("/"), "Successfully edited repository"),
        Err(e) => {
            match e {
                diesel::result::Error::DatabaseError(e, _) => {
                    if let diesel::result::DatabaseErrorKind::UniqueViolation = e {
                        Flash::error(Redirect::to("/"), "New repository name already exists.")
                    } else {
                        Flash::error(Redirect::to("/"), "Failed to edit repository")
                    }
                }
                _ => Flash::error(Redirect::to("/"), "Failed to edit repository")
            }
        }
    }
}

#[post("/delete/<repo_name>")]
fn delete_repo(user: User, repo_name: String) -> Flash<Redirect> {
    use db_tables::ConnectionInfo::dsl::*;

    let con = helper::est_db_con();

    let num_deleted = diesel::delete(
        ConnectionInfo
            .filter(name.eq(&repo_name))
            .filter(owning_user.eq(user.id)))
        .execute(&con).expect("Error sending delete to database");

    if num_deleted == 0 {
        Flash::error(Redirect::to("/"),
                     &format!("Failed to delete [{}] repository, doesn't seem to exist in the first place", repo_name))
    } else {
        Flash::success(Redirect::to("/"), &format!("Deleted [{}] Repository", repo_name))
    }
}

#[post("/add_repo", data = "<name>")]
fn add_more_repos(user: User, name: Form<AddNewForm>) -> Flash<Redirect> {
    let insert_result = diesel::insert_into(db_tables::ConnectionInfo::table)
        .values(&db_tables::ConnectionInfoIns {
            owning_user: user.id,
            name: name.new_repo_name.clone(),
            encryption_password: helper::encrypt(&name.new_repo_password, &user.encryption_password),
        }).execute(&helper::est_db_con());

    match insert_result {
        Ok(_) => Flash::success(Redirect::to("/"), "Successfully added new repository"),
        Err(e) => {
            match e {
                diesel::result::Error::DatabaseError(e, _) => {
                    if let diesel::result::DatabaseErrorKind::UniqueViolation = e {
                        Flash::error(Redirect::to("/"), "New repository name already exists.")
                    } else {
                        Flash::error(Redirect::to("/"), "Failed to add new repository")
                    }
                }
                _ => Flash::error(Redirect::to("/"), "Failed to add new repository")
            }
        }
    }
}

#[get("/public/<file..>")]
fn files(file: std::path::PathBuf) -> Option<NamedFile> {
    NamedFile::open(std::path::Path::new("public/").join(file)).ok()
}

fn main() {
    rocket::ignite()
        .attach(Template::custom(|engines| {
            engines.handlebars.register_helper("url_encode", Box::new(handlebar_helpers::url_encode_helper));
            engines.handlebars.register_helper("to_uppercase", Box::new(handlebar_helpers::to_upper_helper));
        }))
        .mount("/",
               routes![index, logout, user_index, login_page, already_logged_in
               ,login, get_bucket_data, get_bucket_not_logged, download_data, register,
               register_submit, add_more_repos, files, edit_repo, delete_repo]).launch();
}
