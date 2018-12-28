#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
extern crate rocket_contrib;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate serde;

#[macro_use]
extern crate lazy_static;

extern crate regex;
extern crate dirs;

mod helper;
mod db_tables;
mod handlebar_helpers;
mod account_management;
mod repository_mods;

use rocket::response::{Redirect, Flash, status::NotFound};
use rocket::request::{self, Form, FlashMessage, FromRequest, Request};
use rocket::http::{Cookie, Cookies, Status};
use rocket::request::{FormItems};

use rocket_contrib::{templates::Template, json::Json};

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::RwLock;

use serde::{Serialize, Deserialize};
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
}

#[derive(Debug, Serialize)]
pub struct SharedPageData {
    used_kilobytes: i32,
    total_kilobytes: i32,
}

#[derive(Debug, Serialize)]
struct ServiceData {
    enc_addr_part: String,
    env_value_list: Vec<String>,
    env_var_names_list: Vec<i32>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i32,
    pub encryption_password: String,
}

const TEMP_STORAGE_PATH: &str = "temp_download/";
const SIZE_CAP_KILOBYTES: i32 = 100 * 1000;
//const RESTIC_CACHE_PATH: &str = ".cache/restic/";

lazy_static! {
    static ref PATH_CACHE: Mutex<HashMap<(i16,String),Vec<(String,i64)>>> = Mutex::new(HashMap::new());
    static ref DOWNLOAD_IN_USE: Mutex<HashMap<i32, bool>> = Mutex::new(HashMap::new());
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
        Users::dsl::Users.filter(Users::username.eq(&login.username.to_lowercase()))
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
            Flash::error(Redirect::to("/login/"), "Username exists, invalid password though.")
        }
    } else {
        Flash::error(Redirect::to("/login/"), "Invalid username, register with the link below!.")
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
    use db_tables::{ConnectionInfo, ServiceType, BasesList, Services, EnvNames, DbBasesList, Users};

    #[derive(Serialize, Queryable)]
    struct ConInfoData {
        name: String,
        path: String,
        owning_service: String,
    }

    #[derive(Serialize, Queryable)]
    struct ServiceData {
        name: String,
        service_selected: i32,
        list_of_env_vars: String,
    }

    #[derive(Serialize)]
    struct Item {
        id: i32,
        error_msg: String,
        configs: Vec<ConInfoData>,
        flash: Option<String>,
        status: Option<String>,
        env_names: Vec<db_tables::DbEnvNames>,
        service_type: Vec<db_tables::DbServiceType>,
        services: Vec<ServiceData>,
        shared_data: SharedPageData,
    }

    let (flash, status) = match flash {
        None => (None, None),
        Some(c) => (Some(c.msg().to_owned()), Some(c.name().to_owned()))
    };

    let con = helper::est_db_con();

    let mut item = Item {
        id: user.id,
        error_msg: String::new(),
        configs: Vec::new(),
        env_names: Vec::new(),
        service_type: Vec::new(),
        flash,
        status,
        services: Vec::new(),
        shared_data: SharedPageData {
            used_kilobytes: helper::get_used_kilos(&con, user.id),
            total_kilobytes: SIZE_CAP_KILOBYTES,
        },
    };

    item.configs = ConnectionInfo::dsl::ConnectionInfo.inner_join(Services::table)
        .select((ConnectionInfo::name, ConnectionInfo::path, Services::service_name))
        .filter(ConnectionInfo::owning_user.eq(user.id))
        .order_by(ConnectionInfo::name.asc())
        .load::<ConInfoData>(&con).expect("Folder name query not going through");

    item.service_type = ServiceType::dsl::ServiceType
        .load::<db_tables::DbServiceType>(&con).expect("Service type query not working");

    item.env_names = EnvNames::dsl::EnvNames
        .load::<db_tables::DbEnvNames>(&con).expect("Service type query not working");

    item.services = {
        let temp: Vec<DbBasesList> = BasesList::dsl::BasesList
            .select((BasesList::service_name, BasesList::env_name_ids, BasesList::service_type))
            .filter(BasesList::owning_user.eq(user.id))
            .order_by(BasesList::service_name.asc())
            .load::<DbBasesList>(&con).expect("Bases List query working");

        temp.into_iter().map(|c| {
            ServiceData {
                name: c.service_name,
                list_of_env_vars: c.env_name_ids.unwrap_or(String::new()),//.split(",").map(|c_id| c_id.parse::<i32>().expect("Database not number output")).collect(),
                service_selected: c.service_type,
            }
        }).collect()
    };


    Template::render("index", &item)
}

#[get("/bucket/<_folder_name>", rank = 2)]
fn get_bucket_not_logged(_folder_name: String) -> Redirect {
    Redirect::to("/")
}

#[post("/preview/<repo_name>")]
fn preview_command(user: User, repo_name: String) -> Result<String, NotFound<String>> {
    if let Ok(mut cmd) = helper::restic_db(&repo_name, &user) {
        cmd.arg("ls")
            .arg("-l")
            .arg("latest");
        Ok(format!("{:?}", cmd))
    } else {
        Err(NotFound("Repository doesn't exist".to_owned()))
    }
}

#[get("/bucket/<repo_name>")]
fn get_bucket_data(user: User, repo_name: String) -> Result<Template, Flash<Redirect>> {
    use std::path::PathBuf;

    #[derive(Serialize)]
    struct BucketsData {
        repo_name: String,
        status_msg: String,
        files: String,
        shared_data: SharedPageData,
    }
    if let Ok(mut cmd) = helper::restic_db(&repo_name, &user) {
        let out = cmd.arg("ls")
            .arg("-l")
            .arg("latest")
            .output().unwrap();

        let error_str = String::from_utf8_lossy(&out.stderr);
        println!("Error str: {}", error_str);
        if error_str.find("b2_download_file_by_name: 404:").is_some() {
            return Err(Flash::error(
                Redirect::to("/"),
                "Repository not found, are you sure you spelt the name correctly? (Case Sensitive)"));
        }
        if error_str.find("wrong password").is_some() {
            return Err(Flash::error(
                Redirect::to("/"),
                "Repository password is incorrect"));
        }
        std::fs::write("TEST", &out.stdout).expect("WRITING PROBLEM");
        let mut all_files: Vec<(String, i64)> = String::from_utf8_lossy(&out.stdout)
            .lines().skip(1).filter_map(|c| {
            match c.chars().next().unwrap_or('s') {
                '-' => (),
                'd' => (),
                _ => return None,
            }
            let size_in_bytes: i64;
            let mut folder_path = String::new();
            {
                let mut pieces = c.split_whitespace();
                size_in_bytes = pieces.nth(3).unwrap().parse().expect("Size is not number");

                let mut path_started = false;
                for item in pieces {
                    if path_started || item.chars().next().unwrap_or('-') == '/' {
                        if path_started {
                            folder_path.push(' ');
                        }
                        path_started = true;
                        folder_path.push_str(item);
                    }
                }
            }

            if c.chars().next().expect("suddenly no next character,") == 'd' {
                folder_path.push('/');
            }
            Some((folder_path.trim().to_owned(), size_in_bytes))
        }).collect();

        let mut final_html = String::new();
        {
            let first_item = &all_files.first().expect("No files in backup").0;
            let mut cur_folder = PathBuf::from(first_item);
            if !cur_folder.is_dir() {
                cur_folder.pop();
            }
            let mut counter = 0;

            for (idx, (path_str, path_size)) in all_files.iter().enumerate() {
                let path = PathBuf::from(path_str);

                while counter != 0 && !path.starts_with(&cur_folder) {
                    if cur_folder.file_name().expect("No file name") != std::ffi::OsStr::new(" ") {
                        final_html.push_str("</ul></li>");
                        counter -= 1;
                    }
                    cur_folder.pop();
                }
                //println!("Path: {}", path_str);
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
                        &format!("<li><label><input type=\"checkbox\" data-folder-num=\"{}\"><span>{}</span><span class=\"file-size\">{:.1} KB</span></label></li>",
                                 idx, path.file_name().expect("No file name").to_str().unwrap(), *path_size as f32 * 0.001f32));
                }
            }
            for _ in 0..counter {
                final_html.push_str("</ul></li>");
            }
        }

//        std::thread::spawn(move || {
//            let mut cache_dir = dirs::cache_dir().expect("Can't get cache dir");
//            cache_dir.push("restic/");
//
//            for item in std::fs::read_dir(&cache_dir).expect("Failed to read cache dir") {
//                let item = item.expect("Failed to read cache dir entry");
//                if !item.path().is_dir() { continue; }
//                if std::time::SystemTime::now().duration_since(
//                    item.metadata().expect("Cache metadata retrieval failed").modified().unwrap()).unwrap() > std::time::Duration::from_secs(24 * 60 * 60) {}
//            }
//        });

        let mut guard = PATH_CACHE.lock().unwrap();
        guard.insert((user.id as i16, repo_name.clone()), all_files);

        Ok(Template::render("bucket",
                            BucketsData {
                                repo_name: repo_name.to_owned(),
                                status_msg: String::new(),
                                files: final_html,
                                shared_data: SharedPageData {
                                    used_kilobytes: helper::get_used_kilos(&helper::est_db_con(), user.id),
                                    total_kilobytes: SIZE_CAP_KILOBYTES,
                                },
                            }))
    } else {
        Err(Flash::error(
            Redirect::to("/"),
            format!("Repository [{}] not in repo list, add the repo in the <Add new repository> box!", repo_name)))
    }
}

#[post("/bucket/<repo_name>/download", data = "<file_paths>")]
fn download_data(user: User, repo_name: String, file_paths: Json<Vec<usize>>) -> Result<Vec<u8>, Status> {
    use std::fs;
    use db_tables::Users;
    let con = helper::est_db_con();
    let kilos_remaining = SIZE_CAP_KILOBYTES - helper::get_used_kilos(&con, user.id);

    {
        let mut down_guard = DOWNLOAD_IN_USE.lock().expect("Failed to lock download guard, another thread panic?");
        if *down_guard.get(&user.id).unwrap_or(&false) {
            return Err(Status::NotAcceptable);
        }
        down_guard.insert(user.id, true);
    }

    let download_path = format!("{}{}/", TEMP_STORAGE_PATH, user.id);
    fs::create_dir(&download_path).is_ok();
    let guard = PATH_CACHE.lock().unwrap();
    let mut cmd = if let Some(all_paths) = guard.get(&(user.id as i16, repo_name.clone())) {
        let file_paths: Vec<usize> = file_paths.into_inner();

        if let Ok(mut cmd) = helper::restic_db(&repo_name, &user) {
            cmd.arg("restore").arg("latest").arg(&format!("--target={}", &download_path));
            let total = file_paths.iter().fold(0i64, |prev, path_idx| {
                let (path, size) = &all_paths[*path_idx];
                cmd.arg("--include=".to_owned() + path);
                prev + size
            });
            if total / 1000 < kilos_remaining as i64 {
                diesel::update(Users::table.filter(Users::id.eq(user.id)))
                    .set(Users::kilobytes_downloaded.eq(SIZE_CAP_KILOBYTES - kilos_remaining + (total / 1000) as i32))
                    .execute(&con).expect("Failed to update kilobyte remaining");
                Ok(cmd)
            } else {
                Err(Status::FailedDependency)
            }
        } else {
            Err(Status::NotFound)
        }
    } else {
        Err(Status::NotFound)
    }?;
    drop(guard);

    println!("{}", String::from_utf8_lossy(&cmd.output().unwrap().stderr));

    let mut data_to_send = std::io::Cursor::new(Vec::<u8>::new());
    helper::zip_dir(&download_path, &mut data_to_send);
    let inner = data_to_send.into_inner();

    std::fs::remove_dir_all(&download_path).expect("Failed to delete files");

    DOWNLOAD_IN_USE.lock().expect("Failed to lock download guard, another thread panic?").insert(user.id, false);

    Ok(inner)
}

#[post("/logout")]
fn logout(_user: User, mut cookies: Cookies) -> Flash<Redirect> {
    cookies.remove_private(Cookie::named("user_id"));
    cookies.remove_private(Cookie::named("repo_encryption_password"));
    Flash::success(Redirect::to("/login/"), "Successfully logged out.")
}

#[post("/logout", rank = 2)]
fn logout_no_login() -> Flash<Redirect> {
    Flash::error(Redirect::to("/login/"), "Can't logout, not logged in in the first place")
}

#[get("/", rank = 2)]
fn index() -> Redirect {
    Redirect::to("/login/")
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

    diesel::insert_into(db_tables::Users::table)
        .values(&db_tables::DbUserIns {
            email: registration.email.to_lowercase().clone(),
            username: registration.username.to_lowercase().clone(),
            enced_enc_pass: helper::encrypt_base64(&enc, &registration.password, &salt),
            password,
            salt,
        }).execute(&con).expect("Not inserting into database");

    Flash::success(Redirect::to("/login/"), "Successfully Registered")
}

#[post("/retrieve/service/<service_name>")]
fn retrieve_service_data(user: User, service_name: String) -> Json<ServiceData> {
    use db_tables::{BasesList, DbBasesListReturn};
    // `line` is of type `Result<String, Error>`

    let data: DbBasesListReturn = BasesList::table.select((BasesList::env_name_ids, BasesList::encrypted_env_values, BasesList::enc_addr_part))
        .filter(BasesList::service_name.eq(service_name))
        .filter(BasesList::owning_user.eq(user.id))
        .first::<DbBasesListReturn>(&helper::est_db_con()).expect("Can't get bases list data");

    Json(ServiceData {
        enc_addr_part: helper::decrypt(&data.enc_addr_part, &user.encryption_password),
        env_value_list: data.encrypted_env_values.map_or(Vec::new(),
                                                         |c|
                                                             c.split(",")
                                                                 .map(|c| helper::decrypt(c, &user.encryption_password))
                                                                 .collect::<Vec<String>>()),
        env_var_names_list: data.env_name_ids.map_or(Vec::new(), |c| c.split(",").map(|c| c.parse::<i32>().expect("env_name_id not numbers")).collect::<Vec<i32>>()),
    })
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
               register_submit, repository_mods::add_more_repos, repository_mods::add_more_services, repository_mods::edit_service, repository_mods::edit_repo, repository_mods::delete_repo, repository_mods::delete_service, repository_mods::add_b2_preset,
               account_management::edit_account, account_management::edit_account_no_login, account_management::change_username, account_management::change_email,
               account_management::change_password, logout_no_login, files, preview_command,retrieve_service_data]).launch();
}
