#![feature(proc_macro_hygiene, decl_macro)]
#![allow(proc_macro_derive_resolution_fallback)]

#[macro_use]
extern crate rocket;
extern crate rocket_contrib;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate lazy_static;

extern crate dirs;
extern crate chrono;
extern crate time;
extern crate ring;

#[macro_use]
extern crate slog;
extern crate sloggers;

extern crate reqwest;
extern crate lettre;
extern crate flate2;

mod helper;
mod db_tables;
mod handlebar_helpers;
mod account_management;
mod repository_mods;

use rocket::response::{Redirect, Flash, status::NotFound};
use rocket::request::{FlashMessage, FromRequest, Request};
use rocket::http::Status;

use rocket_contrib::{templates::Template, json::Json};

use std::collections::HashMap;
use std::sync::Mutex;
use std::net::IpAddr;

use serde::Serialize;
use diesel::prelude::*;
use rocket::response::NamedFile;

use account_management::User;

use slog::Logger;
use sloggers::Build;
use rocket::fairing;

use helper::{google_analytics_update, Events, Pages, AnalyticsEvent};
use lettre::smtp::extension::Extension::StartTls;
use std::io::Write;

#[derive(Debug, Deserialize, Default)]
pub struct ServerConfig {
    domain: String,
    database_url: String,
    google_analytics_tid: Option<String>,
    invalid_email_domain_list_path: String,
    session_expire_age_hours: i64,
    max_login_attempts_per_ip_per_minute: u16,
    temporary_download_path: String,
    global_download_size_cap_kilobytes: i32,
}

#[derive(Debug, Serialize)]
pub struct SharedPageData {
    used_kilobytes: i32,
    total_kilobytes: i32,
}

#[derive(Debug)]
pub struct UserConInfo {
    ip: IpAddr,
    session: String,
}

impl<'a, 'r> FromRequest<'a, 'r> for UserConInfo {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> rocket::request::Outcome<UserConInfo, ()> {
        let mut cookies = request.cookies();
        let session = if let Some(session) = cookies.get("session").cloned() {
            let mut session_cookie = SESSION_TRACKER_COOKIE.clone();
            session_cookie.set_value(session.value().to_owned());
            cookies.add(session_cookie);
            session.value().to_owned()
        } else {
            let session = helper::get_random_stuff_b32(16);
            cookies.add(SESSION_TRACKER_COOKIE.clone());
            session
        };
        rocket::Outcome::Success(UserConInfo {
            ip: request.client_ip().expect("Nginx not passing real-ip?"),
            session,
        })
    }
}

pub struct Gzip;
impl fairing::Fairing for Gzip {
    fn info(&self) -> fairing::Info {
        fairing::Info {
            name: "Gzip compression",
            kind: fairing::Kind::Response,
        }
    }

    fn on_response(&self, request: &Request, response: &mut rocket::response::Response) {
        use flate2::{Compression,write::GzEncoder};
        use std::io::{Cursor, Read};
        let headers = request.headers();
        if headers
            .get("Accept-Encoding")
            .any(|e| e.to_lowercase().contains("gzip"))
        {
            response.body_bytes().and_then(|body| {
                let mut enc = GzEncoder::new(Vec::new(), Compression::default());
                enc.write_all(&body).map(|_| {
                    response.set_sized_body(Cursor::new(enc.finish().expect("Errors when finishing gzip compression")));
                    response.set_raw_header("Content-Encoding", "gzip");
                }).map_err(|e| eprintln!("{}", e)).ok()
            });
        }
    }
}

#[derive(Debug, Serialize)]
struct ServiceData {
    enc_addr_part: String,
    env_value_list: Vec<String>,
    env_var_names_list: Vec<i32>,
}

#[derive(Deserialize, Debug)]
struct ResticListOutput {
    nodes: Vec<ResticNode>,
}

#[derive(Deserialize, Debug)]
struct ResticNode {
    path: String,
    name: String,
    size: Option<u64>,
    r#type: String,
}

const CONFIG_FILE_PATH: &str = "rbs_config.json";

//const RESTIC_CACHE_PATH: &str = ".cache/restic/";

lazy_static! {
    static ref PATH_CACHE: Mutex<HashMap<(i16,String),Vec<ResticNode>>> = Mutex::new(HashMap::new());
    static ref DOWNLOAD_IN_USE: Mutex<HashMap<i32, bool>> = Mutex::new(HashMap::new());
    static ref CONNECTION_TRACKER: Mutex<HashMap<IpAddr, u16>> = Mutex::new(HashMap::new());

    static ref SESSION_TRACKER_COOKIE: rocket::http::Cookie<'static> = rocket::http::Cookie::build("session", "")
                .max_age(time::Duration::days(365 * 2))
                .path("/")
                .same_site(rocket::http::SameSite::Lax)
                .finish();
    static ref ABC: i64 = crate::SERVER_CONFIG.session_expire_age_hours;

    pub static ref SERVER_CONFIG: ServerConfig = config();

    pub static ref LOGGER: Logger = sloggers::file::FileLoggerBuilder::new("rbs_log.log")
            .format(sloggers::types::Format::Full)
            .rotate_size(50_000_000)
            .rotate_compress(true)
            .build()
            .unwrap();
//    static ref MAX_COOKIE_AGE: time::Duration = time::Duration::days(1);
}

#[get("/login")]
fn already_logged_in(_user: User) -> Redirect {
    Redirect::to("/")
}

#[get("/")]
fn user_index(user: User, con_info: UserConInfo, flash: Option<FlashMessage>) -> Result<Template, Status> {
    use db_tables::{ConnectionInfo, ServiceType, BasesList, Services, EnvNames, DbBasesList, Announcements, AnnouncementDb};

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
        announcements: Vec<AnnouncementDb>,
    }

    helper::google_analytics_update(Some(&user), &con_info, AnalyticsEvent::Page(Pages::Index));

    let (flash, status) = match flash {
        None => (None, None),
        Some(c) => (Some(c.msg().to_owned()), Some(c.name().to_owned()))
    };

    let con = helper::est_db_con().map_err(|_| Status::InternalServerError)?;

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
            total_kilobytes: SERVER_CONFIG.global_download_size_cap_kilobytes,
        },
        announcements: Vec::new(),
    };

    item.configs = ConnectionInfo::dsl::ConnectionInfo.inner_join(Services::table)
        .select((ConnectionInfo::name, ConnectionInfo::path, Services::service_name))
        .filter(ConnectionInfo::owning_user.eq(user.id))
        .order_by(ConnectionInfo::name.asc())
        .load::<ConInfoData>(&con)
        .map_err(|err| {
            error!(*LOGGER, "Folder name query not going through");
            Status::InternalServerError
        })?;

    item.service_type = ServiceType::dsl::ServiceType
        .load::<db_tables::DbServiceType>(&con).expect("Service type query not working");

    item.env_names = EnvNames::dsl::EnvNames
        .load::<db_tables::DbEnvNames>(&con).expect("Env names query not working");

    item.announcements = Announcements::table
        .filter(Announcements::displayed.eq(true))
        .load::<AnnouncementDb>(&con).expect("Announcement query not working");

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

    Ok(Template::render("index", &item))
}

#[get("/bucket/<_folder_name>", rank = 2)]
fn get_bucket_not_logged(_folder_name: String) -> Redirect {
    Redirect::to("/login")
}

#[post("/preview/<repo_name>")]
fn preview_command(user: User, con_info: UserConInfo, repo_name: String) -> Result<String, Status> {
    google_analytics_update(Some(&user), &con_info, AnalyticsEvent::Event(Events::PreviewCommand));

    if let Ok(mut cmd) = helper::restic_db(&helper::est_db_con().map_err(|_| Status::InternalServerError)?, &repo_name, &user) {
        cmd.arg("ls")
            .arg("-l")
            .arg("latest");
        Ok(format!("{:?}", cmd))
    } else {
        Err(Status::NotFound)
    }
}

#[get("/bucket/<repo_name>")]
fn get_bucket_data(user: User, con_info: UserConInfo, repo_name: String) -> Result<Template, Flash<Redirect>> {
    use std::path::PathBuf;

    #[derive(Serialize)]
    struct BucketsData {
        repo_name: String,
        status_msg: String,
        files: String,
        shared_data: SharedPageData,
    }

    google_analytics_update(Some(&user), &con_info, AnalyticsEvent::Page(Pages::Bucket));
    let con = helper::est_db_con().map_err(|_| Flash::error(Redirect::to("/"), "Internal server error"))?;
    if let Ok(mut cmd) = helper::restic_db(&con, &repo_name, &user) {
        let out = cmd.arg("--json")
            .arg("ls")
            .arg("latest")
            .output().unwrap();

        let error_str = String::from_utf8_lossy(&out.stderr);

        if out.stdout.is_empty() {
            // Returns the restic error back to the user.
            // To prevent exploits the server should be ran on a dedicated account that only has permission to the download folder and restic
            // Otherwise restic might be manipulated to output some information about the server (probably not, but just in case).
            return Err(Flash::error(
                Redirect::to("/"),
                format!("Restic error: \"{}\"", error_str)));
        }

        let all_files= match String::from_utf8_lossy(&out.stdout).lines().skip(1)
                .map(|line| serde_json::from_str::<ResticNode>(line))
                .collect::<Result<Vec<ResticNode>,serde_json::Error>>() {
            Ok(c) => c,
            Err(ref err) if !error_str.is_empty() => {
                return Err(Flash::error(
                    Redirect::to("/"),
                    format!("Restic error: \"{}\"", error_str)));
            },
            Err(ref err) => {
                error!(*LOGGER, "Restic json parsing error: {:?}", err);
                return Err(Flash::error(
                    Redirect::to("/"),
                    format!("Internal server error, please try again later.")));
            }
        };

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

        let mut final_html = String::new();
        {
            let first_item = all_files.first().expect("No files in backup");
            if first_item.r#type == "file" {
                error!(*LOGGER, "First restic json item is a file");
                panic!("First json item should not be a file...");
            }
            let mut cur_folder = PathBuf::from(&first_item.path);

//            if !cur_folder.is_dir() {
//                cur_folder.pop();
//            }
            let mut counter = 0;

            for (idx, item) in all_files.iter().enumerate() {
                let path = PathBuf::from(&item.path);
                while counter != 0 && !path.starts_with(&cur_folder) {
                    final_html.push_str("</ul></li>");
                    counter -= 1;
                    cur_folder.pop();
                }

                //println!("Path: {}", path_str);
                if item.r#type == "dir" {
                    //path.strip_prefix(&cur_folder).unwrap().components().for_each(|c| {
                    final_html.push_str(
                        &format!("<li><label><input type=\"checkbox\" data-folder-num=\"{}\"><span>{}</span></label><ul>",
                                 idx, item.name));
                    counter += 1;
                    //});
                    cur_folder = path;
                } else if item.r#type == "file" {
//                    println!("Stuff: {:?}", item);
                    final_html.push_str(
                        &format!("<li><label><input type=\"checkbox\" data-folder-num=\"{}\"><span>{}</span><span class=\"file-size\">{:.1} KB</span></label></li>",
                                 idx, item.name, item.size.unwrap_or_default() as f32 * 0.001f32));
                } else {
                    error!(*LOGGER, "restic JSON output file type unexpected: {}", item.r#type);
                    panic!("restic JSON output file type unexpected: {}", item.r#type);
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
                                    used_kilobytes: helper::get_used_kilos(&con, user.id),
                                    total_kilobytes: SERVER_CONFIG.global_download_size_cap_kilobytes,
                                },
                            }))
    } else {
        Err(Flash::error(
            Redirect::to("/"),
            format!("Repository [{}] not in repo list, add the repo in the <Add new repository> box!", repo_name)))
    }
}

#[post("/bucket/<repo_name>/download", data = "<file_paths>")]
fn download_data(user: User, con_info: UserConInfo, repo_name: String, file_paths: Json<Vec<usize>>) -> Result<Vec<u8>, Status> {
    use std::fs;
    use db_tables::Users;

    google_analytics_update(Some(&user), &con_info, AnalyticsEvent::Event(Events::Download));

    let con = helper::est_db_con().map_err(|_| Status::InternalServerError)?;
    let kilos_remaining = SERVER_CONFIG.global_download_size_cap_kilobytes - helper::get_used_kilos(&con, user.id);

    {
        let mut down_guard = DOWNLOAD_IN_USE.lock().expect("Failed to lock download guard, another thread panic?");
        if *down_guard.get(&user.id).unwrap_or(&false) {
            return Err(Status::NotAcceptable);
        }
        down_guard.insert(user.id, true);
    }

    let download_path = format!("{}{}-{}/", SERVER_CONFIG.temporary_download_path, user.id, helper::get_random_stuff_b32(4));
    fs::create_dir(&download_path).is_ok();
    let guard = PATH_CACHE.lock().unwrap();
    let mut cmd = if let Some(all_paths) = guard.get(&(user.id as i16, repo_name.clone())) {
        let file_paths: Vec<usize> = file_paths.into_inner();

        if let Ok(mut cmd) = helper::restic_db(&con, &repo_name, &user) {
            cmd.arg("restore").arg("latest").arg(&format!("--target={}", &download_path));
            let total = file_paths.iter().fold(0u64, |prev, path_idx| {
                let elem = &all_paths[*path_idx];
                cmd.arg("--include=".to_owned() + &elem.path);
                prev + elem.size.unwrap_or_default()
            });
            if total / 1000 < kilos_remaining as u64 {
                diesel::update(Users::table.filter(Users::id.eq(user.id)))
                    .set(Users::kilobytes_downloaded.eq(SERVER_CONFIG.global_download_size_cap_kilobytes - kilos_remaining + (total / 1000) as i32))
                    .execute(&con)
                    .map_err(|err| error!(*LOGGER, "Error updating kilo_remaining: {:?}", err))
                    .expect("Error updating kilo_remaining");
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

    std::fs::remove_dir_all(&download_path)
        .map_err(|err| error!(*LOGGER, "Failed to remove dir"))
        .is_ok();

    DOWNLOAD_IN_USE.lock().expect("Failed to lock download guard, another thread panic?").insert(user.id, false);

    Ok(inner)
}

#[post("/logout", rank = 2)]
fn logout_no_login() -> Flash<Redirect> {
    Flash::error(Redirect::to("/login/"), "Can't logout, not logged in in the first place")
}

#[get("/", rank = 2)]
fn index() -> Redirect {
    Redirect::to("/home/")
}

#[post("/retrieve/service/<service_name>")]
fn retrieve_service_data(user: User, service_name: String) -> Result<Json<ServiceData>, Status> {
    use db_tables::{BasesList, DbBasesListReturn};
    // `line` is of type `Result<String, Error>`
    let data: DbBasesListReturn = BasesList::table.select((BasesList::env_name_ids, BasesList::encrypted_env_values, BasesList::enc_addr_part))
        .filter(BasesList::service_name.eq(service_name))
        .filter(BasesList::owning_user.eq(user.id))
        .first::<DbBasesListReturn>(&helper::est_db_con().map_err(|_| Status::InternalServerError)?).expect("Can't get bases list data");

    Ok(Json(ServiceData {
        enc_addr_part: helper::decrypt(&data.enc_addr_part, &user.encryption_password),
        env_value_list: data.encrypted_env_values.map_or(Vec::new(),
                                                         |c|
                                                             c.split(",")
                                                                 .map(|c| helper::decrypt(c, &user.encryption_password))
                                                                 .collect::<Vec<String>>()),
        env_var_names_list: data.env_name_ids.map_or(Vec::new(), |c| c.split(",").map(|c| c.parse::<i32>().expect("env_name_id not numbers")).collect::<Vec<i32>>()),
    }))
}

#[get("/public/<file..>")]
fn files(file: std::path::PathBuf) -> Option<NamedFile> {
    NamedFile::open(std::path::Path::new("public/").join(file)).ok()
}

#[get("/home")]
fn home(user: Option<User>, con_info: UserConInfo) -> Template {
    #[derive(Serialize)]
    struct HomePageInfo {
        logged_in: bool
    }

    google_analytics_update(user.as_ref(), &con_info, AnalyticsEvent::Page(Pages::Home));

    Template::render("home", HomePageInfo {
        logged_in: user.is_some()
    })
}

// This is probably not the best way to do things, any alternatives to using a global uninitialized variable appreciated
//pub static mut SERVER_CONFIG: ServerConfig = ServerConfig {..Default::default()};

fn config() -> ServerConfig {
    serde_json::from_str(
        &std::fs::read_to_string(CONFIG_FILE_PATH).expect("Failed to open config file"))
        .expect("Config file format invalid")
}

#[catch(500)]
fn internal_error() -> &'static str {
    "Whoops! Looks like we messed up."
}

fn main() {
    println!("{:#?}", *SERVER_CONFIG);

    std::thread::spawn(move || {
        loop {
            { CONNECTION_TRACKER.lock().unwrap().clear(); }
            if helper::google_analytics_send().is_err() {
                error!(*LOGGER, "Failed to send analytics data");
            }
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    });

    rocket::ignite()
        .attach(Template::custom(|engines| {
            engines.handlebars.register_helper("url_encode", Box::new(handlebar_helpers::url_encode_helper));
            engines.handlebars.register_helper("to_uppercase", Box::new(handlebar_helpers::to_upper_helper));
        }))
        .attach(Gzip)
        .mount("/",
               routes![
                    index,
                    user_index,
                    already_logged_in,
                    get_bucket_data,
                    get_bucket_not_logged,
                    download_data,
                    logout_no_login,
                    files,
                    preview_command,
                    retrieve_service_data,
                    home,

                    account_management::logout,
                    account_management::login_page,
                    account_management::login,
                    account_management::register,
                    account_management::register_submit,
                    account_management::edit_account,
                    account_management::edit_account_no_login,
                    account_management::change_username,
                    account_management::change_email,
                    account_management::act_email_change,
                    account_management::act_email_change_post,
                    account_management::change_password,
                    account_management::verify_email,
                    account_management::enable_2fa,
                    account_management::disable_2fa,
                    account_management::confirm_2fa,
                    account_management::login_already_logged,

                    repository_mods::add_more_repos,
                    repository_mods::add_more_services,
                    repository_mods::edit_service,
                    repository_mods::edit_repo,
                    repository_mods::delete_repo,
                    repository_mods::delete_service,
                    repository_mods::add_b2_preset
                    ])
        .register(catchers![internal_error])
        .launch();
}
