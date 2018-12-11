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
mod account_management;

use rocket::response::{Redirect, Flash, status::NotFound};
use rocket::request::{self, Form, FlashMessage, FromRequest, Request};
use rocket::http::{Cookie, Cookies};
use rocket::request::{FromForm, FormItems};

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
}

#[derive(FromForm)]
struct AddNewRepoForm {
    new_repo_name: String,
    new_repo_path: String,
    new_repo_password: String,
    owning_service: String,
}

#[derive(Debug)]
struct AddNewServiceForm {
    enc_addr_part: String,
    env_value_list: Vec<String>,
    env_var_names_list: Vec<i32>,
    new_service_name: String,
    service_type: i32,
}

impl<'f> FromForm<'f> for AddNewServiceForm {
    // In practice, we'd use a more descriptive error type.
    type Error = ();

    fn from_form(items: &mut FormItems<'f>, strict: bool) -> Result<AddNewServiceForm, ()> {
        let mut ans = AddNewServiceForm {
            enc_addr_part: String::new(),
            new_service_name: String::new(),
            service_type: 0,
            env_value_list: Vec::new(),
            env_var_names_list: Vec::new(),
        };

        for item in items {
            println!("{:?}", item);
            match item.key.as_str() {
                "enc_addr_part" => {
                    let decoded = item.value.url_decode().map_err(|_| ())?;
                    ans.enc_addr_part = decoded;
                }
                "new_service_name" => {
                    let decoded = item.value.url_decode().map_err(|_| ())?;
                    ans.new_service_name = decoded;
                }
                "service_type" => {
                    let decoded = item.value.url_decode().map_err(|_| ())?;
                    ans.service_type = decoded.parse().map_err(|_| ())?;
                }
                "env_value_list" => {
                    let decoded = item.value.url_decode().map_err(|_| ())?;
                    ans.env_value_list.push(decoded);
                }
                "env_var_names_list" => {
                    let decoded = item.value.url_decode().map_err(|_| ())?;
                    ans.env_var_names_list.push(decoded.parse().map_err(|_| ())?);
                }
                _ if strict => return Err(()),
                _ => { /* allow extra value when not strict */ }
            }
        }
        Ok(ans)
    }
}

#[derive(FromForm)]
struct EditRepoForm {
    edit_repo_name: String,
    edit_repo_path: String,
    edit_repo_password: String,
    owning_service: String,
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
    use db_tables::{ConnectionInfo, ServiceType, BasesList, Services, EnvNames, DbBasesList};

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
    }

    let (flash, status) = match flash {
        None => (None, None),
        Some(c) => (Some(c.msg().to_owned()), Some(c.name().to_owned()))
    };

    let mut item = Item {
        id: user.id,
        error_msg: String::new(),
        configs: Vec::new(),
        env_names: Vec::new(),
        service_type: Vec::new(),
        flash,
        status,
        services: Vec::new(),
    };

    let con = helper::est_db_con();

    item.configs = ConnectionInfo::dsl::ConnectionInfo.inner_join(Services::table)
        .select((ConnectionInfo::name, ConnectionInfo::path, Services::service_name))
        .filter(ConnectionInfo::owning_user.eq(user.id))
        .load::<ConInfoData>(&con).expect("Folder name query not going through");

    item.service_type = ServiceType::dsl::ServiceType
        .load::<db_tables::DbServiceType>(&con).expect("Service type query not working");

    item.env_names = EnvNames::dsl::EnvNames
        .load::<db_tables::DbEnvNames>(&con).expect("Service type query not working");

    item.services = {
        let temp: Vec<DbBasesList> = BasesList::dsl::BasesList
            .select((BasesList::service_name, BasesList::env_name_ids, BasesList::service_type))
            .filter(BasesList::owning_user.eq(user.id))
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
            if c.chars().next().expect("suddenly no next character,") == 'd' {
                folder_path.push('/');
            }
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
                    if cur_folder.file_name().expect("No file name") != std::ffi::OsStr::new(" ") {
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
                                 idx, path.file_name().expect("No file name").to_str().unwrap()));
                }
            }
            for _ in 0..counter {
                final_html.push_str("</ul></li>");
            }
        }

        let mut guard = PATH_CACHE.lock().unwrap();
        guard.insert((user.id as i16, repo_name.clone()), all_files);

        Ok(Template::render("bucket",
                            BucketsData {
                                repo_name: repo_name.to_owned(),
                                status_msg: String::new(),
                                files: final_html,
                            }))
    } else {
        Err(Flash::error(
            Redirect::to("/"),
            format!("Repository [{}] not in repo list, add the repo in the <Add new repository> box!", repo_name)))
    }
}

#[post("/bucket/<repo_name>/download", data = "<file_paths>")]
fn download_data(user: User, repo_name: String, file_paths: Json<Vec<usize>>) -> Result<Vec<u8>, NotFound<String>> {
    use std::fs;
    let guard = PATH_CACHE.lock().unwrap();
    if let Some(all_paths) = guard.get(&(user.id as i16, repo_name.clone())) {
        let file_paths: Vec<usize> = file_paths.into_inner();

        if let Ok(mut cmd) = helper::restic_db(&repo_name, &user) {
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

#[post("/edit/repo/<repo_name>", data = "<new_data>")]
fn edit_repo(user: User, repo_name: String, new_data: Form<EditRepoForm>) -> Flash<Redirect> {
    if repo_name.trim().is_empty() || new_data.edit_repo_name.trim().is_empty() {
        return Flash::error(Redirect::to("/"), "Error: repo name can not be empty");
    }
    let con = helper::est_db_con();
    let repo_pass = if new_data.edit_repo_password.is_empty() { None } else { Some(helper::encrypt(&new_data.edit_repo_password, &user.encryption_password)) };
    diesel::select(db_tables::update_repositories(&new_data.owning_service, user.id, &new_data.edit_repo_name, &repo_name, &new_data.edit_repo_path, repo_pass))
        .execute(&con).unwrap();

    Flash::success(Redirect::to("/"), format!("Successfully edited repository <{}>", new_data.edit_repo_name))
}

#[post("/delete/repo/<repo_name>")]
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

#[post("/add/repo", data = "<name>")]
fn add_more_repos(user: User, name: Form<AddNewRepoForm>) -> Flash<Redirect> {
    use db_tables::{Services, update_repositories};

    if name.new_repo_name.trim().is_empty() {
        return Flash::error(Redirect::to("/"), "Error: repo name can not be empty");
    }

    let con = helper::est_db_con();
    println!("{}", name.owning_service);
    diesel::select(update_repositories(&name.owning_service, user.id, &name.new_repo_name, &name.new_repo_name, &name.new_repo_path, helper::encrypt(&name.new_repo_password, &user.encryption_password)))
        .execute(&con).unwrap();
//    let service_id = Services::dsl::Services.select(Services::id)
//        .filter(Services::service_name.eq(&name.owning_service))
//        .filter(Services::owning_user.eq(user.id))
//        .first::<i32>(&con)
//        .expect("Failed to get service id from service name");
//
//    let insert_result = diesel::insert_into(db_tables::ConnectionInfo::table)
//        .values(&db_tables::ConnectionInfoIns {
//            owning_user: user.id,
//            name: name.new_repo_name.clone(),
//            encryption_password: helper::encrypt(&name.new_repo_password, &user.encryption_password),
//            service_used: service_id,
//        }).execute(&con);
//
//    use helper::IsUnique::*;
//    match helper::check_for_unique_error(insert_result).expect("Failed to add new repository") {
//        Unique(_) => Flash::success(Redirect::to("/"), "Successfully added new repository"),
//        NonUnique => {
//            Flash::error(Redirect::to("/"), "New repository name already exists.")
//        }
//    }
    Flash::success(Redirect::to("/"), "Successfully added new repository")
}

#[post("/add/service", data = "<name>")]
fn add_more_services(user: User, name: Form<AddNewServiceForm>) -> Flash<Redirect> {
//    println!("{:?}", name);
    if name.new_service_name.trim().is_empty() {
        return Flash::error(Redirect::to("/"), "Error: Service name can not be empty");
    }
    use db_tables::{Services, ServiceContents, ServicesIns, ServiceContentIns};
    let con = helper::est_db_con();

    let service_insert_result = diesel::insert_into(Services::table)
        .values(ServicesIns {
            owning_user: user.id,
            service_name: name.new_service_name.clone(),
            enc_addr_part: helper::encrypt(&name.enc_addr_part, &user.encryption_password),
            service_type: name.service_type,
        })
        .execute(&con);

    use helper::IsUnique::*;
    match helper::check_for_unique_error(service_insert_result).expect("Failed to add new service") {
        NonUnique => { return Flash::error(Redirect::to("/"), "New service name already exists."); }
        _ => {}
    }

    let last_gen_id: i32 = diesel::select(db_tables::last_insert_id).first(&con).unwrap();
//    println!("{}", last_gen_id);
    let combined: Vec<ServiceContentIns> = name.env_value_list.iter().zip(name.env_var_names_list.iter())
        .map(|c| ServiceContentIns {
            env_name_id: c.1.to_owned(),
            encrypted_env_value: helper::encrypt(c.0, &user.encryption_password).to_owned(),
            owning_service: last_gen_id,
        }).collect();

    let contents_insert_result = diesel::insert_into(ServiceContents::table)
        .values(&combined)
        .execute(&con);

    match helper::check_for_unique_error(contents_insert_result).expect("Failed to add new service") {
        Unique(_) => Flash::success(Redirect::to("/"), "Successfully added new service"),
        NonUnique => {
            Flash::error(Redirect::to("/"), "New repository name already exists.")
        }
    }
}

#[post("/edit/service/<service_name>", data = "<new_data>")]
fn edit_service(user: User, service_name: String, new_data: Form<AddNewServiceForm>) -> Flash<Redirect> {
    println!("{:?}", new_data);
    if new_data.new_service_name.trim().is_empty() {
        return Flash::error(Redirect::to("/"), "Error: Service name can not be empty");
    }
    let con = helper::est_db_con();

    use db_tables::{Services, ServiceContentIns, ServiceContents};

    let service_id: i32 = Services::table.filter(Services::service_name.eq(&service_name)).filter(Services::owning_user.eq(user.id))
        .select(Services::id)
        .first::<i32>(&con).expect("Can't find existing service to edit");

    let combined: Vec<ServiceContentIns> = new_data.env_value_list.iter().zip(new_data.env_var_names_list.iter())
        .filter_map(|c| {
            if c.0.is_empty() { None } else {
                Some(ServiceContentIns {
                    env_name_id: c.1.to_owned(),
                    encrypted_env_value: helper::encrypt(c.0, &user.encryption_password).to_owned(),
                    owning_service: service_id,
                })
            }
        }).collect();

    let to_set = (Services::service_name.eq(&new_data.new_service_name), Services::service_type.eq(new_data.service_type));
    let updater =
        diesel::update(Services::table.filter(Services::id.eq(service_id)));

    if new_data.enc_addr_part.is_empty() {
        updater.set(to_set)
            .execute(&con).expect("Failed to update service without encrypted password");
    } else {
        updater.set((to_set.0, to_set.1, Services::enc_addr_part.eq(helper::encrypt(&new_data.enc_addr_part, &user.encryption_password))))
            .execute(&con).expect("Failed to update service with encrypted password");
    }

    println!("{:?}", combined);

    diesel::delete(ServiceContents::table
        .filter(ServiceContents::owning_service.eq(service_id))
        .filter(ServiceContents::env_name_id.ne_all(&new_data.env_var_names_list)))
        .execute(&con).expect("Failed to delete non-present records");

    diesel::replace_into(ServiceContents::table)
        .values(combined)
        .execute(&con)
        .expect("Failed to replace stuff");

    Flash::success(Redirect::to("/"), "Service Edited")
}

#[post("/delete/service/<service_name>")]
fn delete_service(user: User, service_name: String) -> Flash<Redirect> {
    use db_tables::Services;

    let con = helper::est_db_con();

    let num_deleted = diesel::delete(
        Services::dsl::Services.filter(Services::service_name.eq(&service_name))
            .filter(Services::owning_user.eq(user.id)))
        .execute(&con).expect("Error sending delete to database");

    if num_deleted == 0 {
        Flash::error(Redirect::to("/"),
                     &format!("Failed to delete [{}] service, doesn't seem to exist in the first place", service_name))
    } else {
        Flash::success(Redirect::to("/"), &format!("Deleted [{}] Service", service_name))
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
               register_submit, add_more_repos, add_more_services, files, edit_repo, delete_repo, delete_service, account_management::edit_account,
               account_management::edit_account_no_login, account_management::change_username, account_management::change_email,
               account_management::change_password, logout_no_login, edit_service, preview_command]).launch();
}
