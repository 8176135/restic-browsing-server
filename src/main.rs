#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

//#[macro_use]
extern crate rocket;
extern crate rocket_contrib;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate serde_derive;
extern crate serde;

#[macro_use]
extern crate lazy_static;

mod helper;
mod db_tables;

use rocket::outcome::IntoOutcome;
use rocket::response::{Redirect, Flash, status::NotFound};
use rocket::request::{self, Form, FlashMessage, FromRequest, Request};
use rocket::http::{Cookie, Cookies};

use rocket_contrib::Template;
use rocket_contrib::Json;

use std::collections::HashMap;
use std::sync::Mutex;

use diesel::prelude::*;

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

#[derive(Debug)]
pub struct User {
    pub id: usize,
    pub encryption_password: String,
}

const TEMP_STORAGE_PATH: &str = "temp_download/";

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
        Users::dsl::Users.filter(Users::username.eq(&login.get().username))
            .select(db_tables::DbUserLogin)
            .load::<db_tables::DbUserLogin>(&con).expect("Failed to connect with db").first().cloned();

    if let Some(login_candidate) = login_candidate {
        if helper::verify_user(&login_candidate, &login.get().password) {
            cookies.add_private(Cookie::new("user_id", login_candidate.user_id.to_string()));
            cookies.add_private(Cookie::new("repo_encryption_password", helper::decrypt_base64(&login_candidate.enced_enc_pass, &login.get().password, &login_candidate.salt)));
            Flash::success(Redirect::to("/"), "Successfully logged in.")
        } else {
            Flash::error(Redirect::to("/login"), "Username exists, invalid password though.")
        }
    } else {
        Flash::error(Redirect::to("/login"), "Invalid username, register with the link below!.")
    }

//    if login.get().username == "hocthulhu" && login.get().password == "2446" {
//        cookies.add_private(Cookie::new("user_id", 1.to_string()));
//        Flash::success(Redirect::to("/"), "Successfully logged in.")
//    } else {
//        Flash::error(Redirect::to("/login"), "Invalid username/password.")
//    }
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
fn login_user(_user: User) -> Redirect {
    Redirect::to("/")
}

#[get("/")]
fn user_index(user: User) -> Template {
    #[derive(Serialize)]
    struct Item {
        id: usize,
        error_msg: String,
        configs: Vec<String>,
    }

    let mut item = Item { id: user.id, error_msg: String::new(), configs: Vec::new() };

    if let Ok(txt) = std::fs::read_to_string(format!("resources/user{}.configs", user.id)) {
        item.configs = txt.lines().map(|c| c.to_owned()).collect()
        //item.configs = split_lines.clone().filter_map(|(i, c)| if i % 2 == 0 { Some(c.to_owned()) } else { None }).collect();
//        user.paths = split_lines.filter_map(|(i, c)| if i % 2 == 1 { Some(c.to_owned()) } else { None }).collect();
//        println!("{}", split_lines.size_hint().0);
//        item.configs = split_lines
//            .fold(Vec::with_capacity(split_lines.size_hint().0),
//                  |mut acc, c| {
//            acc.push(c);
//        })
    } else {
        item.error_msg = "No configs atm".to_owned();
    }

    Template::render("index", &item)
}

#[get("/bucket/<_bucket_num>", rank = 2)]
fn get_bucket_not_logged(_bucket_num: usize) -> Redirect {
    Redirect::to("/")
}

#[get("/bucket/<bucket_num>")]
fn get_bucket_data(user: User, bucket_num: usize) -> Result<Template, NotFound<String>> {
    use std::path::PathBuf;
    use db_tables::Users;


    #[derive(Serialize)]
    struct BucketsData {
        bucket_num: usize,
        bucket_name: String,
        status_msg: String,
        files: String,
    }


    let con = helper::est_db_con();
    Users::dsl::Users..select((Users::b2_bucket_name, Users::b2_acc_key, Users::b2_acc_id)).filter(Users::user_id.eq(user.id));

    if let Ok(txt) = std::fs::read_to_string(format!("resources/user{}.configs", user.id)) {

        //let out_puts: Vec<(String, String)> = split_lines.clone().filter_map(|(i, c)| if i % 2 == 1 { Some(c.to_owned()) } else { None }).collect();
        if let Some(bucket_name) = txt.lines().nth(bucket_num) {
            let out = helper::restic(bucket_name, &user)
                .arg("ls")
                .arg("-l")
                .arg("latest")
                .output().unwrap();

            let mut all_files: Vec<String> = String::from_utf8(out.stdout).expect("Output not UTF-8")
                .lines().skip(1).map(|c| {
                let mut path_started = false;
                let mut folder_path = String::new();
                for item in c.split(" ") {
                    if path_started || item.chars().next().unwrap_or('-') == '/' {
                        path_started = true;
                        folder_path.push_str(item);
                    }
                }
                if c.chars().next().unwrap() == 'd' {
                    folder_path.push('/');
                }
                folder_path
            }).collect();

            let mut final_html = String::new();
            {
                let first_item = all_files.first().expect("No files in backup");
                let mut cur_folder = PathBuf::from(first_item);
                if !cur_folder.is_dir() {
                    cur_folder.pop();
//                first_item.split("\\").for_each(|c| final_html.push_str(format!("<li>{}<ul>",c)))
                }
                let mut counter = 0;
//                let open_selector: Vec<TagType> = Vec::new();
//                cur_folder.components()
//                    .for_each(|c| {
//                        if c == std::path::Component::Normal(" ".as_ref()) {
//                            return;
//                        }
//                        final_html.push_str(&format!("<li><input type=\"checkbox\">{}<ul>", c.as_os_str().to_str().unwrap()));
//                        counter += 1;
//                    });

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
//                            if c == std::path::Component::Normal(" ".as_ref()) {
//                                return;
//                            }
                            //println!("{:?}", path);
                            final_html.push_str(
                                &format!("<li><input type=\"checkbox\" data-folder-num=\"{}\">{}<ul>",
                                         idx, c.as_os_str().to_str().unwrap()));
                            counter += 1;
                        });
                        cur_folder = path;
                    } else {
                        final_html.push_str(
                            &format!("<li><input type=\"checkbox\" data-folder-num=\"{}\">{}</li>",
                                     idx, path.file_name().unwrap().to_str().unwrap()));
                    }
                }
                for _ in 0..counter {
                    final_html.push_str("</ul></li>");
                }
            }

            for file in all_files.iter_mut() {
                if file.ends_with(")") {
                    let idx = file.rfind("(").expect("No ending brackets?");
                    file.replace_range(idx.., "");
                }
                file.pop();
            }
            let mut guard = PATH_CACHE.lock().unwrap();
            guard.insert((user.id as i16, bucket_num as i16), all_files);

            Ok(Template::render("bucket",
                                BucketsData {
                                    bucket_num,
                                    bucket_name: bucket_name.to_owned(),
                                    status_msg: String::new(),
                                    files: final_html,
                                }))
        } else {
            Err(NotFound("Number too high".to_owned()))
        }
    } else {
        Err(NotFound("No configs atm".to_owned()))
    }
}

#[post("/bucket/<bucket_num>/download", data = "<file_paths>")]
fn download_data(user: User, bucket_num: usize, file_paths: Json<Vec<usize>>) -> Result<Vec<u8>, NotFound<String>> {
    use std::path::PathBuf;
    use std::fs;
    let guard = PATH_CACHE.lock().unwrap();
    if let Some(all_paths) = guard.get(&(user.id as i16, bucket_num as i16)) {
        let file_paths: Vec<usize> = file_paths.into_inner();

        if let Ok(txt) = std::fs::read_to_string(format!("resources/user{}.configs", user.id)) {
            helper::delete_dir_contents(fs::read_dir(TEMP_STORAGE_PATH));
            if let Some(bucket_name) = txt.lines().nth(bucket_num) {
                let mut out = helper::restic(bucket_name, &user);
                out.arg("restore").arg("latest").arg(&format!("--target={}", TEMP_STORAGE_PATH));
                for path_idx in file_paths {
                    let path = &all_paths[path_idx];
                    //let p_buf = PathBuf::from(path);
                    out.arg("--include=".to_owned() + path);
                }
                println!("{:?}", out);
                out.output().unwrap();
                let mut data_to_send = std::io::Cursor::new(Vec::<u8>::new());
                helper::zip_dir(TEMP_STORAGE_PATH, &mut data_to_send);

                Ok(data_to_send.into_inner())
            } else {
                Err(NotFound("No bucket by this number".to_owned()))
            }
        } else {
            Err(NotFound("Woop".to_owned()))
        }
    } else {
        Err(NotFound("Woop".to_owned()))
    }
}

#[post("/logout")]
fn logout(user: User, mut cookies: Cookies) -> Flash<Redirect> {
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
    let (password, salt) = helper::encrypt_password(&registration.get().password);

    let enc = helper::get_random_stuff(32);

    diesel::insert_into(db_tables::Users::table)
        .values(&db_tables::DbUserIns {
            email: registration.get().email.clone(),
            username: registration.get().username.clone(),
            enced_enc_pass: helper::encrypt_base64(&enc, &password, &salt),
            password,
            salt,
            b2_acc_id: helper::encrypt(&registration.get().b2_acc_id, &password),
            b2_acc_key: helper::encrypt(&registration.get().b2_acc_key, &password),
            b2_bucket_name: registration.get().b2_bucket_name.clone()
        }).execute(&con).expect("Not inserting into database");

    Flash::success(Redirect::to("/login"), "Successfully Registered")
}

lazy_static! {
    static ref PATH_CACHE: Mutex<HashMap<(i16,i16),Vec<String>>> = Mutex::new(HashMap::new());
}
fn main() {
    rocket::ignite()
        .attach(Template::fairing())
        .mount("/",
               routes![index, logout, user_index, login_page, login_user
               ,login, get_bucket_data, get_bucket_not_logged, download_data, register,
               register_submit
               ]).launch();
}