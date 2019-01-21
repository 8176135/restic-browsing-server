extern crate diesel;

use crate::{helper, db_tables};
use rocket_contrib::templates::Template;
use rocket::response::{Redirect, Flash};
use rocket::http::{Cookie, Cookies, Status};
use rocket::request::{Form, FlashMessage, FromRequest, Request, Outcome};
use diesel::prelude::*;

const SESSION_CLIENT_DATA_COOKIE_NAME: &str = "session_client_data";
const SESSION_CLIENT_DATA_DB_AGE_HOURS: i64 = 24;

#[derive(Debug, Clone)]
pub struct User {
    pub id: i32,
    pub encryption_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClientData {
    auth_pass: String,
    //    user_id: i32,
    enc_id: i32,
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> rocket::request::Outcome<User, ()> {
        use rocket::Outcome;
        let mut cookies = request.cookies();
        let session_client_data = cookies.get_private(SESSION_CLIENT_DATA_COOKIE_NAME);
//            .and_then(|cookie| cookie.value().parse::<String>().ok());
        if let Some(mut session_client_cookie) = session_client_data {
            let session_client_data: SessionClientData = serde_json::from_str(&session_client_cookie.value().parse::<String>().unwrap()).expect("Failed to deserialize session data");
            let con = helper::est_db_con();
            use db_tables::{Users, AuthRepoPasswords, AuthRepoPasswordsDb};
            match AuthRepoPasswords::table.select((AuthRepoPasswords::owning_user, AuthRepoPasswords::auth_repo_enc_pass, AuthRepoPasswords::expiry_date))
                .filter(AuthRepoPasswords::id.eq(session_client_data.enc_id))
                .first::<AuthRepoPasswordsDb>(&con) {
                Ok(auth_repo) => {
                    diesel::update(AuthRepoPasswords::table.filter(AuthRepoPasswords::id.eq(session_client_data.enc_id)))
                        .set(AuthRepoPasswords::expiry_date.eq(chrono::Utc::now().naive_local() + chrono::Duration::hours(SESSION_CLIENT_DATA_DB_AGE_HOURS)))
                        .execute(&con);
                    session_client_cookie.set_max_age(time::Duration::hours(SESSION_CLIENT_DATA_DB_AGE_HOURS));
                    cookies.add_private(session_client_cookie);
                    Outcome::Success(User {
                        id: auth_repo.owning_user,
                        encryption_password: helper::decrypt(&auth_repo.auth_repo_enc_pass, &session_client_data.auth_pass),
                    })
                }
                Err(ref err) if err == &diesel::result::Error::NotFound => {
                    Outcome::Forward(())
                }
                _ => panic!("Can't connect to db")
            }
        } else {
            Outcome::Forward(())
        }
    }
}

#[get("/account")]
pub fn edit_account(user: super::User, flash: Option<FlashMessage>) -> Template {
    use db_tables::Users;
    #[derive(Serialize)]
    struct AccountManagementData {
        pub username: String,
        pub email: String,
        pub flash: Option<String>,
        pub status: Option<String>,
    }

    let (flash, status) = match flash {
        None => (None, None),
        Some(c) => (Some(c.msg().to_owned()), Some(c.name().to_owned()))
    };

    let con = helper::est_db_con();

    let output: db_tables::DbUserManagement =
        Users::dsl::Users.filter(Users::id.eq(user.id))
            .select((Users::username, Users::email))
            .first::<db_tables::DbUserManagement>(&con)
            .expect("Can't find user id in database (or connection failed). (Has the user been deleted manually while server is still running?)");

    Template::render("account", AccountManagementData {
        username: output.username.clone(),
        email: output.email.clone(),
        flash,
        status,
    })
}

#[get("/account", rank = 2)]
pub fn edit_account_no_login() -> Redirect {
    Redirect::to("/login")
}

#[derive(FromForm)]
pub struct NewName {
    username: String
}

#[derive(FromForm)]
pub struct NewEmail {
    email: String
}

#[derive(FromForm)]
pub struct NewPassword {
    old_password: String,
    password: String,
}

#[post("/account/change/username", data = "<new_name>")]
pub fn change_username(user: super::User, new_name: Form<NewName>) -> Flash<Redirect> {
    use db_tables::Users;

    let con = helper::est_db_con();

    let insert_result = diesel::update(Users::dsl::Users.filter(Users::id.eq(user.id)))
        .set(Users::username.eq(&new_name.username)).execute(&con);

    use helper::IsUnique::*;
    match helper::check_for_unique_error(insert_result).expect("Failed to update username") {
        Unique(_) => Flash::success(Redirect::to("/account/"), format!("Changed username to \"{}\"", &new_name.username)),
        NonUnique(_) => {
            Flash::error(Redirect::to("/account/"), "New username name already exists.")
        }
    }
}

#[post("/account/change/email", data = "<new_email>")]
pub fn change_email(user: super::User, new_email: Form<NewEmail>) -> Flash<Redirect> {
    Flash::error(Redirect::to("/account/"), "Not yet implemented")
//    use db_tables::Users;
//
//    let con = helper::est_db_con();
//
//    let insert_result = diesel::update(Users::dsl::Users.filter(Users::id.eq(user.id)))
//        .set(Users::email.eq(&new_email.email)).execute(&con);
//
//    use helper::IsUnique::*;
//    match helper::check_for_unique_error(insert_result).expect("Failed to update email") {
//        Unique(_) => Flash::success(Redirect::to("/account/"), format!("Changed email to \"{}\"", &new_email.email)),
//        NonUnique(_) => {
//            Flash::error(Redirect::to("/account/"), "New email is already registered.")
//        }
//    }
}

#[post("/account/change/password", data = "<new_password>")]
pub fn change_password(user: super::User, new_password: Form<NewPassword>) -> Flash<Redirect> {
    use db_tables::Users;

    let con = helper::est_db_con();

    let (password, salt) = helper::encrypt_password(&new_password.password);

    let login_candidate: db_tables::DbUserLogin =
        Users::dsl::Users.filter(Users::id.eq(user.id))
            .select((Users::id, Users::password, Users::salt, Users::enced_enc_pass, Users::activation_code, Users::email))
            .first::<db_tables::DbUserLogin>(&con).expect("Failed to connect with db, or user deleted?");
    if helper::verify_user(&login_candidate, &new_password.old_password) {
        let _insert_result = diesel::update(Users::dsl::Users.filter(Users::id.eq(user.id)))
            .set((Users::password.eq(&password),
                  Users::salt.eq(&salt),
                  Users::enced_enc_pass.eq(helper::encrypt_base64(&user.encryption_password, &new_password.password, &salt))))
            .execute(&con).expect("Failed to update password in DB");

        Flash::success(Redirect::to("/account/"), "Successfully updated password")
    } else {
        Flash::error(Redirect::to("/account/"), "Error, incorrect old password.")
    }
}

#[post("/account/delete")]
pub fn delete_account(user: super::User) -> Flash<Redirect> {
//    use db_tables::Users;
//
//    let con = helper::est_db_con();
//
//    let (password, salt) = helper::encrypt_password(&new_password.password);
//
//    let login_candidate: db_tables::DbUserLogin =
//        Users::dsl::Users.filter(Users::id.eq(user.id))
//            .select((Users::id, Users::password, Users::salt, Users::enced_enc_pass, Users::activation_code))
//            .load::<db_tables::DbUserLogin>(&con).expect("Failed to connect with db").first().unwrap().clone();
//    if helper::verify_user(&login_candidate, &new_password.old_password) {
//        let _insert_result = diesel::update(Users::dsl::Users.filter(Users::id.eq(user.id)))
//            .set((Users::password.eq(&password),
//                  Users::salt.eq(&salt),
//                  Users::enced_enc_pass.eq(helper::encrypt_base64(&user.encryption_password, &new_password.password, &salt))))
//            .execute(&con).expect("Failed to update password in DB");
//
//        Flash::success(Redirect::to("/account/"), "Successfully updated password")
//    } else {
//        Flash::error(Redirect::to("/account/"), "Error, incorrect old password.")
//    }

    Flash::error(Redirect::to("/account/"), "Not implemented yet")
}

#[get("/register")]
pub fn register(flash: Option<FlashMessage>) -> Template {
    let mut context = ::std::collections::HashMap::new();
    if let Some(ref msg) = flash {
        context.insert("flash", msg.msg());
        context.insert("status", msg.name());
    }
    Template::render("signup", context)
}

#[derive(FromForm)]
pub struct Registration {
    username: String,
    password: String,
    email: String,
}

#[post("/register_submit", data = "<registration>")]
pub fn register_submit(registration: Form<Registration>) -> Flash<Redirect> {
    if !helper::check_email_domain(&registration.email) {
        return Flash::error(Redirect::to("/register/"), "Error, temporary emails can't be used sorry.");
    }
    let con = helper::est_db_con();
    let (password, salt) = helper::encrypt_password(&registration.password);

    let enc = helper::get_random_stuff(32);

    let act_code = base64::encode_config(&base64::decode(&helper::get_random_stuff(64)).unwrap(), base64::URL_SAFE_NO_PAD);

    let register_insert_res = diesel::insert_into(db_tables::Users::table)
        .values(&db_tables::DbUserIns {
            email: registration.email.to_lowercase().clone(),
            username: registration.username.to_lowercase().clone(),
            enced_enc_pass: helper::encrypt_base64(&enc, &registration.password, &salt),
            password,
            salt,
            activation_code: Some(act_code.clone()),
        }).execute(&con);

    use helper::IsUnique::*;
    match helper::check_for_unique_error(register_insert_res).expect("Unexpected error in registration") {
        Unique(_) => {
            helper::send_email(&registration.email, "Account Activation - Restic Restorer",
                               &format!("Hello {name}, copy and paste the link below into your url bar to activate your account (I haven't figured out html emails yet)\nActivation link: https://res.handofcthulhu.com/verify/{name}/{code}",
                                        name = registration.username, code = act_code)).expect("Failed to send email");
            Flash::success(Redirect::to("/login/"), "Successfully Registered, check your email for the link to activate your account.")
        }
        NonUnique(ref msg) => match msg.clone().as_str() {
            "email_UNIQUE" => Flash::error(Redirect::to("/register/"), "Email has already been registered, try (Forgot Your Password)?"),
            "username_UNIQUE" => Flash::error(Redirect::to("/register/"), "Username already taken!"),
            _ => panic!("New registration constraint not implemented")
        },
        //_ => panic!("Non unique is not providing message"),
    }
}

#[get("/verify/<username>/<auth_code>")]
pub fn verify_email(username: String, auth_code: String) -> Flash<Redirect> {
    use db_tables::Users;

    #[derive(AsChangeset)]
    #[table_name = "Users"]
    #[changeset_options(treat_none_as_null = "true")]
    struct NullifyActCode {
        activation_code: Option<String>
    }

    let con = helper::est_db_con();
    let db_act_code = Users::table.filter(Users::username.eq(&username))
        .select(Users::activation_code)
        .first::<Option<String>>(&con).unwrap();

    if let Some(db_act_code) = db_act_code {
        if db_act_code == auth_code {
            diesel::update(Users::table.filter(Users::username.eq(&username)))
                .set(NullifyActCode { activation_code: None })
                .execute(&con)
                .expect("Removing activation code failed");
            Flash::success(Redirect::to("/login"), "Account activated! Log in with your password.")
        } else {
            Flash::error(Redirect::to("/login"), "Invalid activation code")
        }
    } else {
        Flash::success(Redirect::to("/login"), "Account already activated! Just log in with your password.")
    }
}

#[derive(FromForm)]
pub struct Login {
    username: String,
    password: String,
}

#[post("/login", data = "<login>")]
pub fn login(mut cookies: Cookies, login: Form<Login>) -> Flash<Redirect> {
    use db_tables::Users;

    let con = helper::est_db_con();
    let login_candidate: Result<db_tables::DbUserLogin, diesel::result::Error> =
        Users::dsl::Users.filter(Users::username.eq(&login.username.to_lowercase()))
            .select((Users::id, Users::password, Users::salt, Users::enced_enc_pass, Users::activation_code, Users::email))
            .first::<db_tables::DbUserLogin>(&con);
    match login_candidate {
        Ok(login_candidate) => {
            if helper::verify_user(&login_candidate, &login.password) {
                if login_candidate.activation_code.is_some() {
                    Flash::error(Redirect::to("/login"),
                                 format!("Please activate your account through the link in your email ({}) (and check your spam box too)! <br/><a href=\"/act_email_change/{}\">Click here if your email is incorrect</a>",
                                         login_candidate.email,
                                         base64::encode_config(&login.username, base64::URL_SAFE_NO_PAD)))
                } else {
                    let random_stuff = helper::get_random_stuff(32);
                    diesel::insert_into(db_tables::AuthRepoPasswords::table).values(&db_tables::AuthRepoPasswordsDb {
                        expiry_date: chrono::Utc::now().naive_local() + chrono::Duration::days(SESSION_CLIENT_DATA_DB_AGE_HOURS),
                        owning_user: login_candidate.id,
                        auth_repo_enc_pass: helper::encrypt(&helper::decrypt_base64(
                            &login_candidate.enced_enc_pass,
                            &login.password,
                            &login_candidate.salt), &random_stuff),
                    }).execute(&con).expect("Failed to insert, db connection problem?");

                    let last_id: i32 = diesel::select(db_tables::last_insert_id).first(&con).unwrap();

                    cookies.add_private(
                        Cookie::build(SESSION_CLIENT_DATA_COOKIE_NAME,
                                      serde_json::to_string(&SessionClientData { auth_pass: random_stuff, enc_id: last_id }).unwrap())
                            .secure(if cfg!(debug_assertions) { false } else { true })
                            .http_only(true)
                            .max_age(time::Duration::days(1))
                            .finish());
//                    cookies.add_private(Cookie::build("repo_encryption_password",
//                                                      helper::decrypt_base64(
//                                                          &login_candidate.enced_enc_pass,
//                                                          &login.password,
//                                                          &login_candidate.salt))
//                        .max_age(crate::MAX_COOKIE_AGE.clone())
//                        .secure(true)
//                        .http_only(true)
//                        .finish());
                    Flash::success(Redirect::to("/"), "Successfully logged in.")
                }
            } else {
                Flash::error(Redirect::to("/login/"), "Username exists, invalid password though.")
            }
        }
        Err(ref err) if err == &diesel::result::Error::NotFound => {
            Flash::error(Redirect::to("/login/"), "Invalid username, register with the link below!.")
        }
        _ => panic!("Can't connect to db")
    }
}

#[get("/login", rank = 2)]
pub fn login_page(flash: Option<FlashMessage>) -> Template {
    let mut context = ::std::collections::HashMap::new();
    if let Some(ref msg) = flash {
        context.insert("flash", msg.msg());
    }
    Template::render("login", context)
}

#[get("/act_email_change/<username>")]
pub fn act_email_change(username: String, flash: Option<FlashMessage>) -> Result<Template, Status> {
    #[derive(Serialize)]
    struct ActivationEmailContext {
        username: String,
        flash: Option<String>,
        status: Option<String>,
    }

    let (flash, status) = match flash {
        None => (None, None),
        Some(c) => (Some(c.msg().to_owned()), Some(c.name().to_owned()))
    };

    use db_tables::Users;
    let username = String::from_utf8_lossy(&base64::decode_config(&username, base64::URL_SAFE_NO_PAD).map_err(|_| Status::NotAcceptable)?).to_string();
    let con = helper::est_db_con();
    match Users::table.select(Users::activation_code)
        .filter(Users::username.eq(&username))
        .first::<Option<String>>(&con) {
        Ok(act_option) => {
            if act_option.is_some() {
                Ok(Template::render("activation_email_change", ActivationEmailContext {
                    username,
                    flash,
                    status,
                }))
            } else {
                Err(Status::NotAcceptable)
            }
        }
        Err(ref err) if err == &diesel::result::Error::NotFound => {
            Err(Status::NotAcceptable)
        }
        _ => panic!("Can't connect to db")
    }
}

#[derive(FromForm)]
pub struct ActEmailChangeForm {
    password: String,
    new_email: String,
}

#[post("/act_email_change/<username>", data = "<data>")]
pub fn act_email_change_post(username: String, data: Form<ActEmailChangeForm>) -> Result<Flash<Redirect>, Status> {
    use db_tables::Users;

    let con = helper::est_db_con();
    let login_candidate: db_tables::DbUserLogin =
        Users::dsl::Users.filter(Users::username.eq(&username.to_lowercase()))
            .select((Users::id, Users::password, Users::salt, Users::enced_enc_pass, Users::activation_code, Users::email))
            .first::<db_tables::DbUserLogin>(&con)
            .map_err(|c| if c == diesel::result::Error::NotFound { Status::NotAcceptable } else { panic!("Can't connect to db") })?;

    if helper::verify_user(&login_candidate, &data.password) {
        if let Some(act_code) = login_candidate.activation_code {
            helper::send_email(&data.new_email, "Account Activation - Restic Restorer",
                               &format!("Hello {name}, copy and paste the link below into your url bar to activate your account (I haven't figured out html emails yet)\nActivation link: https://res.handofcthulhu.com/verify/{name}/{code}",
                                        name = username, code = act_code)).expect("Failed to send email");
            Ok(Flash::success(Redirect::to("/login"), format!("Account activation email sent to: {}.", data.new_email)))
        } else {
            Ok(Flash::error(Redirect::to("/login"), "Account already activated, please login with your password."))
        }
    } else {
        Ok(Flash::error(Redirect::to("/act_email_change/".to_owned() + &base64::encode_config(&username, base64::URL_SAFE_NO_PAD)), "Wrong password, please try again"))
    }
}

#[post("/logout")]
pub fn logout(_user: User, mut cookies: Cookies) -> Flash<Redirect> {
//    let session_client_data = cookies.get_private(SESSION_CLIENT_DATA_COOKIE_NAME).unwrap().value().parse().unwrap();
//    let session_client_data: SessionClientData = serde_json::from_str(session_client_data).unwrap();
    diesel::delete(
        db_tables::AuthRepoPasswords::table.filter(db_tables::AuthRepoPasswords::id.eq(
            serde_json::from_str::<SessionClientData>(
                &cookies.get_private(SESSION_CLIENT_DATA_COOKIE_NAME).unwrap().value().parse::<String>().unwrap())
                .unwrap().enc_id)))
        .execute(&helper::est_db_con())
        .expect("Failed to connect to server");

    cookies.remove_private(Cookie::named("SESSION_CLIENT_DATA_COOKIE_NAME"));
    Flash::success(Redirect::to("/login/"), "Successfully logged out.")
}