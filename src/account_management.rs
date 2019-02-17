extern crate diesel;

use crate::{helper, db_tables, UserConInfo};
use rocket_contrib::templates::Template;
use rocket::response::{Redirect, Flash};
use rocket::http::{Cookie, Cookies, Status};
use rocket::request::{Form, FlashMessage, FromRequest, Request};
use diesel::prelude::*;

use helper::{google_analytics_update,AnalyticsEvent, Events, Pages};

const USER_DATA_COOKIE_NAME: &str = "session_client_data";
pub const TWO_FACTOR_AUTH_TIME_WINDOW: u32 = 30;
pub const TWO_FACTOR_AUTH_DIGITS: u32 = 6;

lazy_static! {
    static ref USER_COOKIE: rocket::http::Cookie<'static> = rocket::http::Cookie::build(USER_DATA_COOKIE_NAME, "")
                .max_age(time::Duration::hours(crate::SERVER_CONFIG.session_expire_age_hours))
                .path("/")
                .same_site(rocket::http::SameSite::Lax)
                .secure(if cfg!(debug_assertions) { false } else { true })
                .http_only(true)
                .finish();
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i32,
    pub encryption_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserCookieData {
    auth_pass: String,
    //  user_id: i32,
    enc_id: i32,
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> rocket::request::Outcome<User, ()> {
        use rocket::Outcome;
        let mut cookies = request.cookies();
        let user_cookie = cookies.get_private(USER_DATA_COOKIE_NAME);

        if let Some(user_cookie) = user_cookie {
            let user_cookie_data: UserCookieData = serde_json::from_str(&user_cookie.value().parse::<String>().unwrap()).expect("Failed to deserialize session data");
            let con = helper::est_db_con();
            use db_tables::{AuthRepoPasswords, AuthRepoPasswordsDb};
            match AuthRepoPasswords::table.select((AuthRepoPasswords::owning_user, AuthRepoPasswords::auth_repo_enc_pass, AuthRepoPasswords::expiry_date))
                .filter(AuthRepoPasswords::id.eq(user_cookie_data.enc_id))
                .first::<AuthRepoPasswordsDb>(&con) {
                Ok(auth_repo) => {
                    diesel::update(AuthRepoPasswords::table.filter(AuthRepoPasswords::id.eq(user_cookie_data.enc_id)))
                        .set(AuthRepoPasswords::expiry_date.eq(chrono::Utc::now().naive_local() + chrono::Duration::hours(crate::SERVER_CONFIG.session_expire_age_hours)))
                        .execute(&con).expect("Failed to connect to db, or update failed");

                    let mut new_user_cookie = USER_COOKIE.clone();
                    new_user_cookie.set_value(user_cookie.value().to_owned());
                    cookies.add_private(new_user_cookie);

                    Outcome::Success(User {
                        id: auth_repo.owning_user,
                        encryption_password: helper::decrypt(&auth_repo.auth_repo_enc_pass, &user_cookie_data.auth_pass),
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
pub fn edit_account(user: User, con_info: UserConInfo, flash: Option<FlashMessage>) -> Template {
    use db_tables::Users;
    #[derive(Serialize)]
    struct AccountManagementData {
        pub username: String,
        pub email: String,
        pub highlight_2fa: bool,
        pub flash: Option<String>,
        pub status: Option<String>,
    }

    google_analytics_update(Some(&user), &con_info, AnalyticsEvent::Page(Pages::Account));

    let (flash, status) = match flash {
        None => (None, None),
        Some(c) => (Some(c.msg().to_owned()), Some(c.name().to_owned()))
    };

    let con = helper::est_db_con();

    let output: db_tables::DbUserManagement =
        Users::dsl::Users.filter(Users::id.eq(user.id))
            .select((Users::username, Users::email, Users::secret_2fa_enc))
            .first::<db_tables::DbUserManagement>(&con)
            .expect("Can't find user id in database (or connection failed). (Has the user been deleted manually while server is still running?)");

    Template::render("account", AccountManagementData {
        username: output.username.clone(),
        email: output.email.clone(),
        highlight_2fa: output.secret_2fa_enc.is_none(),
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
//`
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
            .select((Users::id, Users::password, Users::salt, Users::enced_enc_pass, Users::activation_code, Users::email, Users::secret_2fa_enc))
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
pub fn delete_account(_user: User) -> Flash<Redirect> {
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
pub fn register(flash: Option<FlashMessage>, con_info: UserConInfo) -> Template {

    google_analytics_update(None, &con_info, AnalyticsEvent::Page(Pages::Register));

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
            secret_2fa_enc: None,
        }).execute(&con);

    use helper::IsUnique::*;
    match helper::check_for_unique_error(register_insert_res).expect("Unexpected error in registration") {
        Unique(_) => {
            helper::send_email(&registration.email, "Account Activation - Restic Restorer",
                               &format!("Hello {name}, use the link below into your url bar to activate your account \n\nActivation link: https://{domain}/verify/{name}/{code}",
                                        domain = crate::SERVER_CONFIG.domain,
                                        name = registration.username,
                                        code = act_code)).expect("Failed to send email");
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
    two_factor_auth: String,
}

#[post("/login", rank = 2)]
pub fn login_already_logged(_user: User) -> Flash<Redirect> {
    Flash::error(Redirect::to("/"), "Already logged in")
}

#[post("/login", data = "<login>")]
pub fn login(mut cookies: Cookies, con_info: UserConInfo, login: Form<Login>) -> Flash<Redirect> {
    use db_tables::Users;

    {
        let mut guard = crate::CONNECTION_TRACKER.lock().unwrap();
        let entry = guard.entry(con_info.ip.clone()).or_default();
        if *entry > crate::SERVER_CONFIG.max_login_attempts_per_ip_per_minute {
            return Flash::error(Redirect::to("/login"), "Too many attempts from your IP, please wait a bit");
        }
        *entry += 1;
    }

    let con = helper::est_db_con();
    let login_candidate: Result<db_tables::DbUserLogin, diesel::result::Error> =
        Users::dsl::Users.filter(Users::username.eq(&login.username.to_lowercase()))
            .select((Users::id, Users::password, Users::salt, Users::enced_enc_pass, Users::activation_code, Users::email, Users::secret_2fa_enc))
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
                    if let Some(secret) = login_candidate.secret_2fa_enc.as_ref() {
                        if helper::totp_check(&base64::decode(secret).unwrap(),
                                              login.two_factor_auth.parse().unwrap_or_default()) {
                            google_analytics_update(None, &con_info,AnalyticsEvent::Event(Events::LoginSuccess));
                            login_success(&con, &mut cookies, &login_candidate, &login.password)
                        } else {
                            Flash::error(Redirect::to("/login/"), "Invalid Two Factor Authentication")
                        }
                    } else {
                        google_analytics_update(None, &con_info,AnalyticsEvent::Event(Events::LoginSuccess));
                        login_success(&con, &mut cookies, &login_candidate, &login.password)
                    }
                }
            } else {
                google_analytics_update(None, &con_info,AnalyticsEvent::Event(Events::LoginFail));
                Flash::error(Redirect::to("/login/"), "Username exists, invalid password though.")
            }
        }
        Err(ref err) if err == &diesel::result::Error::NotFound => {
            google_analytics_update(None, &con_info,AnalyticsEvent::Event(Events::LoginFail));
            Flash::error(Redirect::to("/login/"), "Invalid username, register with the link below!.")
        }
        _ => panic!("Can't connect to db")
    }
}

fn login_success(con: &MysqlConnection, cookies: &mut Cookies, login_candidate: &db_tables::DbUserLogin, password: &str) -> Flash<Redirect> {
    let random_stuff = helper::get_random_stuff(32);
    diesel::insert_into(db_tables::AuthRepoPasswords::table).values(&db_tables::AuthRepoPasswordsDb {
        expiry_date: chrono::Utc::now().naive_local() + chrono::Duration::days(crate::SERVER_CONFIG.session_expire_age_hours),
        owning_user: login_candidate.id,
        auth_repo_enc_pass: helper::encrypt(&helper::decrypt_base64(
            &login_candidate.enced_enc_pass,
            password,
            &login_candidate.salt), &random_stuff),
    }).execute(con).expect("Failed to insert, db connection problem?");

    let last_id: i32 = diesel::select(db_tables::last_insert_id).first(con).unwrap();

    cookies.add_private(
        Cookie::build(USER_DATA_COOKIE_NAME,
                      serde_json::to_string(&UserCookieData { auth_pass: random_stuff, enc_id: last_id }).unwrap())
            .secure(if cfg!(debug_assertions) { false } else { true })
            .http_only(true)
            .max_age(time::Duration::hours(1))
            .same_site(rocket::http::SameSite::Lax)
            .finish());
    Flash::success(Redirect::to("/"), "Successfully logged in.")
}


#[get("/login", rank = 2)]
pub fn login_page(flash: Option<FlashMessage>, con_info: UserConInfo) -> Template {
    helper::google_analytics_update(None, &con_info, helper::AnalyticsEvent::Page(helper::Pages::Login));
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
            .select((Users::id, Users::password, Users::salt, Users::enced_enc_pass, Users::activation_code, Users::email, Users::secret_2fa_enc))
            .first::<db_tables::DbUserLogin>(&con)
            .map_err(|c| if c == diesel::result::Error::NotFound { Status::NotAcceptable } else { panic!("Can't connect to db") })?;

    if helper::verify_user(&login_candidate, &data.password) {
        if let Some(act_code) = login_candidate.activation_code {
            helper::send_email(&data.new_email, "Account Activation - Restic Restorer",
                               &format!("Hello {name}, copy and paste the link below into your url bar to activate your account (I haven't figured out html emails yet)\nActivation link: https://{domain}/verify/{name}/{code}",
                                        domain = crate::SERVER_CONFIG.domain,
                                        name = username,
                                        code = act_code)).expect("Failed to send email");
            Ok(Flash::success(Redirect::to("/login"), format!("Account activation email sent to: {}.", data.new_email)))
        } else {
            Ok(Flash::error(Redirect::to("/login"), "Account already activated, please login with your password."))
        }
    } else {
        Ok(Flash::error(Redirect::to("/act_email_change/".to_owned() + &base64::encode_config(&username, base64::URL_SAFE_NO_PAD)), "Wrong password, please try again"))
    }
}

#[post("/account/change/2fa/enable")]
pub fn enable_2fa(user: User) -> Result<String, Status> {
    use db_tables::Users;

    let con = helper::est_db_con();
    if Users::table.select(Users::secret_2fa_enc)
        .filter(Users::id.eq(user.id))
        .first::<Option<String>>(&con).expect("Failed to connect to db").is_some() {
        Err(Status::NotAcceptable)
    } else {
        let mut secret = [0u8; 20];
        use ring::rand::SecureRandom;
        helper::SECURE_RANDOM_GEN.fill(&mut secret).unwrap();
        let base32key = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret);
        Ok(base32key)
    }
}

#[derive(Deserialize, Debug)]
pub struct ConfirmationInfo {
    auth_code_confirm: String,
    secret: String,
}

#[post("/account/change/2fa/confirm", data = "<confirm_data>")]
pub fn confirm_2fa(user: User, confirm_data: rocket_contrib::json::Json<ConfirmationInfo>) -> Result<(), Status> {
    use db_tables::Users;

    let con = helper::est_db_con();
    if Users::table.select(Users::secret_2fa_enc)
        .filter(Users::id.eq(user.id))
        .first::<Option<String>>(&con).expect("Failed to connect to db").is_some() {
        Err(Status::NotAcceptable)
    } else {
        let secret = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &confirm_data.secret).expect("incoming secret not valid base32");
        if helper::totp_check(&secret, confirm_data.auth_code_confirm.parse().unwrap()) {
            let base64key = base64::encode(&secret);
            diesel::update(Users::table.filter(Users::id.eq(user.id)))
                .set(Users::secret_2fa_enc.eq(base64key))
                .execute(&con).expect("Failed to connect to db");
            Ok(())
        } else {
            Err(Status::Unauthorized)
        }
    }
}

#[derive(FromForm)]
pub struct DisableAuthCode {
    auth_code: String,
}

#[post("/account/change/2fa/disable", data = "<data>")]
pub fn disable_2fa(user: User, data: Form<DisableAuthCode>) -> Result<(), Status> {
    use db_tables::Users;

    #[derive(AsChangeset)]
    #[table_name = "Users"]
    #[changeset_options(treat_none_as_null = "true")]
    struct Nullify2FaCode {
        secret_2fa_enc: Option<String>
    }

    let con = helper::est_db_con();
    let secret = Users::table.select(Users::secret_2fa_enc)
        .filter(Users::id.eq(user.id))
        .first::<Option<String>>(&con).expect("Failed to connect to db");
    if let Some(secret) = secret {
        if helper::totp_check(&base64::decode(&secret).unwrap(),
                              data.auth_code.parse().unwrap_or_default()) {
            diesel::update(Users::table.filter(Users::id.eq(user.id)))
                .set(Nullify2FaCode { secret_2fa_enc: None })
                .execute(&con).expect("Failed to connect to db");
            Ok(())
        } else {
            Err(Status::Unauthorized)
        }
    } else {
        Err(Status::NotAcceptable)
    }
}

#[post("/logout")]
pub fn logout(_user: User, mut cookies: Cookies) -> Flash<Redirect> {
    diesel::delete(
        db_tables::AuthRepoPasswords::table.filter(db_tables::AuthRepoPasswords::id.eq(
            serde_json::from_str::<UserCookieData>(
                &cookies.get_private(USER_DATA_COOKIE_NAME).unwrap().value().parse::<String>().unwrap())
                .unwrap().enc_id)))
        .execute(&helper::est_db_con())
        .expect("Failed to connect to server");

    cookies.remove_private(Cookie::named("SESSION_CLIENT_DATA_COOKIE_NAME"));
    Flash::success(Redirect::to("/login/"), "Successfully logged out.")
}