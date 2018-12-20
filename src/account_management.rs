extern crate diesel;

use super::{helper, db_tables};
use super::rocket_contrib::templates::{Template};
use super::rocket::response::{Redirect, Flash};
use super::rocket::request::{self, Form, FlashMessage, FromRequest, Request};
use diesel::prelude::*;

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
            .load::<db_tables::DbUserManagement>(&con)
            .expect("Can't connect to database")
            .first()
            .expect("Can't find user id, in database. (Has the user been deleted manually while server is still running?)")
            .clone();

    Template::render("account", AccountManagementData {
        username: output.username,
        email: output.email,
        flash,
        status
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
        NonUnique => {
            Flash::error(Redirect::to("/account/"), "New repository name already exists.")
        }
    }
}

#[post("/account/change/email", data = "<new_email>")]
pub fn change_email(user: super::User, new_email: Form<NewEmail>) -> Flash<Redirect> {
    use db_tables::Users;

    let con = helper::est_db_con();

    let insert_result = diesel::update(Users::dsl::Users.filter(Users::id.eq(user.id)))
        .set(Users::email.eq(&new_email.email)).execute(&con);

    use helper::IsUnique::*;
    match helper::check_for_unique_error(insert_result).expect("Failed to update email") {
        Unique(_) => Flash::success(Redirect::to("/account/"), format!("Changed email to \"{}\"", &new_email.email)),
        NonUnique => {
            Flash::error(Redirect::to("/account/"), "New email is already registered.")
        }
    }
}

#[post("/account/change/password", data = "<new_password>")]
pub fn change_password(user: super::User, new_password: Form<NewPassword>) -> Flash<Redirect> {
    use db_tables::Users;   

    let con = helper::est_db_con();

    let (password, salt) = helper::encrypt_password(&new_password.password);

    let login_candidate: db_tables::DbUserLogin =
        Users::dsl::Users.filter(Users::id.eq(user.id))
            .select((Users::id, Users::password, Users::salt, Users::enced_enc_pass))
            .load::<db_tables::DbUserLogin>(&con).expect("Failed to connect with db").first().unwrap().clone();
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