// Not sure if main will have diesel on release.
extern crate diesel;

use super::{helper, db_tables};
use super::rocket_contrib::templates::Template;
use super::rocket::response::{Redirect, Flash};
use super::rocket::request::{self, FromForm, FormItems, Form, FlashMessage, FromRequest, Request};
use super::std::{error::Error, fmt};

use diesel::prelude::*;

#[derive(Debug)]
enum RepoModdingError {
    EmptyName,
    DuplicateName,
    DuplicateEnvVar,
}

impl fmt::Display for RepoModdingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::RepoModdingError::*;
        match self {
            &EmptyName => write!(f, "Name cannot be empty"),
            &DuplicateName => write!(f, "Name already exists"),
            &DuplicateEnvVar => write!(f, "Environmental variable duplicated")
        }
    }
}

impl Error for RepoModdingError {}

#[derive(FromForm)]
pub struct EditRepoForm {
    edit_repo_name: String,
    edit_repo_path: String,
    edit_repo_password: String,
    owning_service: String,
}

#[derive(Debug)]
pub struct AddNewServiceForm {
    enc_addr_part: String,
    env_value_list: Vec<String>,
    env_var_names_list: Vec<i32>,
    new_service_name: String,
    service_type: i32,
}

impl<'f> FromForm<'f> for AddNewServiceForm {
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
pub struct AddNewRepoForm {
    new_repo_name: String,
    new_repo_path: String,
    new_repo_password: String,
    owning_service: String,
}

#[post("/add/service", data = "<name>")]
pub fn add_more_services(user: ::User, name: Form<AddNewServiceForm>) -> Flash<Redirect> {
//    println!("{:?}", name);
    match internal_add_more_service(&user, name.into_inner()) {
        Ok(_) => Flash::success(Redirect::to("/"), "Successfully added new service"),
        Err(err) => match err {
            RepoModdingError::EmptyName => Flash::error(Redirect::to("/"), "Error: Service name can not be empty"),
            RepoModdingError::DuplicateEnvVar => Flash::error(Redirect::to("/"), "Duplicate environment variable entries"),
            RepoModdingError::DuplicateName => Flash::error(Redirect::to("/"), "New service name already exists."),
        }
    }
}

fn internal_add_more_service(user: &::User, name: AddNewServiceForm) -> Result<(), RepoModdingError> {
    if name.new_service_name.trim().is_empty() {
        return Err(RepoModdingError::EmptyName);
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
        NonUnique => { return Err(RepoModdingError::EmptyName); }
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
        Unique(_) => Ok(()),
        NonUnique => Err(RepoModdingError::DuplicateEnvVar)
    }
}

#[post("/edit/service/<service_name>", data = "<new_data>")]
pub fn edit_service(user: ::User, service_name: String, new_data: Form<AddNewServiceForm>) -> Flash<Redirect> {
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
pub fn delete_service(user: ::User, service_name: String) -> Flash<Redirect> {
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

#[post("/edit/repo/<repo_name>", data = "<new_data>")]
pub fn edit_repo(user: ::User, repo_name: String, new_data: Form<EditRepoForm>) -> Flash<Redirect> {
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
pub fn delete_repo(user: ::User, repo_name: String) -> Flash<Redirect> {
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
pub fn add_more_repos(user: ::User, name: Form<AddNewRepoForm>) -> Flash<Redirect> {
    match internal_add_more_repos(&user, name.into_inner()) {
        Ok(_) => Flash::success(Redirect::to("/"), "Successfully added new repository"),
        Err(err) => match err {
            RepoModdingError::EmptyName => Flash::error(Redirect::to("/"), "Error: Repository name can not be empty"),
            //TODO: Add logging to this
            _ => Flash::error(Redirect::to("/"), &format!("This really should not happen... , open an issue including this error message: {} in Adding Repository", err))
        }
    }
}

fn internal_add_more_repos(user: &::User, name: AddNewRepoForm) -> Result<(), RepoModdingError> {
    use db_tables::update_repositories;

    if name.new_repo_name.trim().is_empty() {
        return Err(RepoModdingError::EmptyName);
    }

    let con = helper::est_db_con();

    diesel::select(
        update_repositories(
            &name.owning_service,
            user.id, &name.new_repo_name,
            &name.new_repo_name,
            &name.new_repo_path,
            helper::encrypt(&name.new_repo_password, &user.encryption_password)))
        .execute(&con).unwrap();

    Ok(())
}

#[derive(FromForm)]
pub struct B2FormData {
    b2_bucket_name: String,
    b2_new_name: String,
    b2_repo_path: String,
    b2_account_id: String,
    b2_account_key: String,
    b2_repo_password: String,
}

#[post("/add/preset/b2", data = "<data>")]
pub fn add_b2_preset(user: ::User, data: Form<B2FormData>) -> Flash<Redirect> {
    use db_tables::Services;
    if data.b2_new_name.trim().is_empty() {
        return Flash::error(Redirect::to("/"), "Error: Service name can not be empty");
    }
    let service_name = format!("B2 - {}", data.b2_bucket_name);
    let services_response = internal_add_more_service(&user, AddNewServiceForm {
        service_type: 5,
        enc_addr_part: data.b2_bucket_name.clone() + ":",
        new_service_name: service_name.clone(),
        env_value_list: vec![data.b2_account_id.clone(), data.b2_account_key.clone()],
        env_var_names_list: vec![29, 30],
    });
//
    if let Err(err) = services_response {
        return match err {
            RepoModdingError::DuplicateName => Flash::error(Redirect::to("/"), "This preset/bucket name already exists, just add a new repository connection with the existing preset."),
            //TODO: Add logging to this
            _ => Flash::error(Redirect::to("/"), &format!("This really should not happen... , open an issue including this error message: {} in B2 Preset (Service)", err)),
        }
    }

    let repo_response = internal_add_more_repos(&user, AddNewRepoForm {
        new_repo_name: data.b2_new_name.clone(),
        new_repo_password: data.b2_repo_password.clone(),
        new_repo_path: data.b2_repo_path.clone(),
        owning_service: service_name,
    });
    if let Err(err) = repo_response {
        match err {
            RepoModdingError::EmptyName => Flash::error(Redirect::to("/"), "Error: Service name can not be empty"),
            //TODO: Add logging to this
            _ => Flash::error(Redirect::to("/"), &format!("This really should not happen... , open an issue including this error message: {} in (B2 Preset Repo)", err))
        }
    } else {
        Flash::success(Redirect::to("/"), "B2 Preset added")
    }
}
