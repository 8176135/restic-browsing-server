#![allow(proc_macro_derive_resolution_fallback)]
table! {
    Users (id) {
        id -> Integer,
        username -> Text,
        email -> Text,
        password -> Text,
        salt -> Text,
        enced_enc_pass -> Text,
        kilobytes_downloaded -> Integer,
        activation_code -> Nullable<Text>,
    }
}

table! {
    ConnectionInfo (id) {
        id -> Integer,
        owning_user -> Integer,
        name -> Text,
        path -> Text,
        encryption_password -> Text,
        service_used -> Integer,
    }
}

table! {
    EnvNames (id) {
        id -> Integer,
        env_name -> Text,
    }
}

table! {
    ServiceType (id) {
        id -> Integer,
        service_type -> Text,
    }
}

table! {
    Services (id) {
        id -> Integer,
        owning_user -> Integer,
        service_name -> Text,
        service_type -> Integer,
        enc_addr_part -> Text,
    }
}

table! {
    ServiceContents (id) {
        id -> Integer,
        env_name_id -> Integer,
        owning_service -> Integer,
        encrypted_env_value -> Text,
    }
}

table! {
    Announcements (id) {
        id -> Integer,
        displayed -> Bool,
        title -> Text,
        contents -> Text,
    }
}

table! {
    QueryView (name, owning_user) {
        name -> Text,
        path -> Text,
        owning_user -> Integer,
        encryption_password -> Text,
        service_name -> Text,
        encrypted_env_value -> Text,
        env_name -> Text,
        service_type -> Text,
        enc_addr_part -> Text,
    }
}

table! {
    BasesList (owning_user, service_name) {
        owning_user -> Integer,
        service_name -> Text,
        service_type -> Integer,
        env_name_ids -> Nullable<Text>,
        encrypted_env_values -> Nullable<Text>,
        enc_addr_part -> Text,
    }
}

no_arg_sql_function!(last_insert_id, diesel::types::Integer);

joinable!(ConnectionInfo -> Users (owning_user));
joinable!(ConnectionInfo -> Services (service_used));
allow_tables_to_appear_in_same_query!(ConnectionInfo, Users);
allow_tables_to_appear_in_same_query!(ConnectionInfo, Services);

use diesel::sql_types::{Integer, Text, Nullable};
sql_function!(fn update_repositories(service_name: Text, owning_user: Integer, repo_name: Text, old_repo_name: Text, newPath: Text, encryption_password: Nullable<Text>) -> Integer);

#[derive(Insertable, Debug)]
#[table_name = "Users"]
pub struct DbUserIns {
    //    pub user_id: i32,
    pub username: String,
    pub email: String,
    pub password: String,
    pub salt: String,
    pub enced_enc_pass: String,
    pub activation_code: Option<String>,
}

#[derive(Identifiable, Queryable, Debug, Clone)]
#[table_name = "Users"]
pub struct DbUserLogin {
    pub id: i32,
    pub password: String,
    pub salt: String,
    pub enced_enc_pass: String,
    pub activation_code: Option<String>,
}

#[derive(Queryable, Debug, Clone, Serialize)]
pub struct DbUserManagement {
//    pub id: i32,
    pub username: String,
    pub email: String,
}

#[derive(Identifiable, Queryable, Debug, Clone, Serialize)]
#[table_name = "EnvNames"]
pub struct DbEnvNames {
    pub id: i32,
    pub env_name: String,
}

#[derive(Identifiable, Queryable, Debug, Clone, Serialize)]
#[table_name = "ServiceType"]
pub struct DbServiceType {
    pub id: i32,
    pub service_type: String,
}

#[derive(Queryable, Debug, Serialize)]
pub struct DbBasesList {
//    pub owning_user: i32,
    pub service_name: String,
    pub env_name_ids: Option<String>,
    pub service_type: i32
//    pub encrypted_env_values: String,
}

#[derive(Insertable, Debug)]
#[table_name = "ConnectionInfo"]
pub struct ConnectionInfoIns {
    pub owning_user: i32,
    pub name: String,
    pub path: String,
    pub encryption_password: String,
    pub service_used: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "Services"]
pub struct ServicesIns {
    pub owning_user: i32,
    pub service_name: String,
    pub enc_addr_part: String,
    pub service_type: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "ServiceContents"]
pub struct ServiceContentIns {
    pub owning_service: i32,
    pub env_name_id: i32,
    pub encrypted_env_value: String,
}

#[derive(Queryable,Insertable, Debug)]
#[table_name = "QueryView"]
pub struct DbQueryView {
    pub name: String,
    pub path: String,
    pub owning_user: i32,
    pub encryption_password: String,
    pub service_name: String,
    pub encrypted_env_value: String,
    pub env_name: String,
    pub service_type: String,
    pub enc_addr_part: String,
}

#[derive(Serialize,Queryable, Debug)]
pub struct AnnouncementDb {
    id: i32,
    displayed: bool,
    title: String,
    contents: String,
}
//#[derive(Identifiable, Queryable, Debug, Clone)]
//#[table_name = "ConnectionInfo"]
//pub struct ConnectionInfoUpdate {
//    pub owning_user: i32,
//    pub name: String,
//    pub encryption_password: String,
//}

#[derive(Queryable, Debug, Clone)]
pub struct DbEncryptedData {
    pub name: String,
    pub encryption_password: String,
}

#[derive(Queryable, Debug, Clone)]
pub struct DbBasesListReturn {
    pub env_name_ids: Option<String>,
    pub encrypted_env_values: Option<String>,
    pub enc_addr_part: String,
}

