table! {
    Users (user_id) {
        user_id -> Integer,
        username -> Text,
        email -> Text,
        password -> Text,
        salt -> Text,
        enced_enc_pass -> Text,
        b2_acc_key -> Text,
        b2_acc_id -> Text,
        b2_bucket_name -> Text,
    }
}

table! {
    ConnectionInfo (id) {
        id -> Integer,
        owning_user -> Integer,
        name -> Text,
        connection_url -> Text,
        encryption_password -> Text,
    }
}

joinable!(ConnectionInfo -> Users (owning_user));
allow_tables_to_appear_in_same_query!(ConnectionInfo, Users);

#[derive(Insertable, Debug)]
#[table_name = "Users"]
pub struct DbUserIns {
    //    pub user_id: i32,
    pub username: String,
    pub email: String,
    pub password: String,
    pub salt: String,
    pub enced_enc_pass: String,
    pub b2_acc_key: String,
    pub b2_acc_id: String,
    pub b2_bucket_name: String,
}

#[derive(Queryable, Debug, Clone)]
//#[table_name = "Users"]
pub struct DbUserLogin {
    pub user_id: i32,
//    pub username: String,
//    pub email: String,
    pub password: String,
    pub salt: String,
    pub enced_enc_pass: String,
}

#[derive(Queryable, Debug, Clone)]
pub struct DbEncryptedData {
    pub b2_acc_key: String,
    pub b2_acc_id: String,
    pub b2_bucket_name: String,
}
