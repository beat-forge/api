use crate::AppState;
use actix_web::{post, web, HttpResponse, Responder};
use argon2::{password_hash::rand_core::OsRng, password_hash::SaltString, Argon2, PasswordHasher};
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use mongodb::bson::{doc, Uuid, oid::ObjectId};
use serde::{Deserialize, Serialize};
use serde_json::json;

bitflags! {
    pub struct Permissions: i32 {
        const USER = 1 << 0; // can download, upload, and request verification for mods.
        const MODERATOR = 1 << 1; // can verify mods, and delete mods not uploaded by them.
        const ADMIN = 1 << 2; // full control over the site.
    }
}

#[derive(Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    // basic info
    pub username: String,
    pub password: String,

    // public info
    pub display_name: Option<String>,
    pub avatar: Option<String>,

    // system info
    pub permissions: i32, // bitflags
    pub api_key: String,    // uuid

    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String, // todo, recieve already hashed password
}

#[post("/users")]
pub async fn create_user(
    data: web::Data<AppState>,
    body: web::Json<CreateUserRequest>,
) -> impl Responder {
    let collection = data.db.collection::<User>("users");

    let user = collection
        .find_one(doc! {"username": &body.username}, None)
        .await
        .unwrap();
    if user.is_some() {
        return HttpResponse::Conflict().json(json!({"error": "Username already taken"}));
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(body.password.as_bytes(), &salt)
        .unwrap();

    let user = User {
        id: None,

        username: body.username.clone(),
        password: hash.to_string(),

        display_name: None,
        avatar: None,

        permissions: Permissions::USER.bits(),
        api_key: Uuid::new().to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let res = match collection.insert_one(&user, None).await {
        Ok(res) => res,
        Err(e) => return HttpResponse::InternalServerError().json(json!({"error": e.to_string()})),
    };

    HttpResponse::Ok().json(json!({
        "user_id": res.inserted_id,
        "api_key": user.api_key,
    }))
}