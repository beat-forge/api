use crate::{
    structs::{GithubAccessToken, GithubUser, JWTAuth},
    utils::get_bearer_auth,
    AppState,
};
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use mongodb::bson::{doc, oid::ObjectId, Uuid};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::json;

bitflags! {
    pub struct Permissions: i32 {
        const USER = 1 << 0; // can download, upload, and request verification for mods.
        const MODERATOR = 1 << 1; // can verify mods, and delete mods not uploaded by them.
        const ADMIN = 1 << 2; // full control over the site.
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    #[serde(rename = "_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    // basic info
    pub github_id: i64,
    pub username: String,
    pub email: String,

    // public info
    pub display_name: Option<String>,
    pub avatar: Option<String>,

    // system info
    pub permissions: i32, // bitflags
    pub api_key: String,  // uuid

    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthUserRequest {
    pub code: String, // github oauth code
}

#[post("/user/auth")]
pub async fn auth_user(
    data: web::Data<AppState>,
    req: web::Query<AuthUserRequest>,
) -> impl Responder {
    let client = HttpClient::builder()
        .user_agent("forge-registry")
        .build()
        .unwrap();

    let request = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .json(&json!({
            "client_id": std::env::var("GITHUB_CLIENT_ID").unwrap(),
            "client_secret": std::env::var("GITHUB_CLIENT_SECRET").unwrap(),
            "code": req.code,
        }))
        .send()
        .await
        .unwrap();

    let response = request.json::<GithubAccessToken>().await;
    if response.is_err() {
        return HttpResponse::BadRequest().json(json!({
            "error": "invalid code"
        }));
    }

    let access_token = response.unwrap().access_token;

    let github_user = client
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap()
        .json::<GithubUser>()
        .await
        .unwrap();

    let collection = data.db.collection::<User>("users");
    let db_user = match collection
        .find_one(doc! {"github_id":github_user.id}, None)
        .await
    {
        Ok(user) => user,
        Err(e) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": e.to_string()
            }))
        }
    };

    if db_user.is_none() {
        let new_user = match collection
            .insert_one(
                User {
                    id: None,
                    github_id: github_user.id,
                    username: github_user.login,
                    email: github_user.email,
                    display_name: None,
                    avatar: None,
                    permissions: Permissions::USER.bits(),
                    api_key: Uuid::new().to_string(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
                None,
            )
            .await
        {
            Ok(user) => user,
            Err(err) => {
                return HttpResponse::InternalServerError().json(json!({
                    "error": err.to_string()
                }))
            }
        };

        let user = match collection
            .find_one(doc! {"_id": new_user.inserted_id}, None)
            .await
        {
            Ok(user) => user,
            Err(e) => {
                return HttpResponse::InternalServerError().json(json!({
                    "error": e.to_string()
                }))
            }
        };

        if user.is_none() {
            return HttpResponse::InternalServerError().json(json!({
                "error": "failed to find user"
            }));
        }

        let token = encode(
            &Header::default(),
            &JWTAuth::new(user.unwrap()),
            &EncodingKey::from_secret(&data.key),
        )
        .unwrap();

        return HttpResponse::Ok().json(json!({
            "token": token,
        }));
    };

    let user = db_user.unwrap();

    let token = encode(
        &Header::default(),
        &JWTAuth::new(user),
        &EncodingKey::from_secret(&data.key),
    )
    .unwrap();

    HttpResponse::Ok().json(json!({
        "token": token,
    }))
}

#[derive(Serialize, Deserialize)]
pub struct GetUserApiKeyRequest {
    pub jwt: String,
}

#[get("/user/api_key")]
pub async fn get_user_api_key(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let token = get_bearer_auth(&req);

    if token.is_none() {
        return HttpResponse::Unauthorized().json(json!({
            "error": "missing token"
        }));
    }

    let jwt = decode::<JWTAuth>(
        &token.unwrap(),
        &DecodingKey::from_secret(&data.key),
        &Validation::new(Algorithm::HS256),
    );

    if jwt.is_err() {
        return HttpResponse::Unauthorized().json(json!({
            "error": "bad token"
        }));
    }

    let jwt = jwt.unwrap().claims;

    let collection = data.db.collection::<User>("users");
    let user = match collection.find_one(doc! {"_id": jwt.user.id}, None).await {
        Ok(user) => user,
        Err(e) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": e.to_string()
            }))
        }
    };

    if user.is_none() {
        return HttpResponse::Unauthorized().json(json!({
            "error": "bad token"
        }));
    }

    let user = user.unwrap();

    HttpResponse::Ok().json(json!({
        "api_key": user.api_key,
    }))
}
