use std::str::FromStr;

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use mongodb::bson::{doc, oid::ObjectId};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    structs::{
        auth::JWTAuth,
        github::{GithubAccessToken, GithubUser},
        users::User,
    },
    utils::get_bearer_auth,
    AppState,
};

#[derive(Serialize, Deserialize)]
pub struct GetUserRequest {
    pub id: String,
}

#[derive(Serialize, Deserialize)]
pub struct UnprivilegedUser {
    pub github_id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
    pub bio: Option<String>,
    pub mods: Vec<ObjectId>,
    pub permissions: i32,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

#[get("/user/{id}")]
pub async fn get_user(
    req: HttpRequest,
    path: web::Path<GetUserRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user = data
        .db
        .collection::<User>("users")
        .find_one(doc! { "_id": ObjectId::from_str(&path.id).unwrap() }, None)
        .await
        .unwrap();

    if user.is_none() {
        return HttpResponse::NotFound().json(json!({
            "error": "user not found"
        }));
    }

    let user = user.unwrap();

    match get_bearer_auth(&req) {
        Some(jwt) => {
            let token = decode::<JWTAuth>(
                &jwt,
                &DecodingKey::from_secret(&data.key),
                &Validation::default(),
            );

            if token.is_err() {
                return HttpResponse::Unauthorized().json(json!({
                    "error": "invalid token"
                }));
            }

            let token = token.unwrap();

            if token.claims.user.id != user.id {
                return HttpResponse::Unauthorized().json(json!({
                    "error": "invalid token"
                }));
            }

            HttpResponse::Ok().json(user)
        }
        None => HttpResponse::Ok().json(UnprivilegedUser {
            github_id: user.github_id,
            username: user.username,
            display_name: user.display_name,
            avatar: user.avatar,
            bio: user.bio,
            mods: user.mods,
            permissions: user.permissions,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }),
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthUserRequest {
    pub code: String, // github oauth code
}

#[post("/user/auth")]
pub async fn auth_user(
    data: web::Data<AppState>,
    req: web::Json<AuthUserRequest>,
) -> impl Responder {
    let client = Client::builder()
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
        let new_user = match collection.insert_one(User::from(github_user), None).await {
            Ok(user) => user,
            Err(e) => {
                return HttpResponse::InternalServerError().json(json!({
                    "error": e.to_string()
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
