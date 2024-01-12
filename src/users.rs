use async_graphql::{Error, FieldError, FieldResult, SimpleObject};
use chrono::{DateTime, Utc};
use poem::{
    handler,
    http::StatusCode,
    web::{Json, Query},
    IntoResponse, Request, Response,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::{
    auth::{validate_permissions, Authorization, JWTAuth, Permission},
    models,
    mods::{self, Mod},
    DB_POOL, KEY,
};

#[derive(SimpleObject, Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub id: Uuid,
    pub github_id: String,
    pub username: String,
    pub display_name: Option<String>,

    // Authed field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub bio: Option<String>,
    pub mods: Vec<Mod>,
    pub permissions: i32,
    pub avatar: Option<String>,
    pub banner: Option<String>,

    // Authed field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    async fn from_db_user(db: &PgPool, u: models::dUser) -> Result<Self, FieldError> {
        Ok(User {
            id: Uuid::from_bytes(*u.id.as_bytes()),
            github_id: u.github_id.to_string(),
            username: u.username,
            display_name: u.display_name,
            email: Some(u.email),
            bio: u.bio,
            mods: mods::find_by_author(db, Uuid::from_bytes(*u.id.as_bytes()))
                .await
                ?,
            avatar: u.avatar,
            banner: u.banner,
            permissions: u.permissions,
            api_key: Some(u.api_key.to_string()),
            created_at: u.created_at.and_utc(),
            updated_at: u.updated_at.and_utc(),
        })
    }
}

pub async fn find_all(
    db: &PgPool,
    limit: i32,
    offset: i32,
    auth: Authorization,
) -> FieldResult<Vec<User>> {
    let limit = limit as i64;
    let offset = offset as i64;

    // let users = Users::find()
    //     .limit(Some(limit))
    //     .offset(Some(offset))
    //     .all(db)
    //     .await?;
    let users = sqlx::query_as!(
        models::dUser,
        "SELECT * FROM users LIMIT $1 OFFSET $2",
        limit,
        offset
    )
    .fetch_all(db)
    .await?;

    let auser = auth.get_user(db).await;

    // let mut users = futures::future::join_all(
    //     users
    //         .into_iter()
    //         .map(|user| async move { User::from_db_user(db, user).await.unwrap() })
    //         .collect::<Vec<_>>(),
    // )
    // .await;
    let mut _users = vec![];
    for user in users {
        _users.push(User::from_db_user(db, user).await?);
    }

    let mut users = _users;

    if let Some(usr) = &auser {
        futures::future::join_all(
            users
                .iter_mut()
                .map(move |user| async move {
                    if usr.id.as_bytes() != user.id.as_bytes()
                        && !validate_permissions(user.clone(), Permission::VIEW_OTHER).await
                    {
                        user.email = None;
                        user.api_key = None;
                    }
                })
                .collect::<Vec<_>>(),
        )
        .await;
    } else {
        futures::future::join_all(
            users
                .iter_mut()
                .map(move |user| async move {
                    user.email = None;
                    user.api_key = None;
                })
                .collect::<Vec<_>>(),
        )
        .await;
    }

    Ok(users)
}

pub async fn find_by_id(db: &PgPool, _id: Uuid, auth: Authorization) -> FieldResult<User> {
    // let id = sea_orm::prelude::Uuid::from_bytes(*_id.as_bytes());

    // let user = Users::find_by_id(id).one(db).await?;
    let user = sqlx::query_as!(
        models::dUser,
        "SELECT * FROM users WHERE id = $1",
        sqlx::types::Uuid::from_bytes(*_id.as_bytes())
    )
    .fetch_optional(db)
    .await?;

    if user.is_none() {
        return Err(Error::new("User not found"));
    }

    let user = user.expect("Should not be none, as it is checked above");

    let mut user = User::from_db_user(db, user).await?;
    
    // check auth
    let auser = auth.get_user(db).await;
    if let Some(usr) = auser {
        if usr.id.as_bytes() != user.id.as_bytes()
            && !validate_permissions(&user, Permission::VIEW_OTHER).await
        {
            user.email = None;
            user.api_key = None;
        }
    }

    Ok(user)
}

#[derive(Deserialize, Serialize)]
pub struct UserAuthReq {
    pub code: String,
}

#[handler]
pub async fn user_auth(
    // _req: HttpRequest,
    // data: web::Data<Database>,
    // info: web::Query<UserAuthReq>,
    Query(UserAuthReq { code }): Query<UserAuthReq>,
) -> impl IntoResponse {
    let db = match DB_POOL.get() {
        Some(db) => {db},
        None => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    };

    let gat = match match minreq::post("https://github.com/login/oauth/access_token").with_header("User-Agent","forge-registry").with_json(&json!({"client_id":match std::env::var("BF_GITHUB_CLIENT_ID"){Ok(id)=>{id},Err(e)=>{error!("{}",e);return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body("Internal Server Error");},},"client_secret":match std::env::var("BF_GITHUB_CLIENT_SECRET"){Ok(secret)=>{secret},Err(e)=>{error!("{}",e);return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body("Internal Server Error");},},"code":code,})){Ok(req)=>{req},Err(e)=>{error!("{}",e);return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body("Internal Server Error");},}.send() {
        Ok(gat) => {gat},
        Err(e) => {
            error!("{}",e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Invalid Code");
        },
    };

    let gat = match gat.as_str() {
        Ok(gat) => {gat},
        Err(e) => {
            error!("{}",e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    }.split('&').collect::<Vec<_>>()[0]
        .split('=')
        .collect::<Vec<_>>()[1]
        .to_string();

    let github_user = match minreq::get("https://api.github.com/user").with_header("User-Agent","forge-registry").with_header("Authorization",format!("Bearer {}",gat)).send() {Ok(user) => {user},Err(e) => {error!("{}",e); return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body("Internal Server Error");},};

    let github_user = match github_user.as_str() {
        Ok(user) => {user},
        Err(e) => {
            error!("{}",e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    };

    let github_user = match serde_json::from_str:: <GithubUser>(github_user) {
        Ok(user) => {user},
        Err(e) => {
            error!("{}",e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Bad response from GitHub. Please try again later.");
        },
    };

    // let mby_user = Users::find()
    //     .filter(entity::users::Column::GithubId.eq(github_user.id as i32))
    //     .one(&db)
    //     .await
    //     .unwrap();

    // if mby_user.is_none() {
    //     let usr = entity::users::ActiveModel {
    //         github_id: Set(github_user.id as i32),
    //         username: Set(github_user.login),
    //         email: Set(github_user.email.unwrap_or("".to_string())),
    //         bio: Set(github_user.bio),
    //         avatar: Set(github_user.avatar_url),
    //         permissions: Set(7),
    //         ..Default::default()
    //     };

    //     Users::insert(usr).exec(&db).await.unwrap();
    // }

    // let user = Users::find()
    //     .filter(entity::users::Column::GithubId.eq(github_user.id as i32))
    //     .one(&db)
    //     .await
    //     .unwrap()
    //     .unwrap();

    let user = match sqlx::query_as!(models::dUser,"SELECT * FROM users WHERE github_id = $1",github_user.id as i32).fetch_optional(db).await {
        Ok(record) => {record},
        Err(e) => {
            error!("{}",e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    };

    if user.is_none() {
        match sqlx::query!("INSERT INTO users (github_id, username, email, bio, avatar, permissions) VALUES ($1, $2, $3, $4, $5, $6)",github_user.id as i32,github_user.login.clone(),github_user.email.unwrap_or("".to_string()),github_user.bio,github_user.avatar_url,7).execute(db).await {
            Ok(record) => {record},
            Err(e) => {
                error!("{}",e);
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            },
        };
    }

    let user = match sqlx::query_as!(models::dUser,"SELECT * FROM users WHERE github_id = $1",github_user.id as i32).fetch_one(db).await {
        Ok(record) => {record},
        Err(e) => {
            error!("{}",e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    };

    let jwt = match JWTAuth::new(user).encode(*KEY.clone()) {
        Ok(jwt) => jwt,
        Err(e) => {
            error!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        }
    };

    Json(json!({ "jwt": jwt })).into_response()
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GithubUser {
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub email: Option<String>,
    pub id: i64,
    pub login: String,
}

#[handler]
pub async fn get_me(req: &Request) -> impl IntoResponse {
    let db = match DB_POOL.get() {
        Some(db) => {
            db
        },
        None => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    }.clone();

    let auth = match match req.headers().get("Authorization"){Some(header)=>{header},None=>{return Response::builder().status(StatusCode::UNAUTHORIZED).body("Unauthorized. Missing Authorization header.");},}.to_str() {
        Ok(auth) => {auth},
        Err(e) => {
            error!("{}",e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    };

    let auser;
    if auth.starts_with("Bearer") {
        let auth = Authorization::parse(Some(auth.split(' ').collect::<Vec<_>>()[1].to_string()));
        let user = match auth.get_user(&db).await {
            Some(user) => {user},
            None => {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body("Unauthorized");
            },
        };
        auser = match User::from_db_user(&db,user).await {
            Ok(auser) => {auser},
            Err(e) => {
                error!("{}", e.message);
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            },
        };
    } else {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body("Unauthorized");
    }

    Json(auser).into_response()
}
