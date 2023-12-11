use async_graphql::{SimpleObject, FieldResult, FieldError, Error};
use chrono::{DateTime, Utc};
use entity::prelude::*;
use poem::{handler, web::{Query, Json}, Response, Request, IntoResponse, http::StatusCode};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set, DatabaseConnection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;
use uuid::Uuid;

use crate::{
    auth::{validate_permissions, Authorization, JWTAuth, Permission},
    mods::{self, Mod},
    KEY, DB_POOL
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
    async fn from_db_user(db: &DatabaseConnection, u: entity::users::Model) -> Result<Self, FieldError> {
        Ok(User {
            id: Uuid::from_bytes(*u.id.as_bytes()),
            github_id: u.github_id.to_string(),
            username: u.username,
            display_name: u.display_name,
            email: Some(u.email),
            bio: u.bio,
            mods: mods::find_by_author(db, Uuid::from_bytes(*u.id.as_bytes()))
                .await
                .unwrap(),
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
    db: &DatabaseConnection,
    limit: i32,
    offset: i32,
    auth: Authorization,
) -> FieldResult<Vec<User>> {
    let limit = limit as u64;
    let offset = offset as u64;

    let users = Users::find()
        .limit(Some(limit))
        .offset(Some(offset))
        .all(db)
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
        _users.push(User::from_db_user(db, user).await.unwrap());
    }

    let mut users = _users;

    if let Some(usr) = &auser {
        futures::future::join_all(
            users
                .iter_mut()
                .map(move |user| async move {
                    if usr.id.as_bytes() != user.id.as_bytes() && !validate_permissions(user.clone(), Permission::VIEW_OTHER).await {
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

pub async fn find_by_id(db: &DatabaseConnection, _id: Uuid, auth: Authorization) -> FieldResult<User> {
    let id = sea_orm::prelude::Uuid::from_bytes(*_id.as_bytes());

    let user = Users::find_by_id(id).one(db).await?;

    if user.is_none() {
        return Err(Error::new(
            "User not found"
        ));
    }

    let mut user = User::from_db_user(db, user.unwrap()).await?;

    // check auth
    let auser = auth.get_user(db).await;
    if let Some(usr) = auser {
        if usr.id.as_bytes() != user.id.as_bytes() && !validate_permissions(&user, Permission::VIEW_OTHER).await {
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
    let db = DB_POOL.get().unwrap().clone();

    let gat = minreq::post("https://github.com/login/oauth/access_token")
        .with_header("User-Agent", "forge-registry")
        .with_json(&json!({
            "client_id": std::env::var("GITHUB_CLIENT_ID").unwrap(),
            "client_secret": std::env::var("GITHUB_CLIENT_SECRET").unwrap(),
            "code": code,
        }))
        .unwrap()
        .send()
        .unwrap();

    let gat = gat.as_str().unwrap().split('&').collect::<Vec<_>>()[0]
        .split('=')
        .collect::<Vec<_>>()[1]
        .to_string();

    let github_user = minreq::get("https://api.github.com/user")
        .with_header("User-Agent", "forge-registry")
        .with_header("Authorization", format!("Bearer {}", gat))
        .send()
        .unwrap();

    debug!("{}", github_user.as_str().unwrap());
    let github_user = serde_json::from_str::<GithubUser>(github_user.as_str().unwrap()).unwrap();

    let mby_user = Users::find()
        .filter(entity::users::Column::GithubId.eq(github_user.id as i32))
        .one(&db)
        .await
        .unwrap();

    if mby_user.is_none() {
        let usr = entity::users::ActiveModel {
            github_id: Set(github_user.id as i32),
            username: Set(github_user.login),
            email: Set(github_user.email.unwrap_or("".to_string())),
            bio: Set(github_user.bio),
            avatar: Set(github_user.avatar_url),
            permissions: Set(7),
            ..Default::default()
        };

        Users::insert(usr).exec(&db).await.unwrap();
    }

    let user = Users::find()
        .filter(entity::users::Column::GithubId.eq(github_user.id as i32))
        .one(&db)
        .await
        .unwrap()
        .unwrap();

    let jwt = JWTAuth::new(user).encode(*KEY.clone());

   Json(json!({ "jwt": jwt }))
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
pub async fn get_me(
    req: &Request
) -> impl IntoResponse {
    let db = DB_POOL.get().unwrap().clone();

    let auth = req
        .headers()
        .get("Authorization")
        .unwrap()
        .to_str()
        .unwrap();
    let auser;
    if auth.starts_with("Bearer") {
        let auth = Authorization::parse(Some(auth.split(" ").collect::<Vec<_>>()[1].to_string()));
        let user = auth.get_user(&db).await.unwrap();
        auser = user;
    } else {
        return Response::builder().status(StatusCode::UNAUTHORIZED).body("Unauthorized");
    }

    Json(auser).into_response()
}