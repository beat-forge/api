use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use chrono::{DateTime, Utc};
use entity::{categories, mod_stats, mods, users, users_mods, version_stats, versions, version_beat_saber_versions, beat_saber_versions};
use forge_lib::structs::manifest::ModCategory;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use reqwest::Client;
use sea_orm::{
    ColumnTrait, EntityTrait, JoinType, QueryFilter, QuerySelect, Related, RelationTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    structs::github::{GithubAccessToken, GithubUser},
    utils::get_bearer_auth,
    AppState,
};

#[derive(Serialize, Deserialize)]
pub struct GetUserRequest {
    pub id: Uuid,
}

pub struct _Mod {
    pub r#mod: mods::Model,
    pub category: categories::Model,
    pub stats: mod_stats::Model,
    pub versions: Vec<_Version>
}

pub struct _Version {
    pub version: versions::Model,
    pub stats: version_stats::Model,
    pub game_versions: Vec<beat_saber_versions::Model>,
}

#[get("/user/{id}")]
pub async fn get_user(
    path: web::Path<GetUserRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user = users::Entity::find_by_id(path.id)
        .one(&data.db)
        .await
        .unwrap();

    if user.is_none() {
        return HttpResponse::NotFound().json(json!({
            "error": "user not found"
        }));
    }

    let user = user.unwrap();

    let mods: sea_orm::Select<mods::Entity> =
        users_mods::Entity::find_related().filter(users_mods::Column::UserId.eq(user.id));

    let mods = mods.all(&data.db).await.unwrap();

    let mut res_mods = Vec::new();

    for m in mods {
        let category = categories::Entity::find_by_id(m.category.unwrap())
            .one(&data.db)
            .await
            .unwrap()
            .unwrap();

        let versions = versions::Entity::find()
            .filter(versions::Column::ModId.eq(m.id))
            .all(&data.db)
            .await
            .unwrap();

        let stats = mod_stats::Entity::find_by_id(m.stats.unwrap())
            .one(&data.db)
            .await
            .unwrap()
            .unwrap();

        let mut res_versions = Vec::new();

        for v in versions {
            let stats = version_stats::Entity::find_by_id(v.stats)
                .one(&data.db)
                .await
                .unwrap()
                .unwrap();

            let game_versions: sea_orm::Select<beat_saber_versions::Entity> =
                version_beat_saber_versions::Entity::find_related()
                    .filter(version_beat_saber_versions::Column::VersionId.eq(v.id));
            
            let game_versions = game_versions.all(&data.db).await.unwrap();

            res_versions.push(_Version {
                version: v.clone(),
                stats,
                game_versions
            });
        }

        res_mods.push(_Mod {
            r#mod: m.clone(),
            category,
            stats,
            versions: res_versions,
        })
    }

    HttpResponse::Ok().json(json!({
        "user": {
            "id": user.id,
            "github_id": user.github_id,
            "username": user.username,
            "display_name": user.display_name,
            "avatar": user.avatar,
            "bio": user.bio,
            "mods": res_mods.iter().map(|m| {
                json!({
                    "id": m.r#mod.id,
                    "name": m.r#mod.name,
                    "description": m.r#mod.description,
                    "category": m.category.name,
                    "stats": {
                        "downloads": m.stats.downloads,
                    },
                    "versions": m.versions.iter().map(|v| {
                        json!({
                            "id": v.version.id,
                            "version": v.version.version,
                            "approved": v.version.approved,
                            "game_versions": v.game_versions.iter().map(|gv| 
                                &gv.ver
                            ).collect::<Vec<&String>>(),
                            "stats": {
                                "downloads": v.stats.downloads,
                            },
                        })
                    }).collect::<Vec<Value>>(),
                })
            }).collect::<Vec<Value>>(),
            "permissions": user.permissions,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        }
    }))
}

//     if user.is_none() {
//         return HttpResponse::NotFound().json(json!({
//             "error": "user not found"
//         }));
//     }

//     let user = user.unwrap();

//     match get_bearer_auth(&req) {
//         Some(jwt) => {
//             let token = decode::<JWTAuth>(
//                 &jwt,
//                 &DecodingKey::from_secret(&data.key),
//                 &Validation::default(),
//             );

//             if token.is_err() {
//                 return HttpResponse::Unauthorized().json(json!({
//                     "error": "invalid token"
//                 }));
//             }

//             let token = token.unwrap();

//             if token.claims.user.id != user.id {
//                 return HttpResponse::Unauthorized().json(json!({
//                     "error": "invalid token"
//                 }));
//             }

//             HttpResponse::Ok().json(user)
//         }
//         None => HttpResponse::Ok().json(UnprivilegedUser {
//             github_id: user.github_id,
//             username: user.username,
//             display_name: user.display_name,
//             avatar: user.avatar,
//             bio: user.bio,
//             mods: user.mods,
//             permissions: user.permissions,
//             created_at: user.created_at,
//             updated_at: user.updated_at,
//         }),
//     }
// }

// #[derive(Serialize, Deserialize)]
// pub struct AuthUserRequest {
//     pub code: String, // github oauth code
// }

// #[post("/user/auth")]
// pub async fn auth_user(
//     data: web::Data<AppState>,
//     req: web::Json<AuthUserRequest>,
// ) -> impl Responder {
//     let client = Client::builder()
//         .user_agent("forge-registry")
//         .build()
//         .unwrap();

//     let request = client
//         .post("https://github.com/login/oauth/access_token")
//         .header("Accept", "application/json")
//         .json(&json!({
//             "client_id": std::env::var("GITHUB_CLIENT_ID").unwrap(),
//             "client_secret": std::env::var("GITHUB_CLIENT_SECRET").unwrap(),
//             "code": req.code,
//         }))
//         .send()
//         .await
//         .unwrap();

//     let response = request.json::<GithubAccessToken>().await;
//     if response.is_err() {
//         return HttpResponse::BadRequest().json(json!({
//             "error": "invalid code"
//         }));
//     }

//     let access_token = response.unwrap().access_token;

//     let github_user = client
//         .get("https://api.github.com/user")
//         .bearer_auth(access_token)
//         .send()
//         .await
//         .unwrap()
//         .json::<GithubUser>()
//         .await
//         .unwrap();

//     let collection = data.db.collection::<User>("users");
//     let db_user = match collection
//         .find_one(doc! {"github_id":github_user.id}, None)
//         .await
//     {
//         Ok(user) => user,
//         Err(e) => {
//             return HttpResponse::InternalServerError().json(json!({
//                 "error": e.to_string()
//             }))
//         }
//     };

//     if db_user.is_none() {
//         let new_user = match collection.insert_one(User::from(github_user), None).await {
//             Ok(user) => user,
//             Err(e) => {
//                 return HttpResponse::InternalServerError().json(json!({
//                     "error": e.to_string()
//                 }))
//             }
//         };

//         let user = match collection
//             .find_one(doc! {"_id": new_user.inserted_id}, None)
//             .await
//         {
//             Ok(user) => user,
//             Err(e) => {
//                 return HttpResponse::InternalServerError().json(json!({
//                     "error": e.to_string()
//                 }))
//             }
//         };

//         if user.is_none() {
//             return HttpResponse::InternalServerError().json(json!({
//                 "error": "failed to find user"
//             }));
//         }

//         let token = encode(
//             &Header::default(),
//             &JWTAuth::new(user.unwrap()),
//             &EncodingKey::from_secret(&data.key),
//         )
//         .unwrap();

//         return HttpResponse::Ok().json(json!({
//             "token": token,
//         }));
//     };

//     let user = db_user.unwrap();

//     let token = encode(
//         &Header::default(),
//         &JWTAuth::new(user),
//         &EncodingKey::from_secret(&data.key),
//     )
//     .unwrap();

//     HttpResponse::Ok().json(json!({
//         "token": token,
//     }))
// }
