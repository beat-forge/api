use crate::{routes::users::User, AppState};
use actix_web::{get, http::header, post, web, HttpRequest, HttpResponse, Responder};
use chrono::{DateTime, Utc};
use forge_lib::structs::{forgemod::ForgeMod, manifest::ModCategory};
use futures::StreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[get("/mods/categorys")]
pub async fn categorys(_req: HttpRequest) -> impl Responder {
    let res = vec![
        ModCategory::Core,
        ModCategory::Libraries,
        ModCategory::Cosmetic,
        ModCategory::Gameplay,
        ModCategory::Leaderboards,
        ModCategory::Lighting,
        ModCategory::Multiplayer,
        ModCategory::Accessibility,
        ModCategory::Practice,
        ModCategory::Streaming,
        ModCategory::Text,
        ModCategory::Tweaks,
        ModCategory::UI,
        ModCategory::Other,
    ];

    HttpResponse::Ok().json(json!({ "categorys": res }))
}

#[get("/mods")]
pub async fn get_mods(_req: HttpRequest) -> impl Responder {
    todo!("get mods from database");
    HttpResponse::Ok().json(json!({"mods": []}))
}

#[get("/mods/{mod_id}")]
pub async fn get_mod_by_id(_req: HttpRequest, _path: web::Path<Uuid>) -> impl Responder {
    todo!("get mod from database");
    HttpResponse::Ok().json(json!({"mods": []}))
}

//TODO: cache endpoint
#[get("/mods/by_game_semver/{game_version}")]
pub async fn get_mods_by_game_semver(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let version = Version::parse(&path).unwrap();

    let mut matching_versions = vec![];

    let mut mods = data
        .db
        .collection::<DBMod>("mods")
        .find(None, None)
        .await
        .unwrap();

    while mods.advance().await.unwrap() {
        for verison in mods.deserialize_current().unwrap().versions {
            let version_req = VersionReq::parse(&verison.manifest.game_version).unwrap();

            if version_req.matches(&version) {
                matching_versions.push(verison);
            }
        }
    }

    HttpResponse::Ok().json(json!({ "mods": matching_versions }))
}

#[post("/mods")]
pub async fn create_mod(
    req: HttpRequest,
    data: web::Data<AppState>,
    mut payload: web::Payload,
) -> Result<HttpResponse, actix_web::Error> {
    let api_key = req.headers().get(header::AUTHORIZATION).unwrap();

    let users = data.db.collection::<User>("users");
    let user = users
        .find_one(doc! {"api_key": api_key.to_str().unwrap()}, None)
        .await
        .unwrap();

    if user.is_none() {
        return Err(actix_web::error::ErrorUnauthorized("Invalid api key"));
    }

    let user = user.unwrap();

    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;

        if (body.len() + chunk.len()) > 10_485_760 {
            return Err(actix_web::error::ErrorPayloadTooLarge("Payload too large"));
        }

        body.extend_from_slice(&chunk);
    }

    let forge_mod = ForgeMod::try_from(&body.freeze()[..]).unwrap();

    let new_version = ModVersion {
        manifest: forge_mod.manifest.clone(),
        download_url: "".to_string(),
        approved: false,
        created_at: Utc::now(),
    };

    let existing_mod = data
        .db
        .collection::<DBMod>("mods")
        .find_one(doc! {"name": forge_mod.manifest.name.clone()}, None)
        .await
        .unwrap();

    if existing_mod.is_some() {
        // Publish a new version
        let mut existing_mod = existing_mod.unwrap();
        existing_mod.versions.push(new_version);

        let collection = data.db.collection::<DBMod>("mods");
        let res = match collection
            .replace_one(doc! {"_id": existing_mod.id.unwrap()}, existing_mod, None)
            .await
        {
            Ok(res) => res,
            Err(e) => return Err(actix_web::error::ErrorInternalServerError(e)),
        };

        return Ok(HttpResponse::Ok().json(json!({
            "mod_id": res.upserted_id
        })));
    } else {
        // Create a new mod
        let r#mod = DBMod {
            id: None,
            name: forge_mod.manifest.name.clone(),
            author_id: user.id.unwrap(),
            versions: vec![new_version],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let collection = data.db.collection("mods");

        let res = match collection.insert_one(r#mod, None).await {
            Ok(res) => res,
            Err(e) => return Err(actix_web::error::ErrorInternalServerError(e)),
        };

        return Ok(HttpResponse::Ok().json(json!({
            "mod_id": res.inserted_id
        })));
    }
}

#[derive(Serialize, Deserialize)]
pub struct ModVersion {
    pub manifest: forge_lib::structs::manifest::ForgeManifest,
    pub download_url: String,
    pub approved: bool,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct DBMod {
    #[serde(rename = "_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub name: String,
    pub author_id: ObjectId,
    pub versions: Vec<ModVersion>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}
