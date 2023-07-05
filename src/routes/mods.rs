use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use forge_lib::structs::{forgemod::ForgeMod, manifest::ModCategory};
use futures::StreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    structs::{
        mods::{DBMod, ModVersion},
        users::{Permission, User},
    },
    utils::get_bearer_auth,
    AppState,
};

static MOD_CATEGORYS: [ModCategory; 14] = [
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

#[get("/mods/categorys")]
pub async fn categorys(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok().json(json!({ "categorys": MOD_CATEGORYS }))
}

#[derive(Serialize, Deserialize)]
pub struct ModRequestQuery {
    version: String,
    category: Option<ModCategory>,
    sort_by: Option<String>,
    search: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[get("/mods")]
pub async fn get_mods(
    data: web::Data<AppState>,
    query: web::Query<ModRequestQuery>,
) -> impl Responder {
    let mut mods = match data.db.collection::<DBMod>("mods").find(None, None).await {
        Ok(cursor) => cursor,
        Err(err) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": err.to_string()
            }))
        }
    };

    let mut found_mods = vec![];
    let looking_version = Version::parse(&query.version).unwrap();

    while mods.advance().await.unwrap() {
        let forge_mod = mods.deserialize_current().unwrap();

        forge_mod.versions.iter().for_each(|version| {
            // filter out versions that dont match the requested version
            if !VersionReq::parse(&version.manifest.game_version)
                .unwrap()
                .matches(&looking_version)
            {
                return;
            }

            // filter out versions that dont match the requested category
            if let Some(category) = &query.category {
                if version.manifest.category != *category {
                    return;
                }
            }

            // search the name and description for the search query
            if let Some(search) = &query.search {
                let search = search.to_lowercase();
                if !version.manifest.name.to_lowercase().contains(&search)
                    && !version
                        .manifest
                        .description
                        .to_lowercase()
                        .contains(&search)
                {
                    return;
                }
            }

            found_mods.push(forge_mod.clone());
        });
    }

    // sort the mods by the requested sort method
    if let Some(sort_by) = &query.sort_by {
        match sort_by.as_str() {
            "name" => found_mods.sort_by(|a, b| a.name.cmp(&b.name)),
            "downloads" => found_mods.sort_by(|a, b| b.downloads.cmp(&a.downloads)),
            "updated" => found_mods.sort_by(|a, b| b.updated_at.cmp(&a.updated_at)),
            "created" => found_mods.sort_by(|a, b| b.created_at.cmp(&a.created_at)),
            _ => (),
        }
    }

    // limit the amount of mods returned
    let limit = query.limit.unwrap_or(10);
    let offset = query.offset.unwrap_or(0);

    let mods = found_mods
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect::<Vec<DBMod>>();

    HttpResponse::Ok().json(json!({
        "mods": mods,
        "total": mods.len()
    }))
}

#[derive(Serialize, Deserialize)]
pub struct GetModRequest {
    pub id: String,
}

#[get("/mods/{id}")]
pub async fn get_mod(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<GetModRequest>,
) -> impl Responder {
    let oid = path.id.clone();

    let mod_id = match ObjectId::parse_str(&oid) {
        Ok(oid) => oid,
        Err(err) => {
            return HttpResponse::BadRequest().json(json!({
                "error": err.to_string()
            }))
        }
    };

    let forge_mod = data
        .db
        .collection::<DBMod>("mods")
        .find_one(
            Some(doc! {
                "_id": mod_id
            }),
            None,
        )
        .await
        .unwrap();

    match forge_mod {
        Some(forge_mod) => HttpResponse::Ok().json(json!({ "mod": forge_mod })),
        None => HttpResponse::NotFound().json(json!({
            "error": "Mod not found"
        })),
    }
}

/// This endpoint is used to publish a mod to the forge registry by taking in a .forgemod file
#[post("/mods")]
pub async fn create_mod(
    data: web::Data<AppState>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    // Check who is uploading the mod via their auth token and make sure they are allowed to upload mods
    let token = get_bearer_auth(&req);

    if token.is_none() {
        return HttpResponse::Unauthorized().json(json!({
            "error": "Missing api token."
        }));
    }

    let token = token.unwrap();

    let user = match data
        .db
        .collection::<User>("users")
        .find_one(
            Some(doc! {
                "api_key": token
            }),
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

    if user.is_none() {
        return HttpResponse::Unauthorized().json(json!({
            "error": "Invalid api token."
        }));
    }

    let user = user.unwrap();

    if !Permission::UPLOAD_MOD.has_bits(user.permissions) {
        return HttpResponse::Unauthorized().json(json!({
            "error": "You do not have permission to upload mods."
        }));
    }

    // Read the payload into a byte array
    let mut bytes = vec![];
    while let Some(item) = payload.next().await {
        let item = item.unwrap();
        bytes.extend_from_slice(&item);
    }

    // Parse the byte array into a ForgeMod
    let forge_mod = match ForgeMod::try_from(bytes.as_slice()) {
        Ok(forge_mod) => forge_mod,
        Err(_) => {
            return HttpResponse::BadRequest().json(json!({
                "error": "The file you uploaded is not a valid ForgeMod."
            }))
        }
    };

    let manifest = forge_mod.manifest.clone();
    let mut db_mod = DBMod {
        id: None,
        name: manifest.name,
        author_id: user.id.unwrap(),
        description: manifest.description,
        versions: Vec::new(),
        downloads: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Check if the mod already exists
    let existing_mod = data
        .db
        .collection::<DBMod>("mods")
        .find_one(
            Some(doc! {
                "name": db_mod.name.clone()
            }),
            None,
        )
        .await
        .unwrap();

    if let Some(existing_mod) = existing_mod {
        // add a new version to the existing mod
        db_mod.id = existing_mod.id;
        db_mod.versions = existing_mod.versions;
        db_mod.downloads = existing_mod.downloads;
        db_mod.created_at = existing_mod.created_at;
        db_mod.updated_at = Utc::now();

        // add the new version to the mod
        let new_version = ModVersion {
            manifest: forge_mod.manifest,
            downloads: 0,
            download_url: "".to_string(),
            approved: false,
            created_at: Utc::now(),
        };

        db_mod.versions.push(new_version);

        // update the mod in the database
        let forge_mod = data
            .db
            .collection::<DBMod>("mods")
            .find_one_and_replace(
                doc! { "_id": db_mod.id.clone().unwrap() },
                db_mod.clone(),
                None,
            )
            .await
            .unwrap();

        HttpResponse::Ok().json(json!({ "mod": forge_mod }))
    } else {
        // create a new mod
        db_mod.versions.push(ModVersion {
            manifest: forge_mod.manifest,
            downloads: 0,
            download_url: "".to_string(),
            approved: false,
            created_at: Utc::now(),
        });

        // insert the mod into the database
        let forge_mod = data
            .db
            .collection::<DBMod>("mods")
            .insert_one(db_mod.clone(), None)
            .await
            .unwrap();

        HttpResponse::Ok().json(json!({ "mod": forge_mod }))
    }
}
