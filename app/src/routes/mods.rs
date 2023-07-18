use actix_web::{get, web, HttpRequest, HttpResponse, Responder};
use entity::{beat_saber_versions, categories, mod_versions, mods, versions};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect, RelationDef};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::AppState;

#[get("/mods/categories")]
pub async fn get_categories(data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(json!({ "categories": categories::Entity::find().all(&data.db).await.unwrap().iter().map(|c| c.name.clone()).collect::<Vec<String>>() }))
}

#[get("/game_versions")]
pub async fn get_game_versions(data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(json!({ "game_versions": beat_saber_versions::Entity::find().all(&data.db).await.unwrap().iter().map(|m| m.ver.clone()).collect::<Vec<String>>() }))
}

#[derive(Serialize, Deserialize)]
pub struct ModRequestQuery {
    game_version: String, // semver req
    category: Option<String>,
    sort_by: Option<String>,
    search: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
}

#[get("/mods")]
pub async fn get_mods(
    data: web::Data<AppState>,
    query: web::Query<ModRequestQuery>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(10);
    if limit > 100 {
        return HttpResponse::BadRequest().json(json!({
            "error": "Limit cannot be greater than 100."
        }));
    }

    let offset = query.offset.unwrap_or(0);

    let looking_version = match VersionReq::parse(&query.game_version) {
        Ok(v) => v,
        Err(err) => {
            return HttpResponse::BadRequest().json(json!({
                "error": err.to_string()
            }))
        }
    };

    let mut mods_query_base = mods::Entity::find();

    if query.category.is_some() {
        mods_query_base = mods_query_base
            .filter(mods::Column::Category.contains(query.category.as_ref().unwrap()));
    };

    if query.search.is_some() {
        mods_query_base =
            mods_query_base.filter(mods::Column::Name.contains(query.search.as_ref().unwrap()));
    };

    let mods = mods_query_base.all(&data.db).await.unwrap();

    let mod_versions = mod_versions::Entity::find().all(&data.db).await.unwrap();
    let versions = versions::Entity::find().all(&data.db).await.unwrap();

    let mut found_mods = vec![];
    for m in mods {
        let mut found = false;
        for mv in mod_versions.iter().filter(|mv| mv.mod_id == m.id) {
            for v in versions.iter().filter(|v| v.id == mv.version_id) {
                if looking_version.matches(&Version::parse(&v.version).unwrap()) {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        if found {
            found_mods.push(m); // I am for loop jesus - checksum 2023
        }
    }

    HttpResponse::Ok().json(json!({ "mods": found_mods }))
}
// #[get("/mods")]
// pub async fn get_mods(
//     data: web::Data<AppState>,
//     query: web::Query<ModRequestQuery>,
// ) -> impl Responder {
//     let mut mods = match data.db.collection::<Mod>("mods").find(None, None).await {
//         Ok(cursor) => cursor,
//         Err(err) => {
//             return HttpResponse::InternalServerError().json(json!({
//                 "error": err.to_string()
//             }))
//         }
//     };

//     let versions = data.db.collection::<ModVersion>("mods.versions");
//     let looking_version = Version::parse(&q/entityuery.version).unwrap();
//     let mut found_mods = vec![];

//     while mods.advance().await.unwrap() {
//         let forge_mod = mods.deserialize_current().unwrap();

//         for version in &forge_mod.versions {
//             // filter out versions that dont match the requested version
//             let version = versions
//                 .find_one(
//                     doc! {
//                         "_id": version
//                     },
//                     None,
//                 )
//                 .await
//                 .unwrap()
//                 .unwrap();

//             if !version.game_version.matches(&looking_version) {
//                 continue;
//             }

//             // filter out mods that dont match the requested category
//             if let Some(category) = &query.category {
//                 if forge_mod.category != *category {
//                     continue;
//                 }
//             }

//             // search the name and description for the search query
//             if let Some(search) = &query.search {
//                 let search = search.to_lowercase();
//                 if !forge_mod.name.to_lowercase().contains(&search)
//                     && !forge_mod.description.to_lowercase().contains(&search)
//                 {
//                     continue;
//                 }
//             }
//         }

//         found_mods.push(forge_mod.clone());
//     }

//     // sort the mods by the requested sort method
//     if let Some(sort_by) = &query.sort_by {
//         match sort_by.as_str() {
//             "name" => found_mods.sort_by(|a, b| a.name.cmp(&b.name)),
//             "downloads" => found_mods.sort_by(|a, b| b.stats.downloads.cmp(&a.stats.downloads)),
//             "updated" => found_mods.sort_by(|a, b| b.updated_at.cmp(&a.updated_at)),
//             "created" => found_mods.sort_by(|a, b| b.created_at.cmp(&a.created_at)),
//             _ => (),
//         }
//     }

//     // limit the amount of mods returned
//     let limit = query.limit.unwrap_or(10);
//     let offset = query.offset.unwrap_or(0);

//     let mods = found_mods
//         .into_iter()
//         .skip(offset as usize)
//         .take(limit as usize)
//         .collect::<Vec<Mod>>();

//     HttpResponse::Ok().json(json!({
//         "mods": mods,
//         "total": mods.len()
//     }))
// }

// #[derive(Serialize, Deserialize)]
// pub struct GetModRequest {
//     pub id: String,
// }

// #[get("/mods/{id}")]
// pub async fn get_mod(
//     data: web::Data<AppState>,
//     _req: HttpRequest,
//     path: web::Path<GetModRequest>,
// ) -> impl Responder {
//     let oid = path.id.clone();

//     let mod_id = match ObjectId::parse_str(&oid) {
//         Ok(oid) => oid,
//         Err(err) => {
//             return HttpResponse::BadRequest().json(json!({
//                 "error": err.to_string()
//             }))
//         }
//     };

//     let forge_mod = data
//         .db
//         .collection::<Mod>("mods")
//         .find_one(
//             Some(doc! {
//                 "_id": mod_id
//             }),
//             None,
//         )
//         .await
//         .unwrap();

//     match forge_mod {
//         Some(forge_mod) => HttpResponse::Ok().json(json!({ "mod": forge_mod })),
//         None => HttpResponse::NotFound().json(json!({
//             "error": "Mod not found"
//         })),
//     }
// }

// /// This endpoint is used to publish a mod to the forge registry by taking in a .forgemod file
// #[post("/mods")]
// pub async fn create_mod(
//     data: web::Data<AppState>,
//     req: HttpRequest,
//     mut payload: web::Payload,
// ) -> impl Responder {
//     // Check who is uploading the mod via their auth token and make sure they are allowed to upload mods
//     let token = get_bearer_auth(&req);

//     dbg!(&token);

//     if token.is_none() {
//         return HttpResponse::Unauthorized().json(json!({
//             "error": "Missing api token."
//         }));
//     }

//     let token = token.unwrap();

//     let user = match data
//         .db
//         .collection::<User>("users")
//         .find_one(
//             Some(doc! {
//                 "api_key": token
//             }),
//             None,
//         )
//         .await
//     {
//         Ok(user) => user,
//         Err(err) => {
//             return HttpResponse::InternalServerError().json(json!({
//                 "error": err.to_string()
//             }))
//         }
//     };

//     if user.is_none() {
//         return HttpResponse::Unauthorized().json(json!({
//             "error": "Invalid api token."
//         }));
//     }

//     let user = user.unwrap();

//     if !Permission::UPLOAD_MOD.has_bits(user.permissions) {
//         return HttpResponse::Unauthorized().json(json!({
//             "error": "You do not have permission to upload mods."
//         }));
//     }

//     // Read the payload into a byte array
//     let mut bytes = vec![];
//     while let Some(item) = payload.next().await {
//         let item = item.unwrap();
//         bytes.extend_from_slice(&item);
//     }

//     // Parse the byte array into a ForgeMod
//     let forge_mod = match ForgeMod::try_from(bytes.as_slice()) {
//         Ok(forge_mod) => forge_mod,
//         Err(_) => {
//             return HttpResponse::BadRequest().json(json!({
//                 "error": "The file you uploaded is not a valid ForgeMod."
//             }))
//         }
//     };

//     let conflicting_mod = data
//         .db
//         .collection::<Mod>("mods")
//         .find_one(
//             Some(doc! {
//                 "id": &forge_mod.manifest._id
//             }),
//             None,
//         )
//         .await
//         .unwrap();

//     let forge_mod_id = ObjectId::new();
//     let version_id = ObjectId::new();

//     match conflicting_mod {
//         Some(mut conflicting_mod) => {
//             // check if the user is the owner of the conflicting mod
//             if conflicting_mod.author_id != user.id.unwrap() {
//                 return HttpResponse::Conflict().json(json!({
//                     "error": "A mod with that name already exists."
//                 }));
//             }

//             let version = ModVersion {
//                 id: Some(version_id),
//                 mod_id: forge_mod_id,
//                 version: forge_mod.manifest.version,
//                 game_version: forge_mod.manifest.game_version,
//                 approved: false,
//                 stats: ModVersionStats { downloads: 0 },
//                 dependencies: vec![], // todo: support this later
//                 conflicts: vec![],    // todo: support this later
//                 created_at: Utc::now(),
//             };

//             conflicting_mod.name = forge_mod.manifest.name;
//             conflicting_mod.description = forge_mod.manifest.description;
//             conflicting_mod.website = forge_mod.manifest.website;
//             conflicting_mod.category = forge_mod.manifest.category;
//             conflicting_mod.versions.push(version_id);
//             conflicting_mod.updated_at = Utc::now();

//             let db_version = data
//                 .db
//                 .collection::<ModVersion>("mods.versions")
//                 .insert_one(version, None)
//                 .await;

//             if db_version.is_err() {
//                 return HttpResponse::InternalServerError().json(json!({
//                     "error": db_version.unwrap_err().to_string()
//                 }));
//             }

//             let db_mod = data
//                 .db
//                 .collection::<Mod>("mods")
//                 .replace_one(doc! { "_id": conflicting_mod._id }, &conflicting_mod, None)
//                 .await;

//             if db_mod.is_err() {
//                 return HttpResponse::InternalServerError().json(json!({
//                     "error": db_mod.unwrap_err().to_string()
//                 }));
//             }

//             HttpResponse::Created().json(json!({ "mod": conflicting_mod }))
//         }

//         None => {
//             let db_mod = Mod {
//                 _id: Some(forge_mod_id),
//                 id: forge_mod.manifest._id.clone(),
//                 author_id: user.id.unwrap(),
//                 name: forge_mod.manifest.name.clone(),
//                 description: forge_mod.manifest.description.clone(),
//                 cover: String::new(),
//                 icon: String::new(),
//                 website: forge_mod.manifest.website.clone(),
//                 category: forge_mod.manifest.category.clone(),
//                 versions: vec![version_id],
//                 stats: ModStats { downloads: 0 },
//                 created_at: Utc::now(),
//                 updated_at: Utc::now(),
//             };

//             let version = ModVersion {
//                 id: Some(version_id),
//                 mod_id: forge_mod_id,
//                 version: forge_mod.manifest.version.clone(),
//                 game_version: forge_mod.manifest.game_version.clone(),
//                 approved: false,
//                 stats: ModVersionStats { downloads: 0 },
//                 dependencies: vec![], // todo: support this later
//                 conflicts: vec![],    // todo: support this later
//                 created_at: Utc::now(),
//             };

//             if data
//                 .db
//                 .collection::<ModVersion>("mods.versions")
//                 .insert_one(version, None)
//                 .await
//                 .is_err()
//             {
//                 return HttpResponse::InternalServerError().json(json!({
//                     "error": "Failed to insert mod version into database."
//                 }));
//             }

//             if data
//                 .db
//                 .collection::<Mod>("mods")
//                 .insert_one(db_mod, None)
//                 .await
//                 .is_err()
//             {
//                 return HttpResponse::InternalServerError().json(json!({
//                     "error": "Failed to insert mod into database."
//                 }));
//             }

//             if data
//                 .db
//                 .collection::<User>("users")
//                 .update_one(
//                     doc! { "_id": user.id.unwrap() },
//                     doc! { "$push": { "mods": forge_mod_id } },
//                     None,
//                 )
//                 .await
//                 .is_err()
//             {
//                 return HttpResponse::InternalServerError().json(json!({
//                     "error": "Failed to update user in database."
//                 }));
//             }

//             HttpResponse::Created().json(json!({ "mod": forge_mod }))
//         }
//     }
// }
