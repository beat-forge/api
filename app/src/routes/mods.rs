use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use entity::{beat_saber_versions, categories, mod_stats, mod_versions, mods, users, versions, users_mods, version_beat_saber_versions, version_stats};
use forge_lib::structs::forgemod::ForgeMod;
use futures::StreamExt;
use rayon::prelude::*;
use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, RelationDef};
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
    let mod_stats = mod_stats::Entity::find().all(&data.db).await.unwrap();

    let versions = versions::Entity::find().all(&data.db).await.unwrap();

    let mut found_mods = vec![];

    mods.into_iter().for_each(|m| {
        let mut found = false;

        mod_versions
            .iter()
            .filter(|mv| mv.mod_id == m.id)
            .into_iter()
            .for_each(|mv| {
                versions
                    .iter()
                    .filter(|v| v.id == mv.version_id)
                    .into_iter()
                    .for_each(|v| {
                        if looking_version.matches(&Version::parse(&v.version).unwrap()) {
                            found = true;
                            return;
                        }
                    });

                if found {
                    return;
                }
            });

        if found {
            found_mods.push(m); // I am for loop jesus - checksum 2023
        }
    });

    if query.sort_by.is_some() {
        match query.sort_by.as_ref().unwrap().as_str() {
            "name" => found_mods.sort_by(|a, b| a.name.cmp(&b.name)),
            "downloads" => found_mods.sort_by(|a, b| {
                mod_stats
                    .iter()
                    .filter(|ms| ms.id == a.id)
                    .next()
                    .unwrap()
                    .downloads
                    .cmp(
                        &mod_stats
                            .iter()
                            .filter(|ms| ms.id == b.id)
                            .next()
                            .unwrap()
                            .downloads,
                    )
            }),
            "updated" => found_mods.sort_by(|a, b| b.updated_at.cmp(&a.updated_at)),
            "created" => found_mods.sort_by(|a, b| b.created_at.cmp(&a.created_at)),
            _ => (),
        }
    }

    let found_mods = found_mods
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect::<Vec<mods::Model>>();

    HttpResponse::Ok().json(json!({ "mods": found_mods }))
}

#[derive(Serialize, Deserialize)]
pub struct UploadModRequest {
    api_key: String,
}

/*
    CLI -> Authenticate (get api key from website   )
    CLI -> Upload Mod (send mod to website us) POST: "/mods"
        * Payload
        * Query
*/
#[post("/mods")]
pub async fn create_mod(
    req: HttpRequest,
    data: web::Data<AppState>,
    query: web::Query<UploadModRequest>,
    mut forge_mod: web::Payload,
) -> impl Responder {
    let token = query.api_key.clone();

    if token.is_empty() {
        return HttpResponse::Unauthorized().json(json!({
            "error": "Missing api token."
        }));
    }

    let user = users::Entity::find()
        .filter(users::Column::ApiKey.eq(token))
        .one(&data.db)
        .await
        .unwrap();

    if user.is_none() {
        return HttpResponse::Unauthorized().json(json!({
            "error": "Invalid api token."
        }));
    }

    let user = user.unwrap();

    // todo: check if user has permission to upload mods

    let mut bytes = vec![]; // todo: use a stream for rayon support; this is a bottleneck
    while let Some(item) = forge_mod.next().await {
        bytes.extend_from_slice(&item.unwrap());
    }

    let forge_mod = match ForgeMod::try_from(bytes.as_slice()) {
        Ok(forge_mod) => forge_mod,
        Err(_) => {
            return HttpResponse::BadRequest().json(json!({
                "error": "The file you uploaded is not a valid ForgeMod."
            }))
        }
    };

    let mod_category = categories::Entity::find()
        .filter(categories::Column::Name.eq(forge_mod.manifest.category.to_string()))
        .one(&data.db)
        .await
        .unwrap();

    if mod_category.is_none() {
        return HttpResponse::BadRequest().json(json!({
            "error": "The mod category you specified does not exist."
        }));
    }

    let mod_category = mod_category.unwrap();

    let matching_versions = beat_saber_versions::Entity::find()
        .all(&data.db)
        .await
        .unwrap();
    let matching_versions = matching_versions.par_iter().filter(|v| forge_mod.manifest.game_version.matches(&Version::parse(&v.ver).unwrap())).collect::<Vec<_>>();

    // todo: signature verification
    // todo: handle dependencies and conflicts

    let conflicting_mod = mods::Entity::find()
        .filter(mods::Column::Slug.eq(forge_mod.manifest._id.clone()))
        .one(&data.db)
        .await
        .unwrap();

    if conflicting_mod.is_none() {
        // we are creating a new mod
        //? check if the user has permission to create a new mod
        //? MOD_STATS ; MODS ; USERS_MODS ; VERSION_STATS ; VERSIONS ; MOD_VERSIONS ; VERSIONS_BEAT_SABER_VERSIONS ; VERSIONS_CONFLICTS ; VERSIONS_DEPENDENCIES

        let mod_stats = mod_stats::ActiveModel::default();
        let mod_stats = mod_stats::Entity::insert(mod_stats).exec(&data.db).await.unwrap().last_insert_id;

        let db_mod = mods::ActiveModel {
            slug: ActiveValue::Set(forge_mod.manifest._id),
            name: ActiveValue::Set(forge_mod.manifest.name),
            author: ActiveValue::Set(user.id),
            category: ActiveValue::Set(mod_category.id),
            stats: ActiveValue::Set(mod_stats),
            ..Default::default()
        };
        let db_mod = mods::Entity::insert(db_mod).exec(&data.db).await.unwrap().last_insert_id;

        let users_mods  = users_mods::ActiveModel {
            user_id: ActiveValue::Set(user.id),
            mod_id: ActiveValue::Set(db_mod),
        };
        users_mods::Entity::insert(users_mods).exec(&data.db).await.unwrap();

        let version_stats = version_stats::ActiveModel::default();
        let version_stats = version_stats::Entity::insert(version_stats).exec(&data.db).await.unwrap().last_insert_id;

        let version = versions::ActiveModel {
            mod_id: ActiveValue::Set(db_mod),
            version: ActiveValue::Set(forge_mod.manifest.version.to_string()),
            stats: ActiveValue::Set(version_stats),
            ..Default::default()
        };
        let version = versions::Entity::insert(version).exec(&data.db).await.unwrap().last_insert_id;

        let mod_versions = mod_versions::ActiveModel {
            mod_id: ActiveValue::Set(db_mod),
            version_id: ActiveValue::Set(version),
        };
        mod_versions::Entity::insert(mod_versions).exec(&data.db).await.unwrap();
        let mut version_query = Vec::new();
        matching_versions.iter().for_each(|f| {
            let version_beat_saber_versions = version_beat_saber_versions::ActiveModel {
                version_id: ActiveValue::Set(version),
                beat_saber_id: ActiveValue::Set(f.id),
            };
            version_query.push(version_beat_saber_versions);
        });
        version_beat_saber_versions::Entity::insert_many(version_query).exec(&data.db).await.unwrap();

        //todo: handle dependencies and conflicts
    } else {
        // we are updating an existing mod
        //? if the version is the same as the existing version, add the new version to the existing mod
        //? with a newer timestamp, this will allow us to keep track of the mod's history
        //? even if the mod is updated to the same version internally.
        //? MODS ; USERS_MODS ; VERSION_STATS ; VERSIONS ; VERSIONS_BEAT_SABER_VERSIONS ; VERSIONS_CONFLICTS ; VERSIONS_DEPENDENCIES
        // let mod_stats = mod_stats::ActiveModel::default();
        // let mod_stats = mod_stats::Entity::insert(mod_stats).exec(&data.db).await.unwrap().last_insert_id;

        // let db_mod = mods::ActiveModel {
        //     slug: ActiveValue::Set(forge_mod.manifest._id),
        //     name: ActiveValue::Set(forge_mod.manifest.name),
        //     author: ActiveValue::Set(user.id),
        //     category: ActiveValue::Set(mod_category.id),
        //     stats: ActiveValue::Set(mod_stats),
        //     ..Default::default()
        // };
        // let db_mod = mods::Entity::insert(db_mod).exec(&data.db).await.unwrap().last_insert_id;

        // let users_mods  = users_mods::ActiveModel {
        //     user_id: ActiveValue::Set(user.id),
        //     mod_id: ActiveValue::Set(db_mod),
        // };
        // users_mods::Entity::insert(users_mods).exec(&data.db).await.unwrap();
        

        let db_mod = conflicting_mod.unwrap();

        let mut db_model = mods::ActiveModel::from(db_mod.clone());
        db_model.updated_at = ActiveValue::Set(Utc::now().naive_local());
        mods::Entity::update(db_model).exec(&data.db).await.unwrap();

        let db_mod = db_mod.id;

        let version_stats = version_stats::ActiveModel::default();
        let version_stats = version_stats::Entity::insert(version_stats).exec(&data.db).await.unwrap().last_insert_id;

        let version = versions::ActiveModel {
            mod_id: ActiveValue::Set(db_mod),
            version: ActiveValue::Set(forge_mod.manifest.version.to_string()),
            stats: ActiveValue::Set(version_stats),
            ..Default::default()
        };
        let version = versions::Entity::insert(version).exec(&data.db).await.unwrap().last_insert_id;

        let mod_versions = mod_versions::ActiveModel {
            mod_id: ActiveValue::Set(db_mod),
            version_id: ActiveValue::Set(version),
        };
        mod_versions::Entity::insert(mod_versions).exec(&data.db).await.unwrap();
        let mut version_query = Vec::new();
        matching_versions.iter().for_each(|f| {
            let version_beat_saber_versions = version_beat_saber_versions::ActiveModel {
                version_id: ActiveValue::Set(version),
                beat_saber_id: ActiveValue::Set(f.id),
            };
            version_query.push(version_beat_saber_versions);
        });
        version_beat_saber_versions::Entity::insert_many(version_query).exec(&data.db).await.unwrap();
    }

    HttpResponse::Created().finish()
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
