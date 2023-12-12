use std::vec;

use async_graphql::{Error, FieldError, FieldResult, SimpleObject};
use chrono::{DateTime, Utc};

use forge_lib::structs::v1::{unpack_v1_forgemod, ForgeModTypes};
// use juniper::{graphql_value, FieldError, FieldResult, GraphQLObject};

use poem::{handler, http::StatusCode, Request, Response};

use semver::Version;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use meilisearch_entity::prelude::*;

use crate::{
    auth::{validate_permissions, Authorization, Permission},
    models,
    versions::{self, GVersion},
    DB_POOL,
};

#[derive(SimpleObject, Debug, Deserialize, Serialize, Clone)]
pub struct Mod {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub cover: Option<String>,
    pub author: ModAuthor,
    pub category: ModCategory,
    pub stats: GModStats,
    pub versions: Vec<GVersion>,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(SimpleObject, Debug, Deserialize, Serialize, Clone)]
pub struct ModAuthor {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,

    pub bio: Option<String>,
    pub permissions: i32,
    pub avatar: Option<String>,
    pub banner: Option<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Mod {
    async fn from_db_mod(db: &PgPool, m: models::dMod) -> Result<Self, FieldError> {
        let category = sqlx::query_as!(
            models::dCategory,
            "SELECT * FROM categories WHERE id = $1",
            m.category
        )
        .fetch_one(db)
        .await?
        .clone();
        let stats = sqlx::query_as!(
            models::dModStats,
            "SELECT * FROM mod_stats WHERE id = $1",
            m.stats
        )
        .fetch_one(db)
        .await?
        .clone();
        let author = sqlx::query_as!(models::dUser, "SELECT * FROM users WHERE id = $1", m.author)
            .fetch_one(db)
            .await?
            .clone();
        Ok(Mod {
            id: Uuid::from_bytes(*m.id.as_bytes()),
            slug: m.slug,
            name: m.name,
            description: m.description,
            icon: m.icon,
            cover: m.cover,
            author: ModAuthor {
                id: Uuid::from_bytes(*author.id.as_bytes()),
                username: author.username,
                display_name: author.display_name,
                bio: author.bio,
                permissions: author.permissions,
                avatar: author.avatar,
                banner: author.banner,
                created_at: author.created_at.and_utc(),
                updated_at: author.updated_at.and_utc(),
            },
            category: ModCategory {
                name: category.name,
                desc: category.description,
            },
            stats: GModStats {
                downloads: stats.downloads,
            },
            versions: versions::find_by_mod_id(db, Uuid::from_bytes(*m.id.as_bytes())).await?,
            updated_at: m.updated_at.and_utc(),
            created_at: m.created_at.and_utc(),
        })
    }
}

#[derive(SimpleObject, Debug, Deserialize, Serialize, Clone)]
pub struct GModStats {
    pub downloads: i32,
    // pub rating: f32,
    // pub rating_count: i32,
}

#[derive(SimpleObject, Debug, Deserialize, Serialize, Clone)]
pub struct ModCategory {
    pub name: String,
    pub desc: String,
}

pub async fn find_all(
    db: &PgPool,
    limit: i32,
    offset: i32,
    version: Option<String>,
) -> FieldResult<Vec<Mod>> {
    let limit = limit as i64;
    let offset = offset as i64;

    if let Some(version) = version {
        let verid = sqlx::query_as!(
            models::dBeatSaberVersion,
            "SELECT * FROM beat_saber_versions WHERE ver = $1",
            version
        )
        .fetch_one(db)
        .await?
        .id;

        let mods = sqlx::query_as!(models::dMod, "SELECT * FROM mods WHERE id IN (SELECT mod_id FROM mod_beat_saber_versions WHERE beat_saber_version_id = $1) LIMIT $2 OFFSET $3", verid, limit, offset)
            .fetch_all(db)
            .await?.to_vec();

        let mut r = vec![];
        for m in mods {
            r.push(Mod::from_db_mod(db, m).await.unwrap());
        }
        Ok(r)
    } else {
        let mods = sqlx::query_as!(
            models::dMod,
            "SELECT * FROM mods LIMIT $1 OFFSET $2",
            limit,
            offset
        )
        .fetch_all(db)
        .await?.to_vec();

        let mut r = vec![];
        for m in mods {
            r.push(Mod::from_db_mod(db, m).await.unwrap());
        }
        Ok(r)
    }
}

pub async fn find_by_id(db: &PgPool, id: Uuid) -> FieldResult<Mod> {
    let m = sqlx::query_as!(
        models::dMod,
        "SELECT * FROM mods WHERE id = $1",
        sqlx::types::Uuid::from_bytes(*id.as_bytes())
    )
    .fetch_optional(db)
    .await?;

    if let Some(m) = m {
        Mod::from_db_mod(db, m).await
    } else {
        Err(Error::new("Mod not found"))
    }
}

pub async fn find_by_slug(db: &PgPool, slug: String) -> FieldResult<Mod> {
    let m = sqlx::query_as!(models::dMod, "SELECT * FROM mods WHERE slug = $1", slug)
        .fetch_optional(db)
        .await?;

    if let Some(m) = m {
        Mod::from_db_mod(db, m).await
    } else {
        Err(Error::new("Mod not found"))
    }
}

pub async fn find_by_author(db: &PgPool, author: Uuid) -> FieldResult<Vec<Mod>> {
    let mods = sqlx::query_as!(
        models::dMod,
        "SELECT * FROM mods WHERE author = $1",
        sqlx::types::Uuid::from_bytes(*author.as_bytes())
    )
    .fetch_all(db)
    .await?.to_vec();

    let mut r = vec![];
    for m in mods {
        r.push(Mod::from_db_mod(db, m).await.unwrap());
    }
    Ok(r)
}

#[handler]
pub async fn create_mod(req: &Request, body: Vec<u8>) -> Response {
    let db = DB_POOL.get().unwrap().clone();

    let auth = req
        .headers()
        .get("Authorization")
        .unwrap()
        .to_str()
        .unwrap();
    let auser;
    if auth.starts_with("Bearer") {
        let auth = Authorization::parse(Some(auth.split(' ').collect::<Vec<_>>()[1].to_string()));
        let user = auth.get_user(&db).await.unwrap();
        if !validate_permissions(&user, Permission::CREATE_MOD).await {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("Unauthorized");
        }
        auser = user;
    } else {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body("Unauthorized");
    }

    // let mut buf = Vec::new();

    // while let Some(item) = payload.next().await {
    //     let item = item.unwrap();
    //     buf.extend_from_slice(&item);
    //

    let forgemod = {
        let fm = unpack_v1_forgemod(&*body).unwrap();
        match fm {
            ForgeModTypes::Mod(fm) => fm,
            _ => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body("Invalid ForgeMod")
            }
        }
    };

    let manifest = forgemod.manifest.inner.clone();

    // let db_cata = Categories::find()
    //     .filter(entity::categories::Column::Name.eq(manifest.category.clone().to_string()))
    //     .one(&db)
    //     .await
    //     .unwrap();
    let db_cata = sqlx::query_as!(
        models::dCategory,
        "SELECT * FROM categories WHERE name = $1",
        manifest.category.clone().to_string()
    )
    .fetch_optional(&db)
    .await
    .unwrap();

    // if cata does not exist, default to other
    let db_cata = if let Some(db_cata) = db_cata {
        db_cata
    } else {
        // Categories::find()
        //     .filter(entity::categories::Column::Name.eq("other"))
        //     .one(&db)
        //     .await
        //     .unwrap()
        //     .unwrap()
        sqlx::query_as!(
            models::dCategory,
            "SELECT * FROM categories WHERE name = 'other'"
        )
        .fetch_one(&db)
        .await
        .unwrap()
    };

    let v_req = manifest.game_version.clone();
    // let vers = BeatSaberVersions::find()
    //     .all(&db)
    //     .await
    //     .unwrap()
    //     .into_iter()
    //     .filter(|v| v_req.matches(&Version::parse(&v.ver).unwrap()))
    //     .collect::<Vec<_>>();
    let vers = sqlx::query_as!(
        models::dBeatSaberVersion,
        "SELECT * FROM beat_saber_versions"
    )
    .fetch_all(&db)
    .await
    .unwrap()
    .into_iter()
    .filter(|v| v_req.matches(&Version::parse(&v.ver).unwrap()))
    .collect::<Vec<_>>();

    if vers.is_empty() {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("No supported versions");
    }

    // see if mod exists; if it does add a new version; if it doesn't create a new mod
    // let mby_mod = Mods::find()
    //     .filter(entity::mods::Column::Slug.eq(forgemod.manifest._id.clone()))
    //     .one(&db)
    //     .await
    //     .unwrap();
    let mby_mod = sqlx::query_as!(
        models::dMod,
        "SELECT * FROM mods WHERE slug = $1",
        forgemod.manifest._id.clone()
    )
    .fetch_optional(&db)
    .await
    .unwrap();

    let v_id;

    let mut trans = db.begin().await.unwrap();

    if let Some(db_mod) = mby_mod {
        let db_mod = db_mod.id;
        for v in &vers {
            // let vm = entity::mod_beat_saber_versions::ActiveModel {
            //     mod_id: Set(db_mod),
            //     beat_saber_version_id: Set(v.id),
            // };

            // //see if vm exists
            // if ModBeatSaberVersions::find()
            //     .filter(entity::mod_beat_saber_versions::Column::ModId.eq(db_mod))
            //     .filter(entity::mod_beat_saber_versions::Column::BeatSaberVersionId.eq(v.id))
            //     .one(&trans)
            //     .await
            //     .unwrap()
            //     .is_none()
            // {
            //     vm.insert(&trans).await.unwrap();
            // }
            let vm = sqlx::query_as!(models::dFkModBeatSaberVersion, "SELECT * FROM mod_beat_saber_versions WHERE mod_id = $1 AND beat_saber_version_id = $2", db_mod, v.id)
                .fetch_optional(&mut *trans)
                .await
                .unwrap();

            if vm.is_none() {
                sqlx::query!("INSERT INTO mod_beat_saber_versions (mod_id, beat_saber_version_id) VALUES ($1, $2)", db_mod, v.id)
                    .execute(&mut *trans).await.unwrap();
            }
        }

        let version_stats = sqlx::query!("INSERT INTO version_stats DEFAULT VALUES RETURNING id")
            .fetch_one(&mut *trans)
            .await
            .unwrap()
            .id;

        // let version = entity::versions::ActiveModel {
        //     mod_id: Set(db_mod),
        //     version: Set(manifest.version.clone().to_string()),
        //     stats: Set(version_stats),
        //     //todo: artifact hash
        //     artifact_hash: Set("".to_string()),
        //     //todo: download url
        //     download_url: Set(format!(
        //         "{}/cdn/{}@{}",
        //         std::env::var("PUBLIC_URL").unwrap(),
        //         forgemod.manifest._id,
        //         manifest.version.clone().to_string()
        //     )),
        //     ..Default::default()
        // }
        // .insert(&trans)
        // .await
        // .unwrap()
        // .id;
        let version = sqlx::query!("INSERT INTO versions (mod_id, version, stats, artifact_hash, download_url) VALUES ($1, $2, $3, $4, $5) RETURNING id", db_mod, manifest.version.clone().to_string(), version_stats, "", format!("{}/cdn/{}@{}", std::env::var("PUBLIC_URL").unwrap(),forgemod.manifest._id,manifest.version.clone().to_string())).fetch_one(&mut *trans).await.unwrap().id;

        for v in &vers {
            // let _ = entity::version_beat_saber_versions::ActiveModel {
            //     version_id: Set(version),
            //     beat_saber_version_id: Set(v.id),
            // }
            // .insert(&trans)
            // .await
            // .unwrap();
            sqlx::query!("INSERT INTO version_beat_saber_versions (version_id, beat_saber_version_id) VALUES ($1, $2)", version, v.id).execute(&mut *trans).await.unwrap();
        }

        sqlx::query!(
            "INSERT INTO mod_versions (mod_id, version_id) VALUES ($1, $2)",
            db_mod,
            version
        )
        .execute(&mut *trans)
        .await
        .unwrap();

        for conflict in manifest.conflicts {
            // let c_ver = Versions::find()
            //     .filter(entity::versions::Column::ModId.eq(db_mod))
            //     .all(&trans)
            //     .await
            //     .unwrap()
            //     .into_iter()
            //     .filter(|c| {
            //         conflict
            //             .version
            //             .matches(&Version::parse(&c.version).unwrap())
            //     })
            //     .collect::<Vec<_>>();
            let c_ver = sqlx::query!("SELECT * FROM versions WHERE (mod_id = $1)", db_mod)
                .fetch_all(&mut *trans)
                .await
                .unwrap()
                .into_iter()
                .filter(|c| {
                    conflict
                        .version
                        .matches(&Version::parse(&c.version).unwrap())
                })
                .collect::<Vec<_>>();

            for c in c_ver {
                // let _ = entity::version_conflicts::ActiveModel {
                //     version_id: Set(version),
                //     dependent: Set(c.id),
                // }
                // .insert(&trans)
                // .await
                // .unwrap();
                sqlx::query!(
                    "INSERT INTO version_conflicts (version_id, dependent) VALUES ($1, $2)",
                    version,
                    c.id
                )
                .execute(&mut *trans)
                .await
                .unwrap();
            }
        }

        for dependent in manifest.depends {
            // let d_ver = Versions::find()
            //     .filter(entity::versions::Column::ModId.eq(db_mod))
            //     .all(&trans)
            //     .await
            //     .unwrap()
            //     .into_iter()
            //     .filter(|d| {
            //         dependent
            //             .version
            //             .matches(&Version::parse(&d.version).unwrap())
            //     })
            //     .collect::<Vec<_>>();
            let d_ver = sqlx::query!("SELECT * FROM versions WHERE (mod_id = $1)", db_mod)
                .fetch_all(&mut *trans)
                .await
                .unwrap()
                .into_iter()
                .filter(|d| {
                    dependent
                        .version
                        .matches(&Version::parse(&d.version).unwrap())
                })
                .collect::<Vec<_>>();

            for d in d_ver {
                // let _ = entity::version_dependents::ActiveModel {
                //     version_id: Set(version),
                //     dependent: Set(d.id),
                // }
                // .insert(&trans)
                // .await
                // .unwrap();
                sqlx::query!(
                    "INSERT INTO version_dependents (version_id, dependent) VALUES ($1, $2)",
                    version,
                    d.id
                )
                .execute(&mut *trans)
                .await
                .unwrap();
            }
        }
        v_id = version;
    } else {
        // let mod_stats = entity::mod_stats::ActiveModel {
        //     ..Default::default()
        // }
        // .insert(&trans)
        // .await
        // .unwrap()
        // .id;
        let mod_stats = sqlx::query!("INSERT INTO mod_stats DEFAULT VALUES RETURNING id")
            .fetch_one(&mut *trans)
            .await
            .unwrap()
            .id;

        // let db_mod = entity::mods::ActiveModel {
        //     slug: Set(forgemod.manifest._id.clone()),
        //     name: Set(manifest.name.clone()),
        //     author: Set(auser.id),
        //     description: Set(Some(manifest.description.clone())),
        //     website: Set(Some(manifest.website.clone())),
        //     category: Set(db_cata.id),
        //     stats: Set(mod_stats),
        //     ..Default::default()
        // }
        // .insert(&trans)
        // .await
        // .unwrap()
        // .id;
        let db_mod = sqlx::query!("INSERT INTO mods (slug, name, author, description, website, category, stats) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id", forgemod.manifest._id.clone(), manifest.name.clone(), auser.id, manifest.description.clone(), manifest.website.clone(), db_cata.id, mod_stats).fetch_one(&mut *trans).await.unwrap().id;

        // entity::user_mods::ActiveModel {
        //     user_id: Set(auser.id),
        //     mod_id: Set(db_mod),
        // }
        // .insert(&trans)
        // .await
        // .unwrap();
        sqlx::query!(
            "INSERT INTO user_mods (user_id, mod_id) VALUES ($1, $2)",
            auser.id,
            db_mod
        )
        .execute(&mut *trans)
        .await
        .unwrap();

        for v in &vers {
            // let _ = entity::mod_beat_saber_versions::ActiveModel {
            //     mod_id: Set(db_mod),
            //     beat_saber_version_id: Set(v.id),
            // }
            // .insert(&trans)
            // .await
            // .unwrap();
            sqlx::query!("INSERT INTO mod_beat_saber_versions (mod_id, beat_saber_version_id) VALUES ($1, $2)", db_mod, v.id).execute(&mut *trans).await.unwrap();
        }

        // let version_stats = entity::version_stats::ActiveModel {
        //     ..Default::default()
        // }
        // .insert(&trans)
        // .await
        // .unwrap()
        // .id;
        let version_stats = sqlx::query!("INSERT INTO version_stats DEFAULT VALUES RETURNING id")
            .fetch_one(&mut *trans)
            .await
            .unwrap()
            .id;

        // let version = entity::versions::ActiveModel {
        //     mod_id: Set(db_mod),
        //     version: Set(manifest.version.clone().to_string()),
        //     stats: Set(version_stats),
        //     //todo: artifact hash
        //     artifact_hash: Set("".to_string()),
        //     //todo: download url
        //     download_url: Set(format!(
        //         "{}/cdn/{}@{}",
        //         std::env::var("PUBLIC_URL").unwrap(),
        //         forgemod.manifest._id,
        //         manifest.version.clone().to_string()
        //     )),
        //     ..Default::default()
        // }
        // .insert(&trans)
        // .await
        // .unwrap()
        // .id;
        let version = sqlx::query!("INSERT INTO versions (mod_id, version, stats, artifact_hash, download_url) VALUES ($1, $2, $3, $4, $5) RETURNING id", db_mod, manifest.version.clone().to_string(), version_stats, "", format!("{}/cdn/{}@{}", std::env::var("PUBLIC_URL").unwrap(),forgemod.manifest._id,manifest.version.clone().to_string())).fetch_one(&mut *trans).await.unwrap().id;

        for v in &vers {
            // let _ = entity::version_beat_saber_versions::ActiveModel {
            //     version_id: Set(version),
            //     beat_saber_version_id: Set(v.id),
            // }
            // .insert(&trans)
            // .await
            // .unwrap();
            sqlx::query!("INSERT INTO version_beat_saber_versions (version_id, beat_saber_version_id) VALUES ($1, $2)", version, v.id).execute(&mut *trans).await.unwrap();
        }

        sqlx::query!(
            "INSERT INTO mod_versions (mod_id, version_id) VALUES ($1, $2)",
            db_mod,
            version
        )
        .execute(&mut *trans)
        .await
        .unwrap();

        for conflict in manifest.conflicts {
            // let c_ver = Versions::find()
            //     .filter(entity::versions::Column::ModId.eq(db_mod))
            //     .all(&trans)
            //     .await
            //     .unwrap()
            //     .into_iter()
            //     .filter(|c| {
            //         conflict
            //             .version
            //             .matches(&Version::parse(&c.version).unwrap())
            //     })
            //     .collect::<Vec<_>>();
            let c_ver = sqlx::query!("SELECT * FROM versions WHERE (mod_id = $1)", db_mod)
                .fetch_all(&mut *trans)
                .await
                .unwrap()
                .into_iter()
                .filter(|c| {
                    conflict
                        .version
                        .matches(&Version::parse(&c.version).unwrap())
                })
                .collect::<Vec<_>>();

            for c in c_ver {
                // let _ = entity::version_conflicts::ActiveModel {
                //     version_id: Set(version),
                //     dependent: Set(c.id),
                // }
                // .insert(&trans)
                // .await
                // .unwrap();
                sqlx::query!(
                    "INSERT INTO version_conflicts (version_id, dependent) VALUES ($1, $2)",
                    version,
                    c.id
                )
                .execute(&mut *trans)
                .await
                .unwrap();
            }
        }

        for dependent in manifest.depends {
            // let d_ver = Versions::find()
            //     .filter(entity::versions::Column::ModId.eq(db_mod))
            //     .all(&trans)
            //     .await
            //     .unwrap()
            //     .into_iter()
            //     .filter(|d| {
            //         dependent
            //             .version
            //             .matches(&Version::parse(&d.version).unwrap())
            //     })
            //     .collect::<Vec<_>>();
            let d_ver = sqlx::query!("SELECT * FROM versions WHERE (mod_id = $1)", db_mod)
                .fetch_all(&mut *trans)
                .await
                .unwrap()
                .into_iter()
                .filter(|d| {
                    dependent
                        .version
                        .matches(&Version::parse(&d.version).unwrap())
                })
                .collect::<Vec<_>>();

            for d in d_ver {
                // let _ = entity::version_dependents::ActiveModel {
                //     version_id: Set(version),
                //     dependent: Set(d.id),
                // }
                // .insert(&trans)
                // .await
                // .unwrap();
                sqlx::query!(
                    "INSERT INTO version_dependents (version_id, dependent) VALUES ($1, $2)",
                    version,
                    d.id
                )
                .execute(&mut *trans)
                .await
                .unwrap();
            }
        }
        v_id = version;
    }

    // let db_mod = Mods::find()
    //     .filter(entity::mods::Column::Slug.eq(forgemod.manifest._id.clone()))
    //     .one(&trans)
    //     .await
    //     .unwrap()
    //     .unwrap();
    let db_mod = sqlx::query_as!(
        models::dMod,
        "SELECT * FROM mods WHERE (slug = $1)",
        forgemod.manifest._id.clone()
    )
    .fetch_one(&mut *trans)
    .await
    .unwrap();

    let _ = std::fs::create_dir(format!("./data/cdn/{}", &db_mod.id));
    std::fs::write(format!("./data/cdn/{}/{}.forgemod", &db_mod.id, v_id), body).unwrap();

    trans.commit().await.unwrap();

    // add to meilisearch
    let client = meilisearch_sdk::client::Client::new(
        std::env::var("MEILI_URL").unwrap(),
        Some(std::env::var("MEILI_KEY").unwrap()),
    );

    // let mod_vers = ModVersions::find()
    //     .filter(entity::mod_versions::Column::ModId.eq(db_mod.id))
    //     .find_also_related(Versions)
    //     .all(&db)
    //     .await
    //     .unwrap()
    //     .into_iter()
    //     .map(|(_, v)| Version::parse(&v.unwrap().version).unwrap())
    //     .collect::<Vec<_>>();
    let mod_vers = sqlx::query_as!(
        models::dVersion,
        "SELECT * FROM versions WHERE (mod_id = $1)",
        db_mod.id
    )
    .fetch_all(&db)
    .await
    .unwrap()
    .into_iter()
    .map(|v| Version::parse(&v.version).unwrap())
    .collect::<Vec<_>>();

    // let supported_versions = ModBeatSaberVersions::find()
    //     .filter(entity::mod_beat_saber_versions::Column::ModId.eq(db_mod.id))
    //     .find_also_related(BeatSaberVersions)
    //     .all(&db)
    //     .await
    //     .unwrap()
    //     .into_iter()
    //     .map(|(_, v)| Version::parse(&v.unwrap().ver).unwrap())
    //     .collect::<Vec<_>>();
    let supported_versions = sqlx::query_as!(models::dBeatSaberVersion, "SELECT * FROM beat_saber_versions WHERE id IN (SELECT beat_saber_version_id FROM mod_beat_saber_versions WHERE mod_id = $1)", db_mod.id).fetch_all(&db).await.unwrap().into_iter().map(|v| Version::parse(&v.ver).unwrap()).collect::<Vec<_>>();

    // let mod_stats = ModStats::find_by_id(db_mod.stats)
    //     .one(&db)
    //     .await
    //     .unwrap()
    //     .unwrap();
    let mod_stats = sqlx::query_as!(
        models::dModStats,
        "SELECT * FROM mod_stats WHERE id = $1",
        db_mod.stats
    )
    .fetch_one(&db)
    .await
    .unwrap();

    let meilimod = MeiliMod {
        id: db_mod.id,
        slug: db_mod.slug,
        name: db_mod.name,
        description: db_mod.description.unwrap_or("".to_string()),
        category: db_cata.name,
        author: MeiliUser {
            username: auser.username.clone(),
            display_name: auser.display_name.unwrap_or(auser.username),
        },
        stats: MeiliModStats {
            downloads: mod_stats.downloads as u64,
        },
        versions: mod_vers
            .into_iter()
            .map(|v| MeiliVersion { version: v })
            .collect(),
        created_at: db_mod.created_at.and_utc().timestamp(),
        updated_at: db_mod.updated_at.and_utc().timestamp(),
        supported_versions,
    };
    client
        .index(format!(
            "{}mods",
            std::env::var("MEILI_PREFIX").unwrap_or("".to_string())
        ))
        .add_or_replace(&[meilimod], None)
        .await
        .unwrap();

    Response::builder()
        .status(StatusCode::CREATED)
        .body("Created")
}
