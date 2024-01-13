use std::vec;

use async_graphql::{Error, FieldError, FieldResult, SimpleObject};
use chrono::{DateTime, Utc};

use forge_lib::structs::v1::{unpack_v1_forgemod, ForgeModTypes};
// use juniper::{graphql_value, FieldError, FieldResult, GraphQLObject};

use poem::{handler, http::StatusCode, Request, Response};

use semver::Version;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    auth::{validate_permissions, Authorization, Permission},
    models,
    search::{get_prefix, MeiliMod, MeiliModStats, MeiliUser, MeiliVersion},
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
            models::dModStat,
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
            r.push(Mod::from_db_mod(db, m).await?);
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
        .await?
        .to_vec();

        let mut r = vec![];
        for m in mods {
            r.push(Mod::from_db_mod(db, m).await?);
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
    .await?
    .to_vec();

    let mut r = vec![];
    for m in mods {
        r.push(Mod::from_db_mod(db, m).await?);
    }
    Ok(r)
}

#[handler]
pub async fn upload_mod(req: &Request, body: Vec<u8>) -> Response {
    let auth = match match req.headers().get("Authorization") {
        Some(head) => head,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("Unauthorized. Missing Authorization header");
        }
    }
    .to_str()
    {
        Ok(auth) => auth,
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        }
    };
    

    _upload_mod(auth, body).await
}

pub async fn _upload_mod(auth: &str, body: Vec<u8>) -> Response {
    let db = match DB_POOL.get() {
        Some(db) => db,
        None => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        }
    }
    .clone();

    let auser;
    if auth.starts_with("Bearer") {
        let auth = Authorization::parse(Some(auth.split(' ').collect::<Vec<_>>()[1].to_string()));
        // info!("{:?}", auth);
        let user = match auth.get_user(&db).await {
            Some(user) => user,
            None => {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body("Unauthorized");
            }
        };
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
        let fm = match unpack_v1_forgemod(&*body) {
            Ok(fm) => fm,
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body("Could not parse ForgeMod");
            }
        };
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
    let db_cata = match sqlx::query_as!(
        models::dCategory,
        "SELECT * FROM categories WHERE name = $1",
        manifest.category.clone().to_string()
    )
    .fetch_optional(&db)
    .await
    {
        Ok(cata) => cata,
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        }
    };

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
        match sqlx::query_as!(
            models::dCategory,
            "SELECT * FROM categories WHERE name = 'other'"
        )
        .fetch_one(&db)
        .await
        {
            Ok(cata) => cata,
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            }
        }
    };

    let v_req = manifest.game_version.clone();
    // let vers = BeatSaberVersions::find()
    //     .all(&db)
    //     .await
    //     .unwrap()
    //     .into_iter()
    //     .filter(|v| v_req.matches(&Version::parse(&v.ver).unwrap()))
    //     .collect::<Vec<_>>();
    let vers = match sqlx::query_as!(
        models::dBeatSaberVersion,
        "SELECT * FROM beat_saber_versions"
    )
    .fetch_all(&db)
    .await
    {
        Ok(vers) => vers,
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        }
    }
    .into_iter()
    .filter(|v| {
        if let Ok(v) = Version::parse(&v.ver) {
            v_req.matches(&v)
        } else {
            false
        }
    })
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
    let mby_mod = match sqlx::query_as!(
        models::dMod,
        "SELECT * FROM mods WHERE slug = $1",
        forgemod.manifest._id.clone()
    )
    .fetch_optional(&db)
    .await
    {
        Ok(m) => m,
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        }
    };

    let v_id;

    let mut trans = match db.begin().await {
        Ok(trans) => trans,
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        }
    };

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
            let vm = match sqlx::query_as!(models::dFkModBeatSaberVersion,"SELECT * FROM mod_beat_saber_versions WHERE mod_id = $1 AND beat_saber_version_id = $2",db_mod,v.id).fetch_optional(&mut*trans).await {
                Ok(vm) => vm,
                Err(e) => {
                    warn!("{}", e);

                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error");
                },
            };

            if vm.is_none() {
                match sqlx::query!("INSERT INTO mod_beat_saber_versions (mod_id, beat_saber_version_id) VALUES ($1, $2)",db_mod,v.id).execute(&mut*trans).await {
                    Ok(vm) => vm,
                    Err(e) => {
                        warn!("{}", e);

                        return Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body("Internal Server Error");
                    },
                };
            }
        }

        let version_stats =
            match sqlx::query!("INSERT INTO version_stats DEFAULT VALUES RETURNING id")
                .fetch_one(&mut *trans)
                .await
            {
                Ok(record) => record,
                Err(e) => {
                    warn!("{}", e);

                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error");
                }
            }
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
        //         std::env::var("BF_PUBLIC_URL").unwrap(),
        //         forgemod.manifest._id,
        //         manifest.version.clone().to_string()
        //     )),
        //     ..Default::default()
        // }
        // .insert(&trans)
        // .await
        // .unwrap()
        // .id;
        let version = match sqlx::query!("INSERT INTO versions (mod_id, version, stats, artifact_hash, download_url) VALUES ($1, $2, $3, $4, $5) RETURNING id",db_mod,manifest.version.clone().to_string(),version_stats,"",format!("{}/cdn/{}@{}",match std::env::var("BF_PUBLIC_URL"){Ok(url)=>url,Err(e)=>{error!("{}",e);return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body("Internal Server Error");},},forgemod.manifest._id,manifest.version.clone().to_string())).fetch_one(&mut*trans).await {
            Ok(record) => record,
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
        
            },
        }.id;

        for v in &vers {
            // let _ = entity::version_beat_saber_versions::ActiveModel {
            //     version_id: Set(version),
            //     beat_saber_version_id: Set(v.id),
            // }
            // .insert(&trans)
            // .await
            // .unwrap();
            match sqlx::query!("INSERT INTO version_beat_saber_versions (version_id, beat_saber_version_id) VALUES ($1, $2)",version,v.id).execute(&mut*trans).await {
                Ok(_) => {},
                Err(e) => {
                    warn!("{}", e);

                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error");
                },
            };
        }

        match sqlx::query!(
            "INSERT INTO mod_versions (mod_id, version_id) VALUES ($1, $2)",
            db_mod,
            version
        )
        .execute(&mut *trans)
        .await
        {
            Ok(_) => {}
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            }
        };

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
            let c_ver = match sqlx::query!("SELECT * FROM versions WHERE (mod_id = $1)", db_mod)
                .fetch_all(&mut *trans)
                .await
            {
                Ok(records) => records,
                Err(e) => {
                    warn!("{}", e);

                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error");
                }
            }
            .into_iter()
            .filter(|c| {
                if let Ok(c) = Version::parse(&c.version) {
                    conflict.version.matches(&c)
                } else {
                    false
                }
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
                match sqlx::query!(
                    "INSERT INTO version_conflicts (version_id, dependent) VALUES ($1, $2)",
                    version,
                    c.id
                )
                .execute(&mut *trans)
                .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("{}", e);

                        return Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body("Internal Server Error");
                    }
                };
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
            let d_ver = match sqlx::query!("SELECT * FROM versions WHERE (mod_id = $1)", db_mod)
                .fetch_all(&mut *trans)
                .await
            {
                Ok(records) => records,
                Err(e) => {
                    warn!("{}", e);

                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error");
                }
            }
            .into_iter()
            .filter(|d| {
                if let Ok(d) = Version::parse(&d.version) {
                    dependent.version.matches(&d)
                } else {
                    false
                }
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
                match sqlx::query!(
                    "INSERT INTO version_dependents (version_id, dependent) VALUES ($1, $2)",
                    version,
                    d.id
                )
                .execute(&mut *trans)
                .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("{}", e);

                        return Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body("Internal Server Error");
                    }
                };
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
        let mod_stats = match sqlx::query!("INSERT INTO mod_stats DEFAULT VALUES RETURNING id")
            .fetch_one(&mut *trans)
            .await
        {
            Ok(record) => record,
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            }
        }
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
        let db_mod = match sqlx::query!("INSERT INTO mods (slug, name, author, description, website, category, stats, icon, cover) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",forgemod.manifest._id.clone(),manifest.name.clone(),auser.id,manifest.description.clone(),manifest.website.clone(),db_cata.id,mod_stats,"","").fetch_one(&mut*trans).await {
            Ok(record) => record,
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            },
        }.id;

        // entity::user_mods::ActiveModel {
        //     user_id: Set(auser.id),
        //     mod_id: Set(db_mod),
        // }
        // .insert(&trans)
        // .await
        // .unwrap();
        match sqlx::query!(
            "INSERT INTO user_mods (user_id, mod_id) VALUES ($1, $2)",
            auser.id,
            db_mod
        )
        .execute(&mut *trans)
        .await
        {
            Ok(_) => {}
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            }
        };

        for v in &vers {
            // let _ = entity::mod_beat_saber_versions::ActiveModel {
            //     mod_id: Set(db_mod),
            //     beat_saber_version_id: Set(v.id),
            // }
            // .insert(&trans)
            // .await
            // .unwrap();
            match sqlx::query!("INSERT INTO mod_beat_saber_versions (mod_id, beat_saber_version_id) VALUES ($1, $2)",db_mod,v.id).execute(&mut*trans).await {
                Ok(_) => {},
                Err(e) => {
                    warn!("{}", e);

                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error");
                },
            };
        }

        // let version_stats = entity::version_stats::ActiveModel {
        //     ..Default::default()
        // }
        // .insert(&trans)
        // .await
        // .unwrap()
        // .id;
        let version_stats =
            match sqlx::query!("INSERT INTO version_stats DEFAULT VALUES RETURNING id")
                .fetch_one(&mut *trans)
                .await
            {
                Ok(record) => record,
                Err(e) => {
                    warn!("{}", e);

                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error");
                }
            }
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
        //         std::env::var("BF_PUBLIC_URL").unwrap(),
        //         forgemod.manifest._id,
        //         manifest.version.clone().to_string()
        //     )),
        //     ..Default::default()
        // }
        // .insert(&trans)
        // .await
        // .unwrap()
        // .id;
        let version = match sqlx::query!("INSERT INTO versions (mod_id, version, stats, artifact_hash, download_url) VALUES ($1, $2, $3, $4, $5) RETURNING id",db_mod,manifest.version.clone().to_string(),version_stats,"",format!("{}/cdn/{}@{}",match std::env::var("BF_PUBLIC_URL") {
            Ok(url) => url,
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            }
        },forgemod.manifest._id,manifest.version.clone().to_string())).fetch_one(&mut*trans).await {
            Ok(record) => {record},
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            },
        }.id;

        for v in &vers {
            // let _ = entity::version_beat_saber_versions::ActiveModel {
            //     version_id: Set(version),
            //     beat_saber_version_id: Set(v.id),
            // }
            // .insert(&trans)
            // .await
            // .unwrap();
            match sqlx::query!("INSERT INTO version_beat_saber_versions (version_id, beat_saber_version_id) VALUES ($1, $2)",version,v.id).execute(&mut*trans).await {
                Ok(_) => {},
                Err(e) => {
                    warn!("{}", e);

                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error");
                },
            };
        }

        match sqlx::query!("INSERT INTO mod_versions (mod_id, version_id) VALUES ($1, $2)",db_mod,version).execute(&mut*trans).await {
            Ok(_) => {},
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            },
        };

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
            let c_ver = match sqlx::query!("SELECT * FROM versions WHERE (mod_id = $1)",db_mod).fetch_all(&mut*trans).await {
                Ok(vers) => {vers},
                Err(e) => {
                    warn!("{}", e);

                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error");
                },
            }
                .into_iter()
                .filter(|c| {
                    if let Ok(c) = Version::parse(&c.version) {
                        conflict.version.matches(&c)
                    } else {
                        false
                    }
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
                match sqlx::query!("INSERT INTO version_conflicts (version_id, dependent) VALUES ($1, $2)",version,c.id).execute(&mut*trans).await {
                    Ok(_) => {},
                    Err(e) => {
                        warn!("{}", e);

                        return Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body("Internal Server Error");
                    
                    },
                };
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
            let d_ver = match sqlx::query!("SELECT * FROM versions WHERE (mod_id = $1)",db_mod).fetch_all(&mut*trans).await {
                Ok(vers) => {vers},
                Err(e) => {
                    warn!("{}", e);

                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error");
                },
            }
                .into_iter()
                .filter(|d| {
                    if let Ok(d) = Version::parse(&d.version) {
                        dependent.version.matches(&d)
                    } else {
                        false
                    }
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
                match sqlx::query!("INSERT INTO version_dependents (version_id, dependent) VALUES ($1, $2)",version,d.id).execute(&mut*trans).await {
                    Ok(_) => {},
                    Err(e) => {
                        warn!("{}", e);

                        return Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body("Internal Server Error");
                    
                    
                    },
                }
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
    let db_mod = match sqlx::query_as!(models::dMod,"SELECT * FROM mods WHERE (slug = $1)",forgemod.manifest._id.clone()).fetch_one(&mut*trans).await {
        Ok(record) => {record},
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    };

    // add to meilisearch
    let client = meilisearch_sdk::client::Client::new(
        match std::env::var("BF_MEILI_URL") {
            Ok(url) => {url},
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            },
        },
        Some(match std::env::var("BF_MEILI_KEY") {
            Ok(key) => {key},
            Err(e) => {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
            },
        }),
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
    let mod_vers = match match sqlx::query_as!(models::dVersion,"SELECT * FROM versions WHERE (mod_id = $1)",db_mod.id).fetch_all(&mut*trans).await{Ok(records)=>{records},Err(e)=>{warn!("{}",e);return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body("Internal Server Error");},}.into_iter().map(|v|Version::parse(&v.version)).collect::<Result<Vec<_>, _>>() {
        Ok(vers) => {vers},
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    };

    // let supported_versions = ModBeatSaberVersions::find()
    //     .filter(entity::mod_beat_saber_versions::Column::ModId.eq(db_mod.id))
    //     .find_also_related(BeatSaberVersions)
    //     .all(&db)
    //     .await
    //     .unwrap()
    //     .into_iter()
    //     .map(|(_, v)| Version::parse(&v.unwrap().ver).unwrap())
    //     .collect::<Vec<_>>();
    let supported_versions = match match sqlx::query_as!(models::dBeatSaberVersion,"SELECT * FROM beat_saber_versions WHERE id IN (SELECT beat_saber_version_id FROM mod_beat_saber_versions WHERE mod_id = $1)",db_mod.id).fetch_all(&mut*trans).await{Ok(vers)=>{vers},Err(e)=>{warn!("{}",e);return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body("Internal Server Error");},}.into_iter().map(|v|Version::parse(&v.ver)).collect:: <Result<Vec<_> ,_> >() {
        Ok(vers) => {vers},
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
    
        },
    };

    // let mod_stats = ModStats::find_by_id(db_mod.stats)
    //     .one(&db)
    //     .await
    //     .unwrap()
    //     .unwrap();
    let mod_stats = match sqlx::query_as!(models::dModStat,"SELECT * FROM mod_stats WHERE id = $1",db_mod.stats).fetch_one(&mut*trans).await {
        Ok(record) => {record},
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
    
        
        },
    };

    let meilimod = MeiliMod {
        id: Uuid::from_bytes(*db_mod.id.as_bytes()),
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
            .map(|v| MeiliVersion {
                version: v.to_string(),
            })
            .collect(),
        created_at: db_mod.created_at.and_utc().timestamp(),
        updated_at: db_mod.updated_at.and_utc().timestamp(),
        supported_versions: supported_versions
            .into_iter()
            .map(|v| v.to_string())
            .collect(),
    };
    match client.index(format!("{}mods",get_prefix())).add_or_replace(&[meilimod],None).await {
        Ok(_) => {},
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
    
        
        },
    };

    match std::fs::create_dir(format!("./data/cdn/{}", &db_mod.id)) {
        Ok(_) => {},
        Err(e) => {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                warn!("{}", e);

                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error");
        
            }
        },
    };
    match std::fs::write(format!("./data/cdn/{}/{}.forgemod", &db_mod.id,v_id),body) {
        Ok(_) => {},
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    };

    match trans.commit().await {
        Ok(_) => {},
        Err(e) => {
            warn!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        },
    };

    Response::builder()
        .status(StatusCode::CREATED)
        .body("Created")
}
