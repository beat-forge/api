use forge_lib::structs::v1::{unpack_v1_forgemod, ForgeModTypes};

use poem::{handler, http::StatusCode, web::Path, IntoResponse, Response};
use serde::Deserialize;
use sqlx::PgPool;

use crate::{models, DB_POOL};

#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CdnType {
    Dll,
    Package,
}

async fn cdn_handler(
    db: &PgPool,
    slug: String,
    version: String,
    dl_type: CdnType,
) -> impl IntoResponse {
    // let db_mod = Mods::find()
    //     .filter(entity::mods::Column::Slug.eq(&slug))
    //     .one(&db)
    //     .await
    //     .unwrap();
    let db_mod = sqlx::query_as!(models::dMod, "SELECT * FROM mods WHERE slug = $1", slug)
        .fetch_optional(db)
        .await
        .unwrap();

    if let Some(db_mod) = db_mod {
        // let db_version = Versions::find()
        //     .filter(entity::versions::Column::ModId.eq(db_mod.id))
        //     .filter(entity::versions::Column::Version.eq(&version))
        //     .one(&db)
        //     .await
        //     .unwrap();
        let db_version = sqlx::query_as!(
            models::dVersion,
            "SELECT * FROM versions WHERE mod_id = $1 AND version = $2",
            db_mod.id,
            version
        )
        .fetch_optional(db)
        .await
        .unwrap();

        if let Some(db_version) = db_version {
            let file = match std::fs::read(format!(
                "./data/cdn/{}/{}.forgemod",
                db_mod.id, db_version.id
            )) {
                Ok(file) => file,
                Err(_) => {
                    return Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body("Not Found")
                }
            };
            match dl_type {
                CdnType::Dll => {
                    let package = unpack_v1_forgemod(&*file).unwrap();

                    match package {
                        ForgeModTypes::Mod(m) => {
                            return Response::builder()
                                .header("Content-Type", "application/octet-stream")
                                .header(
                                    "Content-Disposition",
                                    format!("attachment; filename=\"{}.dll\"", m.manifest._id),
                                )
                                .body(m.data.artifact_data);
                        }
                        _ => {
                            return Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body("Not Found");
                        }
                    }
                }
                CdnType::Package => {
                    return Response::builder()
                        .header("Content-Type", "application/octet-stream")
                        .header(
                            "Content-Disposition",
                            format!("attachment; filename=\"{}-v{}.beatforge\"", slug, version),
                        )
                        .body(file);
                }
            }
        }
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("Not Found")
}

// #[get("/cdn/{slug}@{version}/{type}")]
#[handler]
pub async fn cdn_get(
    // db: web::Data<Database>,
    // path: web::Path<(String, String, CdnType)>,
    Path((slug, version, dl_type)): Path<(String, String, CdnType)>,
) -> impl IntoResponse {
    let db = DB_POOL.get().unwrap();

    cdn_handler(db, slug, version, dl_type).await
}

// #[get("/cdn/{slug}@{version}")]
#[handler]
pub async fn cdn_get_typeless(
    // db: web::Data<Database>,
    // path: web::Path<(String, String)>,
    Path((slug, version)): Path<(String, String)>,
) -> impl IntoResponse {
    let db = DB_POOL.get().unwrap();

    cdn_handler(db, slug, version, CdnType::Package).await
}
