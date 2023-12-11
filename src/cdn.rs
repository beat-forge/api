use entity::prelude::*;
use forge_lib::structs::v1::{unpack_v1_forgemod, ForgeModTypes};

use poem::{handler, web::Path, Response, IntoResponse, http::StatusCode};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, DatabaseConnection};
use serde::Deserialize;

use crate::DB_POOL;

#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CdnType {
    Dll,
    Package,
}

async fn cdn_handler(
    db: DatabaseConnection,
    slug: String,
    version: String,
    dl_type: CdnType,
) -> impl IntoResponse {
    let db_mod = Mods::find()
        .filter(entity::mods::Column::Slug.eq(&slug))
        .one(&db)
        .await
        .unwrap();

    if let Some(db_mod) = db_mod {
        let db_version = Versions::find()
            .filter(entity::versions::Column::ModId.eq(db_mod.id))
            .filter(entity::versions::Column::Version.eq(&version))
            .one(&db)
            .await
            .unwrap();

        if let Some(db_version) = db_version {
            let file = match std::fs::read(format!(
                "./data/cdn/{}/{}.forgemod",
                db_mod.id, db_version.id
            )) {
                Ok(file) => file,
                Err(_) => return Response::builder().status(StatusCode::NOT_FOUND).body("Not Found"),
            };
            match dl_type {
                CdnType::Dll => {
                    let package = unpack_v1_forgemod(&*file).unwrap();

                    match package {
                        ForgeModTypes::Mod(m) => 
                        {
                            return Response::builder()
                                .header("Content-Type", "application/octet-stream")
                                .header("Content-Disposition", format!("attachment; filename=\"{}.dll\"", m.manifest._id))
                                .body(m.data.artifact_data);
                        },
                        _ => {
                            return Response::builder().status(StatusCode::NOT_FOUND).body("Not Found");
                        }
                    }
                }
                CdnType::Package => {
                    return Response::builder()
                        .header("Content-Type", "application/octet-stream")
                        .header("Content-Disposition", format!("attachment; filename=\"{}-v{}.beatforge\"", slug, version))
                        .body(file);
                }
            }
        }
    }

    Response::builder().status(StatusCode::NOT_FOUND).body("Not Found")
}

// #[get("/cdn/{slug}@{version}/{type}")]
#[handler]
pub async fn cdn_get(
    // db: web::Data<Database>,
    // path: web::Path<(String, String, CdnType)>,
    Path((slug, version, dl_type)): Path<(String, String, CdnType)>,
) -> impl IntoResponse {
    let db = DB_POOL.get().unwrap().clone();

    cdn_handler(db, slug, version, dl_type).await
}

// #[get("/cdn/{slug}@{version}")]
#[handler]
pub async fn cdn_get_typeless(
    // db: web::Data<Database>,
    // path: web::Path<(String, String)>,
    Path((slug, version)): Path<(String, String)>,
) -> impl IntoResponse {
    let db = DB_POOL.get().unwrap().clone();

    cdn_handler(db, slug, version, CdnType::Package).await
}
