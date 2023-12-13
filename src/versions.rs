use async_graphql::*;
use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models;

#[derive(SimpleObject, Debug, Deserialize, Serialize, Clone)]
pub struct GVersion {
    pub id: Uuid,
    pub mod_id: Uuid,
    pub version: String,
    pub approved: bool,
    pub download_url: String,
    pub supported_game_versions: Vec<String>,
    pub stats: GVersionStats,
    pub created_at: DateTime<Utc>,
}

#[derive(SimpleObject, Debug, Deserialize, Serialize, Clone)]
pub struct GVersionStats {
    pub downloads: i32,
    // pub rating: f32,
    // pub rating_count: i32,
}

impl GVersion {
    pub async fn from_db_version(db: &PgPool, v: models::dVersion) -> Result<Self, FieldError> {
        // let versions = VersionBeatSaberVersions::find()
        //     .filter(entity::version_beat_saber_versions::Column::VersionId.eq(v.id))
        //     .find_also_related(BeatSaberVersions)
        //     .all(db)
        //     .await
        //     .unwrap()
        //     .iter()
        //     .map(|v| v.1.clone().unwrap().ver)
        //     .collect::<Vec<_>>();
        let versions = sqlx::query!("SELECT * FROM beat_saber_versions WHERE id IN (SELECT beat_saber_version_id FROM version_beat_saber_versions WHERE version_id = $1)", sqlx::types::Uuid::from_bytes(*v.id.as_bytes()))
            .fetch_all(db)
            .await?
            .iter()
            .map(|v| v.ver.clone())
            .collect::<Vec<_>>();

        // let stats = VersionStats::find_by_id(v.stats)
        //     .one(db)
        //     .await
        //     .unwrap()
        //     .unwrap();
        let stats = sqlx::query_as!(
            models::dVersionStat,
            "SELECT * FROM version_stats WHERE id = $1",
            sqlx::types::Uuid::from_bytes(*v.stats.as_bytes())
        )
        .fetch_one(db)
        .await?;

        Ok(GVersion {
            id: Uuid::from_bytes(*v.id.as_bytes()),
            mod_id: Uuid::from_bytes(*v.mod_id.as_bytes()),
            version: v.version,
            supported_game_versions: versions,
            created_at: v.created_at.and_utc(),
            approved: v.approved,
            download_url: v.download_url,
            stats: GVersionStats {
                downloads: stats.downloads,
            },
        })
    }
}

pub async fn find_by_mod_id(db: &PgPool, id: Uuid) -> FieldResult<Vec<GVersion>> {
    // let id = sea_orm::prelude::Uuid::from_bytes(*id.as_bytes());

    // let versions = Versions::find()
    //     .filter(entity::versions::Column::ModId.eq(id))
    //     .all(db)
    //     .await
    //     .unwrap();
    let versions = sqlx::query_as!(
        models::dVersion,
        "SELECT * FROM versions WHERE mod_id = $1",
        sqlx::types::Uuid::from_bytes(*id.as_bytes())
    )
    .fetch_all(db)
    .await?;

    let mut r = vec![];
    for version in versions {
        r.push(GVersion::from_db_version(db, version).await?);
    }
    Ok(r)
}
