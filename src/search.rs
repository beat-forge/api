use chrono::NaiveDateTime;
use futures_util::future::join_all;
use meilisearch_sdk::{Client, Settings};
use poem::async_trait;
use semver::Version;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models;

#[derive(Serialize, Deserialize)]
pub struct MeiliModStats {
    pub downloads: u64,
}

#[derive(Serialize, Deserialize)]
pub struct MeiliMod {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub versions: Vec<MeiliVersion>,
    pub category: String,
    pub author: MeiliUser,
    pub stats: MeiliModStats,
    pub supported_versions: Vec<Version>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct MeiliUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct MeiliVersion {
    pub version: Version,
}

#[async_trait]
trait MeiliMigratior {
    fn time(&self) -> NaiveDateTime;
    fn name(&self) -> &'static str;
    async fn up(&self, db: &PgPool, client: &Client, prefix: String) -> anyhow::Result<()>;
    async fn down(&self, db: &PgPool, client: &Client, prefix: String) -> anyhow::Result<()>;
}

struct MeiliMigrator {
    migrations: Vec<Box<dyn MeiliMigratior>>,
}

impl MeiliMigrator {
    fn new() -> Self {
        Self {
            migrations: Vec::new(),
        }
    }
}

struct CreateIndexMigration;

#[async_trait]
impl MeiliMigratior for CreateIndexMigration {
    fn time(&self) -> NaiveDateTime {
        NaiveDateTime::parse_from_str("2023-12-13 00:06:41.052509", "%Y-%m-%d %H:%M:%S.%f").unwrap()
    }

    fn name(&self) -> &'static str {
        "CreateIndexMigration"
    }

    async fn up(&self, db: &PgPool, client: &Client, prefix: String) -> anyhow::Result<()> {
        let meili_mods = join_all(
            sqlx::query_as!(models::dMod, "SELECT * FROM mods")
                .fetch_all(db)
                .await?
                .into_iter()
                .map(move |m| async move {
                    let vers = sqlx::query_as!(
                        models::dVersion,
                        "SELECT * FROM versions WHERE mod_id = $1",
                        sqlx::types::Uuid::from_bytes(*m.id.as_bytes())
                    )
                    .fetch_all(db)
                    .await?
                    .into_iter()
                    .map(|v| MeiliVersion {
                        version: Version::parse(&v.version).unwrap(),
                    })
                    .collect::<Vec<_>>();

                    let category = sqlx::query_as!(
                        models::dCategory,
                        "SELECT * FROM categories WHERE id = $1",
                        sqlx::types::Uuid::from_bytes(*m.category.as_bytes())
                    )
                    .fetch_one(db)
                    .await?;

                    let author = sqlx::query_as!(
                        models::dUser,
                        "SELECT * FROM users WHERE id = $1",
                        sqlx::types::Uuid::from_bytes(*m.author.as_bytes())
                    )
                    .fetch_one(db)
                    .await?;

                    let stats = sqlx::query_as!(
                        models::dModStat,
                        "SELECT * FROM mod_stats WHERE id = $1",
                        sqlx::types::Uuid::from_bytes(*m.stats.as_bytes())
                    )
                    .fetch_one(db)
                    .await?;

                    let supported_versions = join_all(
                        sqlx::query!(
                            "SELECT * FROM mod_beat_saber_versions WHERE mod_id = $1",
                            sqlx::types::Uuid::from_bytes(*m.id.as_bytes())
                        )
                        .fetch_all(db)
                        .await?
                        .into_iter()
                        .map(|v| async move {
                            sqlx::query_as!(
                                models::dBeatSaberVersion,
                                "SELECT * FROM beat_saber_versions WHERE id = $1",
                                sqlx::types::Uuid::from_bytes(*v.beat_saber_version_id.as_bytes())
                            )
                            .fetch_one(db)
                            .await
                        }),
                    )
                    .await
                    .into_iter()
                    .map(|v| v.unwrap().ver)
                    .collect::<Vec<_>>();

                    Ok(MeiliMod {
                        id: Uuid::from_bytes(*m.id.as_bytes()),
                        slug: m.slug,
                        name: m.name,
                        description: m.description.unwrap_or("".to_string()),
                        category: category.name,
                        versions: vers,
                        author: MeiliUser {
                            username: author.username.clone(),
                            display_name: author.display_name.unwrap_or(author.username),
                        },
                        stats: MeiliModStats {
                            downloads: stats.downloads as u64,
                        },
                        supported_versions: supported_versions
                            .into_iter()
                            .map(|v| semver::Version::parse(&v).unwrap())
                            .collect(),
                        created_at: m.created_at.and_utc().timestamp(),
                        updated_at: m.updated_at.and_utc().timestamp(),
                    })
                }),
        )
        .await
        .into_iter()
        .collect::<anyhow::Result<Vec<_>>>()?;

        let settings = Settings::new()
            .with_filterable_attributes(&["category, supported_versions"])
            .with_searchable_attributes(&["name", "description"])
            .with_sortable_attributes(&["stats.downloads", "created_at", "updated_at"]);
        client
            .index(format!(
                "{}_mods",
                prefix
            ))
            .set_settings(&settings)
            .await
            .unwrap();

        client
            .index(format!(
                "{}_mods",
                prefix
            ))
            .add_documents(&meili_mods, None)
            .await
            .unwrap();
        Ok(())
    }

    async fn down(&self, db: &PgPool, client: &Client, prefix: String) -> anyhow::Result<()> {
        client.index(format!("{}_mods", prefix)).delete().await?;
        Ok(())
    }
}
