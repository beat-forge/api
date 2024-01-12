use async_graphql::SimpleObject;
use chrono::NaiveDateTime;
use futures_util::future::join_all;
use meilisearch_sdk::{Client, Settings};
use poem::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, error, warn};
use uuid::Uuid;

use crate::models;

#[derive(SimpleObject, Serialize, Deserialize)]
pub struct MeiliModStats {
    pub downloads: u64,
}

#[derive(SimpleObject, Serialize, Deserialize)]
pub struct MeiliMod {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub versions: Vec<MeiliVersion>,
    pub category: String,
    pub author: MeiliUser,
    pub stats: MeiliModStats,
    pub supported_versions: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(SimpleObject, Serialize, Deserialize)]
pub struct MeiliUser {
    pub username: String,
    pub display_name: String,
}

#[derive(SimpleObject, Serialize, Deserialize)]
pub struct MeiliVersion {
    pub version: String,
}

#[async_trait]
trait MeiliMigration {
    fn time(&self) -> NaiveDateTime;
    fn name(&self) -> &'static str;
    async fn up(&self, db: &PgPool, client: &Client) -> anyhow::Result<()>;
    async fn down(&self, db: &PgPool, client: &Client) -> anyhow::Result<()>;
}

pub struct MeiliMigrator {
    migrations: Vec<Box<dyn MeiliMigration>>,
}

impl MeiliMigrator {
    pub fn new() -> Self {
        Self {
            migrations: vec![Box::new(CreateIndexMigration)],
        }
    }

    pub async fn run(&mut self, db: &PgPool, client: &Client) -> anyhow::Result<()> {
        self.migrations.sort_by_key(|a| a.time());
        let applied_migrations = sqlx::query!("SELECT * FROM _meilisearch_migrations")
            .fetch_all(db)
            .await?;

        for migration in self.migrations.iter() {
            if applied_migrations
                .iter()
                .any(|m| m.name == migration.name())
            {
                continue;
            }
            info!("Applying migration {}", migration.name());
            migration.up(db, client).await?;
            sqlx::query!(
                "INSERT INTO _meilisearch_migrations (name, created_at) VALUES ($1, $2)",
                migration.name(),
                migration.time()
            )
            .execute(db)
            .await?;
        }

        Ok(())
    }
}

struct CreateIndexMigration;

#[async_trait]
impl MeiliMigration for CreateIndexMigration {
    fn time(&self) -> NaiveDateTime {
        NaiveDateTime::parse_from_str("2023-12-13 00:06:41.052509", "%Y-%m-%d %H:%M:%S.%f").expect(
            "Failed to parse a hardcoded date, this should never happen, please report this!"
        )
    }

    fn name(&self) -> &'static str {
        "CreateIndexMigration"
    }

    async fn up(&self, db: &PgPool, client: &Client) -> anyhow::Result<()> {
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
                    .map(|v| MeiliVersion { version: v.version })
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

                    let supported_versions = match join_all(sqlx::query!("SELECT * FROM mod_beat_saber_versions WHERE mod_id = $1",sqlx::types::Uuid::from_bytes(*m.id.as_bytes())).fetch_all(db).await? .into_iter().map(|v|async move{sqlx::query_as!(models::dBeatSaberVersion,"SELECT * FROM beat_saber_versions WHERE id = $1",sqlx::types::Uuid::from_bytes(*v.beat_saber_version_id.as_bytes())).fetch_one(db).await}),).await.into_iter().map(|v|if let Ok(v)=v{Ok(v.ver)}else{Err(anyhow::anyhow!("Invalid version"))}).collect:: <Result<Vec<_> ,_> >() {
                        Ok(vers) => {vers},
                        Err(e) => {
                            warn!("{}", e);
                            vec![]
                        },
                    };

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
                        supported_versions,
                        created_at: m.created_at.and_utc().timestamp(),
                        updated_at: m.updated_at.and_utc().timestamp(),
                    })
                }),
        )
        .await
        .into_iter()
        .collect::<anyhow::Result<Vec<_>>>()?;

        let settings = Settings::new()
            .with_filterable_attributes(["category, supported_versions"])
            .with_searchable_attributes(["name", "description"])
            .with_sortable_attributes(["stats.downloads", "created_at", "updated_at"]);
        match client.index(format!("{}mods",get_prefix())).set_settings(&settings).await {
            Ok(_) => {},
            Err(e) => {
                error!("{}", e);

                return Err(anyhow::anyhow!("Failed to set settings"));
            },
        };

        match client.index(format!("{}mods",get_prefix())).add_documents(&meili_mods,None).await {
            Ok(_) => {},
            Err(e) => {
                error!("{}", e);

                return Err(anyhow::anyhow!("Failed to add documents"));
            },
        };
        Ok(())
    }

    async fn down(&self, _db: &PgPool, client: &Client) -> anyhow::Result<()> {
        client
            .index(format!("{}mods", get_prefix()))
            .delete()
            .await?;
        Ok(())
    }
}

pub fn get_prefix() -> String {
    let mut prefix = std::env::var("MEILI_PREFIX").unwrap_or("".to_string());
    if !prefix.ends_with('_') {
        prefix = format!("{}_", prefix);
    }
    prefix
}
