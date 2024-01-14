#![allow(non_camel_case_types)]

use async_graphql::*;

use meilisearch_sdk::{Client, SearchQuery, SearchResults};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::Authorization;
use crate::mods::Mod;
use crate::search::{get_prefix, MeiliMod};
use crate::users::User;
use crate::{mods, users};

#[derive(OneofObject)]
enum VersionSearch {
    BeatSaberVersion(Vec<String>),
}

#[derive(OneofObject)]
enum CategorySearch {
    Category(String),
}

#[derive(InputObject)]
struct Filters {
    version: Option<VersionSearch>,
    category: Option<CategorySearch>,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum SortTypes {
    DownloadsDesc,
    DownloadsAsc,
    CreatedAtDesc,
    CreatedAtAsc,
    UpdatedAtDesc,
    UpdatedAtAsc,
}

impl SortTypes {
    pub fn as_meili_query(&self) -> &'static str {
        match self {
            SortTypes::DownloadsDesc => "stats.downloads:desc",
            SortTypes::DownloadsAsc => "stats.downloads:asc",
            SortTypes::CreatedAtDesc => "created_at:desc",
            SortTypes::CreatedAtAsc => "created_at:asc",
            SortTypes::UpdatedAtDesc => "updated_at:desc",
            SortTypes::UpdatedAtAsc => "updated_at:asc",
        }
    }
}

#[derive(InputObject)]
struct Sort {
    sort: Vec<SortTypes>,
}

#[derive(SimpleObject)]
struct gqlSearchResults {
    pub hits: Vec<gqlSearchResult>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub estimated_total_hits: Option<usize>,
    pub page: Option<usize>,
    pub hits_per_page: Option<usize>,
    pub total_hits: Option<usize>,
    pub total_pages: Option<usize>,
    pub processing_time_ms: usize,
    pub query: String,
    pub index_uid: Option<String>,
}

impl gqlSearchResults {
    pub fn from_meili_results(results: SearchResults<MeiliMod>) -> Self {
        Self {
            hits: results
                .hits
                .into_iter()
                .map(|hit| gqlSearchResult {
                    result: hit.result,
                    ranking_score: hit.ranking_score,
                })
                .collect(),
            offset: results.offset,
            limit: results.limit,
            estimated_total_hits: results.estimated_total_hits,
            page: results.page,
            hits_per_page: results.hits_per_page,
            total_hits: results.total_hits,
            total_pages: results.total_pages,
            processing_time_ms: results.processing_time_ms,
            query: results.query,
            index_uid: results.index_uid,
        }
    }
}

#[derive(SimpleObject)]
struct gqlSearchResult {
    pub result: MeiliMod,
    pub ranking_score: Option<f64>,
}

pub struct Query;

#[Object]
impl Query {
    #[allow(unused_assignments, unused_variables)]
    async fn search_mods<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        query: String,
        #[graphql(validator(maximum = 30))] page_size: Option<i32>,
        page: Option<i32>,
        filters: Option<Filters>,
        sort: Option<Sort>,
    ) -> Result<gqlSearchResults> {
        let client = ctx.data::<Client>()?;
        let mods_index = client.index(get_prefix() + "mods");

        let mut sq = SearchQuery::new(&mods_index);

        let mut filter_str = String::new();
        let mut sorts = Vec::new();

        sq.with_hits_per_page(page_size.unwrap_or(10) as usize);
        sq.with_page(page.unwrap_or(1) as usize);

        if let Some(filters) = filters {
            if let Some(version) = &filters.version {
                match version {
                    VersionSearch::BeatSaberVersion(versions) => {
                        filter_str = versions
                            .iter()
                            .map(|v| format!("supported_versions = \"{}\"", v))
                            .collect::<Vec<_>>()
                            .join(" OR ");
                    }
                };
            }

            if let Some(category) = filters.category {
                match category {
                    CategorySearch::Category(category) => {
                        if filters.version.is_some() {
                            filter_str = format!("category = \"{}\" AND {}", category, filter_str);
                        } else {
                            filter_str = format!("category = \"{}\"", category);
                        }
                    }
                };
            }
        }

        if !filter_str.is_empty() {
            sq.with_filter(&filter_str);
        }

        if let Some(sort) = sort {
            sorts = sort
                .sort
                .into_iter()
                .map(|s| s.as_meili_query())
                .collect::<Vec<_>>();
            sq.with_sort(&sorts);
        };

        sq.with_query(&query);
        let query = sq.build();

        let res: SearchResults<MeiliMod> = client
            .index(get_prefix() + "mods")
            .execute_query(&query)
            .await?;

        Ok(gqlSearchResults::from_meili_results(res))
    }

    async fn user_by_id<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        id: Uuid,
        auth: Option<String>,
    ) -> Result<User> {
        let db = ctx.data::<PgPool>()?;
        users::find_by_id(db, id, Authorization::parse(auth)).await
    }

    async fn users<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        #[graphql(validator(maximum = 10))] limit: Option<i32>,
        offset: Option<i32>,
        auth: Option<String>,
    ) -> Result<Vec<User>> {
        let db = ctx.data::<PgPool>()?;
        users::find_all(
            db,
            limit.unwrap_or(10),
            offset.unwrap_or(0),
            Authorization::parse(auth),
        )
        .await
    }

    async fn mods<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        #[graphql(validator(maximum = 10))] limit: Option<i32>,
        offset: Option<i32>,
        version: Option<String>,
    ) -> Result<Vec<Mod>> {
        let db = ctx.data::<PgPool>()?;

        mods::find_all(db, limit.unwrap_or(10), offset.unwrap_or(0), version).await
    }

    async fn mod_by_id<'ctx>(&self, ctx: &Context<'ctx>, id: Uuid) -> Result<Mod> {
        let db = ctx.data::<PgPool>()?;

        mods::find_by_id(db, id).await
    }

    async fn mod_by_slug<'ctx>(&self, ctx: &Context<'ctx>, slug: String) -> Result<Mod> {
        let db = ctx.data::<PgPool>()?;

        mods::find_by_slug(db, slug).await
    }

    async fn mod_by_author<'ctx>(&self, ctx: &Context<'ctx>, id: Uuid) -> Result<Vec<Mod>> {
        let db = ctx.data::<PgPool>()?;

        mods::find_by_author(db, id).await
    }

    async fn categories<'ctx>(&self, ctx: &Context<'ctx>) -> Result<Vec<GCategory>> {
        let db = ctx.data::<PgPool>()?;

        Ok(
            sqlx::query_as!(GCategory, "SELECT name, description FROM categories")
                .fetch_all(db)
                .await?,
        )
    }

    async fn beat_saber_versions<'ctx>(&self, ctx: &Context<'ctx>) -> Result<Vec<String>> {
        let db = ctx.data::<PgPool>()?;

        Ok(sqlx::query!("SELECT * FROM beat_saber_versions")
            .fetch_all(db)
            .await?
            .iter()
            .map(|v| v.ver.clone())
            .collect::<Vec<_>>())
    }
}

#[derive(SimpleObject)]
pub struct GCategory {
    name: String,
    description: String,
}
