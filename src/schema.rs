use async_graphql::*;

use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::Authorization;
use crate::mods::Mod;
use crate::users::User;
use crate::{mods, users};

pub struct Query;

#[Object]
impl Query {
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

        // Ok(BeatSaberVersions::find()
        //     .all(&db)
        //     .await
        //     .unwrap()
        //     .iter()
        //     .map(|v| v.ver.clone())
        //     .collect::<Vec<_>>())
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
