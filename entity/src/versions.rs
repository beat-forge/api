//! `SeaORM` Entity. Generated by sea-orm-codegen 0.11.3

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "versions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub mod_id: Uuid,
    pub version: String,
    pub approved: bool,
    #[sea_orm(unique)]
    pub stats: Uuid,
    #[sea_orm(unique)]
    pub artifact_hash: String,
    pub download_url: String,
    pub created_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::mod_versions::Entity")]
    ModVersions,
    #[sea_orm(
        belongs_to = "super::mods::Entity",
        from = "Column::ModId",
        to = "super::mods::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Mods,
    #[sea_orm(has_many = "super::version_beat_saber_versions::Entity")]
    VersionBeatSaberVersions,
    #[sea_orm(
        belongs_to = "super::version_stats::Entity",
        from = "Column::Stats",
        to = "super::version_stats::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    VersionStats,
}

impl Related<super::mod_versions::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ModVersions.def()
    }
}

impl Related<super::mods::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Mods.def()
    }
}

impl Related<super::version_beat_saber_versions::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionBeatSaberVersions.def()
    }
}

impl Related<super::version_stats::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionStats.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
