#![allow(non_camel_case_types)]

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::types::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dBeatSaberVersion {
    pub id: Uuid,
    pub ver: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dCategory {
    pub id: Uuid,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dFkModBeatSaberVersion {
    pub mod_id: Uuid,
    pub beat_saber_version_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dModStat {
    pub id: Uuid,
    pub downloads: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dVersionStat {
    pub id: Uuid,
    pub downloads: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dFkModVersion {
    pub mod_id: Uuid,
    pub version_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dMod {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub cover: Option<String>,
    pub website: Option<String>,
    pub author: Uuid,
    pub category: Uuid,
    pub stats: Uuid,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dFkUserMod {
    pub user_id: Uuid,
    pub mod_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dUser {
    pub id: Uuid,
    pub github_id: i32,
    pub username: String,
    pub display_name: Option<String>,
    pub email: String,
    pub bio: Option<String>,
    pub avatar: Option<String>,
    pub banner: Option<String>,
    pub permissions: i32,
    pub api_key: Uuid,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dFkVersionBeatSaberVersion {
    pub version_id: Uuid,
    pub beat_saber_version_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dVersionConflict {
    pub version_id: Uuid,
    pub dependent: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dVersionDependent {
    pub version_id: Uuid,
    pub dependent: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct dVersion {
    pub id: Uuid,
    pub mod_id: Uuid,
    pub version: String,
    pub approved: bool,
    pub stats: Uuid,
    pub artifact_hash: String,
    pub download_url: String,
    pub created_at: NaiveDateTime,
}
