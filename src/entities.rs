use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BeatSaberVersion {
    pub id: Uuid,
    pub ver: String
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Category {
    pub id: Uuid,
    pub name: String,
    pub description: String
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FkModBeatSaberVersion {
    pub mod_id: Uuid,
    pub beat_saber_version_id: Uuid
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModStats {
    pub id: Uuid,
    pub downloads: i32
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VersionStats {
    pub id: Uuid,
    pub downloads: i32
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FkModVersions {
    pub mod_id: Uuid,
    pub version_id: Uuid
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Mod {
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FkUserMods {
    pub user_id: Uuid,
    pub mod_id: Uuid
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct User {
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FkVersionBeatSaberVersions {
    pub version_id: Uuid,
    pub beat_saber_version_id: Uuid
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VersionConflicts {
    pub version_id: Uuid,
    pub dependent: Uuid
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VersionDependents {
    pub version_id: Uuid,
    pub dependent: Uuid
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Versions {
    pub id: Uuid,
    pub mod_id: Uuid,
    pub version: String,
    pub approved: bool,
    pub stats: Uuid,
    pub artifact_hash: String,
    pub download_url: String,
    pub created_at: DateTime<Utc>
}
