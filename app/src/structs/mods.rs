// use chrono::{DateTime, Utc};
// use forge_lib::structs::manifest::ModCategory;
// use semver::{Version, VersionReq};
// use serde::{Deserialize, Serialize};

// #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
// pub struct ModStats {
//     pub downloads: i64,
// }

// #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
// pub struct ModVersionStats {
//     pub downloads: i64,
// }

// #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
// pub struct ModVersion {
//     #[serde(rename = "_id")]
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub id: Option<ObjectId>,
//     pub mod_id: ObjectId,

//     pub approved: bool,
//     pub version: Version,
//     pub game_version: VersionReq,

//     pub dependencies: Vec<ObjectId>,
//     pub conflicts: Vec<ObjectId>,
//     pub stats: ModVersionStats,

//     #[serde(with = "chrono::serde::ts_seconds")]
//     pub created_at: DateTime<Utc>,
// }

// #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
// pub struct Mod {
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub _id: Option<ObjectId>,
//     pub id: String, // slug

//     pub name: String,
//     pub description: String,
//     pub icon: String,
//     pub cover: String,
//     pub website: String,
//     pub author_id: ObjectId,
//     pub category: ModCategory,
//     pub versions: Vec<ObjectId>,
//     pub stats: ModStats,

//     #[serde(with = "chrono::serde::ts_seconds")]
//     pub created_at: DateTime<Utc>,
//     #[serde(with = "chrono::serde::ts_seconds")]
//     pub updated_at: DateTime<Utc>,
// }
