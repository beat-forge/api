use chrono::DateTime;
use chrono::Utc;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

use super::github::GithubUser;

bitflags::bitflags! {
    pub struct Permission: i32 {
        // self permissions
        const UPLOAD_MOD = 1 << 0;
        const EDIT_MOD = 1 << 1;
        const DELETE_MOD = 1 << 2;

        // other permissions
        const EDIT_MOD_OTHER = 1 << 3; // can verfiy mods
        const DELETE_MOD_OTHER = 1 << 4;

        // admin permissions
        const DELETE_USER = 1 << 5;
        const EDIT_USER = 1 << 6;
    }
}

impl Permission {
    pub fn has(&self, other: Self) -> bool {
        self.contains(other)
    }

    pub fn has_bits(&self, bits: i32) -> bool {
        self.bits() & bits == self.bits()
    }
}

impl Default for Permission {
    fn default() -> Self {
        Self::UPLOAD_MOD | Self::EDIT_MOD | Self::DELETE_MOD
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    #[serde(rename = "_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    // basic info
    pub github_id: i64,
    pub username: String,
    pub email: String,

    // public info
    pub display_name: Option<String>,
    pub avatar: Option<String>,
    pub bio: Option<String>,
    pub mods: Vec<ObjectId>,

    // system info
    pub permissions: i32, // bitflags
    pub api_key: String,  // uuid

    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

impl From<GithubUser> for User {
    fn from(user: GithubUser) -> Self {
        let now = Utc::now();
        let permissions = Permission::default().bits();
        let api_key = uuid::Uuid::new_v4().to_string();

        Self {
            id: None,
            github_id: user.id,
            username: user.login.clone(),
            email: user.email,
            display_name: Some(user.login),
            avatar: Some(user.avatar_url),
            bio: None,
            permissions,
            api_key,
            mods: vec![],
            created_at: now,
            updated_at: now,
        }
    }
}
