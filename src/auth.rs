use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{models, users::User, Key, KEY};

bitflags::bitflags! {
    pub struct Permission: i32 {
        // self permissions
        const VIEW_SELF = 1 << 0;
        const EDIT_SELF = 1 << 1;
        // mod permissions
        const CREATE_MOD = 1 << 2;
        const EDIT_MOD = 1 << 3;
        const APPROVE_MOD = 1 << 4;
        // admin permissions
        const EDIT_OTHER_USERS = 1 << 5;
        const EDIT_OTHER_MODS = 1 << 6;
        const VIEW_OTHER = 1 << 7;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JWTUser {
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

impl From<models::dUser> for JWTUser {
    fn from(m: models::dUser) -> Self {
        Self {
            id: Uuid::from_bytes(*m.id.as_bytes()),
            github_id: m.github_id,
            username: m.username,
            display_name: m.display_name,
            email: m.email,
            bio: m.bio,
            avatar: m.avatar,
            banner: m.banner,
            permissions: m.permissions,
            api_key: Uuid::from_bytes(*m.api_key.as_bytes()),
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JWTAuth {
    pub user: JWTUser,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub(crate) exp: DateTime<Utc>, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    #[serde(with = "chrono::serde::ts_seconds")]
    pub(crate) iat: DateTime<Utc>, // Optional. Issued at (as UTC timestamp)
}

impl JWTAuth {
    pub fn new(user: impl Into<JWTUser>) -> Self {
        let now = Utc::now();

        Self {
            user: user.into(),
            exp: now + chrono::Duration::days(1),
            iat: now,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.exp > Utc::now()
    }

    pub fn decode(dec: String, key: Key) -> Option<Self> {
        let token = match jsonwebtoken::decode::<JWTAuth>(
            &dec,
            &jsonwebtoken::DecodingKey::from_secret(&key.0),
            &jsonwebtoken::Validation::default(),
        ) {
            Err(_) => {
                return None;
            }
            Ok(t) => {
                if t.claims.is_valid() {
                    Some(t)
                } else {
                    None
                }
            }
        };

        Some(token?.claims)
    }

    pub fn encode(&self, key: Key) -> Result<String, jsonwebtoken::errors::Error> {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &self,
            &jsonwebtoken::EncodingKey::from_secret(&key.0),
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Authorization {
    Session(String),
    ApiKey(Uuid),
    None,
}

impl Authorization {
    pub fn parse(s: Option<String>) -> Self {
        match s {
            Some(s) => match Uuid::parse_str(&s) {
                Ok(uuid) => Self::ApiKey(uuid),
                Err(_) => Self::Session(s),
            },
            None => Self::None,
        }
    }

    pub async fn get_user(&self, db: &PgPool) -> Option<models::dUser> {
        match self {
            Self::Session(s) => {
                let auth = JWTAuth::decode(s.to_string(), *KEY.clone());
                match auth {
                    Some(auth) => {
                        let user = sqlx::query_as!(
                            models::dUser,
                            "SELECT * FROM users WHERE id = $1",
                            sqlx::types::Uuid::from_bytes(*auth.user.id.as_bytes())
                        )
                        .fetch_one(db)
                        .await
                        .ok()?;

                        Some(user)
                    }
                    None => None,
                }
            }
            Self::ApiKey(uuid) => {
                let user = sqlx::query_as!(
                    models::dUser,
                    "SELECT * FROM users WHERE api_key = $1",
                    sqlx::types::Uuid::from_bytes(*uuid.as_bytes())
                )
                .fetch_one(db)
                .await
                .ok()?;

                Some(user)
            }
            _ => None,
        }
    }
}

pub trait HasPermissions {
    fn permissions(&self) -> i32;
}

impl HasPermissions for &User {
    fn permissions(&self) -> i32 {
        self.permissions
    }
}

impl HasPermissions for &models::dUser {
    fn permissions(&self) -> i32 {
        self.permissions
    }
}

impl HasPermissions for &mut User {
    fn permissions(&self) -> i32 {
        self.permissions
    }
}

impl HasPermissions for &mut models::dUser {
    fn permissions(&self) -> i32 {
        self.permissions
    }
}

impl HasPermissions for User {
    fn permissions(&self) -> i32 {
        self.permissions
    }
}

impl HasPermissions for models::dUser {
    fn permissions(&self) -> i32 {
        self.permissions
    }
}

pub async fn validate_permissions<T: HasPermissions>(user: T, required: Permission) -> bool {
    required.bits() & user.permissions() != 0
}
