use chrono::DateTime;
use chrono::Utc;
use mongodb::bson::oid::ObjectId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GithubAccessToken {
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GithubUser {
    pub login: String,
    pub id: i64,
    pub node_id: String,
    pub avatar_url: String,
    pub gravatar_id: String,
    pub url: String,
    pub html_url: String,
    pub followers_url: String,
    pub following_url: String,
    pub gists_url: String,
    pub starred_url: String,
    pub subscriptions_url: String,
    pub organizations_url: String,
    pub repos_url: String,
    pub events_url: String,
    pub received_events_url: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub site_admin: bool,
    pub name: Option<String>,
    pub company: Option<String>,
    pub blog: String,
    pub location: String,
    pub email: String,
    pub hireable: bool,
    pub bio: String,
    pub twitter_username: String,
    pub public_repos: i64,
    pub public_gists: i64,
    pub followers: i64,
    pub following: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub private_gists: i64,
    pub total_private_repos: i64,
    pub owned_private_repos: i64,
    pub disk_usage: i64,
    pub collaborators: i64,
    pub two_factor_authentication: bool,
    pub plan: Plan,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    pub name: String,
    pub space: i64,
    pub collaborators: i64,
    pub private_repos: i64,
}

// JSON Web Token

#[derive(Debug, Serialize, Deserialize)]
pub struct JWTAuth {
    pub uid: ObjectId,
    #[serde(with = "chrono::serde::ts_seconds")]
    exp: DateTime<Utc>, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    #[serde(with = "chrono::serde::ts_seconds")]
    iat: DateTime<Utc>, // Optional. Issued at (as UTC timestamp)
}

impl JWTAuth {
    pub fn new(uid: ObjectId) -> Self {
        let now = Utc::now();

        Self {
            uid,
            exp: now + chrono::Duration::days(1),
            iat: now,
        }
    }
}
