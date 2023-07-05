use chrono::DateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GithubAccessToken {
    pub access_token: String,
    pub scope: String,
    pub token_type: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GithubUser {
    pub avatar_url: String,
    pub bio: String,
    pub blog: String,
    pub collaborators: i64,
    pub company: Option<String>,
    pub created_at: DateTime<Utc>,
    pub disk_usage: i64,
    pub email: String,
    pub events_url: String,
    pub followers: i64,
    pub followers_url: String,
    pub following: i64,
    pub following_url: String,
    pub gists_url: String,
    pub gravatar_id: String,
    pub hireable: bool,
    pub html_url: String,
    pub id: i64,
    pub location: String,
    pub login: String,
    pub name: Option<String>,
    pub node_id: String,
    pub organizations_url: String,
    pub owned_private_repos: i64,
    pub plan: Plan,
    pub private_gists: i64,
    pub public_gists: i64,
    pub public_repos: i64,
    pub received_events_url: String,
    pub repos_url: String,
    pub site_admin: bool,
    pub starred_url: String,
    pub subscriptions_url: String,
    pub total_private_repos: i64,
    pub twitter_username: String,
    pub two_factor_authentication: bool,
    #[serde(rename = "type")]
    pub type_field: String,
    pub updated_at: DateTime<Utc>,
    pub url: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    pub name: String,
    pub space: i64,
    pub collaborators: i64,
    pub private_repos: i64,
}
