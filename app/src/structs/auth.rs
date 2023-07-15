// use chrono::DateTime;
// use chrono::Utc;
// use serde::{Deserialize, Serialize};

// use super::users::User;

// #[derive(Debug, Serialize, Deserialize)]
// pub struct JWTAuth {
//     pub user: User,
//     #[serde(with = "chrono::serde::ts_seconds")]
//     pub(crate) exp: DateTime<Utc>, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
//     #[serde(with = "chrono::serde::ts_seconds")]
//     pub(crate) iat: DateTime<Utc>, // Optional. Issued at (as UTC timestamp)
// }

// impl JWTAuth {
//     pub fn new(user: User) -> Self {
//         let now = Utc::now();

//         Self {
//             user,
//             exp: now + chrono::Duration::days(1),
//             iat: now,
//         }
//     }
// }
