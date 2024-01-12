use forge_lib::structs::{
    forgemod::ForgeMod,
    v1::{data, manifest, ManifestBuilder, ManifestV1, ModBuilder},
};
use rand::{distributions::Alphanumeric, Rng};
use semver::{Version, VersionReq};
use tracing::{info, error};

use crate::{
    mods::_upload_mod,
    DB_POOL, MIGRATOR, search::{get_prefix, MeiliMigrator}, MEILI_CONN,
};

pub async fn handel_debug_flags() -> anyhow::Result<()> {
    let db = DB_POOL
        .get()
        .ok_or(anyhow::anyhow!("Failed to get DB pool"))?;

    let is_fresh = sqlx::query!(
        "SELECT * FROM _sqlx_migrations"
    ).fetch_all(db).await?.is_empty();

    if !is_fresh {
        // check to see if reset flag is set.
        if let Ok(reset) = std::env::var("BF_DEBUG_FULL_RESET") {
            if reset == "true" {
                error!("Resetting database");
                sqlx::query!("DROP SCHEMA public CASCADE").execute(db).await?;
                sqlx::query!("CREATE SCHEMA public").execute(db).await?;
                MIGRATOR.run(db).await?;

                let meili_index = MEILI_CONN.get().ok_or(anyhow::anyhow!("Failed to get MeiliSearch client"))?.index(format!("{}mods",get_prefix()));
                meili_index.delete().await?;

                MeiliMigrator::new().run(db).await?;
            }
        } else {
            return Ok(());
        }
    }

    if let Ok(user_num) = std::env::var("BF_DEBUG_FAKE_USERS") {
        let user_num = user_num.parse::<usize>()?;
        for _ in 0..user_num {
            generate_user().await?;
        }
    }

    if let Ok(mod_num) = std::env::var("BF_DEBUG_FAKE_MODS_PER_USER") {
        let mod_num = mod_num.parse::<usize>()?;

        let users = sqlx::query!("SELECT api_key FROM users")
            .fetch_all(db)
            .await?;
        for user in users {
            for _ in 0..mod_num {
                generate_mod(user.api_key.to_string(), None).await?;
            }
        }
    }

    if let Ok(vers_num) = std::env::var("BF_DEBUG_FAKE_VERSIONS_PER_MOD") {
        let vers_num = vers_num.parse::<usize>()?;

        let mods = sqlx::query!("SELECT author, slug FROM mods")
            .fetch_all(db)
            .await?;
        for db_mod in mods {
            let api_key = sqlx::query!("SELECT api_key FROM users WHERE id = $1", db_mod.author)
                .fetch_one(db)
                .await?
                .api_key;
            for _ in 0..vers_num {
                generate_mod(api_key.to_string(), Some(db_mod.slug.clone())).await?;
            }
        }
    }

    Ok(())
}

pub async fn generate_user() -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();

    let username: String = rand::thread_rng().sample_iter(&Alphanumeric)
    .take(16)
    .map(char::from)
    .collect();
    let email: String = rand::thread_rng().sample_iter(&Alphanumeric)
    .take(16)
    .map(char::from)
    .collect::<String>() + "@example.com";
    let bio = Some(rand::thread_rng().sample_iter(&Alphanumeric)
    .take(16)
    .map(char::from)
    .collect::<String>());
    let avatar = Some("https://http.cat/501".to_string());
    let permissions = 7;
    let github_id = rng.gen::<u32>() as i32;

    info!("Generating user {}", username);

    let db = DB_POOL
        .get()
        .ok_or(anyhow::anyhow!("Failed to get DB pool"))?;

    sqlx::query!(
        "INSERT INTO users (username, email, bio, avatar, permissions, github_id) VALUES ($1, $2, $3, $4, $5, $6)",
        username,
        email,
        bio,
        avatar,
        permissions,
        github_id
    )
    .execute(db)
    .await?;

    Ok(())
}

pub async fn generate_mod(api_key: String, slug: Option<String>) -> anyhow::Result<()> {
    let random_mod = random_mod(slug).await?;
    let body = random_mod.pack()?;

    info!("Generating mod {}", random_mod.manifest._id);

    let res = _upload_mod(("Bearer ".to_string() + &api_key).as_str(), body.to_vec()).await;
    if res.status().is_success() {
        Ok(())
    } else {
        error!("Failed to upload mod. Server returned {}", res.status());
        Err(anyhow::anyhow!("Failed to upload mod"))
    }
}

type ForgeModV1 = ForgeMod<ManifestV1, manifest::Mod, data::Mod>;

async fn random_mod(slug: Option<String>) -> anyhow::Result<ForgeModV1> {
    let artifact_data = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(1024)
        .map(char::from)
        .collect::<String>()
        .into_bytes();
    Ok(ModBuilder::new_mod_raw(
        ManifestBuilder::new_mod(
            slug.unwrap_or(
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(16)
                    .map(char::from)
                    .collect(),
            ),
            Version::new(rand::thread_rng().gen(), rand::thread_rng().gen(), rand::thread_rng().gen()),
            VersionReq::parse(">=1.29.0")?,
        )
        .build(),
        artifact_data,
    )
    .build())
}
