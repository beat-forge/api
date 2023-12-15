use clap::Parser;
use forge_lib::structs::{
    forgemod::ForgeMod,
    v1::{data, manifest, ManifestBuilder, ManifestV1, ModBuilder},
};
use rand::{distributions::Alphanumeric, Rng};
use semver::{Version, VersionReq};
use tracing::{error, info, debug};
use inquire::Text;

#[derive(Parser, Debug)]
struct Args {
    #[clap(subcommand)]
    subcmd: SubCommand,
    /// API URL
    #[clap(long)]
    beatforge_api_url: String,
}

#[derive(Parser, Debug)]
enum SubCommand {
    /// Generate random data
    #[clap(name = "random")]
    Random(Random),
    /// Import data from beatmods
    #[clap(name = "import")]
    Import(Import),
    /// Create a new user (use this to get an API key)
    #[clap(name = "login-user")]
    User(User),
}

#[derive(Parser, Debug)]
struct Random {
    /// Number of mods to generate
    #[clap(short, long, default_value = "10")]
    count: usize,
    /// API Key
    #[clap(long, allow_hyphen_values = true)]
    beatforge_api_key: String,
}

#[derive(Parser, Debug)]
struct Import {
    /// BeatMods API URL
    #[clap(long)]
    beatmods_api_url: String,
    /// Beat Saber version to import
    #[clap(long)]
    version: String,
    /// API Key
    #[clap(long)]
    beatforge_api_key: String,
}

#[derive(Parser, Debug)]
struct User {
    // Github Oauth client ID
    #[clap(long)]
    github_client_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt().init();

    match args.subcmd {
        SubCommand::Random(random) => {
            info!("Generating {} random mods", random.count);
            for _ in 0..random.count {
                let fm = random_mod().await?;
                upload_mod(
                    fm,
                    random.beatforge_api_key.clone(),
                    args.beatforge_api_url.clone(),
                )
                .await?;
            }
        }
        SubCommand::Import(import) => {
            info!("Importing mods from {}", import.beatmods_api_url);
        }
        SubCommand::User(user) => {
            info!("Creating new user");
            info!("User created. Your api key is: {}",create_user(user.github_client_id, args.beatforge_api_url)?);
        }
    }

    Ok(())
}

fn create_user(client_id: String, api_url: String) -> anyhow::Result<String> {
    info!("A page will open in your browser. Please authorize the app and copy the code into the terminal. The code will be at the end of the URL when you are redirected.");
    let gh_url = format!("https://github.com/login/oauth/authorize?client_id={}&scope=user:email", client_id);
    open::that(gh_url)?;
    
    let code = Text::new("Enter code: ").prompt()?;

    let res = minreq::post(format!("{}/auth/github?code={}", api_url, code)).send().unwrap();
    let jwt = res.json::<serde_json::Value>()?.as_object().unwrap().get("jwt").unwrap().as_str().unwrap().to_string();
    let res = minreq::get(format!("{}/me", api_url)).with_header("Authorization", format!("Bearer {}", jwt)).send().unwrap();
    Ok(res.json::<serde_json::Value>()?.as_object().unwrap().get("api_key").unwrap().as_str().unwrap().to_string())
}

type ForgeModV1 = ForgeMod<ManifestV1, manifest::Mod, data::Mod>;

async fn random_mod() -> anyhow::Result<ForgeModV1> {
    let artifact_data = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(1024)
        .map(char::from)
        .collect::<String>()
        .into_bytes();
    Ok(ModBuilder::new_mod_raw(
        ManifestBuilder::new_mod(
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect(),
            Version::new(0, 0, 1),
            VersionReq::parse(">=1.29.0")?,
        )
        .build(),
        artifact_data,
    )
    .build())
}

async fn upload_mod(fm: ForgeModV1, api_key: String, api_url: String) -> anyhow::Result<()> {
    let bin = fm.pack()?.to_vec();
    debug!("Api key: {}", api_key);
    info!("Uploading mod {}", fm.manifest.inner.name);

    let res = minreq::post(format!("{}/mods", api_url))
        .with_header("Authorization", format!("Bearer {}", api_key))
        .with_body(bin)
        .send()?;

    if res.status_code != 201 {
        error!("Failed to upload mod. Server returned {}", res.status_code);
        anyhow::bail!("Failed to upload mod: {}", res.status_code);
    }

    Ok(())
}
