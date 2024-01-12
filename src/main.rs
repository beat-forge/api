#![deny(clippy::unwrap_used, clippy::print_stdout)]

use std::{path::Path, sync::Arc};

use async_graphql::{
    http::{playground_source, GraphQLPlaygroundConfig, GraphiQLSource},
    EmptyMutation, EmptySubscription, Schema,
};
use async_graphql_poem::GraphQL;
use cached::async_sync::OnceCell;
use poem::{
    get, handler, http::StatusCode, listener::TcpListener, post, IntoResponse, Response, Route,
};
use rand::Rng;
use search::MeiliMigrator;
use sqlx::{migrate::Migrator, postgres::PgPoolOptions, PgPool};
use tracing::{error, info, warn};

mod auth;
mod cdn;
mod models;
mod mods;
mod schema;
mod search;
mod users;
mod versions;

#[cfg(feature = "debug")]
mod debug;

use crate::schema::Query;

/// GraphiQL playground UI
// async fn graphiql_route() -> Result<HttpResponse, Error> {
//     juniper_actix::graphiql_handler("/graphql", None).await
// }

// async fn playground_route() -> Result<HttpResponse, Error> {
//     juniper_actix::playground_handler("/graphql", None).await
// }

#[handler]
async fn graphiql_route() -> Response {
    // Ok(HttpResponse::Ok()
    //     .content_type("text/html; charset=utf-8")
    //     .body(GraphiQLSource::build().endpoint("/graphql").finish()))
    Response::builder()
        .content_type("text/html; charset=utf-8")
        .body(GraphiQLSource::build().endpoint("/graphql").finish())
}

#[handler]
async fn playground_route() -> Response {
    Response::builder()
        .content_type("text/html; charset=utf-8")
        .body(playground_source(GraphQLPlaygroundConfig::new("/graphql")))
}

// async fn graphql_route(
//     req: actix_web::HttpRequest,
//     payload: actix_web::web::Payload,
//     data: web::Data<Schema>,
//     db: web::Data<Database>,
// ) -> Result<HttpResponse, Error> {
//     juniper_actix::graphql_handler(&data, &db, req, payload).await
// }

#[derive(Clone, Copy)]
pub struct Key([u8; 1024]);

lazy_static::lazy_static! {
    pub static ref KEY: Arc<Key> = {
        if !Path::new("./data/secret.key").exists() {
            let _ = std::fs::create_dir(Path::new("./data"));
            let mut rng = rand::thread_rng();
            let key: Vec<u8> = (0..1024).map(|_| rng.gen::<u8>()).collect();
            #[allow(clippy::panic)]
            match std::fs::write("./data/secret.key",key) {
                Ok(_) => {},
                Err(e) => {
                    error!("{}", e);
                    panic!("Failed to write secret key")
                },
            };

            info!("Generated secret key (first run)");
        }

        #[allow(clippy::panic)]
        Arc::new(Key(match match std::fs::read("./data/secret.key"){Ok(key)=>key,Err(e)=>{error!("{}",e);panic!("Failed to read secret key")},}.try_into() {
            Ok(key) => key,
            Err(_) => {
                error!("Secret key is not 1024 bytes long, or is corrupt");
                panic!("Failed to read secret key")
            },
        }))
    };
}

pub static DB_POOL: OnceCell<PgPool> = OnceCell::const_new();

pub static MEILI_CONN: OnceCell<meilisearch_sdk::client::Client> = OnceCell::const_new();

pub static MIGRATOR: Migrator = sqlx::migrate!();

#[handler]
async fn index() -> impl IntoResponse {
    let db = match DB_POOL.get() {
        Some(db) => db,
        None => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        }
    }
    .clone();

    // let user_count = entity::users::Entity::find().count(&db).await.unwrap();
    // let mod_count = entity::mods::Entity::find().count(&db).await.unwrap();

    let user_count = match sqlx::query!("SELECT COUNT(*) FROM users")
        .fetch_one(&db)
        .await
    {
        Ok(record) => record,
        Err(e) => {
            error!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        }
    }
    .count
    .unwrap_or(0) as i32;

    let mod_count = match sqlx::query!("SELECT COUNT(*) FROM mods")
        .fetch_one(&db)
        .await
    {
        Ok(record) => record,
        Err(e) => {
            error!("{}", e);

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error");
        }
    }
    .count
    .unwrap_or(0) as i32;

    let mut res = String::new();
    res.push_str("<!DOCTYPE html><html><body style=\"background-color: #18181b; color: #ffffff\">");
    res.push_str(&format!(
        "<p>Currently running forge-api version {}.<p>",
        env!("CARGO_PKG_VERSION")
    ));

    res.push_str("<br>");

    res.push_str(&format!("<p>Currently Serving <a style=\"color: #ff0000\">{}</a> Users and <a style=\"color: #0000ff\">{}</a> Mods.</p>", user_count, mod_count));

    res.push_str("<br>");

    res.push_str("<p><a href=\"graphiql\">GraphiQL</a></p>");
    res.push_str("<p><a href=\"playground\">Playground</a></p>");

    res.push_str("<br>");

    res.push_str(&format!(
        "<p>Check us out on <a href=\"{}\">GitHub</a></p>",
        env!("CARGO_PKG_REPOSITORY")
    ));

    res.push_str("</body></html>");
    res.into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt().init();

    info!("{}", text_to_ascii_art::convert("Beat-Forge-API".to_string()).expect("Should not fail as it is a constant, utf-8 string"));

    #[cfg(feature = "debug")]
    {
        warn!("THIS IS A DEVELOPMENT BUILD, DO NOT USE IN PRODUCTION");
    }

    info!("starting HTTP server on port 8080");
    info!("GraphiQL playground: http://localhost:8080/graphiql");
    info!("Playground: http://localhost:8080/playground");

    let _ = std::fs::create_dir(Path::new("./data/cdn"));

    let pool = PgPoolOptions::new()
        .min_connections(5)
        .max_connections(20)
        .connect(&std::env::var("BF_DATABASE_URL")?)
        .await?;

    DB_POOL.set(pool.clone())?;
    
    let client = meilisearch_sdk::client::Client::new(
        std::env::var("BF_MEILI_URL")?,
        Some(std::env::var("BF_MEILI_KEY")?),
    );

    MEILI_CONN.set(client.clone())?;

    #[cfg(feature = "debug")]
    {
        debug::handel_debug_flags().await?;
    }

    //migrate
    MIGRATOR.run(&pool).await?;


    MeiliMigrator::new().run(&pool).await?;


    let schema = Schema::build(Query, EmptyMutation, EmptySubscription)
        .data(pool)
        .data(client)
        .finish();

    let app = Route::new()
        .at(
            "/graphql",
            get(GraphQL::new(schema.clone())).post(GraphQL::new(schema)),
        )
        .at("/graphiql", get(graphiql_route))
        .at("/playground", get(playground_route))
        .at("/cdn/:slug@:version/:type", get(cdn::cdn_get))
        .at("/cdn/:slug@:version", get(cdn::cdn_get_typeless))
        .at("/mods", post(mods::upload_mod))
        .at("/auth/github", post(users::user_auth))
        .at("/me", get(users::get_me));

    poem::Server::new(TcpListener::bind("0.0.0.0:8080"))
        .run(app)
        .await?;

    info!("Server shutting down ...");

    Ok(())
}
