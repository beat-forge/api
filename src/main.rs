use std::{io, sync::Arc, path::Path};

use actix_cors::Cors;
use actix_web::{
    middleware,
    web::{self, Data},
    App, HttpResponse, HttpServer, Error, get, Responder,
};
use cached::async_sync::OnceCell;
use meilisearch_sdk::settings::Settings;
use migration::MigratorTrait;
use rand::Rng;
use sea_orm::{EntityTrait, PaginatorTrait, DatabaseConnection};

mod schema;
mod users;
mod mods;
mod versions;
mod auth;
mod cdn;

use crate::schema::{create_schema, Schema};

/// GraphiQL playground UI
async fn graphiql_route() -> Result<HttpResponse, Error> {
    juniper_actix::graphiql_handler("/graphql", None).await
}

async fn playground_route() -> Result<HttpResponse, Error> {
    juniper_actix::playground_handler("/graphql", None).await
}

async fn graphql_route(
    req: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<Schema>,
    db: web::Data<Database>,
) -> Result<HttpResponse, Error> {
    juniper_actix::graphql_handler(&data, &db, req, payload).await
}

#[derive(Clone)]
pub struct Database {
    pool: sea_orm::DatabaseConnection,
}

impl juniper::Context for Database {}

#[derive(Clone, Copy)]
pub struct Key([u8; 1024]);

lazy_static::lazy_static! {
    pub static ref KEY: Arc<Key> = {
        if !Path::new("./data/secret.key").exists() {
            let _ = std::fs::create_dir(Path::new("./data"));
            let mut rng = rand::thread_rng();
            let key: Vec<u8> = (0..1024).map(|_| rng.gen::<u8>()).collect();
            std::fs::write("./data/secret.key", key).unwrap();
    
            println!("Generated secret key (first run)");
        }
    
        Arc::new(Key(std::fs::read("./data/secret.key").unwrap().try_into().unwrap()))
    };
}

#[get("/")]
async fn index(data: web::Data<Database>) -> impl Responder {
    let user_count = entity::users::Entity::find().count(&data.pool).await.unwrap();
    let mod_count = entity::mods::Entity::find().count(&data.pool).await.unwrap();

    let mut res = String::new();
    res.push_str("<!DOCTYPE html><html><body style=\"background-color: #18181b; color: #ffffff\">");
    res.push_str(&format!("<p>Currently running forge-api version {}.<p>", env!("CARGO_PKG_VERSION")));

    res.push_str("<br>");

    res.push_str(&format!("<p>Currently Serving <a style=\"color: #ff0000\">{}</a> Users and <a style=\"color: #0000ff\">{}</a> Mods.</p>", user_count, mod_count));

    res.push_str("<br>");

    res.push_str(&format!("<p><a href=\"graphiql\">GraphiQL</a></p>"));
    res.push_str(&format!("<p><a href=\"playground\">Playground</a></p>"));

    res.push_str("<br>");

    res.push_str(&format!("<p>Check us out on <a href=\"{}\">GitHub</a></p>", env!("CARGO_PKG_REPOSITORY")));

    res.push_str("</body></html>");
    HttpResponse::Ok().body(res)
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("starting HTTP server on port 8080");
    log::info!("GraphiQL playground: http://localhost:8080/graphiql");
    log::info!("Playground: http://localhost:8080/playground");

    let mut db_conf = sea_orm::ConnectOptions::new(std::env::var("DATABASE_URL").unwrap());

    db_conf.max_connections(20);
    db_conf.min_connections(5);
    db_conf.sqlx_logging(true);
    db_conf.sqlx_logging_level(log::LevelFilter::Debug);

    let db_conn = sea_orm::Database::connect(db_conf).await.unwrap();

    let _ = std::fs::create_dir(Path::new("./data/cdn"));

    //migrate
    migration::Migrator::up(&db_conn, None).await.unwrap();

    // set meilisearch settings
    let client = meilisearch_sdk::client::Client::new(std::env::var("MEILI_URL").unwrap(), Some(std::env::var("MEILI_KEY").unwrap()));

    let settings = Settings::new().with_filterable_attributes(&["category", "supported_versions"]).with_searchable_attributes(&["name", "description"]).with_sortable_attributes(&["stats.downloads", "created_at", "updated_at"]);
    client.index(format!("{}_mods", std::env::var("MEILI_PREFIX").unwrap_or("".to_string()))).set_settings(&settings).await.unwrap();

    // Start HTTP server
    HttpServer::new( move || {
        App::new()
            .app_data(Data::new(create_schema()))
            .app_data(Data::new(
                Database {
                    pool: db_conn.clone(),
                }
            ))
            .service(
                web::resource("/graphql")
                    .route(web::post().to(graphql_route))
                    .route(web::get().to(graphql_route)),
            )
            .service(web::resource("/playground").route(web::get().to(playground_route)))
            .service(web::resource("/graphiql").route(web::get().to(graphiql_route)))
            .service(users::user_auth)
            .service(mods::create_mod)
            .service(cdn::cdn_get)
            .service(index)
            .service(users::get_me)
            // the graphiql UI requires CORS to be enabled
            .wrap(Cors::permissive())
            .wrap(middleware::Logger::default())
    })
    .workers(2)
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}