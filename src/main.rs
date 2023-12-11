use std::{io, path::Path, sync::Arc};

use async_graphql::{
    http::{playground_source, GraphQLPlaygroundConfig, GraphiQLSource},
    EmptyMutation, EmptySubscription, Schema,
};
use async_graphql_poem::GraphQL;
use cached::async_sync::OnceCell;
use meilisearch_sdk::settings::Settings;
use migration::MigratorTrait;
use poem::{
    get, handler, listener::TcpListener, post, IntoResponse, Response,
    Route,
};
use rand::Rng;
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait};
use tracing::log::info;

mod auth;
mod cdn;
mod mods;
mod schema;
mod users;
mod versions;

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
            std::fs::write("./data/secret.key", key).unwrap();

            println!("Generated secret key (first run)");
        }

        Arc::new(Key(std::fs::read("./data/secret.key").unwrap().try_into().unwrap()))
    };
}

pub static DB_CONN: OnceCell<DatabaseConnection> = OnceCell::const_new();

pub static MEILI_CONN: OnceCell<meilisearch_sdk::client::Client> = OnceCell::const_new();

#[handler]
async fn index() -> impl IntoResponse {
    let db = DB_CONN.get().unwrap().clone();

    let user_count = entity::users::Entity::find().count(&db).await.unwrap();
    let mod_count = entity::mods::Entity::find().count(&db).await.unwrap();

    let mut res = String::new();
    res.push_str("<!DOCTYPE html><html><body style=\"background-color: #18181b; color: #ffffff\">");
    res.push_str(&format!(
        "<p>Currently running forge-api version {}.<p>",
        env!("CARGO_PKG_VERSION")
    ));

    res.push_str("<br>");

    res.push_str(&format!("<p>Currently Serving <a style=\"color: #ff0000\">{}</a> Users and <a style=\"color: #0000ff\">{}</a> Mods.</p>", user_count, mod_count));

    res.push_str("<br>");

    res.push_str(&format!("<p><a href=\"graphiql\">GraphiQL</a></p>"));
    res.push_str(&format!("<p><a href=\"playground\">Playground</a></p>"));

    res.push_str("<br>");

    res.push_str(&format!(
        "<p>Check us out on <a href=\"{}\">GitHub</a></p>",
        env!("CARGO_PKG_REPOSITORY")
    ));

    res.push_str("</body></html>");
    res
}

#[tokio::main]
async fn main() -> io::Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt().init();

    info!("starting HTTP server on port 8080");
    info!("GraphiQL playground: http://localhost:8080/graphiql");
    info!("Playground: http://localhost:8080/playground");

    let _ = std::fs::create_dir(Path::new("./data/cdn"));

    let mut db_conf = sea_orm::ConnectOptions::new(std::env::var("DATABASE_URL").unwrap());

    db_conf.max_connections(20);
    db_conf.min_connections(5);
    db_conf.sqlx_logging(true);
    db_conf.sqlx_logging_level(tracing::log::LevelFilter::Debug);

    let db_conn = sea_orm::Database::connect(db_conf).await.unwrap();

    DB_CONN.set(db_conn.clone()).unwrap();

    //migrate
    migration::Migrator::up(&db_conn, None).await.unwrap();

    if !std::env::var("NO_MEILI").unwrap_or("false".to_string()).parse::<bool>().unwrap_or(false) {
        // set meilisearch settings
        let client = meilisearch_sdk::client::Client::new(
            std::env::var("MEILI_URL").unwrap(),
            Some(std::env::var("MEILI_KEY").unwrap()),
        );
    
        let settings = Settings::new()
            .with_filterable_attributes(&["category", "supported_versions"])
            .with_searchable_attributes(&["name", "description"])
            .with_sortable_attributes(&["stats.downloads", "created_at", "updated_at"]);
        client
            .index(format!(
                "{}_mods",
                std::env::var("MEILI_PREFIX").unwrap_or("".to_string())
            ))
            .set_settings(&settings)
            .await
            .unwrap();

        MEILI_CONN.set(client).unwrap();
    }

    let app = Route::new()
        .at(
            "/graphql",
            get(GraphQL::new(Schema::new(
                Query,
                EmptyMutation,
                EmptySubscription,
            )))
            .post(GraphQL::new(Schema::new(
                Query,
                EmptyMutation,
                EmptySubscription,
            ))),
        )
        .at("/graphiql", get(graphiql_route))
        .at("/playground", get(playground_route))
        .at("/cdn/:slug@:version/:type", get(cdn::cdn_get))
        .at("/cdn/:slug@:version", get(cdn::cdn_get_typeless))
        .at("/mods", post(mods::create_mod))
        .at("/auth/github", post(users::user_auth))
        .at("/me", get(users::get_me));

    poem::Server::new(TcpListener::bind("0.0.0.0:8080"))
        .run(app)
        .await?;

    Ok(())
    // Start HTTP server
    // HttpServer::new(move || {
    //     let schema = Schema::build(Query, EmptyMutation, EmptySubscription).data(Database {
    //         pool: db_conn.clone(),
    //     });

    //     App::new()
    //         .app_data(Data::new(
    //             Schema::build(Query, EmptyMutation, EmptySubscription).data(Database {
    //                 pool: db_conn.clone(),
    //             }),
    //         ))
    //         .app_data(Data::new(Database {
    //             pool: db_conn.clone(),
    //         }))
    //         // .service(
    //         //     web::resource("/graphql")
    //         //         .route(web::post().to(graphql_route))
    //         //         .route(web::get().to(graphql_route)),
    //         // )
    //         // .service(
    //         //         web::post().to(|data: web::Data<Schema>| {
    //         //             async_graphql_actix_web::graphql(data, async_graphql_actix_web::GraphQLPlaygroundConfig::new())
    //         //         })
    //         // )
    //         .service(web::resource("/playground").route(web::get().to(playground_route)))
    //         .service(web::resource("/graphiql").route(web::get().to(graphiql_route)))
    //         .service(users::user_auth)
    //         .service(mods::create_mod)
    //         .service(cdn::cdn_get)
    //         .service(index)
    //         .service(users::get_me)
    //         // the graphiql UI requires CORS to be enabled
    //         .wrap(Cors::permissive())
    //         .wrap(middleware::Logger::default())
    // })
    // .workers(2)
    // .bind(("0.0.0.0", 8080))?
    // .run()
    // .await
}
