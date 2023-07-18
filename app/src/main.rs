pub mod routes;
pub mod structs;
mod utils;

use actix_cors::Cors;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use rand::Rng;
use reqwest::Client as Reqwest;
use sea_orm::{Database, DatabaseConnection};
use std::path::Path;

pub struct AppState {
    pub db: DatabaseConnection,
    pub reqwest: Reqwest,
    pub key: Vec<u8>,
}

#[get("/")]
pub async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[actix_web::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    dotenv::dotenv().ok();

    let db = Database::connect(std::env::var("POSTGRES_URL").unwrap())
        .await
        .unwrap();

    let reqwest = Reqwest::builder()
        .user_agent(format!("forge-registry/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap();

    if !Path::new("./secret.key").exists() {
        let mut rng = rand::thread_rng();
        let key: Vec<u8> = (0..1024).map(|_| rng.gen::<u8>()).collect();
        std::fs::write("./secret.key", key).unwrap();

        println!("Generated secret key (first run)");
    }

    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .wrap(actix_web::middleware::Logger::default())
            .app_data(web::Data::new(AppState {
                db: db.clone(),
                reqwest: reqwest.clone(),
                key: std::fs::read("./secret.key").unwrap(),
            }))
            .service(index)
            .service(routes::mods::get_mod)
            // .service(routes::mods::get_mod_full)
            .service(routes::mods::get_mods_by_author)
            .service(routes::mods::get_mods)
            .service(routes::mods::create_mod)
            .service(routes::mods::get_categories)
            .service(routes::users::get_user)
            .service(routes::users::get_user_full)
            .service(routes::users::auth_user)
    })
    .bind("0.0.0.0:8080")
    .unwrap()
    .run()
    .await
    .unwrap();
}
