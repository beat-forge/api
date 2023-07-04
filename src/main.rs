pub mod routes;
use std::path::Path;

use actix_web::{web, App, HttpServer};
use mongodb::{options::ClientOptions, Client, Database};
use rand::Rng;

pub struct AppState {
    pub db: Database,
    pub key: Vec<u8>,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    println!("Running server at http://127.0.0.1:8080");

    let client_options = ClientOptions::parse(std::env::var("MONGO_URI").unwrap().as_str())
        .await
        .unwrap();
    
    let client = Client::with_options(client_options).unwrap();
    let db = client.database(std::env::var("MONGO_DB").unwrap().as_str());

    if !Path::new("./secret.key").exists() {
        let mut rng = rand::thread_rng();
        let key: Vec<u8> = (0..1024).map(|_| rng.gen::<u8>()).collect();
        std::fs::write("./secret.key", key).unwrap();

        println!("Generated secret key (first run)");
    }

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                db: db.clone(),
                key: std::fs::read("./secret.key").unwrap(),
            }))
            .service(routes::mods::categorys)
            .service(routes::mods::create_mod)
            .service(routes::users::create_user)
            .service(routes::mods::get_mods_by_game_semver)
    })
    .bind("127.0.0.1:8080")
    .unwrap()
    .run()
    .await
    .unwrap();
}
