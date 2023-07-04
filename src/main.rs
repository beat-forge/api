pub mod routes;

use actix_web::{web, App, HttpServer};
use mongodb::{options::ClientOptions, Client, Database};

pub struct AppState {
    pub db: Database,
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

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState { db: db.clone() }))
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
