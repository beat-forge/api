use actix_web::HttpRequest;

pub fn get_bearer_auth(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|jwt| jwt.to_str().ok())
        .map(|token| token.replace("Bearer ", ""))
}
