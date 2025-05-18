use actix_web::{
    App, HttpMessage, HttpResponse, HttpServer,
    error::ParseError,
    http::header::{Header, HeaderName, HeaderValue, InvalidHeaderValue, TryIntoHeaderValue},
    post, web,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;

pub struct GitHubEventType(String);
type HmacSha256 = Hmac<Sha256>;

impl GitHubEventType {
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryIntoHeaderValue for GitHubEventType {
    type Error = InvalidHeaderValue;

    fn try_into_value(self) -> Result<HeaderValue, Self::Error> {
        HeaderValue::try_from(self.0)
    }
}

impl Header for GitHubEventType {
    fn name() -> HeaderName {
        "X-GitHub-Event".parse().unwrap()
    }

    fn parse<M: HttpMessage>(msg: &M) -> Result<Self, actix_web::error::ParseError> {
        let header = msg.headers().get(Self::name());
        if let Some(header) = header {
            Ok(GitHubEventType(header.to_str().unwrap().to_string()))
        } else {
            Err(ParseError::Header)
        }
    }
}

pub struct GitHubSecretSignature(String);

impl GitHubSecretSignature {
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryIntoHeaderValue for GitHubSecretSignature {
    type Error = InvalidHeaderValue;

    fn try_into_value(self) -> Result<HeaderValue, Self::Error> {
        HeaderValue::try_from(self.0)
    }
}

impl Header for GitHubSecretSignature {
    fn name() -> HeaderName {
        "X-Hub-Signature-256".parse().unwrap()
    }

    fn parse<M: HttpMessage>(msg: &M) -> Result<Self, actix_web::error::ParseError> {
        let header = msg.headers().get(Self::name());
        if let Some(header) = header {
            Ok(GitHubSecretSignature(header.to_str().unwrap().to_string()))
        } else {
            Err(ParseError::Header)
        }
    }
}

fn verify_signature(secret: &str, sig_header: &str, body: &[u8]) -> Result<bool, &'static str> {
    let sig_parts: Vec<&str> = sig_header.split('=').collect();
    if sig_parts.len() != 2 || sig_parts[0] != "sha256" {
        return Err("invalid signature format");
    }

    let signature = hex::decode(sig_parts[1]).map_err(|_| "Invalid hex in signature")?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| "Bad key")?;
    mac.update(body);

    Ok(mac.verify_slice(&signature).is_ok())
}

#[post("/")]
async fn webhook(
    body: web::Bytes,
    event_type: web::Header<GitHubEventType>,
    sig_header: web::Header<GitHubSecretSignature>,
    db: web::Data<PgPool>,
    config: web::Data<Config>,
) -> HttpResponse {
    match verify_signature(&config.github_webhook_secret, &sig_header.0.0, &body) {
        Ok(true) => (),
        Ok(false) => return HttpResponse::Unauthorized().body("Invalid signature"),
        Err(e) => return HttpResponse::BadRequest().body(format!("Bad signature: {}", e)),
    }

    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(json) => json,
        Err(_) => return HttpResponse::BadRequest().body("Invalid JSON"),
    };

    let event_type = event_type.0.0;

    let result = sqlx::query!(
        r#"
        INSERT INTO github_webhooks (event_type, payload)
        VALUES ($1, $2)
        "#,
        event_type,
        payload,
    )
    .execute(db.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("Webhook received"),
        Err(e) => {
            eprintln!("DB error: {}", e);
            HttpResponse::InternalServerError().body("DB insert failed")
        }
    }
}

#[derive(Clone)]
struct Config {
    github_webhook_secret: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let db_url = std::env::var("WEBHOOK_RECEIVER_DSN").expect("WEBHOOK_RECEIVER_DSN must be set");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to DB");

    let config = Config {
        github_webhook_secret: std::env::var("WEBHOOK_SECRET").expect("WEBHOOK_SECRET must be set"),
    };

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("sql migration failed");

    let host = std::env::var("WEBHOOK_HOST").unwrap_or("0.0.0.0".to_string());
    let port: u16 = std::env::var("WEBHOOK_PORT")
        .unwrap_or("1235".to_string())
        .parse()
        .expect("Invalid port format");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(config.clone()))
            .service(webhook)
    })
    .bind((host, port))?
    .run()
    .await
}
