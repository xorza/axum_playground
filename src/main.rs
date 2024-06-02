use std::fmt::Debug;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;
use axum::routing::get;
use jsonwebtoken::{decode, DecodingKey, encode, EncodingKey, Header, TokenData, Validation};
use once_cell::unsync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

const SECRET: &[u8] = b"some-secret";
const ENCODING_KEY: Lazy<EncodingKey> = Lazy::new(|| EncodingKey::from_secret(SECRET));
const DECODING_KEY: Lazy<DecodingKey> = Lazy::new(|| DecodingKey::from_secret(SECRET));

#[derive(Serialize, Deserialize, Clone)]
struct Claims {
    name: String,
    exp: u64,
}

fn gen_token() -> String {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60 * 60;

    let claims = Claims {
        name: "user1".to_string(),
        exp: expiration,
    };

    encode(&Header::default(), &claims, &ENCODING_KEY).unwrap()
}

fn decode_token(token: &str) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
    decode::<Claims>(token, &DECODING_KEY, &Validation::default())
}

async fn handler<B: Debug>(request: Request<B>) -> String {
    let claims = request.extensions().get::<Claims>().unwrap();

    format!("Hello, {}!", claims.name)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let token = gen_token();
    println!("Generated Token: {}", token);

    let app = Router::new()
        .route("/", get(handler))
        .layer(tower::ServiceBuilder::new().layer(axum::middleware::from_fn(auth)));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let api_listener = TcpListener::bind(addr).await?;
    println!("listening on http://{}/", addr);

    axum::serve(api_listener, app.into_make_service()).await?;

    Ok(())
}

async fn auth(mut req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let token_data = req
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|auth_header| {
            if auth_header.starts_with("Bearer ") {
                Some(&auth_header[7..])
            } else {
                None
            }
        })
        .and_then(|token| decode_token(token).ok())
        .and_then(|token_data| {
            if token_data.claims.exp
                > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
            {
                Some(token_data.claims)
            } else {
                None
            }
        });

    if let Some(claims) = token_data {
        req.extensions_mut().insert(claims);
        let resp = next.run(req).await;

        Ok(resp)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
