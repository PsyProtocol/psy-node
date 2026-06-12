use chrono::{Duration, Utc};
#[cfg(not(target_arch = "wasm32"))]
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
pub use tracing::Level;

pub const JWT_COMPANY: &str = "PsyProtocol";
pub const JWT_SUBJECT: &str = "psylang-rust";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub company: String,
    pub sub: String,
    pub realm_id: u64,
    pub exp: i64,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn generate_jwt_token(secret_key: &str, realm_id: u64) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now() + Duration::seconds(604800);
    let claims = Claims {
        company: JWT_COMPANY.to_string(),
        sub: JWT_SUBJECT.to_string(),
        realm_id: realm_id,
        exp: expiration.timestamp(),
    };

    let header = Header::default();
    let encoding_key = EncodingKey::from_secret(secret_key.as_bytes());

    encode(&header, &claims, &encoding_key)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn decrypt_jwt_token(secret_key: &str, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(secret_key.as_bytes());
    let validation = Validation::default();

    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

mod tests {
    #[test]
    fn test_jwt_token() {
        let secret_key = "psy-jwt-sk-test";
        let realm_id = 1;
        let token = super::generate_jwt_token(secret_key, realm_id).unwrap();
        let claims = super::decrypt_jwt_token(secret_key, &token).unwrap();
        assert_eq!(claims.company, "PsyProtocol");
        assert_eq!(claims.sub, "psylang-rust");
        assert_eq!(claims.realm_id, realm_id);
    }
}
