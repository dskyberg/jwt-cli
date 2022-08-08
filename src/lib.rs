use jsonwebtoken::{decode, decode_header, DecodingKey, Header, Validation};
use serde_json::Value;
use std::collections::HashMap;
use x509_parser::prelude::*;

pub use app_state::*;
pub use errors::*;

pub mod app_state;
pub mod errors;

fn build_validation(
    header: &Header,
    app_state: &AppState,
) -> Result<Validation, Box<dyn std::error::Error>> {
    let alg = header.alg;
    let mut validation = Validation::new(alg);
    validation.validate_exp = app_state.validate_exp;
    validation.validate_nbf = app_state.validate_nbf;

    validation.required_spec_claims = app_state.validation_claims.clone();

    Ok(validation)
}

fn verify_x5c(
    x5c_list: &Vec<Vec<u8>>,
    token: &str,
    validation: &Validation,
) -> Result<String, Box<dyn std::error::Error>> {
    // Since order isn't guaranteed in the cert chain, try them all
    // until one succeeds.
    for der in x5c_list {
        // Parse the X.509
        let (_, cert) = X509Certificate::from_der(der)?;
        // Get the public key in SPKI format
        let public_key_bytes = cert.subject_pki.subject_public_key.as_ref();
        // Create a key from the SPKI
        let key = DecodingKey::from_rsa_der(public_key_bytes);

        // Decode the JWT.
        let result = decode::<HashMap<String, Value>>(token, &key, validation);

        if let Ok(token_data) = result {
            let blob = token_data.claims;
            let json = serde_json::to_string(&blob)?;
            return Ok(json);
        }
    }
    Err(errors::Error::VerifyFailed.into())
}

pub fn verify_jwt(token: &str, app_state: &AppState) -> Result<String, Box<dyn std::error::Error>> {
    let header = decode_header(token)?;
    let validation = build_validation(&header, app_state)?;

    let x5c_list = header.x5c_der()?;
    if let Some(x5c) = x5c_list {
        return verify_x5c(&x5c, token, &validation);
    }

    Err(errors::Error::VerifyFailed.into())
}
