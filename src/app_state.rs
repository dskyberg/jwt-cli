use clap::ArgMatches;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AppState {
    #[zeroize(skip)]
    pub in_stream: Box<dyn Read>,
    #[zeroize(skip)]
    pub out_stream: Box<dyn Write>,
    #[zeroize(skip)]
    pub validation_claims: HashSet<String>,
    #[zeroize(skip)]
    pub validate_exp: bool,
    #[zeroize(skip)]
    pub leeway: Option<u64>,
    #[zeroize(skip)]
    pub validate_nbf: bool,
    #[zeroize(skip)]
    pub aud: Option<String>,
    #[zeroize(skip)]
    pub iss: Option<HashSet<String>>,
    #[zeroize(skip)]
    pub sub: Option<String>,
    #[zeroize(skip)]
    pub alg: Option<HashSet<String>>,
    pub key: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// Create an AppState with default settings
    pub fn new() -> Self {
        Self {
            in_stream: Box::new(std::io::stdin()),
            out_stream: Box::new(std::io::stdout()),
            validation_claims: HashSet::new(),
            key: None,
            leeway: None,
            validate_exp: false,
            validate_nbf: false,
            aud: None,
            iss: None,
            sub: None,
            alg: None,
        }
    }

    pub fn read_stream(&mut self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::<u8>::new();
        let _cnt = self
            .in_stream
            .read_to_end(&mut bytes)
            .map_err(Error::IOEReadError);
        Ok(bytes)
    }

    pub fn write_stream(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let _ = self
            .out_stream
            .write_all(bytes)
            .map_err(Error::IOEWriteError);
        Ok(())
    }
}

impl TryFrom<&ArgMatches> for AppState {
    type Error = Error;
    fn try_from(matches: &ArgMatches) -> Result<Self, Self::Error> {
        let mut app_state = AppState::new();

        app_state.key = process_key(matches.value_of("key"))?;

        if let Some(vals) = matches.values_of("validate") {
            app_state.validation_claims = vals.map(|s| s.to_owned()).collect::<HashSet<String>>();
        }

        if let Some(leeway) = matches.value_of("leeway") {
            app_state.leeway = leeway.parse::<u64>().ok();
        }
        if matches.contains_id("validate_exp") {
            app_state.validate_exp = true;
        }
        if matches.contains_id("validate_nbf") {
            app_state.validate_nbf = true;
        }
        if let Some(aud) = matches.value_of("aud") {
            app_state.aud = Some(aud.to_owned())
        }
        if let Some(sub) = matches.value_of("sub") {
            app_state.sub = Some(sub.to_owned())
        }

        if let Some(vals) = matches.values_of("iss") {
            app_state.iss = Some(vals.map(|s| s.to_owned()).collect::<HashSet<String>>());
        }

        if let Some(vals) = matches.values_of("alg") {
            app_state.alg = Some(vals.map(|s| s.to_owned()).collect::<HashSet<String>>());
        }

        Ok(app_state)
    }
}

/// Read a password from a local file
///
/// If the arg to `process_password` is `FILE:<filename>` this method is called
/// to retrieve the password from `<filename>`.
fn read_key_from_file(filename: &str) -> Result<Option<String>, Error> {
    let mut file = File::open(filename).map_err(Error::ReadFileError)?;
    let mut buf = String::new();
    let _cnt = file.read_to_string(&mut buf).map_err(Error::IOEReadError);

    Ok(Some(buf))
}

/// Handle password input options similar to openssl
///
/// The password may be of 2 forms:
/// 1. "pass:<value>": The value after the colon represents the actual password
/// 2. "file:<value>": The value after the colon represents a file that contains the password
///
fn process_key(input: Option<&str>) -> Result<Option<String>, Error> {
    match input {
        None => Ok(None),
        Some(s) => {
            let parts = s.split(':').collect::<Vec<&str>>();
            // If there's not enough args, bail
            if parts.len() < 2 {
                return Err(Error::BadPasswordArg);
            }
            let mode = parts[0].to_owned();
            let target;

            // If the password contains a ':', join them
            if parts.len() > 2 {
                match parts.split_first() {
                    Some((_, remainder)) => {
                        target = remainder.join("");
                    }
                    _ => return Err(Error::BadPasswordArg),
                }
            } else {
                target = parts[1].to_owned();
            }

            match mode.to_lowercase().as_str() {
                "key" => Ok(Some(target)),
                "file" => read_key_from_file(&target),
                _ => Err(Error::BadPasswordArg),
            }
        }
    }
}
