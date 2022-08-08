use clap::{Arg, Command};

use jwt_cli::{AppState, Error};

fn main() -> Result<(), Error> {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
    let m = Command::new("JWT Parser")
        .version(VERSION)
        .about(DESCRIPTION)
        .arg(
            Arg::with_name("key")
                .long("key")
                .value_name("SECRET")
                .help("Key for validating JWT signature")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("validate")
                .long("validate")
                .value_name("CLAIMS")
                .help("Header claims to validate")
                .required(false)
                .takes_value(true)
                .multiple_values(true)
        )
        .arg(
            Arg::with_name("leeway")
                .long("leeway")
                .value_name("SECONDS")
                .help("Add some leeway (in seconds) to the exp and nbf validation to account for clock skew")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("validate_exp")
                .long("validate-exp")
                .takes_value(false)
                .required(false)
                .help("Whether to validate the exp field")
        )
        .arg(
            Arg::with_name("validate_nbf")
                .long("validate-nbf")
                .takes_value(false)
                .required(false)
                .help("Whether to validate the nbf field")
        )
        .arg(
            Arg::with_name("aud")
                .long("aud")
                .value_name("AUDIENCE")
                .help("Check that the aud field is a member of the audience provided")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("iss")
                .long("iss")
                .value_name("ISSUER")
                .help("Check that the iss field matches one of the issuers provided")
                .required(false)
                .takes_value(true)
                .multiple_values(true)
        )
        .arg(
            Arg::with_name("sub")
                .long("sub")
                .value_name("SUBJECT")
                .help("Check that the sub field matches the subject provided")
                .required(false)
                .takes_value(true)
        )
        .arg(
            Arg::with_name("alg")
                .long("alg")
                .value_name("ALGORITHM")
                .help("Check that the alg field matches one of the algorithms provided")
                .required(false)
                .takes_value(true)
        )
        .after_help("CLI wrapper around RUST jsonwebtoken")
        .get_matches();

    let mut app_state = AppState::try_from(&m)?;
    let in_buff = app_state.read_stream()?;
    let token = std::str::from_utf8(&in_buff).expect("UTF failed!!");
    let result = jwt_cli::verify_jwt(token, &app_state).map_err(|_| Error::VerifyFailed)?;
    app_state.write_stream(result.as_bytes())?;

    Ok(())
}
