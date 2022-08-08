use clap::{Arg, Command};

use jwt_cli::{AppState, Error};

fn main() -> Result<(), Error> {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
    let m = Command::new("JWT Parser")
        .version(VERSION)
        .about(DESCRIPTION)
        .arg(Arg::new("in_file"))
        .after_help(
            "Longer explanation to appear after the options when \
                 displaying the help information from --help or -h",
        )
        .get_matches();

    let mut app_state = AppState::try_from(&m)?;
    let in_buff = app_state.read_stream()?;
    let token = std::str::from_utf8(&in_buff).expect("UTF failed!!");
    let result = jwt_cli::verify_jwt(token).map_err(|_| Error::VerifyFailed)?;
    app_state.write_stream(result.as_bytes())?;

    Ok(())
}
