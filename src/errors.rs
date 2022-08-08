use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Bad IO")]
    BadIO(#[from] std::io::Error),
    #[error("Verify failed")]
    VerifyFailed,
    #[error("JSON Serialize Failed")]
    JSONFailed,
}
