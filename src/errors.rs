use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("File input error")]
    ReadFileError(std::io::Error),

    #[error("File output error")]
    WriteFileError(std::io::Error),

    #[error("Stream read error")]
    IOEReadError(std::io::Error),

    #[error("Stream write error")]
    IOEWriteError(std::io::Error),

    #[error("Verify failed")]
    VerifyFailed,

    #[error("JSON Serialize Failed")]
    JSONFailed,

    #[error("Bad password arg")]
    BadPasswordArg,

    #[error("This feature is not yet supported: {0}")]
    NotSupported(String),
}
