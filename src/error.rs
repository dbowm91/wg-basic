use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("unsupported platform or capability: {0}")]
    UnsupportedPlatform(&'static str),
    #[error("I/O or runtime failure: {0}")]
    Runtime(#[from] std::io::Error),
    #[error("protocol failure: {0}")]
    Protocol(String),
    #[error("kernel/backend failure: {0}")]
    Backend(String),
    #[error("resource ownership conflict: {0}")]
    Conflict(String),
}
