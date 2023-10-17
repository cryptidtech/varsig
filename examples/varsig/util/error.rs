use thiserror::Error;

/// Errors for varsig app
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Formatting error
    #[error("fmt error {0}")]
    Fmt(#[from] std::fmt::Error),

    /// A generic error message
    #[error("General varsig error: {0}")]
    General(&'static str),

    /// A varsig create error
    #[error("Varsig error: {0}")]
    Varsig(#[from] varsig::error::Error),

    /// A log crate error
    #[error("Log error: {0}")]
    Log(#[from] log::SetLoggerError),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// No valid application config path found
    #[error("No valid config path found")]
    NoHome,

    /// Cannot initialize config file
    #[error("Cannot initialize config file: {0}")]
    CannotInitializeConfig(String),

    /// Ssh Agent error
    #[error("Ssh agent error: {0}")]
    SshAgent(#[from] ssh_agent_client_rs::Error),

    /// Invalid environment variable key
    #[error("Invalid environment variable key: {0}")]
    InvalidEnv(String),

    /// No key by that name
    #[error("No key known by: {0}")]
    NoKey(String),
}
