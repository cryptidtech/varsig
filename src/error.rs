use thiserror::Error;

/// Errors created by this library
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Formatting error
    #[error(transparent)]
    Fmt(#[from] std::fmt::Error),

    /// A multibase conversion error
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    /// A multicodec decoding error
    #[error(transparent)]
    Multicodec(#[from] multicodec::Error),

    /// A multiutil error
    #[error(transparent)]
    Multiutil(#[from] multiutil::Error),

    /// Missing sigil 0x34
    #[error("Missing Varsig codec sigil")]
    MissingSigil,

    /// Invalid version
    #[error("Invalid Varsig version {0}")]
    InvalidVersion(u8),

    /// Unsupported signature algorithm
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
}
