/// Config
pub mod config;

// Error
pub mod error;

/// Keychain interface
pub mod keychain;

/// Local file keychain
pub mod local_file;

/// SSH Agent keychain
pub mod ssh_agent;

pub type Result<T> = anyhow::Result<T>;

/// ...and in the darkness bind them
pub mod prelude {
    use super::*;

    pub use super::Result;
    pub use config::*;
    pub use error::*;
    pub use keychain::*;
    pub use local_file::*;
    pub use ssh_agent::*;
}
