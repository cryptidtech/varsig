use crate::util::{error::Error, Result};
use serde::{Deserialize, Serialize};
use ssh_key::{PrivateKey, PublicKey, Signature};
use std::path::PathBuf;

/// Interface to the keychain
pub trait Keychain {
    /// list the available keys
    fn list(&mut self) -> Result<Vec<PublicKey>>;

    /// get a key by name
    fn get(&mut self, name: String) -> Result<PublicKey>;

    /// add a key
    fn add(&mut self, key: &PrivateKey) -> Result<()>;

    /// sign a message with a key
    fn sign(&mut self, key: &PublicKey, msg: &[u8]) -> Result<Signature>;
}

/// Keychain config
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeychainConfig {
    /// Default key name
    pub default_key: Option<String>,

    /// Optional file for storing keys if storage is "file"
    pub keyfile: Option<PathBuf>,

    /// Optional env var if storage is "sshagent"
    pub sshagent: Option<String>,

    /// Keychain
    pub storage: Backend,
}

impl KeychainConfig {
    /// Creates a new keychain config
    pub fn new(keyfile: Option<PathBuf>, sshagent: bool, sshagentenv: String) -> Result<Self> {
        let storage = {
            if sshagent {
                Backend::SshAgent
            } else {
                Backend::LocalFile
            }
        };

        Ok(Self {
            default_key: None,
            keyfile,
            sshagent: Some(sshagentenv),
            storage,
        })
    }
}

/// The keychain backend
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum Backend {
    /// The keychain is a local file
    LocalFile,

    /// The keychain is an ssh agent
    SshAgent,
}

impl TryFrom<String> for Backend {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "file" => Ok(Backend::LocalFile),
            "ssh-agent" => Ok(Backend::SshAgent),
            _ => anyhow::bail!(Error::Deserialization(format!(
                "invalid Backend type '{}'",
                &s
            ))),
        }
    }
}

impl Into<String> for Backend {
    fn into(self) -> String {
        match self {
            Backend::LocalFile => "file".to_string(),
            Backend::SshAgent => "ssh-agent".to_string(),
        }
    }
}
