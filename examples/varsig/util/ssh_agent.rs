use crate::util::{error::Error, keychain::Keychain, Result};
use ssh_agent_client_rs::Client;
use ssh_key::{PrivateKey, PublicKey, Signature};
use std::{env, ffi::OsString, path::PathBuf};

const SSH_AUTH_SOCK: &'static str = "SSH_AUTH_SOCK";

/// Keychain struct
pub struct SshAgent {
    /// The env var name used
    pub sshagent: Option<String>,

    /// The sshagent client
    pub client: Client,
}

impl SshAgent {
    /// Create an ssh agent client from the environment variable
    pub fn from_env(sshagent: Option<String>) -> Result<Self> {
        let sshagent = match sshagent {
            Some(sshagent) => sshagent,
            None => SSH_AUTH_SOCK.to_string(),
        };

        // get the unix socket path
        let p: OsString = env::var_os(&sshagent).ok_or(Error::InvalidEnv(sshagent.clone()))?;
        let path = PathBuf::from(p);

        // ssh agent connect
        let client = Client::connect(&path)?;

        // return
        Ok(Self {
            sshagent: Some(sshagent),
            client,
        })
    }
}

/// Interface to the keychain
impl Keychain for SshAgent {
    fn list(&mut self) -> Result<Vec<PublicKey>> {
        Ok(self.client.list_identities()?)
    }

    fn get(&mut self, name: String) -> Result<PublicKey> {
        let haystack = self.client.list_identities()?;
        for key in &haystack {
            if name == key.comment().to_string() {
                return Ok(key.clone());
            }
        }
        anyhow::bail!(Error::NoKey(name));
    }

    fn add(&mut self, key: &PrivateKey) -> Result<()> {
        match self.client.add_identity(key) {
            Ok(()) => Ok(()),
            Err(e) => anyhow::bail!(Error::SshAgent(e)),
        }
    }

    fn sign(&mut self, _key: &PublicKey, _msg: &[u8]) -> Result<Signature> {
        anyhow::bail!(Error::NoHome)
    }
}
