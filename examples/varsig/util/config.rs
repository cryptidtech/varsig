use crate::util::{
    error::Error,
    keychain::{Backend, Keychain, KeychainConfig},
    local_file::LocalFile,
    ssh_agent::SshAgent,
    Result,
};
use directories::ProjectDirs;
use log::debug;
use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;
use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

const CONFIG_FILE: &'static str = "config.toml";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Path to the confid file
    #[serde(skip)]
    path: PathBuf,

    /// Keychain config
    keychain: KeychainConfig,
}

impl Config {
    pub fn from_path(
        path: Option<PathBuf>,
        keyfile: Option<PathBuf>,
        sshagent: bool,
        sshagentenv: String,
    ) -> Result<Self> {
        let path = {
            match path {
                Some(path) => path,
                None => {
                    let pdirs =
                        ProjectDirs::from("tech", "cryptid", "varsig").ok_or(Error::NoHome)?;
                    let mut pb = pdirs.config_dir().to_path_buf();
                    pb.push(CONFIG_FILE);
                    pb
                }
            }
        };

        // create the parent directories if needed
        let prefix = path.parent().ok_or(Error::NoHome)?;
        match prefix.try_exists() {
            Ok(result) => {
                if !result {
                    debug!("creating: {}", prefix.display());
                    fs::create_dir_all(prefix)?;
                }
            }
            Err(e) => {
                anyhow::bail!(Error::CannotInitializeConfig(format!("{}", e)));
            }
        }

        // create a default config if needed
        match path.try_exists() {
            Ok(result) => {
                if !result {
                    debug!("creating default config: {}", path.display());
                    let keychain = KeychainConfig::new(keyfile, sshagent, sshagentenv)?;
                    let config = Config {
                        path: path.clone(),
                        keychain,
                    };
                    let toml = toml::to_string(&config)?;
                    let mut f = File::create(&path)?;
                    f.write_all(toml.as_bytes())?;
                }
            }
            Err(e) => {
                anyhow::bail!(Error::CannotInitializeConfig(format!("{}", e)));
            }
        }

        debug!("loading config: {}", path.display());

        let toml = fs::read_to_string(&path)?;
        let mut config: Self = toml::from_str(&toml)?;
        config.path = path.clone();
        Ok(config)
    }

    /// Loads the actual keychain
    pub fn keychain(&self) -> Result<Box<dyn Keychain>> {
        match self.keychain.storage {
            Backend::LocalFile => {
                let keyfile = LocalFile::from_path(self.keychain.keyfile.clone())?;
                Ok(Box::new(keyfile))
            }
            Backend::SshAgent => {
                let sshagent = SshAgent::from_env(self.keychain.sshagent.clone())?;
                Ok(Box::new(sshagent))
            }
        }
    }

    /// set default key
    pub fn set_default_key(&mut self, name: Option<String>) -> Result<()> {
        // see if there is a matching key and set it as default
        if let Some(name) = name {
            let _key = self.keychain()?.get(name.clone())?;
            self.keychain.default_key = Some(name);
        } else {
            self.keychain.default_key = None;
        }
        self.save()?;
        Ok(())
    }

    /// get default key
    pub fn default_key(&self) -> Result<PublicKey> {
        if let Some(name) = &self.keychain.default_key {
            let key = self.keychain()?.get(name.clone())?;
            Ok(key)
        } else {
            anyhow::bail!(Error::NoKey(String::default()))
        }
    }

    /// Saves the config to disk
    pub fn save(&self) -> Result<()> {
        let toml = toml::to_string(&self)?;
        let mut f = File::create(&self.path)?;
        f.write_all(toml.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toml;

    /*
    #[test]
    fn test_roundtrip() {
        let c1 = Config {
            keychain: KeychainConfig {
                default_key: None,
                keyfile: Some("./keyfile".to_string()),
                envvar: None,
                storage: Backend::LocalFile,
            },
        };
        let s = toml::to_string(&c1).unwrap();
        println!("{}", &s);
        let c2 = toml::from_str(&s).unwrap();
        println!("{:?}", c2);
        assert_eq!(c1, c2);
    }
    */
}
