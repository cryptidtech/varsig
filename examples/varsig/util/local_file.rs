use crate::util::{error::Error, keychain::Keychain, Result};
use directories::ProjectDirs;
use log::debug;
use serde_derive::{Deserialize, Serialize};
use ssh_key::{PrivateKey, PublicKey, Signature};
use std::{
    collections::HashMap,
    fs::{self, File},
    path::PathBuf,
};

const KEY_FILE: &'static str = "keyfile.cbor";

/// Keychain struct
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LocalFile {
    /// The path to the keyfile
    #[serde(skip)]
    pub path: PathBuf,
    /// Private keys in the keychain
    pub keys: HashMap<String, Vec<u8>>,
}

impl LocalFile {
    pub fn from_path(path: Option<PathBuf>) -> Result<Self> {
        let path = {
            match path {
                Some(path) => path,
                None => {
                    let pdirs =
                        ProjectDirs::from("tech", "cryptid", "varsig").ok_or(Error::NoHome)?;
                    let mut pb = pdirs.config_dir().to_path_buf();
                    pb.push(KEY_FILE);
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
                    debug!("creating default keyfile: {}", path.display());
                    let keyfile = LocalFile::default();
                    let f = File::create(&path)?;
                    serde_cbor::to_writer(f, &keyfile)?;
                }
            }
            Err(e) => {
                anyhow::bail!(Error::CannotInitializeConfig(format!("{}", e)));
            }
        }

        debug!("loading config: {}", path.display());

        let f = File::open(&path)?;
        let mut lf: LocalFile = serde_cbor::from_reader(f)?;
        lf.path = path;
        Ok(lf)
    }
}

/// Interface to the keychain
impl Keychain for LocalFile {
    fn list(&mut self) -> Result<Vec<PublicKey>> {
        let mut keys = Vec::with_capacity(self.keys.len());
        for (k, v) in self.keys.iter() {
            if let Ok(mut pk) = PublicKey::from_bytes(v.as_slice()) {
                pk.set_comment(k);
                keys.push(pk);
            }
        }
        Ok(keys)
    }

    fn get(&mut self, name: String) -> Result<PublicKey> {
        if let Some(key) = self.keys.get(&name) {
            if let Ok(mut pk) = PublicKey::from_bytes(key.as_slice()) {
                pk.set_comment(name);
                return Ok(pk.clone());
            }
        }
        anyhow::bail!(Error::NoKey(name))
    }

    fn add(&mut self, _key: &PrivateKey) -> Result<()> {
        Ok(())
    }

    fn sign(&mut self, _key: &PublicKey, _msg: &[u8]) -> Result<Signature> {
        anyhow::bail!(Error::NoHome)
    }
}
