#![allow(dead_code)]
use crate::util::{config::Config, Result};
use anyhow::*;
use rand::rngs::OsRng;
use ssh_key::{
    private::{Ed25519Keypair, KeypairData},
    PrivateKey,
};
use std::path::PathBuf;
use structopt::StructOpt;

mod util;
//use varsig::prelude::*;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "varsig",
    version = "0.2",
    author = "Dave Huseby <dwh@linuxprogrammer.org>",
    about = "Varsig Instpector"
)]
struct Opt {
    /// Silence all output
    #[structopt(short = "q", long = "quiet")]
    quiet: bool,

    /// Verbosity (-v, -vv, -vvv)
    #[structopt(short = "v", parse(from_occurrences))]
    verbosity: usize,

    /// Config file to use
    #[structopt(long = "config", short = "c", parse(from_os_str))]
    config: Option<PathBuf>,

    /// Keychain file
    #[structopt(long = "keychain", short = "k", parse(from_os_str))]
    keyfile: Option<PathBuf>,

    /// Use an ssh-agent?
    #[structopt(long = "ssh-agent", short = "s")]
    sshagent: bool,

    /// Ssh-agent env var
    #[structopt(long = "ssh-agent-env", default_value = "SSH_AUTH_SOCK")]
    sshagentenv: String,

    /// Subcommand
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    /// List available keys
    #[structopt(name = "list")]
    List,

    /// Generate a new key
    #[structopt(name = "generate")]
    Generate {
        /// the name of the new key pair
        name: String,
    },

    /// Set the default key
    #[structopt(name = "default")]
    Default {
        /// the name of the key to make default
        name: Option<String>,
    },
    /*
    /// Remove a key
    #[structopt(name = "remove")]
    Remove {
        /// the name of the key to remove
        name: String,
    },
    */
}

fn main() -> Result<()> {
    // parse the cli options
    let opt = Opt::from_args();

    // set up the logger
    stderrlog::new()
        .quiet(opt.quiet)
        .verbosity(opt.verbosity)
        .init()
        .map_err(|e| util::error::Error::Log(e))?;

    match opt.cmd {
        Command::List => {
            // load the config
            let config = Config::from_path(opt.config, opt.keyfile, opt.sshagent, opt.sshagentenv)?;
            let mut keychain = config.keychain()?;
            let keys = keychain.list()?;
            for key in &keys {
                println!("{}: {}", key.comment(), key.fingerprint(Default::default()));
            }
        }
        Command::Generate { name } => {
            let mut csprng = OsRng;
            let kp = Ed25519Keypair::random(&mut csprng);
            let pk = PrivateKey::new(KeypairData::from(kp), name)?;
            let config = Config::from_path(opt.config, opt.keyfile, opt.sshagent, opt.sshagentenv)?;
            let mut keychain = config.keychain()?;
            keychain.add(&pk)?;
        }
        Command::Default { name } => {
            let mut config =
                Config::from_path(opt.config, opt.keyfile, opt.sshagent, opt.sshagentenv)?;
            config.set_default_key(name)?;
            let key = config.default_key()?;
            println!("{}: {}", key.comment(), key.fingerprint(Default::default()));
        } /*
          Command::Remove { name } => {
              let mut config =
                  Config::from_path(opt.config, opt.keyfile, opt.sshagent, opt.sshagentenv)?;
              let mut keychain = config.keychain()?;
              let key = config.default_key()?;
              if key.comment().to_string() == name {
                  config.set_default_key(None)?;
                  keychain.
              }
          }
          */
    }

    Ok(())
}
