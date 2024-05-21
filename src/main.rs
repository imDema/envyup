use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;

const EXTENSION: &str = "cryptenv";
const VERSION_PREFIX: &str = "[envyup-1-0]";

#[derive(Debug, Parser)]
struct Options {
    /// Print the content of the files
    #[clap(short, long)]
    print: bool,

    /// Dry-Run, do not spawn a shell or write the encrypted file
    #[clap(short('n'), long)]
    dry_run: bool,

    /// path to the env file
    path: PathBuf,
}

fn is_encrypted(path: &Path) -> bool {
    path.extension()
        .is_some_and(|p| p.eq_ignore_ascii_case("cryptenv"))
}

fn decrypt(path: &Path, key: &str) -> Result<String, EnvupError> {
    let s = std::fs::read_to_string(path)?;

    let Some(s) = s.strip_prefix(VERSION_PREFIX) else {
        panic!("File was not enccrypted using {VERSION_PREFIX}");
    };

    let Ok(ciphertext) = B64.decode(s) else {
        panic!("Invalid base64");
    };

    let plaintext = crypto::decrypt(&ciphertext, key)?;

    let output = String::from_utf8(plaintext).unwrap();
    Ok(output)
}

fn encrypt(path: &Path, key: &str) -> Result<String, EnvupError> {
    let s = std::fs::read_to_string(path)?;

    let ciphertext = crypto::encrypt(s.as_bytes(), key)?;
    let b64 = B64.encode(ciphertext);
    let mut output = String::with_capacity(b64.len() + VERSION_PREFIX.len());

    output.push_str(&VERSION_PREFIX);
    output.push_str(&b64);

    Ok(output)
}

fn parse_env(s: &str) -> Result<HashMap<String, String>, EnvupError> {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            l.split_once('=')
                .ok_or_else(|| {
                    EnvupError::InvalidFormat(format!("wrong format, expected `=` in line `{l}`"))
                })
                .map(|t| (t.0.trim().to_owned(), t.1.trim().to_owned()))
        })
        .collect()
}

fn en(opts: Options, password: String) -> Result<(), EnvupError> {
    let content = encrypt(&opts.path, &password)?;
    if opts.print {
        println!("{content}");
    }
    if opts.dry_run {
        return Ok(());
    }

    let mut output_file = File::create(opts.path.with_extension(EXTENSION))?;
    output_file.write_all(content.as_bytes())?;

    Ok(())
}

fn de(opts: Options, password: String) -> Result<(), EnvupError> {
    let content = decrypt(&opts.path, &password)?;
    if opts.print {
        println!("{content}");
    }
    if opts.dry_run {
        return Ok(());
    }

    let map = parse_env(&content)?;

    let shell = std::env::var("SHELL").expect("No SHELL variable in environment!");
    let mut cmd = std::process::Command::new(shell);
    for (k, v) in map {
        cmd.env(k, v);
    }
    eprintln!("Starting shell with new variables.");

    let error = cmd.exec();
    panic!("{error}");
}

fn main() -> eyre::Result<()> {
    color_eyre::install().ok();
    let opts = Options::parse();

    println!("password: ");
    let password = rpassword::read_password().unwrap();
    let result = if is_encrypted(&opts.path) {
        de(opts, password)
    } else {
        println!("confirm password to encrypt `{}`", opts.path.display());
        if rpassword::read_password().unwrap() != password {
            eprintln!("password mismatch!");
            std::process::exit(33);
        }
        en(opts, password)
    };

    if let Err(e) = result {
        println!("ERROR: {e}");
        std::process::exit(1);
    }

    Ok(())
}

mod crypto {
    use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, KeyInit};
    use argon2::Argon2;
    use rand::{rngs::OsRng, Rng};

    use crate::EnvupError;

    const SALT_LEN: usize = 8;
    const NONCE_LEN: usize = 96 / 8;

    pub fn encrypt(data: &[u8], key: &str) -> Result<Vec<u8>, EnvupError> {
        let mut output = Vec::with_capacity(data.len() + SALT_LEN + NONCE_LEN + 16);

        let mut salt = [0; 8];
        OsRng.fill(&mut salt);

        let mut crypt_key = [0u8; 32];
        Argon2::default().hash_password_into(key.as_bytes(), &salt, &mut crypt_key)?;

        let cipher = Aes256Gcm::new(crypt_key.as_ref().try_into().unwrap());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, data)?;

        assert_eq!(NONCE_LEN, nonce.len());

        output.extend_from_slice(&salt);
        output.extend_from_slice(nonce.as_slice());
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub fn decrypt(data: &[u8], key: &str) -> Result<Vec<u8>, EnvupError> {
        let (salt, data) = data.split_at(SALT_LEN);
        let (nonce, ciphertext) = data.split_at(NONCE_LEN);

        let mut crypt_key = [0u8; 32];
        Argon2::default().hash_password_into(key.as_bytes(), &salt, &mut crypt_key)?;

        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let cipher = Aes256Gcm::new(crypt_key.as_ref().try_into().unwrap());
        let plaintext = cipher
            .decrypt(&nonce.try_into().unwrap(), ciphertext)
            .map_err(|_| EnvupError::InvalidKey)?;

        Ok(plaintext)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnvupError {
    #[error("Input/Output error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Cryptography error: AEAD Error")]
    CryptoAes(aes_gcm::Error),
    #[error("Cryptography error: {0}")]
    CryptoArgon2(argon2::Error),
}

impl From<aes_gcm::Error> for EnvupError {
    fn from(value: aes_gcm::Error) -> Self {
        Self::CryptoAes(value.to_owned())
    }
}

impl From<argon2::Error> for EnvupError {
    fn from(value: argon2::Error) -> Self {
        Self::CryptoArgon2(value.to_owned())
    }
}
