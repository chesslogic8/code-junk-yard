use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use argon2::{Argon2, Params};
use chacha20poly1305::{XChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::Aead;

use chacha20poly1305::XNonce;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rand::RngCore;
use rpassword;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"PICORSv5";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Header format:
/// MAGIC (8)
/// salt (16)
/// nonce (24)
/// mem_cost (u32)
/// time_cost (u32)
/// lanes (u32)

#[derive(Parser, Debug)]
#[command(author, version, about = "picors – secure Picocrypt-style CLI")]
struct Args {
    #[arg(required = true)]
    items: Vec<PathBuf>,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.items.len() != 1 {
        eprintln!("Only one file at a time.");
        std::process::exit(1);
    }

    let path = &args.items[0];
    let is_encrypt = !path.extension().map_or(false, |e| e == "pcv");

    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let total_bytes = metadata.len();

    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    if is_encrypt {
        encrypt_file(&mut file, path, &pb)?;
    } else {
        decrypt_file(&mut file, path, &pb)?;
    }

    pb.finish_with_message("Done!");
    Ok(())
}

fn encrypt_file(
    input: &mut File,
    path: &PathBuf,
    pb: &ProgressBar,
) -> io::Result<()> {
    let mut plaintext = Vec::new();
    input.read_to_end(&mut plaintext)?;
    pb.set_length(plaintext.len() as u64);

    // --- password ---
    let mut password = rpassword::prompt_password("Enter password: ").unwrap();
    let confirm = rpassword::prompt_password("Confirm password: ").unwrap();

    if password != confirm {
        eprintln!("Passwords do not match.");
        std::process::exit(1);
    }

    // --- KDF params (reasonable defaults) ---
    let mem_cost = 19456;
    let time_cost = 2;
    let lanes = 1;

    let params = Params::new(mem_cost, time_cost, lanes, Some(KEY_LEN)).unwrap();

    // --- salt + nonce ---
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // --- derive key ---
    let mut key = [0u8; KEY_LEN];
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2.hash_password_into(password.as_bytes(), &salt, &mut key).unwrap();

    // --- cipher ---
    let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = XNonce::from_slice(&nonce_bytes);

    // --- header ---
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_bytes);
    header.extend_from_slice(&(mem_cost as u32).to_le_bytes());
    header.extend_from_slice(&(time_cost as u32).to_le_bytes());
    header.extend_from_slice(&(lanes as u32).to_le_bytes());

    // --- encrypt (header = AAD) ---
    let ciphertext = cipher.encrypt(nonce, chacha20poly1305::aead::Payload {
        msg: &plaintext,
        aad: &header,
    }).map_err(|_| io::Error::new(io::ErrorKind::Other, "encryption failed"))?;

    // --- output ---
    let mut output_path = path.clone();
    output_path.set_extension("pcv");
    let mut output = File::create(&output_path)?;

    output.write_all(&header)?;
    output.write_all(&ciphertext)?;

    println!("\nEncrypted → {}", output_path.display());

    // --- cleanup ---
    password.zeroize();
    key.zeroize();
    plaintext.zeroize();

    Ok(())
}

fn decrypt_file(
    input: &mut File,
    path: &PathBuf,
    pb: &ProgressBar,
) -> io::Result<()> {
    // --- read header ---
    let mut header = vec![0u8; 8 + SALT_LEN + NONCE_LEN + 12];
    input.read_exact(&mut header)?;

    if &header[0..8] != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid file"));
    }

    let salt = &header[8..8 + SALT_LEN];
    let nonce_bytes = &header[8 + SALT_LEN..8 + SALT_LEN + NONCE_LEN];

    let mem_cost = u32::from_le_bytes(header[8 + SALT_LEN + NONCE_LEN..][0..4].try_into().unwrap());
    let time_cost = u32::from_le_bytes(header[8 + SALT_LEN + NONCE_LEN..][4..8].try_into().unwrap());
    let lanes = u32::from_le_bytes(header[8 + SALT_LEN + NONCE_LEN..][8..12].try_into().unwrap());

    let params = Params::new(mem_cost, time_cost, lanes, Some(KEY_LEN)).unwrap();

    // --- read ciphertext ---
    let mut ciphertext = Vec::new();
    input.read_to_end(&mut ciphertext)?;
    pb.set_length(ciphertext.len() as u64);

    // --- password ---
    let mut password = rpassword::prompt_password("Enter password: ").unwrap();

    // --- derive key ---
    let mut key = [0u8; KEY_LEN];
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2.hash_password_into(password.as_bytes(), salt, &mut key).unwrap();

    let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = XNonce::from_slice(nonce_bytes);

    // --- decrypt ---
    let plaintext = cipher.decrypt(nonce, chacha20poly1305::aead::Payload {
        msg: &ciphertext,
        aad: &header,
    }).map_err(|_| io::Error::new(io::ErrorKind::Other, "wrong password or corrupted file"))?;

    // --- output ---
    let mut output_path = path.clone();
    output_path.set_extension("");
    let mut output = File::create(&output_path)?;
    output.write_all(&plaintext)?;

    println!("\nDecrypted → {}", output_path.display());

    // --- cleanup ---
    password.zeroize();
    key.zeroize();

    Ok(())
}