use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use argon2::{Argon2, Params};
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, AeadInPlace, XNonce};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rand::RngCore;
use zeroize::Zeroize;
use rpassword;

const MAGIC: &[u8; 8] = b"PICORSv1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

#[derive(Parser, Debug)]
#[command(author, version, about = "picors – Picocrypt CLI in Rust")]
struct Args {
    /// Input files (single file only in v0.1)
    #[arg(required = true)]
    items: Vec<PathBuf>,

    /// (encryption) use paranoid mode (Serpent cascade) – NYI in v0.1
    #[arg(short = 'p', long)]
    paranoid: bool,

    /// (encryption) encode with Reed-Solomon – NYI in v0.1
    #[arg(short = 'r', long)]
    reed_solomon: bool,

    /// (decryption) attempt to fix corruption – NYI in v0.1
    #[arg(short = 'f', long)]
    fix: bool,

    /// (decryption) keep output even if corrupted – NYI in v0.1
    #[arg(short = 'k', long)]
    keep: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.items.len() != 1 {
        eprintln!("v0.1 supports only one file at a time.");
        std::process::exit(1);
    }

    let path = &args.items[0];
    let is_encrypt = !path.extension().map_or(false, |e| e == "pcv");

    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let total_bytes = metadata.len();

    let pb = ProgressBar::new(total_bytes);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    if is_encrypt {
        encrypt_file(&mut file, path, &pb, args.paranoid, args.reed_solomon)?;
    } else {
        decrypt_file(&mut file, path, &pb, args.fix, args.keep)?;
    }

    pb.finish_with_message("Done!");
    Ok(())
}

fn encrypt_file(
    input: &mut File,
    path: &PathBuf,
    pb: &ProgressBar,
    _paranoid: bool,     // NYI
    _reed_solomon: bool, // NYI
) -> io::Result<()> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let mut password = rpassword::prompt_password("Enter password: ").unwrap();
    let mut key = argon2_key(&password, &salt);
    password.zeroize();

    let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    key.zeroize();   // securely wipe key after cipher is created

    let mut output_path = path.clone();
    output_path.set_extension("pcv");
    let mut output = File::create(&output_path)?;

    // Write header
    output.write_all(MAGIC)?;
    output.write_all(&salt)?;
    output.write_all(&nonce_bytes)?;

    let mut buffer = vec![0u8; 64 * 1024];
    let aad: &[u8] = b"";

    let nonce = XNonce::from_slice(&nonce_bytes);

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        let mut chunk = buffer[..n].to_vec();
        cipher.encrypt_in_place(nonce, aad, &mut chunk)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encryption failed: {}", e)))?;

        output.write_all(&chunk)?;
        pb.inc(n as u64);
    }

    println!("\nEncrypted → {}", output_path.display());
    Ok(())
}

fn decrypt_file(
    input: &mut File,
    path: &PathBuf,
    pb: &ProgressBar,
    _fix: bool,   // NYI
    _keep: bool,  // NYI
) -> io::Result<()> {
    let mut header = [0u8; 8 + SALT_LEN + NONCE_LEN];
    input.read_exact(&mut header)?;

    if &header[0..8] != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Not a picors/pcv file"));
    }

    let salt = &header[8..8 + SALT_LEN];
    let nonce_bytes = &header[8 + SALT_LEN..];

    let mut password = rpassword::prompt_password("Enter password: ").unwrap();
    let mut key = argon2_key(&password, salt);
    password.zeroize();

    let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    key.zeroize();   // securely wipe key after cipher is created

    let mut output_path = path.clone();
    output_path.set_extension("");
    let mut output = File::create(&output_path)?;

    let mut buffer = vec![0u8; 64 * 1024 + TAG_LEN];
    let aad: &[u8] = b"";

    let nonce = XNonce::from_slice(nonce_bytes);

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        let mut chunk = buffer[..n].to_vec();
        cipher.decrypt_in_place(nonce, aad, &mut chunk)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("decryption failed: {}", e)))?;

        output.write_all(&chunk)?;
        pb.inc(n as u64);
    }

    println!("\nDecrypted → {}", output_path.display());
    Ok(())
}

fn argon2_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::new(19456, 2, 1, Some(32)).unwrap(), // matches Picocrypt
    );

    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key).unwrap();
    key
}