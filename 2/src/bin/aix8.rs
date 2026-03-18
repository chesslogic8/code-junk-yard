// src/bin/aix8.rs
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rpassword::prompt_password;
use aix8_lib::{encrypt, decrypt, MAGIC};
use libsodium_rs::ensure_init;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Reliable file encryption CLI for Linux using XChaCha20-Poly1305")]
struct Args {
    /// The file to encrypt or decrypt
    file: String,
}

fn main() -> Result<()> {
    ensure_init().map_err(|_| anyhow!("Failed to initialize libsodium-rs"))?;

    let args = Args::parse();
    let input_path = PathBuf::from(&args.file);

    if !input_path.exists() || !input_path.is_file() {
        return Err(anyhow!("Input '{}' is not a valid file", args.file));
    }

    // Detect if encrypt or decrypt by peeking at magic bytes
    let is_encrypt = {
        let mut file = File::open(&input_path)?;
        let mut magic_buf = [0u8; MAGIC.len()];
        if file.read_exact(&mut magic_buf).is_ok() && magic_buf == *MAGIC {
            false  // Has MAGIC, so decrypt
        } else {
            true   // No MAGIC, so encrypt
        }
    };

    let temp_path = input_path.with_extension("tmp");

    let (output_path, op_desc) = if is_encrypt {
        let pw1 = prompt_password("Enter password: ")?;
        let pw2 = prompt_password("Confirm password: ")?;
        if pw1 != pw2 {
            return Err(anyhow!("Passwords do not match"));
        }
        encrypt(&input_path, &temp_path, &pw1)?;
        (input_path.with_extension("ai"), "Encrypted")
    } else {
        let pw = prompt_password("Enter password: ")?;
        let stored_ext = decrypt(&input_path, &temp_path, &pw)?;
        let mut path = input_path.clone();
        path.set_extension(stored_ext);
        (path, "Decrypted")
    };

    if output_path.exists() {
        fs::remove_file(&temp_path).ok();  // Clean up temp
        return Err(anyhow!("Output file '{}' already exists; won't overwrite for safety", output_path.display()));
    }

    fs::rename(&temp_path, &output_path).context("Failed to rename temp file")?;
    let mut perms = fs::metadata(&output_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&output_path, perms).context("Failed to set file permissions")?;

    // Remove the original input file for "in-place" feel (only one file remains)
    fs::remove_file(&input_path).context("Failed to remove original file")?;

    println!("Success: {} {} -> {}", op_desc, args.file, output_path.display());
    Ok(())
}