use anyhow::{Result, anyhow};
use chacha20poly1305::{
    XChaCha20Poly1305,
    XNonce,
    aead::{Aead, KeyInit},
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::env;
use std::fs::{File, rename, metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/* ---------- CONSTANTS ---------- */
const MAGIC: &[u8; 4] = b"XCF2";
const VERSION: u8 = 2;
const NONCE_SIZE: usize = 24;
const MAX_EXT_LEN: usize = 32;
const EXT_OUT: &str = "enc";

/* hard-coded 256-bit key */
const MASTER_KEY: [u8; 32] = [0x77; 32];

/* ---------- MAIN ---------- */
fn main() -> Result<()> {
    let arg = env::args().nth(1)
        .ok_or_else(|| anyhow!("usage: xcha <file>"))?;

    let path = PathBuf::from(arg);

    /* enforce same directory */
    if path.components().count() != 1 {
        return Err(anyhow!("file must be in current directory"));
    }
    if !metadata(&path)?.is_file() {
        return Err(anyhow!("target must be regular file"));
    }

    if path.extension()
        .and_then(|x| x.to_str())
        .map(|x| x.eq_ignore_ascii_case(EXT_OUT))
        .unwrap_or(false)
    {
        decrypt(&path)
    } else {
        encrypt(&path)
    }
}

/* ---------- ENCRYPT ---------- */
fn encrypt(path: &Path) -> Result<()> {
    let mut plain = Vec::new();
    File::open(path)?.read_to_end(&mut plain)?;

    let original_ext = path.extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_string();

    if original_ext.len() > MAX_EXT_LEN {
        return Err(anyhow!("original extension too long"));
    }
    let ext_bytes = original_ext.as_bytes();

    /* compute plaintext hash (extra integrity layer) */
    let plaintext_hash = Sha256::digest(&plain);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(&MASTER_KEY)
        .map_err(|_| anyhow!("cipher init failed"))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plain.as_ref())
        .map_err(|_| anyhow!("encryption failed"))?;

    let stem = path.file_stem()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow!("bad filename"))?;

    let out_path = path.with_file_name(format!("{}.{}", stem, EXT_OUT));
    let tmp = out_path.with_extension("tmp");

    /* build header */
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&nonce_bytes);
    header.push(ext_bytes.len() as u8);
    header.extend_from_slice(ext_bytes);
    header.extend_from_slice(&plaintext_hash);

    let mut f = File::create(&tmp)?;
    f.write_all(&header)?;
    f.write_all(&ciphertext)?;
    f.sync_all()?;

    rename(tmp, &out_path)?;
    println!("Encrypted: {} → {}", path.display(), out_path.display());
    Ok(())
}

/* ---------- DECRYPT ---------- */
fn decrypt(path: &Path) -> Result<()> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let min_size = 4 + 1 + NONCE_SIZE + 1 + 32; // magic + ver + nonce + extlen + hash
    if data.len() < min_size {
        return Err(anyhow!("file too small"));
    }

    let mut pos = 0;

    /* header parsing with early rejection */
    if &data[pos..pos + 4] != MAGIC {
        return Err(anyhow!("invalid file (bad magic)"));
    }
    pos += 4;

    let version = data[pos];
    if version != VERSION {
        return Err(anyhow!("unsupported version: {}", version));
    }
    pos += 1;

    let nonce_bytes = &data[pos..pos + NONCE_SIZE];
    pos += NONCE_SIZE;

    let ext_len = data[pos] as usize;
    pos += 1;
    if ext_len > MAX_EXT_LEN {
        return Err(anyhow!("invalid extension length"));
    }

    let ext_bytes = &data[pos..pos + ext_len];
    let original_ext = std::str::from_utf8(ext_bytes)
        .map_err(|_| anyhow!("invalid extension encoding"))?;
    pos += ext_len;

    let expected_hash = &data[pos..pos + 32];
    pos += 32;

    let ciphertext = &data[pos..];

    let cipher = XChaCha20Poly1305::new_from_slice(&MASTER_KEY)
        .map_err(|_| anyhow!("cipher init failed"))?;
    let nonce = XNonce::from_slice(nonce_bytes);
    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("decryption failed (tampered, corrupted, or wrong key)"))?;

    /* double guarantee: AEAD already passed + independent hash check */
    let actual_hash = Sha256::digest(&plain);
    if &actual_hash[..] != expected_hash {
        return Err(anyhow!("data corruption detected — hash mismatch after decryption"));
    }

    let stem = path.file_stem()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow!("bad filename"))?;

    let out_name = if original_ext.is_empty() {
        stem.to_string()
    } else {
        format!("{}.{}", stem, original_ext)
    };
    let out_path = path.with_file_name(out_name);

    if out_path.exists() {
        return Err(anyhow!("output file already exists — refusing to overwrite"));
    }

    let tmp = out_path.with_extension("tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(&plain)?;
    f.sync_all()?;

    rename(tmp, &out_path)?;
    println!("Decrypted: {} → {}", path.display(), out_path.display());
    Ok(())
}