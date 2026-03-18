use anyhow::{Result, anyhow};

use chacha20poly1305::{
    ChaCha20Poly1305,
    Nonce,
    aead::{Aead, KeyInit}
};

use rand::rngs::OsRng;
use rand::RngCore;

use std::env;
use std::fs::{File, rename, metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/* ---------- CONSTANTS ---------- */

const MAGIC: &[u8;4] = b"CFA1";
const VERSION: u8 = 1;

const NONCE_SIZE: usize = 12;
const EXT_OUT: &str = "ai";

/* hard coded 256-bit key */

const MASTER_KEY: [u8;32] = [0x55;32];

/* ---------- MAIN ---------- */

fn main() -> Result<()> {

    let arg = env::args().nth(1)
        .ok_or_else(|| anyhow!("usage: chacrypt <file>"))?;

    let path = PathBuf::from(arg);

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

fn encrypt(path:&Path) -> Result<()> {

    let mut plain = Vec::new();
    File::open(path)?.read_to_end(&mut plain)?;

    let ext = path.extension()
        .and_then(|x| x.to_str())
        .unwrap_or("");

    let ext_bytes = ext.as_bytes();

    if ext_bytes.len() > 32 {
        return Err(anyhow!("extension too long"));
    }

    /* random nonce */

    let mut nonce_bytes = [0u8;NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&MASTER_KEY)
        .map_err(|_| anyhow!("cipher init failed"))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plain.as_ref())
        .map_err(|_| anyhow!("encryption failed"))?;

    /* build output */

    let mut out = Vec::new();

    out.extend_from_slice(MAGIC);
    out.push(VERSION);

    out.push(ext_bytes.len() as u8);
    out.extend_from_slice(ext_bytes);

    out.extend_from_slice(&nonce_bytes);

    out.extend_from_slice(&(plain.len() as u64).to_le_bytes());

    out.extend_from_slice(&ciphertext);

    /* output file */

    let stem = path.file_stem()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow!("bad filename"))?;

    let out_path = path.with_file_name(format!("{}.{}",stem,EXT_OUT));
    let tmp = out_path.with_extension("tmp");

    let mut f = File::create(&tmp)?;
    f.write_all(&out)?;
    f.sync_all()?;

    rename(tmp,out_path)?;

    Ok(())
}

/* ---------- DECRYPT ---------- */

fn decrypt(path:&Path) -> Result<()> {

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    if data.len() < 4 + 1 + 1 + NONCE_SIZE + 8 {
        return Err(anyhow!("file too small"));
    }

    let mut pos = 0;

    if &data[..4] != MAGIC {
        return Err(anyhow!("invalid file"));
    }

    pos += 4;

    let version = data[pos];
    pos += 1;

    if version != VERSION {
        return Err(anyhow!("unsupported version"));
    }

    let ext_len = data[pos] as usize;
    pos += 1;

    if ext_len > 32 {
        return Err(anyhow!("invalid extension length"));
    }

    let ext = std::str::from_utf8(&data[pos..pos+ext_len])?;
    pos += ext_len;

    let nonce_bytes = &data[pos..pos+NONCE_SIZE];
    pos += NONCE_SIZE;

    let mut len_buf = [0u8;8];
    len_buf.copy_from_slice(&data[pos..pos+8]);
    pos += 8;

    let ciphertext = &data[pos..];

    let cipher = ChaCha20Poly1305::new_from_slice(&MASTER_KEY)
        .map_err(|_| anyhow!("cipher init failed"))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("decryption failed (tampered or wrong key)"))?;

    let stem = path.file_stem()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow!("bad filename"))?;

    let out_name = if ext.is_empty() {
        stem.to_string()
    } else {
        format!("{}.{}",stem,ext)
    };

    let out_path = path.with_file_name(out_name);
    let tmp = out_path.with_extension("tmp");

    let mut f = File::create(&tmp)?;
    f.write_all(&plain)?;
    f.sync_all()?;

    rename(tmp,out_path)?;

    Ok(())
}