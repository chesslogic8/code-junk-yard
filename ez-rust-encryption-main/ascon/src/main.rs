use anyhow::{Result, anyhow};

use ascon_aead::{
    Ascon128a,
    aead::{Aead, KeyInit}
};

use rand::rngs::OsRng;
use rand::RngCore;

use std::env;
use std::fs::{File, rename, metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/* ---------- CONSTANTS ---------- */

const MAGIC: &[u8;4] = b"ASC1";

const NONCE_SIZE: usize = 16;
const EXT_OUT: &str = "ai";

const MASTER_KEY: [u8;16] = [0x42;16];

/* ---------- MAIN ---------- */

fn main() -> Result<()> {

    let arg = env::args().nth(1)
        .ok_or_else(|| anyhow!("usage: ascon <file>"))?;

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

    let mut nonce_bytes = [0u8;NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Ascon128a::new_from_slice(&MASTER_KEY)
        .map_err(|_| anyhow!("cipher init failed"))?;

    let nonce = ascon_aead::Nonce::<Ascon128a>::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plain.as_ref())
        .map_err(|_| anyhow!("encryption failed"))?;

    let stem = path.file_stem()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow!("bad filename"))?;

    let out_path = path.with_file_name(format!("{}.{}",stem,EXT_OUT));
    let tmp = out_path.with_extension("tmp");

    let mut f = File::create(&tmp)?;

    /* ciphertext first */

    f.write_all(&ciphertext)?;

    /* footer */

    f.write_all(MAGIC)?;
    f.write_all(&[ext_bytes.len() as u8])?;
    f.write_all(ext_bytes)?;
    f.write_all(&nonce_bytes)?;
    f.write_all(&(plain.len() as u64).to_le_bytes())?;

    f.sync_all()?;

    rename(tmp,out_path)?;

    Ok(())
}

/* ---------- DECRYPT ---------- */

fn decrypt(path:&Path) -> Result<()> {

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    if data.len() < NONCE_SIZE + 8 + 5 {
        return Err(anyhow!("file too small"));
    }

    let file_len = data.len();

    let len_pos = file_len - 8;
    let nonce_pos = len_pos - NONCE_SIZE;
    let ext_len_pos = nonce_pos - 1;

    let ext_len = data[ext_len_pos] as usize;

    if ext_len > 32 {
        return Err(anyhow!("invalid extension length"));
    }

    let ext_pos = ext_len_pos - ext_len;
    let magic_pos = ext_pos - 4;

    if &data[magic_pos..magic_pos+4] != MAGIC {
        return Err(anyhow!("invalid file"));
    }

    let ext = std::str::from_utf8(&data[ext_pos..ext_pos+ext_len])?;

    let nonce_bytes = &data[nonce_pos..nonce_pos+NONCE_SIZE];

    let mut len_buf = [0u8;8];
    len_buf.copy_from_slice(&data[len_pos..len_pos+8]);

    let ciphertext = &data[..magic_pos];

    let cipher = Ascon128a::new_from_slice(&MASTER_KEY)
        .map_err(|_| anyhow!("cipher init failed"))?;

    let nonce = ascon_aead::Nonce::<Ascon128a>::from_slice(nonce_bytes);

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