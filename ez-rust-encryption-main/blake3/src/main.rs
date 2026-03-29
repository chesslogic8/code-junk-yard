use anyhow::{Result, anyhow};
use blake3::Hasher;
use rand::rngs::OsRng;
use rand::RngCore;

use std::env;
use std::fs::{File, rename, metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/* ---------- CONSTANTS ---------- */

const MAGIC: &[u8;4] = b"B3C2";

const NONCE_SIZE: usize = 16;
const TAG_SIZE: usize = 32;

const EXT_OUT: &str = "ai";

const MASTER_KEY: [u8;32] = [0x55;32];

/* ---------- MAIN ---------- */

fn main() -> Result<()> {

    let arg = env::args().nth(1)
        .ok_or_else(|| anyhow!("usage: blake3 <file>"))?;

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

/* ---------- KEYSTREAM ---------- */

fn keystream(key:&[u8;32], nonce:&[u8], len:usize) -> Vec<u8> {

    let mut stream = Vec::with_capacity(len);
    let mut counter: u64 = 0;

    while stream.len() < len {

        let mut hasher = Hasher::new_keyed(key);

        hasher.update(nonce);
        hasher.update(&counter.to_le_bytes());

        let block = hasher.finalize();

        stream.extend_from_slice(block.as_bytes());

        counter += 1;
    }

    stream.truncate(len);
    stream
}

/* ---------- MAC ---------- */

fn compute_mac(key:&[u8;32], data:&[u8]) -> [u8;32] {

    let mut hasher = Hasher::new_keyed(key);

    hasher.update(data);

    let hash = hasher.finalize();

    *hash.as_bytes()
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

    let mut nonce = [0u8;NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    let ks = keystream(&MASTER_KEY, &nonce, plain.len());

    let cipher: Vec<u8> = plain.iter()
        .zip(ks.iter())
        .map(|(p,k)| p ^ k)
        .collect();

    let tag = compute_mac(&MASTER_KEY, &cipher);

    let stem = path.file_stem()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow!("bad filename"))?;

    let out_path = path.with_file_name(format!("{}.{}",stem,EXT_OUT));
    let tmp = out_path.with_extension("tmp");

    let mut f = File::create(&tmp)?;

    /* write ciphertext first */

    f.write_all(&cipher)?;

    /* footer */

    f.write_all(&tag)?;
    f.write_all(MAGIC)?;
    f.write_all(&[ext_bytes.len() as u8])?;
    f.write_all(ext_bytes)?;
    f.write_all(&nonce)?;
    f.write_all(&(plain.len() as u64).to_le_bytes())?;

    f.sync_all()?;

    rename(tmp,out_path)?;

    Ok(())
}

/* ---------- DECRYPT ---------- */

fn decrypt(path:&Path) -> Result<()> {

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    if data.len() < NONCE_SIZE + TAG_SIZE + 8 + 5 {
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
    let tag_pos = magic_pos - TAG_SIZE;

    if &data[magic_pos..magic_pos+4] != MAGIC {
        return Err(anyhow!("invalid file"));
    }

    let ext = std::str::from_utf8(&data[ext_pos..ext_pos+ext_len])?;

    let nonce = &data[nonce_pos..nonce_pos+NONCE_SIZE];

    let mut len_buf = [0u8;8];
    len_buf.copy_from_slice(&data[len_pos..len_pos+8]);

    let plain_len = u64::from_le_bytes(len_buf) as usize;

    let tag = &data[tag_pos..tag_pos+TAG_SIZE];

    let ciphertext = &data[..tag_pos];

    let expected = compute_mac(&MASTER_KEY, ciphertext);

    if tag != expected {
        return Err(anyhow!("authentication failed (file corrupted or wrong key)"));
    }

    let ks = keystream(&MASTER_KEY, nonce, plain_len);

    let plain: Vec<u8> = ciphertext.iter()
        .zip(ks.iter())
        .map(|(c,k)| c ^ k)
        .collect();

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