use std::env;
use std::fs::{File, metadata, rename};
use std::io::{Read, Write};
use std::path::Path;
use anyhow::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use salsa20::Salsa20;
use cipher::{KeyIvInit, StreamCipher};

const MAGIC: &[u8; 4] = b"SAL1";
const NONCE_SIZE: usize = 8;   // Salsa20 uses an 8-byte nonce
const MAX_EXT_LEN: usize = 64;
const EXT_OUT: &str = "ai";

const MASTER_KEY: [u8; 32] = [0x33; 32];

fn main() -> Result<()> {
    let arg = env::args().nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: salsa <filename>"))?;

    let path = Path::new(&arg);

    if path.components().count() != 1 {
        return Err(anyhow::anyhow!("file must be in current directory"));
    }

    if !metadata(path)?.is_file() {
        return Err(anyhow::anyhow!("target must be regular file"));
    }

    if path.extension()
        .and_then(|x| x.to_str())
        .map(|x| x.eq_ignore_ascii_case(EXT_OUT))
        .unwrap_or(false)
    {
        decrypt(path)
    } else {
        encrypt(path)
    }
}

fn encrypt(path: &Path) -> Result<()> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let ext = path.extension()
        .and_then(|x| x.to_str())
        .unwrap_or("");

    let ext_bytes = ext.as_bytes();

    if ext_bytes.len() > MAX_EXT_LEN {
        return Err(anyhow::anyhow!("extension too long"));
    }

    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    let mut cipher = Salsa20::new(&MASTER_KEY.into(), &nonce.into());
    cipher.apply_keystream(&mut data);

    let mut out = Vec::new();
    out.extend_from_slice(&data);

    out.extend_from_slice(MAGIC);
    out.push(ext_bytes.len() as u8);
    out.extend_from_slice(ext_bytes);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());

    let stem = path.file_stem()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow::anyhow!("bad filename"))?;

    let out_path = path.with_file_name(format!("{}.{}", stem, EXT_OUT));
    let tmp = out_path.with_extension("tmp");

    let mut f = File::create(&tmp)?;
    f.write_all(&out)?;
    f.sync_all()?;

    rename(tmp, &out_path)?;

    println!("Encrypted → {}", out_path.display());
    Ok(())
}

fn decrypt(path: &Path) -> Result<()> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let len = data.len();
    const MIN_FOOTER: usize = 4 + 1 + 8 + 8; // MAGIC + extlen + nonce(8) + origlen

    if len < MIN_FOOTER {
        return Err(anyhow::anyhow!("file too small to be valid"));
    }

    let orig_len = u64::from_le_bytes(
        data[len - 8..len].try_into().unwrap()
    ) as usize;

    if orig_len > len - MIN_FOOTER {
        return Err(anyhow::anyhow!("corrupted file (length mismatch)"));
    }

    let footer_start = orig_len;

    if &data[footer_start..footer_start + 4] != MAGIC {
        return Err(anyhow::anyhow!("invalid file or wrong key"));
    }

    let ext_len = data[footer_start + 4] as usize;
    if ext_len > MAX_EXT_LEN {
        return Err(anyhow::anyhow!("invalid extension length"));
    }

    let ext_start = footer_start + 5;
    let ext_bytes = &data[ext_start..ext_start + ext_len];

    let nonce_start = ext_start + ext_len;
    let nonce = &data[nonce_start..nonce_start + NONCE_SIZE];

    let mut ciphertext = data[0..orig_len].to_vec();

    let mut cipher = Salsa20::new(&MASTER_KEY.into(), nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    let stem = path.file_stem()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow::anyhow!("bad filename"))?;

    let ext = std::str::from_utf8(ext_bytes)
        .map_err(|_| anyhow::anyhow!("invalid utf-8 in original extension"))?;

    let out_name = if ext.is_empty() {
        stem.to_string()
    } else {
        format!("{}.{}", stem, ext)
    };

    let out_path = path.with_file_name(&out_name);
    let tmp = out_path.with_extension("tmp");

    let mut f = File::create(&tmp)?;
    f.write_all(&ciphertext)?;
    f.sync_all()?;

    rename(tmp, &out_path)?;

    println!("Decrypted → {}", out_path.display());
    Ok(())
}