#[cfg(not(target_os = "linux"))]
compile_error!("This program only supports Linux.");

use anyhow::{Result, anyhow};

use salsa20::{
    cipher::{KeyIvInit, StreamCipher},
    XSalsa20
};

use rand::rngs::OsRng;
use rand::RngCore;

use std::env;
use std::fs::{File, rename, metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8;4] = b"XSL1";
const VERSION: u8 = 1;

const NONCE_SIZE: usize = 24;
const EXT_OUT: &str = "ai";

const MASTER_KEY: [u8;32] = [0x55;32];

fn main() -> Result<()> {

    let arg = env::args().nth(1)
        .ok_or_else(|| anyhow!("usage: xsalsa <file>"))?;

    if arg.contains('/') {
        return Err(anyhow!("file must be in current directory"));
    }

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

fn encrypt(path:&Path) -> Result<()> {

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let ext = path.extension()
        .and_then(|x| x.to_str())
        .unwrap_or("");

    let ext_bytes = ext.as_bytes();

    let mut nonce = [0u8;NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    let mut cipher = XSalsa20::new(&MASTER_KEY.into(), &nonce.into());

    cipher.apply_keystream(&mut data);

    let mut out = Vec::new();

    out.extend_from_slice(&data);

    out.extend_from_slice(MAGIC);
    out.push(VERSION);

    out.push(ext_bytes.len() as u8);
    out.extend_from_slice(ext_bytes);

    out.extend_from_slice(&nonce);

    out.extend_from_slice(&(data.len() as u64).to_le_bytes());

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

fn decrypt(path:&Path) -> Result<()> {

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let mut pos = data.len();

    pos -= 8;
    let mut len_buf = [0u8;8];
    len_buf.copy_from_slice(&data[pos..pos+8]);
    let plain_len = u64::from_le_bytes(len_buf) as usize;

    pos -= NONCE_SIZE;
    let nonce = &data[pos..pos+NONCE_SIZE];

    pos -= 1;
    let ext_len = data[pos] as usize;

    pos -= ext_len;
    let ext = std::str::from_utf8(&data[pos..pos+ext_len])?;

    pos -= 1;
    let version = data[pos];

    if version != VERSION {
        return Err(anyhow!("unsupported version"));
    }

    pos -= 4;
    if &data[pos..pos+4] != MAGIC {
        return Err(anyhow!("invalid file"));
    }

    let mut ciphertext = data[..pos].to_vec();

    let mut cipher = XSalsa20::new(&MASTER_KEY.into(), nonce.into());

    cipher.apply_keystream(&mut ciphertext);

    if ciphertext.len() != plain_len {
        return Err(anyhow!("size mismatch"));
    }

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
    f.write_all(&ciphertext)?;
    f.sync_all()?;

    rename(tmp,out_path)?;

    Ok(())
}