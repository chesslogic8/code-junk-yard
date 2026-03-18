use anyhow::{Result, anyhow};

use serpent::Serpent;

use cipher::{BlockEncrypt, NewBlockCipher};
use cipher::generic_array::GenericArray;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use rand::rngs::OsRng;
use rand::RngCore;

use zeroize::Zeroize;

use std::env;
use std::fs::{File, rename, metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

type HmacSha512 = Hmac<Sha512>;

const MAGIC: &[u8;4] = b"SFA1";

const BLOCK: usize = 16;
const IV_SIZE: usize = 16;
const TAG_SIZE: usize = 64;

const EXT_OUT: &str = "ai";

const MASTER_KEY: [u8;32] = [0x42;32];

fn main() -> Result<()> {

    let arg = env::args().nth(1)
        .ok_or_else(|| anyhow!("usage: filecrypt <file>"))?;

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

/* ---------- KEY DERIVATION ---------- */

fn derive_keys() -> ([u8;64],[u8;32]) {

    let hk = Hkdf::<Sha512>::new(None, &MASTER_KEY);

    let mut mac = [0u8;64];
    let mut enc = [0u8;32];

    hk.expand(b"mac", &mut mac).unwrap();
    hk.expand(b"enc", &mut enc).unwrap();

    (mac,enc)
}

/* ---------- ENCRYPT ---------- */

fn encrypt(path:&Path) -> Result<()> {

    let size = metadata(path)?.len() as usize;

    let mut data = Vec::with_capacity(size);
    File::open(path)?.read_to_end(&mut data)?;

    let ext = path.extension()
        .and_then(|x| x.to_str())
        .unwrap_or("");

    let ext_bytes = ext.as_bytes();

    if ext_bytes.len() > 32 {
        return Err(anyhow!("extension too long"));
    }

    let mut iv = [0u8;IV_SIZE];
    OsRng.fill_bytes(&mut iv);

    let (mut mac_key, mut enc_key) = derive_keys();

    ctr(&enc_key,&iv,&mut data)?;

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key)?;

    mac.update(MAGIC);
    mac.update(&[ext_bytes.len() as u8]);
    mac.update(ext_bytes);
    mac.update(&iv);
    mac.update(&(data.len() as u64).to_le_bytes());
    mac.update(&data);

    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(
        4 + 1 + ext_bytes.len() + IV_SIZE + 8 + data.len() + TAG_SIZE
    );

    out.extend_from_slice(MAGIC);
    out.push(ext_bytes.len() as u8);
    out.extend_from_slice(ext_bytes);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&data);
    out.extend_from_slice(&tag);

    let stem = path.file_stem()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow!("bad filename"))?;

    let out_path = path.with_file_name(format!("{}.{}",stem,EXT_OUT));
    let tmp = out_path.with_extension("tmp");

    let mut f = File::create(&tmp)?;
    f.write_all(&out)?;
    f.sync_all()?;

    rename(tmp,out_path)?;

    mac_key.zeroize();
    enc_key.zeroize();

    Ok(())
}

/* ---------- DECRYPT ---------- */

fn decrypt(path:&Path) -> Result<()> {

    let size = metadata(path)?.len() as usize;

    let mut data = Vec::with_capacity(size);
    File::open(path)?.read_to_end(&mut data)?;

    if data.len() < 100 {
        return Err(anyhow!("file too small"));
    }

    let mut pos = 0;

    if &data[..4] != MAGIC {
        return Err(anyhow!("invalid file"));
    }

    pos += 4;

    if pos >= data.len() {
        return Err(anyhow!("corrupted header"));
    }

    let ext_len = data[pos] as usize;
    pos += 1;

    if ext_len > 32 {
        return Err(anyhow!("invalid extension length"));
    }

    if pos + ext_len > data.len() {
        return Err(anyhow!("corrupted header"));
    }

    let ext = std::str::from_utf8(&data[pos..pos+ext_len])?;
    pos += ext_len;

    if pos + IV_SIZE + 8 > data.len() {
        return Err(anyhow!("corrupted header"));
    }

    let iv = &data[pos..pos+IV_SIZE];
    pos += IV_SIZE;

    let mut len_buf = [0u8;8];
    len_buf.copy_from_slice(&data[pos..pos+8]);
    pos += 8;

    let plain_len = u64::from_le_bytes(len_buf) as usize;

    if pos + plain_len + TAG_SIZE > data.len() {
        return Err(anyhow!("corrupted file"));
    }

    let ct_end = pos + plain_len;

    let mut ct = data[pos..ct_end].to_vec();
    pos = ct_end;

    let tag = &data[pos..pos+TAG_SIZE];

    let (mut mac_key, mut enc_key) = derive_keys();

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key)?;

    mac.update(MAGIC);
    mac.update(&[ext_len as u8]);
    mac.update(ext.as_bytes());
    mac.update(iv);
    mac.update(&len_buf);
    mac.update(&ct);

    mac.verify_slice(tag)?;

    ctr(&enc_key,iv,&mut ct)?;

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
    f.write_all(&ct)?;
    f.sync_all()?;

    rename(tmp,out_path)?;

    mac_key.zeroize();
    enc_key.zeroize();

    Ok(())
}

/* ---------- CTR MODE ---------- */

fn ctr(key:&[u8], iv:&[u8], data:&mut [u8]) -> Result<()> {

    let cipher = Serpent::new_from_slice(key)
        .map_err(|_| anyhow!("cipher init failed"))?;

    let mut counter = 0u64;
    let mut offset = 0;

    while offset < data.len() {

        let mut block = [0u8;BLOCK];

        block[..8].copy_from_slice(&iv[..8]);
        block[8..].copy_from_slice(&counter.to_be_bytes());

        let mut block_ga = GenericArray::from_mut_slice(&mut block);
        cipher.encrypt_block(&mut block_ga);

        let n = (data.len()-offset).min(BLOCK);

        for (a,b) in data[offset..offset+n].iter_mut().zip(block.iter()) {
            *a ^= *b;
        }

        offset += n;
        counter += 1;
    }

    Ok(())
}