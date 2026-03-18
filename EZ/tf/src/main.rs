
use anyhow::{Result, anyhow};
use cipher::{BlockEncrypt, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use threefish::Threefish1024;
use rand::rngs::OsRng;
use rand::RngCore;
use hkdf::Hkdf;
use zeroize::Zeroize;

use std::env;
use std::fs::{File, metadata, rename};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

type HmacSha512 = Hmac<Sha512>;

const MAGIC: &[u8;4] = b"TFA1";
const IV_SIZE: usize = 16;
const TAG_SIZE: usize = 64;
const BLOCK: usize = 128;

const MAX_FILE: u64 = 32 * 1024 * 1024 * 1024;
const EXT_OUT: &str = "ai";

/// change this at compile time
const MASTER_KEY: [u8;128] = [0x11;128];

fn main() -> Result<()> {

    let arg = env::args().nth(1)
        .ok_or_else(|| anyhow!("usage: tf <file>"))?;

    let path = PathBuf::from(arg);

    // only allow files in current directory
    if path.components().count() != 1 {
        return Err(anyhow!("file must be in current directory"));
    }

    if path.extension().and_then(|x| x.to_str()) == Some(EXT_OUT) {
        decrypt(&path)
    } else {
        encrypt(&path)
    }
}

fn derive_keys() -> ([u8;64],[u8;128]) {

    let hk = Hkdf::<Sha512>::new(None, &MASTER_KEY);

    let mut mac = [0u8;64];
    let mut enc = [0u8;128];

    hk.expand(b"mac", &mut mac).unwrap();
    hk.expand(b"enc", &mut enc).unwrap();

    (mac,enc)
}

fn encrypt(path:&Path) -> Result<()> {

    if metadata(path)?.len() > MAX_FILE {
        return Err(anyhow!("file too large"));
    }

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let ext = path.extension()
        .and_then(|x| x.to_str())
        .unwrap_or("");

    let ext_bytes = ext.as_bytes();

    if ext_bytes.len() > 255 {
        return Err(anyhow!("extension too long"));
    }

    let mut iv = [0u8;IV_SIZE];
    OsRng.fill_bytes(&mut iv);

    let (mut mac_key, mut enc_key) = derive_keys();

    ctr(&enc_key,&iv,&mut data);

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key)?;

    mac.update(MAGIC);
    mac.update(&[ext_bytes.len() as u8]);
    mac.update(ext_bytes);
    mac.update(&iv);
    mac.update(&(data.len() as u64).to_le_bytes());
    mac.update(&data);

    let tag = mac.finalize().into_bytes();

    let stem = path.file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("bad filename"))?;

    let out_path = path.with_file_name(format!("{}.{}",stem,EXT_OUT));
    let tmp = out_path.with_extension("tmp");

    let mut f = File::create(&tmp)?;

    // ciphertext
    f.write_all(&data)?;

    // header at end
    f.write_all(MAGIC)?;
    f.write_all(&[ext_bytes.len() as u8])?;
    f.write_all(ext_bytes)?;
    f.write_all(&iv)?;
    f.write_all(&(data.len() as u64).to_le_bytes())?;
    f.write_all(&tag)?;

    f.sync_all()?;

    rename(tmp,out_path)?;

    mac_key.zeroize();
    enc_key.zeroize();

    Ok(())
}

fn decrypt(path:&Path) -> Result<()> {

    if metadata(path)?.len() > MAX_FILE {
        return Err(anyhow!("file too large"));
    }

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    if data.len() < 100 {
        return Err(anyhow!("file too small"));
    }

    let file_len = data.len();

    let tag_pos = file_len - TAG_SIZE;
    let len_pos = tag_pos - 8;
    let iv_pos = len_pos - IV_SIZE;

    let ext_len_pos = iv_pos - 1;
    let ext_len = data[ext_len_pos] as usize;

    let ext_pos = ext_len_pos - ext_len;
    let magic_pos = ext_pos - 4;

    if &data[magic_pos..magic_pos+4] != MAGIC {
        return Err(anyhow!("invalid file"));
    }

    let ext = std::str::from_utf8(&data[ext_pos..ext_pos+ext_len])?;

    let iv = &data[iv_pos..iv_pos+IV_SIZE];

    let mut len_buf = [0u8;8];
    len_buf.copy_from_slice(&data[len_pos..len_pos+8]);

    let tag = &data[tag_pos..tag_pos+TAG_SIZE];

    let mut ct = data[..magic_pos].to_vec();

    let (mut mac_key, mut enc_key) = derive_keys();

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key)?;

    mac.update(MAGIC);
    mac.update(&[ext_len as u8]);
    mac.update(ext.as_bytes());
    mac.update(iv);
    mac.update(&len_buf);
    mac.update(&ct);

    mac.verify_slice(tag)?;

    ctr(&enc_key,iv,&mut ct);

    let stem = path.file_stem()
        .and_then(|s| s.to_str())
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

fn ctr(key:&[u8;128], iv:&[u8], data:&mut [u8]) {

    let mut counter = 0u64;
    let mut offset = 0;

    let mut tweak = [0u8;16];
    tweak[..8].copy_from_slice(&iv[..8]);

    let mut block = [0u8;BLOCK];

    while offset < data.len() {

        tweak[8..].copy_from_slice(&counter.to_le_bytes());

        let cipher = Threefish1024::new_with_tweak(key.into(),&tweak.into());

        block.fill(0);

        let mut g = GenericArray::from_mut_slice(&mut block);
        cipher.encrypt_block(&mut g);

        let n = (data.len()-offset).min(BLOCK);

        for (a,b) in data[offset..offset+n].iter_mut().zip(block.iter()) {
            *a ^= *b;
        }

        offset += n;
        counter += 1;
    }
}

