use std::fs::{File, rename};
use std::io::{self, Read, Write};
use std::path::PathBuf;

use aes::Aes256;
use argon2::{Argon2, Params};
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, AeadInPlace, XNonce};
use cipher::{KeyIvInit, generic_array::GenericArray, StreamCipher};
use clap::Parser;
use ctr::Ctr128BE;
use hkdf::Hkdf;
use indicatif::ProgressBar;
use rand::RngCore;
use rpassword;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"PCv1.1!!";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

#[derive(Parser, Debug)]
struct Args {
    #[arg(required = true)]
    items: Vec<PathBuf>,

    #[arg(short = 'p', long)]
    paranoid: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let path = &args.items[0];
    let is_encrypt = !path.extension().map_or(false, |e| e == "pcv");

    let mut file = File::open(path)?;
    let total = file.metadata()?.len();
    let pb = ProgressBar::new(total);

    if is_encrypt {
        encrypt_file(&mut file, path, &pb, args.paranoid)?;
    } else {
        decrypt_file(&mut file, path, &pb)?;
    }

    pb.finish();
    Ok(())
}

fn derive_nonce(base: &[u8; 24], idx: u64, hk: &Hkdf<Sha256>) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    hk.expand(&idx.to_le_bytes(), &mut nonce).unwrap();

    for i in 0..24 {
        nonce[i] ^= base[i];
    }

    nonce
}

fn encrypt_file(
    input: &mut File,
    path: &PathBuf,
    pb: &ProgressBar,
    paranoid: bool,
) -> io::Result<()> {

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut base_nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut base_nonce);

    let mut password = rpassword::prompt_password("Password: ").unwrap();

    let params = if paranoid {
        Params::new(38912, 4, 1, Some(32)).unwrap()
    } else {
        Params::new(19456, 2, 1, Some(32)).unwrap()
    };

    let master_key = argon2_key(&password, &salt, params.clone());

    let hk = Hkdf::<Sha256>::new(Some(&salt), &master_key);

    let mut xkey = [0u8; 32];
    hk.expand(b"xchacha", &mut xkey).unwrap();

    let mut ctr_key = [0u8; 32];
    hk.expand(b"aes", &mut ctr_key).unwrap();

    let cipher = XChaCha20Poly1305::new_from_slice(&xkey).unwrap();

    let mut output_path = path.clone();
    output_path.set_extension("pcv");
    let mut output = File::create(&output_path)?;

    let mode = if paranoid { 1u8 } else { 0u8 };

    output.write_all(MAGIC)?;
    output.write_all(&salt)?;
    output.write_all(&base_nonce)?;
    output.write_all(&[mode])?;
    output.write_all(&(params.m_cost() as u32).to_le_bytes())?;
    output.write_all(&(params.t_cost() as u32).to_le_bytes())?;
    output.write_all(&(params.p_cost() as u32).to_le_bytes())?;

    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&base_nonce);
    header.push(mode);
    header.extend_from_slice(&(params.m_cost() as u32).to_le_bytes());
    header.extend_from_slice(&(params.t_cost() as u32).to_le_bytes());
    header.extend_from_slice(&(params.p_cost() as u32).to_le_bytes());

    let header_hash = Sha256::digest(&header);
    let header_hash = header_hash.as_slice();

    let mut buffer = vec![0u8; 64 * 1024];
    let mut chunk_index = 0u64;

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 { break; }

        let mut chunk = buffer[..n].to_vec();

        if paranoid {
            let key = GenericArray::from_slice(&ctr_key);
            let mut iv = [0u8; 16];
            iv[..8].copy_from_slice(&base_nonce[..8]);
            iv[8..].copy_from_slice(&chunk_index.to_le_bytes());

            let mut ctr = Ctr128BE::<Aes256>::new(key, GenericArray::from_slice(&iv));
            ctr.apply_keystream(&mut chunk);
        }

        let nonce = derive_nonce(&base_nonce, chunk_index, &hk);

        let mut aad = Vec::new();
        aad.push(mode);
        aad.extend_from_slice(header_hash);
        aad.extend_from_slice(&chunk_index.to_le_bytes());

        let mut data = chunk;
        cipher.encrypt_in_place(XNonce::from_slice(&nonce), &aad, &mut data)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "encrypt fail"))?;

        let len = (NONCE_LEN + data.len()) as u32;
        output.write_all(&len.to_le_bytes())?;
        output.write_all(&nonce)?;
        output.write_all(&data)?;

        pb.inc(n as u64);
        chunk_index += 1;
    }

    password.zeroize();
    Ok(())
}

fn decrypt_file(
    input: &mut File,
    path: &PathBuf,
    pb: &ProgressBar,
) -> io::Result<()> {

    let mut header = [0u8; 8 + SALT_LEN + NONCE_LEN + 1 + 12];
    input.read_exact(&mut header)?;

    if &header[..8] != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
    }

    let salt = &header[8..24];
    let base_nonce: &[u8; 24] = header[24..48].try_into().unwrap();
    let mode = header[48];

    let mem = u32::from_le_bytes(header[49..53].try_into().unwrap());
    let time = u32::from_le_bytes(header[53..57].try_into().unwrap());
    let lanes = u32::from_le_bytes(header[57..61].try_into().unwrap());

    let params = Params::new(mem, time, lanes, Some(32)).unwrap();

    let mut password = rpassword::prompt_password("Password: ").unwrap();
    let master_key = argon2_key(&password, salt, params);

    let hk = Hkdf::<Sha256>::new(Some(salt), &master_key);

    let mut xkey = [0u8; 32];
    hk.expand(b"xchacha", &mut xkey).unwrap();

    let mut ctr_key = [0u8; 32];
    hk.expand(b"aes", &mut ctr_key).unwrap();

    let cipher = XChaCha20Poly1305::new_from_slice(&xkey).unwrap();

    let mut tmp_path = path.clone();
    tmp_path.set_extension("tmp");

    let mut output = File::create(&tmp_path)?;

    let header_hash = Sha256::digest(&header);
    let header_hash = header_hash.as_slice();

    let mut chunk_index = 0u64;

    loop {
        let mut len_buf = [0u8; 4];
        if input.read_exact(&mut len_buf).is_err() { break; }

        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 { break; }

        let mut buf = vec![0u8; len];
        input.read_exact(&mut buf)?;

        let nonce = &buf[..NONCE_LEN];
        let ciphertext = &buf[NONCE_LEN..];

        let mut aad = Vec::new();
        aad.push(mode);
        aad.extend_from_slice(header_hash);
        aad.extend_from_slice(&chunk_index.to_le_bytes());

        let mut chunk = ciphertext.to_vec();

        cipher.decrypt_in_place(XNonce::from_slice(nonce), &aad, &mut chunk)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "decrypt fail"))?;

        if mode == 1 {
            let key = GenericArray::from_slice(&ctr_key);
            let mut iv = [0u8; 16];
            iv[..8].copy_from_slice(&base_nonce[..8]);
            iv[8..].copy_from_slice(&chunk_index.to_le_bytes());

            let mut ctr = Ctr128BE::<Aes256>::new(key, GenericArray::from_slice(&iv));
            ctr.apply_keystream(&mut chunk);
        }

        output.write_all(&chunk)?;
        pb.inc(chunk.len() as u64);

        chunk_index += 1;
    }

    output.flush()?;
    rename(tmp_path, path.with_extension(""))?;

    password.zeroize();
    Ok(())
}

fn argon2_key(password: &str, salt: &[u8], params: Params) -> [u8; 32] {
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key).unwrap();
    key
}