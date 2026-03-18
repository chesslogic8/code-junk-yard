use anyhow::{anyhow, Result};
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{
self as secretstream, Key, TAG_FINAL, TAG_MESSAGE,
};
use libsodium_rs::random;
use std::fs::File;
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::Path;

pub const MAGIC: &[u8] = b"AIX8";
pub const SALT_LEN: usize = 16;

const CHUNK_SIZE: usize = 1 << 20; // 1 MB
const ARGON2_MEM_KIB: u32 = 65536; // 64 MiB
const ARGON2_ITER: u32 = 4;
const ARGON2_PAR: u32 = 4;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Key> {
let params = argon2::Params::new(
ARGON2_MEM_KIB,
ARGON2_ITER,
ARGON2_PAR,
Some(secretstream::KEYBYTES),
)
.map_err(|e| anyhow!("Failed to create Argon2 params: {}", e))?;


let argon2 = argon2::Argon2::new(
    argon2::Algorithm::Argon2id,
    argon2::Version::V0x13,
    params,
);

let mut key_bytes = vec![0u8; secretstream::KEYBYTES];

argon2
    .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
    .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

Key::from_bytes(&key_bytes).map_err(|e| anyhow!("Invalid key: {}", e))


}

pub fn encrypt(input_path: &Path, temp_path: &Path, password: &str) -> Result<()> {
let original_ext = input_path
.extension()
.map_or("".to_string(), |e| e.to_string_lossy().to_string());


let ext_bytes = original_ext.as_bytes();

if ext_bytes.len() > 255 {
    return Err(anyhow!("File extension too long"));
}

let ext_len = ext_bytes.len() as u8;

let salt = random::bytes(SALT_LEN);
let key = derive_key(password, &salt)?;

let mut infile = BufReader::new(File::open(input_path)?);
let mut outfile = BufWriter::new(File::create(temp_path)?);

outfile.write_all(MAGIC)?;
outfile.write_all(&[ext_len])?;
outfile.write_all(ext_bytes)?;
outfile.write_all(&salt)?;

let (mut push_state, header) =
    secretstream::PushState::init_push(&key)
        .map_err(|e| anyhow!("Encryption init failed: {}", e))?;

outfile.write_all(&header)?;

let mut buffer = vec![0u8; CHUNK_SIZE];

loop {
    let n = infile.read(&mut buffer)?;

    if n == 0 {
        break;
    }

    let tag = if n < CHUNK_SIZE {
        TAG_FINAL
    } else {
        TAG_MESSAGE
    };

    let ciphertext = push_state
        .push(&buffer[..n], Some(&[]), tag)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    outfile.write_all(&ciphertext)?;

    if tag == TAG_FINAL {
        break;
    }
}

outfile.flush()?;
Ok(())


}

pub fn decrypt(input_path: &Path, temp_path: &Path, password: &str) -> Result<String> {
let mut infile = File::open(input_path)?;


let mut magic = [0u8; MAGIC.len()];
infile.read_exact(&mut magic)?;

if magic != *MAGIC {
    return Err(anyhow!("Invalid file format (magic mismatch)"));
}

let mut ext_len_buf = [0u8; 1];
infile.read_exact(&mut ext_len_buf)?;
let ext_len = ext_len_buf[0] as usize;

let mut ext_bytes = vec![0u8; ext_len];
infile.read_exact(&mut ext_bytes)?;

let stored_ext =
    String::from_utf8(ext_bytes).map_err(|_| anyhow!("Invalid stored extension"))?;

let mut salt = vec![0u8; SALT_LEN];
infile.read_exact(&mut salt)?;

let key = derive_key(password, &salt)?;

let mut header = [0u8; secretstream::HEADERBYTES];
infile.read_exact(&mut header)?;

let mut pull_state = secretstream::PullState::init_pull(&header, &key)
    .map_err(|e| anyhow!("Decryption init failed (wrong password?): {}", e))?;

let mut outfile = BufWriter::new(File::create(temp_path)?);
let mut reader = BufReader::new(infile);

let mut buffer = vec![0u8; CHUNK_SIZE + secretstream::ABYTES];

let mut seen_final = false;

loop {
    let bytes_read = match reader.read(&mut buffer) {
        Ok(0) => break,
        Ok(n) => n,
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
        Err(e) => return Err(anyhow::Error::from(e)),
    };

    let (plaintext, tag) = pull_state
        .pull(&buffer[..bytes_read], Some(&[]))
        .map_err(|e| anyhow!("Decryption failed (corrupt or wrong password): {}", e))?;

    outfile.write_all(&plaintext)?;

    if tag == TAG_FINAL {
        seen_final = true;
        break;
    }
}

if !seen_final {
    return Err(anyhow!("Ciphertext missing final authentication tag"));
}

let mut extra = [0u8; 1];
if reader.read(&mut extra)? != 0 {
    return Err(anyhow!("Ciphertext has trailing data (possible corruption)"));
}

outfile.flush()?;

Ok(stored_ext)


}
