use std::env;
use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

const KEY: &[u8] = b"change_this_key_to_any_length_you_want";

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        return Err(Error::new(ErrorKind::Other, "usage: xor <file>"));
    }

    let exe_dir = env::current_exe()?
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::Other, "exe path"))?
        .to_path_buf();

    let path = exe_dir.join(&args[1]);

    if !path.exists() {
        return Err(Error::new(ErrorKind::Other, "file must be in same directory"));
    }

    if path.extension().and_then(|e| e.to_str()) == Some("ai") {
        decrypt(&path)
    } else {
        encrypt(&path)
    }
}

fn xor_process(data: &mut [u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= KEY[i % KEY.len()];
    }
}

fn encrypt(path: &Path) -> Result<()> {
    let mut data = fs::read(path)?;

    xor_process(&mut data);

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let mut out = Vec::new();

    out.extend_from_slice(&data);

    out.push(ext.len() as u8);
    out.extend_from_slice(ext.as_bytes());

    let new_path = path.with_extension("ai");

    fs::write(&new_path, out)?;

    fs::remove_file(path)?;

    Ok(())
}

fn decrypt(path: &Path) -> Result<()> {
    let mut data = fs::read(path)?;

    if data.len() < 1 {
        return Err(Error::new(ErrorKind::Other, "file too small"));
    }

    let ext_len = data[data.len() - 1] as usize;
    let ext_start = data.len() - 1 - ext_len;

    let ext = std::str::from_utf8(&data[ext_start..ext_start + ext_len])
        .unwrap_or("")
        .to_string();

    data.truncate(ext_start);

    xor_process(&mut data);

    let new_path: PathBuf = if ext.is_empty() {
        path.with_extension("")
    } else {
        path.with_extension(ext)
    };

    fs::write(&new_path, data)?;

    fs::remove_file(path)?;

    Ok(())
}