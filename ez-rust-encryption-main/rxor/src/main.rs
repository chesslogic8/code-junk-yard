use std::env;
use std::fs::{self, File};
use std::io::{Error, ErrorKind, Result, Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};

const KEY: &[u8] = b"change_this_key_to_any_length_you_want";

fn main() -> Result<()> {
    let mut args = env::args();
    args.next();

    let filename = args
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Other, "usage: rxor <file>"))?;

    if args.next().is_some() {
        return Err(Error::new(ErrorKind::Other, "usage: rxor <file>"));
    }

    let exe_dir = env::current_exe()?
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::Other, "exe path"))?
        .to_path_buf();

    let path = exe_dir.join(filename);

    if !path.exists() {
        return Err(Error::new(ErrorKind::Other, "file must be in same directory"));
    }

    if path.extension().and_then(|e| e.to_str()) == Some("ai") {
        decrypt(&path)
    } else {
        encrypt(&path)
    }
}

fn get_random_byte() -> Result<u8> {
    let mut file = File::open("/dev/urandom")?;
    let mut buf = [0u8; 1];
    file.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn encrypt(path: &Path) -> Result<()> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let new_path = path.with_extension("ai");
    let output = File::create(&new_path)?;
    let mut writer = BufWriter::new(output);

    let iv = get_random_byte()?;
    writer.write_all(&[iv])?;

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let ext_bytes = ext.as_bytes();

    let mut buffer = [0u8; 8192];
    let mut prev = iv;
    let mut i = 0usize;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        for b in &mut buffer[..n] {
            let key = KEY[i % KEY.len()];
            let rot = ((key ^ i as u8) % 8) as u32;

            *b ^= key ^ prev;
            *b = b.rotate_left(rot);
            *b = b.wrapping_add(key);

            prev = *b;
            i += 1;
        }

        writer.write_all(&buffer[..n])?;
    }

    writer.write_all(&[ext_bytes.len() as u8])?;
    writer.write_all(ext_bytes)?;

    fs::remove_file(path)?;

    Ok(())
}

fn decrypt(path: &Path) -> Result<()> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;

    if data.len() < 2 {
        return Err(Error::new(ErrorKind::Other, "file too small"));
    }

    let iv = data[0];

    let ext_len = data[data.len() - 1] as usize;
    let ext_start = data.len() - 1 - ext_len;

    let ext = std::str::from_utf8(&data[ext_start..ext_start + ext_len])
        .unwrap_or("")
        .to_string();

    let mut body = data[1..ext_start].to_vec();

    let mut prev = iv;
    let mut i = 0usize;

    for b in &mut body {
        let key = KEY[i % KEY.len()];
        let rot = ((key ^ i as u8) % 8) as u32;

        let cur = *b;

        *b = b.wrapping_sub(key);
        *b = b.rotate_right(rot);
        *b ^= key ^ prev;

        prev = cur;
        i += 1;
    }

    let new_path: PathBuf = if ext.is_empty() {
        path.with_extension("")
    } else {
        path.with_extension(ext)
    };

    let mut writer = BufWriter::new(File::create(&new_path)?);
    writer.write_all(&body)?;

    fs::remove_file(path)?;

    Ok(())
}