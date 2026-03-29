use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const KEY: &[u8] = b"change_this_key_to_any_length_you_want";

fn main() -> io::Result<()> {
    let mut args = env::args();
    let prog = args.next().unwrap_or_else(|| "xorp".into());

    let usage = format!("usage: {} <file>", prog);

    let input = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, usage.clone()))?;

    if args.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::Other, usage));
    }

    let path = PathBuf::from(input);

    if !path.exists() {
        return Err(io::Error::new(io::ErrorKind::Other, "file not found"));
    }

    if path.extension().and_then(|e| e.to_str()) == Some("ai") {
        decrypt(&path)
    } else {
        encrypt(&path)
    }
}

fn urandom_byte() -> io::Result<u8> {
    let mut f = File::open("/dev/urandom")?;
    let mut b = [0u8; 1];
    f.read_exact(&mut b)?;
    Ok(b[0])
}

fn encrypt(path: &Path) -> io::Result<()> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let out_path = path.with_extension("ai");
    let output = File::create(&out_path)?;
    let mut writer = BufWriter::new(output);

    // IV
    let iv = urandom_byte()?;
    writer.write_all(&[iv])?;

    // Extension
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

    // Append extension metadata
    writer.write_all(&[ext_bytes.len() as u8])?;
    writer.write_all(ext_bytes)?;

    writer.flush()?;
    fs::remove_file(path)?;

    Ok(())
}

fn decrypt(path: &Path) -> io::Result<()> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;

    if data.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::Other, "file too small"));
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

    let out_path = if ext.is_empty() {
        path.with_extension("")
    } else {
        path.with_extension(ext)
    };

    let mut writer = BufWriter::new(File::create(out_path)?);
    writer.write_all(&body)?;
    writer.flush()?;

    fs::remove_file(path)?;

    Ok(())
}