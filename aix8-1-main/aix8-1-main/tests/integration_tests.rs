use aix8_lib::{decrypt, encrypt};
use rand::{Rng, RngCore};
use std::fs;
use std::io::Write;
use std::thread;
use std::time::Instant;
use tempdir::TempDir;

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn roundtrip_empty_file() {
let dir = TempDir::new("aix8").unwrap();


let input = dir.path().join("empty.txt");
let enc = dir.path().join("empty.ai");
let tmp = dir.path().join("tmp");

fs::write(&input, b"").unwrap();

encrypt(&input, &enc, PASSWORD).unwrap();

let ext = decrypt(&enc, &tmp, PASSWORD).unwrap();
let out = dir.path().join(format!("out.{}", ext));
fs::rename(&tmp, &out).unwrap();

assert_eq!(fs::read(&out).unwrap(), b"");


}

#[test]
fn roundtrip_small_file() {
let dir = TempDir::new("aix8").unwrap();


let input = dir.path().join("small.txt");
let enc = dir.path().join("small.ai");
let tmp = dir.path().join("tmp");

fs::write(&input, b"hello secure world").unwrap();

encrypt(&input, &enc, PASSWORD).unwrap();

let ext = decrypt(&enc, &tmp, PASSWORD).unwrap();
let out = dir.path().join(format!("out.{}", ext));
fs::rename(&tmp, &out).unwrap();

assert_eq!(fs::read(&out).unwrap(), b"hello secure world");


}

#[test]
fn roundtrip_random_data() {
let dir = TempDir::new("aix8").unwrap();
let mut rng = rand::thread_rng();


for _ in 0..100 {
    let size = rng.gen_range(0..1_000_000);

    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);

    let input = dir.path().join("rand.bin");
    let enc = dir.path().join("rand.ai");
    let tmp = dir.path().join("tmp");

    fs::write(&input, &data).unwrap();

    encrypt(&input, &enc, PASSWORD).unwrap();

    let ext = decrypt(&enc, &tmp, PASSWORD).unwrap();
    let out = dir.path().join(format!("out.{}", ext));
    fs::rename(&tmp, &out).unwrap();

    assert_eq!(fs::read(&out).unwrap(), data);
}


}

#[test]
fn wrong_password_fails() {
let dir = TempDir::new("aix8").unwrap();


let input = dir.path().join("data.txt");
let enc = dir.path().join("data.ai");
let tmp = dir.path().join("tmp");

fs::write(&input, b"secret").unwrap();

encrypt(&input, &enc, PASSWORD).unwrap();

assert!(decrypt(&enc, &tmp, "wrong password").is_err());


}

#[test]
fn corruption_detection() {
let dir = TempDir::new("aix8").unwrap();


let input = dir.path().join("data.txt");
let enc = dir.path().join("data.ai");
let tmp = dir.path().join("tmp");

fs::write(&input, b"important").unwrap();

encrypt(&input, &enc, PASSWORD).unwrap();

let mut bytes = fs::read(&enc).unwrap();
let mid = bytes.len() / 2;
bytes[mid] ^= 0xFF;

fs::write(&enc, bytes).unwrap();

assert!(decrypt(&enc, &tmp, PASSWORD).is_err());


}

#[test]
fn truncated_ciphertext_fails() {
let dir = TempDir::new("aix8").unwrap();


let input = dir.path().join("data.txt");
let enc = dir.path().join("data.ai");
let tmp = dir.path().join("tmp");

fs::write(&input, b"truncate test").unwrap();

encrypt(&input, &enc, PASSWORD).unwrap();

let mut bytes = fs::read(&enc).unwrap();
bytes.truncate(bytes.len() / 2);

fs::write(&enc, bytes).unwrap();

assert!(decrypt(&enc, &tmp, PASSWORD).is_err());


}

#[test]
fn repeated_encryption_uniqueness() {
let dir = TempDir::new("aix8").unwrap();


let input = dir.path().join("data.txt");
fs::write(&input, b"same plaintext").unwrap();

let mut ciphertexts = Vec::new();

for i in 0..10 {
    let enc = dir.path().join(format!("out{i}.ai"));
    encrypt(&input, &enc, PASSWORD).unwrap();
    ciphertexts.push(fs::read(enc).unwrap());
}

for i in 0..ciphertexts.len() {
    for j in i + 1..ciphertexts.len() {
        assert_ne!(ciphertexts[i], ciphertexts[j]);
    }
}


}

#[test]
fn parallel_encryption_stress() {
let mut handles = Vec::new();


for _ in 0..8 {
    handles.push(thread::spawn(|| {
        let dir = TempDir::new("aix8").unwrap();
        let mut rng = rand::thread_rng();

        for _ in 0..60 {
            let size = rng.gen_range(0..1_000_000);

            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);

            let input = dir.path().join("data.bin");
            let enc = dir.path().join("data.ai");
            let tmp = dir.path().join("tmp");

            fs::write(&input, &data).unwrap();

            encrypt(&input, &enc, PASSWORD).unwrap();

            let ext = decrypt(&enc, &tmp, PASSWORD).unwrap();
            let out = dir.path().join(format!("out.{}", ext));
            fs::rename(&tmp, &out).unwrap();

            assert_eq!(fs::read(&out).unwrap(), data);
        }
    }));
}

for h in handles {
    h.join().unwrap();
}


}

#[test]
#[ignore]
fn massive_10gb_streaming_torture_test() {
let dir = TempDir::new("aix8_big").unwrap();


let input = dir.path().join("huge.bin");
let enc = dir.path().join("huge.ai");
let tmp = dir.path().join("tmp");

let size = 10 * 1024 * 1024 * 1024usize;

let mut rng = rand::thread_rng();
let mut file = fs::File::create(&input).unwrap();

let mut remaining = size;
let mut buffer = [0u8; 8192];

while remaining > 0 {
    let chunk = remaining.min(buffer.len());
    rng.fill_bytes(&mut buffer[..chunk]);
    file.write_all(&buffer[..chunk]).unwrap();
    remaining -= chunk;
}

encrypt(&input, &enc, PASSWORD).unwrap();

let ext = decrypt(&enc, &tmp, PASSWORD).unwrap();
let out = dir.path().join(format!("huge_out.{}", ext));
fs::rename(&tmp, &out).unwrap();

let original = fs::read(&input).unwrap();
let decrypted = fs::read(&out).unwrap();

assert_eq!(original, decrypted);


}
