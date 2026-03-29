

# cam

**Camellia-256-CTR** encryption tool.

A simple, fast, and reliable command-line utility that encrypts and decrypts files **in place** using the Camellia block cipher in CTR mode. Part of the [ez-rust-encryption](https://github.com/starmoon8/ez-rust-encryption) collection.

## Usage


./cam <filename>


- If the file does **not** end with `.ai` → **encrypts** it and creates `filename.ai`
- If the file **ends with** `.ai` → **decrypts** it back to the original filename + extension

No passwords, no flags, no extra arguments. Works only on files in the current directory.

## Build


cd cam
cargo build --release


The binary will be at `target/release/cam`.

## Requirements

- Rust **1.94.1** or higher
- Edition **2024**

## Features

- Uses **Camellia-256** (NIST-approved, completely different design from AES, 20+ years with no practical attacks)
- CTR mode with a fresh random nonce on every encryption
- Hard-coded key (for casual/personal use only)
- Atomic write via temp file + rename (safe, no partial overwrites)
- Preserves original file extension inside the `.ai` container
- Extremely simple one-command interface

## Security Note

This tool is designed for **informal / convenience encryption** only. It uses a fixed key and is **not** suitable for high-security or adversarial environments.

---

Made with the same rock-solid pattern as every other app in the collection.


