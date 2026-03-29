



# hc256

**HC-256** encryption tool.

A simple, fast, and reliable command-line utility that encrypts and decrypts files **in place** using the HC-256 stream cipher. Part of the [ez-rust-encryption](https://github.com/starmoon8/ez-rust-encryption) collection.

## Usage


./hc256 <filename>


- If the file does **not** end with `.ai` → **encrypts** it and creates `filename.ai`
- If the file **ends with** `.ai` → **decrypts** it back to the original filename + extension

**Important:** This tool **does not overwrite** existing files.  
If the output file (either `filename.ai` when encrypting or the original filename when decrypting) already exists, the operation will fail with an OS error (“No such file or directory”).  
Delete or rename the existing target file first if you need to re-encrypt/decrypt the same name.

No passwords, no flags, no extra arguments. Works only on files in the current directory.

## Build


cd hc256
cargo build --release


The binary will be at `target/release/hc256`.

## Requirements

- Rust **1.94.1** or higher
- Edition **2024**

## Features

- Uses **HC-256** (eSTREAM portfolio cipher, direct successor to the existing `hc` (HC-128) in this collection, even higher security margin)
- 256-bit key with a fresh random 256-bit nonce on every encryption
- Hard-coded key (for casual/personal use only)
- Atomic write via temp file + rename (no partial writes, no overwrite)
- Preserves original file extension inside the `.ai` container
- Extremely simple one-command interface

## Security Note

This tool is designed for **informal / convenience encryption** only. It uses a fixed key and is **not** suitable for high-security or adversarial environments.

---

Made with the same rock-solid pattern as every other app in the collection.


Just run this in your `hc256/` folder:


cat > README.md << 'EOF'
[paste the whole block above]
EOF


