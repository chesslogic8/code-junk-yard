


# salsa

**Salsa20** encryption tool.

A simple, fast, and reliable command-line utility that encrypts and decrypts files **in place** using the Salsa20 stream cipher. Part of the [ez-rust-encryption](https://github.com/starmoon8/ez-rust-encryption) collection.

## Usage

./salsa <filename>


- If the file does **not** end with `.ai` → **encrypts** it and creates `filename.ai`
- If the file **ends with** `.ai` → **decrypts** it back to the original filename + extension

**Important:** This tool **does not overwrite** existing files.  
If the output file (either `filename.ai` when encrypting or the original filename when decrypting) already exists, the operation will fail with an OS error (“No such file or directory”).  
Delete or rename the existing target file first if you need to re-encrypt/decrypt the same name.

No passwords, no flags, no extra arguments. Works only on files in the current directory.

## Build


cd salsa
cargo build --release


The binary will be at `target/release/salsa`.

## Requirements

- Rust **1.94.1** or higher
- Edition **2024**

## Features

- Uses **Salsa20** (original eSTREAM portfolio winner, predecessor to ChaCha20, extremely fast and still unbroken after 20+ years)
- 256-bit key with a fresh random 8-byte nonce on every encryption
- Hard-coded key (for casual/personal use only)
- Atomic write via temp file + rename (no partial writes, no overwrite)
- Preserves original file extension inside the `.ai` container
- Extremely simple one-command interface

## Security Note

This tool is designed for **informal / convenience encryption** only. It uses a fixed key and is **not** suitable for high-security or adversarial environments.





cat > README.md << 'EOF'
[paste the whole markdown block above]
EOF


