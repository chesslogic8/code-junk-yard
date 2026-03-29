
# idea

**IDEA** (International Data Encryption Algorithm)  
A classic 64-bit block cipher with 128-bit keys, designed in 1991.  
It uses the unique **Lai-Massey scheme** (modular multiplication mod 65,537 + addition + XOR) — completely different math from AES, Serpent, Twofish, or any of the ARX/stream ciphers in this repo.  
It was the main cipher in early PGP/OpenPGP and is still considered solid and interesting for learning.

This tool is 100% compatible with every other binary in the repo:
- Same one-command interface
- Same `.ai` file format
- Same auto-restore of original extension
- Same atomic `.tmp` + `sync_all()` + rename (never leaves corrupted files)
- Same baked-in key (no passwords ever)
- Same “current directory only” safety

### How to use

```bash
# Encrypt
./idea myfile.txt
# → creates myfile.ai

# Decrypt
./idea myfile.ai
# → restores myfile.txt (original name + extension)
```

Works exactly like `blowctr`, `aes`, `ser`, etc.

### Build it

```bash
cd idea
cargo clean
cargo build --release
```

The binary will be at `./target/release/idea`  
(Already stripped, tiny, and optimized — ~600 KB on Linux)

Drop it in your `~/bin` or anywhere in PATH and you’re good.

