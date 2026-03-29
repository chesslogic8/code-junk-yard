
# xcha

**xcha** — The most dependable Rust CLI for encrypt-once, upload-anywhere, decrypt-guaranteed file protection.

One binary. One command. Zero configuration.  
**Encrypt locally → upload to any cloud → download later → get your exact original file back or a loud, clear error.**

Designed from the ground up around the single goal: *“decrypts for sure or fails explicitly — never silently corrupted data.”*

---

## Features

- Automatic encrypt/decrypt in **one command** (`xcha <file>`)
- Perfect round-trip: `report.txt` → `report.enc` → `report.txt` (original name + extension restored)
- Uses audited **XChaCha20-Poly1305** (fast, constant-time, misuse-resistant AEAD)
- **Double integrity guarantee**:
  - XChaCha20-Poly1305 authentication tag
  - Independent SHA-256 hash of the original plaintext (catches any cloud corruption)
- Versioned header-first format (robust parsing, early rejection on bad files)
- Atomic writes (`*.tmp` + `fsync` + `rename`) — never leaves partial or corrupted files
- Extremely strict error handling with clear messages
- Works with any file (including those with no extension)

## Building

```bash
cargo build --release
```
The binary will be at `target/release/xcha`.

(Or `cargo install --path .` to install globally.)

## Usage

```bash
# Encrypt any file
xcha myfile.txt          # → creates myfile.enc
xcha report.pdf          # → creates report.enc
xcha notes               # → creates notes.enc (no extension)

# Decrypt it back
xcha myfile.enc          # → restores myfile.txt
xcha report.enc          # → restores report.pdf
xcha notes.enc           # → restores notes
```

**Rules**:
- Files must be in the **current working directory** only.
- Never overwrites an existing output file.
- Success messages confirm what happened.

## Reliability Guarantee

This tool was built exactly to the spec we discussed:

- Header parsed from the front (no fragile footer math)
- Multiple independent checks: magic bytes + version + AEAD tag + plaintext hash
- If anything is wrong after a cloud download (bit flip, tampering, corruption), you get an explicit error like  
  `decryption failed (tampered, corrupted, or wrong key)` or  
  `data corruption detected — hash mismatch after decryption`
- No decrypted data is ever written to disk unless **every** check passes

Upload `myfile.enc` to S3, GCS, Dropbox, etc. Download it back — it will either be perfect or the tool will refuse to decrypt and tell you exactly why.

## Security Note (Important)

The master key is **hardcoded** in the binary for maximum simplicity and to eliminate all key-management errors (as per your request).  
This means:
- Anyone who obtains the `xcha` binary can decrypt your `.enc` files.
- The binary itself must be protected like any secret.

Perfect for personal use, backups, or moving files between your own machines/cloud accounts.  
**Not suitable** for sharing the binary or highly sensitive data that requires proper key management.

## Limitations

- Loads the entire file into memory (fine for most files; for multi-GB files we can add a streaming version later)
- Same-directory only (keeps the design simple and safe)
- No password or key file support (hardcoded by design)

---

**Drop this file as `README.md` in your project root.**  
It matches the exact code we built (version 1.0.0 with double integrity checks and `.enc` extension).

