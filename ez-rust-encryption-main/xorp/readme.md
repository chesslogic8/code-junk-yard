
# xorp

`xorp` (XOR Pure Rust) is a small command-line tool written in Rust for encrypting and decrypting files using a custom **rolling XOR + rotation cipher**.

It is designed to be simple, dependency-free, and efficient, making it a good project for learning and experimentation.

---

# Features

* 🔐 Rolling XOR with feedback (each byte depends on the previous)
* 🔄 Bit rotation for additional diffusion
* 🔑 Static key with per-byte mixing
* 🎲 Random IV from `/dev/urandom`
* 📦 No external crates (pure Rust stdlib)
* ⚡ Streaming encryption (handles large files efficiently)
* 🧠 Automatic decrypt based on file extension
* 🏷️ Preserves original file extension
* 🧹 Replaces original file after processing

---

# How It Works

## Encryption

For each byte:

1. XOR with key and previous encrypted byte
2. Rotate bits left
3. Add key value

A random **IV (initialization vector)** is used as the starting “previous byte”.

---

## Decryption

The process is reversed:

1. Subtract key
2. Rotate bits right
3. XOR with key and previous byte

---

# File Format

Encrypted files use the `.ai` extension and store metadata:

```
[ IV (1 byte) ]
[ encrypted data ... ]
[ extension length (1 byte) ]
[ extension bytes ]
```

---

# Usage

Encrypt a file:

```bash
cargo run -- file.txt
```

Output:

```
file.ai
```

Decrypt:

```bash
cargo run -- file.ai
```

Restores the original file.

---

# Build

Debug build:

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

Binary location:

```
target/release/xorp
```

---

# Example

```bash
echo "hello world" > test.txt

cargo run -- test.txt
# → test.ai

cargo run -- test.ai
# → test.txt restored
```

---

# Differences from Basic XOR

Basic XOR encryption:

```
cipher[i] = plaintext[i] ^ key[i % key_len]
```

Problems:

* identical input produces identical output
* patterns remain visible
* each byte is independent

---

## xorp Improvements

* uses a random IV → different output each run
* each byte depends on the previous (feedback)
* includes bit rotation → better diffusion
* combines multiple operations per byte

---

# Limitations

* Not cryptographically secure (not a replacement for AES/ChaCha20)
* Decryption currently loads the full file into memory
* Uses `/dev/urandom` (Unix-only)
* No password-based key derivation

---

# Project Structure

```
xorp/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs
```

---

# Future Ideas

* Fully streaming decryption
* Cross-platform randomness support (Windows)
* CLI flags (`encrypt`, `decrypt`, `--output`)
* Password-based keys
* Stronger cipher implementations

---

# License

MIT

---


