

# rxor

`rxor` is a lightweight Rust command-line tool for encrypting and decrypting files using a **rolling XOR + rotate cipher** with a random initialization vector (IV).

It is designed to be:

* fast ⚡
* dependency-free 📦
* memory-efficient 🧠
* simple to use 🛠️

---

# Features

* 🔐 Custom stream cipher (rolling XOR + rotation + key mixing)
* 🎲 Random IV from `/dev/urandom` (different output every run)
* 📦 No external crates (pure Rust stdlib)
* 💾 Streaming I/O (handles large files efficiently)
* 🔁 Symmetric encryption (same command encrypts/decrypts)
* 🏷️ Preserves original file extension
* 🧹 Replaces original file automatically

---

# How It Works

Each byte is transformed using a combination of:

1. XOR with a key
2. Feedback from the previous encrypted byte
3. Bit rotation
4. Key-based addition

```text
plaintext
   ↓
XOR with key + previous byte
   ↓
bit rotation
   ↓
add key
   ↓
ciphertext
```

Additionally:

* A **random IV (1 byte)** is generated from `/dev/urandom`
* The IV is stored at the beginning of the file
* The original file extension is stored at the end

---

# File Format

Encrypted `.ai` file structure:

```text
[ IV (1 byte) ]
[ encrypted data ... ]
[ extension length (1 byte) ]
[ extension bytes ]
```

---

# Why This Is Better Than Basic XOR

Basic XOR:

```text
cipher[i] = plaintext[i] XOR key[i % key_len]
```

Problems:

* patterns remain visible
* identical inputs → identical outputs
* easy to analyze

---

## rxor Improvements

| Feature            | Basic XOR | rxor            |
| ------------------ | --------- | --------------- |
| Pattern leakage    | High      | Low             |
| Random output      | ❌ No      | ✅ Yes (IV)      |
| Byte independence  | Yes       | No (feedback)   |
| Bit diffusion      | None      | Yes (rotation)  |
| Large file support | Yes       | Yes (streaming) |

---

# Important Note

This is **not a replacement for modern cryptography** like AES or ChaCha20.

It is intended for:

* obfuscation
* learning purposes
* lightweight protection
* CTF challenges
* tooling experiments

---

# Usage

Encrypt a file:

```bash
cargo run -- file.txt
```

Output:

```text
file.ai
```

Decrypt:

```bash
cargo run -- file.ai
```

Restores the original file.

---

# Build

```bash
cargo build --release
```

Binary:

```text
target/release/rxor
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

# Project Structure

```text
rxor/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs
```

---

# Platform Notes

* Uses `/dev/urandom` for randomness
* Works on Linux and macOS
* Not currently Windows-compatible (without changes)

---

# Future Improvements

* Cross-platform randomness (Windows support)
* CLI flags (`encrypt`, `decrypt`, `--output`)
* Directory encryption
* Stronger cipher (ChaCha20 backend)
* Password-based key derivation

---

# License

MIT

---

When you're ready, next step I’ll show:

👉 a **new app** that uses `/dev/urandom` cleanly but also
👉 works cross-platform and is even more “Unix tool”-like

Just say go 👍
