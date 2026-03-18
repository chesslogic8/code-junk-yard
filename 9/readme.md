

# ascrypt

A very small experimental file encryption tool written in Rust.

This project is part of a personal collection of **simple "toy" encryption apps**.
Each app implements a different modern cryptographic algorithm but keeps the design intentionally minimal so the code is easy to read, study, and modify.

`ascrypt` uses the **Ascon-128a authenticated encryption algorithm**.

---

# Purpose

The goal of this project is learning and experimentation.

Design goals:

* extremely small codebase
* easy to read
* deterministic file format
* reliable file writing
* no configuration complexity
* encryption key compiled directly into the binary

These programs are **not meant for real security use**.
They are intended as educational tools and crypto experimentation.

---

# Algorithm: Ascon-128a

Ascon is a modern authenticated encryption algorithm designed for efficiency and strong security.

Important facts:

* Designed in 2014 by a team of cryptographers
* Selected in 2023 as the **NIST Lightweight Cryptography Standard**
* Optimized for small devices and embedded systems
* Uses a sponge-based permutation design

Ascon is especially good for:

* IoT devices
* microcontrollers
* constrained hardware
* high-reliability encryption

Even though it targets lightweight environments, it still provides **very strong modern cryptographic security**.

The `ascrypt` tool specifically uses **Ascon-128a**, a faster variant optimized for processing larger data.

Properties:

* 128-bit key
* 128-bit nonce
* authenticated encryption (AEAD)
* built-in tamper detection

If a file is modified or corrupted, decryption will fail.

---

# How It Works

Encryption workflow:

```
file.txt  →  file.ai
```

Decryption workflow:

```
file.ai   →  file.txt
```

The original file is **not deleted automatically**.
Both files remain so the user can verify results safely.

---

# File Format

Encrypted files contain a small header followed by ciphertext.

Structure:

```
MAGIC (4 bytes)
VERSION (1 byte)
extension length (1 byte)
original extension (0-32 bytes)
nonce (16 bytes)
original length (8 bytes)
ciphertext + authentication tag
```

The header stores the **original file extension**, so the program restores the correct filename during decryption.

Example:

```
photo.jpg → photo.ai
photo.ai  → photo.jpg
```

---

# Key Handling

For simplicity the encryption key is **hard-coded into the program**.

This allows the code to remain small and focused on the algorithm itself.

In real encryption software this would be replaced with:

* password derived keys
* key files
* hardware keys
* or secure key management

---

# Safety Features

Even though the program is simple, several reliability features are used:

* OS random number generator for nonces
* authenticated encryption (tamper detection)
* temporary file writes
* fsync before rename
* atomic file replacement

This prevents partially written output files if the program crashes.

---

# Building

Requires Rust.

```
cargo build --release
```

Binary will appear in:

```
target/release/ascrypt
```

---

# Usage

Encrypt a file:

```
ascrypt file.txt
```

Produces:

```
file.ai
```

Decrypt:

```
ascrypt file.ai
```

Restores:

```
file.txt
```

---

# Educational Goals

This project is part of a small "crypto zoo" of minimal tools implementing different algorithms.

Studying multiple algorithms in isolation helps demonstrate the differences between modern cipher designs.

Examples of algorithms in the collection include:

* block ciphers
* stream ciphers
* AEAD constructions
* sponge-based cryptography

Each program keeps the same philosophy:

```
simple
readable
self-contained
reliable
```

---

# Warning

This software is for **educational purposes only**.

Do not rely on it for protecting sensitive or important data.


