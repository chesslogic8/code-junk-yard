

# ZigCrypt1

**ZigCrypt** is a simple file encryption/decryption tool using **XChaCha20-Poly1305 AEAD**.
It supports **generating a key** and **encrypting/decrypting files** in a single executable.

---

## Features

* Single executable for **key generation** and **file encryption/decryption**.
* Uses a **32-byte `key.key` file** for encryption keys.
* Prevents accidental key overwrite — `keygen` is explicit.
* Safe temporary file handling to avoid panics or corrupted files.

---

## Requirements

* Zig **0.15.2** (Windows, Linux, macOS tested)
* Standard C runtime libraries

---

## Usage

### 1. Generate a Key

```cmd
zigcrypt.exe keygen
```

This will create a `key.key` file in the same directory as the executable.

> ⚠ **Do not share `key.key`** — anyone with this key can decrypt your files.

---

### 2. Encrypt a File

```cmd
zigcrypt.exe myfile.txt
```

* Encrypts `myfile.txt` in-place.
* Creates a temporary file during encryption to prevent data loss.
* Adds a magic header, nonce, ciphertext, and authentication tag.

---

### 3. Decrypt a File

```cmd
zigcrypt.exe myfile.txt
```

* Detects if the file is encrypted (via the magic header).
* Decrypts in-place using the same `key.key`.

> ⚠ The file must be encrypted with the **same `key.key`**.
> ⚠ Will fail if `key.key` is missing or corrupted.

---

## File Format

Encrypted files have the following structure:

| Part       | Size     | Description                 |
| ---------- | -------- | --------------------------- |
| Magic      | 8 bytes  | `"ZIGCRYPT"` identifier     |
| Nonce      | 24 bytes | Random nonce for AEAD       |
| Ciphertext | variable | Encrypted file content      |
| Auth Tag   | 16 bytes | Poly1305 authentication tag |

---

## Safety Notes

* `key.key` is **required** for all encrypt/decrypt operations.
* Temporary `.tmp` files are used to prevent file corruption.
* If an operation fails, the temporary file is deleted automatically.

---

## Example Workflow

```cmd
zigcrypt.exe keygen            # generate key.key
zigcrypt.exe example.txt       # encrypt example.txt
zigcrypt.exe example.txt       # decrypt example.txt
```

---

## License

Free to use for personal and educational purposes.

---


