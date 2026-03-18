

---

# ZigCrypt

**ZigCrypt** is a simple file encryption and decryption tool written in **Zig** using the **XChaCha20-Poly1305 AEAD** cipher. It allows you to securely encrypt files with a 32-byte key and ensures data integrity with authenticated encryption.

---

## Features

* Encrypts and decrypts files using **XChaCha20-Poly1305**.
* Detects if a file is already encrypted.
* Uses a **random nonce** for each encryption.
* Writes files atomically using a temporary file.
* Includes a **magic header** (`"ZIGCRYPT"`) to identify encrypted files.

---

## Requirements

* [Zig](https://ziglang.org/) >= 0.12
* No external dependencies.

---

## Usage

Compile the program:

```bash
zig build-exe zigcrypt.zig
```

Encrypt or decrypt a file:

```bash
./zigcrypt <file>
```

* If the file is **not encrypted**, it will be encrypted in-place.
* If the file is **already encrypted**, it will be decrypted in-place.

---

## Encryption Format

Encrypted files have the following structure:

```
[8 bytes magic header "ZIGCRYPT"]
[24 bytes nonce]
[ciphertext]
[16 bytes authentication tag]
```

* **Nonce** is randomly generated for each encryption.
* **Tag** ensures data integrity and authentication.

---

## Key

Currently, the program uses a **hardcoded 32-byte key**.
⚠ **Important:** Change the key before compiling for security purposes:

```zig
const key: [32]u8 = [_]u8{
    0x3a, 0xf1, 0x7c, 0x2b, 0x9d, 0xe4, 0x6a, 0x81,
    0x5f, 0x12, 0xbc, 0x90, 0x44, 0x6e, 0xd7, 0x29,
    0x8a, 0xcf, 0x01, 0x55, 0x3b, 0x72, 0xe9, 0xd0,
    0x16, 0xa3, 0x4f, 0x88, 0xbe, 0x67, 0x9e, 0x0c
};
```

---

## Security Notes

* Hardcoding keys is **not secure** for production.
* For better security, consider using a **password-based key derivation function (KDF)** like Argon2 or HKDF.
* Sensitive data is temporarily stored in memory; avoid running on untrusted machines.
* Temporary files are used during encryption/decryption and are deleted on completion, but crashes may leave them behind.

---

## Example

Encrypt a file `secret.txt`:

```bash
./zigcrypt secret.txt
```

Output:

```
File encrypted
```

Decrypt the same file:

```bash
./zigcrypt secret.txt
```

Output:

```
File decrypted
```

---

## License

MIT License. Use at your own risk.

---


Do you want me to do that next?


