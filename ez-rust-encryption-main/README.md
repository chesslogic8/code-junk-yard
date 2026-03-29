

# WARNING! Do NOT learn how to code. Just have ai code for you, it is WAY more EZ that way 

# EZ-RUST-ENCRYPTION-APPS


Do you think that more than one cli Command is just stupid? Do you think flags should not exist? How about thinking options are stupid? Did you ever want to eliminate the need for a Key file or even a Password? Well hell's bells, this repo is for you. Here, we do stuff the ez way!  ONE command for each app. Just the file name then it auto encrypts or decrypts ! No password or key needed, key is hard coded for each app! 



## Purpose

This repository is a learning and experimentation project exploring
many symmetric cryptographic algorithms implemented in Rust.

Each directory contains a small standalone encryption utility using
a different cipher but sharing the same file format and command-line
interface.






# Algorithms


# Algorithms

### [aes](aes)
**AES block cipher** (Advanced Encryption Standard).  
A NIST standardized symmetric cipher widely used for secure data encryption.

### [ascon](ascon)
**ASCON AEAD cipher**.  
Winner of the NIST Lightweight Cryptography competition, designed for constrained systems.

### [blake3](blake3)
**BLAKE3 cryptographic hash function** used as a fast modern hashing primitive.

### [blowctr](blowctr)
**Blowfish block cipher in CTR mode**.  
A classic symmetric cipher designed by Bruce Schneier.

### [cam](cam)
**Camellia-256-CTR block cipher**.  
NIST-approved alternative to AES with a completely different design and 20+ years with no practical attacks.

### [cha](cha)
**ChaCha20 stream cipher**.  
A modern high-performance cipher used in TLS and many modern protocols.

### [hc](hc)
**HC-128 stream cipher** from the eSTREAM project.  
Designed for high speed in software.

### [hc256](hc256)
**HC-256 stream cipher**.  
Direct successor to HC-128 (same eSTREAM family) with an even higher security margin.

### [idea](idea)
**IDEA block cipher** (International Data Encryption Algorithm).  
Classic 64-bit block cipher with 128-bit keys using the unique Lai-Massey scheme. Used in early PGP/OpenPGP.

### [isaac](isaac)
**ISAAC cryptographic pseudorandom generator** used as a keystream generator.

### [rabbit](rabbit)
**Rabbit stream cipher** (eSTREAM portfolio).  
Optimized for high-speed software encryption.

### [rxor](rxor)
**rxor XOR + rotate cipher**.  
Fast, lightweight, dependency-free rolling XOR + rotation cipher.

### [salsa](salsa)
**Salsa20 stream cipher**.  
Original eSTREAM winner and predecessor to ChaCha20 — extremely fast and still unbroken.

### [ser](ser)
**Serpent block cipher**.  
AES finalist designed for very strong security margins.

### [tf](tf)
**Twofish block cipher**.  
Another AES finalist designed by Bruce Schneier and colleagues.

### [trivium](trivium)
**Trivium stream cipher** from the eSTREAM project.  
Designed for extremely efficient hardware implementation.

### [xcha](xcha)
**XChaCha20 stream cipher**.  
Extended-nonce version of ChaCha20 allowing a very large nonce space.

### [xor](xor)
**Plain XOR**.  
Basic XOR cipher (many stronger variants exist, such as rolling XOR or XOR + rotate).

### [xorp](xorp)
**Rolling XOR + rotation cipher** (pure Rust, no crates).

### [xsalsa](xsalsa)
**XSalsa20 stream cipher**.  
Extended-nonce version of Salsa20 using a 192-bit nonce for safer random nonce usage.


### [rc6](rc6)
**RC6-256-CTR encryption tool.**






# files made with chatgpt and grok with the  following prompt 

Rust Version 1.94.1 + and 2024 edition +
Create a small Linux command-line encryption tool written in Rust. The program should be simple, reliable, and deterministic. Each tool implements one cipher but all tools must behave the same way and follow the same file format and interface. The application should use a hard-coded key, accept a single file argument, encrypt files to the .ai extension, and decrypt .ai files back to the original file type. The original extension must be stored in metadata so the correct filename can be restored during decryption.

The program must accept exactly one command argument: the name of the file to process. The usage format should look like ./toolname filename. For example: ./aes document.txt or ./aes document.ai. The program must not accept multiple arguments or interactive input. If no argument is given, it should return a usage error such as usage: aes <file>.

The program should only operate on files located in the same directory as the executable. Paths containing directories such as /, ../, or nested folders must be rejected. This prevents the program from modifying files outside the working directory and keeps the behavior predictable. The argument should therefore be treated as a simple filename, not a path.

The program determines whether to encrypt or decrypt based on the file extension. If the file extension is .ai, the program performs decryption. If the file extension is anything else, the program performs encryption. When encrypting a file, the output file must have the same base name but with the .ai extension. For example, file.txt becomes file.ai. When decrypting, the program must restore the original extension that was stored in the metadata so that file.ai becomes file.txt again.

The original file extension must be stored as metadata in the encrypted file. The extension length should be stored as a single byte followed by the extension string itself. Extensions longer than 32 bytes should be rejected to keep the format simple and predictable.

The encrypted file must store its metadata at the end of the file rather than at the beginning. The encrypted file layout should therefore be: ciphertext first, followed by a footer containing the metadata. Storing the metadata at the end helps avoid interfering with file signatures or executable headers and reduces the risk of breaking file formats if the file is inspected or partially processed.

The footer format should follow a consistent structure. After the ciphertext, write a four-byte magic value that uniquely identifies the tool or cipher. After the magic value, write the extension length byte and the extension string. Then write the random nonce used for encryption. Finally write the original file size as an unsigned 64-bit integer. This produces a footer layout that looks like: ciphertext, magic value, extension length, extension string, nonce, and original size.

Each encryption operation must generate a random nonce using the operating system random generator. The nonce size depends on the cipher being used. The nonce is stored in the footer so it can be used during decryption.

Each tool must use a hard-coded symmetric key defined as a constant inside the program. The key size depends on the cipher, but it should typically be either 16 bytes or 32 bytes. The key is intentionally embedded directly in the source code to keep the program simple and deterministic.

All file writes must be done using atomic replacement to prevent corruption if the program crashes. The program should first write the output to a temporary file using the same name but with a .tmp extension. After writing the file, it must call sync_all() to flush the contents to disk. Finally the temporary file should replace the final output file using a rename operation. This ensures that partially written files are never left behind.

The program should read the entire input file into memory before processing it. The logic of the program should remain simple and avoid unnecessary complexity. The structure of the code should generally include a main() function that handles argument parsing and decides whether to call encrypt() or decrypt(), along with separate functions implementing the encryption and decryption logic.

Every tool created under this system should share the same command behavior, file format structure, metadata footer layout, atomic file writing process, and same-directory safety rule. The only parts that change between tools are the cipher implementation, nonce size, key size, and the four-byte magic identifier used in the footer.

This design allows many small encryption tools to exist that all behave identically from the user's perspective while using different cryptographic algorithms internally.


Rust Version 1.94.1 + and 2024 edition +

