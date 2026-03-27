use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::fs;
use std::fs::OpenOptions;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum IronlockError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Invalid file extension: expected .il for decryption")]
    InvalidExtension,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: incorrect password or corrupted file")]
    DecryptionFailed,

    #[error("Invalid file format: not a valid Ironlock encrypted file")]
    InvalidFileFormat,

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Passwords do not match")]
    PasswordMismatch,

    #[error("Password cannot be empty")]
    EmptyPassword,

    #[error("Secure deletion failed: {0}")]
    SecureDeletionFailed(String),

    #[error("Not a directory: {0}")]
    NotADirectory(String),

    #[error("Operation cancelled by user")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, IronlockError>;

// ====================== CLI ======================

#[derive(Parser, Debug)]
#[command(name = "ironlock")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt one or more files
    ///
    /// Files will be encrypted and saved with the .il extension.
    /// Original files are preserved (not deleted).
    /// If no files are specified, reads from stdin and writes to stdout.
    #[command(visible_alias = "enc", visible_alias = "e")]
    Encrypt {
        /// Files to encrypt (reads from stdin if omitted)
        #[arg(num_args = 0..)]
        files: Vec<PathBuf>,

        /// Force overwrite without prompting if output file exists
        #[arg(short, long, default_value_t = false)]
        force: bool,

        /// Securely delete original files after encryption (overwrites with random data)
        #[arg(short = 's', long, visible_alias = "delete", default_value_t = false)]
        shred: bool,

        /// Show a progress bar when processing multiple files
        #[arg(short, long, default_value_t = false)]
        progress: bool,
    },

    /// Decrypt one or more .il files
    ///
    /// Files will be decrypted and restored to their original format.
    /// If no files are specified, reads from stdin and writes to stdout.
    #[command(visible_alias = "dec", visible_alias = "d")]
    Decrypt {
        /// Files to decrypt (reads from stdin if omitted)
        #[arg(num_args = 0..)]
        files: Vec<PathBuf>,

        /// Output directory for decrypted files (defaults to current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Force overwrite without prompting if output file exists
        #[arg(short, long, default_value_t = false)]
        force: bool,

        /// Show a progress bar when processing multiple files
        #[arg(short, long, default_value_t = false)]
        progress: bool,
    },
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}

// ====================== MEMORY LOCKING ======================

/// Attempts to lock a memory region to prevent it from being swapped to disk.
/// This is a best-effort operation — failures are silently ignored.
#[cfg(unix)]
pub fn mlock_slice(data: &[u8]) {
    unsafe {
        libc::mlock(data.as_ptr() as *const libc::c_void, data.len());
    }
}

#[cfg(not(unix))]
pub fn mlock_slice(_data: &[u8]) {
    // No-op on non-Unix platforms
}

// ====================== CRYPTO ======================

pub const MAGIC_BYTES: &[u8; 8] = b"IRONLOCK";
pub const FORMAT_VERSION: u8 = 1;
pub const SALT_LENGTH: usize = 16;
pub const NONCE_LENGTH: usize = 12;
pub const KEY_LENGTH: usize = 32;

const ARGON2_MEMORY_KIB: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub fn current() -> Self {
        Self {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
        }
    }
}

pub fn derive_key_from_password(
    password: &[u8],
    salt: &[u8],
    kdf_params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    let params = Params::new(
        kdf_params.memory_kib,
        kdf_params.iterations,
        kdf_params.parallelism,
        Some(KEY_LENGTH),
    )
    .map_err(|e| IronlockError::EncryptionFailed(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| IronlockError::EncryptionFailed(format!("Key derivation failed: {}", e)))?;

    mlock_slice(key.as_ref());
    Ok(key)
}

pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| IronlockError::EncryptionFailed(format!("Cipher init failed: {}", e)))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| IronlockError::EncryptionFailed(format!("Encryption failed: {}", e)))
}

pub fn decrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| IronlockError::DecryptionFailed)?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| IronlockError::DecryptionFailed)
}

pub fn create_encrypted_file(
    password: &[u8],
    original_filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    create_encrypted_file_with_params(password, original_filename, plaintext, &KdfParams::current())
}

pub fn create_encrypted_file_with_params(
    password: &[u8],
    original_filename: &str,
    plaintext: &[u8],
    kdf_params: &KdfParams,
) -> Result<Vec<u8>> {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let key = derive_key_from_password(password, &salt, kdf_params)?;

    let filename_bytes = original_filename.as_bytes();
    let filename_len = filename_bytes.len() as u16;

    let mut header = Vec::with_capacity(51 + filename_len as usize);
    header.extend_from_slice(MAGIC_BYTES);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(&kdf_params.memory_kib.to_be_bytes());
    header.extend_from_slice(&kdf_params.iterations.to_be_bytes());
    header.extend_from_slice(&kdf_params.parallelism.to_be_bytes());
    header.extend_from_slice(&filename_len.to_be_bytes());
    header.extend_from_slice(filename_bytes);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let ciphertext = encrypt(&key, &nonce, plaintext, &header)?;

    let mut encrypted_file = header;
    encrypted_file.extend_from_slice(&ciphertext);
    Ok(encrypted_file)
}

pub fn decrypt_file(password: &[u8], encrypted_data: &[u8]) -> Result<(String, Vec<u8>)> {
    if encrypted_data.len() < 51 {
        return Err(IronlockError::InvalidFileFormat);
    }

    let magic = &encrypted_data[0..8];
    if magic != MAGIC_BYTES {
        return Err(IronlockError::InvalidFileFormat);
    }

    let version = encrypted_data[8];
    if version != FORMAT_VERSION {
        return Err(IronlockError::InvalidFileFormat);
    }

    let memory_kib = u32::from_be_bytes([encrypted_data[9], encrypted_data[10], encrypted_data[11], encrypted_data[12]]);
    let iterations = u32::from_be_bytes([encrypted_data[13], encrypted_data[14], encrypted_data[15], encrypted_data[16]]);
    let parallelism = u32::from_be_bytes([encrypted_data[17], encrypted_data[18], encrypted_data[19], encrypted_data[20]]);

    let filename_len = u16::from_be_bytes([encrypted_data[21], encrypted_data[22]]) as usize;
    let header_end = 23 + filename_len + SALT_LENGTH + NONCE_LENGTH;

    if encrypted_data.len() < header_end + 16 {
        return Err(IronlockError::InvalidFileFormat);
    }

    let filename_bytes = &encrypted_data[23..23 + filename_len];
    let filename = String::from_utf8_lossy(filename_bytes).to_string();

    let salt = &encrypted_data[23 + filename_len..23 + filename_len + SALT_LENGTH];
    let nonce_bytes = &encrypted_data[23 + filename_len + SALT_LENGTH..header_end];
    let ciphertext = &encrypted_data[header_end..];

    let kdf_params = KdfParams {
        memory_kib,
        iterations,
        parallelism,
    };

    let key = derive_key_from_password(password, salt, &kdf_params)?;

    let mut nonce = [0u8; NONCE_LENGTH];
    nonce.copy_from_slice(nonce_bytes);

    let plaintext = decrypt(&key, &nonce, ciphertext, &encrypted_data[0..header_end])?;

    Ok((filename, plaintext))
}

// ====================== FILE OPS ======================

pub const IRONLOCK_EXTENSION: &str = "il";

const LARGE_FILE_THRESHOLD: u64 = 1024 * 1024 * 1024;

pub fn prompt_confirmation(message: &str) -> Result<bool> {
    print!("{} [y/N]: ", message);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let response = input.trim().to_lowercase();
    Ok(response == "y" || response == "yes")
}

pub fn check_overwrite(path: &Path, force: bool) -> Result<()> {
    if path.exists() {
        if force {
            return Ok(());
        }
        let prompt = format!("File '{}' already exists. Overwrite?", path.display());
        if prompt_confirmation(&prompt)? {
            Ok(())
        } else {
            Err(IronlockError::Cancelled)
        }
    } else {
        Ok(())
    }
}

pub fn secure_delete(path: &Path) -> Result<()> {
    use std::io::Seek;

    let file_size = fs::metadata(path)
        .map_err(|e| IronlockError::SecureDeletionFailed(format!("failed to read metadata: {}", e)))?
        .len() as usize;

    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| IronlockError::SecureDeletionFailed(format!("failed to open file: {}", e)))?;

    let mut random_data = vec![0u8; file_size];

    for _ in 0..3 {
        OsRng.fill_bytes(&mut random_data);

        file.seek(std::io::SeekFrom::Start(0))
            .map_err(|e| IronlockError::SecureDeletionFailed(format!("failed to seek file: {}", e)))?;

        file.write_all(&random_data)
            .map_err(|e| IronlockError::SecureDeletionFailed(format!("failed to overwrite file: {}", e)))?;

        file.flush()
            .map_err(|e| IronlockError::SecureDeletionFailed(format!("failed to flush file: {}", e)))?;

        file.sync_all()
            .map_err(|e| IronlockError::SecureDeletionFailed(format!("failed to sync file: {}", e)))?;
    }

    drop(file);
    fs::remove_file(path)
        .map_err(|e| IronlockError::SecureDeletionFailed(format!("failed to delete file: {}", e)))?;

    Ok(())
}

pub fn collect_files_recursive(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if !dir.is_dir() {
        return Err(IronlockError::NotADirectory(dir.display().to_string()));
    }
    for entry in fs::read_dir(dir)? {
        let entry: fs::DirEntry = entry?;
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        } else if path.is_dir() {
            files.extend(collect_files_recursive(&path)?);
        }
    }
    Ok(files)
}

pub fn encrypt_file(
    source_path: &Path,
    password: &[u8],
    force: bool,
    shred: bool,
) -> Result<PathBuf> {
    let original_filename = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| IronlockError::IoError(io::Error::new(io::ErrorKind::InvalidInput, "Invalid filename")))?;

    let file_stem = source_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| IronlockError::IoError(io::Error::new(io::ErrorKind::InvalidInput, "Invalid filename")))?
        .to_string();

    let output_path = source_path
        .parent()
        .map(|p| p.join(format!("{}.{}", file_stem, IRONLOCK_EXTENSION)))
        .unwrap_or_else(|| PathBuf::from(format!("{}.{}", file_stem, IRONLOCK_EXTENSION)));

    check_overwrite(&output_path, force)?;

    if let Ok(metadata) = fs::metadata(source_path) {
        let size = metadata.len();
        if size > LARGE_FILE_THRESHOLD {
            eprintln!(
                "Warning: '{}' is {:.1} GiB — Ironlock loads the entire file into memory. \
                 Ensure you have enough RAM or use stdin piping for very large files.",
                source_path.display(),
                size as f64 / (1024.0 * 1024.0 * 1024.0)
            );
        }
    }

    let plaintext = fs::read(source_path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            IronlockError::FileNotFound(source_path.display().to_string())
        } else {
            IronlockError::IoError(e)
        }
    })?;

    let encrypted = create_encrypted_file(password, original_filename, &plaintext)?;

    fs::write(&output_path, encrypted)?;

    if shred {
        secure_delete(source_path)?;
    }

    Ok(output_path)
}

pub fn decrypt_file_to_path(
    source_path: &Path,
    password: &[u8],
    output_dir: Option<&Path>,
    force: bool,
) -> Result<PathBuf> {
    let extension = source_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    if extension != IRONLOCK_EXTENSION {
        return Err(IronlockError::InvalidExtension);
    }

    if let Ok(metadata) = fs::metadata(source_path) {
        let size = metadata.len();
        if size > LARGE_FILE_THRESHOLD {
            eprintln!(
                "Warning: '{}' is {:.1} GiB — Ironlock loads the entire file into memory. \
                 Ensure you have enough RAM or use stdin piping for very large files.",
                source_path.display(),
                size as f64 / (1024.0 * 1024.0 * 1024.0)
            );
        }
    }

    let encrypted_data = fs::read(source_path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            IronlockError::FileNotFound(source_path.display().to_string())
        } else {
            IronlockError::IoError(e)
        }
    })?;

    let (original_filename, plaintext) = decrypt_file(password, &encrypted_data)?;

    let safe_filename = Path::new(&original_filename)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| IronlockError::IoError(io::Error::new(io::ErrorKind::InvalidInput, "Invalid or empty filename in encrypted file")))?
        .to_string();

    let output_dir = output_dir.unwrap_or_else(|| Path::new("."));
    let output_path = output_dir.join(safe_filename);

    check_overwrite(&output_path, force)?;

    fs::write(&output_path, plaintext)?;

    Ok(output_path)
}

// ====================== MAIN LOGIC ======================

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{}", prompt);
    io::stderr().flush()?;

    let password =
        rpassword::read_password().map_err(|e| IronlockError::IoError(io::Error::other(e)))?;

    mlock_slice(password.as_bytes());

    Ok(Zeroizing::new(password))
}

fn prompt_password_with_confirm() -> Result<Zeroizing<String>> {
    let password = prompt_password("Enter password: ")?;

    if password.is_empty() {
        return Err(IronlockError::EmptyPassword);
    }

    let confirm = prompt_password("Confirm password: ")?;

    if *password != *confirm {
        return Err(IronlockError::PasswordMismatch);
    }

    Ok(password)
}

fn prompt_password_decrypt() -> Result<Zeroizing<String>> {
    let password = prompt_password("Enter password: ")?;

    if password.is_empty() {
        return Err(IronlockError::EmptyPassword);
    }

    Ok(password)
}

fn encrypt_stdin(password: &[u8]) -> Result<()> {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    let encrypted = create_encrypted_file(password, "stdin", &data)?;
    io::stdout().write_all(&encrypted)?;
    Ok(())
}

fn decrypt_stdin(password: &[u8]) -> Result<()> {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    let (_filename, plaintext) = decrypt_file(password, &data)?;
    io::stdout().write_all(&plaintext)?;
    Ok(())
}

fn require_piped_stdin() {
    if io::stdin().is_terminal() {
        eprintln!(
            "{} No files specified. Pipe data to stdin or provide file paths.",
            "Error:".red().bold()
        );
        std::process::exit(1);
    }
}

fn count_files(files: &[PathBuf], filter_lb: bool) -> u64 {
    let mut count: u64 = 0;
    for path in files {
        if path.is_dir() {
            if let Ok(dir_files) = collect_files_recursive(path) {
                if filter_lb {
                    count += dir_files
                        .iter()
                        .filter(|f| {
                            f.extension().and_then(|e| e.to_str()) == Some(IRONLOCK_EXTENSION)
                        })
                        .count() as u64;
                } else {
                    count += dir_files.len() as u64;
                }
            } else {
                count += 1;
            }
        } else {
            count += 1;
        }
    }
    count
}

fn make_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("=> "),
    );
    pb
}

struct Counters {
    success: usize,
    errors: usize,
    skipped: usize,
    pb: Option<ProgressBar>,
}

impl Counters {
    fn new(pb: Option<ProgressBar>) -> Self {
        Self {
            success: 0,
            errors: 0,
            skipped: 0,
            pb,
        }
    }

    fn output(&self, msg: &str) {
        match &self.pb {
            Some(pb) => pb.println(msg),
            None => println!("{}", msg),
        }
    }

    fn handle_result(
        &mut self,
        prefix: &str,
        result: std::result::Result<PathBuf, IronlockError>,
        shred: bool,
    ) {
        let suffix = match &result {
            Ok(output_path) => {
                if shred {
                    format!(
                        "{} → {} (original securely deleted)",
                        "Checkmark".green(),
                        output_path.display()
                    )
                } else {
                    format!("{} → {}", "Checkmark".green(), output_path.display())
                }
            }
            Err(IronlockError::Cancelled) => format!("{}", "skipped".yellow()),
            Err(IronlockError::DecryptionFailed) => {
                format!("{} incorrect password or corrupted file", "Cross".red())
            }
            Err(e) => format!("{} {}", "Cross".red(), e),
        };

        self.output(&format!("{}{}", prefix, suffix));

        match &result {
            Ok(_) => self.success += 1,
            Err(IronlockError::Cancelled) => self.skipped += 1,
            Err(_) => self.errors += 1,
        }

        if let Some(ref pb) = self.pb {
            pb.inc(1);
        }
    }

    fn handle_dir_error(&mut self, e: IronlockError) {
        self.output(&format!("{} {}", "Cross".red(), e));
        self.errors += 1;
    }

    fn print_summary(&self, operation: &str) {
        if let Some(ref pb) = self.pb {
            pb.finish_and_clear();
        }
        println!();
        if self.errors == 0 && self.skipped == 0 {
            println!(
                "{} {} file(s) {} successfully",
                "Checkmark".green(),
                self.success,
                operation,
            );
        } else {
            println!(
                "{} {} succeeded, {} failed, {} skipped",
                "Warning".yellow(),
                self.success,
                self.errors,
                self.skipped
            );
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Commands::Encrypt {
            files,
            force,
            shred,
            progress,
        } => {
            if files.is_empty() {
                require_piped_stdin();
                let password = prompt_password_with_confirm()?;
                eprintln!();
                encrypt_stdin(password.as_bytes())?;
            } else {
                println!("{}", "Ironlock Encryption".cyan().bold());
                println!();

                let password = prompt_password_with_confirm()?;
                println!();

                let pb = if progress {
                    Some(make_progress_bar(count_files(&files, false)))
                } else {
                    None
                };
                let mut counters = Counters::new(pb);

                for file_path in &files {
                    if file_path.is_dir() {
                        counters
                            .output(&format!("Encrypting directory {} ...", file_path.display()));
                        match collect_files_recursive(file_path) {
                            Ok(dir_files) => {
                                for source in dir_files {
                                    let prefix = format!("  Encrypting {} ... ", source.display());
                                    let result =
                                        encrypt_file(&source, password.as_bytes(), force, shred);
                                    counters.handle_result(&prefix, result, shred);
                                }
                            }
                            Err(e) => counters.handle_dir_error(e),
                        }
                    } else {
                        let prefix = format!("Encrypting {} ... ", file_path.display());
                        let result = encrypt_file(file_path, password.as_bytes(), force, shred);
                        counters.handle_result(&prefix, result, shred);
                    }
                }

                counters.print_summary("encrypted");
            }
        }

        Commands::Decrypt {
            files,
            output,
            force,
            progress,
        } => {
            if files.is_empty() {
                require_piped_stdin();
                let password = prompt_password_decrypt()?;
                eprintln!();
                decrypt_stdin(password.as_bytes())?;
            } else {
                println!("{}", "Ironlock Decryption".cyan().bold());
                println!();

                let password = prompt_password_decrypt()?;
                println!();

                let pb = if progress {
                    Some(make_progress_bar(count_files(&files, true)))
                } else {
                    None
                };
                let mut counters = Counters::new(pb);

                for file_path in &files {
                    if file_path.is_dir() {
                        counters
                            .output(&format!("Decrypting directory {} ...", file_path.display()));
                        match collect_files_recursive(file_path) {
                            Ok(dir_files) => {
                                for source in dir_files {
                                    let prefix = format!("  Decrypting {} ... ", source.display());
                                    let result = decrypt_file_to_path(
                                        &source,
                                        password.as_bytes(),
                                        output.as_deref(),
                                        force,
                                    );
                                    counters.handle_result(&prefix, result, false);
                                }
                            }
                            Err(e) => counters.handle_dir_error(e),
                        }
                    } else {
                        let prefix = format!("Decrypting {} ... ", file_path.display());
                        let result = decrypt_file_to_path(
                            file_path,
                            password.as_bytes(),
                            output.as_deref(),
                            force,
                        );
                        counters.handle_result(&prefix, result, false);
                    }
                }

                counters.print_summary("decrypted");
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}