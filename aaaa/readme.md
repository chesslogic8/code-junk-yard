critical Bug (Needs Fix Before Next Release)
Directory decryption is broken for any folder containing non-.il files.

count_files(&files, true)filters for .il files when building the progress bar.
But collect_files_recursive returns every file, and the loop calls decrypt_file_to_path on all of them.
Result: every non-.il file produces an InvalidExtension error and the progress bar count is wrong.

Quick fix (in the Decrypt branch, inside the directory loop):
Rust// Replace this:
for source in dir_files {
    let prefix = format!(" Decrypting {} ... ", source.display());
    let result = decrypt_file_to_path(...);
    ...
}

// With this:
for source in dir_files {
    if source.extension().and_then(|e| e.to_str()) != Some(IRONLOCK_EXTENSION) {
        continue; // or log as skipped if you want
    }
    let prefix = format!(" Decrypting {} ... ", source.display());
    let result = decrypt_file_to_path(...);
    ...
}
You already filter correctly for the progress counter — just make the processing loop match it.
