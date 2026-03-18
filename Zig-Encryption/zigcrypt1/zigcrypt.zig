const std = @import("std");

const magic: [8]u8 = "ZIGCRYPT".*;
const nonce_size = 24;
const tag_size = 16;
const key_size = 32;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.debug.print("Usage:\n  {s} keygen         -> generate key.key\n", .{args[0]});
        std.debug.print("  {s} <file>         -> encrypt/decrypt file\n", .{args[0]});
        return;
    }

    const cmd = args[1];
    const dir = std.fs.cwd();

    if (std.mem.eql(u8, cmd, "keygen")) {
        // Generate random key.key
        var key: [key_size]u8 = undefined;
        std.crypto.random.bytes(&key);

        // Create key.key
        var file = try dir.createFile("key.key", .{});
        defer file.close();
        try file.writeAll(&key);

        std.debug.print("Generated key.key (32 bytes)\n", .{});
        return;
    }

    // Otherwise, treat cmd as a filename
    const filename = cmd;

    var file = try dir.openFile(filename, .{});
    defer file.close();

    const stat = try file.stat();
    const size = stat.size;

    // Load key from key.key
    var key_file = try dir.openFile("key.key", .{});
    defer key_file.close();

    var key: [key_size]u8 = undefined;
    if (try key_file.readAll(&key) != key_size) {
        std.debug.print("key.key must be exactly 32 bytes\n", .{});
        return;
    }

    var is_encrypted = false;
    var nonce: [nonce_size]u8 = undefined;

    if (size > magic.len + nonce_size + tag_size) {
        var header: [magic.len + nonce_size]u8 = undefined;
        if (try file.readAll(&header) == header.len) {
            if (std.mem.eql(u8, header[0..magic.len], &magic)) {
                is_encrypted = true;
                @memcpy(&nonce, header[magic.len..]);
            }
        }
    }

    try file.seekTo(0);

    const temp_name = try std.fmt.allocPrint(allocator, "{s}.tmp", .{filename});
    defer allocator.free(temp_name);

    var temp_file = try dir.createFile(temp_name, .{});
    defer {
        temp_file.close();
        dir.deleteFile(temp_name) catch {};
    }

    const aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

    if (is_encrypted) {
        const cipher_len = size - magic.len - nonce_size - tag_size;
        const ciphertext = try allocator.alloc(u8, cipher_len);
        defer allocator.free(ciphertext);

        try file.seekTo(magic.len + nonce_size);
        if (try file.readAll(ciphertext) != cipher_len)
            return error.BadFile;

        var tag: [tag_size]u8 = undefined;
        if (try file.readAll(&tag) != tag_size)
            return error.BadFile;

        const plaintext = try allocator.alloc(u8, cipher_len);
        defer allocator.free(plaintext);

        try aead.decrypt(plaintext, ciphertext, tag, "", nonce, key);

        try temp_file.writeAll(plaintext);
        std.debug.print("File decrypted\n", .{});

    } else {
        std.crypto.random.bytes(&nonce);

        const plaintext = try allocator.alloc(u8, size);
        defer allocator.free(plaintext);

        if (try file.readAll(plaintext) != size)
            return error.BadFile;

        const ciphertext = try allocator.alloc(u8, size);
        defer allocator.free(ciphertext);

        var tag: [tag_size]u8 = undefined;

        aead.encrypt(ciphertext, &tag, plaintext, "", nonce, key);

        try temp_file.writeAll(&magic);
        try temp_file.writeAll(&nonce);
        try temp_file.writeAll(ciphertext);
        try temp_file.writeAll(&tag);

        std.debug.print("File encrypted\n", .{});
    }

    // Safe rename of temp file
    dir.rename(temp_name, filename) catch |err| {
        std.debug.print("Error renaming temp file: {}\n", .{err});
        return err;
    };
}
