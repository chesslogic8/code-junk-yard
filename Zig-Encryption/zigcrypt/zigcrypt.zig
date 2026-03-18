const std = @import("std");

const magic: [8]u8 = "ZIGCRYPT".*;
const nonce_size = 24;
const tag_size = 16;

// Full 32-byte “random” key (change before compiling)
const key: [32]u8 = [_]u8{
    0x3a, 0xf1, 0x7c, 0x2b, 0x9d, 0xe4, 0x6a, 0x81,
    0x5f, 0x12, 0xbc, 0x90, 0x44, 0x6e, 0xd7, 0x29,
    0x8a, 0xcf, 0x01, 0x55, 0x3b, 0x72, 0xe9, 0xd0,
    0x16, 0xa3, 0x4f, 0x88, 0xbe, 0x67, 0x9e, 0x0c
};

pub fn main() !void {

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.debug.print("Usage: zigcrypt <file>\n", .{});
        return;
    }

    const filename = args[1];
    const dir = std.fs.cwd();

    var file = try dir.openFile(filename, .{ .mode = .read_write });
    defer file.close();

    const stat = try file.stat();
    const size = stat.size;

    var nonce: [nonce_size]u8 = undefined;
    var is_encrypted = false;

    // Detect encrypted file
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

        try aead.decrypt(
            plaintext,
            ciphertext,
            tag,
            "",
            nonce,
            key,
        );

        try temp_file.writeAll(plaintext);

        std.debug.print("File decrypted\n", .{});

    } else {
        const plaintext = try allocator.alloc(u8, size);
        defer allocator.free(plaintext);

        if (try file.readAll(plaintext) != size)
            return error.BadFile;

        std.crypto.random.bytes(&nonce);

        const ciphertext = try allocator.alloc(u8, size);
        defer allocator.free(ciphertext);

        var tag: [tag_size]u8 = undefined;

        aead.encrypt(
            ciphertext,
            &tag,
            plaintext,
            "",
            nonce,
            key,
        );

        try temp_file.writeAll(&magic);
        try temp_file.writeAll(&nonce);
        try temp_file.writeAll(ciphertext);
        try temp_file.writeAll(&tag);

        std.debug.print("File encrypted\n", .{});
    }

    temp_file.close();
    try dir.rename(temp_name, filename);
}
