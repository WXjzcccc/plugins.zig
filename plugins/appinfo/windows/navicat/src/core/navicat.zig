//! Navicat connection extraction from an NTUSER-class hive.
//!
//! Port of ForensicsTool's `analyzers/extractor/tool/navicatTool.go` (registry
//! part): the connection profiles under `Software\PremiumSoft` with their
//! saved passwords, decrypted with the Navicat 12+ (hex + AES-128-CBC) or
//! Navicat 11 (hex + Blowfish) scheme — both store the ciphertext as
//! hexadecimal text.

const std = @import("std");
const cb = @import("zig_cryptobin");
const hive_mod = @import("hive.zig");

const Allocator = std.mem.Allocator;
const Hive = hive_mod.Hive;

/// The PremiumSoft root inside an NTUSER hive.
const PREMIUMSOFT_PATH = "Software\\PremiumSoft";

/// The connection families the original reports, with their record labels.
pub const ConnType = enum {
    mysql,
    mariadb,
    mongodb,
    oracle,
    postgresql,
    mssql,
    sqlite,

    pub fn fromSubkeyName(name: []const u8) ?ConnType {
        const table = [_]struct { key: []const u8, kind: ConnType }{
            .{ .key = "Navicat", .kind = .mysql },
            .{ .key = "NavicatMARIADB", .kind = .mariadb },
            .{ .key = "NavicatMongoDB", .kind = .mongodb },
            .{ .key = "NavicatOra", .kind = .oracle },
            .{ .key = "NavicatPG", .kind = .postgresql },
            .{ .key = "NavicatMSSQL", .kind = .mssql },
            .{ .key = "NavicatSQLite", .kind = .sqlite },
        };
        for (table) |entry| {
            if (std.mem.eql(u8, entry.key, name)) return entry.kind;
        }
        return null;
    }

    pub fn label(self: ConnType) []const u8 {
        return switch (self) {
            .mysql => "MySQL连接信息",
            .mariadb => "MariaDB连接信息",
            .mongodb => "MongoDB连接信息",
            .oracle => "Oracle连接信息",
            .postgresql => "PostgreSQL连接信息",
            .mssql => "SQLServer连接信息",
            .sqlite => "SQLite连接信息",
        };
    }
};

/// One connection profile. Every string is copied into the caller's arena.
pub const Connection = struct {
    conn_type: ConnType,
    /// The PremiumSoft family subkey the profile came from.
    type_name: []const u8,
    name: []const u8,
    host: []const u8 = "",
    port: ?u32 = null,
    username: []const u8 = "",
    /// Decrypted password ("" when nothing was stored or decryption failed).
    password: []const u8 = "",
    cache_path: []const u8 = "",
    database: []const u8 = "",
    auth_mode: []const u8 = "",
    encrypted: ?bool = null,
    saved_password: ?bool = null,
};

/// Collects every Navicat connection profile of the hive, in registry order.
pub fn collect(alloc: Allocator, hive: *Hive) error{OutOfMemory}![]Connection {
    if (!hive.hasKey(PREMIUMSOFT_PATH)) return &.{};
    const families = hive.subkeys(PREMIUMSOFT_PATH, alloc) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => &[_][]const u8{},
    };

    var out: std.ArrayList(Connection) = .empty;
    for (families) |family| {
        const kind = ConnType.fromSubkeyName(family) orelse continue;
        const servers_path = try std.fmt.allocPrint(alloc, "{s}\\{s}\\Servers", .{ PREMIUMSOFT_PATH, family });
        const names = hive.subkeys(servers_path, alloc) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => &[_][]const u8{},
        };
        for (names) |connection_name| {
            const path = try std.fmt.allocPrint(alloc, "{s}\\{s}", .{ servers_path, connection_name });
            var connection = Connection{
                .conn_type = kind,
                .type_name = family,
                .name = connection_name,
            };
            connection.host = (try hive.stringValue(path, "Host", alloc)) orelse "";
            connection.port = hive.dwordValue(path, "Port");
            connection.username = (try hive.stringValue(path, "UserName", alloc)) orelse "";
            connection.cache_path = (try hive.stringValue(path, "QuerySavePath", alloc)) orelse "";
            // SQLite keeps the (encrypted-database) password under its own
            // value; every other family uses `Pwd`.
            const password_value = switch (kind) {
                .sqlite => "EncryptionPassword",
                else => "Pwd",
            };
            if (try hive.stringValue(path, password_value, alloc)) |stored| {
                connection.password = decrypt(alloc, stored) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                };
            }
            switch (kind) {
                .mssql => {
                    connection.database = (try hive.stringValue(path, "InitialDatabase", alloc)) orelse "";
                    connection.auth_mode = (try hive.stringValue(path, "MSSQLAuthenMode", alloc)) orelse "";
                },
                .sqlite => {
                    connection.database = (try hive.stringValue(path, "InitialDatabase", alloc)) orelse "";
                    if (hive.dwordValue(path, "SQLiteEncrypted")) |flag| {
                        connection.encrypted = flag == 1;
                    }
                    const saved = (try hive.stringValue(path, "EncryptionSavePassword", alloc)) orelse "";
                    connection.saved_password = std.mem.eql(u8, saved, "true");
                },
                else => {},
            }
            try out.append(alloc, connection);
        }
    }
    return out.toOwnedSlice(alloc);
}

// ---------------------------------------------------------------------------
// Password decryption
// ---------------------------------------------------------------------------

const NAVICAT11_USER_KEY = "3DC5CA39";
const NAVICAT12_KEY = "libcckeylibcckey";
const NAVICAT12_IV = "libcciv libcciv ";

/// Decrypts one stored password: Navicat 12+ (hex + AES-128-CBC with PKCS7
/// padding) first, then Navicat 11 (hex + Blowfish). Returns "" when neither
/// scheme fits.
pub fn decrypt(alloc: Allocator, stored: []const u8) error{OutOfMemory}![]const u8 {
    if (stored.len == 0) return "";
    if (decryptV12(alloc, stored) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    }) |plain| return plain;
    if (decryptV11(alloc, stored) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    }) |plain| return plain;
    return "";
}

/// Navicat 12+: hex of AES-128-CBC (PKCS7) ciphertext. Valid only when the
/// plaintext is non-empty UTF-8 — the check the original uses to pick a
/// scheme.
fn decryptV12(alloc: Allocator, stored: []const u8) error{OutOfMemory}!?[]const u8 {
    const ciphertext = hexDecode(alloc, stored) catch return null;
    defer alloc.free(ciphertext);
    if (ciphertext.len == 0 or ciphertext.len % 16 != 0) return null;
    var bin = cb.FromBytes(alloc, ciphertext) catch return null;
    defer bin.deinit();
    _ = try bin.WithKey(NAVICAT12_KEY);
    _ = try bin.WithIv(NAVICAT12_IV);
    _ = bin.Aes().CBC().PKCS7Padding().Decrypt() catch return null;
    const plain = bin.ToString();
    if (plain.len == 0 or !std.unicode.utf8ValidateSlice(plain)) return null;
    return try alloc.dupe(u8, plain);
}

/// Navicat 11: hex of Blowfish-CBC ciphertext under the SHA-1 of the default
/// user key. The plaintext is stored unpadded — the ciphertext length is
/// arbitrary and a partial final block is encrypted CFB-style, so the output
/// keeps the input length.
fn decryptV11(alloc: Allocator, stored: []const u8) error{OutOfMemory}!?[]const u8 {
    const ciphertext = hexDecode(alloc, stored) catch return null;
    defer alloc.free(ciphertext);
    if (ciphertext.len == 0) return null;
    const plain = try decryptV11Bytes(alloc, ciphertext);
    if (plain.len == 0) return null;
    return plain;
}

/// The Navicat 11 cipher (ForensicsTool's `Navicat11Cipher.Decrypt`):
/// CBC decryption whose chaining value is updated with the ciphertext, plus
/// a CFB-style tail for a partial final block.
fn decryptV11Bytes(alloc: Allocator, ciphertext: []const u8) error{OutOfMemory}![]const u8 {
    // The user key is a fixed 8-byte string, so the key schedule cannot fail.
    const cipher = Navicat11Cipher.init(NAVICAT11_USER_KEY) catch unreachable;
    return cipher.decrypt(alloc, ciphertext);
}

pub const Navicat11Cipher = struct {
    context: cb.blowfish.Context,
    iv: [8]u8,

    /// Key schedule: SHA-1 of the user key, IV = Blowfish-ECB(FF..FF).
    pub fn init(user_key: []const u8) error{InvalidKeyLength}!Navicat11Cipher {
        var hasher = std.crypto.hash.Sha1.init(.{});
        hasher.update(user_key);
        var key: [20]u8 = undefined;
        hasher.final(&key);
        const context = cb.blowfish.Context.init(&key);
        const iv: [8]u8 = @splat(0xFF);
        var encrypted: [8]u8 = undefined;
        context.encrypt(&encrypted, iv);
        return .{ .context = context, .iv = encrypted };
    }

    pub fn deinit(self: *Navicat11Cipher, alloc: Allocator) void {
        // The context holds no allocations; the parameter keeps the call
        // sites symmetric with the rest of the ciphers.
        _ = self;
        _ = alloc;
    }

    pub fn decrypt(self: *const Navicat11Cipher, alloc: Allocator, data: []const u8) ![]const u8 {
        const out = try alloc.alloc(u8, data.len);
        errdefer alloc.free(out);
        var cv = self.iv;
        const blocks = data.len / 8;
        for (0..blocks) |index| {
            const start = index * 8;
            var block: [8]u8 = undefined;
            @memcpy(&block, data[start..][0..8]);
            var plain: [8]u8 = undefined;
            self.context.decrypt(&plain, block);
            for (&plain, cv) |*byte, chain| byte.* ^= chain;
            @memcpy(out[start..][0..8], &plain);
            for (&cv, block) |*chain, byte| chain.* ^= byte;
        }
        const left = data.len % 8;
        if (left != 0) {
            var stream: [8]u8 = undefined;
            self.context.encrypt(&stream, cv);
            const start = blocks * 8;
            for (0..left) |index| {
                out[start + index] = data[start + index] ^ stream[index];
            }
        }
        return out;
    }
};

fn hexDecode(alloc: Allocator, text: []const u8) ![]u8 {
    if (text.len == 0 or text.len % 2 != 0) return error.InvalidHex;
    const out = try alloc.alloc(u8, text.len / 2);
    errdefer alloc.free(out);
    for (out, 0..) |*byte, index| {
        const high = hexValue(text[index * 2]) orelse return error.InvalidHex;
        const low = hexValue(text[index * 2 + 1]) orelse return error.InvalidHex;
        byte.* = (high << 4) | low;
    }
    return out;
}

fn hexValue(char: u8) ?u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'a'...'f' => char - 'a' + 10,
        'A'...'F' => char - 'A' + 10,
        else => null,
    };
}

const testing = std.testing;

test "navicat 12+ password round trips through hex" {
    const alloc = testing.allocator;

    // Encrypt the way Navicat stores a password: AES-128-CBC under the fixed
    // key and IV, PKCS7-padded, then hex-encoded (Navicat writes uppercase).
    var bin = try cb.FromBytes(alloc, "p@ssw0rd-12!");
    defer bin.deinit();
    _ = try bin.WithKey(NAVICAT12_KEY);
    _ = try bin.WithIv(NAVICAT12_IV);
    _ = try bin.Aes().CBC().PKCS7Padding().Encrypt();
    const lower = try bin.ToHexString();
    defer alloc.free(lower);
    const stored = try alloc.dupe(u8, lower);
    defer alloc.free(stored);
    for (stored) |*char| char.* = std.ascii.toUpper(char.*);

    const recovered = try decrypt(alloc, stored);
    defer alloc.free(recovered);
    try testing.expectEqualStrings("p@ssw0rd-12!", recovered);
}

test "navicat 11 cipher round trips full and partial blocks" {
    const cipher = try Navicat11Cipher.init(NAVICAT11_USER_KEY);

    // Navicat 11 stores the plaintext unpadded: full blocks go through the
    // chained CBC steps, a partial final block through the CFB-style tail.
    for ([_][]const u8{ "secret-password!", "root123456", "12345", "1" }) |plain| {
        const ciphertext = try encryptV11ForTest(testing.allocator, &cipher, plain);
        defer testing.allocator.free(ciphertext);
        const recovered = try cipher.decrypt(testing.allocator, ciphertext);
        defer testing.allocator.free(recovered);
        try testing.expectEqualSlices(u8, plain, recovered);
    }
}

/// The inverse of `Navicat11Cipher.decrypt` (the chaining rule ForensicsTool's
/// Decrypt applies): each plaintext block is encrypted with the running
/// chaining value, which then absorbs the ciphertext; a partial final block
/// is XORed with the CFB-style keystream.
fn encryptV11ForTest(alloc: Allocator, cipher: *const Navicat11Cipher, plain: []const u8) ![]u8 {
    const ciphertext = try alloc.alloc(u8, plain.len);
    errdefer alloc.free(ciphertext);
    var cv = cipher.iv;
    for (0..plain.len / 8) |index| {
        var block: [8]u8 = undefined;
        for (0..8) |byte| block[byte] = plain[index * 8 + byte] ^ cv[byte];
        cipher.context.encrypt(ciphertext[index * 8 ..][0..8], block);
        for (&cv, ciphertext[index * 8 ..][0..8]) |*chain, byte| chain.* ^= byte;
    }
    const tail_start = plain.len / 8 * 8;
    const tail_len = plain.len % 8;
    if (tail_len != 0) {
        var stream: [8]u8 = undefined;
        cipher.context.encrypt(&stream, cv);
        for (0..tail_len) |index| {
            ciphertext[tail_start + index] = plain[tail_start + index] ^ stream[index];
        }
    }
    return ciphertext;
}

test "decrypt recovers real stored passwords" {
    // Vectors from a real NTUSER.DAT (Navicat 11 scheme): uppercase hex,
    // unpadded, from one ciphertext byte up to full blocks.
    const cases = [_]struct { stored: []const u8, plain: []const u8 }{
        .{ .stored = "15", .plain = "1" },
        .{ .stored = "15057D7EA4", .plain = "12312" },
        .{ .stored = "5658213B", .plain = "root" },
        .{ .stored = "15057D7BA390", .plain = "123456" },
        .{ .stored = "7095E023DFC0E71C42C5", .plain = "root123456" },
        .{ .stored = "2620B6512385244F", .plain = "Aa123456" },
        .{ .stored = "54B5175B2ED908A291A323D02F378176", .plain = "eea11854a079626b" },
    };
    for (cases) |case| {
        const recovered = try decrypt(testing.allocator, case.stored);
        defer testing.allocator.free(recovered);
        try testing.expectEqualStrings(case.plain, recovered);
    }
}

test "hex decode accepts upper and lower case" {
    const out = try hexDecode(testing.allocator, "0A1B2c3D");
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0x1b, 0x2c, 0x3d }, out);
    try testing.expectError(error.InvalidHex, hexDecode(testing.allocator, "abc"));
}
