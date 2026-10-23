//! SAM hive structures and password-hash decryption.
//!
//! Port of ForensicsTool's `analyzers/winreg/structs` package (which follows
//! pypykatz): the `F` and `V` value layouts of `SAM\Domains\Account`, the
//! hashed boot key and the per-user NT hash decryption. Ciphers and hashes
//! come from `zig-cryptobin` (RC4, DES, AES-CBC, MD5), matching the
//! `deatil/go-cryptobin` calls of the original.

const std = @import("std");
const cb = @import("zig_cryptobin");
const crypto = @import("crypto.zig");

const Allocator = std.mem.Allocator;

// pypykatz' string constants; the trailing NUL is part of each constant.
const QWERTY = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00";
const DIGITS = "0123456789012345678901234567890123456789\x00";
const NTPASSWORD = "NTPASSWORD\x00";

/// The NT hash of an empty password, as stored (hex).
pub const DEFAULT_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0";

/// `F` starts with these fixed 104 bytes; the key data follows.
const F_KEYDATA_OFFSET: usize = 104;

// ---------------------------------------------------------------------------
// Domain account F: key data of SAM\Domains\Account
// ---------------------------------------------------------------------------

/// Legacy (`marker == 1`) key data: RC4-encrypted with an MD5-derived key.
pub const LegacyKeyData = struct {
    salt: [16]u8,
    key: [16]u8,
    checksum: [16]u8,
};

/// AES key data (`marker == 2`), Windows Vista and later.
pub const AesKeyData = struct {
    salt: [16]u8,
    /// The encrypted hashed boot key, a multiple of 16 bytes.
    data: []const u8,
};

pub const KeyData = union(enum) {
    legacy: LegacyKeyData,
    aes: AesKeyData,
};

pub const DomainF = struct {
    next_rid: u32,
    key0: ?KeyData,

    /// Parses the `F` value of `SAM\Domains\Account`.
    pub fn parse(data: []const u8) ?DomainF {
        if (data.len <= F_KEYDATA_OFFSET) return null;
        const rest = data[F_KEYDATA_OFFSET..];
        const key0: ?KeyData = switch (rest[0]) {
            1 => blk: {
                // revision, length, salt, key, checksum, reserved = 64 bytes.
                if (rest.len < 64) break :blk null;
                var legacy: LegacyKeyData = undefined;
                @memcpy(&legacy.salt, rest[8..24]);
                @memcpy(&legacy.key, rest[24..40]);
                @memcpy(&legacy.checksum, rest[40..56]);
                break :blk .{ .legacy = legacy };
            },
            2 => blk: {
                // revision, length, checksum length, data length, salt, data.
                if (rest.len < 32) break :blk null;
                const data_length = std.mem.readInt(u32, rest[12..16], .little);
                if (rest.len < 32 + data_length) break :blk null;
                var aes: AesKeyData = undefined;
                @memcpy(&aes.salt, rest[16..32]);
                break :blk .{ .aes = .{
                    .salt = aes.salt,
                    .data = rest[32 .. 32 + data_length],
                } };
            },
            else => null,
        };
        // next_rid sits at offset 72 of F.
        const next_rid = if (data.len >= 76)
            std.mem.readInt(u32, data[72..76], .little)
        else
            0;
        return .{ .next_rid = next_rid, .key0 = key0 };
    }
};

// ---------------------------------------------------------------------------
// User account F
// ---------------------------------------------------------------------------

pub const UserF = struct {
    /// FILETIMEs (100 ns since 1601-01-01 UTC); 0 means "never".
    last_login: u64,
    last_pwd_change: u64,
    last_failed_login: u64,
    rid: u32,
    user_attribute: u32,
    logon_count: i16,
    invalid_logon_count: i16,

    pub fn parse(data: []const u8) ?UserF {
        if (data.len < 68) return null;
        return .{
            .last_login = std.mem.readInt(u64, data[8..16], .little),
            .last_pwd_change = std.mem.readInt(u64, data[24..32], .little),
            .last_failed_login = std.mem.readInt(u64, data[40..48], .little),
            .rid = std.mem.readInt(u32, data[48..52], .little),
            .user_attribute = std.mem.readInt(u32, data[56..60], .little),
            .logon_count = @bitCast(std.mem.readInt(u16, data[64..66], .little)),
            .invalid_logon_count = @bitCast(std.mem.readInt(u16, data[66..68], .little)),
        };
    }
};

// ---------------------------------------------------------------------------
// User account V
// ---------------------------------------------------------------------------

/// The fixed header of `V` is 204 bytes; the offsets inside it are relative
/// to that size (pypykatz' `VOffset`).
pub const V_OFFSET: usize = 204;

pub const UserV = struct {
    raw: []const u8,
    name_offset: u32,
    name_length: u32,
    full_name_offset: u32,
    full_name_length: u32,
    comment_offset: u32,
    comment_length: u32,
    lm_hash_offset: u32,
    lm_hash_length: u32,
    nt_hash_offset: u32,
    nt_hash_length: u32,

    /// Offsets in the fixed header: name 12, full name 24, comment 36,
    /// LM hash 156, NT hash 168.
    pub fn parse(data: []const u8) ?UserV {
        if (data.len < V_OFFSET) return null;
        return .{
            .raw = data,
            .name_offset = readU32(data, 12),
            .name_length = readU32(data, 16),
            .full_name_offset = readU32(data, 24),
            .full_name_length = readU32(data, 28),
            .comment_offset = readU32(data, 36),
            .comment_length = readU32(data, 40),
            .lm_hash_offset = readU32(data, 156),
            .lm_hash_length = readU32(data, 160),
            .nt_hash_offset = readU32(data, 168),
            .nt_hash_length = readU32(data, 172),
        };
    }

    /// A UTF-16LE string at `offset_field + V_OFFSET`, copied into `alloc`.
    fn string(self: UserV, offset_field: u32, length_field: u32, alloc: Allocator) error{OutOfMemory}![]const u8 {
        const start = V_OFFSET + offset_field;
        const length = length_field;
        if (start + length > self.raw.len or length == 0) return "";
        return decodeUtf16le(alloc, self.raw[start .. start + length]);
    }

    pub fn userName(self: UserV, alloc: Allocator) error{OutOfMemory}![]const u8 {
        return self.string(self.name_offset, self.name_length, alloc);
    }

    pub fn fullName(self: UserV, alloc: Allocator) error{OutOfMemory}![]const u8 {
        return self.string(self.full_name_offset, self.full_name_length, alloc);
    }

    pub fn comment(self: UserV, alloc: Allocator) error{OutOfMemory}![]const u8 {
        return self.string(self.comment_offset, self.comment_length, alloc);
    }

    /// The stored NT hash blob. Which layout applies follows the DOMAIN key
    /// data (legacy RC4 or AES), not the blob's own pek id: the original's
    /// head-byte heuristic misparses hives whose pek id is not 1.
    pub fn ntHash(self: UserV, aes: bool) ?NtHash {
        const start = V_OFFSET + self.nt_hash_offset;
        const end = start + self.nt_hash_length;
        if (end > self.raw.len or start >= end) return null;
        const blob = self.raw[start..end];
        if (aes) {
            // pek id, revision, data offset, salt, data.
            if (blob.len < 24) return null;
            var salt: [16]u8 = undefined;
            @memcpy(&salt, blob[8..24]);
            return .{ .aes = .{
                .salt = salt,
                .data = blob[24..],
            } };
        }
        // pek id, revision, hash: 20 bytes.
        if (blob.len != 20) return null;
        var hash: [16]u8 = undefined;
        @memcpy(&hash, blob[4..20]);
        return .{ .legacy = hash };
    }
};

pub const NtHash = union(enum) {
    /// RC4-encrypted with an MD5-derived key (pre-Vista).
    legacy: [16]u8,
    /// AES-CBC encrypted with the hashed boot key.
    aes: struct {
        salt: [16]u8,
        data: []const u8,
    },
};

fn readU32(data: []const u8, offset: usize) u32 {
    if (offset + 4 > data.len) return 0;
    var buffer: [4]u8 = undefined;
    @memcpy(&buffer, data[offset .. offset + 4]);
    return std.mem.readInt(u32, &buffer, .little);
}

/// Machine SID subauthorities from the `V` value of `SAM\Domains\Account`:
/// the last 12 bytes are the three little-endian u32s after `S-1-5-21`
/// (pypykatz' approach — it also works on the short `V` values modern
/// machines write, where the fixed 408-byte offset the original used reads
/// past the value). Returns "" when the value is too short.
pub fn machineSidFromDomainV(data: []const u8, alloc: Allocator) error{OutOfMemory}![]const u8 {
    if (data.len < 12) return "";
    const tail = data[data.len - 12 ..];
    const p1 = std.mem.readInt(u32, tail[0..4], .little);
    const p2 = std.mem.readInt(u32, tail[4..8], .little);
    const p3 = std.mem.readInt(u32, tail[8..12], .little);
    return std.fmt.allocPrint(alloc, "S-1-5-21-{d}-{d}-{d}", .{ p1, p2, p3 });
}

// ---------------------------------------------------------------------------
// Boot key and hash decryption
// ---------------------------------------------------------------------------

/// Derives the hashed boot key from the domain key data and the boot key.
/// Null when the legacy checksum does not verify (wrong boot key) or the
/// key data is malformed.
pub fn hashedBootKey(alloc: Allocator, key0: KeyData, boot_key: [16]u8) !?[16]u8 {
    switch (key0) {
        .legacy => |legacy| {
            const rc4_key = md5Of(&.{
                &legacy.salt, QWERTY, &boot_key, DIGITS,
            });
            var input: [32]u8 = undefined;
            @memcpy(input[0..16], &legacy.key);
            @memcpy(input[16..32], &legacy.checksum);
            const decrypted = crypto.rc4(alloc, &input, &rc4_key) catch return null;
            defer alloc.free(decrypted);
            const checksum = md5Of(&.{
                decrypted[0..16], DIGITS, decrypted[0..16], QWERTY,
            });
            if (!std.mem.eql(u8, decrypted[16..32], &checksum)) return null;
            var out: [16]u8 = undefined;
            @memcpy(&out, decrypted[0..16]);
            return out;
        },
        .aes => |aes| {
            if (aes.data.len < 16) return null;
            var out: [16]u8 = undefined;
            const block = aes.data[0..16].*;
            const decrypted = crypto.aesCbcDecrypt(alloc, &block, &boot_key, &aes.salt) catch return null;
            defer alloc.free(decrypted);
            @memcpy(&out, decrypted[0..16]);
            return out;
        },
    }
}

/// What decrypting one user's NT hash produced.
pub const HashResult = union(enum) {
    /// The decrypted NT hash.
    hash: [16]u8,
    /// No hash is stored: the password is blank; the caller reports the
    /// well-known constant.
    empty,
    /// The boot key was missing or the key data unusable: no decryption.
    unavailable,
};

/// Decrypts one user's NT hash with the hashed boot key and the RID. Cipher
/// failures (wrong key material, bad padding) report as `.unavailable`, so a
/// single broken account never fails the run.
pub fn decryptNtHash(
    alloc: Allocator,
    hashed_boot_key: ?[16]u8,
    rid: u32,
    hash: ?NtHash,
) error{OutOfMemory}!HashResult {
    const boot = hashed_boot_key orelse return .unavailable;
    const stored = hash orelse return .unavailable;
    switch (stored) {
        .legacy => |encrypted| {
            var rid_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &rid_bytes, rid, .little);
            const rc4_key = md5Of(&.{ boot[0..], rid_bytes[0..], NTPASSWORD });
            const key = crypto.rc4(alloc, &encrypted, &rc4_key) catch return .unavailable;
            defer alloc.free(key);
            if (key.len < 16) return .unavailable;
            return desDecryptHash(alloc, key[0..16].*, rid);
        },
        .aes => |aes| {
            if (aes.data.len == 0) return .empty;
            if (aes.data.len < 16) return .unavailable;
            var key: [16]u8 = undefined;
            const block = aes.data[0..16].*;
            const decrypted = crypto.aesCbcDecrypt(alloc, &block, &boot, &aes.salt) catch return .unavailable;
            defer alloc.free(decrypted);
            @memcpy(&key, decrypted[0..16]);
            return desDecryptHash(alloc, key, rid);
        },
    }
}

/// The final step shared by both schemes: decrypt the 16 recovered bytes with
/// two DES keys derived from the RID.
fn desDecryptHash(alloc: Allocator, key: [16]u8, rid: u32) error{OutOfMemory}!HashResult {
    const keys = rid2Keys(rid);
    const hash1 = crypto.desEcbDecryptBlock(alloc, key[0..8], &keys[0]) catch return .unavailable;
    const hash2 = crypto.desEcbDecryptBlock(alloc, key[8..16], &keys[1]) catch return .unavailable;
    var hash: [16]u8 = undefined;
    @memcpy(hash[0..8], &hash1);
    @memcpy(hash[8..16], &hash2);
    return .{ .hash = hash };
}

/// MD5 over concatenated parts, into a fixed buffer.
fn md5Of(parts: []const []const u8) [16]u8 {
    var hasher = std.crypto.hash.Md5.init(.{});
    for (parts) |part| hasher.update(part);
    var digest: [16]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Two 8-byte DES keys derived from the RID (ForensicsTool's `rid2Key`).
fn rid2Keys(rid: u32) [2][8]u8 {
    var rid_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &rid_bytes, rid, .little);
    const key1 = expandDesKey(&.{ rid_bytes[0], rid_bytes[1], rid_bytes[2], rid_bytes[3], rid_bytes[0], rid_bytes[1], rid_bytes[2] });
    const key2 = expandDesKey(&.{ rid_bytes[3], rid_bytes[0], rid_bytes[1], rid_bytes[2], rid_bytes[3], rid_bytes[0], rid_bytes[1] });
    return .{ key1, key2 };
}

/// Expands a 7-byte key to 8 bytes with parity bits (ForensicsTool's
/// `expandDESKey`).
fn expandDesKey(key: *const [7]u8) [8]u8 {
    return .{
        ((key[0] >> 1) & 0x7f) << 1,
        (((key[0] & 0x01) << 6) | ((key[1] >> 2) & 0x3f)) << 1,
        (((key[1] & 0x03) << 5) | ((key[2] >> 3) & 0x1f)) << 1,
        (((key[2] & 0x07) << 4) | ((key[3] >> 4) & 0x0f)) << 1,
        (((key[3] & 0x0f) << 3) | ((key[4] >> 5) & 0x07)) << 1,
        (((key[4] & 0x1f) << 2) | ((key[5] >> 6) & 0x03)) << 1,
        (((key[5] & 0x3f) << 1) | ((key[6] >> 7) & 0x01)) << 1,
        (key[6] & 0x7f) << 1,
    };
}

/// Decodes UTF-16LE bytes to UTF-8, replacing invalid units with U+FFFD.
pub fn decodeUtf16le(alloc: Allocator, bytes: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    var index: usize = 0;
    while (index + 1 < bytes.len + 1) {
        if (index + 2 > bytes.len) break;
        const unit = std.mem.readInt(u16, bytes[index..][0..2], .little);
        index += 2;
        if (unit >= 0xD800 and unit < 0xDC00) {
            // High surrogate: try to pair it with the next unit.
            if (index + 2 <= bytes.len) {
                const low = std.mem.readInt(u16, bytes[index..][0..2], .little);
                if (low >= 0xDC00 and low < 0xE000) {
                    index += 2;
                    const codepoint = 0x10000 + (@as(u21, unit - 0xD800) << 10) + (low - 0xDC00);
                    try appendCodepoint(alloc, &out, codepoint);
                    continue;
                }
            }
            try out.appendSlice(alloc, "\u{FFFD}");
            continue;
        }
        if (unit >= 0xDC00 and unit < 0xE000) {
            try out.appendSlice(alloc, "\u{FFFD}");
            continue;
        }
        try appendCodepoint(alloc, &out, unit);
    }
    return out.toOwnedSlice(alloc);
}

fn appendCodepoint(alloc: Allocator, out: *std.ArrayList(u8), codepoint: u21) error{OutOfMemory}!void {
    var buffer: [4]u8 = undefined;
    const length = std.unicode.utf8Encode(codepoint, &buffer) catch {
        try out.appendSlice(alloc, "\u{FFFD}");
        return;
    };
    try out.appendSlice(alloc, buffer[0..length]);
}

const testing = std.testing;

test "expandDesKey matches ForensicsTool's rid2Key output" {
    // rid 0x01F4 (500, Administrator): LE bytes f4 01 00 00.
    const keys = rid2Keys(500);
    try testing.expectEqualSlices(u8, &.{ 0xF4, 0x00, 0x40, 0x00, 0x0E, 0xA0, 0x04, 0x00 }, &keys[0]);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x7A, 0x00, 0x20, 0x00, 0x06, 0xD0, 0x02 }, &keys[1]);
}

test "userF parses the documented layout" {
    var data: [68]u8 = @splat(0);
    std.mem.writeInt(u64, data[8..16], 0x1D6_4A3C0_1234_5678, .little);
    std.mem.writeInt(u32, data[48..52], 500, .little);
    std.mem.writeInt(u16, data[64..66], 42, .little);
    const user_f = UserF.parse(&data).?;
    try testing.expectEqual(@as(u64, 0x1D6_4A3C0_1234_5678), user_f.last_login);
    try testing.expectEqual(@as(u32, 500), user_f.rid);
    try testing.expectEqual(@as(i16, 42), user_f.logon_count);
}

test "userV reads strings at their documented offsets" {
    var data: [V_OFFSET + 16]u8 = @splat(0);
    // name offset 0, length 10: UTF-16LE "admin" + NUL.
    std.mem.writeInt(u32, data[12..16], 0, .little);
    std.mem.writeInt(u32, data[16..20], 10, .little);
    const admin_utf16 = [10]u8{ 'a', 0, 'd', 0, 'm', 0, 'i', 0, 'n', 0 };
    @memcpy(data[V_OFFSET..][0..10], &admin_utf16);
    const user_v = UserV.parse(&data).?;
    const name = try user_v.userName(testing.allocator);
    defer testing.allocator.free(name);
    try testing.expectEqualStrings("admin", name);
}

test "machineSidFromDomainV reads the last 12 bytes" {
    var data: [272]u8 = @splat(0);
    std.mem.writeInt(u32, data[260..264], 3009981523, .little);
    std.mem.writeInt(u32, data[264..268], 787904381, .little);
    std.mem.writeInt(u32, data[268..272], 4043190930, .little);
    const sid = try machineSidFromDomainV(&data, testing.allocator);
    defer testing.allocator.free(sid);
    try testing.expectEqualStrings("S-1-5-21-3009981523-787904381-4043190930", sid);
    // Too short: no SID.
    try testing.expectEqualStrings("", try machineSidFromDomainV(data[0..11], testing.allocator));
}
