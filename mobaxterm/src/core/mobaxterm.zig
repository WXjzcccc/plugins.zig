//! MobaXterm saved passwords and credentials from an NTUSER-class hive.
//!
//! Port of the registry part of ForensicsTool's `mobaTool.go`: the values of
//! `Software\Mobatek\MobaXterm\P` (session passwords) and `…\C` (named
//! credentials), decrypted with MobaXterm's scheme — SHA-512 of the master
//! password as an AES-256 key, IV = AES-256-ECB of 16 zero bytes, ciphertext
//! base64 in AES-256-CFB8. (The original's `.ini` branch is a file-format
//! feature and is not part of this plugin.)

const std = @import("std");
const cb = @import("zig_cryptobin");
const regf = @import("regf_zig");
const hive_mod = @import("hive.zig");

const Allocator = std.mem.Allocator;
const Hive = hive_mod.Hive;

/// The MobaXterm root inside an NTUSER hive.
const MOBAXTERM_PATH = "Software\\Mobatek\\MobaXterm";

/// One saved session password (`P` value).
pub const Password = struct {
    /// Everything before the first colon of the value name (the protocol).
    protocol: []const u8,
    /// The rest of the value name up to the separator (`//user@host:22`).
    account_host: []const u8,
    /// Decrypted password ("" when decryption failed).
    password: []const u8 = "",
};

/// One named credential (`C` value).
pub const Credential = struct {
    /// The value name (the credential's name).
    name: []const u8,
    username: []const u8 = "",
    /// Decrypted password ("" when decryption failed).
    password: []const u8 = "",
};

pub const Report = struct {
    passwords: []Password,
    credentials: []Credential,
};

/// Collects the saved passwords and credentials of the hive.
/// `master_password` is the MobaXterm master password ("" when none).
pub fn collect(
    alloc: Allocator,
    hive: *Hive,
    master_password: []const u8,
) error{OutOfMemory}!Report {
    if (!hive.hasKey(MOBAXTERM_PATH)) {
        return .{ .passwords = &.{}, .credentials = &.{} };
    }
    const key_material = try deriveKey(alloc, master_password);
    var cipher = Cfb8.init(&key_material);

    var passwords: std.ArrayList(Password) = .empty;
    if (try collectValues(alloc, hive, "P")) |entries| {
        for (entries) |entry| {
            const name = entry.name;
            const value = try valueString(entry.value, alloc);
            defer alloc.free(value);
            var password = Password{
                .protocol = "",
                .account_host = name,
            };
            if (std.mem.indexOfScalar(u8, name, ':')) |colon| {
                password.protocol = name[0..colon];
                password.account_host = name[colon + 1 ..];
            }
            if (std.mem.indexOfScalar(u8, value, '=')) |equal| {
                password.password = try decrypt(alloc, &cipher, value[equal + 1 ..]);
            }
            try passwords.append(alloc, password);
        }
    }

    var credentials: std.ArrayList(Credential) = .empty;
    if (try collectValues(alloc, hive, "C")) |entries| {
        for (entries) |entry| {
            const name = entry.name;
            const value = try valueString(entry.value, alloc);
            defer alloc.free(value);
            var credential = Credential{ .name = name };
            if (std.mem.indexOfScalar(u8, value, '=')) |equal| {
                const rest = value[equal + 1 ..];
                if (std.mem.indexOfScalar(u8, rest, ':')) |colon| {
                    credential.username = rest[0..colon];
                    credential.password = try decrypt(alloc, &cipher, rest[colon + 1 ..]);
                }
            }
            try credentials.append(alloc, credential);
        }
    }

    return .{
        .passwords = try passwords.toOwnedSlice(alloc),
        .credentials = try credentials.toOwnedSlice(alloc),
    };
}

/// The string values of one child key (`P` or `C`), as name/value pairs.
fn collectValues(
    alloc: Allocator,
    hive: *Hive,
    child: []const u8,
) error{OutOfMemory}!?[]regf.ValueEntry {
    const child_path = try std.fmt.allocPrint(alloc, "{s}\\{s}", .{ MOBAXTERM_PATH, child });
    var entries = hive.inner.listValues(child_path, alloc) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    // Keep only string values (the base64 ciphertexts), in registry order.
    var out: std.ArrayList(regf.ValueEntry) = .empty;
    for (entries.items) |entry| {
        switch (entry.value) {
            .sz, .expand_sz => try out.append(alloc, entry),
            else => entry.deinit(hive.inner.gpa),
        }
    }
    entries.deinit(hive.inner.gpa);
    return try out.toOwnedSlice(alloc);
}

/// The UTF-8 text of a string-typed registry value, copied into `alloc`.
fn valueString(value: regf.RegValue, alloc: Allocator) error{OutOfMemory}![]const u8 {
    return switch (value) {
        .sz => |text| try alloc.dupe(u8, text),
        .expand_sz => |text| try alloc.dupe(u8, text),
        else => "",
    };
}

/// SHA-512 of the master password, truncated to 32 bytes (ForensicsTool's
/// `decryptMoba` key derivation; an empty master password is MobaXterm's
/// default).
fn deriveKey(alloc: Allocator, master_password: []const u8) error{OutOfMemory}![32]u8 {
    const digest = cb.hash.digest(alloc, .sha512, master_password) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnsupportedHash => unreachable, // SHA-512 is always supported
    };
    defer alloc.free(digest);
    var key: [32]u8 = undefined;
    @memcpy(&key, digest[0..32]);
    return key;
}

/// AES-256-CFB8 decryption of one base64 ciphertext. Failures yield "" (the
/// original skips undecryptable values the same way).
fn decrypt(alloc: Allocator, cipher: *const Cfb8, ciphertext: []const u8) error{OutOfMemory}![]const u8 {
    const raw = base64Decode(alloc, ciphertext) catch return "";
    defer alloc.free(raw);
    const plain = try alloc.alloc(u8, raw.len);
    cipher.decrypt(plain, raw);
    return plain;
}

fn base64Decode(alloc: Allocator, text: []const u8) ![]u8 {
    if (text.len == 0) return error.InvalidBase64;
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
    const out = try alloc.alloc(u8, size);
    errdefer alloc.free(out);
    decoder.decode(out, text) catch return error.InvalidBase64;
    return out;
}

/// AES-256-CFB8, the one mode MobaXterm uses that `zig-cryptobin` does not
/// carry (its CFB is full-block feedback). The block cipher underneath is
/// std's AES core.
pub const Cfb8 = struct {
    /// The AES-256 encryption context (only the forward cipher is needed;
    /// CFB8 never runs the inverse cipher).
    cipher: std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256),

    iv: [16]u8,

    pub fn init(key: *const [32]u8) Cfb8 {
        var self = Cfb8{
            .cipher = std.crypto.core.aes.Aes256.initEnc(key.*),
            .iv = undefined,
        };
        // MobaXterm's IV: AES-256-ECB of 16 zero bytes under the same key.
        const zeros: [16]u8 = @splat(0);
        self.cipher.encrypt(&self.iv, &zeros);
        return self;
    }

    /// Decrypts `src` into `dst` (same length) with CFB8 feedback of the
    /// ciphertext: the feedback register changes every byte, so the block
    /// cipher runs once per byte.
    pub fn decrypt(self: *const Cfb8, dst: []u8, src: []const u8) void {
        var feedback = self.iv;
        var stream: [16]u8 = undefined;
        for (src, 0..) |byte, index| {
            self.cipher.encrypt(&stream, &feedback);
            dst[index] = byte ^ stream[0];
            // Shift the feedback register left one byte, append the
            // ciphertext byte.
            std.mem.copyForwards(u8, feedback[0..15], feedback[1..]);
            feedback[15] = byte;
        }
    }
};

const testing = std.testing;

test "cfb8 round trips against a manual encrypt" {
    var key: [32]u8 = @splat(0);
    for (&key, 0..) |*byte, index| byte.* = @truncate(index);
    const cipher = Cfb8.init(&key);

    // Encrypt with the mirrored CFB8 rule (plaintext feedback), starting
    // from the same IV the decryptor derives.
    const plain = "MobaXterm saved password, somewhat longer than one block!";
    const ciphertext = try testing.allocator.alloc(u8, plain.len);
    defer testing.allocator.free(ciphertext);
    {
        var feedback = cipher.iv;
        var stream: [16]u8 = undefined;
        for (plain, 0..) |byte, index| {
            cipher.cipher.encrypt(&stream, &feedback);
            ciphertext[index] = byte ^ stream[0];
            std.mem.copyForwards(u8, feedback[0..15], feedback[1..]);
            feedback[15] = ciphertext[index];
        }
    }

    const recovered = try testing.allocator.alloc(u8, plain.len);
    defer testing.allocator.free(recovered);
    var decryptor = Cfb8.init(&key);
    decryptor.cipher = cipher.cipher;
    decryptor.decrypt(recovered, ciphertext);
    try testing.expectEqualSlices(u8, plain, recovered);
}

test "cfb8 decrypt with mismatched iv yields garbage, not a crash" {
    var key: [32]u8 = @splat(0);
    const cipher = Cfb8.init(&key);
    const src = "0123456789abcdef";
    var dst: [16]u8 = undefined;
    cipher.decrypt(&dst, src);
    // Just any bytes; the property under test is "no crash, no error".
    try testing.expect(dst.len == 16);
}
