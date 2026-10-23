//! Thin wrappers over `zig-cryptobin` for the cipher and hash operations of
//! SAM hash decryption, keeping the call sites free of the fluent API's
//! ownership dance. Every function returns a caller-owned buffer.

const std = @import("std");
const cb = @import("zig_cryptobin");

const Allocator = std.mem.Allocator;

/// RC4 (encrypt and decrypt are the same operation). Returns `data.len` bytes.
pub fn rc4(alloc: Allocator, data: []const u8, key: []const u8) ![]u8 {
    var bin = try cb.FromBytes(alloc, data);
    defer bin.deinit();
    _ = try bin.WithKey(key);
    _ = try bin.RC4().Decrypt();
    return alloc.dupe(u8, bin.ToBytes());
}

/// AES-128-CBC decryption without padding removal; `data` must be a multiple
/// of 16 bytes, `key` and `iv` 16 bytes each.
pub fn aesCbcDecrypt(alloc: Allocator, data: []const u8, key: []const u8, iv: []const u8) ![]u8 {
    var bin = try cb.FromBytes(alloc, data);
    defer bin.deinit();
    _ = try bin.WithKey(key);
    _ = try bin.WithIv(iv);
    _ = try bin.Aes().CBC().NoPadding().Decrypt();
    return alloc.dupe(u8, bin.ToBytes());
}

/// Single-block DES-ECB decryption without padding; both slices are 8 bytes.
pub fn desEcbDecryptBlock(alloc: Allocator, data: []const u8, key: []const u8) ![8]u8 {
    var bin = try cb.FromBytes(alloc, data);
    defer bin.deinit();
    _ = try bin.WithKey(key);
    _ = try bin.Des().ECB().NoPadding().Decrypt();
    const out = bin.ToBytes();
    if (out.len < 8) return error.InvalidBlockLength;
    return out[0..8].*;
}

const testing = std.testing;

test "rc4 round trips an RFC 6229 vector" {
    // The keystream the cryptobin test suite checks, XORed back to zeros.
    const keystream = [_]u8{
        0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
        0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8,
    };
    const zeros: [16]u8 = @splat(0);
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const out = try rc4(testing.allocator, &keystream, &key);
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(u8, &zeros, out);
}

test "des ecb decrypts an FIPS 74 vector" {
    // FIPS 74: DES decrypt of the ciphertext of "Now is the time for all "
    // under key 0123456789abcdef, first block: plaintext "Now is t".
    const ciphertext = [_]u8{ 0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15 };
    const key = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    const out = try desEcbDecryptBlock(testing.allocator, &ciphertext, &key);
    try testing.expectEqualSlices(u8, "Now is t", &out);
}
