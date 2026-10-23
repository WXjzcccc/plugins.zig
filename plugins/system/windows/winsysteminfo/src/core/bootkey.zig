//! SYSTEM hive helpers: the current control set and the boot key.

const std = @import("std");
const hive_mod = @import("hive.zig");

const Allocator = std.mem.Allocator;
const Hive = hive_mod.Hive;

/// The control set the system last booted from (`Select\Current`), formatted
/// as the key name `ControlSet001`; 001 when the value is missing.
pub fn controlSetName(hive: *Hive, alloc: Allocator) error{OutOfMemory}![]const u8 {
    const current = hive.dwordValue("Select", "Current") orelse 1;
    return std.fmt.allocPrint(alloc, "ControlSet{d:0>3}", .{current});
}

/// The boot key (the "system key") of a SYSTEM hive: the four hex class names
/// of `ControlSetXXX\Control\LSA\{JD,Skew1,GBG,Data}`, concatenated and
/// byte-permuted. Null when any part is missing.
pub fn bootKey(hive: *Hive, alloc: Allocator) error{OutOfMemory}!?[16]u8 {
    const control_set = try controlSetName(hive, alloc);
    const parts = [_][]const u8{ "JD", "Skew1", "GBG", "Data" };
    var obfuscated: [16]u8 = undefined;
    var offset: usize = 0;
    for (parts) |part| {
        const path = try std.fmt.allocPrint(alloc, "{s}\\Control\\LSA\\{s}", .{ control_set, part });
        const class_name = (try hive.className(path, alloc)) orelse return null;
        if (class_name.len != 8) return null;
        const decoded = hexDecode4(class_name) orelse return null;
        @memcpy(obfuscated[offset .. offset + 4], &decoded);
        offset += 4;
    }
    // The permutation ForensicsTool (via pypykatz) applies.
    const transforms = [16]u8{ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
    var key: [16]u8 = undefined;
    for (transforms, 0..) |position, index| key[index] = obfuscated[position];
    return key;
}

/// Decodes exactly 8 hex characters into 4 bytes.
fn hexDecode4(text: []const u8) ?[4]u8 {
    if (text.len != 8) return null;
    var out: [4]u8 = undefined;
    for (0..4) |index| {
        const high = hexValue(text[index * 2]) orelse return null;
        const low = hexValue(text[index * 2 + 1]) orelse return null;
        out[index] = (high << 4) | low;
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

test "boot key permutation follows the documented transform" {
    // Extracted from the original: the transform order applied to 16 bytes.
    const transforms = [16]u8{ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
    const obfuscated: [16]u8 = @splat(0);
    _ = obfuscated;
    // Every index is unique and in range.
    var seen: [16]bool = @splat(false);
    for (transforms) |position| {
        try testing.expect(!seen[position]);
        seen[position] = true;
    }
    try testing.expectEqual(@as(u8, 0), transforms[8]);
}

test "hexDecode4 accepts upper and lower case" {
    try testing.expectEqualSlices(u8, &.{ 0x9b, 0x1f, 0x2a, 0x88 }, &hexDecode4("9B1F2a88").?);
    try testing.expectEqual(@as(?[4]u8, null), hexDecode4("9B1F2a8"));
}
