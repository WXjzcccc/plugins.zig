//! SECURITY hive helpers: the machine SID from `Policy\PolMachineSid`.
//!
//! The `PolMachineSid` key's default value holds the machine SID in the
//! standard binary form: revision (u8), subauthority count (u8), identifier
//! authority (48-bit big-endian), then one little-endian u32 per
//! subauthority — `S-1-5-21-a-b-c` for a standalone machine.

const std = @import("std");
const hive_mod = @import("hive.zig");

const Allocator = std.mem.Allocator;
const Hive = hive_mod.Hive;

/// The machine SID of a SECURITY hive, copied into `alloc`; null when the
/// key or value is missing or does not parse.
pub fn machineSid(hive: *Hive, alloc: Allocator) error{OutOfMemory}!?[]const u8 {
    const raw = (try hive.binaryValue(POL_MACHINE_SID_PATH, "", alloc)) orelse return null;
    return try formatBinarySid(raw, alloc);
}

/// `Policy\PolMachineSid`, addressed from the SECURITY hive's root.
pub const POL_MACHINE_SID_PATH = "Policy\\PolMachineSid";

/// Formats a binary SID (revision/count/authority/subauthorities) as
/// `S-{authority}-{sub}-…`. Returns null for malformed input.
pub fn formatBinarySid(raw: []const u8, alloc: Allocator) error{OutOfMemory}!?[]const u8 {
    if (raw.len < 8) return null;
    if (raw[0] != 1) return null; // revision 1
    const count = raw[1];
    if (count == 0 or raw.len != 8 + @as(usize, count) * 4) return null;

    // The 48-bit identifier authority is big-endian in the blob. The string
    // form is S-{revision}-{authority}-{sub}-… (S-1-5-21-…).
    var authority: u64 = 0;
    for (raw[2..8]) |byte| authority = (authority << 8) | byte;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.print(alloc, "S-{d}-{d}-", .{ raw[0], authority });
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const sub = std.mem.readInt(u32, raw[8 + index * 4 ..][0..4], .little);
        if (index != 0) try out.append(alloc, '-');
        try out.print(alloc, "{d}", .{sub});
    }
    return try out.toOwnedSlice(alloc);
}

const testing = std.testing;

test "formatBinarySid parses S-1-5-21-a-b-c" {
    // Revision 1, identifier authority 5, four subauthorities 21, a, b, c.
    var blob: [24]u8 = undefined;
    blob[0] = 1;
    blob[1] = 4;
    @memset(blob[2..8], 0);
    blob[7] = 5;
    std.mem.writeInt(u32, blob[8..12], 21, .little);
    std.mem.writeInt(u32, blob[12..16], 3009981523, .little);
    std.mem.writeInt(u32, blob[16..20], 787904381, .little);
    std.mem.writeInt(u32, blob[20..24], 4043190930, .little);

    const sid = (try formatBinarySid(&blob, testing.allocator)).?;
    defer testing.allocator.free(sid);
    try testing.expectEqualStrings("S-1-5-21-3009981523-787904381-4043190930", sid);
}

test "formatBinarySid rejects malformed input" {
    // Too short, wrong revision, wrong length for the subauthority count.
    try testing.expectEqual(@as(?[]const u8, null), try formatBinarySid(&.{1}, testing.allocator));
    var blob: [24]u8 = @splat(0);
    blob[0] = 2; // wrong revision
    blob[1] = 5;
    try testing.expectEqual(@as(?[]const u8, null), try formatBinarySid(&blob, testing.allocator));
    var lying: [24]u8 = @splat(0);
    lying[0] = 1;
    lying[1] = 9; // count larger than the blob holds
    try testing.expectEqual(@as(?[]const u8, null), try formatBinarySid(&lying, testing.allocator));
}
