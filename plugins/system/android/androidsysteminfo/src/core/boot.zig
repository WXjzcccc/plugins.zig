//! Headers of Android boot records: the dropbox `SYSTEM_BOOT` entries and
//! `/data/system/last-header.txt`. Both are simple `Key: value` text files
//! written by `system_server`'s boot recorder:
//!
//! ```text
//! isPrevious: true
//! Build: Xiaomi/venus/venus:13/TKQ1.220829.002/V14.0.11.0.TKBCNXM:user/release-keys
//! Hardware: venus
//! Revision: 0
//! Bootloader: unknown
//! Radio: 4.3CPL2-27.1-18673.12-1226_0642_747925de6a5,...
//! Kernel: Linux version 5.4.233-qgki-gbb70cde46897 (...) #1 SMP PREEMPT ...
//! ```

const std = @import("std");

/// One boot header, the fields worth recording as device attributes.
pub const Header = struct {
    build: ?[]const u8 = null,
    hardware: ?[]const u8 = null,
    revision: ?[]const u8 = null,
    bootloader: ?[]const u8 = null,
    radio: ?[]const u8 = null,
    kernel: ?[]const u8 = null,
};

/// Parses `Key: value` lines. Unknown keys and duplicate keys are ignored
/// (first occurrence wins).
pub fn parseHeader(alloc: std.mem.Allocator, text: []const u8) error{OutOfMemory}!Header {
    var header = Header{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        const colon = std.mem.indexOf(u8, line, ": ") orelse continue;
        const key = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 2 ..], " \t\r");
        const field: *?[]const u8 = blk: {
            if (std.mem.eql(u8, key, "Build")) break :blk &header.build;
            if (std.mem.eql(u8, key, "Hardware")) break :blk &header.hardware;
            if (std.mem.eql(u8, key, "Revision")) break :blk &header.revision;
            if (std.mem.eql(u8, key, "Bootloader")) break :blk &header.bootloader;
            if (std.mem.eql(u8, key, "Radio")) break :blk &header.radio;
            if (std.mem.eql(u8, key, "Kernel")) break :blk &header.kernel;
            continue;
        };
        if (field.* == null) field.* = try alloc.dupe(u8, value);
    }
    return header;
}

/// `isPrevious: true` marks a `SYSTEM_BOOT` entry as from an earlier boot
/// (the newest entry is the boot in progress when the snapshot was taken).
pub fn isPrevious(text: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (!std.mem.startsWith(u8, line, "isPrevious:")) continue;
        const value = std.mem.trim(u8, line["isPrevious:".len..], " \t\r");
        return std.ascii.eqlIgnoreCase(value, "true");
    }
    return false;
}

const testing = std.testing;

const sample =
    \\isPrevious: true
    \\Build: Xiaomi/venus/venus:13/TKQ1.220829.002/V14.0.11.0.TKBCNXM:user/release-keys
    \\Hardware: venus
    \\Revision: 0
    \\Bootloader: unknown
    \\Radio: 4.3CPL2-27.1
    \\Kernel: Linux version 5.4.233-qgki
    \\
;

test "parses the boot header fields" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const header = try parseHeader(arena_state.allocator(), sample);
    try testing.expectEqualStrings("Xiaomi/venus/venus:13/TKQ1.220829.002/V14.0.11.0.TKBCNXM:user/release-keys", header.build.?);
    try testing.expectEqualStrings("venus", header.hardware.?);
    try testing.expectEqualStrings("0", header.revision.?);
    try testing.expectEqualStrings("unknown", header.bootloader.?);
    try testing.expectEqualStrings("4.3CPL2-27.1", header.radio.?);
    try testing.expectEqualStrings("Linux version 5.4.233-qgki", header.kernel.?);
    try testing.expect(isPrevious(sample));
    try testing.expect(!isPrevious("Build: x\n"));
}
