//! Bluetooth records from `/data/misc/bluedroid/bt_config.conf` (and its
//! `.bak`): a classic INI file with an `[Adapter]` section (local name,
//! address, link keys) and, when devices have been paired, one
//! `[DeviceID<N>]`-style section per remote device. Parsed with the shared
//! `ini_zig` reader.

const std = @import("std");
const ini = @import("ini_zig");

/// The local adapter or one paired remote device.
pub const Device = struct {
    /// `adapter` for `[Adapter]`, else the section name (`DeviceID0`...).
    kind: []const u8,
    address: []const u8,
    name: ?[]const u8 = null,
    scan_mode: ?i64 = null,
    discovery_timeout: ?i64 = null,
    /// `[Info] TimeCreated` — when the config store was written.
    time_created: ?[]const u8 = null,
    /// Identity/link keys, verbatim hex.
    irk: ?[]const u8 = null,
    ir: ?[]const u8 = null,
    dhk: ?[]const u8 = null,
    er: ?[]const u8 = null,
    link_key: ?[]const u8 = null,
};

pub const Error = error{OutOfMemory};

/// Parses one bt_config file. The `.bak` carries the same shape; callers
/// parse whichever they were given.
pub fn parse(arena: std.mem.Allocator, bytes: []const u8, devices: *std.ArrayList(Device)) Error!void {
    const document = try ini.parse(arena, bytes);
    defer document.deinit(arena);

    var time_created: ?[]const u8 = null;
    if (document.get("Info", "TimeCreated")) |value| {
        time_created = try arena.dupe(u8, value);
    }

    for (document.sections) |section| {
        const is_adapter = std.mem.eql(u8, section.name, "Adapter");
        const is_device = std.mem.startsWith(u8, section.name, "DeviceID");
        if (!is_adapter and !is_device) continue;

        const address = document.get(section.name, "Address") orelse "";
        if (address.len == 0) continue;
        try devices.append(arena, .{
            .kind = try arena.dupe(u8, if (is_adapter) "adapter" else section.name),
            .address = try arena.dupe(u8, address),
            .name = blk: {
                const value = document.get(section.name, "Name") orelse break :blk null;
                break :blk try arena.dupe(u8, value);
            },
            .scan_mode = intValue(document.get(section.name, "ScanMode")),
            .discovery_timeout = intValue(document.get(section.name, "DiscoveryTimeout")),
            .time_created = time_created,
            .irk = hexValue(arena, document.get(section.name, "LE_LOCAL_KEY_IRK")) catch null,
            .ir = hexValue(arena, document.get(section.name, "LE_LOCAL_KEY_IR")) catch null,
            .dhk = hexValue(arena, document.get(section.name, "LE_LOCAL_KEY_DHK")) catch null,
            .er = hexValue(arena, document.get(section.name, "LE_LOCAL_KEY_ER")) catch null,
            .link_key = hexValue(arena, document.get(section.name, "LinkKey")) catch null,
        });
    }
}

fn intValue(value: ?[]const u8) ?i64 {
    const text = value orelse return null;
    return std.fmt.parseInt(i64, std.mem.trim(u8, text, " "), 10) catch null;
}

fn hexValue(arena: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    const text = value orelse return null;
    const trimmed = std.mem.trim(u8, text, " ");
    if (trimmed.len == 0) return null;
    return try arena.dupe(u8, trimmed);
}

const testing = std.testing;

const sample =
    \\[Info]
    \\FileSource = Empty
    \\TimeCreated = 2026-07-14 22:26:58
    \\
    \\[Metrics]
    \\Salt256Bit = 2ca05c11
    \\
    \\[Adapter]
    \\Address = 9c:bc:f0:bd:6c:36
    \\LE_LOCAL_KEY_IRK = 401e59e0cfaeae70257dc42e68e20b0d
    \\LE_LOCAL_KEY_IR = 77066517c74e8105270503a18e1217bd
    \\LE_LOCAL_KEY_DHK = dd97cddf50dd7049fe3e51885b808d
    \\LE_LOCAL_KEY_ER = 29c13053e0ed13dd0965510894865629
    \\ScanMode = 1
    \\DiscoveryTimeout = 120
    \\Name = Mi 11
    \\
    \\[DeviceID0]
    \\Address = 5c:eb:68:83:05:e3
    \\Name = WH-1000XM4
    \\LinkKey = 2b93cfcbdc9c9a2d
;

test "parses adapter and paired devices" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var devices: std.ArrayList(Device) = .empty;
    try parse(arena_state.allocator(), sample, &devices);

    try testing.expectEqual(@as(usize, 2), devices.items.len);
    const adapter = devices.items[0];
    try testing.expectEqualStrings("adapter", adapter.kind);
    try testing.expectEqualStrings("9c:bc:f0:bd:6c:36", adapter.address);
    try testing.expectEqualStrings("Mi 11", adapter.name.?);
    try testing.expectEqual(@as(?i64, 1), adapter.scan_mode);
    try testing.expectEqual(@as(?i64, 120), adapter.discovery_timeout);
    try testing.expectEqualStrings("401e59e0cfaeae70257dc42e68e20b0d", adapter.irk.?);
    try testing.expectEqualStrings("2026-07-14 22:26:58", adapter.time_created.?);

    const paired = devices.items[1];
    try testing.expectEqualStrings("DeviceID0", paired.kind);
    try testing.expectEqualStrings("WH-1000XM4", paired.name.?);
    try testing.expectEqualStrings("2b93cfcbdc9c9a2d", paired.link_key.?);
}
