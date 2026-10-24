//! ADB authorization records.
//!
//! Two sources:
//!
//! - `/data/misc/adb/adb_keys` — the permanent keys, one public key per
//!   line (`base64 [user@host comment]`), written by adbd for every key the
//!   user confirmed.
//! - `/data/misc/adb/adb_temp_keys.xml` (ABX) — temporary grants plus the
//!   connection metadata adbd keeps: `<adbKey><key/><name/>` with a
//!   `<lastConnection>` epoch value, and the `<wifiAP>` BSSIDs the device
//!   connected to while tethered-debugging.

const std = @import("std");
const abx = @import("abx.zig");

/// One ADB key grant.
pub const Key = struct {
    /// SHA-256 over the base64 key text — the stable identity of a key.
    digest: []const u8,
    /// `user@host` from the comment or the temp store's `<name>`.
    user_host: ?[]const u8 = null,
    /// `permanent` for adb_keys, `temporary` for the temp store.
    kind: []const u8,
    /// Temp store only: epoch value as stored (seconds or milliseconds;
    /// adbd has used both across versions — kept raw and rendered by the
    /// caller when it looks like an epoch).
    last_connection_raw: ?[]const u8 = null,
};

/// One BSSID from the temp store's `<wifiAP>` section.
pub const Bssid = struct {
    bssid: []const u8,
};

pub const Error = error{ OutOfMemory, Corrupt };

/// Parses adb_keys; appends one record per line. Lines are
/// `<base64>[ <comment>]`; the comment carries `user@host`.
pub fn parseKeys(arena: std.mem.Allocator, bytes: []const u8, keys: *std.ArrayList(Key)) Error!void {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        var parts = std.mem.tokenizeAny(u8, line, " \t");
        const base64 = parts.next() orelse continue;
        if (base64.len < 16) continue;
        const comment = parts.rest();
        try keys.append(arena, .{
            .digest = try sha256Hex(arena, base64),
            .user_host = blk: {
                const trimmed = std.mem.trim(u8, comment, " \t\r");
                if (trimmed.len == 0) break :blk null;
                break :blk try arena.dupe(u8, trimmed);
            },
            .kind = "permanent",
        });
    }
}

/// Parses adb_temp_keys.xml; appends the temporary keys and the BSSIDs.
///
/// AOSP writes each field as a typed attribute of the `<adbKey>` element
/// (`key`, `name`, `lastConnection`) and the tethered BSSIDs as repeated
/// `bssid` attributes of `<wifiAP>`; older builds used child elements with
/// the same names, so both shapes are read.
pub fn parseTempKeys(
    arena: std.mem.Allocator,
    bytes: []const u8,
    keys: *std.ArrayList(Key),
    bssids: *std.ArrayList(Bssid),
) abx.Error!void {
    const root = try abx.parse(arena, bytes);
    for (root.children) |section| {
        if (std.mem.eql(u8, section.name, "adbKey")) {
            const key_text = scalarField(arena, section, "key") orelse continue;
            if (key_text.len < 16) continue;
            keys.append(arena, .{
                .digest = sha256Hex(arena, key_text) catch return error.OutOfMemory,
                .user_host = scalarField(arena, section, "name"),
                .kind = "temporary",
                .last_connection_raw = scalarField(arena, section, "lastConnection"),
            }) catch return error.OutOfMemory;
        } else if (std.mem.eql(u8, section.name, "wifiAP")) {
            const attribute_values = section.attrsNamed(arena, "bssid") catch return error.OutOfMemory;
            for (attribute_values) |value| {
                if (value != .string or value.string.len == 0) continue;
                bssids.append(arena, .{ .bssid = value.string }) catch return error.OutOfMemory;
            }
            for (section.children) |field| {
                if (!std.mem.eql(u8, field.name, "bssid")) continue;
                if (field.text.len == 0) continue;
                bssids.append(arena, .{ .bssid = field.text }) catch return error.OutOfMemory;
            }
        }
    }
}

/// A named field of one element: the attribute value rendered as text, else
/// the child element's text.
fn scalarField(arena: std.mem.Allocator, node: *const abx.Node, name: []const u8) ?[]const u8 {
    if (node.attrText(arena, name) catch null) |value| {
        if (value.len > 0) return value;
    }
    if (node.child(name)) |child| {
        if (child.text.len > 0) return child.text;
    }
    return null;
}

/// SHA-256 over the key text, lowercase hex.
pub fn sha256Hex(arena: std.mem.Allocator, key_text: []const u8) error{OutOfMemory}![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key_text, &digest, .{});
    return std.fmt.allocPrint(arena, "{x}", .{&digest}) catch error.OutOfMemory;
}

const testing = std.testing;

const keys_sample =
    \\QAAAAFFDVrBPGhvp88QUSN/ndK5ACd/D15aGw3WeA3DbPOSIC0F0gPn8sX4gZ5C+nTrC8MMHXS+rZbtv user@desktop
    \\
    \\QAAAAMuoe68dgxq5w/Y9w6csK0ISIT47mUcHqjMi1tNF7rW/2xVH+EIabrj/vPX+jhf+E68BTE+1Q5B6
;

test "parses adb_keys with and without comments" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var keys: std.ArrayList(Key) = .empty;
    try parseKeys(arena_state.allocator(), keys_sample, &keys);
    try testing.expectEqual(@as(usize, 2), keys.items.len);
    try testing.expectEqualStrings("user@desktop", keys.items[0].user_host.?);
    try testing.expectEqualStrings("permanent", keys.items[0].kind);
    try testing.expect(keys.items[0].digest.len == 64);
    try testing.expect(keys.items[1].user_host == null);
    // Same input, same digest: keys are identified by content.
    try testing.expectEqualStrings(keys.items[0].digest, try sha256Hex(arena_state.allocator(), "QAAAAFFDVrBPGhvp88QUSN/ndK5ACd/D15aGw3WeA3DbPOSIC0F0gPn8sX4gZ5C+nTrC8MMHXS+rZbtv"));
}

test "parses the temp key store" {
    var writer = @import("abx_test_helper.zig").Writer{};
    defer writer.deinit();
    try writer.out.appendSlice(testing.allocator, &@import("abx_test_helper.zig").magic);
    try writer.document();
    try writer.startTag("keyStore");
    try writer.attrInt("version", 2);
    try writer.startTag("adbKey");
    try writer.attrString("key", "QAAAAtsAOJdQELQhX7l5RILsUCzTwaWc6ubLqeF1FzCZFFWULL");
    try writer.attrString("name", "Administrator@DESKTOP-TTS4RVJ");
    try writer.attrLongHex("lastConnection", 1784240823872);
    try writer.endTag("adbKey");
    try writer.startTag("wifiAP");
    try writer.attrString("bssid", "82:46:b4:f4:e7:96");
    try writer.attrString("bssid", "66:ff:9e:95:fa:d2");
    try writer.endTag("wifiAP");
    try writer.endTag("keyStore");

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var keys: std.ArrayList(Key) = .empty;
    var bssids: std.ArrayList(Bssid) = .empty;
    try parseTempKeys(arena_state.allocator(), writer.out.items, &keys, &bssids);

    try testing.expectEqual(@as(usize, 1), keys.items.len);
    try testing.expectEqualStrings("Administrator@DESKTOP-TTS4RVJ", keys.items[0].user_host.?);
    try testing.expectEqualStrings("temporary", keys.items[0].kind);
    try testing.expectEqual(@as(usize, 2), bssids.items.len);
    try testing.expectEqualStrings("82:46:b4:f4:e7:96", bssids.items[0].bssid);
}
