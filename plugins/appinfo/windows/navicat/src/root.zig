//! LovelyCarve Navicat connection analyzer plugin (LPP v2, SDK 0.2.0).
//!
//! Port of the registry part of ForensicsTool's Navicat extraction: the
//! connection profiles (hosts, ports, users and saved passwords) that
//! Navicat keeps under `Software\PremiumSoft` of every user's NTUSER.DAT,
//! with the password decryption for both the Navicat 12+ (AES-128-CBC over
//! base64) and Navicat 11 (Blowfish over hex) schemes. Hive parsing itself
//! is `regf`, the standalone library in this repository.

const std = @import("std");
const lc = @import("lovelycarve");

const analyzers = @import("plugin/run.zig");
const records = @import("plugin/records.zig");

/// Must match `id` in plugin.toml.
pub const PLUGIN_ID = "com.wxjzc.navicat";

/// Must match the analyzer ids in plugin.toml.
pub const EVIDENCE_ANALYZER = "navicatevidence";
pub const FILE_ANALYZER = "navicatfile";

pub const plugin = lc.Plugin{
    .id = PLUGIN_ID,
    .records = &records.all,
    .analyzers = &.{
        lc.analyzer(EVIDENCE_ANALYZER, analyzers.evidence),
        lc.analyzer(FILE_ANALYZER, analyzers.files),
    },
};

comptime {
    lc.exportPlugin(@This());
}

test {
    _ = @import("core/hive.zig");
    _ = @import("core/navicat.zig");
    _ = @import("plugin/analyze.zig");
    _ = @import("plugin/run.zig");
    _ = @import("plugin/records.zig");
}

const testing = std.testing;

test "the handshake advertises both analyzers and every record type" {
    var stub = lc.testing.Stub.init(testing.allocator, null, missing);
    defer stub.deinit();
    var api = stub.api();
    var table = try lc.testing.entry(&api, &plugin);
    defer table.destroy(table.instance);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const hello = try lc.testing.describe(alloc, &table);
    try testing.expectEqual(@as(u64, 2), hello.getUint("protocol").?);
    try testing.expectEqualStrings(PLUGIN_ID, hello.getString("plugin").?);

    const advertised = hello.get("analyzers").?.array;
    try testing.expectEqual(@as(usize, 2), advertised.len);
    try testing.expectEqualStrings(EVIDENCE_ANALYZER, advertised[0].string);
    try testing.expectEqualStrings(FILE_ANALYZER, advertised[1].string);

    // profile.fact is registered for every plugin; ours follow it.
    const schemas = hello.get("records").?.array;
    try testing.expectEqual(records.all.len + 1, schemas.len);
    try testing.expectEqualStrings("profile.fact", schemas[0].getString("type").?);
    try testing.expect(std.mem.startsWith(u8, hello.getString("schema_hash").?, "fnv1a64:"));
}

fn missing(
    _: ?*anyopaque,
    _: std.mem.Allocator,
    method: []const u8,
    _: lc.wire.Value,
) lc.testing.Reply {
    return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
}
