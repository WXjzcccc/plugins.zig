//! LovelyCarve UU远程 analyzer plugin (LPP v2, SDK 0.2.0).
//!
//! Collects the evidence NetEase UU远程 (GameViewer) leaves on a machine:
//! the account identity with its JWT claims, the internal device
//! identifiers and their last-use traces, the controller/controlled session
//! files (whose content is an encrypted format this plugin does not
//! attempt to decrypt), cached remote file listings, the upgrade history,
//! telemetry sessions, and the registry keys with install facts and the
//! login phone numbers. INI parsing is the shared `ini` library of this
//! repository, hive parsing is `regf`.

const std = @import("std");
const lc = @import("lovelycarve");

const analyzers = @import("plugin/run.zig");
const records = @import("plugin/records.zig");

/// Must match `id` in plugin.toml.
pub const PLUGIN_ID = "com.wxjzc.uuremote";

/// Must match the analyzer ids in plugin.toml.
pub const EVIDENCE_ANALYZER = "uuremoteevidence";
pub const FILE_ANALYZER = "uuremotefile";

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
    _ = @import("core/slogname.zig");
    _ = @import("core/jwt.zig");
    _ = @import("core/uuremote.zig");
    _ = @import("core/registry.zig");
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

// An end-to-end run over the real sample files of `testfiles/`: the stub
// host serves the files from memory, the analyzer runs unchanged, and the
// emitted records are checked against the live installation they came from.
test "an evidence run emits every record family from the sample files" {
    const e2e = @import("plugin/e2e.zig");
    try e2e.runEvidenceTest();
}

fn missing(
    _: ?*anyopaque,
    _: std.mem.Allocator,
    method: []const u8,
    _: lc.wire.Value,
) lc.testing.Reply {
    return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
}
