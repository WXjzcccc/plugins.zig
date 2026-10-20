//! LovelyCarve APK analyzer plugin (LPP v2, SDK 0.2.0).
//!
//! Two analyzers over one parser core:
//!
//! - `apkevidence` (evidence scope, automatic) finds every `*.apk` in an
//!   evidence item and analyzes each of them;
//! - `apkfile` (files scope, manual) analyzes the packages the user selected.
//!
//! The parser core under `src/core` and `src/utils` is the standalone
//! apk_analyzer project, unchanged apart from its file IO: the plugin reads
//! evidence through the run's read-only file handles, so the core only ever
//! parses an in-memory buffer.

const std = @import("std");
const lc = @import("lovelycarve");

const analyzers = @import("plugin/run.zig");
const records = @import("plugin/records.zig");

/// Must match `id` in plugin.toml.
pub const PLUGIN_ID = "com.wxjzc.apkanalyzer";

/// Must match the analyzer ids in plugin.toml.
pub const EVIDENCE_ANALYZER = "apkevidence";
pub const FILE_ANALYZER = "apkfile";

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

// The parser core's own tests run with `zig build test`, like this file's.
test {
    _ = @import("core/analysis/catalog.zig");
    _ = @import("core/analysis/engine.zig");
    _ = @import("core/analysis/icon.zig");
    _ = @import("core/analysis/signing_info.zig");
    _ = @import("core/android/axml/document.zig");
    _ = @import("core/android/chunk.zig");
    _ = @import("core/android/manifest/parser.zig");
    _ = @import("core/android/resources/config.zig");
    _ = @import("core/android/resources/resolver.zig");
    _ = @import("core/android/resources/table.zig");
    _ = @import("core/android/string_pool.zig");
    _ = @import("core/android/typed_value.zig");
    _ = @import("core/limits.zig");
    _ = @import("core/model.zig");
    _ = @import("core/signing/algorithms.zig");
    _ = @import("core/signing/apk_block.zig");
    _ = @import("core/signing/cms.zig");
    _ = @import("core/signing/der.zig");
    _ = @import("core/signing/parser.zig");
    _ = @import("core/signing/x509.zig");
    _ = @import("plugin/analyze.zig");
    _ = @import("plugin/conversion.zig");
    _ = @import("plugin/run.zig");
    _ = @import("plugin/records.zig");
    _ = @import("utils/io/cursor.zig");
    _ = @import("utils/logging.zig");
    _ = @import("utils/zip/archive.zig");
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

test "an unknown analyzer is rejected, not guessed" {
    var stub = lc.testing.Stub.init(testing.allocator, null, missing);
    defer stub.deinit();
    var api = stub.api();
    var table = try lc.testing.entry(&api, &plugin);
    defer table.destroy(table.instance);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const reply = try lc.testing.call(alloc, &table, 3, "run.start", try lc.wire.mapOf(alloc, &.{
        lc.wire.entry("run_id", lc.wire.str("run-3")),
        lc.wire.entry("analyzer", lc.wire.str("otherapk")),
        lc.wire.entry("target", try lc.wire.mapOf(alloc, &.{
            lc.wire.entry("kind", lc.wire.str("files")),
        })),
    }));
    try testing.expectEqual(lc.abi.STATUS_ERROR, reply.status);
    try testing.expectEqualStrings("INVALID_ANALYZER", reply.fault.?.code);
}

fn missing(
    _: ?*anyopaque,
    _: std.mem.Allocator,
    method: []const u8,
    _: lc.wire.Value,
) lc.testing.Reply {
    return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
}
