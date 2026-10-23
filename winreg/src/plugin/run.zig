//! The analyzer entry point: an evidence-scope run over the registry hives
//! the host resolved from the manifest's `inputs` patterns.

const std = @import("std");

const lc = @import("lovelycarve");
const analyze = @import("analyze.zig");

/// Evidence scope: run over every hive of the evidence item.
pub fn evidence(run: *const lc.Run) lc.Error!void {
    const settings = analyze.Items.fromOptions(run.optionValues());
    const inputs = run.inputsOf();
    return analyze.analyzeRun(run, inputs, settings);
}

const testing = std.testing;

const test_plugin = lc.Plugin{
    .id = "org.example.winreg",
    .records = &.{},
    .analyzers = &.{lc.analyzer("winregevidence", evidence)},
};

/// A `run.start` whose inputs are the given file names (no content: the mock
/// host answers file.read with "nope", so every hive becomes a warning).
fn startParams(alloc: std.mem.Allocator, names: []const []const u8) !lc.wire.Value {
    var inputs: std.ArrayList(lc.wire.Value) = .empty;
    for (names, 0..) |name, index| {
        const file_id = try std.fmt.allocPrint(alloc, "file-{d}", .{index});
        try inputs.append(alloc, try lc.wire.mapOf(alloc, &.{
            lc.wire.entry("file_id", lc.wire.str(file_id)),
            lc.wire.entry("name", lc.wire.str(name)),
            lc.wire.entry("size", lc.wire.uint(4)),
            lc.wire.entry("root_path", lc.wire.str(name)),
        }));
    }
    return lc.wire.mapOf(alloc, &.{
        lc.wire.entry("run_id", lc.wire.str("run-1")),
        lc.wire.entry("analyzer", lc.wire.str("winregevidence")),
        lc.wire.entry("target", try lc.wire.mapOf(alloc, &.{
            lc.wire.entry("kind", lc.wire.str("evidence")),
            lc.wire.entry("view", try lc.wire.mapOf(alloc, &.{
                lc.wire.entry("view_id", lc.wire.str("view-1")),
                lc.wire.entry("label", lc.wire.str("evidence")),
            })),
        })),
        lc.wire.entry("inputs", .{ .array = inputs.items }),
        lc.wire.entry("locale", lc.wire.str("zh-CN")),
    });
}

const MockNoFile = struct {
    fn handle(
        _: ?*anyopaque,
        _: std.mem.Allocator,
        method: []const u8,
        _: lc.wire.Value,
    ) lc.testing.Reply {
        if (std.mem.eql(u8, method, "file.read")) {
            return .{ .value = .{ .bytes = "nope" } };
        }
        return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
    }
};

test "a run without hive inputs says so instead of failing" {
    var stub = lc.testing.Stub.init(testing.allocator, null, MockNoFile.handle);
    defer stub.deinit();
    var api = stub.api();
    var table = try lc.testing.entry(&api, &test_plugin);
    defer table.destroy(table.instance);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const reply = try lc.testing.callOk(alloc, &table, 2, "run.start", try startParams(alloc, &.{}));
    try testing.expectEqual(@as(u64, 0), stub.emittedCount());
    try testing.expectEqual(@as(usize, 0), stub.warnings.items.len);
    try testing.expectEqualStrings("没有发现 Windows 注册表配置单元", reply.?.getString("summary").?);
}

test "a non-hive input becomes a warning, not a failed run" {
    var stub = lc.testing.Stub.init(testing.allocator, null, MockNoFile.handle);
    defer stub.deinit();
    var api = stub.api();
    var table = try lc.testing.entry(&api, &test_plugin);
    defer table.destroy(table.instance);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const reply = try lc.testing.callOk(alloc, &table, 2, "run.start", try startParams(alloc, &.{"note.txt"}));
    try testing.expectEqualStrings("没有发现 Windows 注册表配置单元", reply.?.getString("summary").?);

    // A *.DAT that is not a hive is parsed (like the original) and warned.
    const reply_dat = try lc.testing.callOk(alloc, &table, 3, "run.start", try startParams(alloc, &.{"junk.dat"}));
    try testing.expectEqual(@as(usize, 1), stub.warnings.items.len);
    try testing.expectEqualStrings("HIVE_PARSE_FAILED", stub.warnings.items[0].code);
    try testing.expectEqualStrings("没有可解析的注册表配置单元", reply_dat.?.getString("summary").?);
}
