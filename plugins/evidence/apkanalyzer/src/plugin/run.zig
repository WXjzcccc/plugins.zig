//! The two analyzer entry points and the loop they share.
//!
//! `apkevidence` (evidence scope) analyzes every APK the host resolved from
//! the manifest's `inputs` patterns; `apkfile` (files scope) analyzes the
//! packages the user selected. Both receive their files as the run's inputs,
//! so the loop is the same and only the wording of the summary differs.

const std = @import("std");

const lc = @import("lovelycarve");
const analyze = @import("analyze.zig");
const logging = @import("../utils/logging.zig");
const records = @import("records.zig");

/// Evidence scope: run over every APK of the evidence item.
pub fn evidence(run: *const lc.Run) lc.Error!void {
    return analyzeRun(run, .evidence);
}

/// Files scope: run over the selected packages.
pub fn files(run: *const lc.Run) lc.Error!void {
    return analyzeRun(run, .files);
}

fn analyzeRun(run: *const lc.Run, scope: Scope) lc.Error!void {
    logging.bind(run.context());
    defer logging.unbind();

    const settings = analyze.Settings.fromOptions(run.optionValues());
    const inputs = run.inputsOf();
    if (inputs.len == 0) {
        const empty = if (scope == .files) "没有选择 APK 文件" else "没有发现 APK 文件";
        run.setSummary(empty);
        run.log(.info, "the run resolved no APK inputs");
        return;
    }

    var analyzed: u64 = 0;
    var failed: u64 = 0;
    for (inputs, 0..) |file, index| {
        try run.checkCancelled();
        try run.progress(index, inputs.len, analyze.displayPath(file));
        if (try analyze.analyzeFile(run, file, settings)) |failure| {
            failed += 1;
            // A package that cannot be read or parsed is a warning of the run,
            // not a failure: the other packages still produce results.
            try run.warnFile(file, failure.code, failure.message);
            run.log(.warn, failure.message);
        } else {
            analyzed += 1;
        }
    }
    try run.progress(inputs.len, inputs.len, null);

    const summary = try std.fmt.allocPrint(
        run.context().arena,
        "分析 {d} 个 APK（失败 {d} 个）",
        .{ analyzed, failed },
    );
    run.setSummary(summary);
    run.log(.info, summary);
}

/// Which analyzer started the run; it only changes the empty-run message.
pub const Scope = enum { evidence, files };

const testing = std.testing;

const test_plugin = lc.Plugin{
    .id = "org.example.apk",
    .records = &records.all,
    .analyzers = &.{
        lc.analyzer("apkevidence", evidence),
        lc.analyzer("apkfile", files),
    },
};

test "a selected non-apk is a warning with its file id" {
    var stub = lc.testing.Stub.init(testing.allocator, null, MockFile.handle);
    defer stub.deinit();
    var api = stub.api();
    var table = try lc.testing.entry(&api, &test_plugin);
    defer table.destroy(table.instance);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const reply = try lc.testing.callOk(alloc, &table, 2, "run.start", try startParams(alloc, "apkfile", "broken.apk"));
    try testing.expect(reply != null);
    try testing.expectEqual(@as(usize, 1), stub.warnings.items.len);
    try testing.expectEqualStrings("APK_PARSE_FAILED", stub.warnings.items[0].code);
    try testing.expectEqualStrings("file-1", stub.warnings.items[0].file_id.?);
    try testing.expectEqualStrings("分析 0 个 APK（失败 1 个）", reply.?.getString("summary").?);
}

test "a run without inputs says so instead of failing" {
    var stub = lc.testing.Stub.init(testing.allocator, null, MockFile.handle);
    defer stub.deinit();
    var api = stub.api();
    var table = try lc.testing.entry(&api, &test_plugin);
    defer table.destroy(table.instance);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const reply = try lc.testing.callOk(alloc, &table, 2, "run.start", try startParams(alloc, "apkfile", null));
    try testing.expectEqual(@as(u64, 0), stub.emittedCount());
    try testing.expectEqual(@as(usize, 0), stub.warnings.items.len);
    try testing.expectEqualStrings("没有选择 APK 文件", reply.?.getString("summary").?);
}

test "an empty evidence run names the evidence case, not the selection" {
    var stub = lc.testing.Stub.init(testing.allocator, null, MockFile.handle);
    defer stub.deinit();
    var api = stub.api();
    var table = try lc.testing.entry(&api, &test_plugin);
    defer table.destroy(table.instance);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const reply = try lc.testing.callOk(alloc, &table, 2, "run.start", try startParams(alloc, "apkevidence", null));
    try testing.expectEqualStrings("没有发现 APK 文件", reply.?.getString("summary").?);
}

/// A `run.start` for one analyzer; `name` null means no input at all.
fn startParams(alloc: std.mem.Allocator, analyzer: []const u8, name: ?[]const u8) !lc.wire.Value {
    var inputs: std.ArrayList(lc.wire.Value) = .empty;
    if (name) |file_name| {
        try inputs.append(alloc, try lc.wire.mapOf(alloc, &.{
            lc.wire.entry("file_id", lc.wire.str("file-1")),
            lc.wire.entry("name", lc.wire.str(file_name)),
            lc.wire.entry("size", lc.wire.uint(4)),
            lc.wire.entry("root_path", lc.wire.str(file_name)),
        }));
    }
    const target = if (std.mem.eql(u8, analyzer, "apkfile"))
        try lc.wire.mapOf(alloc, &.{lc.wire.entry("kind", lc.wire.str("files"))})
    else
        try lc.wire.mapOf(alloc, &.{
            lc.wire.entry("kind", lc.wire.str("evidence")),
            lc.wire.entry("view", try lc.wire.mapOf(alloc, &.{
                lc.wire.entry("view_id", lc.wire.str("view-1")),
                lc.wire.entry("label", lc.wire.str("evidence")),
            })),
        });
    return lc.wire.mapOf(alloc, &.{
        lc.wire.entry("run_id", lc.wire.str("run-1")),
        lc.wire.entry("analyzer", lc.wire.str(analyzer)),
        lc.wire.entry("target", target),
        lc.wire.entry("inputs", .{ .array = inputs.items }),
        lc.wire.entry("locale", lc.wire.str("zh-CN")),
    });
}

const MockFile = struct {
    fn handle(
        _: ?*anyopaque,
        _: std.mem.Allocator,
        method: []const u8,
        _: lc.wire.Value,
    ) lc.testing.Reply {
        if (std.mem.eql(u8, method, "file.read")) {
            // Not a ZIP: the parser rejects it, which is the warning above.
            return .{ .value = .{ .bytes = "nope" } };
        }
        return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
    }
};
