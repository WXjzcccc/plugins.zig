//! A minimal LovelyCarve plugin (LPP v2) built on the shared Zig SDK.
//!
//! It does exactly one thing: read `etc/os-release` from a Linux evidence
//! image and emit one record per reported field. `analyze` below is the whole
//! analyzer — that is the part you replace. Everything else is identity, the
//! record schema and the entry point, all of which the SDK
//! (`plugins/zig-sdk`) provides.
//!
//! Build and try it:
//!
//!   zig build test                     # unit tests, with a fake host
//!   zig build -Doptimize=ReleaseSafe   # zig-out/lib/zigtemplate.dll
//!   zig build schema                   # zig-out/schema.json from the library
//!   zig build package                  # zig-out/<id>-<version>-<platform>.lcpkg

const std = @import("std");
const lc = @import("lovelycarve");

// ------------------------------------------------------------------ identity

/// Must match `id` in plugin.toml. The host refuses a package whose manifest
/// id and `plugin.hello` id disagree.
const PLUGIN_ID = "com.wxjzc.zigtemplate";

/// Must match `[[analyzer]] id` in plugin.toml. Analyzer ids are lowercase
/// identifiers (a-z, 0-9, _) on both sides of the handshake — a dotted id is a
/// record-type rule, not an analyzer rule.
const ANALYZER_ID = "zigtemplateosrelease";

/// Record type prefix: everything a plugin emits lives in its own namespace.
const NS = "zigtemplate";

/// The one record type this analyzer emits.
const RELEASE_TYPE = NS ++ ".release";

/// Where os-release normally lives, then the fallback location.
const RELEASE_PATHS = [_][]const u8{ "etc/os-release", "usr/lib/os-release" };

/// Cap on the file read: os-release is a few hundred bytes.
const MAX_RELEASE_BYTES: u64 = 1024 * 1024;

/// Fields worth reporting, in report order. Add or remove as you like.
const REPORTED = [_]struct { key: []const u8, title: []const u8 }{
    .{ .key = "PRETTY_NAME", .title = "系统" },
    .{ .key = "NAME", .title = "操作系统类型" },
    .{ .key = "VERSION_ID", .title = "系统版本号" },
    .{ .key = "ID", .title = "操作系统名称" },
    .{ .key = "ID_LIKE", .title = "父发行版本" },
    .{ .key = "HOME_URL", .title = "主页" },
};

// -------------------------------------------------------------- record schema

/// The typed shape of `zigtemplate.release`: three positional fields, in this
/// order. `key` identifies the record and `{key}` is its default title; the
/// host renders one table column per field and stores the schema next to the
/// rows, so the results stay readable without the plugin.
const RELEASE_SCHEMA = lc.RecordSchema.new(RELEASE_TYPE, "系统信息", &.{
    lc.Field.new("key", "英文名称", .text).asKey(),
    lc.Field.new("field_value", "值", .text),
    lc.Field.new("source", "源文件", .path),
}).withTitle("{key}");

// -------------------------------------------------------------------- plugin

/// The one thing the host looks for: identity, the record types this library
/// emits and the analyzers it implements. The manifest's analyzer list must
/// match `analyzers`; the exported `schema.json` must match `records`.
pub const plugin = lc.Plugin{
    .id = PLUGIN_ID,
    .records = &.{RELEASE_SCHEMA},
    .analyzers = &.{lc.analyzer(ANALYZER_ID, analyze)},
};

comptime {
    lc.exportPlugin(@This());
}

// ------------------------------------------------------------------ analysis

/// Runs against a system view. `run.context().arena` owns everything the run
/// allocates; records are validated against the schema and sent in batches by
/// `emit`, and an error discards everything the run emitted.
fn analyze(run: *const lc.Run) lc.Error!void {
    const view = try run.requireView();
    run.log(.debug, "scanning the view for os-release");
    try run.progress(0, 2, "reading os-release");

    const release = (try readRelease(view)) orelse {
        // Levels are the host's own: the desktop app defaults to a `warn`
        // filter, so `.warn` and `.err` show up without extra setup and
        // `.info` / `.debug` need `RUST_LOG=plugin=info` (`=debug`).
        run.log(.warn, "no os-release found in the view");
        run.setSummary("没有找到 os-release");
        return;
    };

    try run.progress(1, 2, "parsing");
    const arena = run.context().arena;
    run.log(.info, try std.fmt.allocPrint(arena, "parsing {s} at {s}", .{
        release.root,
        release.path,
    }));

    const fields = try parse(arena, release.text);
    var emitted: usize = 0;
    for (REPORTED) |reported| {
        const value = find(fields, reported.key) orelse continue;
        // Positional values, in RELEASE_SCHEMA field order: key, field_value,
        // source. `.from` attaches the file's provenance (volume key, path
        // inside the volume, node id), which is what「定位源文件」uses.
        try run.record(RELEASE_TYPE, &.{
            lc.wire.str(reported.key),
            lc.wire.str(value),
            lc.wire.str(release.path),
        }).from(&release.file).emit();
        emitted += 1;
    }

    try run.progress(2, 2, null);
    const summary = try std.fmt.allocPrint(arena, "{s}: {d} 个字段", .{
        release.path,
        emitted,
    });
    run.setSummary(summary);
    run.log(.info, summary);
}

const Release = struct {
    file: lc.FileRef,
    /// Path inside the view, relative to its root (`etc/os-release`).
    path: []const u8,
    /// Volume key of the root volume (`part:0`).
    root: []const u8,
    text: []const u8,
};

/// The first path that exists in the view. `open` answers null for a missing
/// path, which is the normal case for `usr/lib/os-release` on most
/// distributions.
fn readRelease(view: lc.View) lc.Error!?Release {
    for (RELEASE_PATHS) |path| {
        const file = (try view.open(path)) orelse continue;
        return .{
            .file = file,
            .path = path,
            .root = file.root() orelse "",
            .text = try file.readText(MAX_RELEASE_BYTES),
        };
    }
    return null;
}

// ------------------------------------------------------------------- parsing

const Field = struct { key: []const u8, value: []const u8 };

/// `KEY=value` lines, skipping comments and blank lines. Quotes are stripped
/// and `\` escapes are resolved, per the os-release spec.
fn parse(arena: std.mem.Allocator, text: []const u8) lc.Error![]const Field {
    var fields: std.ArrayList(Field) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const equals = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        if (key.len == 0) continue;
        const value = try unquote(arena, std.mem.trim(u8, line[equals + 1 ..], " \t"));
        try fields.append(arena, .{ .key = try arena.dupe(u8, key), .value = value });
    }
    return fields.items;
}

fn unquote(arena: std.mem.Allocator, raw: []const u8) lc.Error![]const u8 {
    if (raw.len < 2) return arena.dupe(u8, raw);
    const quote = raw[0];
    if ((quote != '"' and quote != '\'') or raw[raw.len - 1] != quote) return arena.dupe(u8, raw);

    const inner = raw[1 .. raw.len - 1];
    if (quote == '\'') return arena.dupe(u8, inner);

    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < inner.len) : (index += 1) {
        if (inner[index] == 0x5c and index + 1 < inner.len) {
            index += 1;
            switch (inner[index]) {
                'n' => try out.append(arena, '\n'),
                't' => try out.append(arena, '\t'),
                else => try out.append(arena, inner[index]),
            }
        } else {
            try out.append(arena, inner[index]);
        }
    }
    return out.items;
}

fn find(fields: []const Field, key: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.key, key)) return field.value;
    }
    return null;
}

// --------------------------------------------------------------------- tests

const testing = std.testing;

/// A fake host for one system view: `etc/os-release` holds `contents` (and does
/// not exist when that is empty). It answers the evidence side only —
/// `view.open` and `file.read` — while the stub itself answers and records
/// `run.emit`, `run.progress` and `run.warn`.
const MockHost = struct {
    var contents: []const u8 = "";

    fn handle(
        state: ?*anyopaque,
        alloc: std.mem.Allocator,
        method: []const u8,
        params: lc.wire.Value,
    ) lc.testing.Reply {
        _ = state;
        if (std.mem.eql(u8, method, "view.open")) {
            const path = params.getString("path") orelse "";
            if (contents.len == 0 or !std.mem.eql(u8, path, "etc/os-release")) {
                return .{ .value = .nil };
            }
            return .{ .value = lc.wire.mapOf(alloc, &.{
                lc.wire.entry("file_id", lc.wire.str("file-1")),
                lc.wire.entry("name", lc.wire.str("os-release")),
                lc.wire.entry("size", lc.wire.uint(contents.len)),
                lc.wire.entry("view_path", lc.wire.str(path)),
                lc.wire.entry("root", lc.wire.str("part:0")),
                lc.wire.entry("root_path", lc.wire.str(path)),
                lc.wire.entry("node_id", lc.wire.str("node-1")),
            }) catch return oom() };
        }
        if (std.mem.eql(u8, method, "file.read")) {
            return .{ .value = .{ .bytes = contents } };
        }
        return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
    }

    fn oom() lc.testing.Reply {
        return .{ .fault = .{ .code = "OUT_OF_MEMORY", .message = "the fake host ran out of memory" } };
    }
};

/// A stub host, an instance created through the real entry point and an arena
/// for the decoded replies.
///
/// It is filled in place rather than returned by value: the plugin table holds
/// the addresses of `stub` and `arena_state`, which would dangle after a move.
const Fixture = struct {
    stub: lc.testing.Stub,
    table: lc.abi.PluginApiV1,
    arena_state: std.heap.ArenaAllocator,

    fn init(self: *Fixture, alloc: std.mem.Allocator) !void {
        self.* = .{
            .stub = lc.testing.Stub.init(alloc, null, MockHost.handle),
            .table = undefined,
            .arena_state = std.heap.ArenaAllocator.init(alloc),
        };
        var api = self.stub.api();
        self.table = try lc.testing.entry(&api, &plugin);
    }

    fn arena(self: *Fixture) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    fn deinit(self: *Fixture) void {
        self.table.destroy(self.table.instance);
        self.stub.deinit();
        self.arena_state.deinit();
    }

    /// `run.start` over one Linux system view, shaped exactly like the host
    /// sends it. The reply is `{summary}`.
    fn start(self: *Fixture, analyzer: []const u8) !?lc.wire.Value {
        const alloc = self.arena();
        const view = try lc.wire.mapOf(alloc, &.{
            lc.wire.entry("view_id", lc.wire.str("view-1")),
            lc.wire.entry("label", lc.wire.str("Test Linux")),
            lc.wire.entry("system", try lc.wire.mapOf(alloc, &.{
                lc.wire.entry("id", lc.wire.str("linux@part:0")),
                lc.wire.entry("family", lc.wire.str("linux")),
                lc.wire.entry("product", lc.wire.str("Test Linux")),
                lc.wire.entry("root", lc.wire.str("part:0")),
            })),
            lc.wire.entry("mounts", try lc.wire.arrayOf(alloc, &.{try lc.wire.mapOf(alloc, &.{
                lc.wire.entry("path", lc.wire.str("")),
                lc.wire.entry("root", lc.wire.str("part:0")),
                lc.wire.entry("source", lc.wire.str("root")),
            })})),
        });
        const params = try lc.wire.mapOf(alloc, &.{
            lc.wire.entry("run_id", lc.wire.str("run-1")),
            lc.wire.entry("analyzer", lc.wire.str(analyzer)),
            lc.wire.entry("target", try lc.wire.mapOf(alloc, &.{
                lc.wire.entry("kind", lc.wire.str("system")),
                lc.wire.entry("view", view),
            })),
            lc.wire.entry("locale", lc.wire.str("zh-CN")),
        });
        return lc.testing.callOk(alloc, &self.table, 2, "run.start", params);
    }
};

test "the handshake advertises the plugin, its analyzer and its records" {
    var fixture: Fixture = undefined;
    try fixture.init(testing.allocator);
    defer fixture.deinit();

    const hello = try lc.testing.describe(fixture.arena(), &fixture.table);
    try testing.expectEqual(@as(u64, 2), hello.getUint("protocol").?);
    try testing.expectEqualStrings(PLUGIN_ID, hello.getString("plugin").?);
    try testing.expectEqualStrings(lc.plugin_mod.SDK_VERSION, hello.getString("sdk").?);
    try testing.expectEqual(@as(usize, 0), hello.get("filesystems").?.array.len);

    const analyzers = hello.get("analyzers").?.array;
    try testing.expectEqual(@as(usize, 1), analyzers.len);
    try testing.expectEqualStrings(ANALYZER_ID, analyzers[0].string);

    // `profile.fact` is registered for every plugin; ours follows it.
    const records = hello.get("records").?.array;
    try testing.expectEqual(@as(usize, 2), records.len);
    try testing.expectEqualStrings("profile.fact", records[0].getString("type").?);
    try testing.expectEqualStrings(RELEASE_TYPE, records[1].getString("type").?);
    try testing.expectEqualStrings("系统信息", records[1].getString("label").?);
    try testing.expectEqualStrings("{key}", records[1].getString("title").?);
    const fields = records[1].get("fields").?.array;
    try testing.expectEqual(@as(usize, 3), fields.len);
    try testing.expectEqualStrings("key", fields[0].getString("id").?);
    try testing.expectEqualStrings("text", fields[0].getString("kind").?);
    try testing.expectEqual(true, fields[0].get("key").?.boolean);
    try testing.expectEqualStrings("path", fields[2].getString("kind").?);

    // The host compares this hash with the package's schema.json.
    try testing.expect(std.mem.startsWith(u8, hello.getString("schema_hash").?, "fnv1a64:"));
}

test "run.start turns os-release into one record per reported field" {
    MockHost.contents =
        \\PRETTY_NAME="Test OS 1.0"
        \\NAME=Test
        \\VERSION_ID="1.0"
        \\ID=test
        \\ID_LIKE=debian
        \\HOME_URL="https://example.com/"
        \\# a comment, and a line with no equals sign
        \\NOT_A_FIELD
        \\EMPTY=
        \\
    ;
    defer MockHost.contents = "";

    var fixture: Fixture = undefined;
    try fixture.init(testing.allocator);
    defer fixture.deinit();

    const reply = (try fixture.start(ANALYZER_ID)).?;

    // Only the six reported fields become records: NOT_A_FIELD has no "=",
    // EMPTY is not reported, and the comment is skipped.
    const records = try fixture.stub.emittedRecords(fixture.arena());
    try testing.expectEqual(@as(usize, 6), records.len);

    const first = records[0];
    try testing.expectEqualStrings(RELEASE_TYPE, first.getString("type").?);
    // Values are positional, in schema field order.
    const values = first.get("values").?.array;
    try testing.expectEqual(@as(usize, 3), values.len);
    try testing.expectEqualStrings("PRETTY_NAME", values[0].string);
    try testing.expectEqualStrings("Test OS 1.0", values[1].string);
    try testing.expectEqualStrings("etc/os-release", values[2].string);
    // No explicit title: the schema's {key} template renders it.
    try testing.expect(first.get("title") == null);

    // Provenance, so the host can offer「定位源文件」.
    const sources = first.get("sources").?.array;
    try testing.expectEqual(@as(usize, 1), sources.len);
    try testing.expectEqualStrings("part:0", sources[0].getString("root").?);
    try testing.expectEqualStrings("etc/os-release", sources[0].getString("path").?);
    try testing.expectEqualStrings("node-1", sources[0].getString("node_id").?);

    // The view was opened, and the file read once per record attempt.
    try testing.expect(fixture.stub.saw("view.open"));
    try testing.expect(fixture.stub.saw("file.read"));
    try testing.expect(fixture.stub.saw("run.emit"));

    try testing.expect(std.mem.indexOf(u8, reply.getString("summary").?, "6 个字段") != null);
}

test "a view without os-release emits nothing and says so" {
    MockHost.contents = "";
    var fixture: Fixture = undefined;
    try fixture.init(testing.allocator);
    defer fixture.deinit();

    const reply = (try fixture.start(ANALYZER_ID)).?;
    try testing.expectEqual(@as(u64, 0), fixture.stub.emittedCount());
    try testing.expectEqualStrings("没有找到 os-release", reply.getString("summary").?);

    // A missing file is logged as a warning, not reported as a run warning and
    // certainly not as a failure: `run.warn` is for parts of a run that could
    // not be completed.
    try testing.expectEqual(@as(usize, 0), fixture.stub.warnings.items.len);
    const logs = fixture.stub.logs.items;
    try testing.expectEqual(lc.abi.LOG_WARN, logs[logs.len - 1].level);
    try testing.expectEqualStrings("no os-release found in the view", logs[logs.len - 1].message);
}

test "the analyzer logs its scan, its progress and its outcome" {
    MockHost.contents =
        \\PRETTY_NAME="Test OS 1.0"
        \\NAME=Test
        \\
    ;
    defer MockHost.contents = "";

    var fixture: Fixture = undefined;
    try fixture.init(testing.allocator);
    defer fixture.deinit();

    _ = try fixture.start(ANALYZER_ID);

    // `run.log` is a side channel: the stub records every line with its level,
    // in call order, and none of it reaches the records.
    const logs = fixture.stub.logs.items;
    try testing.expectEqual(@as(usize, 3), logs.len);
    try testing.expectEqual(lc.abi.LOG_DEBUG, logs[0].level);
    try testing.expectEqualStrings("scanning the view for os-release", logs[0].message);
    try testing.expectEqual(lc.abi.LOG_INFO, logs[1].level);
    try testing.expectEqualStrings("parsing part:0 at etc/os-release", logs[1].message);
    try testing.expectEqual(lc.abi.LOG_INFO, logs[2].level);
    try testing.expectEqualStrings("etc/os-release: 2 个字段", logs[2].message);

    const progress = fixture.stub.progress.items;
    try testing.expectEqual(@as(usize, 3), progress.len);
    try testing.expectEqual(@as(u64, 0), progress[0].current);
    try testing.expectEqual(@as(?u64, 2), progress[0].total);
    try testing.expectEqualStrings("reading os-release", progress[0].message.?);
    try testing.expectEqual(@as(u64, 2), progress[2].current);
    try testing.expect(progress[2].message == null);
}

test "an unknown analyzer is rejected, not guessed" {
    var fixture: Fixture = undefined;
    try fixture.init(testing.allocator);
    defer fixture.deinit();

    const reply = try lc.testing.call(
        fixture.arena(),
        &fixture.table,
        3,
        "run.start",
        try lc.wire.mapOf(fixture.arena(), &.{
            lc.wire.entry("run_id", lc.wire.str("run-2")),
            lc.wire.entry("analyzer", lc.wire.str("otheranalyzer")),
            lc.wire.entry("target", try lc.wire.mapOf(fixture.arena(), &.{
                lc.wire.entry("kind", lc.wire.str("files")),
            })),
        }),
    );
    try testing.expectEqual(lc.abi.STATUS_ERROR, reply.status);
    try testing.expectEqualStrings("INVALID_ANALYZER", reply.fault.?.code);
}

test "os-release parsing follows the spec" {
    var alloc_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer alloc_state.deinit();
    const alloc = alloc_state.allocator();

    const fields = try parse(alloc,
        \\# a comment
        \\
        \\NAME=Test
        \\PRETTY_NAME="Test \"OS\""
        \\VERSION_ID='1.0'
        \\ESCAPED="a\nb\tc\qd"
        \\  SPACED  =  value with spaces
        \\NOT_A_FIELD
    );
    try testing.expectEqual(@as(usize, 5), fields.len);
    try testing.expectEqualStrings("Test", find(fields, "NAME").?);
    try testing.expectEqualStrings("Test \"OS\"", find(fields, "PRETTY_NAME").?);
    try testing.expectEqualStrings("1.0", find(fields, "VERSION_ID").?);
    try testing.expectEqualStrings("a\nb\tcqd", find(fields, "ESCAPED").?);
    try testing.expectEqualStrings("value with spaces", find(fields, "SPACED").?);
    try testing.expect(find(fields, "NOT_A_FIELD") == null);
}
