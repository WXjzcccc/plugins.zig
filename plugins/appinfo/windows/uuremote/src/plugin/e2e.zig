//! End-to-end run over the real sample files in `testfiles/` — actual
//! GameViewer artifacts collected from a live installation (the registry
//! hive mirrors the winsysteminfo plugin's `testfiles/7` set). The stub
//! host serves the files from memory; the analyzer runs unchanged.
//!
//! The directory is resolved relative to this source file, so the test works
//! both from the repository root and from the plugin directory. A missing
//! testfiles directory skips the test (the parsers keep their own unit
//! tests), so a fresh checkout without samples still builds green.
//!
//! The assertions check *structure only* — record families, field presence,
//! merge and encryption flags. No account identifiers from the samples are
//! copied into this file; the samples themselves live in `testfiles/`.

const std = @import("std");
const lc = @import("lovelycarve");

const records = @import("records.zig");
const registry_mod = @import("../core/registry.zig");
const run_mod = @import("run.zig");

/// One file of the store.
const Fixture = struct {
    id: []const u8,
    view_path: []const u8,
    bytes: []const u8,
};

/// The state handed to the stub host handler.
const Store = struct {
    fixtures: []const Fixture,
};

/// The host side of the stub: answers `file.read` from the store.
fn fileHandler(
    state: ?*anyopaque,
    alloc: std.mem.Allocator,
    method: []const u8,
    params: lc.wire.Value,
) lc.testing.Reply {
    _ = alloc;
    if (!std.mem.eql(u8, method, "file.read")) {
        return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
    }
    const store: *Store = @ptrCast(@alignCast(state.?));
    const file_id = params.getString("file_id") orelse
        return .{ .fault = .{ .code = "INVALID_PARAMS", .message = "no file_id" } };
    const offset = params.getUint("offset") orelse 0;
    const length = params.getUint("length") orelse 0;
    for (store.fixtures) |fixture| {
        if (!std.mem.eql(u8, fixture.id, file_id)) continue;
        if (offset >= fixture.bytes.len) return .{ .value = .{ .bytes = "" } };
        const end = @min(offset + length, fixture.bytes.len);
        return .{ .value = .{ .bytes = fixture.bytes[@intCast(offset)..@intCast(end)] } };
    }
    return .{ .fault = .{ .code = "FILE_NOT_FOUND", .message = file_id } };
}

/// Candidate `<plugin root>/testfiles` paths, tried in order. `@src().file`
/// is absolute or relative to whatever root the compiler was given, so when
/// the derived root is empty the repository layout and the plugin directory
/// are probed as fallbacks.
fn testfilesCandidates(arena: std.mem.Allocator) ![]const []const u8 {
    const plugin_root = comptime pluginRoot();
    if (plugin_root.len > 0) {
        const path = try std.fmt.allocPrint(arena, "{s}/testfiles", .{plugin_root});
        const candidates = try arena.alloc([]const u8, 1);
        candidates[0] = path;
        return candidates;
    }
    const candidates = try arena.alloc([]const u8, 2);
    candidates[0] = "plugins/appinfo/windows/uuremote/testfiles";
    candidates[1] = "testfiles";
    return candidates;
}

/// The plugin root directory (two levels above `src/plugin/`), computed at
/// comptime from the source path of this file.
fn pluginRoot() []const u8 {
    const src = @src().file;
    // Cut "/src/plugin/e2e.zig" (either separator) off the end.
    const markers = [_][]const u8{ "/src/plugin/e2e.zig", "\\src\\plugin\\e2e.zig" };
    for (markers) |marker| {
        if (std.mem.lastIndexOf(u8, src, marker)) |at| {
            return src[0..at];
        }
    }
    return "";
}

pub fn runEvidenceTest() !void {
    const testing = std.testing;
    const allocator = testing.allocator;

    // The fixture arena sits on libc's allocator: the samples include a
    // full registry hive (hundreds of MB), which must not go through the
    // leak-checking test allocator.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = std.testing.io;
    const candidates = try testfilesCandidates(arena);
    var dir: std.Io.Dir = for (candidates) |candidate| {
        if (std.Io.Dir.cwd().openDir(io, candidate, .{ .iterate = true })) |opened| {
            break opened;
        } else |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        }
    } else {
        std.debug.print("(testfiles/ 未找到，跳过端到端样例测试)\n", .{});
        return;
    };
    defer dir.close(io);

    // Walk the directory and read every file into the store.
    var fixtures: std.ArrayList(Fixture) = .empty;
    try walk(io, arena, dir, &fixtures);
    if (fixtures.items.len == 0) return; // an empty testfiles dir: nothing to prove

    var store_state = Store{ .fixtures = fixtures.items };
    var stub = lc.testing.Stub.init(allocator, &store_state, fileHandler);
    defer stub.deinit();
    const api = stub.api();
    var cancelled = std.atomic.Value(bool).init(false);
    // The run context shares the fixture arena: every host-side allocation
    // of the run dies with it at the end of the test.
    const ctx = lc.host.Context{
        .host = lc.host.HostConnection.init(api),
        .cancelled = &cancelled,
        .arena = arena,
        .alloc = arena,
    };

    var inputs: std.ArrayList(lc.protocol.FileInfo) = .empty;
    defer inputs.deinit(allocator);
    var hive_fixture: ?Fixture = null;
    for (fixtures.items) |fixture| {
        // The registry hive goes through the direct collector below: serving
        // a multi-hundred-MB file through the stub's `file.read` round-trips
        // kills the build runner's test protocol, while the collector itself
        // handles it fine (verified by the standalone run and the probe).
        if (std.ascii.eqlIgnoreCase(std.fs.path.basename(fixture.view_path), "NTUSER.DAT")) {
            hive_fixture = fixture;
            continue;
        }
        try inputs.append(allocator, .{
            .file_id = fixture.id,
            .name = std.fs.path.basename(fixture.view_path),
            .size = fixture.bytes.len,
            .view_path = fixture.view_path,
        });
    }

    const start = lc.protocol.RunStart{
        .run_id = "run",
        .analyzer = "uuremoteevidence",
        .target = .{ .files = {} },
        .inputs = inputs.items,
    };
    var run = try lc.Run.init(ctx, start, &records.all);
    try run_mod.evidence(&run);
    // The host flushes the record buffer when the run settles; the stub test
    // does it here so the emitted records can be inspected.
    try run.flush();

    // ------------------------------------------------------- expectations

    // Structure only: every record family appears, every identity field is
    // present, and the sample's merge/encryption facts hold. The values
    // themselves stay in testfiles/ and are never named here.
    const emitted = try stub.emittedRecords(allocator);
    defer allocator.free(emitted);

    var counts = std.StringHashMap(usize).init(allocator);
    defer counts.deinit();
    for (emitted) |record| {
        const record_type = record.getString("type") orelse continue;
        const entry = try counts.getOrPut(record_type);
        if (!entry.found_existing) entry.value_ptr.* = 0;
        entry.value_ptr.* += 1;
    }
    try testing.expect(counts.get("uuremote.account") orelse 0 >= 1);
    try testing.expect(counts.get("uuremote.device") orelse 0 >= 1);
    try testing.expect(counts.get("uuremote.session") orelse 0 >= 1);
    try testing.expect(counts.get("uuremote.run_log") orelse 0 >= 1);
    try testing.expect(counts.get("uuremote.telemetry") orelse 0 >= 1);
    try testing.expect(counts.get("uuremote.file_trace") orelse 0 >= 1);
    try testing.expect(counts.get("uuremote.upgrade") orelse 0 >= 1);
    // The registry hive of the sample set is larger than the store cap, so
    // the login family only appears when a small-enough hive is present; the
    // registry reader itself is covered by the unit tests and the probe.
    if (counts.get("uuremote.login")) |login_count| {
        try testing.expect(login_count >= 1);
    }

    var local_devices: usize = 0;
    var remote_devices_with_trace: usize = 0;
    var merged_sessions: usize = 0;
    var unencrypted_sessions: usize = 0;
    for (emitted) |record| {
        const record_type = record.getString("type") orelse continue;
        const values = record.get("values").?.array;
        if (std.mem.eql(u8, record_type, "uuremote.account")) {
            // user id, device id and the JWT client id are all present.
            for (values[0..3]) |value| {
                try testing.expect(value == .string and value.string.len > 0);
            }
        } else if (std.mem.eql(u8, record_type, "uuremote.device")) {
            try testing.expect(values[0] == .string and values[0].string.len == 16);
            if (std.mem.eql(u8, values[1].string, "local")) {
                local_devices += 1;
                try testing.expect(values[3].boolean); // assist code configured
            } else {
                try testing.expect(std.mem.eql(u8, values[1].string, "remote"));
                if (values[2] != .nil or values[5].boolean or values[7].boolean) {
                    remote_devices_with_trace += 1;
                }
            }
        } else if (std.mem.eql(u8, record_type, "uuremote.session")) {
            try testing.expect(values[6].boolean); // SLOG-encrypted content
            if (!values[6].boolean) unencrypted_sessions += 1;
            if (values[5].uint >= 2) merged_sessions += 1; // connection + streamer
            try testing.expect(values[1] != .nil); // start time from the file name
        } else if (std.mem.eql(u8, record_type, "uuremote.run_log")) {
            try testing.expect(values[0] == .string and values[0].string.len > 0);
            try testing.expect(values[1] != .nil);
        } else if (std.mem.eql(u8, record_type, "uuremote.telemetry")) {
            try testing.expect(values[0] == .string and values[0].string.len > 0);
            try testing.expect(values[1] != .nil); // release known
            try testing.expect(values[4] != .nil); // started known
        } else if (std.mem.eql(u8, record_type, "uuremote.file_trace")) {
            try testing.expect(values[0] == .string and values[0].string.len == 16);
            try testing.expect(values[1] == .string and values[1].string.len > 0);
        } else if (std.mem.eql(u8, record_type, "uuremote.upgrade")) {
            try testing.expect(values[0] == .string and values[0].string.len > 0);
            try testing.expect(values[1] != .nil); // discovered timestamp
        } else if (std.mem.eql(u8, record_type, "uuremote.login")) {
            try testing.expect(values[0] == .string and values[0].string.len > 0);
            try testing.expect(values[1] != .nil); // login time decoded
            try testing.expect(values[2] != .nil); // app version known
        }
    }
    try testing.expectEqual(@as(usize, 1), local_devices);
    try testing.expect(remote_devices_with_trace >= 1);
    try testing.expect(merged_sessions >= 1);
    try testing.expectEqual(@as(usize, 0), unencrypted_sessions);

    // The run finished with a summary that names the input count.
    var summarized = false;
    for (stub.logs.items) |line| {
        if (std.mem.indexOf(u8, line.message, "个输入") != null) summarized = true;
    }
    try testing.expect(summarized);

    // The registry path over the real sample hive, run directly (see the
    // input loop above for why it is not part of the stub run). Structural
    // assertions only: the values stay in the sample file.
    if (hive_fixture) |hive| {
        var info = try registry_mod.collect(arena, std.heap.c_allocator, hive.bytes);
        defer registry_mod.freeInfo(arena, &info);
        try testing.expect(info.app_version != null);
        try testing.expect(info.install_dir != null);
        try testing.expect(info.installed orelse false);
        try testing.expect(info.logins.len >= 1);
        for (info.logins) |login| {
            try testing.expect(login.phone.len > 0);
            try testing.expect(login.login_ms != null);
        }
    }
}

/// Recursively reads `dir` into `fixtures`, one entry per file. View paths
/// use `/` separators regardless of the host platform.
fn walk(
    io: std.Io,
    arena: std.mem.Allocator,
    dir: std.Io.Dir,
    fixtures: *std.ArrayList(Fixture),
) !void {
    var iterator = try dir.walk(arena);
    defer iterator.deinit();
    var next_id: usize = 0;
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file) continue;
        // `entry.dir` is the containing directory: read via `basename`, keep
        // the root-relative `path` for the view path. Real hives reach
        // hundreds of MB; the sample NTUSER.DAT is read in full.
        const bytes = try entry.dir.readFileAlloc(io, entry.basename, arena, .limited(1 << 30));
        const view_path = try arena.dupe(u8, entry.path);
        for (view_path) |*c| {
            if (c.* == '\\') c.* = '/';
        }
        try fixtures.append(arena, .{
            .id = try std.fmt.allocPrint(arena, "f{d}", .{next_id}),
            .view_path = view_path,
            .bytes = bytes,
        });
        next_id += 1;
    }
}
