//! From run inputs to records: parse each NTUSER-class hive and emit its
//! Navicat connection profiles.
//!
//! Memory: hives are loaded one at a time through libc's allocator and a
//! per-hive arena holds every parsed value, so a run's peak stays around two
//! copies of its largest hive.

const std = @import("std");

const lc = @import("lovelycarve");
const hive_mod = @import("../core/hive.zig");
const navicat = @import("../core/navicat.zig");
const records = @import("records.zig");

/// Largest hive read per run; plugin.toml caps the process at 2 GiB.
pub const MAX_HIVE_SIZE: u64 = 1024 * 1024 * 1024;

/// The display path of a file: its path inside the run's view, else the path
/// inside its volume, else its name.
pub fn displayPath(file: lc.FileRef) []const u8 {
    return file.viewPath() orelse file.rootPath() orelse file.name();
}

/// Reads the whole file into a libc-owned buffer (freed by the caller).
fn readWhole(file: lc.FileRef, alloc: std.mem.Allocator, cap: u64) ![]u8 {
    const size = file.size();
    if (size > cap) return error.TooLarge;
    const length = std.math.cast(usize, size) orelse return error.TooLarge;
    const buffer = try alloc.alloc(u8, length);
    errdefer alloc.free(buffer);

    var position: usize = 0;
    while (position < length) {
        const want: u64 = @min(length - position, lc.MAX_HOST_READ);
        const reply = try file.context().callHost(lc.protocol.method.file_read, try lc.value.map(
            file.context().arena,
            &.{
                lc.value.entry("file_id", lc.value.str(file.id())),
                lc.value.entry("offset", lc.value.uint(position)),
                lc.value.entry("length", lc.value.uint(want)),
            },
        ));
        const chunk = try lc.value.intoBytes(reply, lc.protocol.method.file_read);
        if (chunk.len == 0 or chunk.len > want) return error.ShortRead;
        @memcpy(buffer[position..][0..chunk.len], chunk);
        position += chunk.len;
    }
    return buffer;
}

/// Formats a warning message in the run's arena (warnings are stored with the
/// run, so they must outlive this call).
fn message(run: *const lc.Run, comptime format: []const u8, args: anytype) lc.Error![]const u8 {
    return std.fmt.allocPrint(run.context().arena, format, args);
}

/// One registry analysis run over the hive inputs (either analyzer scope).
pub fn analyzeRun(run: *const lc.Run, inputs: []const lc.FileRef) lc.Error!void {
    const run_arena = run.context().arena;

    if (inputs.len == 0) {
        run.setSummary("没有发现 NTUSER.DAT 配置单元");
        run.log(.info, "the run resolved no NTUSER.DAT inputs");
        return;
    }

    var analyzed: u64 = 0;
    var failed: u64 = 0;
    var connections_total: u64 = 0;
    try run.progress(0, inputs.len, null);
    for (inputs, 0..) |file, index| {
        try run.checkCancelled();
        try run.progress(index, inputs.len, displayPath(file));
        if (try analyzeFile(run, file, &connections_total)) |failure| {
            failed += 1;
            // A hive that cannot be read or parsed is a warning of the run,
            // not a failure: the other hives still produce results.
            try run.warnFile(file, failure.code, failure.message);
            run.log(.err, failure.message);
        } else {
            analyzed += 1;
        }
    }
    try run.progress(inputs.len, inputs.len, null);

    const summary = try std.fmt.allocPrint(
        run_arena,
        "分析 {d} 个 NTUSER.DAT，发现 {d} 个 Navicat 连接（失败 {d} 个）",
        .{ analyzed, connections_total, failed },
    );
    run.setSummary(summary);
    run.log(.info, summary);
}

/// Why one hive could not be analyzed.
pub const Failure = struct {
    code: []const u8,
    message: []const u8,
};

/// Analyzes one hive; null on success, else the failure for the run warning.
/// Every stage logs: the input path up front, the detailed reason on failure,
/// the per-hive result at the end.
fn analyzeFile(run: *const lc.Run, file: lc.FileRef, connections_total: *u64) lc.Error!?Failure {
    const path = displayPath(file);
    const run_arena = run.context().arena;
    run.log(.info, try message(run, "开始解析 {s}", .{path}));
    if (file.size() == 0) {
        return .{ .code = "HIVE_EMPTY", .message = try message(run, "{s} 是空文件，已跳过", .{path}) };
    }
    if (file.size() > MAX_HIVE_SIZE) {
        return .{ .code = "HIVE_TOO_LARGE", .message = try message(
            run,
            "{s} 为 {d} 字节，超过上限 {d}，已跳过",
            .{ path, file.size(), MAX_HIVE_SIZE },
        ) };
    }

    const buffer = readWhole(file, std.heap.c_allocator, MAX_HIVE_SIZE) catch |err| {
        return .{ .code = "HIVE_READ_FAILED", .message = try message(run, "读取 {s} 失败：{s}", .{ path, @errorName(err) }) };
    };
    defer std.heap.c_allocator.free(buffer);

    // A per-hive arena owns every parsed value.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var hive = hive_mod.Hive.open(arena, buffer) catch |err| {
        return .{ .code = "HIVE_PARSE_FAILED", .message = try message(run, "解析 {s} 失败：{s}", .{ path, @errorName(err) }) };
    };

    const connections = try navicat.collect(run_arena, &hive);
    for (connections) |connection| {
        try emitConnection(run, file, connection);
        connections_total.* += 1;
    }
    run.log(.info, try message(run, "解析 {s} 完成，{d} 个 Navicat 连接", .{ path, connections.len }));
    return null;
}

/// Emits one connection into the record type of its family: the shared
/// fields on every type, the family's extras on SQL Server and SQLite.
fn emitConnection(run: *const lc.Run, file: lc.FileRef, connection: navicat.Connection) lc.Error!void {
    const base = [_]lc.wire.Value{
        lc.wire.str(connection.name),
        lc.wire.str(connection.host),
        if (connection.port) |port| lc.wire.uint(port) else .nil,
        lc.wire.str(connection.username),
        lc.wire.str(connection.password),
        lc.wire.str(connection.cache_path),
    };
    switch (connection.conn_type) {
        .mssql => try run.record(records.MSSQL_TYPE, &(base ++ [_]lc.wire.Value{
            lc.wire.str(connection.database),
            lc.wire.str(connection.auth_mode),
        })).from(&file).emit(),
        .sqlite => try run.record(records.SQLITE_TYPE, &(base ++ [_]lc.wire.Value{
            lc.wire.str(connection.database),
            if (connection.encrypted) |flag| lc.wire.Value{ .boolean = flag } else .nil,
            if (connection.saved_password) |flag| lc.wire.Value{ .boolean = flag } else .nil,
        })).from(&file).emit(),
        else => try run.record(switch (connection.conn_type) {
            .mysql => records.MYSQL_TYPE,
            .mariadb => records.MARIADB_TYPE,
            .mongodb => records.MONGODB_TYPE,
            .oracle => records.ORACLE_TYPE,
            .postgresql => records.POSTGRESQL_TYPE,
            else => unreachable,
        }, &base).from(&file).emit(),
    }
}
