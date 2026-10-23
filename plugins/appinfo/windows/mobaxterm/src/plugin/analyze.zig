//! From run inputs to records: parse each NTUSER-class hive and emit its
//! MobaXterm saved passwords and credentials.
//!
//! Memory: hives are loaded one at a time through libc's allocator and a
//! per-hive arena holds every parsed value.

const std = @import("std");

const lc = @import("lovelycarve");
const hive_mod = @import("../core/hive.zig");
const mobaxterm = @import("../core/mobaxterm.zig");
const records = @import("records.zig");

/// Largest hive read per run; plugin.toml caps the process at 2 GiB.
pub const MAX_HIVE_SIZE: u64 = 1024 * 1024 * 1024;

/// The run settings read from the analyzer options.
pub const Settings = struct {
    /// The MobaXterm master password; "" when none is set (the default key).
    master_password: []const u8 = "",

    pub fn fromOptions(options: lc.Options) Settings {
        var settings = Settings{};
        if (options.text("master_password")) |password| {
            settings.master_password = password;
        }
        return settings;
    }
};

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

/// One registry analysis run over the hive inputs (either analyzer scope).
pub fn analyzeRun(run: *const lc.Run, inputs: []const lc.FileRef, settings: Settings) lc.Error!void {
    const run_arena = run.context().arena;

    if (inputs.len == 0) {
        run.setSummary("没有发现 NTUSER.DAT 配置单元");
        run.log(.info, "the run resolved no NTUSER.DAT inputs");
        return;
    }

    var analyzed: u64 = 0;
    var failed: u64 = 0;
    var found: u64 = 0;
    try run.progress(0, inputs.len, null);
    for (inputs, 0..) |file, index| {
        try run.checkCancelled();
        try run.progress(index, inputs.len, displayPath(file));
        if (try analyzeFile(run, file, settings, &found)) |failure| {
            failed += 1;
            try run.warnFile(file, failure.code, failure.message);
            run.log(.err, failure.message);
        } else {
            analyzed += 1;
        }
    }
    try run.progress(inputs.len, inputs.len, null);

    const summary = try std.fmt.allocPrint(
        run_arena,
        "分析 {d} 个 NTUSER.DAT，发现 {d} 个 MobaXterm 密码或凭据（失败 {d} 个）",
        .{ analyzed, found, failed },
    );
    run.setSummary(summary);
    run.log(.info, summary);
}

/// Formats a warning message in the run's arena.
fn message(run: *const lc.Run, comptime format: []const u8, args: anytype) lc.Error![]const u8 {
    return std.fmt.allocPrint(run.context().arena, format, args);
}

/// Why one hive could not be analyzed.
pub const Failure = struct {
    code: []const u8,
    message: []const u8,
};

/// Analyzes one hive; null on success, else the failure for the run warning.
/// Every stage logs: the input path up front, the detailed reason on failure,
/// the per-hive result at the end.
fn analyzeFile(
    run: *const lc.Run,
    file: lc.FileRef,
    settings: Settings,
    found: *u64,
) lc.Error!?Failure {
    const run_arena = run.context().arena;
    const path = displayPath(file);
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

    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var hive = hive_mod.Hive.open(arena, buffer) catch |err| {
        return .{ .code = "HIVE_PARSE_FAILED", .message = try message(run, "解析 {s} 失败：{s}", .{ path, @errorName(err) }) };
    };

    const report = try mobaxterm.collect(run_arena, &hive, settings.master_password);
    for (report.passwords) |password| {
        try run.record(records.PASSWORD_TYPE, &.{
            lc.wire.str(path),
            lc.wire.str(password.account_host),
            lc.wire.str(password.protocol),
            lc.wire.str(password.password),
        }).from(&file).emit();
        found.* += 1;
    }
    for (report.credentials) |credential| {
        try run.record(records.CREDENTIAL_TYPE, &.{
            lc.wire.str(path),
            lc.wire.str(credential.name),
            lc.wire.str(credential.username),
            lc.wire.str(credential.password),
        }).from(&file).emit();
        found.* += 1;
    }
    run.log(.info, try message(run, "解析 {s} 完成，{d} 个密码、{d} 个凭据", .{ path, report.passwords.len, report.credentials.len }));
    return null;
}

const testing = std.testing;

test "settings read the master password option" {
    const none = Settings.fromOptions(lc.Options.init(.nil));
    try testing.expectEqual(@as(usize, 0), none.master_password.len);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const values = try lc.value.map(arena_state.allocator(), &.{
        lc.value.entry("master_password", lc.value.str("s3cret")),
    });
    const settings = Settings.fromOptions(lc.Options.init(values));
    try testing.expectEqualStrings("s3cret", settings.master_password);
}
