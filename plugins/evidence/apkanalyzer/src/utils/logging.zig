//! Parser diagnostics, forwarded to the LovelyCarve SDK log.
//!
//! This module is an adapter, not a logging system of its own: it formats one
//! line into a fixed buffer and hands it to [lc.Context.log], which is the
//! SDK's plugin log (Run.log writes through it too, so plugin output and
//! parser output end up in the same place).
//!
//! The context is thread-local: one plugin process serves several runs at
//! once, each on its own worker thread, and a run's parser lines must reach
//! that run's log. With no context bound (unit tests, for example) the lines
//! are dropped instead of failing an analysis.

const std = @import("std");
const lc = @import("lovelycarve");

/// Longest formatted line kept; longer ones are truncated.
pub const MAX_MESSAGE_BYTES: usize = 1024;

threadlocal var context: ?lc.Context = null;

/// Binds the log of this thread to `ctx` (the run's context).
pub fn bind(ctx: lc.Context) void {
    context = ctx;
}

/// Drops the binding of this thread.
pub fn unbind() void {
    context = null;
}

/// Whether this thread has a log to write to.
pub fn enabled() bool {
    return context != null;
}

/// One line at `level` in `scope`.
pub fn log(
    comptime level: lc.LogLevel,
    comptime scope: @EnumLiteral(),
    source: ?std.builtin.SourceLocation,
    comptime format: []const u8,
    args: anytype,
) void {
    const ctx = context orelse return;
    _ = source;

    var body_buffer: [MAX_MESSAGE_BYTES]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buffer, format, args) catch blk: {
        // The buffer ran out: keep what fits rather than dropping the line.
        const cut: usize = @min(body_buffer.len - 3, MAX_MESSAGE_BYTES - 3);
        body_buffer[cut] = '.';
        body_buffer[cut + 1] = '.';
        body_buffer[cut + 2] = '.';
        break :blk body_buffer[0 .. cut + 3];
    };

    var line_buffer: [MAX_MESSAGE_BYTES + 64]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buffer, "{s}: {s}", .{ @tagName(scope), body }) catch body;
    ctx.log(level, line);
}

pub fn debug(
    comptime scope: @EnumLiteral(),
    source: std.builtin.SourceLocation,
    comptime format: []const u8,
    args: anytype,
) void {
    log(.debug, scope, source, format, args);
}

pub fn info(
    comptime scope: @EnumLiteral(),
    source: std.builtin.SourceLocation,
    comptime format: []const u8,
    args: anytype,
) void {
    log(.info, scope, source, format, args);
}

pub fn warn(
    comptime scope: @EnumLiteral(),
    source: std.builtin.SourceLocation,
    comptime format: []const u8,
    args: anytype,
) void {
    log(.warn, scope, source, format, args);
}

pub fn err(
    comptime scope: @EnumLiteral(),
    source: std.builtin.SourceLocation,
    comptime format: []const u8,
    args: anytype,
) void {
    log(.err, scope, source, format, args);
}

/// A logger bound to one scope: `const log = logging.scoped(.apk_archive);`.
pub fn scoped(comptime scope: @EnumLiteral()) type {
    return struct {
        pub fn debug(
            source: std.builtin.SourceLocation,
            comptime format: []const u8,
            args: anytype,
        ) void {
            log(.debug, scope, source, format, args);
        }

        pub fn info(
            source: std.builtin.SourceLocation,
            comptime format: []const u8,
            args: anytype,
        ) void {
            log(.info, scope, source, format, args);
        }

        pub fn warn(
            source: std.builtin.SourceLocation,
            comptime format: []const u8,
            args: anytype,
        ) void {
            log(.warn, scope, source, format, args);
        }

        pub fn err(
            source: std.builtin.SourceLocation,
            comptime format: []const u8,
            args: anytype,
        ) void {
            log(.err, scope, source, format, args);
        }
    };
}

const testing = std.testing;

var cancelled = std.atomic.Value(bool).init(false);

fn missing(
    _: ?*anyopaque,
    _: std.mem.Allocator,
    method: []const u8,
    _: lc.wire.Value,
) lc.testing.Reply {
    return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
}

test "a bound context receives the line, an unbound thread drops it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var stub = lc.testing.Stub.init(testing.allocator, null, missing);
    defer stub.deinit();
    const api = stub.api();

    // Unbound: nothing is written.
    info(.apk_test, @src(), "dropped {d}", .{1});
    try testing.expectEqual(@as(usize, 0), stub.logs.items.len);

    bind(.{
        .host = lc.HostConnection.init(api),
        .cancelled = &cancelled,
        .arena = arena_state.allocator(),
        .alloc = testing.allocator,
    });
    defer unbind();

    info(.apk_archive, @src(), "entries={d}", .{3});
    warn(.apk_signing, @src(), "no signer", .{});
    try testing.expectEqual(@as(usize, 2), stub.logs.items.len);
    try testing.expectEqual(lc.abi.LOG_INFO, stub.logs.items[0].level);
    try testing.expectEqualStrings("apk_archive: entries=3", stub.logs.items[0].message);
    try testing.expectEqual(lc.abi.LOG_WARN, stub.logs.items[1].level);
    try testing.expectEqualStrings("apk_signing: no signer", stub.logs.items[1].message);
}
