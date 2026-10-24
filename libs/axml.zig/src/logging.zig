//! Parser diagnostics with a pluggable sink.
//!
//! The library itself has no host and no logger, so call sites format one
//! line and hand it to whatever sink the embedding application bound to this
//! thread (`bind`). With no sink bound (unit tests, standalone tools) the
//! lines are dropped instead of failing a parse. The LovelyCarve APK plugin
//! binds this sink to its SDK log, so parser output and run output end up in
//! the same place.

const std = @import("std");

/// Longest formatted line kept; longer ones are truncated.
pub const MAX_MESSAGE_BYTES: usize = 1024;

/// Severity of one line, in increasing order.
pub const Level = enum(u8) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,
};

/// The embedding application's receiver for one formatted line.
pub const Handler = *const fn (level: Level, message: []const u8) void;

threadlocal var handler: ?Handler = null;

/// Binds this thread's sink.
pub fn bind(target: Handler) void {
    handler = target;
}

/// Drops this thread's binding.
pub fn unbind() void {
    handler = null;
}

/// Whether this thread has a sink to write to.
pub fn enabled() bool {
    return handler != null;
}

/// One line at `level` in `scope`.
pub fn log(
    comptime level: Level,
    comptime scope: @EnumLiteral(),
    source: ?std.builtin.SourceLocation,
    comptime format: []const u8,
    args: anytype,
) void {
    _ = source;
    const target = handler orelse return;

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
    target(level, line);
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

/// A logger bound to one scope: `const log = logging.scoped(.axml_document);`.
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

var captured: [4][MAX_MESSAGE_BYTES + 64]u8 = undefined;
var captured_len: usize = 0;
var last_level: ?Level = null;

fn capture(level: Level, message: []const u8) void {
    if (captured_len >= captured.len) return;
    const n = @min(message.len, captured[captured_len].len);
    @memcpy(captured[captured_len][0..n], message[0..n]);
    captured_len += 1;
    last_level = level;
}

test "a bound handler receives the line, an unbound thread drops it" {
    // Unbound: nothing is captured.
    info(.axml_test, @src(), "dropped {d}", .{1});
    try testing.expectEqual(@as(usize, 0), captured_len);

    bind(capture);
    defer {
        unbind();
        captured_len = 0;
        last_level = null;
    }

    info(.axml_strings, @src(), "entries={d}", .{3});
    warn(.axml_document, @src(), "truncated", .{});
    try testing.expectEqual(@as(usize, 2), captured_len);
    try testing.expectEqualStrings("axml_strings: entries=3", captured[0][0..23]);
    try testing.expectEqualStrings("axml_document: truncated", captured[1][0..24]);
    try testing.expectEqual(Level.warn, last_level.?);
}
