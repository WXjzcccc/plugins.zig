//! Path patterns of declared inputs and `view.find`.
//!
//! Paths are `/`-separated and relative to a view. `**` matches any number of
//! directories (including none), `*` any run of characters inside one name and
//! `?` one character; letters match ASCII case-insensitively, as on the Windows
//! file systems the evidence often comes from.
//!
//! Matching happens in the host, so this module only validates patterns before
//! they are sent (`view.find` rejects a malformed pattern with
//! `INVALID_PARAMS`). The rules mirror `plugins/sdk/src/glob.rs`.

const std = @import("std");

/// Longest accepted pattern.
pub const MAX_PATTERN_BYTES: usize = 512;

/// Most path segments a pattern may have.
pub const MAX_SEGMENTS: usize = 64;

/// Checks a path pattern. Returns `null` when `pattern` is valid, else a
/// message describing the first problem; nothing is allocated, so the message
/// is static.
pub fn validate(pattern: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, pattern, " \t\r\n\x0b\x0c");
    const relative = std.mem.trimStart(u8, trimmed, "/");
    if (relative.len == 0 or relative.len > MAX_PATTERN_BYTES) {
        return "pattern must be 1..=512 bytes";
    }

    var segments: usize = 0;
    var previous_was_any: bool = false;
    var iterator = std.mem.splitScalar(u8, relative, '/');
    while (iterator.next()) |segment| {
        if (segment.len == 0 or
            std.mem.eql(u8, segment, ".") or
            std.mem.eql(u8, segment, "..") or
            std.mem.indexOfScalar(u8, segment, '\\') != null or
            std.mem.indexOfScalar(u8, segment, 0) != null)
        {
            return "pattern must not contain empty, '.', '..' or backslash segments";
        }
        if (std.mem.eql(u8, segment, "**")) {
            // Repeated `**` segments collapse into one.
            if (!previous_was_any) segments += 1;
            previous_was_any = true;
            continue;
        }
        if (std.mem.indexOf(u8, segment, "**") != null) {
            return "** must be a whole path segment";
        }
        previous_was_any = false;
        segments += 1;
    }

    if (segments > MAX_SEGMENTS) return "pattern has more than 64 segments";
    if (previous_was_any) return "pattern must end with a file name pattern";
    return null;
}

/// Checks a name pattern for "anywhere in the view" (`**/<name>`): it may not
/// contain a `/`, and follows the same rules as [`validate`].
pub fn anywhereValidate(name: []const u8) ?[]const u8 {
    if (std.mem.indexOfScalar(u8, name, '/') != null) {
        return "name pattern must not contain '/'";
    }
    var buffer: [MAX_PATTERN_BYTES]u8 = undefined;
    const prefixed = std.fmt.bufPrint(&buffer, "**/{s}", .{name}) catch
        return "pattern must be 1..=512 bytes";
    return validate(prefixed);
}

const testing = std.testing;

test "valid patterns are accepted" {
    const valid = [_][]const u8{
        "etc/passwd",
        "/etc/passwd",
        "var/log/wtmp*",
        "home/*/.bash_history",
        "**/os-release",
        "a/**/b",
        "a/**/**/b",
        "**/etc/**/passwd",
        "a?c",
        "etc/os-release",
        "  etc/passwd  ",
    };
    for (valid) |pattern| {
        testing.expectEqual(@as(?[]const u8, null), validate(pattern)) catch |err| {
            std.debug.print("rejected {s}\n", .{pattern});
            return err;
        };
    }
}

test "unsafe patterns are rejected" {
    const invalid = [_][]const u8{
        "",
        "/",
        "   ",
        "../etc",
        "etc/../passwd",
        "a//b",
        "a\\b",
        "a/\x00/b",
        "**",
        "a/**b",
        "a/**",
        "**/**",
    };
    for (invalid) |pattern| {
        testing.expect(validate(pattern) != null) catch |err| {
            std.debug.print("accepted {s}\n", .{pattern});
            return err;
        };
    }
}

test "over-long patterns are rejected" {
    var buffer: [MAX_PATTERN_BYTES + 2]u8 = undefined;
    @memset(buffer[0..], 'a');
    try testing.expectEqual(null, validate(buffer[0..MAX_PATTERN_BYTES]));
    try testing.expect(validate(buffer[0 .. MAX_PATTERN_BYTES + 1]) != null);
}

test "too many segments are rejected" {
    var buffer: [2 * MAX_SEGMENTS + 2]u8 = undefined;
    var index: usize = 0;
    var segment: usize = 0;
    while (segment < MAX_SEGMENTS) : (segment += 1) {
        if (segment != 0) {
            buffer[index] = '/';
            index += 1;
        }
        buffer[index] = 'a';
        index += 1;
    }
    try testing.expectEqual(null, validate(buffer[0..index]));

    buffer[index] = '/';
    buffer[index + 1] = 'a';
    try testing.expect(validate(buffer[0 .. index + 2]) != null);
}

test "name patterns must not contain a separator" {
    try testing.expectEqual(null, anywhereValidate("*.log"));
    try testing.expectEqual(null, anywhereValidate("os-release"));
    try testing.expect(anywhereValidate("etc/passwd") != null);
    try testing.expect(anywhereValidate("") != null);
}
