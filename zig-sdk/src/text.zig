//! Text helpers for parsers and analyzers of evidence files.

const std = @import("std");

const sdk = @import("error.zig");

const replacement = "\u{FFFD}";

/// Splits at every line boundary Python's `str.splitlines()` recognises
/// (`\n`, `\r`, `\r\n`, `\v`, `\f`, `\x1c`-`\x1e`, `\x85`, U+2028, U+2029),
/// without a trailing empty line.
///
/// The returned slices point *into* `text`; only the list itself is owned by
/// `alloc`, so `text` has to outlive the result.
pub fn splitLines(alloc: std.mem.Allocator, text: []const u8) sdk.Error![][]const u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    errdefer lines.deinit(alloc);

    var start: usize = 0;
    var index: usize = 0;
    while (index < text.len) {
        const width = separatorWidth(text[index..]) orelse {
            index += 1;
            continue;
        };
        try lines.append(alloc, text[start..index]);
        index += width;
        start = index;
    }
    if (start < text.len) try lines.append(alloc, text[start..]);
    return lines.toOwnedSlice(alloc);
}

/// The byte length of the line separator at the start of `rest`, or `null`.
fn separatorWidth(rest: []const u8) ?usize {
    return switch (rest[0]) {
        '\n', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e' => 1,
        '\r' => if (rest.len > 1 and rest[1] == '\n') 2 else 1,
        0x85 => 1,
        0xe2 => if (std.mem.startsWith(u8, rest, "\u{2028}") or
            std.mem.startsWith(u8, rest, "\u{2029}")) 3 else null,
        else => null,
    };
}

/// UTF-8 with U+FFFD for invalid sequences, matching Rust's
/// `String::from_utf8_lossy`: a byte that cannot start a sequence costs one
/// replacement character, and a truncated or interrupted sequence costs one
/// replacement character for its whole maximal subpart.
pub fn decodeLossy(alloc: std.mem.Allocator, bytes: []const u8) sdk.Error![]u8 {
    if (std.unicode.utf8ValidateSlice(bytes)) return alloc.dupe(u8, bytes);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    var index: usize = 0;
    while (index < bytes.len) {
        const width = std.unicode.utf8ByteSequenceLength(bytes[index]) catch {
            // Not a lead byte at all: one replacement per byte, as Rust does.
            try out.appendSlice(alloc, replacement);
            index += 1;
            continue;
        };
        // How much of the announced sequence is really there: the lead byte
        // plus the continuation bytes that follow it.
        var present: usize = 1;
        while (present < width and index + present < bytes.len and
            bytes[index + present] & 0xc0 == 0x80) : (present += 1)
        {}
        if (present == width) {
            // Structurally complete: valid, or a sequence Rust rejects as a
            // whole (surrogate, overlong, out of range).
            if (std.unicode.utf8Decode(bytes[index..][0..width])) |_| {
                try out.appendSlice(alloc, bytes[index..][0..width]);
            } else |_| {
                try out.appendSlice(alloc, replacement);
            }
            index += width;
            continue;
        }
        try out.appendSlice(alloc, replacement);
        index += present;
    }
    return out.toOwnedSlice(alloc);
}

const testing = std.testing;

/// `expectEqualSlices` compares slice elements by identity, so line lists are
/// compared element by element instead.
fn expectLines(expected: []const []const u8, actual: []const []const u8) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual, 0..) |want, got, index| {
        testing.expectEqualStrings(want, got) catch |err| {
            std.debug.print("line {d} differs\n", .{index});
            return err;
        };
    }
}

test "matches python splitlines" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try expectLines(&.{}, try splitLines(alloc, ""));
    try expectLines(&.{""}, try splitLines(alloc, "\n"));
    try expectLines(&.{ "a", "b", "c", "", "d" }, try splitLines(alloc, "a\r\nb\rc\n\nd"));
    try expectLines(&.{ "a", "b", "c" }, try splitLines(alloc, "a\u{2028}b\x0cc\n"));
    try expectLines(&.{"a"}, try splitLines(alloc, "a"));
}

test "decode lossy replaces only invalid sequences" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try testing.expectEqualStrings("文件", try decodeLossy(alloc, "文件"));
    try testing.expectEqualStrings("\u{FFFD}a", try decodeLossy(alloc, "\x80a"));
    try testing.expectEqualStrings("a\u{FFFD}", try decodeLossy(alloc, "a\xe4\xbd"));
}
