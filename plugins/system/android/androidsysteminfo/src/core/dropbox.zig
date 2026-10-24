//! Headers of DropBoxManager entries (`/data/system/dropbox/`) and ANR
//! traces (`/data/anr/`). Both are text files that start with a small
//! `Key: value` header block, then a blank line and the body:
//!
//! ```text
//! Process: system_server
//! Subject: SystemServiceRegistry
//! Build: ...
//! Dropped-Count: 0
//!
//! android.util.Log$TerribleFailure: ...
//! ```
//!
//! ANR traces carry the same shape (with a full-width colon on MIUI) plus a
//! `----- pid N at 1975-02-26 02:43:51...+0800 -----` dump header inside the
//! body; the trace time and ABI live there.

const std = @import("std");

/// One parsed entry header. `time_text` keeps the raw ANR dump time (the
/// caller turns it into a timestamp); dropbox entries have no in-file time.
pub const EntryHeader = struct {
    process: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    /// `Dropped-Count` of dropbox entries.
    dropped_count: ?i64 = null,
    /// The `----- pid N at TIME -----` line's time, verbatim.
    time_text: ?[]const u8 = null,
    /// `ABI: 'arm64'` from the ANR dump header.
    abi: ?[]const u8 = null,
};

/// Parses the leading header block of one entry. Header keys end at the
/// first ASCII or full-width colon; parsing stops at the first blank line.
pub fn parseEntryHeader(alloc: std.mem.Allocator, text: []const u8) error{OutOfMemory}!EntryHeader {
    var header = EntryHeader{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) break;
        const colon = std.mem.indexOfAny(u8, line, "：:") orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t\r");
        if (std.mem.eql(u8, key, "Process") or std.mem.eql(u8, key, "ProcessName")) {
            if (header.process == null) header.process = try alloc.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "Subject")) {
            if (header.subject == null) header.subject = try alloc.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "Dropped-Count")) {
            if (header.dropped_count == null) {
                header.dropped_count = std.fmt.parseInt(i64, value, 10) catch null;
            }
        }
    }
    // The ANR dump header sits inside the body: scan for the pid line.
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, text, index, "----- pid ")) |found| {
        const line_end = std.mem.indexOfScalarPos(u8, text, found, '\n') orelse text.len;
        const line = text[found..line_end];
        // `----- pid 2178 at 1975-02-26 02:43:51.375379785+0800 -----`
        if (std.mem.indexOf(u8, line, " at ")) |at| {
            const time_value = std.mem.trim(u8, line[at + 4 ..], " -\r");
            if (time_value.len > 0) header.time_text = try alloc.dupe(u8, time_value);
            break;
        }
        index = line_end;
    }
    if (header.time_text == null) {
        // Fallback for `TimeStamp : ...` header keys (MIUI style).
        var fallback = std.mem.splitScalar(u8, text, '\n');
        while (fallback.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0) break;
            const colon = std.mem.indexOfAny(u8, line, "：:") orelse continue;
            const key = std.mem.trim(u8, line[0..colon], " \t");
            if (std.mem.eql(u8, key, "TimeStamp") or std.mem.eql(u8, key, "Timestamp")) {
                header.time_text = try alloc.dupe(u8, std.mem.trim(u8, line[colon + 1 ..], " \t\r"));
                break;
            }
        }
    }
    if (std.mem.indexOf(u8, text, "ABI: '")) |abi| {
        const start = abi + 6;
        const end = std.mem.indexOfScalarPos(u8, text, start, '\'') orelse text.len;
        if (end > start) header.abi = try alloc.dupe(u8, text[start..end]);
    }
    return header;
}

/// Splits `1975-02-26 02:43:51.375379785+0800` (or `1975-02-26-02-43-51` from
/// file names) into its parts; used for ANR times.
pub const TimeParts = struct {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    /// Offset minutes east, when the text carries one (`+0800`).
    offset_minutes: ?i32,
};

pub fn parseTimeParts(text: []const u8) ?TimeParts {
    const separators = [_][]const u8{ "-", "-", " ", ":", ":", "." };
    var fields: [6]i64 = undefined;
    var count: usize = 0;
    var rest: []const u8 = text;

    // Year first, then value/separator pairs.
    var token_end = nextSeparatorEnd(rest, 0) orelse return null;
    fields[0] = std.fmt.parseInt(i64, rest[0..token_end], 10) catch return null;
    rest = rest[token_end..];
    count = 1;
    for (separators) |_| {
        if (rest.len == 0) break;
        // Skip one separator character, then read the next value token.
        rest = rest[1..];
        token_end = nextSeparatorEnd(rest, 0) orelse break;
        fields[count] = std.fmt.parseInt(i64, rest[0..token_end], 10) catch break;
        count += 1;
        rest = rest[token_end..];
        if (count == 6) break;
    }
    if (count < 6) return null;

    var offset: ?i32 = null;
    if (std.mem.indexOfScalar(u8, text, '+')) |plus| {
        offset = parseOffset(text[plus + 1 ..]);
    }
    return .{
        .year = @intCast(fields[0]),
        .month = @intCast(fields[1]),
        .day = @intCast(fields[2]),
        .hour = @intCast(fields[3]),
        .minute = @intCast(fields[4]),
        .second = @intCast(fields[5]),
        .offset_minutes = offset,
    };
}

fn parseOffset(text: []const u8) ?i32 {
    // `0800` or `08:00`
    const digits = std.mem.trimEnd(u8, text, " ");
    if (digits.len < 4) return null;
    const hours = std.fmt.parseInt(i32, digits[0..2], 10) catch return null;
    const minutes = std.fmt.parseInt(i32, digits[2..4], 10) catch return null;
    return hours * 60 + minutes;
}

fn nextSeparatorEnd(text: []const u8, from: usize) ?usize {
    var index = from;
    while (index < text.len) : (index += 1) {
        switch (text[index]) {
            '-', ' ', ':', '.' => return index,
            else => {},
        }
    }
    return text.len;
}

const testing = std.testing;

test "parses a wtf header" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const sample =
        \\Process: system_server
        \\Subject: SystemServiceRegistry
        \\Build: Xiaomi/venus
        \\Dropped-Count: 0
        \\
        \\android.util.Log$TerribleFailure: No service published
    ;
    const header = try parseEntryHeader(arena_state.allocator(), sample);
    try testing.expectEqualStrings("system_server", header.process.?);
    try testing.expectEqualStrings("SystemServiceRegistry", header.subject.?);
    try testing.expectEqual(@as(?i64, 0), header.dropped_count);
    try testing.expect(header.time_text == null);
}

test "parses an anr header with dump time" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const sample =
        \\Subject:
        \\Exception ： FW_SCOUT_HANG
        \\ProcessName : system_server
        \\Pid : 2178
        \\
        \\----- pid 2178 at 1975-02-26 02:43:51.375379785+0800 -----
        \\Cmd line: system_server
        \\ABI: 'arm64'
    ;
    const header = try parseEntryHeader(arena_state.allocator(), sample);
    try testing.expectEqualStrings("system_server", header.process.?);
    try testing.expectEqualStrings("1975-02-26 02:43:51.375379785+0800", header.time_text.?);
    try testing.expectEqualStrings("arm64", header.abi.?);

    const parts = parseTimeParts(header.time_text.?).?;
    try testing.expectEqual(@as(i32, 1975), parts.year);
    try testing.expectEqual(@as(u32, 26), parts.day);
    try testing.expectEqual(@as(?i32, 480), parts.offset_minutes);
}

test "parses anr file-name times" {
    const parts = parseTimeParts("1975-02-26-02-43-51").?;
    try testing.expectEqual(@as(i32, 1975), parts.year);
    try testing.expectEqual(@as(u32, 51), parts.second);
    try testing.expect(parts.offset_minutes == null);
}
