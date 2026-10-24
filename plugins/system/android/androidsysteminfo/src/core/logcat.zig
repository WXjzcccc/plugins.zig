//! The `bootlog.txt` MIUI boot log: a full logcat capture of one boot
//! (`-v threadtime`), 13 MiB / ~95,000 lines on the reference device.
//!
//! ```text
//! Fri Jul 17 13:16:22 CST 2026            <- logcat start banner (year!)
//! --------- beginning of main             <- buffer switch
//! 07-17 13:16:20.531  1034  1034 I auditd  : type=1400 audit(0.0:485): ...
//! ```
//!
//! Logcat timestamps carry no year; the year and the UTC offset come from
//! the banner. The device clock is often not synced during early boot, so a
//! line's month/day before the banner's date still maps to the banner year —
//! the honest answer for those rows is "device clock unset", not a year
//! guess of our own. Lines that are not headers (stack-trace continuations)
//! are appended to the previous record's message by the caller.

const std = @import("std");

/// One parsed logcat header line (continuations are handled by the caller).
pub const Entry = struct {
    /// The 1-based line number in the file.
    number: usize,
    /// Logcat buffer as announced by `--------- beginning of <name>`; empty
    /// when no marker has been seen yet.
    buffer: []const u8,
    /// `V D I W E F`, or `?` for lines that parse as neither header nor
    /// continuation.
    level: u8,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    millis: u32,
    pid: i64,
    tid: i64,
    tag: []const u8,
    message: []const u8,
};

/// The logcat banner: `Fri Jul 17 13:16:22 CST 2026`.
pub const Banner = struct {
    year: i32,
    month: u32,
    day: u32,
    /// UTC offset in minutes east; null when the zone is unknown.
    offset_minutes: ?i32,
};

const month_names = [_][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/// Offsets of the zone abbreviations seen on Android devices. Only what the
/// reference evidence uses is mapped; anything else falls back to a local
/// (zone-unknown) timestamp.
const zone_offsets = [_]struct { name: []const u8, minutes: i32 }{
    .{ .name = "CST", .minutes = 8 * 60 }, // 中国标准时间 on Xiaomi CN devices
    .{ .name = "UTC", .minutes = 0 },
    .{ .name = "GMT", .minutes = 0 },
};

/// Parses the banner line; null when the line is not a banner.
pub fn parseBanner(line: []const u8) ?Banner {
    var parts = std.mem.tokenizeAny(u8, line, " \t\r");
    _ = parts.next() orelse return null; // weekday
    const month_name = parts.next() orelse return null;
    const day_text = parts.next() orelse return null;
    const time_text = parts.next() orelse return null;
    const zone = parts.next() orelse return null;
    const year_text = parts.next() orelse return null;

    var month: u32 = 0;
    for (month_names, 1..) |candidate, index| {
        if (std.mem.eql(u8, candidate, month_name)) month = @intCast(index);
    }
    if (month == 0) return null;
    const day = std.fmt.parseInt(u32, day_text, 10) catch return null;
    const year = std.fmt.parseInt(i32, year_text, 10) catch return null;
    if (day < 1 or day > 31) return null;

    var offset: ?i32 = null;
    for (zone_offsets) |known| {
        if (std.mem.eql(u8, known.name, zone)) offset = known.minutes;
    }
    _ = time_text;
    return .{ .year = year, .month = month, .day = day, .offset_minutes = offset };
}

/// `--------- beginning of main` — announces the current buffer.
pub fn parseBufferMarker(line: []const u8) ?[]const u8 {
    if (std.mem.indexOf(u8, line, "beginning of ") == null) return null;
    const marker = "--------- beginning of ";
    const index = std.mem.indexOf(u8, line, marker) orelse return null;
    var name = std.mem.trim(u8, line[index + marker.len ..], " \t\r");
    if (name.len == 0) return null;
    // A trailing "(+offset)" appears on some devices: `beginning of crash`.
    if (std.mem.indexOfScalar(u8, name, '(')) |paren| name = std.mem.trimEnd(u8, name[0..paren], " ");
    return name;
}

/// Parses one logcat line; null when the line is not a header (the caller
/// treats it as a continuation of the previous entry).
pub fn parseLine(number: usize, buffer: []const u8, raw_line: []const u8) ?Entry {
    var parts = std.mem.tokenizeAny(u8, raw_line, " \t");
    const date = parts.next() orelse return null;
    const time = parts.next() orelse return null;
    const pid_text = parts.next() orelse return null;
    const tid_text = parts.next() orelse return null;
    const level_text = parts.next() orelse return null;
    if (level_text.len != 1) return null;
    const level = level_text[0];
    switch (level) {
        'V', 'D', 'I', 'W', 'E', 'F' => {},
        else => return null,
    }

    // MM-DD
    if (date.len < 5 or date[2] != '-') return null;
    const month = std.fmt.parseInt(u32, date[0..2], 10) catch return null;
    const day = std.fmt.parseInt(u32, date[3..5], 10) catch return null;
    // HH:MM:SS.mmm
    if (time.len < 8 or time[2] != ':' or time[5] != ':') return null;
    const hour = std.fmt.parseInt(u32, time[0..2], 10) catch return null;
    const minute = std.fmt.parseInt(u32, time[3..5], 10) catch return null;
    const second = std.fmt.parseInt(u32, time[6..8], 10) catch return null;
    var millis: u32 = 0;
    if (time.len >= 12 and time[8] == '.') {
        millis = std.fmt.parseInt(u32, time[9..@min(time.len, 12)], 10) catch 0;
    } else if (time.len > 9 and time[8] == '.') {
        millis = std.fmt.parseInt(u32, time[9..time.len], 10) catch 0;
    }

    const pid = std.fmt.parseInt(i64, pid_text, 10) catch return null;
    const tid = std.fmt.parseInt(i64, tid_text, 10) catch return null;

    // The rest: `tag  : message` — the tag ends at the first ':'.
    const rest = raw_line[parts.index..];
    const tag_end = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    const tag = std.mem.trim(u8, rest[0..tag_end], " \t");
    const message = std.mem.trimStart(u8, rest[tag_end + 1 ..], " \t");

    return .{
        .number = number,
        .buffer = buffer,
        .level = level,
        .month = month,
        .day = day,
        .hour = hour,
        .minute = minute,
        .second = second,
        .millis = millis,
        .pid = pid,
        .tid = tid,
        .tag = tag,
        .message = message,
    };
}

/// Formats the entry's wall-clock time as RFC 3339 with the banner's year
/// and offset (`2026-07-17T13:16:20.531+08:00`); null when the banner had no
/// known zone and the caller wants a zone-less time (it formats that itself
/// through `Timestamp.localNanos`).
pub fn formatTimestamp(
    banner: Banner,
    entry: Entry,
    buffer: *[32]u8,
) ?[]const u8 {
    const offset = banner.offset_minutes orelse return null;
    const sign: u8 = if (offset < 0) '-' else '+';
    const magnitude: u32 = @intCast(if (offset < 0) -offset else offset);
    const rendered = std.fmt.bufPrint(
        buffer,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}{c}{d:0>2}:{d:0>2}",
        .{
            @as(u32, @intCast(banner.year)),
            entry.month,
            entry.day,
            entry.hour,
            entry.minute,
            entry.second,
            entry.millis,
            sign,
            magnitude / 60,
            magnitude % 60,
        },
    ) catch return null;
    return rendered;
}

const testing = std.testing;

const banner_line = "Fri Jul 17 13:16:22 CST 2026";

test "parses the banner, buffer markers and log lines" {
    const banner = parseBanner(banner_line).?;
    try testing.expectEqual(@as(i32, 2026), banner.year);
    try testing.expectEqual(@as(u32, 7), banner.month);
    try testing.expectEqual(@as(u32, 17), banner.day);
    try testing.expectEqual(@as(?i32, 480), banner.offset_minutes);

    try testing.expectEqualStrings("main", parseBufferMarker("--------- beginning of main").?);
    try testing.expect(parseBufferMarker("07-17 13:16:20.531  1034  1034 I auditd  : x") == null);

    const entry = parseLine(5, "main", "07-17 13:16:20.531  1034  1034 I auditd  : type=1400 audit(0.0:485): avc: denied").?;
    try testing.expectEqual(@as(usize, 5), entry.number);
    try testing.expectEqual(@as(u8, 'I'), entry.level);
    try testing.expectEqual(@as(u32, 7), entry.month);
    try testing.expectEqual(@as(u32, 17), entry.day);
    try testing.expectEqual(@as(u32, 13), entry.hour);
    try testing.expectEqual(@as(u32, 16), entry.minute);
    try testing.expectEqual(@as(u32, 20), entry.second);
    try testing.expectEqual(@as(u32, 531), entry.millis);
    try testing.expectEqual(@as(i64, 1034), entry.pid);
    try testing.expectEqualStrings("auditd", entry.tag);
    try testing.expectEqualStrings("type=1400 audit(0.0:485): avc: denied", entry.message);

    var buffer: [32]u8 = undefined;
    try testing.expectEqualStrings("2026-07-17T13:16:20.531+08:00", formatTimestamp(banner, entry, &buffer).?);
}

test "a continuation line is not a header" {
    try testing.expect(parseLine(9, "main", "        at android.util.Log.wtf(Log.java:315)") == null);
    const unknown_zone = parseBanner("Fri Jul 17 13:16:22 XXX 2026").?;
    try testing.expect(unknown_zone.offset_minutes == null);
}
