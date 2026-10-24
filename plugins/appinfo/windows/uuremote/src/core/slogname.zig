//! Parsers for the GameViewer `.slog` log file names.
//!
//! The log content itself is an encrypted format (files start with an
//! `SLOG` magic); this plugin does not attempt to decrypt it. The file
//! names, however, carry the evidence: the log kind, the connection role,
//! the second the file was created and the writing process id.
//!
//! Observed shapes (all under `<install>/GameViewer/log/<component>/…`):
//!
//!   connection_log_controller_20260829105508476_14480.slog   主控连接日志
//!   connection_log_controlled_20260830100846506_1556.slog    被控连接日志
//!   connection_log_controlled_20260902193237092_8752.1.slog  同会话的分段
//!   streamer_log_controlled_20260830100846506_1556.slog      同会话的串流日志
//!   log_20261016104937107_7076.slog                          组件运行日志
//!
//! The 17-digit group is `yyyyMMddHHmmssSSS`; the trailing number is the pid.

const std = @import("std");

/// What a `.slog` file logs.
pub const Kind = enum {
    /// One remote session, named `connection_log_*`.
    connection,
    /// The streamer side of one remote session, named `streamer_log_*`.
    streamer,
    /// A component run log, named `log_*`.
    run,
    /// Anything else.
    unknown,
};

/// Whose side of the connection the file logs.
pub const Role = enum {
    controller,
    controlled,
    none,
};

pub const Parsed = struct {
    kind: Kind,
    role: Role,
    /// Unix milliseconds of the timestamp in the name; null when the name
    /// carries no valid timestamp.
    start_ms: ?i64,
    pid: ?u32,
    /// Rotation index: a base name without a suffix is segment 0.
    segment: u32,
};

/// Parses a `.slog` file name (with or without directory parts). Returns
/// null when the name is not an SLog file at all.
pub fn parseName(name: []const u8) ?Parsed {
    const base = std.fs.path.basename(name);
    if (!std.ascii.endsWithIgnoreCase(base, ".slog")) return null;
    var stem = base[0 .. base.len - 5];

    // An optional `.N` rotation suffix.
    var segment: u32 = 0;
    if (std.mem.lastIndexOfScalar(u8, stem, '.')) |dot| {
        if (parseU32(stem[dot + 1 ..])) |index| {
            segment = index;
            stem = stem[0..dot];
        }
    }

    // Split from the right: pid, then timestamp, then the kind/role prefix.
    var role = Role.none;
    var kind = Kind.unknown;
    var rest = stem;
    if (startsWithPrefix(stem, "connection_log_")) {
        kind = .connection;
        rest = stem["connection_log_".len..];
    } else if (startsWithPrefix(stem, "streamer_log_")) {
        kind = .streamer;
        rest = stem["streamer_log_".len..];
    } else if (startsWithPrefix(stem, "log_")) {
        kind = .run;
        rest = stem["log_".len..];
    } else {
        return .{ .kind = .unknown, .role = .none, .start_ms = null, .pid = null, .segment = segment };
    }

    if (kind != .run) {
        if (startsWithPrefix(rest, "controller_")) {
            role = .controller;
            rest = rest["controller_".len..];
        } else if (startsWithPrefix(rest, "controlled_")) {
            role = .controlled;
            rest = rest["controlled_".len..];
        }
    }

    // What remains is `<timestamp>_<pid>` (the pid may be absent).
    var start_ms: ?i64 = null;
    var pid: ?u32 = null;
    const uscore = std.mem.lastIndexOfScalar(u8, rest, '_');
    const timestamp_part = if (uscore) |at| rest[0..at] else rest;
    if (parseStamp(timestamp_part)) |ms| start_ms = ms;
    if (uscore) |at| {
        if (parseU32(rest[at + 1 ..])) |number| pid = number;
    }
    return .{ .kind = kind, .role = role, .start_ms = start_ms, .pid = pid, .segment = segment };
}

/// Whether the first bytes of a file mark it as the encrypted SLog format.
pub fn hasSlogMagic(bytes: []const u8) bool {
    return bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "SLOG");
}

fn startsWithPrefix(text: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, text, prefix);
}

fn parseU32(text: []const u8) ?u32 {
    if (text.len == 0 or text.len > 10) return null;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return null;
    }
    return std.fmt.parseInt(u32, text, 10) catch null;
}

/// `yyyyMMddHHmmssSSS` (17 digits) to Unix milliseconds.
fn parseStamp(text: []const u8) ?i64 {
    if (text.len != 17) return null;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return null;
    }
    const year = parseInt(text[0..4]) orelse return null;
    const month = parseInt(text[4..6]) orelse return null;
    const day = parseInt(text[6..8]) orelse return null;
    const hour = parseInt(text[8..10]) orelse return null;
    const minute = parseInt(text[10..12]) orelse return null;
    const second = parseInt(text[12..14]) orelse return null;
    const millis = parseInt(text[14..17]) orelse return null;
    if (year < 2000 or year > 2100) return null;
    if (month < 1 or month > 12) return null;
    if (day < 1 or day > 31) return null;
    if (hour > 23 or minute > 59 or second > 59) return null;
    const days = daysFromCivil(year, month, day);
    const seconds = days * 86_400 +
        @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
    return seconds * 1000 + millis;
}

fn parseInt(text: []const u8) ?i64 {
    return std.fmt.parseInt(i64, text, 10) catch null;
}

/// Days since 1970-01-01 for a proleptic Gregorian civil date (Howard
/// Hinnant's `days_from_civil`).
fn daysFromCivil(year: i64, month: i64, day: i64) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const m = if (month > 2) month - 3 else month + 9;
    const doy = @divFloor(153 * m + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146_097 + doe - 719_468;
}

const testing = std.testing;

test "parses connection log names of both roles" {
    const controlled = parseName("connection_log_controlled_20260830100846506_1556.slog").?;
    try testing.expectEqual(Kind.connection, controlled.kind);
    try testing.expectEqual(Role.controlled, controlled.role);
    try testing.expectEqual(@as(u32, 1556), controlled.pid.?);
    try testing.expectEqual(@as(u32, 0), controlled.segment);
    // 2026-08-30T10:08:46.506 local time read as UTC (no offset recorded).
    const expected: i64 = daysFromCivil(2026, 8, 30) * 86_400_000 +
        10 * 3_600_000 + 8 * 60_000 + 46_000 + 506;
    try testing.expectEqual(expected, controlled.start_ms.?);

    const controller = parseName("connection_log_controller_20260829105508476_14480.slog").?;
    try testing.expectEqual(Role.controller, controller.role);
    try testing.expectEqual(@as(u32, 14480), controller.pid.?);
}

test "parses rotation segments and streamer logs" {
    const rotated = parseName("connection_log_controlled_20260902193237092_8752.2.slog").?;
    try testing.expectEqual(@as(u32, 2), rotated.segment);
    try testing.expectEqual(@as(u32, 8752), rotated.pid.?);

    const streamer = parseName("streamer_log_controlled_20260830100846506_1556.slog").?;
    try testing.expectEqual(Kind.streamer, streamer.kind);
    try testing.expectEqual(Role.controlled, streamer.role);

    const run = parseName("log_20261016104937107_7076.slog").?;
    try testing.expectEqual(Kind.run, run.kind);
    try testing.expectEqual(Role.none, run.role);
    try testing.expectEqual(@as(u32, 7076), run.pid.?);
}

test "rejects non-slog names and malformed stamps" {
    try testing.expect(parseName("config.ini") == null);
    try testing.expect(parseName("Sentry") == null);
    const bad_stamp = parseName("connection_log_controller_20261329105508476_1.slog").?;
    try testing.expect(bad_stamp.start_ms == null);
    try testing.expect(bad_stamp.pid.? == 1);
}

test "magic detection" {
    try testing.expect(hasSlogMagic("SLOG\r\x1A\x00\x01"));
    try testing.expect(!hasSlogMagic("hello"));
    try testing.expect(!hasSlogMagic("SL"));
}
