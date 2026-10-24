//! `ini.zig` — a small Windows-INI reader for forensic parsing.
//!
//! Windows applications (GameViewer/UU远程 among them) keep settings in
//! classic INI files. This module parses such files into sections and
//! entries without interpreting their meaning, so plugins can extract
//! evidence from them.
//!
//! Behaviour follows what forensic parsing needs, not the full diversity of
//! INI dialects:
//!
//! - Lines are split on `\n`, `\r\n` and `\r`; a UTF-8 BOM is skipped.
//! - `[section]` headers and `key=value` pairs; everything outside a section
//!   is kept under the empty-name section (the implicit head).
//! - `;` and `#` start a comment only at the start of a (trimmed) line;
//!   inline comments are kept as part of the value, because INI dialects
//!   disagree on them and values may contain `#`.
//! - Later entries win: lookups mimic `GetPrivateProfileString`, where the
//!   last occurrence of a key (across all sections of the same name) answers.
//!   Every entry is still kept in order for record-level parsing.
//! - Surrounding double quotes of a value are stripped (Windows convention).
//! - `\xNNNN` escapes (four hex digits, UTF-16 code units, including
//!   surrogate pairs) are decoded into UTF-8 — the escape style the
//!   GameViewer files use for non-ASCII text (`\x6b64\x7535\x8111` =
//!   "此电脑").
//! - Broken lines never fail the parse: they become `Issue`s with their line
//!   number, and the rest of the document still parses.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// One `key=value` pair as written. `value` is decoded, `raw_value` is the
/// trimmed text after `=` as written (before quote stripping and escape
/// decoding). `line` is 1-based.
pub const Entry = struct {
    key: []const u8,
    value: []const u8,
    raw_value: []const u8,
    line: usize,
};

/// One `[section]` with its entries in file order. The implicit head section
/// (entries before the first header) has the empty name.
pub const Section = struct {
    name: []const u8,
    line: usize,
    entries: []const Entry,
};

/// A line the parser could not make sense of. INI dialects are diverse, so a
/// parse reports these and keeps going instead of failing.
pub const Issue = struct {
    line: usize,
    message: []const u8,
};

pub const Document = struct {
    sections: []const Section,
    issues: []const Issue,

    /// The last value of `key` within the last section of that name, like
    /// `GetPrivateProfileString`. Section and key names compare
    /// case-insensitively, like the Windows loader.
    pub fn get(self: *const Document, section: []const u8, key: []const u8) ?[]const u8 {
        var found: ?[]const u8 = null;
        for (self.sections) |sec| {
            if (!std.ascii.eqlIgnoreCase(sec.name, section)) continue;
            for (sec.entries) |entry| {
                if (std.ascii.eqlIgnoreCase(entry.key, key)) found = entry.value;
            }
        }
        return found;
    }

    /// Every entry of `key` in `section`, in file order (the raw view; most
    /// forensic questions want the last one, see `get`).
    pub fn getAll(
        self: *const Document,
        section: []const u8,
        key: []const u8,
        alloc: Allocator,
    ) Allocator.Error![]const []const u8 {
        var values: std.ArrayList([]const u8) = .empty;
        errdefer values.deinit(alloc);
        for (self.sections) |sec| {
            if (!std.ascii.eqlIgnoreCase(sec.name, section)) continue;
            for (sec.entries) |entry| {
                if (std.ascii.eqlIgnoreCase(entry.key, key)) {
                    try values.append(alloc, entry.value);
                }
            }
        }
        return values.toOwnedSlice(alloc);
    }

    /// Frees everything the parse allocated. All slices inside the document
    /// (and the ones `getAll` handed out) die with it.
    pub fn deinit(self: *const Document, alloc: Allocator) void {
        for (self.sections) |section| {
            for (section.entries) |entry| {
                alloc.free(entry.key);
                alloc.free(entry.value);
                alloc.free(entry.raw_value);
            }
            alloc.free(section.entries);
            alloc.free(section.name);
        }
        alloc.free(self.sections);
        for (self.issues) |issue| alloc.free(issue.message);
        alloc.free(self.issues);
    }
};

pub const Error = error{OutOfMemory};

/// Parses an INI document. `bytes` may be UTF-8 (with or without BOM); the
/// returned slices are owned by `alloc` — free them with `Document.deinit`.
pub fn parse(alloc: Allocator, bytes: []const u8) Error!Document {
    var sections: std.ArrayList(Section) = .empty;
    errdefer sections.deinit(alloc);
    var issues: std.ArrayList(Issue) = .empty;
    errdefer issues.deinit(alloc);

    // One entry list per section; built in parallel with `sections`.
    var entry_lists: std.ArrayList(std.ArrayList(Entry)) = .empty;
    errdefer {
        for (entry_lists.items) |*list| list.deinit(alloc);
        entry_lists.deinit(alloc);
    }

    var body = bytes;
    if (std.mem.startsWith(u8, body, "\xEF\xBB\xBF")) body = body[3..];

    // The implicit head section receives entries before the first header.
    try sections.append(alloc, .{ .name = try alloc.dupe(u8, ""), .line = 0, .entries = &.{} });
    try entry_lists.append(alloc, .empty);

    var lines = std.mem.tokenizeAny(u8, body, "\r\n");
    var line_number: usize = 0;
    while (lines.next()) |raw_line| {
        line_number += 1;
        const line = std.mem.trim(u8, raw_line, " \t\x0B\x0C");
        if (line.len == 0) continue;
        if (line[0] == ';' or line[0] == '#') continue;

        if (line[0] == '[') {
            const close = std.mem.lastIndexOfScalar(u8, line, ']') orelse {
                try issues.append(alloc, .{
                    .line = line_number,
                    .message = try std.fmt.allocPrint(alloc, "未闭合的节标题：{s}", .{truncate(line)}),
                });
                continue;
            };
            const name = std.mem.trim(u8, line[1..close], " \t");
            try sections.append(alloc, .{
                .name = try alloc.dupe(u8, name),
                .line = line_number,
                .entries = &.{},
            });
            try entry_lists.append(alloc, .empty);
            continue;
        }

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
            try issues.append(alloc, .{
                .line = line_number,
                .message = try std.fmt.allocPrint(alloc, "缺少 '=' 的行：{s}", .{truncate(line)}),
            });
            continue;
        };
        const key = std.mem.trim(u8, line[0..eq], " \t");
        if (key.len == 0) {
            try issues.append(alloc, .{
                .line = line_number,
                .message = try alloc.dupe(u8, "空的键名"),
            });
            continue;
        }
        const raw_value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        const value = try decodeValue(alloc, raw_value);
        const current = &entry_lists.items[entry_lists.items.len - 1];
        try current.append(alloc, .{
            .key = try alloc.dupe(u8, key),
            .value = value,
            .raw_value = try alloc.dupe(u8, raw_value),
            .line = line_number,
        });
    }

    // Move the per-section entry lists into their sections.
    for (sections.items, entry_lists.items) |*section, *list| {
        section.entries = try list.toOwnedSlice(alloc);
    }
    const owned_lists = try entry_lists.toOwnedSlice(alloc);
    alloc.free(owned_lists);
    return .{
        .sections = try sections.toOwnedSlice(alloc),
        .issues = try issues.toOwnedSlice(alloc),
    };
}

/// Decodes one value: strips one pair of surrounding double quotes, then
/// expands `\xNNNN` escapes into UTF-8. Anything else stays as written.
fn decodeValue(alloc: Allocator, raw: []const u8) Error![]const u8 {
    var text = raw;
    if (text.len >= 2 and text[0] == '"' and text[text.len - 1] == '"') {
        text = text[1 .. text.len - 1];
    }
    if (std.mem.indexOf(u8, text, "\\x") == null) return alloc.dupe(u8, text);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    var pending_surrogate: u21 = 0;

    var index: usize = 0;
    while (index < text.len) {
        if (text[index] == '\\' and index + 6 <= text.len and text[index + 1] == 'x') {
            const digits = text[index + 2 .. index + 6];
            if (hex4(digits)) |unit| {
                index += 6;
                const code: u21 = unit;
                if (pending_surrogate != 0) {
                    // A high surrogate waits for the next `\x` escape to
                    // complete the pair; anything else breaks it.
                    if (code >= 0xDC00 and code <= 0xDFFF) {
                        const combined = 0x10000 + ((pending_surrogate - 0xD800) << 10) + (code - 0xDC00);
                        try appendUtf8(alloc, &out, combined);
                        pending_surrogate = 0;
                    } else {
                        try appendUtf8(alloc, &out, 0xFFFD);
                        pending_surrogate = if (code >= 0xD800 and code <= 0xDBFF) code else 0;
                        if (pending_surrogate == 0) try appendUtf8(alloc, &out, code);
                    }
                } else if (code >= 0xD800 and code <= 0xDBFF) {
                    pending_surrogate = code;
                } else if (code >= 0xDC00 and code <= 0xDFFF) {
                    try appendUtf8(alloc, &out, 0xFFFD);
                } else {
                    try appendUtf8(alloc, &out, code);
                }
                continue;
            }
        }
        pending_surrogate = 0;
        try out.append(alloc, text[index]);
        index += 1;
    }
    if (pending_surrogate != 0) try appendUtf8(alloc, &out, 0xFFFD);
    return out.toOwnedSlice(alloc);
}

fn appendUtf8(alloc: Allocator, out: *std.ArrayList(u8), code: u21) Error!void {
    var buffer: [4]u8 = undefined;
    const length = std.unicode.utf8Encode(code, &buffer) catch {
        // Invalid scalar: keep the replacement character instead of failing.
        return out.appendSlice(alloc, "\xEF\xBF\xBD");
    };
    try out.appendSlice(alloc, buffer[0..length]);
}

fn hex4(digits: []const u8) ?u16 {
    var value: u16 = 0;
    for (digits) |c| {
        const digit: u16 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => return null,
        };
        value = value * 16 + digit;
    }
    return value;
}

/// Keeps issue messages short: at most one line of 48 characters.
fn truncate(line: []const u8) []const u8 {
    const cut = @min(line.len, 48);
    return line[0..cut];
}

const testing = std.testing;

test "parses sections, entries and last-wins lookups" {
    const doc = try parse(testing.allocator,
        \\[General]
        \\uuid=e63d9c4b-8bdc-46ab-9001-084eaca29964
        \\auto_run=1
        \\
        \\; a comment
        \\# another comment
        \\[aeawuwo5hea5k4rt]
        \\refresh_type=6
        \\last_refresh_time=1788356451
        \\enable_remote=1
    );
    defer doc.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 3), doc.sections.len);
    try testing.expectEqualStrings("e63d9c4b-8bdc-46ab-9001-084eaca29964", doc.get("General", "uuid").?);
    try testing.expectEqualStrings("1", doc.get("general", "AUTO_RUN").?);
    try testing.expectEqual(@as(usize, 1788356451), try std.fmt.parseInt(usize, doc.get("aeawuwo5hea5k4rt", "last_refresh_time").?, 10));
    try testing.expect(doc.get("General", "missing") == null);
    try testing.expectEqual(@as(usize, 0), doc.issues.len);
}

test "later sections and duplicate keys win" {
    const doc = try parse(testing.allocator,
        \\[cloudpcswitch]
        \\guest_anonymous_id=false
        \\
        \\[cloudpcswitch]
        \\guest_anonymous_id=true
    );
    defer doc.deinit(testing.allocator);
    try testing.expectEqualStrings("true", doc.get("cloudpcswitch", "guest_anonymous_id").?);
    const all = try doc.getAll("cloudpcswitch", "guest_anonymous_id", testing.allocator);
    defer testing.allocator.free(all);
    try testing.expectEqual(@as(usize, 2), all.len);
}

test "decodes quoted values and xNNNN escapes" {
    const doc = try parse(testing.allocator,
        \\[local]
        \\lastFolderName=\x6b64\x7535\x8111
        \\subtitle=\x4fee\x590d\x5df2\x77e5\x95ee\x9898
        \\url="https://a56.gdl.netease.com/setup.exe?key=1"
        \\plain=no\xescape here
    );
    defer doc.deinit(testing.allocator);
    try testing.expectEqualStrings("此电脑", doc.get("local", "lastFolderName").?);
    try testing.expectEqualStrings("修复已知问题", doc.get("local", "subtitle").?);
    try testing.expectEqualStrings("https://a56.gdl.netease.com/setup.exe?key=1", doc.get("local", "url").?);
    try testing.expectEqualStrings("no\\xescape here", doc.get("local", "plain").?);
}

test "decodes surrogate pairs" {
    const doc = try parse(testing.allocator,
        \\[s]
        \\emoji=\xd83d\xde00
    );
    defer doc.deinit(testing.allocator);
    try testing.expectEqualStrings("😀", doc.get("s", "emoji").?);
}

test "broken lines become issues, parsing continues" {
    const doc = try parse(testing.allocator,
        \\[General]
        \\no_equals_sign
        \\=empty_key
        \\[unclosed
        \\uuid=kept
    );
    defer doc.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), doc.issues.len);
    try testing.expectEqualStrings("kept", doc.get("General", "uuid").?);
    try testing.expectEqual(@as(usize, 4), doc.issues[2].line);
}

test "entries before any header land in the head section" {
    const doc = try parse(testing.allocator,
        \\orphan=1
        \\[General]
        \\uuid=2
    );
    defer doc.deinit(testing.allocator);
    try testing.expectEqualStrings("1", doc.get("", "orphan").?);
    try testing.expectEqualStrings("2", doc.get("General", "uuid").?);
}

test "crlf and bom are handled" {
    const text = "\xEF\xBB\xBF[General]\r\nuuid=abc\r\nauto_run=1\r\n";
    const doc = try parse(testing.allocator, text);
    defer doc.deinit(testing.allocator);
    try testing.expectEqualStrings("abc", doc.get("General", "uuid").?);
    try testing.expectEqualStrings("1", doc.get("General", "auto_run").?);
}
