//! JSON for `plugin.hello`, the document `lc-plugin-host --describe`
//! prints and the plugin build writes beside the manifest as `schema.json`.
//!
//! The host reads that file with `serde_json` into the same `Hello` type the
//! wire carries, so this only has to emit valid JSON with the protocol's field
//! names; key order is irrelevant (the schema hash covers ordering, not this
//! document).

const std = @import("std");

const wire = @import("wire.zig");

pub const Error = error{ OutOfMemory, UnsupportedType };

/// Compact JSON, one line.
pub fn write(alloc: std.mem.Allocator, value: wire.Value) Error![]u8 {
    return writeInner(alloc, value, null);
}

/// Indented JSON with two spaces per level, for the `schema.json` a package
/// ships (it is meant to be read by people and diffed in reviews).
pub fn writePretty(alloc: std.mem.Allocator, value: wire.Value) Error![]u8 {
    return writeInner(alloc, value, "  ");
}

fn writeInner(alloc: std.mem.Allocator, value: wire.Value, indent: ?[]const u8) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try writeValue(alloc, &out, value, indent, 0);
    return out.toOwnedSlice(alloc);
}

fn writeValue(
    alloc: std.mem.Allocator,
    out: *std.ArrayList(u8),
    value: wire.Value,
    indent: ?[]const u8,
    depth: usize,
) Error!void {
    switch (value) {
        .nil => try out.appendSlice(alloc, "null"),
        .boolean => |flag| try out.appendSlice(alloc, if (flag) "true" else "false"),
        .uint => |number| try appendFormat(alloc, out, "{d}", .{number}),
        .int => |number| try appendFormat(alloc, out, "{d}", .{number}),
        .float => |number| {
            if (!std.math.isFinite(number)) return error.UnsupportedType;
            try appendFormat(alloc, out, "{d}", .{number});
        },
        .string => |text| try writeString(alloc, out, text),
        .bytes => |data| {
            // The protocol sends binary as MessagePack bin; JSON has no such
            // type, so it becomes a lowercase hex string.
            try out.append(alloc, '"');
            for (data) |byte| try appendFormat(alloc, out, "{x:0>2}", .{byte});
            try out.append(alloc, '"');
        },
        .array => |items| {
            if (items.len == 0) {
                try out.appendSlice(alloc, "[]");
                return;
            }
            try out.append(alloc, '[');
            for (items, 0..) |item, index| {
                if (index != 0) try out.append(alloc, ',');
                try newline(alloc, out, indent, depth + 1);
                try writeValue(alloc, out, item, indent, depth + 1);
            }
            try newline(alloc, out, indent, depth);
            try out.append(alloc, ']');
        },
        .map => |entries| {
            if (entries.len == 0) {
                try out.appendSlice(alloc, "{}");
                return;
            }
            try out.append(alloc, '{');
            for (entries, 0..) |entry, index| {
                if (index != 0) try out.append(alloc, ',');
                try newline(alloc, out, indent, depth + 1);
                try writeString(alloc, out, entry.key);
                try out.appendSlice(alloc, if (indent == null) ":" else ": ");
                try writeValue(alloc, out, entry.value, indent, depth + 1);
            }
            try newline(alloc, out, indent, depth);
            try out.append(alloc, '}');
        },
    }
}

/// Formats into a small stack buffer and appends the result; the JSON
/// documents here are small and a scratch writer per value would only add
/// allocation.
fn appendFormat(
    alloc: std.mem.Allocator,
    out: *std.ArrayList(u8),
    comptime format: []const u8,
    args: anytype,
) Error!void {
    var buffer: [64]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, format, args) catch return error.OutOfMemory;
    try out.appendSlice(alloc, text);
}

fn newline(
    alloc: std.mem.Allocator,
    out: *std.ArrayList(u8),
    indent: ?[]const u8,
    depth: usize,
) Error!void {
    const spaces = indent orelse return;
    try out.append(alloc, '\n');
    var level: usize = 0;
    while (level < depth) : (level += 1) try out.appendSlice(alloc, spaces);
}

fn writeString(alloc: std.mem.Allocator, out: *std.ArrayList(u8), text: []const u8) Error!void {
    try out.append(alloc, '"');
    var index: usize = 0;
    while (index < text.len) : (index += 1) {
        const byte = text[index];
        switch (byte) {
            '"' => try out.appendSlice(alloc, "\\\""),
            '\\' => try out.appendSlice(alloc, "\\\\"),
            '\n' => try out.appendSlice(alloc, "\\n"),
            '\r' => try out.appendSlice(alloc, "\\r"),
            '\t' => try out.appendSlice(alloc, "\\t"),
            0x08 => try out.appendSlice(alloc, "\\b"),
            0x0c => try out.appendSlice(alloc, "\\f"),
            else => {
                if (byte < 0x20) {
                    try appendFormat(alloc, out, "\\u{x:0>4}", .{byte});
                } else {
                    try out.append(alloc, byte);
                }
            },
        }
    }
    try out.append(alloc, '"');
}

const testing = std.testing;

test "values encode as JSON" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const value = try wire.mapOf(alloc, &.{
        wire.entry("protocol", wire.uint(2)),
        wire.entry("plugin", wire.str("org.example.demo")),
        wire.entry("analyzers", try wire.arrayOf(alloc, &.{wire.str("base")})),
        wire.entry("empty", try wire.arrayOf(alloc, &.{})),
        wire.entry("records", .nil),
    });
    try testing.expectEqualStrings(
        "{\"protocol\":2,\"plugin\":\"org.example.demo\",\"analyzers\":[\"base\"],\"empty\":[],\"records\":null}",
        try write(alloc, value),
    );

    const pretty = try writePretty(alloc, try wire.mapOf(alloc, &.{
        wire.entry("a", wire.uint(1)),
        wire.entry("b", try wire.arrayOf(alloc, &.{wire.str("x\"y")})),
    }));
    try testing.expectEqualStrings(
        "{\n  \"a\": 1,\n  \"b\": [\n    \"x\\\"y\"\n  ]\n}",
        pretty,
    );
}

test "control characters are escaped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    try testing.expectEqualStrings(
        "\"a\\tb\\u0001\"",
        try write(alloc, wire.str("a\tb\x01")),
    );
}
