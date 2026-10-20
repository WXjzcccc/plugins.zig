//! Just enough MessagePack for the plugin protocol: the LPP frame payload is a
//! MessagePack map, so we need to read one and write one.
//!
//! Only what the protocol uses is implemented — nil, bool, ints, floats,
//! strings, binary, arrays and maps. Ext types are rejected rather than
//! silently mishandled.

const std = @import("std");

pub const Error = error{ Malformed, UnsupportedType, OutOfMemory };

pub const Entry = struct { key: []const u8, value: Value };

pub const Value = union(enum) {
    nil,
    boolean: bool,
    uint: u64,
    int: i64,
    /// Always encoded as float64 (0xcb); float32 replies decode into it too.
    float: f64,
    string: []const u8,
    bytes: []const u8,
    // These must be `const` slices, or `&.{...}` literals fail to compile.
    array: []const Value,
    map: []const Entry,

    pub fn get(self: Value, key: []const u8) ?Value {
        const entries = switch (self) {
            .map => |items| items,
            else => return null,
        };
        for (entries) |item| {
            if (std.mem.eql(u8, item.key, key)) return item.value;
        }
        return null;
    }

    pub fn getString(self: Value, key: []const u8) ?[]const u8 {
        return switch (self.get(key) orelse return null) {
            .string => |text| text,
            else => null,
        };
    }

    pub fn getUint(self: Value, key: []const u8) ?u64 {
        return switch (self.get(key) orelse return null) {
            .uint => |number| number,
            else => null,
        };
    }

    /// Integer fields read as floats too: the host is free to encode `1` as an
    /// int even where the schema says number.
    pub fn getFloat(self: Value, key: []const u8) ?f64 {
        return switch (self.get(key) orelse return null) {
            .float => |number| number,
            .uint => |number| @floatFromInt(number),
            .int => |number| @floatFromInt(number),
            else => null,
        };
    }
};

pub fn entry(key: []const u8, value: Value) Entry {
    return .{ .key = key, .value = value };
}

pub fn str(text: []const u8) Value {
    return .{ .string = text };
}

pub fn uint(number: u64) Value {
    return .{ .uint = number };
}

/// Build a map, copying the entries into `alloc`.
///
/// The copy matters: `&.{...}` is a *stack temporary*, so handing its address
/// to the host produces a dangling pointer the moment the function returns.
pub fn mapOf(alloc: std.mem.Allocator, items: []const Entry) Error!Value {
    return .{ .map = try alloc.dupe(Entry, items) };
}

/// Build an array, copying the items into `alloc`. Same reason as `mapOf`.
pub fn arrayOf(alloc: std.mem.Allocator, items: []const Value) Error!Value {
    return .{ .array = try alloc.dupe(Value, items) };
}

pub fn encode(alloc: std.mem.Allocator, value: Value) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try write(alloc, &out, value);
    return out.toOwnedSlice(alloc);
}

fn write(alloc: std.mem.Allocator, out: *std.ArrayList(u8), value: Value) Error!void {
    switch (value) {
        .nil => try out.append(alloc, 0xc0),
        .boolean => |flag| try out.append(alloc, if (flag) 0xc3 else 0xc2),
        .uint => |number| try writeUint(alloc, out, number),
        .int => |number| try writeInt(alloc, out, number),
        .float => |number| {
            try out.append(alloc, 0xcb);
            try out.appendSlice(alloc, &bigEndian(@as(u64, @bitCast(number))));
        },
        .string => |text| {
            if (text.len < 32) {
                try out.append(alloc, 0xa0 | @as(u8, @intCast(text.len)));
            } else if (text.len < 256) {
                try out.appendSlice(alloc, &.{ 0xd9, @intCast(text.len) });
            } else if (text.len < 65536) {
                try out.append(alloc, 0xda);
                try out.appendSlice(alloc, &bigEndian(@as(u16, @intCast(text.len))));
            } else {
                try out.append(alloc, 0xdb);
                try out.appendSlice(alloc, &bigEndian(@as(u32, @intCast(text.len))));
            }
            try out.appendSlice(alloc, text);
        },
        .bytes => |data| {
            if (data.len < 256) {
                try out.appendSlice(alloc, &.{ 0xc4, @intCast(data.len) });
            } else if (data.len < 65536) {
                try out.append(alloc, 0xc5);
                try out.appendSlice(alloc, &bigEndian(@as(u16, @intCast(data.len))));
            } else {
                try out.append(alloc, 0xc6);
                try out.appendSlice(alloc, &bigEndian(@as(u32, @intCast(data.len))));
            }
            try out.appendSlice(alloc, data);
        },
        .array => |items| {
            try writeHeader(alloc, out, 0x90, 0xdc, 0xdd, items.len);
            for (items) |item| try write(alloc, out, item);
        },
        .map => |items| {
            try writeHeader(alloc, out, 0x80, 0xde, 0xdf, items.len);
            for (items) |item| {
                try write(alloc, out, str(item.key));
                try write(alloc, out, item.value);
            }
        },
    }
}

/// Array and map length headers: fix form, then 16-bit, then 32-bit.
fn writeHeader(
    alloc: std.mem.Allocator,
    out: *std.ArrayList(u8),
    fix_tag: u8,
    tag16: u8,
    tag32: u8,
    len: usize,
) Error!void {
    if (len < 16) {
        try out.append(alloc, fix_tag | @as(u8, @intCast(len)));
    } else if (len < 65536) {
        try out.append(alloc, tag16);
        try out.appendSlice(alloc, &bigEndian(@as(u16, @intCast(len))));
    } else {
        try out.append(alloc, tag32);
        try out.appendSlice(alloc, &bigEndian(@as(u32, @intCast(len))));
    }
}

fn writeUint(alloc: std.mem.Allocator, out: *std.ArrayList(u8), number: u64) Error!void {
    if (number < 128) {
        try out.append(alloc, @intCast(number));
    } else if (number <= 0xff) {
        try out.appendSlice(alloc, &.{ 0xcc, @intCast(number) });
    } else if (number <= 0xffff) {
        try out.append(alloc, 0xcd);
        try out.appendSlice(alloc, &bigEndian(@as(u16, @intCast(number))));
    } else if (number <= 0xffff_ffff) {
        try out.append(alloc, 0xce);
        try out.appendSlice(alloc, &bigEndian(@as(u32, @intCast(number))));
    } else {
        try out.append(alloc, 0xcf);
        try out.appendSlice(alloc, &bigEndian(number));
    }
}

fn writeInt(alloc: std.mem.Allocator, out: *std.ArrayList(u8), number: i64) Error!void {
    if (number >= -32) {
        try out.append(alloc, @bitCast(@as(i8, @intCast(number))));
    } else if (number >= -128) {
        try out.appendSlice(alloc, &.{ 0xd0, @bitCast(@as(i8, @intCast(number))) });
    } else if (number >= -32768) {
        try out.append(alloc, 0xd1);
        try out.appendSlice(alloc, &bigEndian(@as(i16, @intCast(number))));
    } else if (number >= -2147483648) {
        try out.append(alloc, 0xd2);
        try out.appendSlice(alloc, &bigEndian(@as(i32, @intCast(number))));
    } else {
        try out.append(alloc, 0xd3);
        try out.appendSlice(alloc, &bigEndian(number));
    }
}

fn bigEndian(number: anytype) [@sizeOf(@TypeOf(number))]u8 {
    var bytes: [@sizeOf(@TypeOf(number))]u8 = undefined;
    std.mem.writeInt(@TypeOf(number), &bytes, number, .big);
    return bytes;
}

/// Decode one value. Everything in the result is copied into `alloc`, because
/// the buffer being read belongs to the caller and is freed as soon as this
/// call returns.
pub fn decode(alloc: std.mem.Allocator, data: []const u8) Error!Value {
    var reader = Reader{ .data = data };
    const value = try read(alloc, &reader);
    if (reader.pos != data.len) return error.Malformed;
    return value;
}

const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, len: usize) Error![]const u8 {
        if (self.pos + len > self.data.len) return error.Malformed;
        const slice = self.data[self.pos..][0..len];
        self.pos += len;
        return slice;
    }

    fn byte(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }

    /// `self` first so this reads as `reader.int(u16)`.
    fn int(self: *Reader, comptime T: type) Error!T {
        const raw = try self.take(@sizeOf(T));
        return std.mem.readInt(T, raw[0..@sizeOf(T)], .big);
    }
};

/// Copy `len` bytes out of the reader. Never return a borrowed slice: the
/// source buffer dies with the host call.
fn copy(alloc: std.mem.Allocator, reader: *Reader, len: usize) Error![]const u8 {
    return alloc.dupe(u8, try reader.take(len));
}

// Every recursive function needs an explicit error set, or the compiler
// reports "dependency loop with length 2" while inferring it.
fn read(alloc: std.mem.Allocator, reader: *Reader) Error!Value {
    const tag = try reader.byte();
    return switch (tag) {
        0xc0 => .nil,
        0xc2 => .{ .boolean = false },
        0xc3 => .{ .boolean = true },
        0x00...0x7f => .{ .uint = tag },
        0xe0...0xff => .{ .int = @as(i8, @bitCast(tag)) },
        0xcc => .{ .uint = try reader.int(u8) },
        0xcd => .{ .uint = try reader.int(u16) },
        0xce => .{ .uint = try reader.int(u32) },
        0xcf => .{ .uint = try reader.int(u64) },
        0xd0 => .{ .int = try reader.int(i8) },
        0xd1 => .{ .int = try reader.int(i16) },
        0xd2 => .{ .int = try reader.int(i32) },
        0xd3 => .{ .int = try reader.int(i64) },
        0xca => .{ .float = @as(f32, @bitCast(try reader.int(u32))) },
        0xcb => .{ .float = @bitCast(try reader.int(u64)) },
        0xa0...0xbf => .{ .string = try copy(alloc, reader, tag & 0x1f) },
        0xd9 => .{ .string = try copy(alloc, reader, try reader.int(u8)) },
        0xda => .{ .string = try copy(alloc, reader, try reader.int(u16)) },
        0xdb => .{ .string = try copy(alloc, reader, try reader.int(u32)) },
        0xc4 => .{ .bytes = try copy(alloc, reader, try reader.int(u8)) },
        0xc5 => .{ .bytes = try copy(alloc, reader, try reader.int(u16)) },
        0xc6 => .{ .bytes = try copy(alloc, reader, try reader.int(u32)) },
        0x90...0x9f => .{ .array = try readArray(alloc, reader, tag & 0x0f) },
        0xdc => .{ .array = try readArray(alloc, reader, try reader.int(u16)) },
        0xdd => .{ .array = try readArray(alloc, reader, try reader.int(u32)) },
        0x80...0x8f => .{ .map = try readMap(alloc, reader, tag & 0x0f) },
        0xde => .{ .map = try readMap(alloc, reader, try reader.int(u16)) },
        0xdf => .{ .map = try readMap(alloc, reader, try reader.int(u32)) },
        else => error.UnsupportedType,
    };
}

fn readArray(alloc: std.mem.Allocator, reader: *Reader, len: usize) Error![]const Value {
    const items = try alloc.alloc(Value, len);
    for (items) |*slot| slot.* = try read(alloc, reader);
    return items;
}

fn readMap(alloc: std.mem.Allocator, reader: *Reader, len: usize) Error![]const Entry {
    const items = try alloc.alloc(Entry, len);
    for (items) |*slot| {
        const key = try read(alloc, reader);
        // Named `key` and not `entry`: a capture named `entry` would shadow
        // the module-level `entry` function.
        const name = switch (key) {
            .string => |text| text,
            else => return error.UnsupportedType,
        };
        slot.* = .{ .key = name, .value = try read(alloc, reader) };
    }
    return items;
}

const testing = std.testing;

test "round trip through a decode/encode cycle" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original = try mapOf(alloc, &.{
        entry("protocol", uint(2)),
        entry("plugin", str("org.lovelycarve.template")),
        entry("records", try arrayOf(alloc, &.{try mapOf(alloc, &.{
            entry("type", str("demo.release")),
            entry("label", str("系统信息")),
        })})),
        entry("data", .{ .bytes = &.{ 0, 1, 0xff } }),
    });

    const decoded = try decode(alloc, try encode(alloc, original));
    try testing.expectEqual(@as(u64, 2), decoded.getUint("protocol").?);
    try testing.expectEqualStrings(
        "org.lovelycarve.template",
        decoded.getString("plugin").?,
    );
    try testing.expectEqualStrings(
        "demo.release",
        decoded.get("records").?.array[0].getString("type").?,
    );
    try testing.expectEqualSlices(u8, &.{ 0, 1, 0xff }, decoded.get("data").?.bytes);
}

test "integers use the shortest encoding" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try testing.expectEqualSlices(u8, &.{0x05}, try encode(alloc, uint(5)));
    try testing.expectEqualSlices(u8, &.{ 0xcc, 0xff }, try encode(alloc, uint(255)));
    try testing.expectEqualSlices(u8, &.{ 0xcd, 0x01, 0x00 }, try encode(alloc, uint(256)));
    try testing.expectEqualSlices(u8, &.{0xff}, try encode(alloc, .{ .int = -1 }));
}

test "malformed and unsupported input is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Trailing bytes mean the frame did not hold exactly one value.
    try testing.expectError(error.Malformed, decode(alloc, &.{ 0x01, 0x02 }));
    // Truncated string.
    try testing.expectError(error.Malformed, decode(alloc, &.{ 0xa5, 'a' }));
    // An ext type is outside the subset this protocol uses.
    try testing.expectError(error.UnsupportedType, decode(alloc, &.{ 0xd4, 0x01, 0x00 }));
}

test "floats round-trip as float64" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const encoded = try encode(alloc, .{ .float = 0.75 });
    // 0xcb is float64, and 0.75 has an exact bit pattern.
    try testing.expectEqualSlices(u8, &.{ 0xcb, 0x3f, 0xe8, 0, 0, 0, 0, 0, 0 }, encoded);
    const decoded = try decode(alloc, encoded);
    try testing.expectEqual(@as(f64, 0.75), decoded.float);

    // A float32 reply decodes into the same member.
    const small = try decode(alloc, &.{ 0xca, 0x3f, 0x40, 0, 0 });
    try testing.expectEqual(@as(f64, 0.75), small.float);

    // Integers read as floats where the schema says number.
    const map = try mapOf(alloc, &.{
        entry("confidence", .{ .float = 0.5 }),
        entry("count", uint(3)),
    });
    try testing.expectEqual(@as(f64, 0.5), map.getFloat("confidence").?);
    try testing.expectEqual(@as(f64, 3), map.getFloat("count").?);
    try testing.expectEqual(null, map.getFloat("missing"));
}
