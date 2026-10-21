//! Typing and (de)serialization of registry values (`REG_*`).

const std = @import("std");
const errors = @import("error.zig");

const Allocator = std.mem.Allocator;
const Error = errors.Error;

/// A registry value's type (the `type` field of a `vk` cell).
pub const RegType = enum(u32) {
    none = 0,
    sz = 1,
    expand_sz = 2,
    binary = 3,
    dword = 4,
    dword_be = 5,
    link = 6,
    multi_sz = 7,
    qword = 11,
    _,

    pub fn fromU32(v: u32) RegType {
        return switch (v) {
            0 => .none,
            1 => .sz,
            2 => .expand_sz,
            3 => .binary,
            4 => .dword,
            5 => .dword_be,
            6 => .link,
            7 => .multi_sz,
            11 => .qword,
            else => @enumFromInt(v),
        };
    }

    pub fn toU32(self: RegType) u32 {
        return @intFromEnum(self);
    }
};

/// A decoded registry value. Every slice is owned by the value: release it
/// with [`RegValue.deinit`].
pub const RegValue = union(enum) {
    none,
    sz: []u8,
    expand_sz: []u8,
    binary: []u8,
    dword: u32,
    dword_be: u32,
    multi_sz: [][]u8,
    qword: u64,
    /// Non-standard type: raw bytes + type code.
    other: Other,

    pub const Other = struct {
        ty: u32,
        data: []u8,
    };

    /// Corresponding REGF type.
    pub fn regType(self: RegValue) RegType {
        return switch (self) {
            .none => .none,
            .sz => .sz,
            .expand_sz => .expand_sz,
            .binary => .binary,
            .dword => .dword,
            .dword_be => .dword_be,
            .multi_sz => .multi_sz,
            .qword => .qword,
            .other => |o| RegType.fromU32(o.ty),
        };
    }

    /// Encodes the value to raw bytes (a data cell's content). The caller owns
    /// the returned buffer.
    pub fn toBytes(self: RegValue, gpa: Allocator) Error![]u8 {
        return switch (self) {
            .none => gpa.alloc(u8, 0),
            .sz => |s| encodeUtf16z(gpa, s),
            .expand_sz => |s| encodeUtf16z(gpa, s),
            .binary => |b| gpa.dupe(u8, b),
            .dword => |v| blk: {
                const out = try gpa.alloc(u8, 4);
                std.mem.writeInt(u32, out[0..4], v, .little);
                break :blk out;
            },
            .dword_be => |v| blk: {
                const out = try gpa.alloc(u8, 4);
                std.mem.writeInt(u32, out[0..4], v, .big);
                break :blk out;
            },
            .qword => |v| blk: {
                const out = try gpa.alloc(u8, 8);
                std.mem.writeInt(u64, out[0..8], v, .little);
                break :blk out;
            },
            .multi_sz => |items| blk: {
                var out: std.ArrayList(u8) = .empty;
                errdefer out.deinit(gpa);
                for (items) |item| {
                    const enc = try encodeUtf16z(gpa, item);
                    defer gpa.free(enc);
                    try out.appendSlice(gpa, enc);
                }
                try out.appendSlice(gpa, &.{ 0, 0 }); // final terminator
                break :blk try out.toOwnedSlice(gpa);
            },
            .other => |o| gpa.dupe(u8, o.data),
        };
    }

    /// Decodes a value from its type and raw bytes.
    pub fn fromRaw(gpa: Allocator, ty: RegType, data: []const u8) Error!RegValue {
        return switch (ty) {
            .none => .none,
            .sz => .{ .sz = try decodeUtf16z(gpa, data) },
            .expand_sz => .{ .expand_sz = try decodeUtf16z(gpa, data) },
            .binary => .{ .binary = try gpa.dupe(u8, data) },
            .dword => .{ .dword = readU32Le(data) },
            .dword_be => .{ .dword_be = readU32Be(data) },
            .link => .{ .sz = try decodeUtf16z(gpa, data) },
            .multi_sz => .{ .multi_sz = try decodeMultiSz(gpa, data) },
            .qword => .{ .qword = readU64Le(data) },
            else => .{ .other = .{ .ty = ty.toU32(), .data = try gpa.dupe(u8, data) } },
        };
    }

    /// Releases every buffer owned by the value. Safe on any variant.
    pub fn deinit(self: RegValue, gpa: Allocator) void {
        switch (self) {
            .sz => |s| gpa.free(s),
            .expand_sz => |s| gpa.free(s),
            .binary => |b| gpa.free(b),
            .multi_sz => |items| {
                for (items) |item| gpa.free(item);
                gpa.free(items);
            },
            .other => |o| gpa.free(o.data),
            .none, .dword, .dword_be, .qword => {},
        }
    }

    /// Deep structural equality (the Rust `PartialEq` counterpart).
    pub fn eql(self: RegValue, other: RegValue) bool {
        if (std.meta.activeTag(self) != std.meta.activeTag(other)) return false;
        return switch (self) {
            .none => true,
            .sz => |a| std.mem.eql(u8, a, other.sz),
            .expand_sz => |a| std.mem.eql(u8, a, other.expand_sz),
            .binary => |a| std.mem.eql(u8, a, other.binary),
            .dword => |a| a == other.dword,
            .dword_be => |a| a == other.dword_be,
            .qword => |a| a == other.qword,
            .multi_sz => |a| blk: {
                const b = other.multi_sz;
                if (a.len != b.len) break :blk false;
                for (a, b) |x, y| {
                    if (!std.mem.eql(u8, x, y)) break :blk false;
                }
                break :blk true;
            },
            .other => |a| a.ty == other.other.ty and std.mem.eql(u8, a.data, other.other.data),
        };
    }
};

fn encodeUtf16z(gpa: Allocator, s: []const u8) Error![]u8 {
    const units = std.unicode.utf8ToUtf16LeAlloc(gpa, s) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidUtf8 => {
            // Store the raw bytes widened one-to-one rather than failing: the
            // caller handed us a malformed string, and a hive write must not
            // silently drop it.
            const out = try gpa.alloc(u8, (s.len + 1) * 2);
            for (s, 0..) |b, i| {
                out[i * 2] = b;
                out[i * 2 + 1] = 0;
            }
            out[s.len * 2] = 0;
            out[s.len * 2 + 1] = 0;
            return out;
        },
    };
    defer gpa.free(units);
    const out = try gpa.alloc(u8, units.len * 2 + 2);
    for (units, 0..) |u, i| {
        std.mem.writeInt(u16, out[i * 2 ..][0..2], u, .little);
    }
    out[units.len * 2] = 0;
    out[units.len * 2 + 1] = 0;
    return out;
}

/// Decodes UTF-16LE bytes up to the first NUL, replacing unpaired surrogates
/// with U+FFFD (the Rust `from_utf16_lossy` behaviour).
fn decodeUtf16z(gpa: Allocator, data: []const u8) Error![]u8 {
    const units = try readUnits(gpa, data);
    defer gpa.free(units);
    var end: usize = 0;
    while (end < units.len and units[end] != 0) : (end += 1) {}
    return utf16Lossy(gpa, units[0..end]);
}

fn decodeMultiSz(gpa: Allocator, data: []const u8) Error![][]u8 {
    const units = try readUnits(gpa, data);
    defer gpa.free(units);
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |s| gpa.free(s);
        out.deinit(gpa);
    }
    var start: usize = 0;
    var i: usize = 0;
    while (i < units.len) : (i += 1) {
        if (units[i] != 0) continue;
        if (i == start) break; // double NUL (or a leading NUL) ends the list
        const s = try utf16Lossy(gpa, units[start..i]);
        try out.append(gpa, s);
        start = i + 1;
    }
    return out.toOwnedSlice(gpa);
}

fn readUnits(gpa: Allocator, data: []const u8) Error![]u16 {
    const n = data.len / 2;
    const units = try gpa.alloc(u16, n);
    for (0..n) |i| {
        units[i] = std.mem.readInt(u16, data[i * 2 ..][0..2], .little);
    }
    return units;
}

fn utf16Lossy(gpa: Allocator, units: []const u16) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < units.len) {
        const u = units[i];
        if (u >= 0xD800 and u <= 0xDBFF) {
            if (i + 1 < units.len and units[i + 1] >= 0xDC00 and units[i + 1] <= 0xDFFF) {
                const cp: u21 = 0x10000 +
                    (@as(u21, u - 0xD800) << 10) +
                    @as(u21, units[i + 1] - 0xDC00);
                var buf: [4]u8 = undefined;
                // `cp` is a valid scalar value by construction (the surrogate
                // pair was already checked), so encoding cannot fail; fall back
                // to U+FFFD rather than trapping if that ever stops holding.
                const n = std.unicode.utf8Encode(cp, &buf) catch blk: {
                    break :blk std.unicode.utf8Encode(0xFFFD, &buf) catch 0;
                };
                try out.appendSlice(gpa, buf[0..n]);
                i += 2;
                continue;
            }
            try out.appendSlice(gpa, "\u{FFFD}");
            i += 1;
            continue;
        }
        if (u >= 0xDC00 and u <= 0xDFFF) {
            try out.appendSlice(gpa, "\u{FFFD}");
            i += 1;
            continue;
        }
        var buf: [4]u8 = undefined;
        // Surrogates were handled above, so `u` is a valid scalar value.
        const n = std.unicode.utf8Encode(@intCast(u), &buf) catch blk: {
            break :blk std.unicode.utf8Encode(0xFFFD, &buf) catch 0;
        };
        try out.appendSlice(gpa, buf[0..n]);
        i += 1;
    }
    return out.toOwnedSlice(gpa);
}

fn readU32Le(data: []const u8) u32 {
    var b: [4]u8 = @splat(0);
    const n = @min(data.len, 4);
    @memcpy(b[0..n], data[0..n]);
    return std.mem.readInt(u32, &b, .little);
}

fn readU32Be(data: []const u8) u32 {
    var b: [4]u8 = @splat(0);
    const n = @min(data.len, 4);
    @memcpy(b[0..n], data[0..n]);
    return std.mem.readInt(u32, &b, .big);
}

fn readU64Le(data: []const u8) u64 {
    var b: [8]u8 = @splat(0);
    const n = @min(data.len, 8);
    @memcpy(b[0..n], data[0..n]);
    return std.mem.readInt(u64, &b, .little);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn roundTrip(v: RegValue) !void {
    const gpa = testing.allocator;
    const ty = v.regType();
    const bytes = try v.toBytes(gpa);
    defer gpa.free(bytes);
    const back = try RegValue.fromRaw(gpa, ty, bytes);
    defer back.deinit(gpa);
    try testing.expect(v.eql(back));
}

test "round-trip every value kind" {
    const gpa = testing.allocator;
    const sz = try gpa.dupe(u8, "Hello");
    defer gpa.free(sz);
    try roundTrip(.{ .sz = sz });

    const exp = try gpa.dupe(u8, "%PATH%");
    defer gpa.free(exp);
    try roundTrip(.{ .expand_sz = exp });

    try roundTrip(.{ .dword = 0xDEAD_BEEF });
    try roundTrip(.{ .dword_be = 0x0102_0304 });
    try roundTrip(.{ .qword = 0x0123_4567_89AB_CDEF });
    try roundTrip(.none);

    const bin = try gpa.dupe(u8, &.{ 1, 2, 3, 4, 5 });
    defer gpa.free(bin);
    try roundTrip(.{ .binary = bin });

    const items = try gpa.alloc([]u8, 2);
    items[0] = try gpa.dupe(u8, "a");
    items[1] = try gpa.dupe(u8, "bb");
    defer {
        gpa.free(items[0]);
        gpa.free(items[1]);
        gpa.free(items);
    }
    try roundTrip(.{ .multi_sz = items });

    const empty_items = try gpa.alloc([]u8, 0);
    defer gpa.free(empty_items);
    try roundTrip(.{ .multi_sz = empty_items });

    const other = try gpa.dupe(u8, &.{ 9, 8, 7 });
    defer gpa.free(other);
    try roundTrip(.{ .other = .{ .ty = 0x42, .data = other } });
}

test "sz is null-terminated utf16" {
    const gpa = testing.allocator;
    const v: RegValue = .{ .sz = try gpa.dupe(u8, "Hi") };
    defer v.deinit(gpa);
    const b = try v.toBytes(gpa);
    defer gpa.free(b);
    try testing.expectEqualSlices(u8, &.{ 'H', 0, 'i', 0, 0, 0 }, b);
}

test "multi_sz has a double terminator" {
    const gpa = testing.allocator;
    const items = try gpa.alloc([]u8, 2);
    items[0] = try gpa.dupe(u8, "a");
    items[1] = try gpa.dupe(u8, "b");
    const v: RegValue = .{ .multi_sz = items };
    defer v.deinit(gpa);
    const b = try v.toBytes(gpa);
    defer gpa.free(b);
    try testing.expectEqualSlices(
        u8,
        &.{ 'a', 0, 0, 0, 'b', 0, 0, 0, 0, 0 },
        b,
    );
}

test "dword tolerates a short buffer" {
    const gpa = testing.allocator;
    const v = try RegValue.fromRaw(gpa, .dword, &.{ 0x34, 0x12 });
    defer v.deinit(gpa);
    try testing.expectEqual(@as(u32, 0x1234), v.dword);
}

test "non-ascii strings survive the utf16 round trip" {
    const gpa = testing.allocator;
    const s = try gpa.dupe(u8, "ключ \u{1F600}");
    defer gpa.free(s);
    const v: RegValue = .{ .sz = s };
    const bytes = try v.toBytes(gpa);
    defer gpa.free(bytes);
    const back = try RegValue.fromRaw(gpa, .sz, bytes);
    defer back.deinit(gpa);
    try testing.expectEqualStrings("ключ \u{1F600}", back.sz);
}

test "unpaired surrogate decodes to U+FFFD" {
    const gpa = testing.allocator;
    // 0xD800 followed by NUL: a lone high surrogate.
    const v = try RegValue.fromRaw(gpa, .sz, &.{ 0x00, 0xD8, 0x00, 0x00 });
    defer v.deinit(gpa);
    try testing.expectEqualStrings("\u{FFFD}", v.sz);
}

test "type codes map both ways" {
    try testing.expectEqual(@as(u32, 11), RegType.qword.toU32());
    try testing.expectEqual(RegType.dword_be, RegType.fromU32(5));
    try testing.expectEqual(@as(u32, 0x99), RegType.fromU32(0x99).toU32());
}
