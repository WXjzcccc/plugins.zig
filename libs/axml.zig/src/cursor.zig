const std = @import("std");

/// A bounds-checked cursor over immutable in-memory data.
///
/// Returned byte slices borrow `data`; the cursor never allocates.
pub const Cursor = struct {
    data: []const u8,
    pos: usize = 0,

    pub const Error = error{
        EndOfInput,
        IntegerOverflow,
    };

    pub fn init(data: []const u8) Cursor {
        return .{ .data = data };
    }

    pub fn offset(self: Cursor) usize {
        return self.pos;
    }

    pub fn remaining(self: Cursor) usize {
        return self.data.len - self.pos;
    }

    pub fn atEnd(self: Cursor) bool {
        return self.pos == self.data.len;
    }

    pub fn seekTo(self: *Cursor, new_pos: usize) Error!void {
        if (new_pos > self.data.len) return error.EndOfInput;
        self.pos = new_pos;
    }

    pub fn skip(self: *Cursor, len: usize) Error!void {
        _ = try self.readBytes(len);
    }

    pub fn readByte(self: *Cursor) Error!u8 {
        const bytes = try self.readBytes(1);
        return bytes[0];
    }

    pub fn readBytes(self: *Cursor, len: usize) Error![]const u8 {
        const end = try checkedAdd(self.pos, len);
        if (end > self.data.len) return error.EndOfInput;
        defer self.pos = end;
        return self.data[self.pos..end];
    }

    pub fn sliceAt(self: Cursor, start: usize, len: usize) Error![]const u8 {
        const end = try checkedAdd(start, len);
        if (end > self.data.len) return error.EndOfInput;
        return self.data[start..end];
    }

    pub fn readInt(
        self: *Cursor,
        comptime T: type,
        endian: std.builtin.Endian,
    ) Error!T {
        validateIntegerType(T);
        const bytes = try self.readBytes(@sizeOf(T));
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], endian);
    }

    pub fn intAt(
        self: Cursor,
        comptime T: type,
        start: usize,
        endian: std.builtin.Endian,
    ) Error!T {
        validateIntegerType(T);
        const bytes = try self.sliceAt(start, @sizeOf(T));
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], endian);
    }

    fn validateIntegerType(comptime T: type) void {
        switch (@typeInfo(T)) {
            .int => |info| {
                if (info.signedness != .unsigned or info.bits % 8 != 0) {
                    @compileError("Cursor.readInt supports byte-aligned unsigned integers");
                }
            },
            else => @compileError("Cursor.readInt expects an integer type"),
        }
    }
};

pub fn checkedAdd(a: usize, b: usize) Cursor.Error!usize {
    const result = @addWithOverflow(a, b);
    if (result[1] != 0) return error.IntegerOverflow;
    return result[0];
}

pub fn u64ToUsize(value: u64) Cursor.Error!usize {
    if (value > std.math.maxInt(usize)) return error.IntegerOverflow;
    return @intCast(value);
}

test "cursor reads little-endian integers and borrowed slices" {
    var cursor = Cursor.init(&.{ 0x34, 0x12, 0xaa, 0xbb });

    try std.testing.expectEqual(@as(u16, 0x1234), try cursor.readInt(u16, .little));
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, try cursor.readBytes(2));
    try std.testing.expect(cursor.atEnd());
    try std.testing.expectEqual(@as(u8, 0x12), try Cursor.init(cursor.data).intAt(u8, 1, .little));
}

test "cursor rejects out-of-range and overflowing spans" {
    var cursor = Cursor.init("abc");
    try cursor.seekTo(3);
    try std.testing.expectError(error.EndOfInput, cursor.readByte());
    try std.testing.expectError(error.EndOfInput, cursor.seekTo(4));
    try std.testing.expectError(error.EndOfInput, Cursor.init("abc").sliceAt(2, 2));
    try std.testing.expectError(error.IntegerOverflow, checkedAdd(std.math.maxInt(usize), 1));
}
