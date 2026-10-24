//! Test-only ABX writer: builds byte-exact ABX documents for parser tests.
//! Not compiled into the plugin library — only test binaries import this.

const std = @import("std");

pub const magic = [_]u8{ 0x41, 0x42, 0x58, 0x00 };

pub const Writer = struct {
    out: std.ArrayList(u8) = .empty,
    dict: std.ArrayList([]const u8) = .empty,

    pub fn deinit(self: *Writer) void {
        self.out.deinit(std.testing.allocator);
        self.dict.deinit(std.testing.allocator);
    }

    pub fn byte(self: *Writer, value: u8) !void {
        try self.out.append(std.testing.allocator, value);
    }

    fn writeU16(self: *Writer, value: u16) !void {
        try self.out.append(std.testing.allocator, @intCast(value >> 8));
        try self.out.append(std.testing.allocator, @intCast(value & 0xff));
    }

    pub fn utf(self: *Writer, value: []const u8) !void {
        try self.writeU16(@intCast(value.len));
        try self.out.appendSlice(std.testing.allocator, value);
    }

    /// Interned write: a 0xFFFF definition on first sight, else the index.
    fn interned(self: *Writer, value: []const u8) !void {
        for (self.dict.items, 0..) |known, index| {
            if (std.mem.eql(u8, known, value)) {
                try self.writeU16(@intCast(index));
                return;
            }
        }
        try self.writeU16(0xffff);
        try self.utf(value);
        try self.dict.append(std.testing.allocator, value);
    }

    pub fn document(self: *Writer) !void {
        try self.byte(0x00 | 0x10);
    }

    pub fn startTag(self: *Writer, name: []const u8) !void {
        try self.byte(2 | 0x30);
        try self.interned(name);
    }

    pub fn endTag(self: *Writer, name: []const u8) !void {
        try self.byte(3 | 0x30);
        try self.interned(name);
    }

    pub fn attrInt(self: *Writer, name: []const u8, value: i32) !void {
        try self.byte(15 | 0x60);
        try self.interned(name);
        var raw: [4]u8 = undefined;
        std.mem.writeInt(u32, &raw, @bitCast(value), .big);
        try self.out.appendSlice(std.testing.allocator, &raw);
    }

    pub fn attrLong(self: *Writer, name: []const u8, value: i64) !void {
        try self.byte(15 | 0x80);
        try self.interned(name);
        var raw: [8]u8 = undefined;
        std.mem.writeInt(u64, &raw, @bitCast(value), .big);
        try self.out.appendSlice(std.testing.allocator, &raw);
    }

    pub fn attrLongHex(self: *Writer, name: []const u8, value: i64) !void {
        try self.byte(15 | 0x90);
        try self.interned(name);
        var raw: [8]u8 = undefined;
        std.mem.writeInt(u64, &raw, @bitCast(value), .big);
        try self.out.appendSlice(std.testing.allocator, &raw);
    }

    pub fn attrBool(self: *Writer, name: []const u8, value: bool) !void {
        try self.byte(15 | (if (value) @as(u8, 0xC0) else 0xD0));
        try self.interned(name);
    }

    pub fn attrString(self: *Writer, name: []const u8, value: []const u8) !void {
        try self.byte(15 | 0x20);
        try self.interned(name);
        try self.utf(value);
    }

    pub fn attrInterned(self: *Writer, name: []const u8, value: []const u8) !void {
        try self.byte(15 | 0x30);
        try self.interned(name);
        try self.interned(value);
    }

    pub fn text(self: *Writer, value: []const u8) !void {
        try self.byte(4 | 0x20);
        try self.utf(value);
    }
};
