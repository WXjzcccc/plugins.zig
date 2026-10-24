const std = @import("std");
const cursor_mod = @import("cursor.zig");

pub const Cursor = cursor_mod.Cursor;

pub const header_size = 8;

/// Android resource chunk type identifiers from `ResourceTypes.h`.
pub const Type = struct {
    pub const null_type: u16 = 0x0000;
    pub const string_pool: u16 = 0x0001;
    pub const table: u16 = 0x0002;
    pub const xml: u16 = 0x0003;

    pub const xml_start_namespace: u16 = 0x0100;
    pub const xml_end_namespace: u16 = 0x0101;
    pub const xml_start_element: u16 = 0x0102;
    pub const xml_end_element: u16 = 0x0103;
    pub const xml_cdata: u16 = 0x0104;
    pub const xml_resource_map: u16 = 0x0180;
};

pub const Error = Cursor.Error || error{
    InvalidHeaderSize,
    InvalidChunkSize,
    TrailingData,
};

pub const Header = struct {
    type_id: u16,
    size: u32,
    header_bytes: u16,
};

/// A validated view over one complete resource chunk.
///
/// The byte slices borrow the input passed to `read`/`parse`; no allocation is
/// performed. `header_bytes` and `size` have already been checked against each
/// other and the input bounds.
pub const Chunk = struct {
    header: Header,
    bytes: []const u8,
    offset: usize,

    pub fn extraHeader(self: Chunk) []const u8 {
        return self.bytes[header_size..self.header.header_bytes];
    }

    pub fn body(self: Chunk) []const u8 {
        return self.bytes[self.header.header_bytes..];
    }

    pub fn childIterator(self: Chunk) Iterator {
        return .init(self.body());
    }
};

/// Reads one chunk transactionally. On failure, `cursor` is not advanced.
pub fn read(cursor: *Cursor) Error!Chunk {
    var candidate = cursor.*;
    const start = candidate.offset();

    const type_id = try candidate.readInt(u16, .little);
    const header_bytes = try candidate.readInt(u16, .little);
    const size = try candidate.readInt(u32, .little);

    if (header_bytes < header_size) return error.InvalidHeaderSize;
    if (size < header_bytes) return error.InvalidChunkSize;

    try candidate.seekTo(start);
    const bytes = try candidate.readBytes(@as(usize, size));
    cursor.* = candidate;

    return .{
        .header = .{
            .type_id = type_id,
            .size = size,
            .header_bytes = header_bytes,
        },
        .bytes = bytes,
        .offset = start,
    };
}

/// Parses exactly one chunk and rejects unclaimed trailing bytes.
pub fn parse(data: []const u8) Error!Chunk {
    var cursor = Cursor.init(data);
    const result = try read(&cursor);
    if (!cursor.atEnd()) return error.TrailingData;
    return result;
}

pub const Iterator = struct {
    cursor: Cursor,

    pub fn init(data: []const u8) Iterator {
        return .{ .cursor = .init(data) };
    }

    pub fn next(self: *Iterator) Error!?Chunk {
        if (self.cursor.atEnd()) return null;
        return try read(&self.cursor);
    }
};

test "chunk parser exposes validated header and body" {
    const bytes = [_]u8{
        0x03, 0x00, // RES_XML_TYPE
        0x0c, 0x00, // extended header size
        0x10, 0x00, 0x00, 0x00, // total size
        0xaa, 0xbb, 0xcc, 0xdd, // extended header
        0x11, 0x22, 0x33, 0x44, // body
    };

    const result = try parse(&bytes);
    try std.testing.expectEqual(Type.xml, result.header.type_id);
    try std.testing.expectEqual(@as(u32, bytes.len), result.header.size);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, result.extraHeader());
    try std.testing.expectEqualSlices(u8, &.{ 0x11, 0x22, 0x33, 0x44 }, result.body());
}

test "chunk parser is bounds safe and transactional" {
    const too_short_header = [_]u8{ 1, 0, 7, 0, 8, 0, 0, 0 };
    try std.testing.expectError(error.InvalidHeaderSize, parse(&too_short_header));

    const header_larger_than_chunk = [_]u8{ 1, 0, 12, 0, 8, 0, 0, 0 };
    try std.testing.expectError(error.InvalidChunkSize, parse(&header_larger_than_chunk));

    const truncated = [_]u8{ 1, 0, 8, 0, 12, 0, 0, 0 };
    var cursor = Cursor.init(&truncated);
    try std.testing.expectError(error.EndOfInput, read(&cursor));
    try std.testing.expectEqual(@as(usize, 0), cursor.offset());
}

test "chunk iterator cannot loop on a zero-sized child" {
    const children = [_]u8{
        1, 0, 8, 0, 8, 0, 0, 0,
        2, 0, 8, 0, 8, 0, 0, 0,
    };
    var iterator = Iterator.init(&children);
    try std.testing.expectEqual(@as(u16, 1), (try iterator.next()).?.header.type_id);
    try std.testing.expectEqual(@as(u16, 2), (try iterator.next()).?.header.type_id);
    try std.testing.expect((try iterator.next()) == null);
}
