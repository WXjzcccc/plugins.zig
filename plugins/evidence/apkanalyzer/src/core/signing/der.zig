const std = @import("std");

pub const TagClass = enum(u2) {
    universal = 0,
    application = 1,
    context_specific = 2,
    private = 3,
};

pub const UniversalTag = enum(u32) {
    boolean = 1,
    integer = 2,
    bit_string = 3,
    octet_string = 4,
    null = 5,
    object_identifier = 6,
    utf8_string = 12,
    sequence = 16,
    set = 17,
    numeric_string = 18,
    printable_string = 19,
    teletex_string = 20,
    ia5_string = 22,
    utc_time = 23,
    generalized_time = 24,
    universal_string = 28,
    bmp_string = 30,
    _,
};

pub const Error = error{
    Truncated,
    IndefiniteLengthUnsupported,
    NonCanonicalLength,
    LengthOverflow,
    InvalidHighTag,
    NonCanonicalHighTag,
    InvalidObjectIdentifier,
    InvalidString,
    UnexpectedTag,
    TrailingData,
};

pub const Element = struct {
    class: TagClass,
    constructed: bool,
    tag_number: u32,
    encoded: []const u8,
    content: []const u8,
    header_len: usize,

    pub fn universalTag(self: Element) ?UniversalTag {
        if (self.class != .universal) return null;
        return @fromBackingInt(@intCast(self.tag_number));
    }

    pub fn children(self: Element) Reader {
        return .{ .data = self.content };
    }

    pub fn expectUniversal(self: Element, tag: UniversalTag, constructed: bool) Error!void {
        if (self.class != .universal or
            self.tag_number != @backingInt(tag) or
            self.constructed != constructed)
        {
            return error.UnexpectedTag;
        }
    }
};

pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn remaining(self: Reader) usize {
        return self.data.len - self.pos;
    }

    pub fn atEnd(self: Reader) bool {
        return self.pos == self.data.len;
    }

    pub fn next(self: *Reader) Error!?Element {
        if (self.atEnd()) return null;
        const start = self.pos;

        const first = try self.readByte();
        const class: TagClass = @fromBackingInt(@intCast(@as(u2, @truncate(first >> 6))));
        const constructed = (first & 0x20) != 0;
        var tag_number: u32 = first & 0x1f;
        if (tag_number == 0x1f) {
            tag_number = 0;
            var first_group = true;
            while (true) {
                const group = try self.readByte();
                if (first_group and (group & 0x7f) == 0) return error.NonCanonicalHighTag;
                first_group = false;
                if (tag_number > (std.math.maxInt(u32) >> 7)) return error.InvalidHighTag;
                tag_number = (tag_number << 7) | (group & 0x7f);
                if ((group & 0x80) == 0) break;
            }
            if (tag_number < 31) return error.NonCanonicalHighTag;
        }

        const first_length = try self.readByte();
        const content_len: usize = if ((first_length & 0x80) == 0)
            first_length
        else length: {
            const count: usize = first_length & 0x7f;
            if (count == 0) return error.IndefiniteLengthUnsupported;
            if (count > @sizeOf(usize)) return error.LengthOverflow;
            if (self.remaining() < count) return error.Truncated;
            if (self.data[self.pos] == 0) return error.NonCanonicalLength;

            var value: usize = 0;
            for (0..count) |_| {
                const byte = try self.readByte();
                if (value > (std.math.maxInt(usize) >> 8)) return error.LengthOverflow;
                value = (value << 8) | byte;
            }
            if (value < 128) return error.NonCanonicalLength;
            break :length value;
        };

        if (content_len > self.remaining()) return error.Truncated;
        const content_start = self.pos;
        self.pos += content_len;
        return .{
            .class = class,
            .constructed = constructed,
            .tag_number = tag_number,
            .encoded = self.data[start..self.pos],
            .content = self.data[content_start..self.pos],
            .header_len = content_start - start,
        };
    }

    pub fn requireNext(self: *Reader) Error!Element {
        return (try self.next()) orelse error.Truncated;
    }

    pub fn requireEnd(self: Reader) Error!void {
        if (!self.atEnd()) return error.TrailingData;
    }

    fn readByte(self: *Reader) Error!u8 {
        if (self.pos >= self.data.len) return error.Truncated;
        defer self.pos += 1;
        return self.data[self.pos];
    }
};

pub fn parseSingle(data: []const u8) Error!Element {
    var reader: Reader = .{ .data = data };
    const element = try reader.requireNext();
    try reader.requireEnd();
    return element;
}

pub fn decodeOidAlloc(allocator: std.mem.Allocator, content: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    if (content.len == 0) return error.InvalidObjectIdentifier;

    var subidentifiers: std.ArrayList(u64) = .empty;
    defer subidentifiers.deinit(allocator);
    var value: u64 = 0;
    var in_component = false;
    for (content) |byte| {
        if (value > (std.math.maxInt(u64) >> 7)) return error.InvalidObjectIdentifier;
        value = (value << 7) | (byte & 0x7f);
        in_component = true;
        if ((byte & 0x80) == 0) {
            try subidentifiers.append(allocator, value);
            value = 0;
            in_component = false;
        }
    }
    if (in_component or subidentifiers.items.len == 0) return error.InvalidObjectIdentifier;

    const first_value = subidentifiers.items[0];
    const first_arc: u64 = if (first_value < 40) 0 else if (first_value < 80) 1 else 2;
    const second_arc = first_value - first_arc * 40;

    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    output.writer.print("{d}.{d}", .{ first_arc, second_arc }) catch return error.OutOfMemory;
    for (subidentifiers.items[1..]) |arc| {
        output.writer.print(".{d}", .{arc}) catch return error.OutOfMemory;
    }
    return output.toOwnedSlice();
}

pub fn decodeStringAlloc(allocator: std.mem.Allocator, element: Element) (Error || std.mem.Allocator.Error)![]u8 {
    if (element.class != .universal or element.constructed) return error.UnexpectedTag;
    const tag: UniversalTag = @fromBackingInt(@intCast(element.tag_number));
    return switch (tag) {
        .utf8_string, .printable_string, .teletex_string, .ia5_string, .numeric_string, .utc_time, .generalized_time => try allocator.dupe(u8, element.content),
        .bmp_string => decodeBmpStringAlloc(allocator, element.content),
        .universal_string => decodeUniversalStringAlloc(allocator, element.content),
        else => error.UnexpectedTag,
    };
}

pub fn integerHexAlloc(allocator: std.mem.Allocator, content: []const u8) std.mem.Allocator.Error![]u8 {
    var bytes = content;
    while (bytes.len > 1 and bytes[0] == 0) bytes = bytes[1..];
    if (bytes.len == 0) return allocator.dupe(u8, "00");

    const output = try allocator.alloc(u8, bytes.len * 2);
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output;
}

fn decodeBmpStringAlloc(allocator: std.mem.Allocator, content: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    if (content.len % 2 != 0) return error.InvalidString;
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();

    var index: usize = 0;
    while (index < content.len) {
        const first = std.mem.readInt(u16, content[index..][0..2], .big);
        index += 2;
        const codepoint: u21 = if (first >= 0xd800 and first <= 0xdbff) codepoint: {
            if (index >= content.len) return error.InvalidString;
            const second = std.mem.readInt(u16, content[index..][0..2], .big);
            index += 2;
            if (second < 0xdc00 or second > 0xdfff) return error.InvalidString;
            break :codepoint @intCast(0x10000 +
                ((@as(u32, first) - 0xd800) << 10) +
                (@as(u32, second) - 0xdc00));
        } else if (first >= 0xdc00 and first <= 0xdfff) {
            return error.InvalidString;
        } else @intCast(first);
        try appendCodepoint(&output.writer, codepoint);
    }
    return output.toOwnedSlice();
}

fn decodeUniversalStringAlloc(allocator: std.mem.Allocator, content: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    if (content.len % 4 != 0) return error.InvalidString;
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var index: usize = 0;
    while (index < content.len) : (index += 4) {
        const raw = std.mem.readInt(u32, content[index..][0..4], .big);
        if (raw > 0x10ffff or (raw >= 0xd800 and raw <= 0xdfff)) return error.InvalidString;
        try appendCodepoint(&output.writer, @intCast(raw));
    }
    return output.toOwnedSlice();
}

fn appendCodepoint(writer: *std.Io.Writer, codepoint: u21) (Error || std.mem.Allocator.Error)!void {
    var buffer: [4]u8 = undefined;
    const len = std.unicode.utf8Encode(codepoint, &buffer) catch return error.InvalidString;
    writer.writeAll(buffer[0..len]) catch return error.OutOfMemory;
}

test "DER reader parses a sequence and rejects non-canonical length" {
    const sequence = try parseSingle(&.{ 0x30, 0x03, 0x02, 0x01, 0x05 });
    try sequence.expectUniversal(.sequence, true);
    var children = sequence.children();
    const integer = try children.requireNext();
    try integer.expectUniversal(.integer, false);
    try std.testing.expectEqualSlices(u8, &.{0x05}, integer.content);
    try children.requireEnd();

    try std.testing.expectError(error.NonCanonicalLength, parseSingle(&.{ 0x04, 0x81, 0x01, 0x00 }));
}

test "OID decoder supports a multi-byte first subidentifier" {
    const oid = try decodeOidAlloc(std.testing.allocator, &.{ 0x88, 0x37, 0x03 });
    defer std.testing.allocator.free(oid);
    try std.testing.expectEqualStrings("2.999.3", oid);
}

test "BMPString decoder handles surrogate pairs" {
    const element: Element = .{
        .class = .universal,
        .constructed = false,
        .tag_number = @backingInt(UniversalTag.bmp_string),
        .encoded = &.{},
        .content = &.{ 0x00, 0x41, 0xd8, 0x3d, 0xde, 0x00 },
        .header_len = 0,
    };
    const decoded = try decodeStringAlloc(std.testing.allocator, element);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("A😀", decoded);
}
