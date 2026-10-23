const std = @import("std");
const chunk = @import("chunk.zig");
const cursor_mod = @import("../../utils/io/cursor.zig");
const logging = @import("../../utils/logging.zig");

const Cursor = cursor_mod.Cursor;

pub const sorted_flag: u32 = 1 << 0;
pub const utf8_flag: u32 = 1 << 8;
pub const no_index: u32 = 0xffff_ffff;
pub const pool_header_size = 28;

pub const LookupError = error{InvalidStringIndex};

pub const Error = Cursor.Error || std.mem.Allocator.Error || error{
    WrongChunkType,
    InvalidStringPoolHeader,
    InvalidIndexSection,
    InvalidStringData,
    InvalidStyleData,
    InvalidUtf8,
    InvalidUtf16,
    StringLengthMismatch,
    MissingStringTerminator,
};

/// An owning, UTF-8 decoded representation of Android's `ResStringPool`.
pub const StringPool = struct {
    flags: u32,
    strings: []const []const u8,
    /// Raw offsets into the style-data section. `no_index` means unstyled.
    style_offsets: []const u32,

    pub fn isUtf8(self: StringPool) bool {
        return self.flags & utf8_flag != 0;
    }

    pub fn isSorted(self: StringPool) bool {
        return self.flags & sorted_flag != 0;
    }

    pub fn get(self: StringPool, index: u32) LookupError![]const u8 {
        const resolved: usize = @intCast(index);
        if (resolved >= self.strings.len) return error.InvalidStringIndex;
        return self.strings[resolved];
    }

    pub fn getOptional(self: StringPool, index: u32) LookupError!?[]const u8 {
        if (index == no_index) return null;
        return try self.get(index);
    }

    pub fn deinit(self: *StringPool, allocator: std.mem.Allocator) void {
        for (self.strings) |string| allocator.free(string);
        allocator.free(self.strings);
        allocator.free(self.style_offsets);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, source: chunk.Chunk) Error!StringPool {
        logging.debug(.apk_android_strings, @src(), "string pool parsing started offset={d} bytes={d}", .{
            source.offset,
            source.bytes.len,
        });
        const pool = parseImpl(allocator, source) catch |err| {
            logging.err(.apk_android_strings, @src(), "string pool parsing failed offset={d} error={s}", .{
                source.offset,
                @errorName(err),
            });
            return err;
        };
        logging.debug(.apk_android_strings, @src(), "string pool parsed strings={d} styles={d} encoding={s}", .{
            pool.strings.len,
            pool.style_offsets.len,
            if (pool.isUtf8()) "utf8" else "utf16",
        });
        return pool;
    }

    fn parseImpl(allocator: std.mem.Allocator, source: chunk.Chunk) Error!StringPool {
        if (source.header.type_id != chunk.Type.string_pool) return error.WrongChunkType;
        if (source.header.header_bytes < pool_header_size) return error.InvalidStringPoolHeader;

        var header = Cursor.init(source.bytes);
        try header.seekTo(chunk.header_size);
        const string_count = try u32ToUsize(try header.readInt(u32, .little));
        const style_count = try u32ToUsize(try header.readInt(u32, .little));
        const flags = try header.readInt(u32, .little);
        const strings_start = try u32ToUsize(try header.readInt(u32, .little));
        const styles_start = try u32ToUsize(try header.readInt(u32, .little));

        const index_count = try checkedAdd(string_count, style_count);
        const index_bytes = try checkedMul(index_count, @sizeOf(u32));
        const indices_start: usize = source.header.header_bytes;
        const indices_end = try checkedAdd(indices_start, index_bytes);
        if (indices_end > source.bytes.len) return error.InvalidIndexSection;

        if (string_count != 0 and strings_start == 0) return error.InvalidStringData;
        if (strings_start != 0 and (strings_start < indices_end or strings_start > source.bytes.len)) {
            return error.InvalidStringData;
        }
        if (style_count != 0 and styles_start == 0) return error.InvalidStyleData;
        if (styles_start != 0 and (styles_start < indices_end or styles_start > source.bytes.len)) {
            return error.InvalidStyleData;
        }
        if (strings_start != 0 and styles_start != 0 and styles_start < strings_start) {
            return error.InvalidStyleData;
        }

        const string_data_start = if (strings_start == 0) source.bytes.len else strings_start;
        const string_data_end = if (styles_start == 0) source.bytes.len else styles_start;
        if (string_data_end < string_data_start) return error.InvalidStringData;
        const string_data = source.bytes[string_data_start..string_data_end];

        var strings = try allocator.alloc([]const u8, string_count);
        var initialized: usize = 0;
        errdefer {
            for (strings[0..initialized]) |string| allocator.free(string);
            allocator.free(strings);
        }

        var normalized_utf8_sequences: usize = 0;
        for (strings, 0..) |*destination, index| {
            const offset_position = try checkedAdd(indices_start, try checkedMul(index, @sizeOf(u32)));
            const relative_offset = try u32ToUsize(try Cursor.init(source.bytes).intAt(u32, offset_position, .little));
            if (relative_offset >= string_data.len) return error.InvalidStringData;

            if (flags & utf8_flag != 0) {
                const decoded = try decodeUtf8(allocator, string_data, relative_offset);
                destination.* = decoded.value;
                normalized_utf8_sequences += decoded.normalized_sequences;
            } else {
                destination.* = try decodeUtf16(allocator, string_data, relative_offset);
            }
            initialized += 1;
        }

        if (normalized_utf8_sequences != 0) {
            logging.warn(.apk_android_strings, @src(), "string pool normalized Android modified UTF-8 sequences offset={d} count={d}", .{
                source.offset,
                normalized_utf8_sequences,
            });
        }

        const style_offsets = try allocator.alloc(u32, style_count);
        errdefer allocator.free(style_offsets);
        const style_indices_start = try checkedAdd(indices_start, try checkedMul(string_count, @sizeOf(u32)));
        const style_data_len = if (styles_start == 0) 0 else source.bytes.len - styles_start;

        for (style_offsets, 0..) |*destination, index| {
            const offset_position = try checkedAdd(style_indices_start, try checkedMul(index, @sizeOf(u32)));
            const relative_offset = try Cursor.init(source.bytes).intAt(u32, offset_position, .little);
            if (relative_offset != no_index and @as(usize, relative_offset) >= style_data_len) {
                return error.InvalidStyleData;
            }
            destination.* = relative_offset;
        }

        return .{
            .flags = flags,
            .strings = strings,
            .style_offsets = style_offsets,
        };
    }
};

const DecodedUtf8 = struct {
    value: []const u8,
    normalized_sequences: usize,
};

const ModifiedCodepoint = struct {
    value: u21,
    utf16_units: usize,
    normalized: bool = false,
};

fn decodeUtf8(allocator: std.mem.Allocator, data: []const u8, offset: usize) Error!DecodedUtf8 {
    var cursor = Cursor.init(data);
    try cursor.seekTo(offset);

    const declared_utf16_units = try readLength8(&cursor);
    const byte_length = try readLength8(&cursor);
    const bytes = try cursor.readBytes(byte_length);
    if (try cursor.readByte() != 0) return error.MissingStringTerminator;

    var index: usize = 0;
    var output_length: usize = 0;
    var utf16_units: usize = 0;
    var normalized_sequences: usize = 0;
    while (index < bytes.len) {
        const decoded = nextModifiedUtf8Codepoint(bytes, &index);
        output_length = try checkedAdd(output_length, std.unicode.utf8CodepointSequenceLength(decoded.value) catch return error.InvalidUtf8);
        utf16_units = try checkedAdd(utf16_units, decoded.utf16_units);
        if (decoded.normalized) normalized_sequences += 1;
    }
    if (utf16_units != declared_utf16_units) normalized_sequences += 1;

    const output = try allocator.alloc(u8, output_length);
    errdefer allocator.free(output);
    index = 0;
    var output_offset: usize = 0;
    while (index < bytes.len) {
        const decoded = nextModifiedUtf8Codepoint(bytes, &index);
        output_offset += std.unicode.utf8Encode(decoded.value, output[output_offset..]) catch return error.InvalidUtf8;
    }
    return .{
        .value = output,
        .normalized_sequences = normalized_sequences,
    };
}

fn decodeUtf16(allocator: std.mem.Allocator, data: []const u8, offset: usize) Error![]const u8 {
    var cursor = Cursor.init(data);
    try cursor.seekTo(offset);

    const unit_count = try readLength16(&cursor);
    const unit_bytes = try checkedMul(unit_count, @sizeOf(u16));
    const encoded = try cursor.readBytes(unit_bytes);
    if (try cursor.readInt(u16, .little) != 0) return error.MissingStringTerminator;

    var scan: usize = 0;
    var output_length: usize = 0;
    while (scan < unit_count) {
        const codepoint = try nextUtf16Codepoint(encoded, &scan);
        const codepoint_bytes = std.unicode.utf8CodepointSequenceLength(codepoint) catch return error.InvalidUtf16;
        output_length = try checkedAdd(output_length, codepoint_bytes);
    }

    const output = try allocator.alloc(u8, output_length);
    errdefer allocator.free(output);
    scan = 0;
    var output_offset: usize = 0;
    while (scan < unit_count) {
        const codepoint = try nextUtf16Codepoint(encoded, &scan);
        const written = std.unicode.utf8Encode(codepoint, output[output_offset..]) catch return error.InvalidUtf16;
        output_offset += written;
    }
    return output;
}

fn readLength8(cursor: *Cursor) Cursor.Error!usize {
    const first = try cursor.readByte();
    if (first & 0x80 == 0) return first;
    const second = try cursor.readByte();
    return (@as(usize, first & 0x7f) << 8) | second;
}

fn readLength16(cursor: *Cursor) Cursor.Error!usize {
    const first = try cursor.readInt(u16, .little);
    if (first & 0x8000 == 0) return first;
    const second = try cursor.readInt(u16, .little);
    return (@as(usize, first & 0x7fff) << 16) | second;
}

fn nextModifiedUtf8Codepoint(bytes: []const u8, index: *usize) ModifiedCodepoint {
    const first = bytes[index.*];
    index.* += 1;
    if (first < 0x80) return .{ .value = first, .utf16_units = 1 };

    if (first == 0xc0 and hasContinuation(bytes, index.*, 1) and bytes[index.*] == 0x80) {
        index.* += 1;
        return .{ .value = 0, .utf16_units = 1, .normalized = true };
    }

    if (first >= 0xc2 and first <= 0xdf and hasContinuation(bytes, index.*, 1)) {
        const value = (@as(u21, first & 0x1f) << 6) | (bytes[index.*] & 0x3f);
        index.* += 1;
        return .{ .value = value, .utf16_units = 1 };
    }

    if (first >= 0xe0 and first <= 0xef and hasContinuation(bytes, index.*, 2)) {
        const value = (@as(u21, first & 0x0f) << 12) |
            (@as(u21, bytes[index.*] & 0x3f) << 6) |
            (bytes[index.* + 1] & 0x3f);
        index.* += 2;
        if (value < 0x800) return .{ .value = 0xfffd, .utf16_units = 1, .normalized = true };
        if (value >= 0xd800 and value <= 0xdbff) {
            if (index.* + 2 < bytes.len and bytes[index.*] == 0xed and
                bytes[index.* + 1] >= 0xb0 and bytes[index.* + 1] <= 0xbf and
                bytes[index.* + 2] >= 0x80 and bytes[index.* + 2] <= 0xbf)
            {
                const low: u21 = 0xd000 |
                    (@as(u21, bytes[index.* + 1] & 0x3f) << 6) |
                    (bytes[index.* + 2] & 0x3f);
                index.* += 3;
                return .{
                    .value = 0x10000 + ((value - 0xd800) << 10) + (low - 0xdc00),
                    .utf16_units = 2,
                    .normalized = true,
                };
            }
            return .{ .value = 0xfffd, .utf16_units = 1, .normalized = true };
        }
        if (value >= 0xdc00 and value <= 0xdfff) {
            return .{ .value = 0xfffd, .utf16_units = 1, .normalized = true };
        }
        return .{ .value = value, .utf16_units = 1 };
    }

    if (first >= 0xf0 and first <= 0xf4 and hasContinuation(bytes, index.*, 3)) {
        const value = (@as(u21, first & 0x07) << 18) |
            (@as(u21, bytes[index.*] & 0x3f) << 12) |
            (@as(u21, bytes[index.* + 1] & 0x3f) << 6) |
            (bytes[index.* + 2] & 0x3f);
        index.* += 3;
        if (value >= 0x10000 and value <= 0x10ffff) return .{ .value = value, .utf16_units = 2 };
    }

    return .{ .value = 0xfffd, .utf16_units = 1, .normalized = true };
}

fn hasContinuation(bytes: []const u8, index: usize, count: usize) bool {
    if (index + count > bytes.len) return false;
    for (bytes[index .. index + count]) |byte| if (byte & 0xc0 != 0x80) return false;
    return true;
}

fn nextUtf16Codepoint(encoded: []const u8, unit_index: *usize) Error!u21 {
    const byte_index = try checkedMul(unit_index.*, @sizeOf(u16));
    const first = try Cursor.init(encoded).intAt(u16, byte_index, .little);
    unit_index.* += 1;

    if (first >= 0xd800 and first <= 0xdbff) {
        if (unit_index.* >= encoded.len / @sizeOf(u16)) return error.InvalidUtf16;
        const second_byte_index = try checkedMul(unit_index.*, @sizeOf(u16));
        const second = try Cursor.init(encoded).intAt(u16, second_byte_index, .little);
        if (second < 0xdc00 or second > 0xdfff) return error.InvalidUtf16;
        unit_index.* += 1;
        return 0x10000 + (@as(u21, first - 0xd800) << 10) + @as(u21, second - 0xdc00);
    }
    if (first >= 0xdc00 and first <= 0xdfff) return error.InvalidUtf16;
    return @as(u21, first);
}

fn checkedAdd(a: usize, b: usize) Cursor.Error!usize {
    return cursor_mod.checkedAdd(a, b);
}

fn checkedMul(a: usize, b: usize) Cursor.Error!usize {
    const result = @mulWithOverflow(a, b);
    if (result[1] != 0) return error.IntegerOverflow;
    return result[0];
}

fn u32ToUsize(value: u32) Cursor.Error!usize {
    // This remains explicit so the parser is also correct on 16-bit targets.
    if (value > std.math.maxInt(usize)) return error.IntegerOverflow;
    return @intCast(value);
}

test "UTF-8 string pool decodes ASCII and multibyte strings" {
    const bytes = [_]u8{
        0x01, 0x00, 0x1c, 0x00, 0x38, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, // string count
        0x00, 0x00, 0x00, 0x00, // style count
        0x00, 0x01, 0x00, 0x00, // UTF-8 flag
        0x24, 0x00, 0x00, 0x00, // strings start
        0x00, 0x00, 0x00, 0x00, // styles start
        0x00, 0x00, 0x00, 0x00, // offset 0
        0x0b, 0x00, 0x00, 0x00, // offset 11
        0x08, 0x08, 'm',  'a',
        'n',  'i',  'f',  'e',
        's',  't',  0,    0x02,
        0x06, 0xe5, 0xba, 0x94,
        0xe7, 0x94, 0xa8, 0,
    };

    var pool = try StringPool.parse(std.testing.allocator, try chunk.parse(&bytes));
    defer pool.deinit(std.testing.allocator);
    try std.testing.expect(pool.isUtf8());
    try std.testing.expectEqualStrings("manifest", try pool.get(0));
    try std.testing.expectEqualStrings("应用", try pool.get(1));
    try std.testing.expect((try pool.getOptional(no_index)) == null);
    try std.testing.expectError(error.InvalidStringIndex, pool.get(2));
}

test "UTF-16 string pool decodes surrogate pairs" {
    const bytes = [_]u8{
        0x01, 0x00, 0x1c, 0x00, 0x2c, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, // string count
        0x00, 0x00, 0x00, 0x00, // style count
        0x00, 0x00, 0x00, 0x00, // UTF-16
        0x20, 0x00, 0x00, 0x00, // strings start
        0x00, 0x00, 0x00, 0x00, // styles start
        0x00, 0x00, 0x00, 0x00, // offset
        0x03, 0x00, // three UTF-16 code units
        0x41, 0x00, // A
        0x3d, 0xd8, 0x00, 0xde, // U+1F600
        0x00, 0x00, // terminator
        0x00, 0x00, // alignment padding
    };

    var pool = try StringPool.parse(std.testing.allocator, try chunk.parse(&bytes));
    defer pool.deinit(std.testing.allocator);
    try std.testing.expect(!pool.isUtf8());
    try std.testing.expectEqualStrings("A😀", try pool.get(0));
}

test "UTF-8 string pool accepts Android modified UTF-8" {
    const encoded = [_]u8{ 0x02, 0x06, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80, 0 };
    const decoded = try decodeUtf8(std.testing.allocator, &encoded, 0);
    defer std.testing.allocator.free(decoded.value);
    try std.testing.expectEqualStrings("😀", decoded.value);
    try std.testing.expectEqual(@as(usize, 1), decoded.normalized_sequences);
}

test "string pool rejects invalid offsets and missing terminators" {
    const bad_offset = [_]u8{
        1, 0, 28, 0, 36, 0, 0, 0,
        1, 0, 0,  0, 0,  0, 0, 0,
        0, 1, 0,  0, 32, 0, 0, 0,
        0, 0, 0,  0, 8,  0, 0, 0,
        0, 0, 0,  0,
    };
    try std.testing.expectError(
        error.InvalidStringData,
        StringPool.parse(std.testing.allocator, try chunk.parse(&bad_offset)),
    );

    const missing_terminator = [_]u8{
        1, 0, 28,  0, 36, 0, 0, 0,
        1, 0, 0,   0, 0,  0, 0, 0,
        0, 1, 0,   0, 32, 0, 0, 0,
        0, 0, 0,   0, 0,  0, 0, 0,
        1, 1, 'x', 1,
    };
    try std.testing.expectError(
        error.MissingStringTerminator,
        StringPool.parse(std.testing.allocator, try chunk.parse(&missing_terminator)),
    );
}
