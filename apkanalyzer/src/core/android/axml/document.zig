const std = @import("std");
const chunk = @import("../chunk.zig");
const string_pool = @import("../string_pool.zig");
const typed_value = @import("../typed_value.zig");
const cursor_mod = @import("../../../utils/io/cursor.zig");
const logging = @import("../../../utils/logging.zig");

const Cursor = cursor_mod.Cursor;

pub const ParseError = chunk.Error || string_pool.Error || typed_value.Error || error{
    WrongRootChunkType,
    MissingStringPool,
    DuplicateStringPool,
    DuplicateResourceMap,
    InvalidResourceMap,
    InvalidNodeHeader,
    InvalidNodeExtension,
    InvalidAttributeLayout,
    InvalidSpecialAttributeIndex,
    InvalidStringIndex,
};

pub const Node = struct {
    line_number: u32,
    comment: ?[]const u8,
};

pub const NamespaceEvent = struct {
    node: Node,
    prefix: ?[]const u8,
    uri: []const u8,
    prefix_index: u32,
    uri_index: u32,
};

pub const Attribute = struct {
    namespace_uri: ?[]const u8,
    name: []const u8,
    raw_value: ?[]const u8,
    value: typed_value.Value,
    /// Resolved only when `value.data_type == .string`.
    value_string: ?[]const u8,
    /// Resource identifier obtained from the XML resource-map chunk.
    resource_id: ?u32,
    namespace_index: u32,
    name_index: u32,
    raw_value_index: u32,
};

pub const StartElement = struct {
    node: Node,
    namespace_uri: ?[]const u8,
    name: []const u8,
    attributes: []const Attribute,
    namespace_index: u32,
    name_index: u32,
    /// Zero-based indices into `attributes`; null represents Android's zero
    /// sentinel in the on-disk one-based fields.
    id_attribute: ?usize,
    class_attribute: ?usize,
    style_attribute: ?usize,
};

pub const EndElement = struct {
    node: Node,
    namespace_uri: ?[]const u8,
    name: []const u8,
    namespace_index: u32,
    name_index: u32,
};

pub const Cdata = struct {
    node: Node,
    text: []const u8,
    value: typed_value.Value,
    value_string: ?[]const u8,
    text_index: u32,
};

pub const Event = union(enum) {
    start_namespace: NamespaceEvent,
    end_namespace: NamespaceEvent,
    start_element: StartElement,
    end_element: EndElement,
    cdata: Cdata,
};

/// Owns all decoded strings, resource IDs, attributes, and events reachable
/// through this value. Treat `Document` as move-only and call `deinit` once.
pub const Document = struct {
    arena: std.heap.ArenaAllocator,
    string_pool: string_pool.StringPool,
    resource_map: []const u32,
    events: []const Event,

    pub fn parse(backing_allocator: std.mem.Allocator, data: []const u8) ParseError!Document {
        logging.info(.apk_android_axml, @src(), "AXML document parsing started bytes={d}", .{data.len});
        const document = parseImpl(backing_allocator, data) catch |err| {
            logging.err(.apk_android_axml, @src(), "AXML document parsing failed bytes={d} error={s}", .{
                data.len,
                @errorName(err),
            });
            return err;
        };
        logging.info(.apk_android_axml, @src(), "AXML document parsed strings={d} resource_ids={d} events={d}", .{
            document.string_pool.strings.len,
            document.resource_map.len,
            document.events.len,
        });
        return document;
    }

    fn parseImpl(backing_allocator: std.mem.Allocator, data: []const u8) ParseError!Document {
        const root = try chunk.parse(data);
        if (root.header.type_id != chunk.Type.xml) return error.WrongRootChunkType;

        var arena = std.heap.ArenaAllocator.init(backing_allocator);
        errdefer arena.deinit();
        const allocator = arena.allocator();

        var decoded_pool: ?string_pool.StringPool = null;
        var resource_map: ?[]const u32 = null;

        var first_pass = root.childIterator();
        while (try first_pass.next()) |child| {
            switch (child.header.type_id) {
                chunk.Type.string_pool => {
                    if (decoded_pool != null) return error.DuplicateStringPool;
                    decoded_pool = try string_pool.StringPool.parse(allocator, child);
                },
                chunk.Type.xml_resource_map => {
                    if (resource_map != null) return error.DuplicateResourceMap;
                    resource_map = try parseResourceMap(allocator, child);
                    logging.debug(.apk_android_axml, @src(), "AXML resource map decoded resource_ids={d}", .{resource_map.?.len});
                },
                else => {},
            }
        }

        const pool = decoded_pool orelse return error.MissingStringPool;
        const resources = resource_map orelse try allocator.alloc(u32, 0);
        if (resources.len > pool.strings.len) return error.InvalidResourceMap;

        var event_list: std.ArrayList(Event) = .empty;
        defer event_list.deinit(allocator);

        var second_pass = root.childIterator();
        while (try second_pass.next()) |child| {
            const event: ?Event = switch (child.header.type_id) {
                chunk.Type.xml_start_namespace => .{ .start_namespace = try parseNamespace(child, pool) },
                chunk.Type.xml_end_namespace => .{ .end_namespace = try parseNamespace(child, pool) },
                chunk.Type.xml_start_element => .{ .start_element = try parseStartElement(allocator, child, pool, resources) },
                chunk.Type.xml_end_element => .{ .end_element = try parseEndElement(child, pool) },
                chunk.Type.xml_cdata => .{ .cdata = try parseCdata(child, pool) },
                else => null,
            };
            if (event) |value| try event_list.append(allocator, value);
        }

        const events = try event_list.toOwnedSlice(allocator);
        return .{
            .arena = arena,
            .string_pool = pool,
            .resource_map = resources,
            .events = events,
        };
    }

    pub fn deinit(self: *Document) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn string(self: *const Document, index: u32) string_pool.LookupError![]const u8 {
        return self.string_pool.get(index);
    }

    pub fn resourceIdForString(self: *const Document, index: u32) ?u32 {
        return resourceIdForIndex(self.resource_map, index);
    }

    pub fn resolveValueString(self: *const Document, value: typed_value.Value) string_pool.LookupError!?[]const u8 {
        const index = value.stringIndex() orelse return null;
        return try self.string_pool.get(index);
    }
};

fn parseResourceMap(allocator: std.mem.Allocator, source: chunk.Chunk) ParseError![]const u32 {
    const body = source.body();
    if (body.len % @sizeOf(u32) != 0) return error.InvalidResourceMap;

    const resource_ids = try allocator.alloc(u32, body.len / @sizeOf(u32));
    var cursor = Cursor.init(body);
    for (resource_ids) |*resource_id| resource_id.* = try cursor.readInt(u32, .little);
    return resource_ids;
}

fn parseNode(source: chunk.Chunk, pool: string_pool.StringPool) ParseError!Node {
    if (source.header.header_bytes < 16) return error.InvalidNodeHeader;
    var cursor = Cursor.init(source.bytes);
    try cursor.seekTo(chunk.header_size);
    const line_number = try cursor.readInt(u32, .little);
    const comment_index = try cursor.readInt(u32, .little);
    return .{
        .line_number = line_number,
        .comment = pool.getOptional(comment_index) catch return error.InvalidStringIndex,
    };
}

fn parseNamespace(source: chunk.Chunk, pool: string_pool.StringPool) ParseError!NamespaceEvent {
    const node = try parseNode(source, pool);
    var extension = Cursor.init(source.body());
    const prefix_index = extension.readInt(u32, .little) catch return error.InvalidNodeExtension;
    const uri_index = extension.readInt(u32, .little) catch return error.InvalidNodeExtension;
    return .{
        .node = node,
        .prefix = pool.getOptional(prefix_index) catch return error.InvalidStringIndex,
        .uri = pool.get(uri_index) catch return error.InvalidStringIndex,
        .prefix_index = prefix_index,
        .uri_index = uri_index,
    };
}

fn parseStartElement(
    allocator: std.mem.Allocator,
    source: chunk.Chunk,
    pool: string_pool.StringPool,
    resource_map: []const u32,
) ParseError!StartElement {
    const node = try parseNode(source, pool);
    const body = source.body();
    var extension = Cursor.init(body);

    const namespace_index = extension.readInt(u32, .little) catch return error.InvalidNodeExtension;
    const name_index = extension.readInt(u32, .little) catch return error.InvalidNodeExtension;
    const attribute_start = extension.readInt(u16, .little) catch return error.InvalidNodeExtension;
    const attribute_size = extension.readInt(u16, .little) catch return error.InvalidNodeExtension;
    const attribute_count = extension.readInt(u16, .little) catch return error.InvalidNodeExtension;
    const id_index = extension.readInt(u16, .little) catch return error.InvalidNodeExtension;
    const class_index = extension.readInt(u16, .little) catch return error.InvalidNodeExtension;
    const style_index = extension.readInt(u16, .little) catch return error.InvalidNodeExtension;

    if (attribute_start < 20 or attribute_size < 20) return error.InvalidAttributeLayout;
    const attribute_bytes = try checkedMul(attribute_count, attribute_size);
    const attributes_end = try checkedAdd(attribute_start, attribute_bytes);
    if (attributes_end > body.len) return error.InvalidAttributeLayout;

    const attributes = try allocator.alloc(Attribute, attribute_count);
    for (attributes, 0..) |*attribute, index| {
        const record_start = try checkedAdd(attribute_start, try checkedMul(index, attribute_size));
        const record_end = try checkedAdd(record_start, attribute_size);
        const record = body[record_start..record_end];
        var attribute_cursor = Cursor.init(record);

        const attribute_namespace_index = try attribute_cursor.readInt(u32, .little);
        const attribute_name_index = try attribute_cursor.readInt(u32, .little);
        const raw_value_index = try attribute_cursor.readInt(u32, .little);
        const value = typed_value.read(&attribute_cursor) catch |err| {
            logging.err(.apk_android_axml, @src(), "AXML attribute value parsing failed element={s} attribute_index={d} error={s}", .{
                pool.get(name_index) catch "<invalid>",
                index,
                @errorName(err),
            });
            return switch (err) {
                error.EndOfInput => error.InvalidAttributeLayout,
                else => err,
            };
        };
        const value_string = if (value.stringIndex()) |string_index|
            pool.get(string_index) catch return error.InvalidStringIndex
        else
            null;

        attribute.* = .{
            .namespace_uri = pool.getOptional(attribute_namespace_index) catch return error.InvalidStringIndex,
            .name = pool.get(attribute_name_index) catch return error.InvalidStringIndex,
            .raw_value = pool.getOptional(raw_value_index) catch return error.InvalidStringIndex,
            .value = value,
            .value_string = value_string,
            .resource_id = resourceIdForIndex(resource_map, attribute_name_index),
            .namespace_index = attribute_namespace_index,
            .name_index = attribute_name_index,
            .raw_value_index = raw_value_index,
        };
    }

    return .{
        .node = node,
        .namespace_uri = pool.getOptional(namespace_index) catch return error.InvalidStringIndex,
        .name = pool.get(name_index) catch return error.InvalidStringIndex,
        .attributes = attributes,
        .namespace_index = namespace_index,
        .name_index = name_index,
        .id_attribute = try specialAttributeIndex(id_index, attribute_count),
        .class_attribute = try specialAttributeIndex(class_index, attribute_count),
        .style_attribute = try specialAttributeIndex(style_index, attribute_count),
    };
}

fn parseEndElement(source: chunk.Chunk, pool: string_pool.StringPool) ParseError!EndElement {
    const node = try parseNode(source, pool);
    var extension = Cursor.init(source.body());
    const namespace_index = extension.readInt(u32, .little) catch return error.InvalidNodeExtension;
    const name_index = extension.readInt(u32, .little) catch return error.InvalidNodeExtension;
    return .{
        .node = node,
        .namespace_uri = pool.getOptional(namespace_index) catch return error.InvalidStringIndex,
        .name = pool.get(name_index) catch return error.InvalidStringIndex,
        .namespace_index = namespace_index,
        .name_index = name_index,
    };
}

fn parseCdata(source: chunk.Chunk, pool: string_pool.StringPool) ParseError!Cdata {
    const node = try parseNode(source, pool);
    var extension = Cursor.init(source.body());
    const text_index = extension.readInt(u32, .little) catch return error.InvalidNodeExtension;
    const value: typed_value.Value = typed_value.read(&extension) catch |err| switch (err) {
        error.InvalidValueSize, error.NonZeroReservedByte => blk: {
            logging.warn(.apk_android_axml, @src(), "AXML CDATA value ignored offset={d} text_index={d} error={s}", .{
                source.offset,
                text_index,
                @errorName(err),
            });
            break :blk .{ .size = typed_value.minimum_size, .data_type = .null_value, .data = 0 };
        },
        error.EndOfInput => return error.InvalidNodeExtension,
        else => return err,
    };
    const value_string = if (value.stringIndex()) |string_index|
        pool.get(string_index) catch return error.InvalidStringIndex
    else
        null;
    return .{
        .node = node,
        .text = pool.get(text_index) catch return error.InvalidStringIndex,
        .value = value,
        .value_string = value_string,
        .text_index = text_index,
    };
}

fn specialAttributeIndex(one_based: u16, attribute_count: u16) ParseError!?usize {
    if (one_based == 0) return null;
    if (one_based > attribute_count) return error.InvalidSpecialAttributeIndex;
    return @as(usize, one_based - 1);
}

fn resourceIdForIndex(resource_map: []const u32, index: u32) ?u32 {
    const resolved: usize = @intCast(index);
    if (resolved >= resource_map.len or resource_map[resolved] == 0) return null;
    return resource_map[resolved];
}

fn checkedAdd(a: anytype, b: anytype) Cursor.Error!usize {
    const left: usize = @intCast(a);
    const right: usize = @intCast(b);
    return cursor_mod.checkedAdd(left, right);
}

fn checkedMul(a: anytype, b: anytype) Cursor.Error!usize {
    const left: usize = @intCast(a);
    const right: usize = @intCast(b);
    const result = @mulWithOverflow(left, right);
    if (result[1] != 0) return error.IntegerOverflow;
    return result[0];
}

const TestBuilder = struct {
    bytes: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) TestBuilder {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *TestBuilder) void {
        self.bytes.deinit(self.allocator);
    }

    fn appendU8(self: *TestBuilder, value: u8) !void {
        try self.bytes.append(self.allocator, value);
    }

    fn appendU16(self: *TestBuilder, value: u16) !void {
        var encoded: [2]u8 = undefined;
        std.mem.writeInt(u16, &encoded, value, .little);
        try self.bytes.appendSlice(self.allocator, &encoded);
    }

    fn appendU32(self: *TestBuilder, value: u32) !void {
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, value, .little);
        try self.bytes.appendSlice(self.allocator, &encoded);
    }

    fn slice(self: *TestBuilder, value: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, value);
    }

    fn beginChunk(self: *TestBuilder, type_id: u16, header_bytes: u16) !usize {
        const start = self.bytes.items.len;
        try self.appendU16(type_id);
        try self.appendU16(header_bytes);
        try self.appendU32(0);
        return start;
    }

    fn finishChunk(self: *TestBuilder, start: usize) void {
        const size: u32 = @intCast(self.bytes.items.len - start);
        std.mem.writeInt(u32, self.bytes.items[start + 4 ..][0..4], size, .little);
    }

    fn node(self: *TestBuilder, line: u32) !void {
        try self.appendU32(line);
        try self.appendU32(string_pool.no_index);
    }

    fn typed(self: *TestBuilder, data_type: typed_value.DataType, data: u32) !void {
        try self.appendU16(8);
        try self.appendU8(0);
        try self.appendU8(@backingInt(data_type));
        try self.appendU32(data);
    }

    fn attribute(self: *TestBuilder, namespace_index: u32, name_index: u32, raw_index: u32, data_type: typed_value.DataType, data: u32) !void {
        try self.appendU32(namespace_index);
        try self.appendU32(name_index);
        try self.appendU32(raw_index);
        try self.typed(data_type, data);
    }
};

fn appendTestStringPool(builder: *TestBuilder, strings: []const []const u8) !void {
    const start = try builder.beginChunk(chunk.Type.string_pool, string_pool.pool_header_size);
    try builder.appendU32(@intCast(strings.len));
    try builder.appendU32(0);
    try builder.appendU32(string_pool.utf8_flag);
    const strings_start: u32 = @intCast(string_pool.pool_header_size + strings.len * @sizeOf(u32));
    try builder.appendU32(strings_start);
    try builder.appendU32(0);

    const offsets_start = builder.bytes.items.len;
    for (strings) |_| try builder.appendU32(0);
    const data_start = builder.bytes.items.len;
    for (strings, 0..) |string, index| {
        const offset: u32 = @intCast(builder.bytes.items.len - data_start);
        std.mem.writeInt(u32, builder.bytes.items[offsets_start + index * 4 ..][0..4], offset, .little);
        const utf16_units = try utf16UnitsForTest(string);
        try std.testing.expect(utf16_units < 0x80 and string.len < 0x80);
        try builder.appendU8(@intCast(utf16_units));
        try builder.appendU8(@intCast(string.len));
        try builder.slice(string);
        try builder.appendU8(0);
    }
    while ((builder.bytes.items.len - start) % 4 != 0) try builder.appendU8(0);
    builder.finishChunk(start);
}

fn utf16UnitsForTest(string: []const u8) !usize {
    var index: usize = 0;
    var units: usize = 0;
    while (index < string.len) {
        const length = try std.unicode.utf8ByteSequenceLength(string[index]);
        const end = index + length;
        const codepoint = try std.unicode.utf8Decode(string[index..end]);
        units += if (codepoint >= 0x10000) 2 else 1;
        index = end;
    }
    return units;
}

fn appendResourceMap(builder: *TestBuilder, ids: []const u32) !void {
    const start = try builder.beginChunk(chunk.Type.xml_resource_map, chunk.header_size);
    for (ids) |resource_id| try builder.appendU32(resource_id);
    builder.finishChunk(start);
}

fn appendNamespace(builder: *TestBuilder, type_id: u16, line: u32, prefix: u32, uri: u32) !void {
    const start = try builder.beginChunk(type_id, 16);
    try builder.node(line);
    try builder.appendU32(prefix);
    try builder.appendU32(uri);
    builder.finishChunk(start);
}

fn appendStartElement(builder: *TestBuilder, line: u32, namespace_index: u32, name_index: u32, attributes: []const [5]u32) !void {
    const start = try builder.beginChunk(chunk.Type.xml_start_element, 16);
    try builder.node(line);
    try builder.appendU32(namespace_index);
    try builder.appendU32(name_index);
    try builder.appendU16(20);
    try builder.appendU16(20);
    try builder.appendU16(@intCast(attributes.len));
    try builder.appendU16(0);
    try builder.appendU16(0);
    try builder.appendU16(0);
    for (attributes) |attribute| {
        try builder.attribute(
            attribute[0],
            attribute[1],
            attribute[2],
            @fromBackingInt(@intCast(@as(u8, @intCast(attribute[3])))),
            attribute[4],
        );
    }
    builder.finishChunk(start);
}

fn appendEndElement(builder: *TestBuilder, line: u32, namespace_index: u32, name_index: u32) !void {
    const start = try builder.beginChunk(chunk.Type.xml_end_element, 16);
    try builder.node(line);
    try builder.appendU32(namespace_index);
    try builder.appendU32(name_index);
    builder.finishChunk(start);
}

fn appendCdata(builder: *TestBuilder, line: u32, text_index: u32) !void {
    const start = try builder.beginChunk(chunk.Type.xml_cdata, 16);
    try builder.node(line);
    try builder.appendU32(text_index);
    try builder.typed(.string, text_index);
    builder.finishChunk(start);
}

fn appendCdataWithInvalidValueSize(builder: *TestBuilder, line: u32, text_index: u32) !void {
    const start = try builder.beginChunk(chunk.Type.xml_cdata, 16);
    try builder.node(line);
    try builder.appendU32(text_index);
    try builder.appendU16(0);
    try builder.appendU8(0);
    try builder.appendU8(@backingInt(typed_value.DataType.string));
    try builder.appendU32(text_index);
    builder.finishChunk(start);
}

test "document owns decoded events, attributes, typed values, and resource map" {
    var builder = TestBuilder.init(std.testing.allocator);
    defer builder.deinit();

    const strings = [_][]const u8{
        "manifest",
        "package",
        "dev.example",
        "android",
        "http://schemas.android.com/apk/res/android",
        "versionCode",
        "application",
        "label",
        "Demo",
        "hello",
    };

    const root_start = try builder.beginChunk(chunk.Type.xml, chunk.header_size);
    try appendTestStringPool(&builder, &strings);
    try appendResourceMap(&builder, &.{ 0, 0, 0, 0, 0, 0x0101_021b, 0, 0x0101_0001 });
    try appendNamespace(&builder, chunk.Type.xml_start_namespace, 1, 3, 4);
    try appendStartElement(&builder, 2, string_pool.no_index, 0, &.{
        .{ string_pool.no_index, 1, 2, @backingInt(typed_value.DataType.string), 2 },
        .{ 4, 5, string_pool.no_index, @backingInt(typed_value.DataType.int_decimal), 42 },
    });
    try appendStartElement(&builder, 3, string_pool.no_index, 6, &.{
        .{ 4, 7, 8, @backingInt(typed_value.DataType.string), 8 },
    });
    try appendCdata(&builder, 4, 9);
    try appendEndElement(&builder, 5, string_pool.no_index, 6);
    try appendEndElement(&builder, 6, string_pool.no_index, 0);
    try appendNamespace(&builder, chunk.Type.xml_end_namespace, 7, 3, 4);
    builder.finishChunk(root_start);

    var document = try Document.parse(std.testing.allocator, builder.bytes.items);
    defer document.deinit();

    // The parsed document must not retain any slice into the APK input.
    @memset(builder.bytes.items, 0xa5);

    try std.testing.expectEqual(@as(usize, 10), document.string_pool.strings.len);
    try std.testing.expectEqual(@as(usize, 7), document.events.len);
    try std.testing.expectEqual(@as(u32, 0x0101_021b), document.resourceIdForString(5).?);

    const namespace = document.events[0].start_namespace;
    try std.testing.expectEqualStrings("android", namespace.prefix.?);
    try std.testing.expectEqualStrings("http://schemas.android.com/apk/res/android", namespace.uri);

    const manifest = document.events[1].start_element;
    try std.testing.expectEqualStrings("manifest", manifest.name);
    try std.testing.expectEqual(@as(usize, 2), manifest.attributes.len);
    try std.testing.expectEqualStrings("dev.example", manifest.attributes[0].raw_value.?);
    try std.testing.expectEqualStrings("dev.example", manifest.attributes[0].value_string.?);
    try std.testing.expectEqual(@as(i32, 42), manifest.attributes[1].value.intValue().?);
    try std.testing.expectEqual(@as(u32, 0x0101_021b), manifest.attributes[1].resource_id.?);

    const application = document.events[2].start_element;
    try std.testing.expectEqualStrings("application", application.name);
    try std.testing.expectEqualStrings("Demo", application.attributes[0].value_string.?);

    const cdata = document.events[3].cdata;
    try std.testing.expectEqualStrings("hello", cdata.text);
    try std.testing.expectEqualStrings("hello", cdata.value_string.?);
    try std.testing.expectEqualStrings("application", document.events[4].end_element.name);
    try std.testing.expectEqualStrings("manifest", document.events[5].end_element.name);
}

test "document preserves CDATA text when its optional typed value is malformed" {
    var builder = TestBuilder.init(std.testing.allocator);
    defer builder.deinit();

    const strings = [_][]const u8{ "manifest", "ignored" };
    const root = try builder.beginChunk(chunk.Type.xml, 8);
    try appendTestStringPool(&builder, &strings);
    try appendStartElement(&builder, 1, string_pool.no_index, 0, &.{});
    try appendCdataWithInvalidValueSize(&builder, 2, 1);
    try appendEndElement(&builder, 3, string_pool.no_index, 0);
    builder.finishChunk(root);

    var document = try Document.parse(std.testing.allocator, builder.bytes.items);
    defer document.deinit();
    try std.testing.expectEqual(@as(usize, 3), document.events.len);
    const cdata = document.events[1].cdata;
    try std.testing.expectEqualStrings("ignored", cdata.text);
    try std.testing.expectEqual(typed_value.DataType.null_value, cdata.value.data_type);
    try std.testing.expect(cdata.value_string == null);
}

test "document rejects missing pools and misaligned resource maps" {
    const empty_xml = [_]u8{ 3, 0, 8, 0, 8, 0, 0, 0 };
    try std.testing.expectError(error.MissingStringPool, Document.parse(std.testing.allocator, &empty_xml));

    var builder = TestBuilder.init(std.testing.allocator);
    defer builder.deinit();
    const root_start = try builder.beginChunk(chunk.Type.xml, chunk.header_size);
    try appendTestStringPool(&builder, &.{"manifest"});
    const map_start = try builder.beginChunk(chunk.Type.xml_resource_map, chunk.header_size);
    try builder.appendU8(1);
    builder.finishChunk(map_start);
    builder.finishChunk(root_start);
    try std.testing.expectError(error.InvalidResourceMap, Document.parse(std.testing.allocator, builder.bytes.items));
}
