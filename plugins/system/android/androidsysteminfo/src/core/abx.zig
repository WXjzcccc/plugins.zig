//! Android Binary XML (ABX) reader.
//!
//! Android 12+ serializes most `/data/system` XML files (packages.xml,
//! appops.xml, users/0.xml, adb_temp_keys.xml, …) with
//! `android.util.BinaryXmlSerializer`. The wire format is NOT the resource
//! AXML of APK files: every event is one byte whose low nibble is an
//! XmlPullParser token and whose high nibble is a value type, followed by a
//! value written by `FastDataOutput` — big-endian primitives, `writeUTF`
//! strings (u16 length + modified UTF-8 bytes) and a string dictionary where
//! a reference is a plain u16 and `0xFFFF` introduces a new string.
//!
//! Wire reference: `BinaryXmlSerializer.java` and `FastDataOutput.java` in
//! AOSP `frameworks/libs/modules-utils`. Magic: `ABX\0`.

const std = @import("std");

/// Magic of protocol version 0: "ABX\0".
pub const magic = [_]u8{ 0x41, 0x42, 0x58, 0x00 };

/// XmlPullParser event tokens (low nibble).
const Token = struct {
    const start_document: u8 = 0;
    const end_document: u8 = 1;
    const start_tag: u8 = 2;
    const end_tag: u8 = 3;
    const text: u8 = 4;
    const attribute: u8 = 15;
};

/// Value types (high nibble).
const Type = struct {
    const null_: u8 = 0x10;
    const string: u8 = 0x20;
    const string_interned: u8 = 0x30;
    const bytes_hex: u8 = 0x40;
    const bytes_base64: u8 = 0x50;
    const int: u8 = 0x60;
    const int_hex: u8 = 0x70;
    const long: u8 = 0x80;
    const long_hex: u8 = 0x90;
    const float: u8 = 0xA0;
    const double: u8 = 0xB0;
    const boolean_true: u8 = 0xC0;
    const boolean_false: u8 = 0xD0;
};

/// A typed attribute value.
pub const Value = union(enum) {
    null_,
    boolean: bool,
    /// `TYPE_INT` / `TYPE_INT_HEX` — both carry a signed 32-bit value.
    int: i64,
    /// `TYPE_LONG` / `TYPE_LONG_HEX` — both carry a signed 64-bit value.
    long: i64,
    float: f32,
    double: f64,
    string: []const u8,
    /// `TYPE_BYTES_HEX` / `TYPE_BYTES_BASE64`, decoded to raw bytes (the
    /// wire carries raw bytes; the hex/base64 spelling is Java-side only).
    bytes: []const u8,
};

/// One attribute of an element.
pub const Attribute = struct {
    name: []const u8,
    value: Value,
};

/// One element of the document tree. Names, text and values point into the
/// parse arena.
pub const Node = struct {
    name: []const u8,
    attributes: []const Attribute = &.{},
    children: []const *Node = &.{},
    /// Concatenated TEXT content of this element.
    text: []const u8 = "",

    /// The first child element with this name.
    pub fn child(self: *const Node, name: []const u8) ?*const Node {
        for (self.children) |candidate| {
            if (std.mem.eql(u8, candidate.name, name)) return candidate;
        }
        return null;
    }

    /// The value of the named attribute.
    pub fn attr(self: *const Node, name: []const u8) ?Value {
        for (self.attributes) |attribute| {
            if (std.mem.eql(u8, attribute.name, name)) return attribute.value;
        }
        return null;
    }

    /// Every value of the named attribute, in order (Android reuses one
    /// attribute name for repeated entries, e.g. the `bssid` list).
    pub fn attrsNamed(self: *const Node, arena: std.mem.Allocator, name: []const u8) error{OutOfMemory}![]const Value {
        var found: std.ArrayList(Value) = .empty;
        for (self.attributes) |attribute| {
            if (std.mem.eql(u8, attribute.name, name)) try found.append(arena, attribute.value);
        }
        return found.toOwnedSlice(arena);
    }

    /// A scalar attribute rendered as text (numbers formatted, booleans as
    /// `true`/`false`); null when absent, null-typed or a byte array.
    pub fn attrText(self: *const Node, arena: std.mem.Allocator, name: []const u8) error{OutOfMemory}!?[]const u8 {
        const value = self.attr(name) orelse return null;
        return switch (value) {
            .null_ => null,
            .boolean => |boolean| try arena.dupe(u8, if (boolean) "true" else "false"),
            .int => |int| try std.fmt.allocPrint(arena, "{d}", .{int}),
            .long => |long| try std.fmt.allocPrint(arena, "{d}", .{long}),
            .float => |float| try std.fmt.allocPrint(arena, "{d}", .{float}),
            .double => |double| try std.fmt.allocPrint(arena, "{d}", .{double}),
            .string => |string| string,
            .bytes => null,
        };
    }

    /// An integer attribute; `TYPE_LONG` values are narrowed.
    pub fn attrInt(self: *const Node, name: []const u8) ?i64 {
        return switch (self.attr(name) orelse return null) {
            .int => |int| int,
            .long => |long| long,
            else => null,
        };
    }

    /// A boolean attribute.
    pub fn attrBool(self: *const Node, name: []const u8) ?bool {
        return switch (self.attr(name) orelse return null) {
            .boolean => |boolean| boolean,
            else => null,
        };
    }

    /// A long attribute; `TYPE_INT` values are widened.
    pub fn attrLong(self: *const Node, name: []const u8) ?i64 {
        return self.attrInt(name);
    }
};

pub const Error = error{
    /// The buffer does not start with the ABX magic.
    NotAbx,
    /// A token, length or reference points outside the buffer, an intern
    /// reference has no definition, or the document is unbalanced.
    Corrupt,
    /// Nesting deeper than [`max_depth`].
    TooDeep,
    OutOfMemory,
};

/// Element nesting guard; real system files stay below a dozen levels.
pub const max_depth: usize = 64;

/// Parses one ABX document and returns its root element.
pub fn parse(arena: std.mem.Allocator, bytes: []const u8) Error!*Node {
    if (bytes.len < magic.len or !std.mem.eql(u8, bytes[0..magic.len], &magic)) {
        return error.NotAbx;
    }
    var reader = Reader{ .arena = arena, .bytes = bytes };
    reader.position = magic.len;
    const root = try reader.parseDocument();
    return root;
}

const Reader = struct {
    arena: std.mem.Allocator,
    bytes: []const u8,
    position: usize = 0,
    /// String dictionary: the first definition is index 0, and so on.
    interned: std.ArrayList([]const u8) = .empty,

    fn parseDocument(self: *Reader) Error!*Node {
        const start = try self.readByte();
        if (start != Token.start_document | Type.null_) return error.Corrupt;
        const root = try self.parseElement(1);
        // Only the end-of-document marker may follow.
        if (self.position < self.bytes.len) {
            const end = try self.readByte();
            if (end & 0x0f != Token.end_document) return error.Corrupt;
        }
        return root;
    }

    fn parseElement(self: *Reader, depth: usize) Error!*Node {
        if (depth > max_depth) return error.TooDeep;
        const start = try self.readByte();
        if (start & 0x0f != Token.start_tag) return error.Corrupt;
        const name: []const u8 = switch (start & 0xf0) {
            Type.string_interned => try self.readInterned(),
            Type.string => try self.readUTF(),
            else => return error.Corrupt,
        };

        var attributes: std.ArrayList(Attribute) = .empty;
        var text: std.ArrayList(u8) = .empty;
        var children: std.ArrayList(*Node) = .empty;

        while (true) {
            const byte = try self.readByte();
            switch (byte & 0x0f) {
                Token.attribute => {
                    const attr_name = try self.readInterned();
                    const value: Value = switch (byte & 0xf0) {
                        Type.null_ => .null_,
                        Type.string => .{ .string = try self.readUTF() },
                        Type.string_interned => .{ .string = try self.readInterned() },
                        Type.bytes_hex, Type.bytes_base64 => .{ .bytes = try self.readRawBytes() },
                        Type.int, Type.int_hex => .{ .int = @intCast(try self.readInt(u32)) },
                        Type.long, Type.long_hex => .{ .long = @bitCast(try self.readInt(u64)) },
                        Type.float => .{ .float = @bitCast(try self.readInt(u32)) },
                        Type.double => .{ .double = @bitCast(try self.readInt(u64)) },
                        Type.boolean_true => .{ .boolean = true },
                        Type.boolean_false => .{ .boolean = false },
                        else => return error.Corrupt,
                    };
                    try attributes.append(self.arena, .{ .name = attr_name, .value = value });
                },
                Token.start_tag => {
                    self.position -= 1;
                    const element = try self.parseElement(depth + 1);
                    try children.append(self.arena, element);
                },
                Token.end_tag => {
                    const end_name: []const u8 = switch (byte & 0xf0) {
                        Type.string_interned => try self.readInterned(),
                        Type.string => try self.readUTF(),
                        else => return error.Corrupt,
                    };
                    if (!std.mem.eql(u8, end_name, name)) return error.Corrupt;
                    const node = try self.arena.create(Node);
                    node.* = .{
                        .name = name,
                        .attributes = try attributes.toOwnedSlice(self.arena),
                        .children = try children.toOwnedSlice(self.arena),
                        .text = try text.toOwnedSlice(self.arena),
                    };
                    return node;
                },
                Token.text => {
                    const chunk: []const u8 = switch (byte & 0xf0) {
                        Type.string => try self.readUTF(),
                        else => return error.Corrupt,
                    };
                    try text.appendSlice(self.arena, chunk);
                },
                else => return error.Corrupt,
            }
        }
    }

    fn readByte(self: *Reader) Error!u8 {
        if (self.position >= self.bytes.len) return error.Corrupt;
        const byte = self.bytes[self.position];
        self.position += 1;
        return byte;
    }

    fn readInt(self: *Reader, comptime T: type) Error!T {
        const width = @sizeOf(T);
        const end = self.position + width;
        if (end > self.bytes.len) return error.Corrupt;
        defer self.position = end;
        return std.mem.readInt(T, self.bytes[self.position..end][0..width], .big);
    }

    /// `FastDataOutput.writeUTF`: u16 byte length + the bytes.
    fn readUTF(self: *Reader) Error![]const u8 {
        const length: usize = try self.readInt(u16);
        const end = self.position + length;
        if (end > self.bytes.len) return error.Corrupt;
        defer self.position = end;
        // Java modified UTF-8 differs from UTF-8 only for NUL and astral
        // characters; forensic strings are copied through unchanged.
        return try self.arena.dupe(u8, self.bytes[self.position..end]);
    }

    /// `FastDataOutput.writeInternedUTF`: a plain u16 reference, or 0xFFFF
    /// followed by the string itself (which defines the next index).
    fn readInterned(self: *Reader) Error![]const u8 {
        const reference = try self.readInt(u16);
        if (reference != 0xffff) {
            if (reference >= self.interned.items.len) return error.Corrupt;
            return self.interned.items[reference];
        }
        const value = try self.readUTF();
        try self.interned.append(self.arena, value);
        return value;
    }

    /// Bytes attribute: u16 length + raw bytes.
    fn readRawBytes(self: *Reader) Error![]const u8 {
        const length: usize = try self.readInt(u16);
        const end = self.position + length;
        if (end > self.bytes.len) return error.Corrupt;
        defer self.position = end;
        return try self.arena.dupe(u8, self.bytes[self.position..end]);
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

const Writer = @import("abx_test_helper.zig").Writer;

test "parses tags, attributes of every scalar type and interning" {
    var writer = Writer{};
    defer writer.deinit();
    try writer.out.appendSlice(testing.allocator, &magic);
    try writer.document();
    try writer.startTag("user");
    try writer.attrInt("id", 0);
    try writer.attrLong("lastLoggedIn", 1768863548083);
    try writer.attrBool("isRestricted", false);
    try writer.attrString("name", "owner");
    try writer.attrInterned("type", "android.os.usertype.full.SYSTEM");
    try writer.startTag("restrictions");
    try writer.text("some text");
    try writer.endTag("restrictions");
    try writer.endTag("user");
    try writer.byte(1 | 0x10);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const root = try parse(arena_state.allocator(), writer.out.items);

    try testing.expectEqualStrings("user", root.name);
    try testing.expectEqual(@as(i64, 0), root.attrInt("id").?);
    try testing.expectEqual(@as(i64, 1768863548083), root.attrLong("lastLoggedIn").?);
    try testing.expectEqual(false, root.attrBool("isRestricted").?);
    try testing.expectEqualStrings("owner", (try root.attrText(arena_state.allocator(), "name")).?);
    try testing.expectEqualStrings("android.os.usertype.full.SYSTEM", (try root.attrText(arena_state.allocator(), "type")).?);

    const restrictions = root.child("restrictions").?;
    try testing.expectEqualStrings("some text", restrictions.text);
    try testing.expect(root.child("missing") == null);
}

test "rejects non-abx input and truncated documents" {
    try testing.expectError(error.NotAbx, parse(testing.allocator, "plain xml"));
    var writer = Writer{};
    defer writer.deinit();
    try writer.out.appendSlice(testing.allocator, &magic);
    try writer.document();
    try writer.startTag("a");
    // No end tag: truncated.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectError(error.Corrupt, parse(arena_state.allocator(), writer.out.items));
}

test "an unknown intern reference is corrupt, not a crash" {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(testing.allocator);
    try bytes.appendSlice(testing.allocator, &magic);
    try bytes.append(testing.allocator, 0x10); // START_DOCUMENT
    try bytes.append(testing.allocator, 2 | 0x30); // START_TAG, interned
    try bytes.appendSlice(testing.allocator, &[_]u8{ 0x00, 0x05 }); // ref 5: never defined

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectError(error.Corrupt, parse(arena_state.allocator(), bytes.items));
}
