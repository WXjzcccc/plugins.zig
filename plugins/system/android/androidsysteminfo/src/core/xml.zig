//! A minimal plain-XML reader for Android's non-ABX files.
//!
//! WifiConfigStore.xml and friends are plain-text XML written by the same
//! `TypedXmlSerializer` API as their ABX siblings: elements carry a `name`
//! attribute and either a text value (`<string>`) or a `value` attribute
//! (`<int>`, `<boolean>`, …). This module parses exactly that shape —
//! elements, attributes, text, self-closing tags, the XML declaration,
//! comments and the five predefined entities — and nothing more. Attribute
//! values use double quotes only, which is what Android's serializer emits.

const std = @import("std");

/// One element: name, attributes in document order, text and children.
pub const Node = struct {
    name: []const u8,
    attributes: []const Attribute = &.{},
    children: []const *Node = &.{},
    text: []const u8 = "",

    pub fn child(self: *const Node, name: []const u8) ?*const Node {
        for (self.children) |candidate| {
            if (std.mem.eql(u8, candidate.name, name)) return candidate;
        }
        return null;
    }

    /// All child elements with this name, in document order.
    pub fn childrenNamed(self: *const Node, arena: std.mem.Allocator, name: []const u8) error{OutOfMemory}![]const *Node {
        var found: std.ArrayList(*Node) = .empty;
        for (self.children) |candidate| {
            if (std.mem.eql(u8, candidate.name, name)) try found.append(arena, candidate);
        }
        return found.toOwnedSlice(arena);
    }

    pub fn attr(self: *const Node, name: []const u8) ?[]const u8 {
        for (self.attributes) |attribute| {
            if (std.mem.eql(u8, attribute.name, name)) return attribute.value;
        }
        return null;
    }
};

pub const Attribute = struct {
    name: []const u8,
    value: []const u8,
};

pub const Error = error{
    /// The document has no root element.
    Empty,
    /// Unbalanced or malformed markup.
    Corrupt,
    /// Elements nested deeper than [`max_depth`].
    TooDeep,
    OutOfMemory,
};

pub const max_depth: usize = 64;

/// Parses one XML document and returns its root element.
pub fn parse(arena: std.mem.Allocator, bytes: []const u8) Error!*Node {
    var reader = Reader{ .arena = arena, .bytes = bytes };
    return reader.parseDocument();
}

const Reader = struct {
    arena: std.mem.Allocator,
    bytes: []const u8,
    position: usize = 0,

    fn parseDocument(self: *Reader) Error!*Node {
        var root: ?*Node = null;
        while (true) {
            self.skipPrologue() catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {},
            };
            if (self.position >= self.bytes.len) break;
            if (self.bytes[self.position] != '<') {
                self.position += 1;
                continue;
            }
            if (self.position + 1 < self.bytes.len and self.bytes[self.position + 1] == '/') {
                // The root element's end tag: stop.
                break;
            }
            root = try self.parseElement(1);
            break;
        }
        return root orelse error.Empty;
    }

    /// Skips the declaration, comments, DOCTYPE and whitespace before the
    /// root element.
    fn skipPrologue(self: *Reader) Error!void {
        while (self.position < self.bytes.len) {
            const rest = self.bytes[self.position..];
            const trimmed = std.mem.trimStart(u8, rest, " \t\r\n");
            self.position = self.bytes.len - trimmed.len;
            if (!std.mem.startsWith(u8, trimmed, "<")) return;
            if (std.mem.startsWith(u8, trimmed, "<?") or
                std.mem.startsWith(u8, trimmed, "<!--") or
                std.mem.startsWith(u8, trimmed, "<!"))
            {
                const end = std.mem.indexOfPos(u8, trimmed, 1, if (trimmed[1] == '!') "-->" else "?>") orelse {
                    // DOCTYPE ends with a plain '>'; scan to it.
                    self.position += (std.mem.indexOfScalar(u8, trimmed, '>') orelse return error.Corrupt);
                    self.position += 1;
                    continue;
                };
                self.position += end + @as(usize, if (trimmed[1] == '!') 3 else 2);
                continue;
            }
            return;
        }
    }

    fn parseElement(self: *Reader, depth: usize) Error!*Node {
        if (depth > max_depth) return error.TooDeep;
        try self.expect('<');
        const name_end = self.findNameEnd() orelse return error.Corrupt;
        const name = try self.arena.dupe(u8, self.bytes[self.position..name_end]);
        self.position = name_end;

        var attributes: std.ArrayList(Attribute) = .empty;
        var text: std.ArrayList(u8) = .empty;
        var children: std.ArrayList(*Node) = .empty;

        // Attributes, then '>' (with content) or '/>' (self-closing).
        while (true) {
            self.skipWhitespace();
            if (self.position >= self.bytes.len) return error.Corrupt;
            if (self.bytes[self.position] == '>') {
                self.position += 1;
                break;
            }
            if (self.bytes[self.position] == '/') {
                try self.expect('/');
                try self.expect('>');
                return try self.finishNode(name, &attributes, &text, &children);
            }
            const attribute = try self.parseAttribute();
            try attributes.append(self.arena, attribute);
        }

        // Content until the matching end tag.
        while (true) {
            if (self.position >= self.bytes.len) return error.Corrupt;
            if (self.bytes[self.position] == '<') {
                if (std.mem.startsWith(u8, self.bytes[self.position..], "</")) {
                    const end = std.mem.indexOfScalarPos(u8, self.bytes, self.position, '>') orelse return error.Corrupt;
                    const closing = std.mem.trim(u8, self.bytes[self.position + 2 .. end], " \t\r\n");
                    if (!std.mem.eql(u8, closing, name)) return error.Corrupt;
                    self.position = end + 1;
                    return try self.finishNode(name, &attributes, &text, &children);
                }
                if (std.mem.startsWith(u8, self.bytes[self.position..], "<!--")) {
                    const end = std.mem.indexOfPos(u8, self.bytes, self.position + 4, "-->") orelse return error.Corrupt;
                    self.position = end + 3;
                    continue;
                }
                // A child element; the parser starts at '<'.
                const element = try self.parseElement(depth + 1);
                try children.append(self.arena, element);
                continue;
            }
            // Text up to the next '<', entity-decoded.
            const next = std.mem.indexOfScalarPos(u8, self.bytes, self.position, '<') orelse return error.Corrupt;
            try self.decodeText(self.bytes[self.position..next], &text);
            self.position = next;
        }
    }

    fn finishNode(
        self: *Reader,
        name: []const u8,
        attributes: *std.ArrayList(Attribute),
        text: *std.ArrayList(u8),
        children: *std.ArrayList(*Node),
    ) Error!*Node {
        const node = try self.arena.create(Node);
        node.* = .{
            .name = name,
            .attributes = try attributes.toOwnedSlice(self.arena),
            .children = try children.toOwnedSlice(self.arena),
            .text = try text.toOwnedSlice(self.arena),
        };
        return node;
    }

    fn parseAttribute(self: *Reader) Error!Attribute {
        const name_end = self.findNameEnd() orelse return error.Corrupt;
        const name = try self.arena.dupe(u8, self.bytes[self.position..name_end]);
        self.position = name_end;
        self.skipWhitespace();
        try self.expect('=');
        self.skipWhitespace();
        try self.expect('"');
        const value_end = std.mem.indexOfScalarPos(u8, self.bytes, self.position, '"') orelse return error.Corrupt;
        var value: std.ArrayList(u8) = .empty;
        try self.decodeText(self.bytes[self.position..value_end], &value);
        self.position = value_end + 1;
        return .{ .name = name, .value = try value.toOwnedSlice(self.arena) };
    }

    fn findNameEnd(self: *Reader) ?usize {
        var index = self.position;
        while (index < self.bytes.len) : (index += 1) {
            switch (self.bytes[index]) {
                ' ', '\t', '\r', '\n', '=', '>', '/' => return index,
                else => {},
            }
        }
        return null;
    }

    fn skipWhitespace(self: *Reader) void {
        while (self.position < self.bytes.len) : (self.position += 1) {
            switch (self.bytes[self.position]) {
                ' ', '\t', '\r', '\n' => {},
                else => return,
            }
        }
    }

    fn expect(self: *Reader, char: u8) Error!void {
        if (self.position >= self.bytes.len or self.bytes[self.position] != char) return error.Corrupt;
        self.position += 1;
    }

    /// Appends `raw` to `out` with the predefined entities decoded. Numeric
    /// character references are passed through as UTF-8 when well-formed.
    fn decodeText(self: *Reader, raw: []const u8, out: *std.ArrayList(u8)) Error!void {
        var index: usize = 0;
        while (index < raw.len) {
            if (raw[index] != '&') {
                try out.append(self.arena, raw[index]);
                index += 1;
                continue;
            }
            const semicolon = std.mem.indexOfScalarPos(u8, raw, index, ';') orelse {
                try out.append(self.arena, raw[index]);
                index += 1;
                continue;
            };
            const entity = raw[index + 1 .. semicolon];
            if (std.mem.eql(u8, entity, "quot")) {
                try out.append(self.arena, '"');
            } else if (std.mem.eql(u8, entity, "amp")) {
                try out.append(self.arena, '&');
            } else if (std.mem.eql(u8, entity, "lt")) {
                try out.append(self.arena, '<');
            } else if (std.mem.eql(u8, entity, "gt")) {
                try out.append(self.arena, '>');
            } else if (std.mem.eql(u8, entity, "apos")) {
                try out.append(self.arena, '\'');
            } else if (entity.len > 1 and entity[0] == '#') {
                const code = std.fmt.parseInt(u21, entity[if (entity[1] == 'x') 2 else 1 ..], if (entity[1] == 'x') 16 else 10) catch {
                    try out.appendSlice(self.arena, raw[index .. semicolon + 1]);
                    index = semicolon + 1;
                    continue;
                };
                var encoded: [4]u8 = undefined;
                const width = std.unicode.utf8Encode(code, &encoded) catch {
                    try out.appendSlice(self.arena, raw[index .. semicolon + 1]);
                    index = semicolon + 1;
                    continue;
                };
                try out.appendSlice(self.arena, encoded[0..width]);
            } else {
                try out.appendSlice(self.arena, raw[index .. semicolon + 1]);
            }
            index = semicolon + 1;
        }
    }
};

const testing = std.testing;

test "parses WifiConfigStore-shaped documents" {
    const document =
        \\<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
        \\<WifiConfigStoreData>
        \\<int name="Version" value="3" />
        \\<NetworkList>
        \\<Network>
        \\<WifiConfiguration>
        \\<string name="ConfigKey">&quot;OnePlus 9&quot;WPA_PSK</string>
        \\<string name="SSID">&quot;OnePlus 9&quot;</string>
        \\<boolean name="HiddenSSID" value="false" />
        \\<long name="LastConnectedTime" value="1784265393980" />
        \\<null name="BSSID" />
        \\<string name="Note">a &amp; b &#65;</string>
        \\</WifiConfiguration>
        \\</Network>
        \\</NetworkList>
        \\</WifiConfigStoreData>
    ;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const root = try parse(arena_state.allocator(), document);

    try testing.expectEqualStrings("WifiConfigStoreData", root.name);
    const network_list = root.child("NetworkList").?;
    const networks = try network_list.childrenNamed(arena_state.allocator(), "Network");
    try testing.expectEqual(@as(usize, 1), networks.len);
    const config = networks[0].child("WifiConfiguration").?;
    // TypedXmlSerializer shape: the element is the value's type, the `name`
    // attribute is the key.
    var ssid: ?*const Node = null;
    var hidden: ?*const Node = null;
    var note: ?*const Node = null;
    for (config.children) |child| {
        const key = child.attr("name") orelse continue;
        if (std.mem.eql(u8, key, "SSID")) ssid = child;
        if (std.mem.eql(u8, key, "HiddenSSID")) hidden = child;
        if (std.mem.eql(u8, key, "Note")) note = child;
    }
    try testing.expectEqualStrings("string", ssid.?.name);
    try testing.expectEqualStrings("\"OnePlus 9\"", ssid.?.text);
    try testing.expectEqualStrings("boolean", hidden.?.name);
    try testing.expectEqualStrings("false", hidden.?.attr("value").?);
    try testing.expectEqualStrings("a & b A", note.?.text);
    // `<null name="BSSID" />` parses as a self-closing element.
    var has_bssid = false;
    for (config.children) |child| {
        if (std.mem.eql(u8, child.name, "null")) has_bssid = true;
    }
    try testing.expect(has_bssid);
}

test "self-closing root and malformed documents are reported" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const root = try parse(arena_state.allocator(), "<root><a/></root>");
    try testing.expectEqualStrings("root", root.name);
    try testing.expect(root.child("a") != null);

    try testing.expectError(error.Corrupt, parse(arena_state.allocator(), "<root><a></b></root>"));
    try testing.expectError(error.Empty, parse(arena_state.allocator(), "no markup here"));
}
