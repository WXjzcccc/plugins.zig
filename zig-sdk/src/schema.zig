//! Record schemas: the typed shape of the records an analyzer emits.
//!
//! A plugin registers one `RecordSchema` per record type. The host stores
//! records in typed tables built from the schema, renders columns by
//! `FieldKind`, projects timestamp fields with a timeline role into the case
//! timeline and keeps the schema next to the stored rows, so results stay
//! readable without the plugin. Both sides validate with the functions of this
//! module, and `schemaHash` must match the host's own hash of the same
//! schemas byte for byte.
//!
//! Everything here is plain data: build schemas with the `RecordSchema`
//! builders and hand the result to `Plugin.recordSchema`.

const std = @import("std");

const sdk = @import("error.zig");
const wire = @import("wire.zig");

/// Errors of the schema codec ([toValue], [schemaHash]): the protocol boundary
/// reports wire failures as faults instead of leaking the MessagePack error
/// set into every caller.
pub const Error = sdk.Error;

/// Errors of [RecordSchema.validate] and [validateValue]: the schema or a
/// value is malformed.
pub const ValidateError = error{ InvalidSchema, OutOfMemory };

/// Most fields one record type may declare.
pub const MAX_FIELDS: usize = 128;
/// Longest text-like value (text, path, hash, ip, enum, title, ...).
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
/// Most items of a `list` value.
pub const MAX_LIST_ITEMS: usize = 4096;
/// Deepest nesting of a `json` value.
pub const MAX_JSON_DEPTH: usize = 8;
/// Most scalar and container entries of one `json` value.
pub const MAX_JSON_ENTRIES: usize = 4096;
/// Most record types one plugin may register.
pub const MAX_RECORD_TYPES: usize = 256;
/// Longest rendered title.
pub const MAX_TITLE_BYTES: usize = 1024;

/// How a field value is stored, rendered, sorted and searched.
pub const FieldKind = enum {
    /// UTF-8 text.
    text,
    /// Signed or unsigned 64-bit integer.
    int,
    /// Finite floating-point number.
    float,
    boolean,
    /// RFC 3339 with an offset (2024-01-02T03:04:05Z), or a local time
    /// without offset (2024-01-02T03:04:05) when the time zone is unknown.
    timestamp,
    /// A byte count (non-negative integer).
    size,
    /// Seconds (non-negative number).
    duration,
    /// A file system path as recorded by the evidence.
    path,
    /// A digest or other hexadecimal identifier.
    hash,
    /// An IPv4 / IPv6 address (or host name where the source mixes both).
    ip,
    /// One of the declared choices.
    enumeration,
    /// A list of text values.
    list,
    /// Structured data without a fixed shape.
    json,

    /// The protocol name of this kind (size, enum, ...).
    pub fn as_str(self: FieldKind) []const u8 {
        return switch (self) {
            .text => "text",
            .int => "int",
            .float => "float",
            .boolean => "bool",
            .timestamp => "timestamp",
            .size => "size",
            .duration => "duration",
            .path => "path",
            .hash => "hash",
            .ip => "ip",
            .enumeration => "enum",
            .list => "list",
            .json => "json",
        };
    }

    /// Whether keyword search looks into values of this kind.
    pub fn searchable(self: FieldKind) bool {
        return switch (self) {
            .text, .path, .hash, .ip, .enumeration, .list => true,
            .int, .float, .boolean, .timestamp, .size, .duration, .json => false,
        };
    }
};

/// One choice of an `enum` field.
pub const Choice = struct {
    id: []const u8,
    label: []const u8,
};

/// One field of a record type.
pub const Field = struct {
    id: []const u8,
    /// Default (Chinese) label; translations live in the package locales.
    label: []const u8,
    kind: FieldKind,
    /// Identifies the record together with the other key fields; key fields
    /// form the default title and get an index.
    key: bool = false,
    /// Kept in the record but not shown as a table column.
    hidden: bool = false,
    /// Timeline role (login, modified, ...) of a timestamp field; such
    /// fields are projected into the case timeline.
    timeline: ?[]const u8 = null,
    choices: []const Choice = &.{},

    pub fn new(id: []const u8, label: []const u8, kind: FieldKind) Field {
        return .{ .id = id, .label = label, .kind = kind };
    }

    /// Marks this field as part of the record identity.
    pub fn asKey(self: Field) Field {
        var field = self;
        field.key = true;
        return field;
    }

    /// Hides this field from result tables.
    pub fn asHidden(self: Field) Field {
        var field = self;
        field.hidden = true;
        return field;
    }

    /// Gives a timestamp field a timeline role.
    pub fn withTimeline(self: Field, role: []const u8) Field {
        var field = self;
        field.timeline = role;
        return field;
    }

    /// Declares the choices of an `enum` field.
    pub fn withChoices(self: Field, choices: []const Choice) Field {
        var field = self;
        field.choices = choices;
        return field;
    }
};

/// A vertical property list instead of the default record table. Each record
/// contributes one named value; optional secondary text (for example an
/// original key) sits below its label. Every visible field must have exactly
/// one role so the view loses no data.
pub const PropertyLayout = struct {
    value: []const u8,
    label: ?[]const u8 = null,
    secondary: ?[]const u8 = null,

    pub fn new(value: []const u8) PropertyLayout {
        return .{ .value = value };
    }

    pub fn withLabel(self: PropertyLayout, label: []const u8) PropertyLayout {
        var layout = self;
        layout.label = label;
        return layout;
    }

    pub fn withSecondary(self: PropertyLayout, secondary: []const u8) PropertyLayout {
        var layout = self;
        layout.secondary = secondary;
        return layout;
    }
};

/// The shape of one record type.
pub const RecordSchema = struct {
    /// Namespaced lowercase type (linux.login).
    record_type: []const u8,
    /// Default (Chinese) label of the result item.
    label: []const u8,
    /// Title template over field ids ({user} @ {terminal}); the key fields
    /// joined with " · " when absent.
    title: ?[]const u8 = null,
    /// Display group of the result item; the analyzer category when absent.
    category: ?[]const u8 = null,
    /// A vertical list of properties instead of the default record table.
    properties: ?PropertyLayout = null,
    fields: []const Field,

    pub fn new(record_type: []const u8, label: []const u8, fields: []const Field) RecordSchema {
        return .{ .record_type = record_type, .label = label, .fields = fields };
    }

    pub fn withTitle(self: RecordSchema, template: []const u8) RecordSchema {
        var schema = self;
        schema.title = template;
        return schema;
    }

    pub fn withCategory(self: RecordSchema, category: []const u8) RecordSchema {
        var schema = self;
        schema.category = category;
        return schema;
    }

    pub fn withProperties(self: RecordSchema, layout: PropertyLayout) RecordSchema {
        var schema = self;
        schema.properties = layout;
        return schema;
    }

    /// Position of field `id`, or null when the type has no such field.
    pub fn fieldIndex(self: RecordSchema, id: []const u8) ?usize {
        for (self.fields, 0..) |field, index| {
            if (std.mem.eql(u8, field.id, id)) return index;
        }
        return null;
    }

    /// Checks identifiers, limits and the title template.
    pub fn validate(self: RecordSchema) ValidateError!void {
        if (!validRecordType(self.record_type)) return error.InvalidSchema;
        if (!validLabel(self.label)) return error.InvalidSchema;
        if (self.category) |category| {
            if (!validIdentifier(category)) return error.InvalidSchema;
        }
        if (self.fields.len == 0 or self.fields.len > MAX_FIELDS) return error.InvalidSchema;
        for (self.fields, 0..) |field, index| {
            if (!validIdentifier(field.id)) return error.InvalidSchema;
            if (!validLabel(field.label)) return error.InvalidSchema;
            for (self.fields[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier.id, field.id)) return error.InvalidSchema;
            }
            if (field.timeline) |role| {
                if (!validIdentifier(role)) return error.InvalidSchema;
                if (field.kind != .timestamp) return error.InvalidSchema;
            }
            if (field.choices.len != 0) {
                if (field.kind != .enumeration) return error.InvalidSchema;
                for (field.choices, 0..) |choice, choice_index| {
                    if (!validIdentifier(choice.id)) return error.InvalidSchema;
                    if (!validLabel(choice.label)) return error.InvalidSchema;
                    for (field.choices[0..choice_index]) |earlier| {
                        if (std.mem.eql(u8, earlier.id, choice.id)) return error.InvalidSchema;
                    }
                }
            }
        }
        if (self.properties) |layout| {
            if (!self.validLayout(layout)) return error.InvalidSchema;
        }
        if (self.title) |template| {
            if (!self.validTitle(template)) return error.InvalidSchema;
        }
    }

    /// Each role names a visible field, once, and every visible field has a
    /// role.
    fn validLayout(self: RecordSchema, layout: PropertyLayout) bool {
        const roles = [_]?[]const u8{ layout.value, layout.label, layout.secondary };
        var used: [MAX_FIELDS]bool = @splat(false);
        for (roles, 0..) |role, role_index| {
            const id = role orelse continue;
            const index = self.fieldIndex(id) orelse return false;
            if (self.fields[index].hidden) return false;
            for (roles[0..role_index]) |earlier| {
                if (earlier) |other| {
                    if (std.mem.eql(u8, other, id)) return false;
                }
            }
            used[index] = true;
        }
        for (self.fields, 0..) |field, index| {
            if (!field.hidden and !used[index]) return false;
        }
        return true;
    }

    fn validTitle(self: RecordSchema, template: []const u8) bool {
        var rest = template;
        while (std.mem.indexOfScalar(u8, rest, '{')) |start| {
            const after = rest[start + 1 ..];
            if (after.len > 0 and after[0] == '{') {
                rest = after[1..];
                continue;
            }
            const end = std.mem.indexOfScalar(u8, after, '}') orelse return false;
            if (self.fieldIndex(after[0..end]) == null) return false;
            rest = after[end + 1 ..];
        }
        return true;
    }

    /// Checks one record values against this schema.
    pub fn validateValues(self: RecordSchema, values: []const wire.Value) error{ InvalidRecord, OutOfMemory }!void {
        if (values.len != self.fields.len) return error.InvalidRecord;
        for (self.fields, values) |field, value| {
            try validateValue(field, value);
        }
    }

    /// The default title: the title template, else the key fields joined
    /// with " · ", else the first non-empty text field, else the label.
    pub fn renderTitle(self: RecordSchema, alloc: std.mem.Allocator, values: []const wire.Value) ![]const u8 {
        const text = struct {
            fn display(allocator: std.mem.Allocator, schema: RecordSchema, all: []const wire.Value, index: usize) []const u8 {
                _ = schema;
                if (index >= all.len) return "";
                return displayValue(allocator, all[index]) catch "";
            }
        }.display;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(alloc);
        if (self.title) |template| {
            var rest = template;
            while (std.mem.indexOfScalar(u8, rest, '{')) |start| {
                try out.appendSlice(alloc, rest[0..start]);
                const after = rest[start + 1 ..];
                if (after.len > 0 and after[0] == '{') {
                    try out.append(alloc, '{');
                    rest = after[1..];
                    continue;
                }
                if (std.mem.indexOfScalar(u8, after, '}')) |end| {
                    if (self.fieldIndex(after[0..end])) |index| {
                        try out.appendSlice(alloc, text(alloc, self, values, index));
                    }
                    rest = after[end + 1 ..];
                } else {
                    try out.appendSlice(alloc, rest[start..]);
                    rest = "";
                    break;
                }
            }
            const tail = try std.mem.replaceOwned(u8, alloc, rest, "}}", "}");
            try out.appendSlice(alloc, tail);
        } else {
            var first = true;
            for (self.fields, 0..) |field, index| {
                if (!field.key) continue;
                const value = text(alloc, self, values, index);
                if (value.len == 0) continue;
                if (!first) try out.appendSlice(alloc, " · ");
                first = false;
                try out.appendSlice(alloc, value);
            }
            if (first) {
                for (self.fields, 0..) |field, index| {
                    if (field.kind != .text) continue;
                    const value = text(alloc, self, values, index);
                    if (value.len == 0) continue;
                    try out.appendSlice(alloc, value);
                    break;
                }
            }
        }
        const trimmed = std.mem.trim(u8, out.items, " \t\r\n");
        if (trimmed.len == 0) return self.label;
        return truncate(alloc, trimmed, MAX_TITLE_BYTES);
    }

    /// The protocol encoding of this schema as a MessagePack map.
    pub fn toValue(self: RecordSchema, alloc: std.mem.Allocator) sdk.Error!wire.Value {
        var entries: std.ArrayList(wire.Entry) = .empty;
        try entries.append(alloc, wire.entry("type", .{ .string = self.record_type }));
        try entries.append(alloc, wire.entry("label", .{ .string = self.label }));
        if (self.title) |title| try entries.append(alloc, wire.entry("title", .{ .string = title }));
        if (self.category) |category| try entries.append(alloc, wire.entry("category", .{ .string = category }));
        if (self.properties) |layout| {
            var layout_entries: std.ArrayList(wire.Entry) = .empty;
            try layout_entries.append(alloc, wire.entry("value", .{ .string = layout.value }));
            if (layout.label) |label| try layout_entries.append(alloc, wire.entry("label", .{ .string = label }));
            if (layout.secondary) |secondary| try layout_entries.append(alloc, wire.entry("secondary", .{ .string = secondary }));
            try entries.append(alloc, wire.entry("properties", try mapOf(alloc, layout_entries.items)));
        }
        const fields = try alloc.alloc(wire.Value, self.fields.len);
        for (self.fields, 0..) |field, index| fields[index] = try fieldToValue(alloc, field);
        try entries.append(alloc, wire.entry("fields", try arrayOf(alloc, fields)));
        return mapOf(alloc, entries.items);
    }
};

/// `wire.mapOf` with the wire error set mapped to the SDK's: a schema map only
/// fails to build when memory runs out.
fn mapOf(alloc: std.mem.Allocator, entries: []const wire.Entry) sdk.Error!wire.Value {
    return wire.mapOf(alloc, entries) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => sdk.fail("PROTOCOL_ERROR", "schema is not encodable as MessagePack"),
    };
}

/// `wire.arrayOf`, with the same error mapping as [`mapOf`].
fn arrayOf(alloc: std.mem.Allocator, items: []const wire.Value) sdk.Error!wire.Value {
    return wire.arrayOf(alloc, items) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => sdk.fail("PROTOCOL_ERROR", "schema is not encodable as MessagePack"),
    };
}

fn fieldToValue(alloc: std.mem.Allocator, field: Field) sdk.Error!wire.Value {
    var entries: std.ArrayList(wire.Entry) = .empty;
    try entries.append(alloc, wire.entry("id", .{ .string = field.id }));
    try entries.append(alloc, wire.entry("label", .{ .string = field.label }));
    try entries.append(alloc, wire.entry("kind", .{ .string = field.kind.as_str() }));
    if (field.key) try entries.append(alloc, wire.entry("key", .{ .boolean = true }));
    if (field.hidden) try entries.append(alloc, wire.entry("hidden", .{ .boolean = true }));
    if (field.timeline) |role| try entries.append(alloc, wire.entry("timeline", .{ .string = role }));
    if (field.choices.len != 0) {
        const choices = try alloc.alloc(wire.Value, field.choices.len);
        for (field.choices, 0..) |choice, index| {
            choices[index] = try mapOf(alloc, &.{
                wire.entry("id", .{ .string = choice.id }),
                wire.entry("label", .{ .string = choice.label }),
            });
        }
        try entries.append(alloc, wire.entry("choices", try arrayOf(alloc, choices)));
    }
    return mapOf(alloc, entries.items);
}

/// "fnv1a64:" plus 16 hex digits over the schemas sorted by record type and
/// encoded as a MessagePack array of maps. The host recomputes it from
/// `plugin.hello`; a mismatch means the library and its manifest disagree.
pub fn schemaHash(alloc: std.mem.Allocator, schemas: []const RecordSchema) Error![]const u8 {
    const sorted = try alloc.dupe(RecordSchema, schemas);
    std.mem.sort(RecordSchema, sorted, {}, struct {
        fn lessThan(_: void, left: RecordSchema, right: RecordSchema) bool {
            return std.mem.order(u8, left.record_type, right.record_type) == .lt;
        }
    }.lessThan);
    const values = try alloc.alloc(wire.Value, sorted.len);
    for (sorted, 0..) |schema, index| values[index] = try schema.toValue(alloc);
    const encoded = wire.encode(alloc, .{ .array = values }) catch |err| return codecFault(err);
    var hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (encoded) |byte| {
        hash ^= @as(u64, byte);
        hash = hash *% 0x0000_0100_0000_01b3;
    }
    return std.fmt.allocPrint(alloc, "fnv1a64:{x:0>16}", .{hash}) catch error.OutOfMemory;
}

/// The MessagePack codec never fails for a schema map (it holds only strings,
/// booleans and lists), so a failure here is reported as a protocol fault.
fn codecFault(err: wire.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => sdk.fail("PROTOCOL_ERROR", "the record schema is not encodable as MessagePack"),
    };
}

/// One identifier: 1..=64 bytes, starting with a lowercase letter, then
/// a-z, 0-9 or underscore.
pub fn validIdentifier(value: []const u8) bool {
    if (value.len == 0 or value.len > 64) return false;
    if (value[0] < 'a' or value[0] > 'z') return false;
    for (value) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or byte == '_';
        if (!ok) return false;
    }
    return true;
}

/// A namespaced record type: dot-separated lowercase identifiers.
pub fn validRecordType(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    if (std.mem.indexOfScalar(u8, value, '.') == null) return false;
    var parts = std.mem.splitScalar(u8, value, '.');
    while (parts.next()) |part| {
        if (part.len == 0 or part.len > 64) return false;
        for (part) |byte| {
            const ok = (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or byte == '_';
            if (!ok) return false;
        }
    }
    return true;
}

fn validLabel(value: []const u8) bool {
    if (std.mem.trim(u8, value, " \t\r\n").len == 0) return false;
    return value.len <= 256;
}

/// One value checked against its field kind.
pub fn validateValue(field: Field, value: wire.Value) error{ InvalidRecord, OutOfMemory }!void {
    switch (value) {
        .nil => return,
        .string => |text_value| if (text_value.len > MAX_TEXT_BYTES) return error.InvalidRecord,
        else => {},
    }
    switch (field.kind) {
        .text, .path, .hash, .ip => switch (value) {
            .string => {},
            else => return error.InvalidRecord,
        },
        .enumeration => {
            const text_value = switch (value) {
                .string => |text_value| text_value,
                else => return error.InvalidRecord,
            };
            if (field.choices.len != 0) {
                for (field.choices) |choice| {
                    if (std.mem.eql(u8, choice.id, text_value)) return;
                }
                return error.InvalidRecord;
            }
        },
        .int => switch (value) {
            .uint, .int => {},
            else => return error.InvalidRecord,
        },
        .size => switch (value) {
            .uint => {},
            else => return error.InvalidRecord,
        },
        .float, .duration => {
            const number: f64 = switch (value) {
                .uint => |integer| @floatFromInt(integer),
                .int => |integer| @floatFromInt(integer),
                .float => |float_value| float_value,
                else => return error.InvalidRecord,
            };
            if (!std.math.isFinite(number)) return error.InvalidRecord;
            if (field.kind == .duration and number < 0) return error.InvalidRecord;
        },
        .boolean => switch (value) {
            .boolean => {},
            else => return error.InvalidRecord,
        },
        .timestamp => {
            const text_value = switch (value) {
                .string => |text_value| text_value,
                else => return error.InvalidRecord,
            };
            if (parseTimestamp(text_value) == null) return error.InvalidRecord;
        },
        .list => {
            const items = switch (value) {
                .array => |items| items,
                else => return error.InvalidRecord,
            };
            if (items.len > MAX_LIST_ITEMS) return error.InvalidRecord;
            var total: usize = 0;
            for (items) |item| {
                const text_value = switch (item) {
                    .string => |text_value| text_value,
                    else => return error.InvalidRecord,
                };
                if (text_value.len > MAX_TEXT_BYTES) return error.InvalidRecord;
                total += text_value.len;
            }
            if (total > MAX_TEXT_BYTES) return error.InvalidRecord;
        },
        .json => {
            var entries: usize = 0;
            try validateJson(value, 0, &entries);
        },
    }
}

fn validateJson(value: wire.Value, depth: usize, entries: *usize) error{ InvalidRecord, OutOfMemory }!void {
    if (depth > MAX_JSON_DEPTH) return error.InvalidRecord;
    entries.* += 1;
    if (entries.* > MAX_JSON_ENTRIES) return error.InvalidRecord;
    switch (value) {
        .nil, .boolean, .int, .uint => {},
        .float => |number| if (!std.math.isFinite(number)) return error.InvalidRecord,
        .string => |text_value| if (text_value.len > MAX_TEXT_BYTES) return error.InvalidRecord,
        .array => |items| for (items) |item| try validateJson(item, depth + 1, entries),
        .map => |pairs| {
            for (pairs, 0..) |pair, index| {
                for (pairs[0..index]) |earlier| {
                    if (std.mem.eql(u8, earlier.key, pair.key)) return error.InvalidRecord;
                }
                try validateJson(pair.value, depth + 1, entries);
            }
        },
        .bytes => return error.InvalidRecord,
    }
}

/// How a value reads as text (list items joined with ", "); numbers and
/// booleans use their plain decimal form.
pub fn displayValue(alloc: std.mem.Allocator, value: wire.Value) ![]const u8 {
    return switch (value) {
        .nil => "",
        .boolean => |flag| if (flag) "true" else "false",
        .uint => |number| std.fmt.allocPrint(alloc, "{d}", .{number}),
        .int => |number| std.fmt.allocPrint(alloc, "{d}", .{number}),
        .float => |number| std.fmt.allocPrint(alloc, "{d}", .{number}),
        .string => |text_value| text_value,
        .bytes => |data| std.fmt.allocPrint(alloc, "<{d} bytes>", .{data.len}),
        .array => |items| blk: {
            var out: std.ArrayList(u8) = .empty;
            for (items) |item| {
                const text_value = try displayValue(alloc, item);
                if (text_value.len == 0) continue;
                if (out.items.len != 0) try out.appendSlice(alloc, ", ");
                try out.appendSlice(alloc, text_value);
            }
            break :blk out.items;
        },
        .map => |pairs| blk: {
            var out: std.ArrayList(u8) = .empty;
            try out.append(alloc, '{');
            for (pairs, 0..) |pair, index| {
                if (index != 0) try out.appendSlice(alloc, ", ");
                try out.appendSlice(alloc, pair.key);
                try out.appendSlice(alloc, ": ");
                try out.appendSlice(alloc, try displayValue(alloc, pair.value));
            }
            try out.append(alloc, '}');
            break :blk out.items;
        },
    };
}

fn truncate(alloc: std.mem.Allocator, text_value: []const u8, max_bytes: usize) ![]const u8 {
    if (text_value.len <= max_bytes) return text_value;
    var end = max_bytes;
    while (end > 0 and (text_value[end] & 0xc0) == 0x80) end -= 1;
    return std.fmt.allocPrint(alloc, "{s}\u{2026}", .{text_value[0..end]});
}

/// A parsed timestamp: seconds since the Unix epoch (the local wall clock
/// minus the offset), the sub-second part and the offset when known.
pub const ParsedTimestamp = struct {
    epoch_seconds: i64,
    nanos: u32,
    offset_minutes: ?i32,
};

/// Accepts RFC 3339 (2024-01-02T03:04:05Z, +08:00) or a local
/// YYYY-MM-DD[ T]HH:MM:SS[.f] time, which carries no offset.
pub fn parseTimestamp(bytes: []const u8) ?ParsedTimestamp {
    if (bytes.len < 19 or bytes.len > 64) return null;
    if (bytes[4] != '-' or bytes[7] != '-') return null;
    if (bytes[10] != 'T' and bytes[10] != 't' and bytes[10] != ' ') return null;
    if (bytes[13] != ':' or bytes[16] != ':') return null;
    const year = readDigits(bytes[0..4]) orelse return null;
    const month = readDigits(bytes[5..7]) orelse return null;
    const day = readDigits(bytes[8..10]) orelse return null;
    const hour = readDigits(bytes[11..13]) orelse return null;
    const minute = readDigits(bytes[14..16]) orelse return null;
    const second = readDigits(bytes[17..19]) orelse return null;
    if (month < 1 or month > 12) return null;
    if (day == 0 or day > daysInMonth(year, month)) return null;
    if (hour > 23 or minute > 59 or second > 60) return null;
    var position: usize = 19;
    var nanos: u32 = 0;
    if (position < bytes.len and bytes[position] == '.') {
        position += 1;
        const start = position;
        while (position < bytes.len and bytes[position] >= '0' and bytes[position] <= '9') {
            position += 1;
        }
        const digits = position - start;
        if (digits == 0 or digits > 9) return null;
        const fraction = readDigits(bytes[start..position]) orelse return null;
        nanos = fraction * pow10(@intCast(9 - digits));
    }
    var offset_minutes: ?i32 = null;
    if (position < bytes.len) {
        const marker = bytes[position];
        if ((marker == 'Z' or marker == 'z') and position + 1 == bytes.len) {
            offset_minutes = 0;
        } else if ((marker == '+' or marker == '-') and position + 6 == bytes.len) {
            if (bytes[position + 3] != ':') return null;
            const hours = readDigits(bytes[position + 1 .. position + 3]) orelse return null;
            const minutes = readDigits(bytes[position + 4 .. position + 6]) orelse return null;
            if (hours > 23 or minutes > 59) return null;
            const total: i32 = @intCast(hours * 60 + minutes);
            offset_minutes = if (marker == '-') -total else total;
        } else {
            return null;
        }
    }
    const days = daysFromCivil(@intCast(year), month, day);
    const local_seconds = days * 86_400 +
        @as(i64, @intCast(hour)) * 3_600 +
        @as(i64, @intCast(minute)) * 60 +
        @as(i64, @intCast(@min(second, 59)));
    return .{
        .epoch_seconds = local_seconds - @as(i64, offset_minutes orelse 0) * 60,
        .nanos = nanos,
        .offset_minutes = offset_minutes,
    };
}

fn readDigits(input: []const u8) ?u32 {
    var total: u32 = 0;
    for (input) |digit| {
        if (digit < '0' or digit > '9') return null;
        total = total * 10 + (digit - '0');
    }
    return total;
}

fn pow10(power: u32) u32 {
    var result: u32 = 1;
    var index: u32 = 0;
    while (index < power) : (index += 1) result *= 10;
    return result;
}

fn daysInMonth(year: u32, month: u32) u32 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        else => if ((year % 4 == 0 and year % 100 != 0) or year % 400 == 0) 29 else 28,
    };
}

/// Days since 1970-01-01 (Howard Hinnant civil calendar algorithm).
pub fn daysFromCivil(year: i64, month: u32, day: u32) i64 {
    const adjusted = if (month <= 2) year - 1 else year;
    const era = @divFloor(adjusted, 400);
    const year_of_era = adjusted - era * 400;
    const shifted_month: i64 = @intCast(month);
    const month_term = if (shifted_month > 2) shifted_month - 3 else shifted_month + 9;
    const day_of_year = @divFloor(153 * month_term + 2, 5) + @as(i64, @intCast(day)) - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return era * 146_097 + day_of_era - 719_468;
}

/// The inverse of `daysFromCivil`.
pub fn civilFromDays(days: i64) struct { year: i64, month: u32, day: u32 } {
    const shifted = days + 719_468;
    const era = @divFloor(shifted, 146_097);
    const day_of_era = shifted - era * 146_097;
    const year_of_era = @divFloor(
        day_of_era - @divFloor(day_of_era, 1_460) + @divFloor(day_of_era, 36_524) - @divFloor(day_of_era, 146_096),
        365,
    );
    const day_of_year = day_of_era - (365 * year_of_era + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100));
    const month_index = @divFloor(5 * day_of_year + 2, 153);
    const day: u32 = @intCast(day_of_year - @divFloor(153 * month_index + 2, 5) + 1);
    const month: u32 = @intCast(if (month_index < 10) month_index + 3 else month_index - 9);
    const year = year_of_era + era * 400 + @as(i64, if (month <= 2) 1 else 0);
    return .{ .year = year, .month = month, .day = day };
}

const testing = std.testing;

test "identifiers and record types follow the protocol" {
    try testing.expect(validIdentifier("login_time"));
    try testing.expect(!validIdentifier("Login"));
    try testing.expect(!validIdentifier("1abc"));
    try testing.expect(!validIdentifier(""));
    try testing.expect(validRecordType("linux.login"));
    try testing.expect(!validRecordType("login"));
    try testing.expect(!validRecordType("linux..login"));
}

test "timestamps parse the forms the host accepts" {
    try testing.expectEqual(@as(i64, 0), parseTimestamp("1970-01-01T00:00:00Z").?.epoch_seconds);
    try testing.expectEqual(@as(i64, 1_704_164_645), parseTimestamp("2024-01-02T03:04:05Z").?.epoch_seconds);
    try testing.expectEqual(@as(i32, 480), parseTimestamp("2024-01-02T11:04:05+08:00").?.offset_minutes.?);
    // 11:04:05+08:00 is the same instant as 03:04:05Z.
    try testing.expectEqual(
        @as(i64, 1_704_164_645),
        parseTimestamp("2024-01-02T11:04:05+08:00").?.epoch_seconds,
    );
    try testing.expectEqual(@as(u32, 500_000_000), parseTimestamp("2024-01-02T03:04:05.5Z").?.nanos);
    try testing.expectEqual(@as(?i32, null), parseTimestamp("2024-02-29T23:59:59").?.offset_minutes);
    try testing.expectEqual(null, parseTimestamp("2023-02-29T00:00:00Z"));
    try testing.expectEqual(null, parseTimestamp("2024-01-02T03:04Z"));
}

test "civil date conversion round-trips" {
    const days = daysFromCivil(2024, 2, 29);
    const back = civilFromDays(days);
    try testing.expectEqual(@as(i64, 2024), back.year);
    try testing.expectEqual(@as(u32, 2), back.month);
    try testing.expectEqual(@as(u32, 29), back.day);
    try testing.expectEqual(@as(i64, -1), daysFromCivil(1969, 12, 31));
}

test "titles follow the template, then the key fields, then the label" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const fields = [_]Field{
        Field.new("user", "用户", .text).asKey(),
        Field.new("uid", "UID", .int),
    };
    const schema = RecordSchema.new("linux.user", "用户", &fields).withTitle("{user} ({uid})");
    const values = [_]wire.Value{ .{ .string = "root" }, .{ .uint = 0 } };
    try testing.expectEqualStrings("root (0)", try schema.renderTitle(alloc, &values));

    const plain = RecordSchema.new("linux.user", "用户", &fields);
    try testing.expectEqualStrings("root", try plain.renderTitle(alloc, &values));

    const values_nil = [_]wire.Value{ .nil, .nil };
    try testing.expectEqualStrings("用户", try plain.renderTitle(alloc, &values_nil));
}

test "schema hash is stable across registration order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const fields = [_]Field{Field.new("name", "名称", .text)};
    const a = RecordSchema.new("test.a", "甲", &fields);
    const b = RecordSchema.new("test.b", "乙", &fields);
    try a.validate();
    try b.validate();
    const first = try schemaHash(alloc, &.{ a, b });
    const second = try schemaHash(alloc, &.{ b, a });
    try testing.expectEqualStrings(first, second);
    try testing.expect(std.mem.startsWith(u8, first, "fnv1a64:"));
}

test "invalid schemas are rejected" {
    const fields = [_]Field{Field.new("name", "名称", .text)};
    try testing.expectError(error.InvalidSchema, RecordSchema.new("test.a", "标签", &.{}).validate());
    try testing.expectError(error.InvalidSchema, RecordSchema.new("nodot", "标签", &fields).validate());
    try testing.expectError(
        error.InvalidSchema,
        RecordSchema.new("test.a", "标签", &[_]Field{Field.new("Bad", "坏", .text)}).validate(),
    );
    try testing.expectError(
        error.InvalidSchema,
        RecordSchema.new("test.a", "标签", &[_]Field{Field.new("when", "时间", .text).withTimeline("login")}).validate(),
    );
    try testing.expectError(
        error.InvalidSchema,
        RecordSchema.new("test.a", "标签", &fields).withTitle("{missing}").validate(),
    );
}
