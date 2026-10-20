//! Records: what an analyzer emits.
//!
//! A record type has a fixed [`schema.RecordSchema`]; its values are positional,
//! in schema field order. This module carries the value types that are not
//! plain MessagePack scalars: [`Timestamp`] (never label a local time as UTC),
//! [`Severity`], [`SourceRef`] and [`DynamicRecord`] for parsers that only
//! learn their columns at run time.
//!
//! It also defines the built-in `profile.fact` record type behind
//! `Run.provide`: one evidence profile fact (time zone, host name, user
//! names, ...) that later analyzers read back through `Run.profile`.

const std = @import("std");

const wire = @import("wire.zig");
const schema = @import("schema.zig");
const sdk = @import("error.zig");

/// Longest formatted timestamp: `YYYY-MM-DDTHH:MM:SS.123456789+HH:MM`.
pub const MAX_TIMESTAMP_BYTES: usize = 40;

/// A point in time: RFC 3339 with an offset, or a local wall-clock time whose
/// time zone the evidence does not record.
///
/// The text lives in an inline buffer, so a timestamp needs no allocator and
/// can be built in a hot loop. Build local times with [`Timestamp.local`] so a
/// time without a known zone is never mistaken for UTC.
pub const Timestamp = struct {
    buffer: [MAX_TIMESTAMP_BYTES]u8 = undefined,
    len: u8 = 0,

    /// Copies `text` into the inline buffer. Text longer than the buffer is
    /// refused: no valid timestamp is that long.
    fn init(text: []const u8) Timestamp {
        std.debug.assert(text.len <= MAX_TIMESTAMP_BYTES);
        var timestamp = Timestamp{};
        @memcpy(timestamp.buffer[0..text.len], text);
        timestamp.len = @intCast(text.len);
        return timestamp;
    }

    /// UTC from Unix seconds.
    pub fn fromUnix(seconds: i64) Timestamp {
        return fromUnixNanos(seconds, 0);
    }

    /// UTC from Unix milliseconds.
    pub fn fromUnixMillis(milliseconds: i64) Timestamp {
        const seconds = @divFloor(milliseconds, 1_000);
        const nanos: u32 = @intCast(@mod(milliseconds, 1_000) * 1_000_000);
        return fromUnixNanos(seconds, nanos);
    }

    /// UTC from Unix seconds plus a sub-second part.
    pub fn fromUnixNanos(seconds: i64, nanos: u32) Timestamp {
        const clamped: u32 = @min(nanos, 999_999_999);
        const days = @divFloor(seconds, 86_400);
        const second_of_day: u64 = @intCast(@mod(seconds, 86_400));
        const civil = schema.civilFromDays(days);
        var builder = Builder{};
        builder.year(civil.year);
        builder.append("-");
        builder.padded(civil.month, 2);
        builder.append("-");
        builder.padded(civil.day, 2);
        builder.append("T");
        builder.padded(second_of_day / 3_600, 2);
        builder.append(":");
        builder.padded(second_of_day % 3_600 / 60, 2);
        builder.append(":");
        builder.padded(second_of_day % 60, 2);
        builder.fraction(clamped);
        builder.append("Z");
        return Timestamp.init(builder.text());
    }

    /// A local wall-clock time without a known time zone.
    pub fn local(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) ?Timestamp {
        return localNanos(year, month, day, hour, minute, second, 0);
    }

    /// [`Timestamp.local`] with a sub-second part.
    pub fn localNanos(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        nanos: u32,
    ) ?Timestamp {
        if (year < 0 or year > 9999) return null;
        var builder = Builder{};
        builder.year(year);
        builder.append("-");
        builder.padded(month, 2);
        builder.append("-");
        builder.padded(day, 2);
        builder.append("T");
        builder.padded(hour, 2);
        builder.append(":");
        builder.padded(minute, 2);
        builder.append(":");
        builder.padded(second, 2);
        builder.fraction(@min(nanos, 999_999_999));
        const text = builder.text();
        if (schema.parseTimestamp(text) == null) return null;
        return Timestamp.init(text);
    }

    /// A wall-clock time at a fixed UTC offset (minutes east of UTC).
    pub fn withOffset(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        offset_minutes: i32,
    ) ?Timestamp {
        if (year < 0 or year > 9999) return null;
        if (offset_minutes <= -24 * 60 or offset_minutes >= 24 * 60) return null;
        const magnitude: u32 = @intCast(if (offset_minutes < 0) -offset_minutes else offset_minutes);
        var builder = Builder{};
        builder.year(year);
        builder.append("-");
        builder.padded(month, 2);
        builder.append("-");
        builder.padded(day, 2);
        builder.append("T");
        builder.padded(hour, 2);
        builder.append(":");
        builder.padded(minute, 2);
        builder.append(":");
        builder.padded(second, 2);
        builder.append(if (offset_minutes < 0) "-" else "+");
        builder.padded(magnitude / 60, 2);
        builder.append(":");
        builder.padded(magnitude % 60, 2);
        const text = builder.text();
        if (schema.parseTimestamp(text) == null) return null;
        return Timestamp.init(text);
    }

    /// Accepts RFC 3339 or a local `YYYY-MM-DDTHH:MM:SS[.f]` time. A space
    /// between date and time is normalised to `T`.
    pub fn parse(text: []const u8) ?Timestamp {
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        if (schema.parseTimestamp(trimmed) == null) return null;
        if (std.mem.indexOfScalar(u8, trimmed, ' ')) |space| {
            if (trimmed.len > MAX_TIMESTAMP_BYTES) return null;
            var timestamp = Timestamp.init(trimmed);
            timestamp.buffer[space] = 'T';
            return timestamp;
        }
        if (trimmed.len > MAX_TIMESTAMP_BYTES) return null;
        return Timestamp.init(trimmed);
    }

    pub fn asStr(self: *const Timestamp) []const u8 {
        return self.buffer[0..self.len];
    }

    /// Whether the time zone is known.
    pub fn hasOffset(self: *const Timestamp) bool {
        const parsed = schema.parseTimestamp(self.asStr()) orelse return false;
        return parsed.offset_minutes != null;
    }
};

/// Formats into the fixed timestamp buffer without an allocator.
const Builder = struct {
    buffer: [MAX_TIMESTAMP_BYTES]u8 = undefined,
    len: usize = 0,

    fn append(self: *Builder, bytes: []const u8) void {
        std.debug.assert(self.len + bytes.len <= MAX_TIMESTAMP_BYTES);
        @memcpy(self.buffer[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    /// A non-negative number, zero padded to at least `width` digits.
    fn padded(self: *Builder, number: u64, width: usize) void {
        var digits: [20]u8 = undefined;
        var value = number;
        var index: usize = digits.len;
        while (true) {
            index -= 1;
            digits[index] = '0' + @as(u8, @intCast(value % 10));
            value /= 10;
            if (value == 0) break;
        }
        var pad = width -| (digits.len - index);
        while (pad > 0) : (pad -= 1) {
            self.buffer[self.len] = '0';
            self.len += 1;
        }
        self.append(digits[index..]);
    }

    /// A year, zero padded to four columns (the sign counts, as in Rust's
    /// `{:04}`).
    fn year(self: *Builder, value: i64) void {
        if (value < 0) {
            self.buffer[self.len] = '-';
            self.len += 1;
            self.padded(@intCast(-value), 3);
        } else {
            self.padded(@intCast(value), 4);
        }
    }

    /// The sub-second part: nothing for zero, else `.` and the significant
    /// digits (nine at most).
    fn fraction(self: *Builder, nanos: u32) void {
        if (nanos == 0) return;
        var digits: [9]u8 = undefined;
        var value = nanos;
        var index: usize = digits.len;
        while (index > 0) {
            index -= 1;
            digits[index] = '0' + @as(u8, @intCast(value % 10));
            value /= 10;
        }
        var end: usize = digits.len;
        while (end > 0 and digits[end - 1] == '0') end -= 1;
        self.buffer[self.len] = '.';
        self.len += 1;
        self.append(digits[0..end]);
    }

    fn text(self: *const Builder) []const u8 {
        return self.buffer[0..self.len];
    }
};

/// Severity of a record that flags something (a finding).
pub const Severity = enum {
    info,
    low,
    medium,
    high,
    critical,

    /// The protocol name of this severity.
    pub fn asStr(self: Severity) []const u8 {
        return switch (self) {
            .info => "info",
            .low => "low",
            .medium => "medium",
            .high => "high",
            .critical => "critical",
        };
    }
};

/// Where a record came from: an evidence address, optionally down to a byte
/// range. `root` is the volume key (`part:1`, `lvm:0:1`, `root`) and `path`
/// the path inside that volume, so the source can be located whichever view
/// the analyzer read it through.
pub const SourceRef = struct {
    root: ?[]const u8 = null,
    path: ?[]const u8 = null,
    node_id: ?[]const u8 = null,
    offset: ?u64 = null,
    length: ?u64 = null,
    /// What part of the source holds the record (`line 12`, `row 4`).
    note: ?[]const u8 = null,

    /// Narrows this source to `length` bytes at `offset`.
    pub fn at(self: SourceRef, offset: u64, length: u64) SourceRef {
        var source = self;
        source.offset = offset;
        source.length = length;
        return source;
    }

    /// Notes where in the source the record is.
    pub fn noteText(self: SourceRef, note: []const u8) SourceRef {
        var source = self;
        source.note = note;
        return source;
    }

    /// The protocol encoding: a map with only the fields that are set.
    pub fn toValue(self: SourceRef, alloc: std.mem.Allocator) sdk.Error!wire.Value {
        var entries: std.ArrayList(wire.Entry) = .empty;
        if (self.root) |root| try entries.append(alloc, wire.entry("root", wire.str(root)));
        if (self.path) |path| try entries.append(alloc, wire.entry("path", wire.str(path)));
        if (self.node_id) |node_id| try entries.append(alloc, wire.entry("node_id", wire.str(node_id)));
        if (self.offset) |offset| try entries.append(alloc, wire.entry("offset", wire.uint(offset)));
        if (self.length) |length| try entries.append(alloc, wire.entry("length", wire.uint(length)));
        if (self.note) |note| try entries.append(alloc, wire.entry("note", wire.str(note)));
        return wire.mapOf(alloc, entries.items) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => sdk.fail("PROTOCOL_ERROR", "a record source is not encodable"),
        };
    }
};

/// A record whose schema is built at run time (no derive), for generic parsers
/// that only learn their columns from the evidence.
pub const DynamicRecord = struct {
    schema: *const schema.RecordSchema,
    values: []wire.Value,

    /// A record with every field unset.
    pub fn init(
        alloc: std.mem.Allocator,
        record_schema: *const schema.RecordSchema,
    ) error{OutOfMemory}!DynamicRecord {
        const values = try alloc.alloc(wire.Value, record_schema.fields.len);
        for (values) |*slot| slot.* = .nil;
        return .{ .schema = record_schema, .values = values };
    }

    /// Sets a field by id; unknown ids are ignored.
    pub fn set(self: *DynamicRecord, field: []const u8, value: wire.Value) void {
        const index = self.schema.fieldIndex(field) orelse return;
        self.values[index] = value;
    }

    /// The values in schema field order.
    pub fn valuesSlice(self: DynamicRecord) []const wire.Value {
        return self.values;
    }
};

/// The built-in record type behind `Run.provide`: one evidence profile fact
/// (time zone, host name, user names, ...).
pub const PROFILE_FACT = "profile.fact";

const profile_fact_fields = [_]schema.Field{
    schema.Field.new("key", "键", .text).asKey(),
    schema.Field.new("value", "值", .json),
    schema.Field.new("system", "系统", .text),
};

/// The schema of [`PROFILE_FACT`], identical to the Rust
/// `profile_fact_schema()`: `RecordSchema::new("profile.fact", "检材画像")
/// .title("{key}").field(key: Text key).field(value: Json).field(system: Text)`.
pub fn profileFactSchema() schema.RecordSchema {
    return schema.RecordSchema.new(PROFILE_FACT, "检材画像", &profile_fact_fields)
        .withTitle("{key}");
}

const testing = std.testing;

test "timestamps format UTC and keep unknown zones local" {
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", Timestamp.fromUnix(0).asStr());
    try testing.expectEqualStrings(
        "2024-01-02T03:04:05.5Z",
        Timestamp.fromUnixNanos(1_704_164_645, 500_000_000).asStr(),
    );
    try testing.expectEqualStrings(
        "1969-12-31T23:59:59.999Z",
        Timestamp.fromUnixMillis(-1).asStr(),
    );
    try testing.expectEqualStrings(
        "2024-01-02T03:04:05.123456789Z",
        Timestamp.fromUnixNanos(1_704_164_645, 123_456_789).asStr(),
    );

    const leap = Timestamp.local(2024, 2, 29, 23, 59, 59) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("2024-02-29T23:59:59", leap.asStr());
    try testing.expect(!leap.hasOffset());
    try testing.expectEqual(null, Timestamp.local(2023, 2, 29, 0, 0, 0));
    try testing.expectEqual(null, Timestamp.local(2024, 13, 1, 0, 0, 0));

    const offset = Timestamp.withOffset(2024, 1, 2, 11, 4, 5, 480) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqualStrings("2024-01-02T11:04:05+08:00", offset.asStr());
    try testing.expect(offset.hasOffset());
    const west = Timestamp.withOffset(2024, 1, 2, 3, 4, 5, -300) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqualStrings("2024-01-02T03:04:05-05:00", west.asStr());
    try testing.expectEqual(null, Timestamp.withOffset(2024, 1, 2, 3, 4, 5, 24 * 60));

    const parsed = Timestamp.parse("2024-01-02 03:04:05") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("2024-01-02T03:04:05", parsed.asStr());
    try testing.expect(!parsed.hasOffset());
    try testing.expectEqual(null, Timestamp.parse("yesterday"));
}

test "severities use their protocol names" {
    try testing.expectEqualStrings("info", Severity.info.asStr());
    try testing.expectEqualStrings("low", Severity.low.asStr());
    try testing.expectEqualStrings("medium", Severity.medium.asStr());
    try testing.expectEqualStrings("high", Severity.high.asStr());
    try testing.expectEqualStrings("critical", Severity.critical.asStr());
}

test "sources serialize only the fields that are set" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const source = (SourceRef{
        .root = "part:1",
        .path = "var/log/auth.log",
        .node_id = "n-7",
    }).at(4096, 512).noteText("line 12");
    const encoded = try source.toValue(alloc);
    try testing.expectEqual(@as(usize, 6), encoded.map.len);
    try testing.expectEqualStrings("part:1", encoded.getString("root").?);
    try testing.expectEqualStrings("var/log/auth.log", encoded.getString("path").?);
    try testing.expectEqualStrings("n-7", encoded.getString("node_id").?);
    try testing.expectEqual(@as(u64, 4096), encoded.getUint("offset").?);
    try testing.expectEqual(@as(u64, 512), encoded.getUint("length").?);
    try testing.expectEqualStrings("line 12", encoded.getString("note").?);

    const empty = try (SourceRef{}).toValue(alloc);
    try testing.expectEqual(@as(usize, 0), empty.map.len);
}

test "dynamic records follow their schema" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const fields = [_]schema.Field{
        schema.Field.new("name", "名称", .text),
        schema.Field.new("size", "大小", .size),
    };
    const row_schema = schema.RecordSchema.new("test.row", "行", &fields);
    var record = try DynamicRecord.init(alloc, &row_schema);
    record.set("size", .{ .uint = 4 });
    record.set("missing", .{ .string = "ignored" });
    try testing.expectEqual(@as(usize, 2), record.valuesSlice().len);
    try testing.expectEqual(wire.Value.nil, record.valuesSlice()[0]);
    try testing.expectEqual(@as(u64, 4), record.valuesSlice()[1].uint);
}

test "the profile fact schema matches the Rust one byte for byte" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const profile = profileFactSchema();
    try profile.validate();

    // Produced by rmp_serde::to_vec_named(RecordSchema) for
    // RecordSchema::new("profile.fact", "检材画像").title("{key}")
    //   .field(key: Text key).field(value: Json).field(system: Text)
    const expected = [_]u8{
        0x84, 0xa4, 0x74, 0x79, 0x70, 0x65, 0xac, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65,
        0x2e, 0x66, 0x61, 0x63, 0x74, 0xa5, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0xac, 0xe6, 0xa3,
        0x80, 0xe6, 0x9d, 0x90, 0xe7, 0x94, 0xbb, 0xe5, 0x83, 0x8f, 0xa5, 0x74, 0x69, 0x74,
        0x6c, 0x65, 0xa5, 0x7b, 0x6b, 0x65, 0x79, 0x7d, 0xa6, 0x66, 0x69, 0x65, 0x6c, 0x64,
        0x73, 0x93, 0x84, 0xa2, 0x69, 0x64, 0xa3, 0x6b, 0x65, 0x79, 0xa5, 0x6c, 0x61, 0x62,
        0x65, 0x6c, 0xa3, 0xe9, 0x94, 0xae, 0xa4, 0x6b, 0x69, 0x6e, 0x64, 0xa4, 0x74, 0x65,
        0x78, 0x74, 0xa3, 0x6b, 0x65, 0x79, 0xc3, 0x83, 0xa2, 0x69, 0x64, 0xa5, 0x76, 0x61,
        0x6c, 0x75, 0x65, 0xa5, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0xa3, 0xe5, 0x80, 0xbc, 0xa4,
        0x6b, 0x69, 0x6e, 0x64, 0xa4, 0x6a, 0x73, 0x6f, 0x6e, 0x83, 0xa2, 0x69, 0x64, 0xa6,
        0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0xa5, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0xa6, 0xe7,
        0xb3, 0xbb, 0xe7, 0xbb, 0x9f, 0xa4, 0x6b, 0x69, 0x6e, 0x64, 0xa4, 0x74, 0x65, 0x78,
        0x74,
    };
    const encoded = try wire.encode(alloc, try profile.toValue(alloc));
    try testing.expectEqualSlices(u8, &expected, encoded);

    const hash = try schema.schemaHash(alloc, &.{profile});
    try testing.expectEqualStrings("fnv1a64:95fb6f3590dae3ea", hash);
}
