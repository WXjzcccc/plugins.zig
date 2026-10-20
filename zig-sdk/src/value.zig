//! MessagePack payload helpers for LPP params and replies.
//!
//! These mirror the Rust SDK's `value` module: field lookup with the LPP
//! error codes, `nil` for optional fields, and the reply shapes the protocol
//! uses for byte data.

const std = @import("std");

const wire = @import("wire.zig");
const sdk = @import("error.zig");

pub const Value = wire.Value;
pub const Entry = wire.Entry;
pub const Error = sdk.Error;

pub const Range = struct {
    offset: u64,
    length: usize,
};

pub fn entry(key: []const u8, item: Value) Entry {
    return wire.entry(key, item);
}

pub fn str(text: []const u8) Value {
    return wire.str(text);
}

pub fn uint(number: u64) Value {
    return wire.uint(number);
}

pub fn boolean(flag: bool) Value {
    return .{ .boolean = flag };
}

pub fn bytes(data: []const u8) Value {
    return .{ .bytes = data };
}

/// Copies `items` into `alloc`; see `wire.mapOf`.
pub fn map(alloc: std.mem.Allocator, items: []const Entry) Error!Value {
    return wire.mapOf(alloc, items) catch |err| return encodeFault(err);
}

/// Copies `items` into `alloc`; see `wire.arrayOf`.
pub fn array(alloc: std.mem.Allocator, items: []const Value) Error!Value {
    return wire.arrayOf(alloc, items) catch |err| return encodeFault(err);
}

/// The codec's errors are not the SDK's: out of memory stays out of memory and
/// the rest becomes a protocol fault, so every caller keeps one error set.
fn encodeFault(err: wire.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => sdk.fail("PROTOCOL_ERROR", "could not build a MessagePack value"),
    };
}

/// The value of `key` in a map; `null` for a missing key or a non-map.
pub fn get(value: Value, key: []const u8) ?Value {
    return value.get(key);
}

pub fn requiredStr(value: Value, key: []const u8) Error![]const u8 {
    const found = get(value, key) orelse
        return sdk.failfmt("INVALID_PARAMS", "{s} is missing", .{key});
    return switch (found) {
        .string => |text| text,
        else => sdk.failfmt("INVALID_PARAMS", "{s} must be a string", .{key}),
    };
}

pub fn requiredUint(value: Value, key: []const u8) Error!u64 {
    const found = get(value, key) orelse
        return sdk.failfmt("INVALID_PARAMS", "{s} is missing", .{key});
    return switch (found) {
        .uint => |number| number,
        else => sdk.failfmt("INVALID_PARAMS", "{s} must be an unsigned integer", .{key}),
    };
}

/// A string field that may be missing or `nil`.
pub fn optionalStr(value: Value, key: []const u8) ?[]const u8 {
    return value.getString(key);
}

pub fn optionalUint(value: Value, key: []const u8) ?u64 {
    return value.getUint(key);
}

pub fn optionalString(text: ?[]const u8) Value {
    return if (text) |slice| .{ .string = slice } else .nil;
}

pub fn optionalUintValue(number: ?u64) Value {
    return if (number) |value| .{ .uint = value } else .nil;
}

pub fn optionalBool(flag: ?bool) Value {
    return if (flag) |value| .{ .boolean = value } else .nil;
}

pub fn optionalFloat(number: ?f64) Value {
    return if (number) |value| .{ .float = value } else .nil;
}

/// Binary replies become a byte slice. The slice is owned by the reply buffer
/// and is only valid until the call that produced it returns.
pub fn intoBytes(value: Value, method: []const u8) Error![]const u8 {
    return switch (value) {
        .bytes => |data| data,
        else => sdk.failfmt(
            "PROTOCOL_ERROR",
            "{s} result must be MessagePack binary",
            .{method},
        ),
    };
}

/// An array of binaries, as `source.readv`, `file.readv` and `evidence.readv`
/// return. The list is allocated from `alloc`; the slices point into the
/// reply buffer.
pub fn intoByteList(
    alloc: std.mem.Allocator,
    value: Value,
    method: []const u8,
) Error![][]const u8 {
    const items = switch (value) {
        .array => |entries| entries,
        else => return sdk.failfmt(
            "PROTOCOL_ERROR",
            "{s} result must be an array of binaries",
            .{method},
        ),
    };
    const out = try alloc.alloc([]const u8, items.len);
    for (items, out) |item, *slot| slot.* = try intoBytes(item, method);
    return out;
}

/// `[[offset, length], ...]`, the shape `source.readv`, `file.readv` and
/// `evidence.readv` expect.
pub fn ranges(alloc: std.mem.Allocator, items: []const Range) Error!Value {
    const encoded = try alloc.alloc(Value, items.len);
    for (items, encoded) |item, *slot| {
        const pair = try alloc.alloc(Value, 2);
        pair[0] = .{ .uint = item.offset };
        pair[1] = .{ .uint = item.length };
        slot.* = .{ .array = pair };
    }
    return .{ .array = encoded };
}

const testing = std.testing;

test "required and optional field access" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const payload = try map(alloc, &.{
        entry("name", str("文件")),
        entry("size", uint(5)),
        entry("data", bytes(&.{ 1, 2 })),
        entry("missing", .nil),
    });

    try testing.expectEqualStrings("文件", try requiredStr(payload, "name"));
    try testing.expectEqual(@as(u64, 5), try requiredUint(payload, "size"));
    try testing.expectEqualStrings("文件", optionalStr(payload, "name").?);
    try testing.expectEqual(null, optionalStr(payload, "missing"));
    try testing.expectEqual(null, optionalUint(payload, "missing"));
    try testing.expectEqualSlices(
        u8,
        &.{ 1, 2 },
        try intoBytes(get(payload, "data").?, "test"),
    );

    // The wrong type is reported with its LPP code, not silently coerced.
    try testing.expectError(error.Fault, requiredUint(payload, "name"));
    try testing.expectEqualStrings("INVALID_PARAMS", sdk.codeOf(error.Fault));
    try testing.expectEqualStrings("name must be an unsigned integer", sdk.messageOf(error.Fault));
    try testing.expectError(error.Fault, requiredStr(payload, "size"));
    _ = sdk.take();
}

test "ranges encode as offset/length pairs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const encoded = try ranges(arena.allocator(), &.{
        .{ .offset = 4096, .length = 512 },
        .{ .offset = 0, .length = 16 },
    });
    try testing.expectEqual(@as(usize, 2), encoded.array.len);
    try testing.expectEqual(@as(u64, 4096), encoded.array[0].array[0].uint);
    try testing.expectEqual(@as(u64, 512), encoded.array[0].array[1].uint);
}

test "byte list replies are validated" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const reply = try array(alloc, &.{ bytes(&.{1}), bytes(&.{ 2, 3 }) });
    const chunks = try intoByteList(alloc, reply, "source.readv");
    try testing.expectEqual(@as(usize, 2), chunks.len);
    try testing.expectEqualSlices(u8, &.{ 2, 3 }, chunks[1]);

    try testing.expectError(error.Fault, intoByteList(alloc, uint(1), "source.readv"));
    _ = sdk.take();
}
