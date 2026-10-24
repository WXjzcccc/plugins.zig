const std = @import("std");
const cursor_mod = @import("cursor.zig");

pub const Cursor = cursor_mod.Cursor;

pub const minimum_size = 8;

pub const Error = Cursor.Error || error{
    InvalidValueSize,
    NonZeroReservedByte,
    TrailingData,
};

pub const DataType = enum(u8) {
    null_value = 0x00,
    reference = 0x01,
    attribute = 0x02,
    string = 0x03,
    float_value = 0x04,
    dimension = 0x05,
    fraction = 0x06,
    dynamic_reference = 0x07,
    dynamic_attribute = 0x08,

    int_decimal = 0x10,
    int_hexadecimal = 0x11,
    int_boolean = 0x12,

    color_argb8 = 0x1c,
    color_rgb8 = 0x1d,
    color_argb4 = 0x1e,
    color_rgb4 = 0x1f,

    _,
};

pub const DimensionUnit = enum(u4) {
    px = 0,
    dp = 1,
    sp = 2,
    pt = 3,
    inch = 4,
    mm = 5,
    _,
};

pub const FractionUnit = enum(u4) {
    fraction = 0,
    fraction_parent = 1,
    _,
};

pub const Dimension = struct {
    value: f32,
    unit: DimensionUnit,
};

pub const Fraction = struct {
    value: f32,
    unit: FractionUnit,
};

/// Decoded fixed header of Android's `Res_value`.
///
/// Unknown data type bytes are retained by the non-exhaustive `DataType` enum,
/// allowing callers to inspect newer Android value kinds without losing data.
pub const Value = struct {
    size: u16,
    data_type: DataType,
    data: u32,

    pub fn stringIndex(self: Value) ?u32 {
        return if (self.data_type == .string) self.data else null;
    }

    pub fn referenceId(self: Value) ?u32 {
        return switch (self.data_type) {
            .reference, .dynamic_reference => self.data,
            else => null,
        };
    }

    pub fn attributeId(self: Value) ?u32 {
        return switch (self.data_type) {
            .attribute, .dynamic_attribute => self.data,
            else => null,
        };
    }

    pub fn boolValue(self: Value) ?bool {
        if (self.data_type != .int_boolean) return null;
        return self.data != 0;
    }

    pub fn intValue(self: Value) ?i32 {
        return switch (self.data_type) {
            .int_decimal, .int_hexadecimal => @bitCast(self.data),
            else => null,
        };
    }

    pub fn floatValue(self: Value) ?f32 {
        if (self.data_type != .float_value) return null;
        return @bitCast(self.data);
    }

    pub fn dimensionValue(self: Value) ?Dimension {
        if (self.data_type != .dimension) return null;
        return .{
            .value = complexToFloat(self.data),
            .unit = @fromBackingInt(@intCast(@as(u4, @truncate(self.data)))),
        };
    }

    pub fn fractionValue(self: Value) ?Fraction {
        if (self.data_type != .fraction) return null;
        return .{
            .value = complexToFloat(self.data),
            .unit = @fromBackingInt(@intCast(@as(u4, @truncate(self.data)))),
        };
    }
};

/// Reads one `Res_value` transactionally, including any future extension bytes
/// described by its size field. On failure, `cursor` is not advanced.
pub fn read(cursor: *Cursor) Error!Value {
    var candidate = cursor.*;

    const size = try candidate.readInt(u16, .little);
    if (size < minimum_size) return error.InvalidValueSize;

    const reserved = try candidate.readByte();
    if (reserved != 0) return error.NonZeroReservedByte;

    const data_type: DataType = @fromBackingInt(@intCast(try candidate.readByte()));
    const data = try candidate.readInt(u32, .little);
    try candidate.skip(@as(usize, size - minimum_size));

    cursor.* = candidate;
    return .{ .size = size, .data_type = data_type, .data = data };
}

pub fn parse(data: []const u8) Error!Value {
    var cursor = Cursor.init(data);
    const value = try read(&cursor);
    if (!cursor.atEnd()) return error.TrailingData;
    return value;
}

/// Converts Android's signed 23.8 complex representation to a scalar.
pub fn complexToFloat(data: u32) f32 {
    const radix_multipliers = [4]f32{
        1.0 / 256.0,
        1.0 / 32768.0,
        1.0 / 8388608.0,
        1.0 / 2147483648.0,
    };
    const mantissa: i32 = @bitCast(data & 0xffff_ff00);
    const radix: usize = @intCast((data >> 4) & 0x3);
    return @as(f32, @floatFromInt(mantissa)) * radix_multipliers[radix];
}

test "typed value parses primitive kinds" {
    const boolean_bytes = [_]u8{ 8, 0, 0, 0x12, 1, 0, 0, 0 };
    const boolean = try parse(&boolean_bytes);
    try std.testing.expectEqual(DataType.int_boolean, boolean.data_type);
    try std.testing.expectEqual(true, boolean.boolValue().?);
    try std.testing.expect(boolean.intValue() == null);

    const negative_int_bytes = [_]u8{ 8, 0, 0, 0x10, 0xfe, 0xff, 0xff, 0xff };
    try std.testing.expectEqual(@as(i32, -2), (try parse(&negative_int_bytes)).intValue().?);
}

test "typed value decodes float and complex units" {
    var float_bytes = [_]u8{ 8, 0, 0, 0x04, 0, 0, 0, 0 };
    std.mem.writeInt(u32, float_bytes[4..8], @bitCast(@as(f32, 3.5)), .little);
    try std.testing.expectApproxEqAbs(@as(f32, 3.5), (try parse(&float_bytes)).floatValue().?, 0.0001);

    // Mantissa 0x100 with radix 0 represents 1.0; low nibble 1 is dp.
    const dimension_bytes = [_]u8{ 8, 0, 0, 0x05, 0x01, 0x01, 0, 0 };
    const dimension = (try parse(&dimension_bytes)).dimensionValue().?;
    try std.testing.expectApproxEqAbs(@as(f32, 1.0), dimension.value, 0.0001);
    try std.testing.expectEqual(DimensionUnit.dp, dimension.unit);
}

test "typed value rejects malformed sizes without advancing" {
    const bytes = [_]u8{ 7, 0, 0, 0x12, 1, 0, 0, 0 };
    var cursor = Cursor.init(&bytes);
    try std.testing.expectError(error.InvalidValueSize, read(&cursor));
    try std.testing.expectEqual(@as(usize, 0), cursor.offset());

    const extended_but_truncated = [_]u8{ 12, 0, 0, 0x10, 1, 0, 0, 0 };
    try std.testing.expectError(error.EndOfInput, parse(&extended_but_truncated));
}
