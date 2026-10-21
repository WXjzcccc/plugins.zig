//! Errors raised when reading or writing a REGF hive.
//!
//! Zig error sets cannot carry payloads, so the diagnostic details that the
//! Rust reference exposes as enum fields (`Truncated { offset }`,
//! `BadChecksum { expected, found }`, ...) travel through an optional
//! [`Diag`] out-parameter. Callers that do not care pass `null`.

const std = @import("std");

pub const Error = error{
    /// Base block signature missing ("regf" expected).
    BadSignature,
    /// Invalid header checksum.
    BadChecksum,
    /// Truncated buffer: out-of-bounds read at the given offset.
    Truncated,
    /// Inconsistent cell (size or signature).
    CorruptCell,
    /// Key missing at the requested path.
    KeyNotFound,
    /// Value missing under the requested key.
    ValueNotFound,
    /// Write rejected: the hive was not cleanly closed
    /// (diverging sequence numbers, pending transaction log).
    DirtyHive,
    /// Value data too large for the current write implementation
    /// ("big data" segments are not produced on write).
    ValueTooLarge,
    /// Allocation failure.
    OutOfMemory,
};

/// Diagnostic payload accompanying an [`Error`]. Only the fields relevant to
/// the error that was raised are meaningful.
pub const Diag = struct {
    /// Byte offset of the failure (`Truncated`, `CorruptCell`).
    offset: usize = 0,
    /// Checksum the header claims (`BadChecksum`).
    expected: u32 = 0,
    /// Checksum actually computed over the header (`BadChecksum`).
    found: u32 = 0,
    /// Size of the rejected value (`ValueTooLarge`).
    size: usize = 0,
    /// Largest size accepted on write (`ValueTooLarge`).
    max: usize = 0,
};

/// Stores `d` into the caller's diagnostic slot, if any.
pub inline fn set(diag: ?*Diag, d: Diag) void {
    if (diag) |p| p.* = d;
}

/// Sets only the `offset` field of the diagnostic slot.
pub inline fn setOffset(diag: ?*Diag, offset: usize) void {
    set(diag, .{ .offset = offset });
}

/// Renders the error the way the Rust `Display` impl does, into `buf`.
/// Returns the written slice, or a short fallback if `buf` is too small.
pub fn describe(err: Error, d: Diag, buf: []u8) []const u8 {
    const written = switch (err) {
        error.BadSignature => std.fmt.bufPrint(buf, "missing REGF signature (expected \"regf\")", .{}),
        error.BadChecksum => std.fmt.bufPrint(
            buf,
            "invalid header checksum: expected 0x{x:0>8}, found 0x{x:0>8}",
            .{ d.expected, d.found },
        ),
        error.Truncated => std.fmt.bufPrint(buf, "buffer truncated at offset {d}", .{d.offset}),
        error.CorruptCell => std.fmt.bufPrint(buf, "corrupt cell at offset {d}", .{d.offset}),
        error.KeyNotFound => std.fmt.bufPrint(buf, "key not found", .{}),
        error.ValueNotFound => std.fmt.bufPrint(buf, "value not found", .{}),
        error.DirtyHive => std.fmt.bufPrint(
            buf,
            "unreconciled hive (pending transaction log): write rejected",
            .{},
        ),
        error.ValueTooLarge => std.fmt.bufPrint(
            buf,
            "value of {d} bytes is too large (max {d} on write)",
            .{ d.size, d.max },
        ),
        error.OutOfMemory => std.fmt.bufPrint(buf, "out of memory", .{}),
    };
    return written catch "error";
}

test "describe covers every error" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "missing REGF signature (expected \"regf\")",
        describe(error.BadSignature, .{}, &buf),
    );
    try std.testing.expectEqualStrings(
        "invalid header checksum: expected 0x0000000a, found 0x0000000b",
        describe(error.BadChecksum, .{ .expected = 10, .found = 11 }, &buf),
    );
    try std.testing.expectEqualStrings(
        "buffer truncated at offset 4096",
        describe(error.Truncated, .{ .offset = 4096 }, &buf),
    );
    try std.testing.expectEqualStrings(
        "corrupt cell at offset 32",
        describe(error.CorruptCell, .{ .offset = 32 }, &buf),
    );
    try std.testing.expectEqualStrings(
        "value of 20000 bytes is too large (max 16344 on write)",
        describe(error.ValueTooLarge, .{ .size = 20000, .max = 16344 }, &buf),
    );
    try std.testing.expectEqualStrings("out of memory", describe(error.OutOfMemory, .{}, &buf));
}

test "diag slot is optional" {
    var d: Diag = .{};
    setOffset(&d, 7);
    try std.testing.expectEqual(@as(usize, 7), d.offset);
    setOffset(null, 9); // must not crash
}
