//! The REGF base block: the 4096-byte header preceding the hive bins.

const std = @import("std");
const errors = @import("error.zig");

const Error = errors.Error;
const Diag = errors.Diag;

/// REGF base block size (and start offset of the hive bins).
pub const REGF_HEADER_SIZE: usize = 0x1000;

const SIGNATURE: []const u8 = "regf";
const OFF_PRIMARY_SEQ: usize = 0x04;
const OFF_SECONDARY_SEQ: usize = 0x08;
const OFF_MAJOR: usize = 0x14;
const OFF_MINOR: usize = 0x18;
const OFF_ROOT_CELL: usize = 0x24;
const OFF_HIVE_BINS_SIZE: usize = 0x28;
const OFF_CHECKSUM: usize = 0x1FC;
/// Number of 32-bit words covered by the checksum (508 bytes).
const CHECKSUM_WORDS: usize = 127;

/// A hive base block: the 4096-byte header preceding the hive bins.
pub const Header = struct {
    primary_sequence: u32,
    secondary_sequence: u32,
    major_version: u32,
    minor_version: u32,
    root_cell_offset: u32,
    hive_bins_size: u32,

    /// Parses and validates a base block (signature + checksum).
    pub fn parse(data: []const u8, diag: ?*Diag) Error!Header {
        if (data.len < REGF_HEADER_SIZE) {
            errors.setOffset(diag, REGF_HEADER_SIZE);
            return error.Truncated;
        }
        if (!std.mem.eql(u8, data[0..4], SIGNATURE)) {
            errors.setOffset(diag, 0);
            return error.BadSignature;
        }
        const expected = checksum(data);
        const found = rd(data, OFF_CHECKSUM);
        if (expected != found) {
            errors.set(diag, .{ .offset = OFF_CHECKSUM, .expected = expected, .found = found });
            return error.BadChecksum;
        }
        return parseUnchecked(data);
    }

    /// Parses the header without verifying the checksum. Reserved for the
    /// internal construction of a hive being assembled (checksum not yet
    /// computed).
    pub fn parseUnchecked(data: []const u8) Header {
        return .{
            .primary_sequence = rd(data, OFF_PRIMARY_SEQ),
            .secondary_sequence = rd(data, OFF_SECONDARY_SEQ),
            .major_version = rd(data, OFF_MAJOR),
            .minor_version = rd(data, OFF_MINOR),
            .root_cell_offset = rd(data, OFF_ROOT_CELL),
            .hive_bins_size = rd(data, OFF_HIVE_BINS_SIZE),
        };
    }

    /// A hive is "dirty" when its two sequence numbers differ: it was
    /// interrupted mid-write and a transaction log remains to be replayed.
    /// Writing to it without reconciliation would corrupt it.
    pub fn isDirty(self: Header) bool {
        return self.primary_sequence != self.secondary_sequence;
    }

    /// REGF checksum: XOR of the first 127 32-bit words (bytes 0..508),
    /// with 0 mapped to 1 and 0xFFFF_FFFF mapped to 0xFFFF_FFFE.
    pub fn checksum(data: []const u8) u32 {
        var sum: u32 = 0;
        for (0..CHECKSUM_WORDS) |i| {
            sum ^= rd(data, i * 4);
        }
        return switch (sum) {
            0 => 1,
            0xFFFF_FFFF => 0xFFFF_FFFE,
            else => sum,
        };
    }

    /// Rewrites into `data` the header fields that may have changed (hive bins
    /// size, sequences), bumps the sequence counter to mark a new consistent
    /// transaction, then recomputes the checksum. Call after any modification,
    /// before serialization.
    pub fn finalize(self: *Header, data: []u8) void {
        const next = self.primary_sequence +% 1;
        self.primary_sequence = next;
        self.secondary_sequence = next; // equal => clean hive
        wr(data, OFF_PRIMARY_SEQ, next);
        wr(data, OFF_SECONDARY_SEQ, next);
        wr(data, OFF_HIVE_BINS_SIZE, self.hive_bins_size);
        const sum = checksum(data);
        wr(data, OFF_CHECKSUM, sum);
    }
};

inline fn rd(data: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, data[off..][0..4], .little);
}

inline fn wr(data: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, data[off..][0..4], v, .little);
}

test "parse rejects a short buffer" {
    var short: [16]u8 = @splat(0);
    var diag: Diag = .{};
    try std.testing.expectError(error.Truncated, Header.parse(&short, &diag));
    try std.testing.expectEqual(REGF_HEADER_SIZE, diag.offset);
}

test "parse rejects a bad signature" {
    var data: [REGF_HEADER_SIZE]u8 = @splat(0);
    @memcpy(data[0..4], "nope");
    try std.testing.expectError(error.BadSignature, Header.parse(&data, null));
}

test "checksum round-trips through finalize" {
    var data: [REGF_HEADER_SIZE]u8 = @splat(0);
    @memcpy(data[0..4], "regf");
    // `finalize` only rewrites the sequence numbers, the bins size and the
    // checksum; the rest of the base block is written by the hive builder.
    std.mem.writeInt(u32, data[OFF_ROOT_CELL..][0..4], 0x20, .little);
    std.mem.writeInt(u32, data[OFF_MAJOR..][0..4], 1, .little);
    std.mem.writeInt(u32, data[OFF_MINOR..][0..4], 5, .little);
    var h: Header = .{
        .primary_sequence = 1,
        .secondary_sequence = 1,
        .major_version = 1,
        .minor_version = 5,
        .root_cell_offset = 0x20,
        .hive_bins_size = 0x1000,
    };
    h.finalize(&data);
    const parsed = try Header.parse(&data, null);
    try std.testing.expectEqual(@as(u32, 2), parsed.primary_sequence);
    try std.testing.expectEqual(@as(u32, 2), parsed.secondary_sequence);
    try std.testing.expect(!parsed.isDirty());
    try std.testing.expectEqual(@as(u32, 0x20), parsed.root_cell_offset);
    try std.testing.expectEqual(@as(u32, 0x1000), parsed.hive_bins_size);
    try std.testing.expectEqual(@as(u32, 1), parsed.major_version);
    try std.testing.expectEqual(@as(u32, 5), parsed.minor_version);
}

test "checksum maps the two special values" {
    // All-zero words XOR to 0, which the format maps to 1.
    var zeros: [REGF_HEADER_SIZE]u8 = @splat(0);
    try std.testing.expectEqual(@as(u32, 1), Header.checksum(&zeros));
    // An all-ones header XORs to 0xFFFF_FFFF, mapped to 0xFFFF_FFFE.
    @memset(&zeros, 0xFF);
    try std.testing.expectEqual(@as(u32, 0xFFFF_FFFE), Header.checksum(&zeros));
}

test "dirty detection follows the sequence numbers" {
    const clean: Header = .{
        .primary_sequence = 5,
        .secondary_sequence = 5,
        .major_version = 1,
        .minor_version = 5,
        .root_cell_offset = 0x20,
        .hive_bins_size = 0x1000,
    };
    try std.testing.expect(!clean.isDirty());
    var dirty = clean;
    dirty.secondary_sequence = 4;
    try std.testing.expect(dirty.isDirty());
}


