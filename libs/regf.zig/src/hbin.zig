//! Hive-bin management and cell allocation.
//!
//! A hive body is a sequence of **hive bins** (HBIN) of 4096 bytes (or a
//! multiple), each prefixed with a 32-byte header. An HBIN holds
//! variable-sized **cells**: `[i32 size][payload]`, the size being negative
//! when the cell is allocated and positive when it is free. The offsets used
//! within a hive ("data offsets") are relative to the start of the hive bins,
//! i.e. the `REGF_HEADER_SIZE` offset within the buffer.

const std = @import("std");
const errors = @import("error.zig");
const header = @import("header.zig");

const Allocator = std.mem.Allocator;
const Error = errors.Error;
const Diag = errors.Diag;

const HBIN_MAGIC: []const u8 = "hbin";
/// Size of a hive-bin header.
pub const HBIN_HEADER: usize = 0x20;
pub const CELL_ALIGN: usize = 8;
pub const HBIN_GRANULARITY: usize = 0x1000;

/// Rounds `n` up to the next multiple of `align`.
inline fn alignUp(n: usize, alignment: usize) usize {
    return ((n + alignment - 1) / alignment) * alignment;
}

/// Converts a data offset (relative to the hive bins) into an absolute buffer
/// index.
pub inline fn abs(data_offset: u32) usize {
    return header.REGF_HEADER_SIZE + @as(usize, data_offset);
}

/// Converts an absolute buffer index into a data offset.
pub inline fn rel(abs_index: usize) u32 {
    return @intCast(abs_index - header.REGF_HEADER_SIZE);
}

/// Raw (signed) value of a cell's size field at the absolute index.
fn cellRawSize(data: []const u8, abs_index: usize) Error!i32 {
    if (abs_index + 4 > data.len) {
        return error.Truncated;
    }
    return std.mem.readInt(i32, data[abs_index..][0..4], .little);
}

/// Writes a cell's (signed) size field at the absolute index.
fn writeSize(data: []u8, abs_index: usize, size: i32) void {
    std.mem.writeInt(i32, data[abs_index..][0..4], size, .little);
}

/// Reads a hive bin's declared size at its absolute start, or null when the
/// header is not a usable HBIN.
fn hbinSize(data: []const u8, pos: usize) ?usize {
    if (pos + HBIN_HEADER > data.len) return null;
    if (!std.mem.eql(u8, data[pos..][0..4], HBIN_MAGIC)) return null;
    const size = std.mem.readInt(u32, data[pos + 8 ..][0..4], .little);
    if (size == 0) return null;
    return @intCast(size);
}

/// Allocates a cell able to hold `payload_len` payload bytes and returns its
/// data offset. Reuses a free cell (first fit, splitting the remainder) or
/// grows the hive by a new HBIN.
///
/// The payload contents are left untouched: the caller writes them via
/// [`payloadMut`]. The size field is set (negative = allocated).
pub fn allocate(
    data: *std.ArrayList(u8),
    gpa: Allocator,
    hive_bins_size: *u32,
    payload_len: usize,
    diag: ?*Diag,
) Error!u32 {
    const need = alignUp(4 + payload_len, CELL_ALIGN);

    // 1. First-fit search among the free cells.
    const found = firstFit(data.items, hive_bins_size.*, need) catch |e| {
        errors.setOffset(diag, 0);
        return e;
    };
    if (found) |cur| {
        splitAndOccupy(data.items, cur, cellSizeAt(data.items, cur), need);
        return rel(cur);
    }

    // 2. No room: append a new HBIN at the end.
    const new_hbin_size = alignUp(HBIN_HEADER + need, HBIN_GRANULARITY);
    const hbin_data_offset = hive_bins_size.*;
    const base = data.items.len;
    try data.resize(gpa, base + new_hbin_size);
    const buf = data.items;
    @memset(buf[base .. base + new_hbin_size], 0);

    // HBIN header.
    @memcpy(buf[base..][0..4], HBIN_MAGIC);
    std.mem.writeInt(u32, buf[base + 4 ..][0..4], hbin_data_offset, .little);
    std.mem.writeInt(u32, buf[base + 8 ..][0..4], @intCast(new_hbin_size), .little);

    // Allocated cell.
    const cell = base + HBIN_HEADER;
    writeSize(buf, cell, -@as(i32, @intCast(need)));

    // Optional free remainder.
    const leftover = new_hbin_size - HBIN_HEADER - need;
    if (leftover >= CELL_ALIGN) {
        writeSize(buf, cell + need, @intCast(leftover));
    }
    hive_bins_size.* += @intCast(new_hbin_size);
    return rel(cell);
}

fn cellSizeAt(data: []const u8, abs_index: usize) usize {
    const raw = std.mem.readInt(i32, data[abs_index..][0..4], .little);
    return @intCast(@abs(raw));
}

/// Returns the absolute index of the first free cell that fits `need`.
fn firstFit(data: []const u8, hive_bins_size: u32, need: usize) Error!?usize {
    const end = @min(header.REGF_HEADER_SIZE + @as(usize, hive_bins_size), data.len);
    var pos = header.REGF_HEADER_SIZE;
    while (pos + HBIN_HEADER <= end) {
        const size = hbinSize(data, pos) orelse return null;
        const hbin_end = @min(pos + size, data.len);
        var cur = pos + HBIN_HEADER;
        while (cur + 4 <= hbin_end) {
            const raw = try cellRawSize(data, cur);
            const cell_size = @abs(raw);
            if (cell_size < 4 or cur + cell_size > hbin_end) break; // inconsistent: skip the HBIN
            if (raw > 0 and cell_size >= need) return cur;
            cur += cell_size;
        }
        pos += size;
    }
    return null;
}

/// Occupies a free cell of size `size` at `abs_index`, splitting the remainder
/// into a new free cell when it is usable.
fn splitAndOccupy(data: []u8, abs_index: usize, size: usize, need: usize) void {
    const leftover = size - need;
    if (leftover >= CELL_ALIGN) {
        writeSize(data, abs_index, -@as(i32, @intCast(need)));
        writeSize(data, abs_index + need, @intCast(leftover));
    } else {
        // Remainder too small: keep the whole cell (allocated).
        writeSize(data, abs_index, -@as(i32, @intCast(size)));
    }
}

/// Frees the cell at the given data offset, merging with the following cell
/// when it is free and belongs to the same HBIN (forward coalescing).
pub fn free(data: []u8, data_offset: u32, hive_bins_size: u32, diag: ?*Diag) Error!void {
    const idx = abs(data_offset);
    const raw = cellRawSize(data, idx) catch {
        errors.setOffset(diag, idx);
        return error.Truncated;
    };
    var size: usize = @intCast(@abs(raw));
    // A hostile cell can claim a size that does not fit a positive i32 (the
    // free marker) or that runs past the buffer; neither can be coalesced
    // into a legal free cell.
    if (size < 4 or size > std.math.maxInt(i32) or idx + size > data.len) {
        errors.setOffset(diag, idx);
        return error.CorruptCell;
    }
    const hbin_end = enclosingHbinEnd(data, idx, hive_bins_size);

    // Forward coalescing: while the following cell is free.
    var next = idx + size;
    while (next + 4 <= hbin_end) {
        const nraw = cellRawSize(data, next) catch break;
        if (nraw <= 0) break; // occupied
        const nsize: usize = @intCast(nraw);
        // Stop before the merged run stops being representable as a cell.
        if (nsize < 4 or size + nsize > std.math.maxInt(i32)) break;
        size += nsize;
        next = idx + size;
    }
    writeSize(data, idx, @intCast(size)); // positive = free
}

/// Absolute end of the HBIN containing the given index.
fn enclosingHbinEnd(data: []const u8, idx: usize, hive_bins_size: u32) usize {
    const end = @min(header.REGF_HEADER_SIZE + @as(usize, hive_bins_size), data.len);
    var pos = header.REGF_HEADER_SIZE;
    while (pos + HBIN_HEADER <= end) {
        const size = hbinSize(data, pos) orelse return data.len;
        if (idx >= pos and idx < pos + size) return @min(pos + size, data.len);
        pos += size;
    }
    return data.len;
}

/// Mutable access to an allocated cell's payload (excluding the size field).
pub fn payloadMut(data: []u8, data_offset: u32, diag: ?*Diag) Error![]u8 {
    const idx = abs(data_offset);
    const raw = cellRawSize(data, idx) catch {
        errors.setOffset(diag, idx);
        return error.Truncated;
    };
    const size: usize = @intCast(@abs(raw));
    if (size < 4 or idx + size > data.len) {
        errors.setOffset(diag, idx);
        return error.CorruptCell;
    }
    return data[idx + 4 .. idx + size];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Builds a hive body with a single empty HBIN, mirroring `Hive.initEmpty`.
fn freshBody(gpa: Allocator) !std.ArrayList(u8) {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(gpa);
    try body.resize(gpa, header.REGF_HEADER_SIZE + HBIN_GRANULARITY);
    @memset(body.items, 0);
    const hb = header.REGF_HEADER_SIZE;
    @memcpy(body.items[hb..][0..4], HBIN_MAGIC);
    std.mem.writeInt(u32, body.items[hb + 4 ..][0..4], 0, .little);
    std.mem.writeInt(u32, body.items[hb + 8 ..][0..4], HBIN_GRANULARITY, .little);
    const cell = hb + HBIN_HEADER;
    writeSize(body.items, cell, @intCast(HBIN_GRANULARITY - HBIN_HEADER));
    return body;
}

test "abs and rel are inverse" {
    try testing.expectEqual(@as(usize, 0x1000), abs(0));
    try testing.expectEqual(@as(u32, 0), rel(0x1000));
    try testing.expectEqual(@as(u32, 0x20), rel(abs(0x20)));
}

test "first allocation splits the initial free cell" {
    const gpa = testing.allocator;
    var body = try freshBody(gpa);
    defer body.deinit(gpa);
    var bins: u32 = HBIN_GRANULARITY;

    const off = try allocate(&body, gpa, &bins, 12, null);
    try testing.expectEqual(@as(u32, 0x20), off);
    // The new cell is 16 bytes (4 + 12, aligned); the remainder stays free.
    try testing.expectEqual(@as(i32, -16), std.mem.readInt(i32, body.items[0x1020..][0..4], .little));
    try testing.expectEqual(
        @as(i32, @intCast(HBIN_GRANULARITY - HBIN_HEADER - 16)),
        std.mem.readInt(i32, body.items[0x1030..][0..4], .little),
    );
    try testing.expectEqual(@as(u32, HBIN_GRANULARITY), bins);
}

test "allocation reuses a freed cell" {
    const gpa = testing.allocator;
    var body = try freshBody(gpa);
    defer body.deinit(gpa);
    var bins: u32 = HBIN_GRANULARITY;

    const a = try allocate(&body, gpa, &bins, 8, null);
    const b = try allocate(&body, gpa, &bins, 8, null);
    try testing.expect(a != b);

    try free(body.items, a, bins, null);
    const again = try allocate(&body, gpa, &bins, 8, null);
    try testing.expectEqual(a, again);
    try testing.expectEqual(bins, HBIN_GRANULARITY); // no growth
}

test "freeing coalesces forward" {
    const gpa = testing.allocator;
    var body = try freshBody(gpa);
    defer body.deinit(gpa);
    var bins: u32 = HBIN_GRANULARITY;

    const a = try allocate(&body, gpa, &bins, 8, null);
    const b = try allocate(&body, gpa, &bins, 8, null);
    const c = try allocate(&body, gpa, &bins, 8, null);

    try free(body.items, b, bins, null);
    // Freeing `a` must merge with the now-free `b`.
    try free(body.items, a, bins, null);
    const merged = std.mem.readInt(i32, body.items[abs(a)..][0..4], .little);
    try testing.expectEqual(@as(i32, 32), merged); // two 16-byte cells

    // A large allocation that only fits in the merged run reuses `a`.
    const big = try allocate(&body, gpa, &bins, 20, null);
    try testing.expectEqual(a, big);
    _ = c;
}

test "growth appends a new hbin when nothing fits" {
    const gpa = testing.allocator;
    var body = try freshBody(gpa);
    defer body.deinit(gpa);
    var bins: u32 = HBIN_GRANULARITY;

    // Fill the first HBIN completely.
    _ = try allocate(&body, gpa, &bins, HBIN_GRANULARITY - HBIN_HEADER - 4, null);
    try testing.expectEqual(@as(u32, HBIN_GRANULARITY), bins);

    const off = try allocate(&body, gpa, &bins, 64, null);
    try testing.expectEqual(@as(u32, 2 * HBIN_GRANULARITY), bins);
    try testing.expectEqual(@as(usize, header.REGF_HEADER_SIZE + 2 * HBIN_GRANULARITY), body.items.len);
    // The second HBIN header points back at its own data offset.
    const pos = header.REGF_HEADER_SIZE + HBIN_GRANULARITY;
    try testing.expectEqualSlices(u8, "hbin", body.items[pos..][0..4]);
    try testing.expectEqual(
        @as(u32, HBIN_GRANULARITY),
        std.mem.readInt(u32, body.items[pos + 4 ..][0..4], .little),
    );
    try testing.expectEqual(rel(pos + HBIN_HEADER), off);
}

test "payloadMut rejects an out-of-range offset" {
    const gpa = testing.allocator;
    var body = try freshBody(gpa);
    defer body.deinit(gpa);
    var bins: u32 = HBIN_GRANULARITY;
    _ = try allocate(&body, gpa, &bins, 8, null);

    var diag: Diag = .{};
    try testing.expectError(error.Truncated, payloadMut(body.items, 0xFFFF_0000, &diag));
    try testing.expectEqual(@as(usize, abs(0xFFFF_0000)), diag.offset);
}

test "payloadMut returns exactly the payload" {
    const gpa = testing.allocator;
    var body = try freshBody(gpa);
    defer body.deinit(gpa);
    var bins: u32 = HBIN_GRANULARITY;

    const off = try allocate(&body, gpa, &bins, 12, null);
    const p = try payloadMut(body.items, off, null);
    try testing.expectEqual(@as(usize, 12), p.len);
    p[0] = 0xAA;
    try testing.expectEqual(@as(u8, 0xAA), body.items[abs(off) + 4]);
}

