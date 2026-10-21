//! REGF structures: reading key nodes (`nk`), values (`vk`), subkey lists
//! (`lf`/`lh`/`li`/`ri`) and data (`db`), plus building the payloads used for
//! writing.

const std = @import("std");
const errors = @import("error.zig");
const hbin = @import("hbin.zig");
const name_mod = @import("name.zig");
const value = @import("value.zig");

const Allocator = std.mem.Allocator;
const Error = errors.Error;
const Diag = errors.Diag;
const RegType = value.RegType;

/// Offset value meaning "no cell".
pub const FREE: u32 = 0xFFFF_FFFF;

const FLAG_NK_COMP_NAME: u16 = 0x0020;
const FLAG_VK_COMP_NAME: u16 = 0x0001;
const INLINE_BIT: u32 = 0x8000_0000;

/// Values larger than this are stored as big-data (`db`) records.
pub const BIG_DATA_LIMIT: usize = 16344;

/// Smallest readable `nk` payload (up to and including the name length).
const NK_MIN: usize = 76;
/// Smallest readable `vk` payload (up to and including the name).
const VK_MIN: usize = 20;
/// Smallest readable `sk` payload.
const SK_MIN: usize = 16;

// ---------------------------------------------------------------------------
// Cells
// ---------------------------------------------------------------------------

/// Returns the payload (excluding the size field) of the cell at the data
/// offset.
pub fn cellPayload(data: []const u8, data_offset: u32, diag: ?*Diag) Error![]const u8 {
    const idx = hbin.abs(data_offset);
    if (idx + 4 > data.len) {
        errors.setOffset(diag, idx);
        return error.Truncated;
    }
    const raw = std.mem.readInt(i32, data[idx..][0..4], .little);
    const size: usize = @intCast(@abs(raw));
    if (size < 4 or idx + size > data.len) {
        errors.setOffset(diag, idx);
        return error.CorruptCell;
    }
    return data[idx + 4 .. idx + size];
}

/// Converts a data offset to the absolute index of its cell, for diagnostics.
pub inline fn cellAbs(data_offset: u32) usize {
    return hbin.abs(data_offset);
}

// ---------------------------------------------------------------------------
// Key node (nk)
// ---------------------------------------------------------------------------

pub const KeyNodeRaw = struct {
    /// Owned UTF-8 name.
    name: []u8,
    subkey_count: u32,
    subkey_list_offset: u32,
    value_count: u32,
    value_list_offset: u32,
    security_offset: u32,

    pub fn deinit(self: KeyNodeRaw, gpa: Allocator) void {
        gpa.free(self.name);
    }
};

pub fn readKeyNode(gpa: Allocator, data: []const u8, data_offset: u32, diag: ?*Diag) Error!KeyNodeRaw {
    const p = cellPayload(data, data_offset, diag) catch |e| {
        if (diag != null and diag.?.offset == 0) errors.setOffset(diag, cellAbs(data_offset));
        return e;
    };
    if (p.len < NK_MIN or !std.mem.eql(u8, p[0..2], "nk")) {
        errors.setOffset(diag, cellAbs(data_offset));
        return error.CorruptCell;
    }
    const flags = std.mem.readInt(u16, p[2..4], .little);
    const name_len = std.mem.readInt(u16, p[72..74], .little);
    // The name length is attacker-controlled: it must fit inside the cell.
    if (NK_MIN + @as(usize, name_len) > p.len) {
        errors.setOffset(diag, cellAbs(data_offset));
        return error.CorruptCell;
    }
    const name_bytes = p[NK_MIN .. NK_MIN + @as(usize, name_len)];
    return .{
        .name = try decodeName(gpa, name_bytes, flags & FLAG_NK_COMP_NAME != 0),
        .subkey_count = rd(p, 20),
        .subkey_list_offset = rd(p, 28),
        .value_count = rd(p, 36),
        .value_list_offset = rd(p, 40),
        .security_offset = rd(p, 44),
    };
}

/// Builds the payload of a new leaf `nk` (no subkey, no value). The caller
/// owns the result.
pub fn buildKeyNode(gpa: Allocator, name: []const u8, parent: u32, security: u32) Error![]u8 {
    const ascii = std.unicode.utf8ValidateSlice(name) and isAscii(name);
    const name_bytes = try encodeName(gpa, name, ascii);
    defer gpa.free(name_bytes);

    const p = try gpa.alloc(u8, NK_MIN + name_bytes.len);
    @memset(p, 0);
    @memcpy(p[0..2], "nk");
    const flags: u16 = if (ascii) FLAG_NK_COMP_NAME else 0;
    std.mem.writeInt(u16, p[2..4], flags, .little);
    wr(p, 16, parent);
    wr(p, 20, 0); // subkey count
    wr(p, 28, FREE); // subkey list
    wr(p, 32, FREE); // volatile subkey list
    wr(p, 36, 0); // value count
    wr(p, 40, FREE); // value list
    wr(p, 44, security);
    wr(p, 48, FREE); // class name
    std.mem.writeInt(u16, p[72..74], @intCast(name_bytes.len), .little);
    @memcpy(p[76..], name_bytes);
    return p;
}

/// Sets a `nk` u32 field in place (via its data offset).
pub fn setNkField(data: []u8, nk_offset: u32, field_off: usize, v: u32, diag: ?*Diag) Error!void {
    const p = hbin.payloadMut(data, nk_offset, diag) catch |e| {
        if (diag != null and diag.?.offset == 0) errors.setOffset(diag, cellAbs(nk_offset));
        return e;
    };
    if (field_off + 4 > p.len) {
        errors.setOffset(diag, cellAbs(nk_offset));
        return error.CorruptCell;
    }
    wr(p, field_off, v);
}

pub const NK_SUBKEY_COUNT: usize = 20;
pub const NK_SUBKEY_LIST: usize = 28;
pub const NK_VALUE_COUNT: usize = 36;
pub const NK_VALUE_LIST: usize = 40;

// ---------------------------------------------------------------------------
// Subkey lists (lf / lh / li / ri)
// ---------------------------------------------------------------------------

/// A leaf list's format, preserved across rewrites.
pub const LeafKind = enum { lf, lh, li };

/// One entry of a leaf list: a subkey name plus the `nk` offset it points to.
pub const Entry = struct {
    /// Borrowed: the caller keeps the names alive while building the list.
    name: []const u8,
    offset: u32,
};

/// Maximum `ri` nesting accepted while resolving a subkey list. The format
/// allows an index root to reference leaf lists only (an `ri` may not point at
/// another `ri`), so a handful of levels is already generous; the bound keeps a
/// malicious self-referencing `ri` from exhausting the stack.
const MAX_RI_DEPTH: u8 = 8;

/// Returns the nk offsets of a list (resolving `ri` recursively). The caller
/// owns the returned slice.
pub fn subkeyOffsets(gpa: Allocator, data: []const u8, list_offset: u32, diag: ?*Diag) Error![]u32 {
    return subkeyOffsetsDepth(gpa, data, list_offset, 0, diag);
}

fn subkeyOffsetsDepth(
    gpa: Allocator,
    data: []const u8,
    list_offset: u32,
    depth: u8,
    diag: ?*Diag,
) Error![]u32 {
    if (list_offset == 0 or list_offset == FREE) {
        return gpa.alloc(u32, 0);
    }
    if (depth > MAX_RI_DEPTH) {
        errors.setOffset(diag, cellAbs(list_offset));
        return error.CorruptCell;
    }
    const p = cellPayload(data, list_offset, diag) catch |e| {
        if (diag != null and diag.?.offset == 0) errors.setOffset(diag, cellAbs(list_offset));
        return e;
    };
    if (p.len < 4) {
        errors.setOffset(diag, cellAbs(list_offset));
        return error.CorruptCell;
    }
    const count = std.mem.readInt(u16, p[2..4], .little);

    var out: std.ArrayList(u32) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, count);

    if (std.mem.eql(u8, p[0..2], "lf") or std.mem.eql(u8, p[0..2], "lh")) {
        for (0..count) |i| {
            const o = 4 + i * 8;
            if (o + 4 <= p.len) out.appendAssumeCapacity(rd(p, o));
        }
    } else if (std.mem.eql(u8, p[0..2], "li")) {
        for (0..count) |i| {
            const o = 4 + i * 4;
            if (o + 4 <= p.len) out.appendAssumeCapacity(rd(p, o));
        }
    } else if (std.mem.eql(u8, p[0..2], "ri")) {
        for (0..count) |i| {
            const o = 4 + i * 4;
            if (o + 4 > p.len) continue;
            const sub = try subkeyOffsetsDepth(gpa, data, rd(p, o), depth + 1, diag);
            defer gpa.free(sub);
            try out.appendSlice(gpa, sub);
        }
    } else {
        errors.setOffset(diag, cellAbs(list_offset));
        return error.CorruptCell;
    }
    return out.toOwnedSlice(gpa);
}

/// Detects a list's leaf format (to preserve `lf`/`lh`/`li`). An `ri` list is
/// reported as `lf`, because [`buildLeafList`] flattens `ri` lists.
pub fn leafKind(data: []const u8, list_offset: u32, diag: ?*Diag) Error!LeafKind {
    if (list_offset == 0 or list_offset == FREE) return .lf;
    const p = cellPayload(data, list_offset, diag) catch |e| {
        if (diag != null and diag.?.offset == 0) errors.setOffset(diag, cellAbs(list_offset));
        return e;
    };
    if (p.len >= 2) {
        if (std.mem.eql(u8, p[0..2], "lh")) return .lh;
        if (std.mem.eql(u8, p[0..2], "li")) return .li;
    }
    return .lf;
}

/// Builds a sorted leaf list from `(name, nk_offset)` entries. Entries must
/// already be sorted according to [`name.cmpStr`]. The caller owns the result.
pub fn buildLeafList(gpa: Allocator, kind: LeafKind, entries: []const Entry) Error![]u8 {
    const magic: []const u8 = switch (kind) {
        .lf => "lf",
        .lh => "lh",
        .li => "li",
    };
    const entry_size: usize = if (kind == .li) 4 else 8;
    const p = try gpa.alloc(u8, 4 + entries.len * entry_size);
    @memset(p, 0);
    @memcpy(p[0..2], magic);
    std.mem.writeInt(u16, p[2..4], @intCast(entries.len), .little);
    for (entries, 0..) |e, i| {
        const base = 4 + i * entry_size;
        wr(p, base, e.offset);
        switch (kind) {
            .lf => {
                // Hint: the first 4 ASCII bytes of the name.
                for (0..4) |j| {
                    p[base + 4 + j] = if (j < e.name.len) e.name[j] else 0;
                }
            },
            .lh => wr(p, base + 4, name_mod.lhHash(e.name)),
            .li => {},
        }
    }
    return p;
}

// ---------------------------------------------------------------------------
// Values (vk) and data (inline / db)
// ---------------------------------------------------------------------------

pub const ValueNodeRaw = struct {
    /// Owned UTF-8 name (empty for the default value).
    name: []u8,
    ty: RegType,
    data_size: u32,
    data_offset: u32,
    is_inline: bool,

    pub fn deinit(self: ValueNodeRaw, gpa: Allocator) void {
        gpa.free(self.name);
    }
};

pub fn readValueNode(gpa: Allocator, data: []const u8, vk_offset: u32, diag: ?*Diag) Error!ValueNodeRaw {
    const p = cellPayload(data, vk_offset, diag) catch |e| {
        if (diag != null and diag.?.offset == 0) errors.setOffset(diag, cellAbs(vk_offset));
        return e;
    };
    if (p.len < VK_MIN or !std.mem.eql(u8, p[0..2], "vk")) {
        errors.setOffset(diag, cellAbs(vk_offset));
        return error.CorruptCell;
    }
    const name_len = std.mem.readInt(u16, p[2..4], .little);
    // The name length is attacker-controlled: it must fit inside the cell.
    if (VK_MIN + @as(usize, name_len) > p.len) {
        errors.setOffset(diag, cellAbs(vk_offset));
        return error.CorruptCell;
    }
    const raw_size = rd(p, 4);
    const data_field = rd(p, 8);
    const flags = std.mem.readInt(u16, p[16..18], .little);
    const name = if (name_len == 0)
        try gpa.alloc(u8, 0)
    else blk: {
        const nb = p[VK_MIN .. VK_MIN + @as(usize, name_len)];
        break :blk try decodeName(gpa, nb, flags & FLAG_VK_COMP_NAME != 0);
    };
    return .{
        .name = name,
        .ty = RegType.fromU32(rd(p, 12)),
        .data_size = raw_size & ~INLINE_BIT,
        .data_offset = data_field,
        .is_inline = raw_size & INLINE_BIT != 0,
    };
}

/// Reads all `vk` offsets of a value list. The caller owns the slice.
pub fn valueOffsets(
    gpa: Allocator,
    data: []const u8,
    list_offset: u32,
    count: u32,
    diag: ?*Diag,
) Error![]u32 {
    if (count == 0 or list_offset == 0 or list_offset == FREE) {
        return gpa.alloc(u32, 0);
    }
    const p = cellPayload(data, list_offset, diag) catch |e| {
        if (diag != null and diag.?.offset == 0) errors.setOffset(diag, cellAbs(list_offset));
        return e;
    };
    // `count` comes from the key node and can claim up to 4 billion entries;
    // the list cell bounds what can really be read, and so what is worth
    // allocating.
    const n = @min(@as(usize, count), p.len / 4);
    const out = try gpa.alloc(u32, n);
    for (0..n) |i| out[i] = rd(p, i * 4);
    return out;
}

/// Reassembles a value's raw bytes (handles inline data and `db` big data).
/// The caller owns the result.
pub fn readValueData(gpa: Allocator, data: []const u8, vk: *const ValueNodeRaw, diag: ?*Diag) Error![]u8 {
    const size: usize = vk.data_size;
    if (vk.is_inline) {
        const le = std.mem.toBytes(std.mem.nativeToLittle(u32, vk.data_offset));
        const n = @min(size, 4);
        return gpa.dupe(u8, le[0..n]);
    }
    if (size == 0) return gpa.alloc(u8, 0);

    const cell = cellPayload(data, vk.data_offset, diag) catch |e| {
        if (diag != null and diag.?.offset == 0) errors.setOffset(diag, cellAbs(vk.data_offset));
        return e;
    };
    if (size > BIG_DATA_LIMIT and cell.len >= 8 and std.mem.eql(u8, cell[0..2], "db")) {
        // Big data: "db", segment count, offset of the segment list.
        const segments = std.mem.readInt(u16, cell[2..4], .little);
        const list_off = rd(cell, 4);
        const list = try cellPayload(data, list_off, diag);
        // `size` comes from the value node and can claim up to 2 GiB, while
        // the segments are cells of this hive: it is the real ceiling.
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        try out.ensureTotalCapacity(gpa, @min(size, data.len));
        const n = @min(@as(usize, segments), list.len / 4);
        for (0..n) |i| {
            const seg_off = rd(list, i * 4);
            const seg = try cellPayload(data, seg_off, diag);
            const remaining = size - out.items.len;
            if (remaining == 0) break;
            // A data segment holds at most BIG_DATA_LIMIT bytes; every segment
            // but the last is exactly that long. The cell itself may be padded
            // to the 8-byte cell alignment, so the segment length must be
            // clamped or the padding would be spliced into the value.
            const take = @min(remaining, @min(seg.len, BIG_DATA_LIMIT));
            // Segments may alias one another (the same cell referenced twice),
            // so the sum can exceed the pre-reserved capacity: grow if needed.
            try out.appendSlice(gpa, seg[0..take]);
        }
        if (out.items.len > size) out.shrinkRetainingCapacity(size);
        return out.toOwnedSlice(gpa);
    }
    return gpa.dupe(u8, cell[0..@min(size, cell.len)]);
}

/// Builds a `vk` payload. `data_field` is either a data offset (data stored in
/// a cell) or the inline bytes; `inline`/`size` disambiguate. The caller owns
/// the result.
pub fn buildValueNode(
    gpa: Allocator,
    name: []const u8,
    ty: RegType,
    size: u32,
    data_field: u32,
    is_inline: bool,
) Error![]u8 {
    const ascii = isAscii(name);
    const name_bytes = try encodeName(gpa, name, ascii);
    defer gpa.free(name_bytes);

    const p = try gpa.alloc(u8, VK_MIN + name_bytes.len);
    @memset(p, 0);
    @memcpy(p[0..2], "vk");
    std.mem.writeInt(u16, p[2..4], @intCast(name_bytes.len), .little);
    const raw_size = if (is_inline) size | INLINE_BIT else size;
    wr(p, 4, raw_size);
    wr(p, 8, data_field);
    wr(p, 12, ty.toU32());
    const flags: u16 = if (ascii and name.len != 0) FLAG_VK_COMP_NAME else 0;
    std.mem.writeInt(u16, p[16..18], flags, .little);
    if (name_bytes.len != 0) @memcpy(p[20..], name_bytes);
    return p;
}

// ---------------------------------------------------------------------------
// Security (sk): reference-count increment when sharing
// ---------------------------------------------------------------------------

/// Increments the reference count of a shared `sk` cell.
pub fn incrSecurityRefcount(data: []u8, sk_offset: u32, diag: ?*Diag) Error!void {
    const p = hbin.payloadMut(data, sk_offset, diag) catch |e| {
        if (diag != null and diag.?.offset == 0) errors.setOffset(diag, cellAbs(sk_offset));
        return e;
    };
    if (p.len < SK_MIN or !std.mem.eql(u8, p[0..2], "sk")) {
        errors.setOffset(diag, cellAbs(sk_offset));
        return error.CorruptCell;
    }
    const rc = std.mem.readInt(u32, p[12..16], .little) +% 1;
    std.mem.writeInt(u32, p[12..16], rc, .little);
}

/// Payload of a minimal `sk` cell: a self-relative security descriptor with no
/// DACL. `flink`/`blink`/`refcount` are filled in by the hive builder once the
/// cell's offset is known.
pub fn buildMinSecurity(gpa: Allocator) Error![]u8 {
    // sk: "sk"(2) reserved(2) flink(4) blink(4) refcount(4) sd_size(4) sd(20)
    const p = try gpa.alloc(u8, SK_MIN + 4 + 20);
    @memset(p, 0);
    @memcpy(p[0..2], "sk");
    wr(p, 16, 20); // security descriptor size
    const sd = SK_MIN + 4; // past flink/blink/refcount/sd_size
    p[sd] = 1; // revision
    std.mem.writeInt(u16, p[sd + 2 ..][0..2], 0x8000, .little); // SE_SELF_RELATIVE
    // owner/group/sacl/dacl offsets = 0 (absent)
    return p;
}

// ---------------------------------------------------------------------------
// Name helpers
// ---------------------------------------------------------------------------

/// True when every byte is ASCII (and therefore needs no UTF-16 encoding).
pub fn isAscii(s: []const u8) bool {
    for (s) |b| {
        if (b >= 0x80) return false;
    }
    return true;
}

/// Decodes a stored name: raw bytes when `ascii`, otherwise UTF-16LE code
/// units (lossily). The caller owns the result.
fn decodeName(gpa: Allocator, bytes: []const u8, ascii: bool) Error![]u8 {
    if (ascii) return gpa.dupe(u8, bytes);
    const n = bytes.len / 2;
    const units = try gpa.alloc(u16, n);
    defer gpa.free(units);
    for (0..n) |i| units[i] = std.mem.readInt(u16, bytes[i * 2 ..][0..2], .little);
    return std.unicode.utf16LeToUtf8Alloc(gpa, units) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        // Malformed UTF-16 cannot be represented; keep the raw bytes so the
        // name is never silently dropped.
        else => gpa.dupe(u8, bytes),
    };
}

/// Encodes a name for storage. The caller owns the result.
fn encodeName(gpa: Allocator, s: []const u8, ascii: bool) Error![]u8 {
    if (ascii) return gpa.dupe(u8, s);
    const units = std.unicode.utf8ToUtf16LeAlloc(gpa, s) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidUtf8 => {
            // Widen byte-by-byte so a malformed name is still round-trippable.
            const out = try gpa.alloc(u8, s.len * 2);
            for (s, 0..) |b, i| {
                out[i * 2] = b;
                out[i * 2 + 1] = 0;
            }
            return out;
        },
    };
    defer gpa.free(units);
    const out = try gpa.alloc(u8, units.len * 2);
    for (units, 0..) |u, i| std.mem.writeInt(u16, out[i * 2 ..][0..2], u, .little);
    return out;
}

inline fn rd(p: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, p[off..][0..4], .little);
}

inline fn wr(p: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, p[off..][0..4], v, .little);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const header = @import("header.zig");

/// Wraps `payload` into a fresh single-HBIN hive body, returning the body and
/// the payload's data offset.
const CellFixture = struct {
    body: std.ArrayList(u8),
    bins: u32,
    offset: u32,

    fn deinit(self: *CellFixture, gpa: Allocator) void {
        self.body.deinit(gpa);
    }
};

fn fixture(gpa: Allocator, payload: []const u8) !CellFixture {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(gpa);
    try body.resize(gpa, header.REGF_HEADER_SIZE + hbin.HBIN_GRANULARITY);
    @memset(body.items, 0);
    const hb = header.REGF_HEADER_SIZE;
    @memcpy(body.items[hb..][0..4], "hbin");
    std.mem.writeInt(u32, body.items[hb + 4 ..][0..4], 0, .little);
    std.mem.writeInt(u32, body.items[hb + 8 ..][0..4], hbin.HBIN_GRANULARITY, .little);
    var bins: u32 = hbin.HBIN_GRANULARITY;
    const off = try hbin.allocate(&body, gpa, &bins, payload.len, null);
    const dst = try hbin.payloadMut(body.items, off, null);
    @memcpy(dst[0..payload.len], payload);
    return .{ .body = body, .bins = bins, .offset = off };
}

test "key node round-trips through build and read" {
    const gpa = testing.allocator;
    const payload = try buildKeyNode(gpa, "Elements", 0x1234, 0x5678);
    defer gpa.free(payload);
    try testing.expectEqual(@as(usize, NK_MIN + 8), payload.len);

    var f = try fixture(gpa, payload);
    defer f.deinit(gpa);

    const nk = try readKeyNode(gpa, f.body.items, f.offset, null);
    defer nk.deinit(gpa);
    try testing.expectEqualStrings("Elements", nk.name);
    try testing.expectEqual(@as(u32, 0), nk.subkey_count);
    try testing.expectEqual(FREE, nk.subkey_list_offset);
    try testing.expectEqual(@as(u32, 0), nk.value_count);
    try testing.expectEqual(FREE, nk.value_list_offset);
    try testing.expectEqual(@as(u32, 0x5678), nk.security_offset);
}

test "non-ascii key names are stored as utf16" {
    const gpa = testing.allocator;
    const payload = try buildKeyNode(gpa, "ключ", FREE, 0);
    defer gpa.free(payload);
    // 4 UTF-16 code units -> 8 bytes, no COMP_NAME flag.
    try testing.expectEqual(@as(usize, NK_MIN + 8), payload.len);
    const flags = std.mem.readInt(u16, payload[2..4], .little);
    try testing.expectEqual(@as(u16, 0), flags & FLAG_NK_COMP_NAME);

    var f = try fixture(gpa, payload);
    defer f.deinit(gpa);
    const nk = try readKeyNode(gpa, f.body.items, f.offset, null);
    defer nk.deinit(gpa);
    try testing.expectEqualStrings("ключ", nk.name);
}

test "reading a non-nk cell is corrupt" {
    const gpa = testing.allocator;
    var f = try fixture(gpa, "nope");
    defer f.deinit(gpa);
    var diag: Diag = .{};
    try testing.expectError(error.CorruptCell, readKeyNode(gpa, f.body.items, f.offset, &diag));
    try testing.expectEqual(cellAbs(f.offset), diag.offset);
}

test "setNkField writes a u32 in place" {
    const gpa = testing.allocator;
    const payload = try buildKeyNode(gpa, "K", FREE, 0);
    defer gpa.free(payload);
    var f = try fixture(gpa, payload);
    defer f.deinit(gpa);

    try setNkField(f.body.items, f.offset, NK_SUBKEY_COUNT, 7, null);
    try setNkField(f.body.items, f.offset, NK_VALUE_COUNT, 3, null);
    const nk = try readKeyNode(gpa, f.body.items, f.offset, null);
    defer nk.deinit(gpa);
    try testing.expectEqual(@as(u32, 7), nk.subkey_count);
    try testing.expectEqual(@as(u32, 3), nk.value_count);
}

test "leaf list of every kind round-trips" {
    const gpa = testing.allocator;
    const entries = [_]Entry{
        .{ .name = "Alpha", .offset = 0x100 },
        .{ .name = "beta", .offset = 0x200 },
        .{ .name = "Z", .offset = 0x300 },
    };

    for ([_]LeafKind{ .lf, .lh, .li }) |kind| {
        const payload = try buildLeafList(gpa, kind, &entries);
        defer gpa.free(payload);

        const magic: []const u8 = switch (kind) {
            .lf => "lf",
            .lh => "lh",
            .li => "li",
        };
        try testing.expectEqualSlices(u8, magic, payload[0..2]);
        try testing.expectEqual(@as(u16, 3), std.mem.readInt(u16, payload[2..4], .little));

        var f = try fixture(gpa, payload);
        defer f.deinit(gpa);

        const offsets = try subkeyOffsets(gpa, f.body.items, f.offset, null);
        defer gpa.free(offsets);
        try testing.expectEqualSlices(u32, &.{ 0x100, 0x200, 0x300 }, offsets);
        try testing.expectEqual(kind, try leafKind(f.body.items, f.offset, null));
    }
}

test "lf name hints and lh hashes are written" {
    const gpa = testing.allocator;
    const entries = [_]Entry{
        .{ .name = "Alpha", .offset = 0x100 },
        .{ .name = "Z", .offset = 0x300 },
    };
    const lf = try buildLeafList(gpa, .lf, &entries);
    defer gpa.free(lf);
    try testing.expectEqualSlices(u8, "Alph", lf[8..12]);
    // A name shorter than 4 bytes is NUL padded.
    try testing.expectEqualSlices(u8, &.{ 'Z', 0, 0, 0 }, lf[16..20]);

    const lh = try buildLeafList(gpa, .lh, &entries);
    defer gpa.free(lh);
    try testing.expectEqual(name_mod.lhHash("Alpha"), std.mem.readInt(u32, lh[8..12], .little));
    try testing.expectEqual(name_mod.lhHash("Z"), std.mem.readInt(u32, lh[16..20], .little));
}

test "ri lists are resolved recursively" {
    const gpa = testing.allocator;
    // Build two leaf lists, then an ri pointing at them.
    const leaf_a = try buildLeafList(gpa, .lf, &[_]Entry{
        .{ .name = "a", .offset = 0x100 },
        .{ .name = "b", .offset = 0x200 },
    });
    defer gpa.free(leaf_a);
    const leaf_b = try buildLeafList(gpa, .lf, &[_]Entry{
        .{ .name = "c", .offset = 0x300 },
    });
    defer gpa.free(leaf_b);

    var f = try fixture(gpa, leaf_a);
    defer f.deinit(gpa);
    const off_a = f.offset;
    const off_b = try hbin.allocate(&f.body, gpa, &f.bins, leaf_b.len, null);
    @memcpy((try hbin.payloadMut(f.body.items, off_b, null))[0..leaf_b.len], leaf_b);

    // ri payload: "ri", count=2, [off_a, off_b]
    var ri: [12]u8 = @splat(0);
    @memcpy(ri[0..2], "ri");
    std.mem.writeInt(u16, ri[2..4], 2, .little);
    std.mem.writeInt(u32, ri[4..8], off_a, .little);
    std.mem.writeInt(u32, ri[8..12], off_b, .little);
    const off_ri = try hbin.allocate(&f.body, gpa, &f.bins, ri.len, null);
    @memcpy((try hbin.payloadMut(f.body.items, off_ri, null))[0..ri.len], &ri);

    const offsets = try subkeyOffsets(gpa, f.body.items, off_ri, null);
    defer gpa.free(offsets);
    try testing.expectEqualSlices(u32, &.{ 0x100, 0x200, 0x300 }, offsets);
    // An ri is flattened to lf on rewrite.
    try testing.expectEqual(LeafKind.lf, try leafKind(f.body.items, off_ri, null));
}

test "empty and absent subkey lists" {
    const gpa = testing.allocator;
    for ([_]u32{ 0, FREE }) |off| {
        const offsets = try subkeyOffsets(gpa, &.{}, off, null);
        defer gpa.free(offsets);
        try testing.expectEqual(@as(usize, 0), offsets.len);
        try testing.expectEqual(LeafKind.lf, try leafKind(&.{}, off, null));
    }
}

test "unknown list magic is corrupt" {
    const gpa = testing.allocator;
    var f = try fixture(gpa, "zzzzzzzz");
    defer f.deinit(gpa);
    var diag: Diag = .{};
    try testing.expectError(error.CorruptCell, subkeyOffsets(gpa, f.body.items, f.offset, &diag));
    try testing.expectEqual(cellAbs(f.offset), diag.offset);
}

test "value node round-trips (inline and cell data)" {
    const gpa = testing.allocator;

    const inline_vk = try buildValueNode(gpa, "Element", .sz, 3, 0x00434241, true);
    defer gpa.free(inline_vk);
    var f1 = try fixture(gpa, inline_vk);
    defer f1.deinit(gpa);
    {
        const vk = try readValueNode(gpa, f1.body.items, f1.offset, null);
        defer vk.deinit(gpa);
        try testing.expectEqualStrings("Element", vk.name);
        try testing.expectEqual(RegType.sz, vk.ty);
        try testing.expectEqual(@as(u32, 3), vk.data_size);
        try testing.expect(vk.is_inline);
        const raw = try readValueData(gpa, f1.body.items, &vk, null);
        defer gpa.free(raw);
        try testing.expectEqualSlices(u8, "ABC", raw);
    }

    const cell_vk = try buildValueNode(gpa, "", .binary, 9, 0x400, false);
    defer gpa.free(cell_vk);
    var f2 = try fixture(gpa, cell_vk);
    defer f2.deinit(gpa);
    {
        const vk = try readValueNode(gpa, f2.body.items, f2.offset, null);
        defer vk.deinit(gpa);
        try testing.expectEqualStrings("", vk.name);
        try testing.expectEqual(@as(u32, 9), vk.data_size);
        try testing.expect(!vk.is_inline);
        try testing.expectEqual(@as(u32, 0x400), vk.data_offset);
    }
}

test "value offsets are bounded by the list cell" {
    const gpa = testing.allocator;
    // A list cell holding two offsets, but the nk claims 1000.
    var payload: [8]u8 = @splat(0);
    std.mem.writeInt(u32, payload[0..4], 0x111, .little);
    std.mem.writeInt(u32, payload[4..8], 0x222, .little);
    var f = try fixture(gpa, &payload);
    defer f.deinit(gpa);

    const offsets = try valueOffsets(gpa, f.body.items, f.offset, 1000, null);
    defer gpa.free(offsets);
    // The cell payload is padded to the 8-byte cell alignment, so the list
    // exposes a third, zeroed slot; a real read is bounded by the nk count.
    try testing.expectEqual(@as(u32, 0x111), offsets[0]);
    try testing.expectEqual(@as(u32, 0x222), offsets[1]);
    try testing.expect(offsets.len >= 2);

    const bounded = try valueOffsets(gpa, f.body.items, f.offset, 2, null);
    defer gpa.free(bounded);
    try testing.expectEqualSlices(u32, &.{ 0x111, 0x222 }, bounded);
}

test "empty value lists" {
    const gpa = testing.allocator;
    for ([_]u32{ 0, FREE }) |off| {
        const offsets = try valueOffsets(gpa, &.{}, off, 5, null);
        defer gpa.free(offsets);
        try testing.expectEqual(@as(usize, 0), offsets.len);
    }
    const zero = try valueOffsets(gpa, &.{}, 0x20, 0, null);
    defer gpa.free(zero);
    try testing.expectEqual(@as(usize, 0), zero.len);
}

test "big data is reassembled from its segments" {
    const gpa = testing.allocator;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try body.resize(gpa, header.REGF_HEADER_SIZE + hbin.HBIN_GRANULARITY);
    @memset(body.items, 0);
    const hb = header.REGF_HEADER_SIZE;
    @memcpy(body.items[hb..][0..4], "hbin");
    std.mem.writeInt(u32, body.items[hb + 8 ..][0..4], hbin.HBIN_GRANULARITY, .little);
    var bins: u32 = hbin.HBIN_GRANULARITY;

    // Two full-size segments (16344 bytes is a multiple of the 8-byte cell
    // alignment, so a segment payload carries no padding), then a short tail.
    const seg_len = BIG_DATA_LIMIT; // 16344
    const tail_len: usize = 100;
    const total = seg_len * 2 + tail_len;

    var seg_offsets: [3]u32 = undefined;
    for (0..2) |i| {
        const off = try hbin.allocate(&body, gpa, &bins, seg_len, null);
        const dst = try hbin.payloadMut(body.items, off, null);
        @memset(dst[0..seg_len], @intCast('A' + i));
        seg_offsets[i] = off;
    }
    {
        const off = try hbin.allocate(&body, gpa, &bins, tail_len, null);
        const dst = try hbin.payloadMut(body.items, off, null);
        @memset(dst[0..tail_len], 'Z');
        seg_offsets[2] = off;
    }

    // Segment list cell.
    var list: [12]u8 = @splat(0);
    for (seg_offsets, 0..) |o, i| std.mem.writeInt(u32, list[i * 4 ..][0..4], o, .little);
    const off_list = try hbin.allocate(&body, gpa, &bins, list.len, null);
    @memcpy((try hbin.payloadMut(body.items, off_list, null))[0..list.len], &list);

    // db cell.
    var db: [8]u8 = @splat(0);
    @memcpy(db[0..2], "db");
    std.mem.writeInt(u16, db[2..4], 3, .little);
    std.mem.writeInt(u32, db[4..8], off_list, .little);
    const off_db = try hbin.allocate(&body, gpa, &bins, db.len, null);
    @memcpy((try hbin.payloadMut(body.items, off_db, null))[0..db.len], &db);

    const vk: ValueNodeRaw = .{
        .name = try gpa.dupe(u8, "Big"),
        .ty = .binary,
        .data_size = @intCast(total),
        .data_offset = off_db,
        .is_inline = false,
    };
    defer vk.deinit(gpa);

    const raw = try readValueData(gpa, body.items, &vk, null);
    defer gpa.free(raw);
    try testing.expectEqual(total, raw.len);
    try testing.expectEqual(@as(u8, 'A'), raw[0]);
    try testing.expectEqual(@as(u8, 'A'), raw[seg_len - 1]);
    try testing.expectEqual(@as(u8, 'B'), raw[seg_len]);
    try testing.expectEqual(@as(u8, 'B'), raw[seg_len * 2 - 1]);
    try testing.expectEqual(@as(u8, 'Z'), raw[seg_len * 2]);
    try testing.expectEqual(@as(u8, 'Z'), raw[total - 1]);

    // A declared size larger than the segments stops at the last segment.
    var over = vk;
    over.data_size = @intCast(total + 5000);
    const clipped = try readValueData(gpa, body.items, &over, null);
    defer gpa.free(clipped);
    try testing.expectEqual(total, clipped.len);
}

test "security refcount increments" {
    const gpa = testing.allocator;
    const payload = try buildMinSecurity(gpa);
    defer gpa.free(payload);
    try testing.expectEqual(@as(usize, SK_MIN + 4 + 20), payload.len);

    var f = try fixture(gpa, payload);
    defer f.deinit(gpa);
    // Fill flink/blink/refcount like the hive builder does.
    {
        const p = try hbin.payloadMut(f.body.items, f.offset, null);
        wr(p, 4, f.offset);
        wr(p, 8, f.offset);
        wr(p, 12, 1);
    }
    try incrSecurityRefcount(f.body.items, f.offset, null);
    try incrSecurityRefcount(f.body.items, f.offset, null);
    const p = try hbin.payloadMut(f.body.items, f.offset, null);
    try testing.expectEqual(@as(u32, 3), rd(p, 12));
    try testing.expectEqual(@as(u32, 20), rd(p, 16));
    try testing.expectEqual(@as(u8, 1), p[SK_MIN + 4]); // revision
}

test "incrSecurityRefcount rejects a non-sk cell" {
    const gpa = testing.allocator;
    var f = try fixture(gpa, "nope nope nope nope");
    defer f.deinit(gpa);
    try testing.expectError(error.CorruptCell, incrSecurityRefcount(f.body.items, f.offset, null));
}

test "ascii detection" {
    try testing.expect(isAscii("Elements"));
    try testing.expect(isAscii(""));
    try testing.expect(!isAscii("ключ"));
    try testing.expect(!isAscii("caf\u{e9}"));
}
