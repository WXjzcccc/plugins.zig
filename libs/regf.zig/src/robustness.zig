//! Hostile-input ("never panic") regression tests.
//!
//! A hive file is fully attacker-controlled: it can be truncated, carry bogus
//! cell sizes, dangling offsets, cyclic subkey lists, or a `db` record whose
//! segments all point at the same cell. Every one of those must surface as an
//! `Error`, never as a panic, an out-of-bounds read or an unbounded recursion.
//!
//! The tests are deliberately conservative about *which* error is raised: where
//! the format leaves room for interpretation (`CorruptCell` vs `Truncated`), the
//! assertion is "rejected, with one of the cell errors" rather than one exact
//! code. `std.testing.allocator` additionally turns every leak into a failure.
//!
//! This file is a standalone test root (`zig test src/robustness.zig`) and is
//! also pulled into `src/root.zig`'s `test` block, so `zig build test` runs it
//! with the rest of the suite. It imports the sibling modules directly so that
//! both entry points work without extra build wiring.

const std = @import("std");
const testing = std.testing;

const Allocator = std.mem.Allocator;

const errors = @import("error.zig");
const header = @import("header.zig");
const hbin = @import("hbin.zig");
const cell = @import("cell.zig");
const name_mod = @import("name.zig");
const value_mod = @import("value.zig");
const hive_mod = @import("hive.zig");

const Diag = errors.Diag;
const Header = header.Header;
const Hive = hive_mod.Hive;
const RegValue = value_mod.RegValue;

const REGF_HEADER_SIZE = header.REGF_HEADER_SIZE;
const HBIN_SIZE = hbin.HBIN_GRANULARITY;
const HBIN_HEADER = hbin.HBIN_HEADER;
const BIG_DATA_LIMIT = cell.BIG_DATA_LIMIT;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn wrU32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .little);
}

fn rdU32(buf: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, buf[off..][0..4], .little);
}

/// Absolute buffer index of a data offset.
fn absIndex(data_offset: u32) usize {
    return hbin.abs(data_offset);
}

/// Accepts the two errors a rejected cell may raise. Anything else (including
/// `error.TestUnexpectedSuccess`) is propagated.
fn expectRejection(err: anyerror) !void {
    switch (err) {
        error.CorruptCell, error.Truncated => {},
        else => return err,
    }
}

/// A mutable synthetic hive image used to inject malformed cells. The base
/// block is valid (signature, checksum) so `Hive.fromBytes` accepts the image
/// and the malformation is only reached by the readers.
const Image = struct {
    bytes: std.ArrayList(u8),
    bins: u32,

    fn init(gpa: Allocator, hbin_count: usize) !Image {
        std.debug.assert(hbin_count > 0);
        var bytes: std.ArrayList(u8) = .empty;
        errdefer bytes.deinit(gpa);
        try bytes.resize(gpa, REGF_HEADER_SIZE + hbin_count * HBIN_SIZE);
        @memset(bytes.items, 0);

        @memcpy(bytes.items[0..4], "regf");
        wrU32(bytes.items, 0x04, 1); // primary sequence
        wrU32(bytes.items, 0x08, 1); // secondary sequence
        wrU32(bytes.items, 0x14, 1); // major version
        wrU32(bytes.items, 0x18, 5); // minor version
        wrU32(bytes.items, 0x1C, 0); // file type: primary
        wrU32(bytes.items, 0x20, 1); // file format: direct memory load
        wrU32(bytes.items, 0x2C, 1); // clustering factor

        for (0..hbin_count) |i| {
            const pos = REGF_HEADER_SIZE + i * HBIN_SIZE;
            @memcpy(bytes.items[pos..][0..4], "hbin");
            wrU32(bytes.items, pos + 4, @intCast(i * HBIN_SIZE));
            wrU32(bytes.items, pos + 8, HBIN_SIZE);
            // One free cell filling the block, so `hbin.allocate` can carve
            // well-formed cells out of it.
            std.mem.writeInt(
                i32,
                bytes.items[pos + HBIN_HEADER ..][0..4],
                @intCast(HBIN_SIZE - HBIN_HEADER),
                .little,
            );
        }

        var img: Image = .{
            .bytes = bytes,
            .bins = @intCast(hbin_count * HBIN_SIZE),
        };
        img.fix();
        return img;
    }

    fn deinit(self: *Image, gpa: Allocator) void {
        self.bytes.deinit(gpa);
        self.* = undefined;
    }

    /// Writes `payload` into a fresh, correctly sized cell and returns its data
    /// offset. The library allocator is used so the cell walker sees a valid
    /// cell (negative size field, 8-byte alignment).
    fn put(self: *Image, gpa: Allocator, payload: []const u8) !u32 {
        const off = try hbin.allocate(&self.bytes, gpa, &self.bins, payload.len, null);
        const dst = try hbin.payloadMut(self.bytes.items, off, null);
        @memcpy(dst[0..payload.len], payload);
        return off;
    }

    /// Mutable payload of an existing cell, to corrupt its fields.
    fn payloadOf(self: *Image, off: u32) ![]u8 {
        return hbin.payloadMut(self.bytes.items, off, null);
    }

    /// Overwrites a cell's signed size field (negative = allocated).
    fn setCellSize(self: *Image, off: u32, raw: i32) void {
        std.mem.writeInt(i32, self.bytes.items[absIndex(off)..][0..4], raw, .little);
    }

    fn setRoot(self: *Image, off: u32) void {
        wrU32(self.bytes.items, 0x24, off);
    }

    /// Stores an arbitrary `hive_bins_size` and repairs the checksum.
    fn setBinsSize(self: *Image, v: u32) void {
        wrU32(self.bytes.items, 0x28, v);
        wrU32(self.bytes.items, 0x1FC, Header.checksum(self.bytes.items));
    }

    /// Rewrites `hive_bins_size` from the allocator and the base-block checksum.
    fn fix(self: *Image) void {
        wrU32(self.bytes.items, 0x28, self.bins);
        wrU32(self.bytes.items, 0x1FC, Header.checksum(self.bytes.items));
    }

    fn open(self: *Image, gpa: Allocator) !Hive {
        return Hive.fromBytes(gpa, self.bytes.items, null);
    }
};

// -- "must be rejected" assertions ------------------------------------------

fn expectRootRejected(h: *Hive) !void {
    if (h.rootKey()) |k| {
        k.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |_| {}
}

fn expectOpenRejected(h: *Hive, path: []const u8) !void {
    if (h.open(path)) |k| {
        k.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |_| {}
}

fn expectSubkeysRejected(h: *Hive, path: []const u8) !void {
    if (h.listSubkeys(path, testing.allocator)) |result| {
        var names = result;
        for (names.items) |n| testing.allocator.free(n);
        names.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |_| {}
}

fn expectValuesRejected(h: *Hive, path: []const u8) !void {
    if (h.listValues(path, testing.allocator)) |result| {
        var entries = result;
        for (entries.items) |e| e.deinit(testing.allocator);
        entries.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |_| {}
}

fn expectValueRejected(h: *Hive, path: []const u8, value_name: []const u8) !void {
    if (h.getValue(path, value_name)) |v| {
        v.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |_| {}
}

/// Builds a `vk` for `data_off`, stores it and asserts that reading its data is
/// rejected.
fn expectDataRejected(gpa: Allocator, img: *Image, declared_size: u32, data_off: u32) !void {
    const vk_payload = try cell.buildValueNode(gpa, "Big", .binary, declared_size, data_off, false);
    defer gpa.free(vk_payload);
    const vk_off = try img.put(gpa, vk_payload);

    const vk = try cell.readValueNode(gpa, img.bytes.items, vk_off, null);
    defer vk.deinit(gpa);
    if (cell.readValueData(gpa, img.bytes.items, &vk, null)) |raw| {
        gpa.free(raw);
        return error.TestUnexpectedSuccess;
    } else |e| try expectRejection(e);
}

/// Builds a `vk` for `data_off` and returns its data, or null when the read was
/// rejected. Used where the format allows either outcome.
fn tryReadData(gpa: Allocator, img: *Image, declared_size: u32, data_off: u32) !?[]u8 {
    const vk_payload = try cell.buildValueNode(gpa, "Big", .binary, declared_size, data_off, false);
    defer gpa.free(vk_payload);
    const vk_off = try img.put(gpa, vk_payload);

    const vk = try cell.readValueNode(gpa, img.bytes.items, vk_off, null);
    defer vk.deinit(gpa);
    return cell.readValueData(gpa, img.bytes.items, &vk, null) catch null;
}

// -- Fixtures ---------------------------------------------------------------

/// A small but structurally rich hive: root `nk`, an `lf` subkey list, several
/// `nk` children, `vk` values of several types, inline and cell-backed data,
/// and a shared `sk` security descriptor.
fn seedHive(gpa: Allocator) ![]u8 {
    var h = try Hive.initEmpty(gpa, "BCD");
    defer h.deinit();

    const elements = "Objects\\{bootmgr}\\Elements";
    var k = try h.createKey(elements);
    k.deinit(gpa);
    var k2 = try h.createKey("Objects\\{bootmgr}\\Description");
    k2.deinit(gpa);

    try setSz(gpa, &h, elements, "Element", "{9dea862c-5cdd-4e70-acc1-f32b344d4795}");
    try h.setValue(elements, "Count", .{ .dword = 0x1234_5678 });
    try h.setValue(elements, "Qword", .{ .qword = 0x0123_4567_89ab_cdef });
    {
        const blob = try gpa.dupe(u8, "0123456789abcdef");
        const v: RegValue = .{ .binary = blob };
        defer v.deinit(gpa);
        try h.setValue(elements, "Blob", v);
    }
    {
        const items = try gpa.alloc([]u8, 2);
        items[0] = try gpa.dupe(u8, "a");
        items[1] = try gpa.dupe(u8, "bb");
        const v: RegValue = .{ .multi_sz = items };
        defer v.deinit(gpa);
        try h.setValue(elements, "List", v);
    }
    return h.toBytes(gpa);
}

fn setSz(gpa: Allocator, h: *Hive, path: []const u8, value_name: []const u8, text: []const u8) !void {
    const copy = try gpa.dupe(u8, text);
    const v: RegValue = .{ .sz = copy };
    defer v.deinit(gpa);
    try h.setValue(path, value_name, v);
}

/// Best-effort traversal of whatever the hive claims to contain. Every error is
/// tolerated, every successful allocation is released: the point is that the
/// process survives, and the testing allocator reports anything leaked.
fn exercise(h: *Hive, gpa: Allocator) void {
    if (h.rootKey()) |k| k.deinit(gpa) else |_| {}
    if (h.open("")) |k| k.deinit(gpa) else |_| {}
    if (h.open("Objects")) |k| k.deinit(gpa) else |_| {}
    if (h.open("Objects\\{bootmgr}\\Elements")) |k| k.deinit(gpa) else |_| {}

    if (h.listSubkeys("", gpa)) |result| {
        var names = result;
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    } else |_| {}
    if (h.listSubkeys("Objects", gpa)) |result| {
        var names = result;
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    } else |_| {}

    if (h.listValues("", gpa)) |result| {
        var entries = result;
        for (entries.items) |e| e.deinit(gpa);
        entries.deinit(gpa);
    } else |_| {}
    if (h.listValues("Objects\\{bootmgr}\\Elements", gpa)) |result| {
        var entries = result;
        for (entries.items) |e| e.deinit(gpa);
        entries.deinit(gpa);
    } else |_| {}

    if (h.getValue("", "x")) |v| v.deinit(gpa) else |_| {}
    if (h.getValue("Objects", "Element")) |v| v.deinit(gpa) else |_| {}
    if (h.getValue("Objects\\{bootmgr}\\Elements", "Element")) |v| v.deinit(gpa) else |_| {}

    if (h.toBytes(gpa)) |bytes| gpa.free(bytes) else |_| {}

    _ = h.isDirty();
    _ = h.lastDiag();
    _ = h.image().len;
    _ = h.header();
}

/// Best-effort *writes* over whatever the hive claims to contain: creation,
/// replacement, deletion and finalization. A hostile hive reaches the allocator
/// and the free-list walker here, where a bogus cell size must be an error too.
fn exerciseWrites(h: *Hive, gpa: Allocator) void {
    if (h.createKey("fuzz")) |k| k.deinit(gpa) else |_| {}
    if (h.createKey("fuzz\\sub\\deep")) |k| k.deinit(gpa) else |_| {}
    if (h.createKey("Objects\\fuzz")) |k| k.deinit(gpa) else |_| {}

    h.setValue("", "zdw", .{ .dword = 0xDEAD_BEEF }) catch {};
    h.setValue("fuzz", "zdw", .{ .dword = 1 }) catch {};
    h.setValue("Objects", "zdw", .{ .dword = 2 }) catch {};
    h.setValue("", "zq", .{ .qword = 0x0123_4567_89ab_cdef }) catch {};

    if (gpa.dupe(u8, "0123456789abcdef0123456789abcdef")) |blob| {
        const v: RegValue = .{ .binary = blob };
        defer v.deinit(gpa);
        h.setValue("", "zbin", v) catch {};
        h.setValue("fuzz", "zbin", v) catch {};
    } else |_| {}

    h.deleteValue("", "zdw") catch {};
    h.deleteValue("", "zq") catch {};
    h.deleteValue("", "Element") catch {};
    h.deleteValue("fuzz", "zbin") catch {};
    h.deleteValue("Objects\\{bootmgr}\\Elements", "Element") catch {};

    if (h.toBytes(gpa)) |bytes| gpa.free(bytes) else |_| {}
}

fn probeTruncated(gpa: Allocator, bytes: []const u8) !void {
    if (Hive.fromBytes(gpa, bytes, null)) |h| {
        var hive = h;
        defer hive.deinit();
        exercise(&hive, gpa);
        exerciseWrites(&hive, gpa);
    } else |_| {}
}

// ---------------------------------------------------------------------------
// Base block
// ---------------------------------------------------------------------------

test "robustness: empty and sub-header buffers are rejected" {
    const gpa = testing.allocator;
    try testing.expectError(error.Truncated, Hive.fromBytes(gpa, &.{}, null));
    try testing.expectError(error.Truncated, Hive.fromBytes(gpa, &.{0}, null));
    try testing.expectError(error.Truncated, Hive.fromBytes(gpa, &.{ 'r', 'e', 'g', 'f' }, null));

    var buf: [REGF_HEADER_SIZE]u8 = @splat(0);
    const cuts = [_]usize{ 1, 3, 4, 0x100, 0x1FC, 0x200, 0xFFF };
    for (cuts) |n| {
        try testing.expectError(error.Truncated, Hive.fromBytes(gpa, buf[0..n], null));
    }
}

test "robustness: a bad signature or a bad checksum is rejected" {
    const gpa = testing.allocator;
    var img = try Image.init(gpa, 1);
    defer img.deinit(gpa);
    img.setRoot(0x20);
    img.fix();

    // Baseline: the untouched image parses.
    {
        var h = try img.open(gpa);
        h.deinit();
    }

    img.bytes.items[0] = 'R';
    try testing.expectError(error.BadSignature, Hive.fromBytes(gpa, img.bytes.items, null));
    img.bytes.items[0] = 'r';

    // Flip a byte covered by the checksum (the reserved base-block area).
    img.bytes.items[0x30] ^= 0xFF;
    try testing.expectError(error.BadChecksum, Hive.fromBytes(gpa, img.bytes.items, null));
    // The diagnostic points at the checksum field.
    var diag: Diag = .{};
    try testing.expectError(error.BadChecksum, Hive.fromBytes(gpa, img.bytes.items, &diag));
    try testing.expectEqual(@as(usize, 0x1FC), diag.offset);
    try testing.expect(diag.expected != diag.found);
}

test "robustness: a valid base block without hive bins has no readable root" {
    const gpa = testing.allocator;
    var img = try Image.init(gpa, 1);
    defer img.deinit(gpa);
    img.setRoot(0x20);
    img.fix();

    // Keep only the base block: the header is intact, the bins are gone.
    const shell = try gpa.dupe(u8, img.bytes.items[0..REGF_HEADER_SIZE]);
    defer gpa.free(shell);

    var h = try Hive.fromBytes(gpa, shell, null);
    defer h.deinit();
    try testing.expect(!h.isDirty());
    try testing.expectEqual(@as(u32, 0x20), h.base_block.root_cell_offset);

    try expectRootRejected(&h);
    try expectOpenRejected(&h, "");
    try expectSubkeysRejected(&h, "");
    try expectValuesRejected(&h, "");
    try expectValueRejected(&h, "", "x");

    // Finalizing is still safe: the base block itself is complete.
    const out = try h.toBytes(gpa);
    defer gpa.free(out);
    try testing.expectEqual(@as(usize, REGF_HEADER_SIZE), out.len);
}

test "robustness: out-of-range root cell offsets are errors, not crashes" {
    const gpa = testing.allocator;
    // -1, i32 max, just past the single bin, the hbin header, the hbin's own
    // offset and size fields, the first (free) cell, and an offset inside the
    // base block itself.
    const offsets = [_]u32{ 0xFFFF_FFFF, 0x7FFF_FFFF, 0x1000, 0, 0x1004, 0x1008, 0x20, 0x24 };
    for (offsets) |off| {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        img.setRoot(off);
        img.fix();

        var h = try img.open(gpa);
        defer h.deinit();
        try expectRootRejected(&h);
        try expectSubkeysRejected(&h, "");
        try expectValuesRejected(&h, "");
    }
}

test "robustness: hive_bins_size is not trusted while reading" {
    const gpa = testing.allocator;
    const values = [_]u32{ 0, 0x1000, 0x1234, 0xFFFF_F000, 0xFFFF_FFFF };
    for (values) |bins| {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        const nk_payload = try cell.buildKeyNode(gpa, "ROOT", cell.FREE, cell.FREE);
        defer gpa.free(nk_payload);
        const nk_off = try img.put(gpa, nk_payload);
        img.setRoot(nk_off);
        img.setBinsSize(bins);

        var h = try img.open(gpa);
        defer h.deinit();
        try testing.expectEqual(bins, h.base_block.hive_bins_size);

        var root = try h.rootKey();
        defer root.deinit(gpa);
        try testing.expectEqualStrings("ROOT", root.name);

        // `toBytes` records the (possibly bogus) declared size and re-checksums;
        // it must not try to walk the bins.
        const out = try h.toBytes(gpa);
        defer gpa.free(out);
        try testing.expectEqual(bins, rdU32(out, 0x28));
    }
}

// ---------------------------------------------------------------------------
// Cells
// ---------------------------------------------------------------------------

test "robustness: degenerate cell size fields are rejected" {
    const gpa = testing.allocator;
    // Zero, below the 4-byte minimum, negative versions of the same, and the
    // two extremes (i32 min is the one that used to overflow `@abs`).
    const bad_sizes = [_]i32{ 0, 1, 2, 3, -1, -2, -3, std.math.minInt(i32), std.math.maxInt(i32) };
    for (bad_sizes) |raw| {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        const off = try img.put(gpa, "nk payload");
        img.setCellSize(off, raw);

        var diag: Diag = .{};
        if (cell.cellPayload(img.bytes.items, off, &diag)) |_| {
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
        try testing.expectEqual(absIndex(off), diag.offset);

        // The typed readers must reject it too.
        if (cell.readKeyNode(gpa, img.bytes.items, off, null)) |nk| {
            nk.deinit(gpa);
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
        if (cell.readValueNode(gpa, img.bytes.items, off, null)) |vk| {
            vk.deinit(gpa);
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
    }

    // A bare size field with no payload is a *valid* cell, but not a node.
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        const off = try img.put(gpa, "nk payload");
        img.setCellSize(off, -4);
        try testing.expectError(error.CorruptCell, cell.readKeyNode(gpa, img.bytes.items, off, null));
        try testing.expectError(error.CorruptCell, cell.readValueNode(gpa, img.bytes.items, off, null));
    }
}

test "robustness: a cell that walks off the buffer is rejected" {
    const gpa = testing.allocator;
    var img = try Image.init(gpa, 1);
    defer img.deinit(gpa);
    const off = try img.put(gpa, "some payload");

    // One byte past the end of the image, and a cell that claims the whole
    // address space.
    const remaining = img.bytes.items.len - absIndex(off);
    const bad = [_]i32{
        -@as(i32, @intCast(remaining + 1)),
        -@as(i32, std.math.maxInt(i32)),
        std.math.maxInt(i32),
    };
    for (bad) |raw| {
        img.setCellSize(off, raw);
        var diag: Diag = .{};
        if (cell.cellPayload(img.bytes.items, off, &diag)) |_| {
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
    }
}

test "robustness: a cell that is not an nk is rejected" {
    const gpa = testing.allocator;
    var img = try Image.init(gpa, 1);
    defer img.deinit(gpa);

    // Too short to hold the fixed fields.
    const short_off = try img.put(gpa, "nk");
    try testing.expectError(error.CorruptCell, cell.readKeyNode(gpa, img.bytes.items, short_off, null));

    // Long enough, but the wrong magic (case matters).
    var buf: [84]u8 = @splat(0);
    @memcpy(buf[0..2], "NK");
    const wrong_off = try img.put(gpa, &buf);
    try testing.expectError(error.CorruptCell, cell.readKeyNode(gpa, img.bytes.items, wrong_off, null));

    // The right magic with an empty name is a valid (if useless) node.
    @memcpy(buf[0..2], "nk");
    const ok_off = try img.put(gpa, &buf);
    const nk = try cell.readKeyNode(gpa, img.bytes.items, ok_off, null);
    defer nk.deinit(gpa);
    try testing.expectEqualStrings("", nk.name);
    try testing.expectEqual(@as(u32, 0), nk.subkey_count);
}

test "robustness: an nk whose name runs past its cell is rejected" {
    const gpa = testing.allocator;
    var img = try Image.init(gpa, 1);
    defer img.deinit(gpa);

    const payload = try cell.buildKeyNode(gpa, "R", cell.FREE, cell.FREE);
    defer gpa.free(payload);
    const off = try img.put(gpa, payload);
    const payload_len = (try img.payloadOf(off)).len;
    try testing.expect(payload_len >= 76);

    // One byte past the cell, then progressively absurd values. A huge
    // name length used to index past the payload slice and panic.
    const bad = [_]u16{ @intCast(payload_len - 76 + 1), 0x7FFF, 0xFFFF };
    for (bad) |name_len| {
        {
            const p = try img.payloadOf(off);
            std.mem.writeInt(u16, p[72..74], name_len, .little);
        }
        if (cell.readKeyNode(gpa, img.bytes.items, off, null)) |nk| {
            nk.deinit(gpa);
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
    }

    // Exactly filling the cell is fine.
    {
        const p = try img.payloadOf(off);
        std.mem.writeInt(u16, p[72..74], @intCast(p.len - 76), .little);
    }
    const nk = try cell.readKeyNode(gpa, img.bytes.items, off, null);
    defer nk.deinit(gpa);
    try testing.expectEqual(payload_len - 76, nk.name.len);
}

test "robustness: a vk whose name runs past its cell is rejected" {
    const gpa = testing.allocator;
    var img = try Image.init(gpa, 1);
    defer img.deinit(gpa);

    const payload = try cell.buildValueNode(gpa, "V", .dword, 4, 0x1122_3344, true);
    defer gpa.free(payload);
    const off = try img.put(gpa, payload);
    const payload_len = (try img.payloadOf(off)).len;
    try testing.expect(payload_len >= 20);

    const bad = [_]u16{ @intCast(payload_len - 20 + 1), 0x7FFF, 0xFFFF };
    for (bad) |name_len| {
        {
            const p = try img.payloadOf(off);
            std.mem.writeInt(u16, p[2..4], name_len, .little);
        }
        if (cell.readValueNode(gpa, img.bytes.items, off, null)) |vk| {
            vk.deinit(gpa);
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
    }

    // Exactly filling the cell is fine.
    {
        const p = try img.payloadOf(off);
        std.mem.writeInt(u16, p[2..4], @intCast(p.len - 20), .little);
    }
    const vk = try cell.readValueNode(gpa, img.bytes.items, off, null);
    defer vk.deinit(gpa);
    try testing.expectEqual(payload_len - 20, vk.name.len);
}

// ---------------------------------------------------------------------------
// Subkey lists (lf / lh / li / ri)
// ---------------------------------------------------------------------------

test "robustness: subkey lists with an unknown magic are rejected" {
    const gpa = testing.allocator;
    // Eight-byte cells: the two magic bytes plus a zero count.
    const magics = [_][]const u8{
        "zz\x00\x00\x00\x00\x00\x00",
        "nk\x00\x00\x00\x00\x00\x00",
        "vk\x00\x00\x00\x00\x00\x00",
        "LF\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
    };
    for (magics) |m| {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        const off = try img.put(gpa, m);
        var diag: Diag = .{};
        if (cell.subkeyOffsets(gpa, img.bytes.items, off, &diag)) |offs| {
            gpa.free(offs);
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
        try testing.expectEqual(absIndex(off), diag.offset);
        // `leafKind` only classifies lf/lh/li; an unknown list reads as lf but
        // is still rejected by the offset reader above.
        _ = cell.leafKind(img.bytes.items, off, null) catch {};
    }

    // A valid magic with trailing garbage after the count is *not* a corruption:
    // the count bounds the entries, and the cell's tail is ignored.
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        const off = try img.put(gpa, "lf" ++ "\x00\x00\x00\x00junkjunk");
        const offs = try cell.subkeyOffsets(gpa, img.bytes.items, off, null);
        defer gpa.free(offs);
        try testing.expectEqual(@as(usize, 0), offs.len);
    }
}

test "robustness: a subkey list with a huge element count is bounded by its cell" {
    const gpa = testing.allocator;
    var img = try Image.init(gpa, 1);
    defer img.deinit(gpa);

    // lf: 8-byte entries, two fit.
    var lf: [20]u8 = @splat(0);
    @memcpy(lf[0..2], "lf");
    std.mem.writeInt(u16, lf[2..4], 0xFFFF, .little);
    wrU32(&lf, 4, 0x111);
    wrU32(&lf, 12, 0x222);
    const lf_off = try img.put(gpa, &lf);
    {
        const offs = try cell.subkeyOffsets(gpa, img.bytes.items, lf_off, null);
        defer gpa.free(offs);
        try testing.expectEqualSlices(u32, &.{ 0x111, 0x222 }, offs);
    }

    // lh: same entry layout.
    var lh: [20]u8 = @splat(0);
    @memcpy(lh[0..2], "lh");
    std.mem.writeInt(u16, lh[2..4], 0xFFFF, .little);
    wrU32(&lh, 4, 0x333);
    wrU32(&lh, 12, 0x444);
    const lh_off = try img.put(gpa, &lh);
    {
        const offs = try cell.subkeyOffsets(gpa, img.bytes.items, lh_off, null);
        defer gpa.free(offs);
        try testing.expectEqualSlices(u32, &.{ 0x333, 0x444 }, offs);
    }

    // li: 4-byte entries.
    var li: [12]u8 = @splat(0);
    @memcpy(li[0..2], "li");
    std.mem.writeInt(u16, li[2..4], 0xFFFF, .little);
    wrU32(&li, 4, 0x555);
    wrU32(&li, 8, 0x666);
    const li_off = try img.put(gpa, &li);
    {
        const offs = try cell.subkeyOffsets(gpa, img.bytes.items, li_off, null);
        defer gpa.free(offs);
        try testing.expectEqualSlices(u32, &.{ 0x555, 0x666 }, offs);
    }

    // Reached through the public API, with a root nk that claims 0xFFFF
    // children: the bogus child offsets must be an error, not a crash.
    const nk_payload = try cell.buildKeyNode(gpa, "ROOT", cell.FREE, cell.FREE);
    defer gpa.free(nk_payload);
    const nk_off = try img.put(gpa, nk_payload);
    try cell.setNkField(img.bytes.items, nk_off, cell.NK_SUBKEY_LIST, lf_off, null);
    try cell.setNkField(img.bytes.items, nk_off, cell.NK_SUBKEY_COUNT, 0xFFFF, null);
    img.setRoot(nk_off);
    img.fix();

    var h = try img.open(gpa);
    defer h.deinit();
    try expectSubkeysRejected(&h, "");
}

test "robustness: self-referential ri lists are bounded, not infinite" {
    const gpa = testing.allocator;

    // 1. An ri whose single entry points at its own cell.
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        var ri: [8]u8 = @splat(0);
        @memcpy(ri[0..2], "ri");
        std.mem.writeInt(u16, ri[2..4], 1, .little);
        const off = try img.put(gpa, &ri);
        {
            const p = try img.payloadOf(off);
            wrU32(p, 4, off);
        }
        var diag: Diag = .{};
        if (cell.subkeyOffsets(gpa, img.bytes.items, off, &diag)) |offs| {
            gpa.free(offs);
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
        try testing.expectEqual(absIndex(off), diag.offset);
    }

    // 2. Two ri cells pointing at each other.
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        var a: [8]u8 = @splat(0);
        @memcpy(a[0..2], "ri");
        std.mem.writeInt(u16, a[2..4], 1, .little);
        const off_a = try img.put(gpa, &a);
        var b: [8]u8 = @splat(0);
        @memcpy(b[0..2], "ri");
        std.mem.writeInt(u16, b[2..4], 1, .little);
        const off_b = try img.put(gpa, &b);
        {
            const pa = try img.payloadOf(off_a);
            wrU32(pa, 4, off_b);
            const pb = try img.payloadOf(off_b);
            wrU32(pb, 4, off_a);
        }
        if (cell.subkeyOffsets(gpa, img.bytes.items, off_a, null)) |offs| {
            gpa.free(offs);
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
    }

    // 3. Through the public API: resolving a child must fail, not hang.
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        var ri: [8]u8 = @splat(0);
        @memcpy(ri[0..2], "ri");
        std.mem.writeInt(u16, ri[2..4], 1, .little);
        const ri_off = try img.put(gpa, &ri);
        {
            const p = try img.payloadOf(ri_off);
            wrU32(p, 4, ri_off);
        }
        const nk_payload = try cell.buildKeyNode(gpa, "ROOT", cell.FREE, cell.FREE);
        defer gpa.free(nk_payload);
        const nk_off = try img.put(gpa, nk_payload);
        try cell.setNkField(img.bytes.items, nk_off, cell.NK_SUBKEY_LIST, ri_off, null);
        try cell.setNkField(img.bytes.items, nk_off, cell.NK_SUBKEY_COUNT, 1, null);
        img.setRoot(nk_off);
        img.fix();

        var h = try img.open(gpa);
        defer h.deinit();
        try expectOpenRejected(&h, "child");
        try expectSubkeysRejected(&h, "");
    }
}

test "robustness: an ri with a bogus sublist offset is rejected" {
    const gpa = testing.allocator;

    // A sublist offset past the end of the image. (0xFFFF_FFFF would be
    // `cell.FREE`, i.e. "no list at all", which is legitimately empty.)
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        var ri: [8]u8 = @splat(0);
        @memcpy(ri[0..2], "ri");
        std.mem.writeInt(u16, ri[2..4], 1, .little);
        wrU32(&ri, 4, 0xFFFF_FFF0);
        const off = try img.put(gpa, &ri);
        if (cell.subkeyOffsets(gpa, img.bytes.items, off, null)) |offs| {
            gpa.free(offs);
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
    }

    // A sublist offset pointing into an hbin header (the "hbin" magic is read
    // as an absurd cell size).
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        var ri: [8]u8 = @splat(0);
        @memcpy(ri[0..2], "ri");
        std.mem.writeInt(u16, ri[2..4], 1, .little);
        wrU32(&ri, 4, 0x04);
        const off = try img.put(gpa, &ri);
        if (cell.subkeyOffsets(gpa, img.bytes.items, off, null)) |offs| {
            gpa.free(offs);
            return error.TestUnexpectedSuccess;
        } else |e| try expectRejection(e);
    }

    // A *valid* ri still resolves: the depth bound must not break the format.
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        var leaf: [12]u8 = @splat(0);
        @memcpy(leaf[0..2], "li");
        std.mem.writeInt(u16, leaf[2..4], 1, .little);
        wrU32(&leaf, 4, 0xABC);
        const leaf_off = try img.put(gpa, &leaf);
        var ri: [8]u8 = @splat(0);
        @memcpy(ri[0..2], "ri");
        std.mem.writeInt(u16, ri[2..4], 1, .little);
        wrU32(&ri, 4, leaf_off);
        const ri_off = try img.put(gpa, &ri);

        const offs = try cell.subkeyOffsets(gpa, img.bytes.items, ri_off, null);
        defer gpa.free(offs);
        try testing.expectEqualSlices(u32, &.{0xABC}, offs);
    }
}

// ---------------------------------------------------------------------------
// Values (vk) and data
// ---------------------------------------------------------------------------

test "robustness: inline values never expose more than four bytes" {
    const gpa = testing.allocator;
    var img = try Image.init(gpa, 1);
    defer img.deinit(gpa);

    // Declared size 0xFFFF with the inline flag: only the 4-byte data field is
    // available, and the reader must clamp to it.
    const payload = try cell.buildValueNode(gpa, "V", .binary, 0xFFFF, 0x4142_4344, true);
    defer gpa.free(payload);
    const off = try img.put(gpa, payload);

    const vk = try cell.readValueNode(gpa, img.bytes.items, off, null);
    defer vk.deinit(gpa);
    try testing.expect(vk.is_inline);
    try testing.expectEqual(@as(u32, 0xFFFF), vk.data_size);

    const raw = try cell.readValueData(gpa, img.bytes.items, &vk, null);
    defer gpa.free(raw);
    try testing.expectEqual(@as(usize, 4), raw.len);
    try testing.expectEqualSlices(u8, &.{ 0x44, 0x43, 0x42, 0x41 }, raw);

    // An inline value of size 0 is empty, and does not look at the data field.
    {
        const zero_payload = try cell.buildValueNode(gpa, "Z", .none, 0, 0xDEAD_BEEF, true);
        defer gpa.free(zero_payload);
        const zero_off = try img.put(gpa, zero_payload);
        const zero_vk = try cell.readValueNode(gpa, img.bytes.items, zero_off, null);
        defer zero_vk.deinit(gpa);
        const zero_raw = try cell.readValueData(gpa, img.bytes.items, &zero_vk, null);
        defer gpa.free(zero_raw);
        try testing.expectEqual(@as(usize, 0), zero_raw.len);
    }
}

test "robustness: a vk whose data_size exceeds its data cell never over-reads" {
    const gpa = testing.allocator;
    var img = try Image.init(gpa, 1);
    defer img.deinit(gpa);

    // 12 bytes of data occupy exactly 12 bytes of cell payload (8-byte cell
    // alignment), so a declared size of 0x7FFF_FFFF must clamp to 12. (The top
    // bit of the `data size` field is the inline flag, so the largest declarable
    // cell-backed size is 0x7FFF_FFFF.)
    const data = "0123456789ab";
    const data_off = try img.put(gpa, data);
    const vk_payload = try cell.buildValueNode(gpa, "Blob", .binary, 0x7FFF_FFFF, data_off, false);
    defer gpa.free(vk_payload);
    const vk_off = try img.put(gpa, vk_payload);

    const vk = try cell.readValueNode(gpa, img.bytes.items, vk_off, null);
    defer vk.deinit(gpa);
    try testing.expectEqual(@as(u32, 0x7FFF_FFFF), vk.data_size);
    try testing.expect(!vk.is_inline);

    const raw = try cell.readValueData(gpa, img.bytes.items, &vk, null);
    defer gpa.free(raw);
    try testing.expectEqual(@as(usize, data.len), raw.len);
    try testing.expectEqualStrings(data, raw);
}

test "robustness: a vk with a bogus data offset is rejected" {
    const gpa = testing.allocator;
    // Past the end of the buffer, i32 max, the hbin header itself, the hbin's
    // zeroed offset field, and offset 0.
    const offsets = [_]u32{ 0xFFFF_FFFF, 0x7FFF_FFFF, 0x1000, 0x1004, 0 };
    for (offsets) |data_off| {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        try expectDataRejected(gpa, &img, 32, data_off);
    }
}

test "robustness: big-data records with bogus segments are rejected" {
    const gpa = testing.allocator;

    // 1. The segment-list offset is out of bounds.
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        var db: [8]u8 = @splat(0);
        @memcpy(db[0..2], "db");
        std.mem.writeInt(u16, db[2..4], 1, .little);
        wrU32(&db, 4, 0xFFFF_FFFF);
        const db_off = try img.put(gpa, &db);
        try expectDataRejected(gpa, &img, BIG_DATA_LIMIT + 1, db_off);
    }

    // 2. A segment offset is out of bounds.
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        var list: [4]u8 = @splat(0);
        wrU32(&list, 0, 0xFFFF_FFFF);
        const list_off = try img.put(gpa, &list);
        var db: [8]u8 = @splat(0);
        @memcpy(db[0..2], "db");
        std.mem.writeInt(u16, db[2..4], 1, .little);
        wrU32(&db, 4, list_off);
        const db_off = try img.put(gpa, &db);
        try expectDataRejected(gpa, &img, BIG_DATA_LIMIT + 1, db_off);
    }

    // 3. A huge segment count with a one-entry list is bounded by the list.
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        const seg_off = try img.put(gpa, "0123456789ab");
        var list: [4]u8 = @splat(0);
        wrU32(&list, 0, seg_off);
        const list_off = try img.put(gpa, &list);
        var db: [8]u8 = @splat(0);
        @memcpy(db[0..2], "db");
        std.mem.writeInt(u16, db[2..4], 0xFFFF, .little);
        wrU32(&db, 4, list_off);
        const db_off = try img.put(gpa, &db);

        if (try tryReadData(gpa, &img, BIG_DATA_LIMIT + 1, db_off)) |raw| {
            defer gpa.free(raw);
            try testing.expectEqual(@as(usize, 12), raw.len);
        }
    }

    // 4. Many segments all pointing at the same large cell: the total can
    //    exceed the buffer, so the accumulator must grow (or be refused), not
    //    assume capacity. 5 x 4004 bytes > the 18 KiB a 12 KiB image reserves.
    {
        var img = try Image.init(gpa, 2);
        defer img.deinit(gpa);
        const seg_len: usize = 4000;
        const seg_bytes = try gpa.alloc(u8, seg_len);
        defer gpa.free(seg_bytes);
        @memset(seg_bytes, 'A');
        const seg_off = try img.put(gpa, seg_bytes);
        const segment_cell_len: usize = (try img.payloadOf(seg_off)).len;

        const refs: usize = 5;
        const list = try gpa.alloc(u8, refs * 4);
        defer gpa.free(list);
        for (0..refs) |i| wrU32(list, i * 4, seg_off);
        const list_off = try img.put(gpa, list);

        var db: [8]u8 = @splat(0);
        @memcpy(db[0..2], "db");
        std.mem.writeInt(u16, db[2..4], @intCast(refs), .little);
        wrU32(&db, 4, list_off);
        const db_off = try img.put(gpa, &db);

        if (try tryReadData(gpa, &img, 0x7FFF_FFFF, db_off)) |raw| {
            defer gpa.free(raw);
            try testing.expect(raw.len <= refs * segment_cell_len);
        }
    }

    // 5. A value above the big-data threshold whose cell is not a `db` record
    //    falls back to the plain (cell-clamped) path.
    {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);
        const plain_off = try img.put(gpa, "not a db");
        if (try tryReadData(gpa, &img, BIG_DATA_LIMIT + 1, plain_off)) |raw| {
            defer gpa.free(raw);
            try testing.expectEqual(@as(usize, (try img.payloadOf(plain_off)).len), raw.len);
        }
    }
}

test "robustness: a valid root with dangling value and subkey lists is an error" {
    const gpa = testing.allocator;
    var img = try Image.init(gpa, 1);
    defer img.deinit(gpa);

    const nk_payload = try cell.buildKeyNode(gpa, "ROOT", cell.FREE, cell.FREE);
    defer gpa.free(nk_payload);
    const nk_off = try img.put(gpa, nk_payload);
    img.setRoot(nk_off);

    // Dangling list offsets and absurd counts, all at once. (0xFFFF_FFFF would
    // be `cell.FREE`, i.e. "no list", so use a merely bogus offset.)
    const bogus: u32 = 0xFFFF_FFF0;
    try cell.setNkField(img.bytes.items, nk_off, cell.NK_SUBKEY_LIST, bogus, null);
    try cell.setNkField(img.bytes.items, nk_off, cell.NK_SUBKEY_COUNT, 0xFFFF_FFFF, null);
    try cell.setNkField(img.bytes.items, nk_off, cell.NK_VALUE_LIST, bogus, null);
    try cell.setNkField(img.bytes.items, nk_off, cell.NK_VALUE_COUNT, 0xFFFF_FFFF, null);
    img.fix();

    var h = try img.open(gpa);
    defer h.deinit();
    var root = try h.rootKey();
    defer root.deinit(gpa);
    try testing.expectEqual(@as(u32, 0xFFFF_FFFF), root.value_count);
    try expectSubkeysRejected(&h, "");
    try expectValuesRejected(&h, "");
    try expectValueRejected(&h, "", "x");
    // Writes are refused as well (the lists are unusable, not just empty).
    try testing.expectError(error.Truncated, h.deleteValue("", "x"));

    // A `FREE` list offset with a non-zero count is the format's "no list":
    // it is legitimately empty, and must not be turned into a read error.
    try cell.setNkField(img.bytes.items, nk_off, cell.NK_SUBKEY_LIST, cell.FREE, null);
    try cell.setNkField(img.bytes.items, nk_off, cell.NK_VALUE_LIST, cell.FREE, null);
    var empty = try img.open(gpa);
    defer empty.deinit();
    var names = try empty.listSubkeys("", gpa);
    defer names.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), names.items.len);
}

test "robustness: writes over a hostile cell size never trap" {
    const gpa = testing.allocator;

    // A root key with one value whose data cell carries an absurd size field.
    // Replacing the value frees the old data cell, and deleting it frees the
    // `vk` too: both walk the size field, which used to overflow `i32`.
    const bad_sizes = [_]i32{
        std.math.minInt(i32),
        -1,
        0,
        3,
        std.math.maxInt(i32),
        -@as(i32, @intCast(HBIN_SIZE)),
    };
    for (bad_sizes) |raw| {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);

        const nk_payload = try cell.buildKeyNode(gpa, "ROOT", cell.FREE, cell.FREE);
        defer gpa.free(nk_payload);
        const nk_off = try img.put(gpa, nk_payload);
        img.setRoot(nk_off);

        // Value list -> vk -> data cell, all well formed first.
        const data_off = try img.put(gpa, "0123456789ab");
        const vk_payload = try cell.buildValueNode(gpa, "Blob", .binary, 12, data_off, false);
        defer gpa.free(vk_payload);
        const vk_off = try img.put(gpa, vk_payload);
        const list_off = try img.put(gpa, &.{
            @truncate(vk_off),
            @truncate(vk_off >> 8),
            @truncate(vk_off >> 16),
            @truncate(vk_off >> 24),
        });
        try cell.setNkField(img.bytes.items, nk_off, cell.NK_VALUE_LIST, list_off, null);
        try cell.setNkField(img.bytes.items, nk_off, cell.NK_VALUE_COUNT, 1, null);
        img.fix();

        // Corrupt the *data* cell's size field, then attempt writes.
        img.setCellSize(data_off, raw);

        var h = try img.open(gpa);
        defer h.deinit();
        // Every outcome is acceptable as long as the process survives: the
        // mutation may be rejected by the guard or tolerated by the reader.
        h.setValue("", "Blob", .{ .dword = 1 }) catch {};
        h.setValue("", "Other", .{ .dword = 2 }) catch {};
        h.deleteValue("", "Blob") catch {};
        if (h.createKey("child")) |k| k.deinit(gpa) else |_| {}
        if (h.toBytes(gpa)) |bytes| gpa.free(bytes) else |_| {}
    }
}

test "robustness: writes over a hostile vk cell size never trap" {
    const gpa = testing.allocator;
    const bad_sizes = [_]i32{ std.math.minInt(i32), -2, 0, std.math.maxInt(i32) };
    for (bad_sizes) |raw| {
        var img = try Image.init(gpa, 1);
        defer img.deinit(gpa);

        const nk_payload = try cell.buildKeyNode(gpa, "ROOT", cell.FREE, cell.FREE);
        defer gpa.free(nk_payload);
        const nk_off = try img.put(gpa, nk_payload);
        img.setRoot(nk_off);

        const vk_payload = try cell.buildValueNode(gpa, "Blob", .dword, 4, 0x1122_3344, true);
        defer gpa.free(vk_payload);
        const vk_off = try img.put(gpa, vk_payload);
        const list_off = try img.put(gpa, &.{
            @truncate(vk_off),
            @truncate(vk_off >> 8),
            @truncate(vk_off >> 16),
            @truncate(vk_off >> 24),
        });
        try cell.setNkField(img.bytes.items, nk_off, cell.NK_VALUE_LIST, list_off, null);
        try cell.setNkField(img.bytes.items, nk_off, cell.NK_VALUE_COUNT, 1, null);
        img.fix();

        img.setCellSize(vk_off, raw);

        var h = try img.open(gpa);
        defer h.deinit();
        h.setValue("", "Blob", .{ .dword = 1 }) catch {};
        h.deleteValue("", "Blob") catch {};
        if (h.createKey("child")) |k| k.deinit(gpa) else |_| {}
        if (h.toBytes(gpa)) |bytes| gpa.free(bytes) else |_| {}
    }
}

// ---------------------------------------------------------------------------
// Truncation
// ---------------------------------------------------------------------------

test "robustness: truncating a valid hive at any boundary never panics" {
    const gpa = testing.allocator;
    const seed = try seedHive(gpa);
    defer gpa.free(seed);
    try testing.expect(seed.len > REGF_HEADER_SIZE);

    // Every 64-byte boundary.
    var cut: usize = 0;
    while (cut <= seed.len) : (cut += 64) {
        try probeTruncated(gpa, seed[0..cut]);
    }

    // Every power-of-two boundary (and one byte past each).
    var p: usize = 1;
    while (p <= seed.len) : (p *= 2) {
        try probeTruncated(gpa, seed[0..p]);
        if (p + 1 <= seed.len) try probeTruncated(gpa, seed[0 .. p + 1]);
    }

    // The untruncated image is still fully readable (a control case).
    try probeTruncated(gpa, seed);
}

// ---------------------------------------------------------------------------
// Mutation fuzzing (deterministic seeds)
// ---------------------------------------------------------------------------

test "robustness: single-byte mutations never panic" {
    const gpa = testing.allocator;
    const seed = try seedHive(gpa);
    defer gpa.free(seed);

    var prng = std.Random.DefaultPrng.init(0x5EED_0BAD_C0FF_EE01);
    const rnd = prng.random();

    const buf = try gpa.alloc(u8, seed.len);
    defer gpa.free(buf);

    var accepted: usize = 0;
    for (0..2000) |_| {
        @memcpy(buf, seed);
        const pos = rnd.intRangeLessThan(usize, 0, buf.len);
        buf[pos] = rnd.int(u8);

        if (Hive.fromBytes(gpa, buf, null)) |h| {
            var hive = h;
            defer hive.deinit();
            accepted += 1;
            exercise(&hive, gpa);
            exerciseWrites(&hive, gpa);
        } else |_| {}
    }
    // The fuzz must reach the readers, not only the checksum rejection path:
    // bytes outside the checksummed base block are the interesting ones.
    try testing.expect(accepted > 1000);
}

test "robustness: word-level mutations never panic" {
    const gpa = testing.allocator;
    const seed = try seedHive(gpa);
    defer gpa.free(seed);

    var prng = std.Random.DefaultPrng.init(0xA11C_E5EE_D00D_1234);
    const rnd = prng.random();

    const buf = try gpa.alloc(u8, seed.len);
    defer gpa.free(buf);

    // Word-sized writes inside the hive bins hit the fields that matter: cell
    // sizes, list counts, offsets, name lengths.
    const slots = (seed.len - REGF_HEADER_SIZE) / 4;
    for (0..600) |_| {
        @memcpy(buf, seed);
        const slot = rnd.intRangeLessThan(usize, 0, slots);
        wrU32(buf, REGF_HEADER_SIZE + slot * 4, rnd.int(u32));

        if (Hive.fromBytes(gpa, buf, null)) |h| {
            var hive = h;
            defer hive.deinit();
            exercise(&hive, gpa);
            exerciseWrites(&hive, gpa);
        } else |_| {}
    }
}

test "robustness: mutations that keep the header valid still navigate safely" {
    const gpa = testing.allocator;
    const seed = try seedHive(gpa);
    defer gpa.free(seed);

    var prng = std.Random.DefaultPrng.init(0xDEAD_BEEF_1234_5678);
    const rnd = prng.random();

    const buf = try gpa.alloc(u8, seed.len);
    defer gpa.free(buf);

    // Corrupt a handful of bytes per iteration (outside the base block, then
    // repair the checksum) so the hive is accepted with a badly damaged body.
    for (0..400) |_| {
        @memcpy(buf, seed);
        const flips = 1 + rnd.intRangeLessThan(usize, 0, 8);
        for (0..flips) |_| {
            const pos = rnd.intRangeLessThan(usize, REGF_HEADER_SIZE, buf.len);
            buf[pos] = rnd.int(u8);
        }
        wrU32(buf, 0x1FC, Header.checksum(buf));

        if (Hive.fromBytes(gpa, buf, null)) |h| {
            var hive = h;
            defer hive.deinit();
            exercise(&hive, gpa);
            exerciseWrites(&hive, gpa);
        } else |_| {}
    }
}

// ---------------------------------------------------------------------------
// Pure helpers used by the tests above are also exercised directly
// ---------------------------------------------------------------------------

test "robustness: name helpers tolerate arbitrary bytes" {
    // Upcasing and comparison must not trap on any 16-bit value, and the lh
    // hash is defined for every byte string.
    var unit: u32 = 0;
    while (unit <= 0xFFFF) : (unit += 1) {
        _ = name_mod.upcase(@intCast(unit));
    }
    try testing.expect(name_mod.eqName("a", "A"));
    try testing.expect(!name_mod.eqName("a", "b"));
    try testing.expectEqual(name_mod.lhHash(""), 0);
    _ = name_mod.lhHash("a very long name that is not a real registry key");
    try testing.expect(name_mod.cmpStr("", "") == .eq);
}



