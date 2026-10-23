//! Typed access to one Windows registry hive, on top of `regf.zig`.
//!
//! The hive is loaded from an in-memory copy of the evidence file (the plugin
//! reads evidence through the run's read-only file handles). Every getter
//! copies its result into the caller's allocator — in practice a per-file
//! arena — so the `regf` values can be released immediately and the callers
//! stay free of ownership bookkeeping.

const std = @import("std");
const regf = @import("regf_zig");

const Allocator = std.mem.Allocator;

pub const Hive = struct {
    inner: regf.Hive,

    /// Parses a hive image. `bytes` is copied, so the caller keeps ownership.
    pub fn open(gpa: Allocator, bytes: []const u8) regf.Error!Hive {
        const inner = try regf.Hive.fromBytes(gpa, bytes, null);
        return .{ .inner = inner };
    }

    pub fn deinit(self: *Hive) void {
        self.inner.deinit();
    }

    /// The subkey names of the key at `path`; every name is copied into `alloc`.
    pub fn subkeys(self: *Hive, path: []const u8, alloc: Allocator) regf.Error![][]const u8 {
        var names = try self.inner.listSubkeys(path, self.inner.gpa);
        defer {
            for (names.items) |name| self.inner.gpa.free(name);
            names.deinit(self.inner.gpa);
        }
        const out = try alloc.alloc([]const u8, names.items.len);
        for (names.items, 0..) |name, index| out[index] = try alloc.dupe(u8, name);
        return out;
    }

    /// Whether the key at `path` exists.
    pub fn hasKey(self: *Hive, path: []const u8) bool {
        const key = self.inner.open(path) catch return false;
        key.deinit(self.inner.gpa);
        return true;
    }

    /// A string value (`REG_SZ` or `REG_EXPAND_SZ`), copied into `alloc`.
    /// Null when the value is missing or of another type.
    pub fn stringValue(self: *Hive, path: []const u8, name: []const u8, alloc: Allocator) error{OutOfMemory}!?[]const u8 {
        const value = self.inner.getValue(path, name) catch return null;
        defer value.deinit(self.inner.gpa);
        return switch (value) {
            .sz => |text| try alloc.dupe(u8, text),
            .expand_sz => |text| try alloc.dupe(u8, text),
            else => null,
        };
    }

    /// A `REG_DWORD` value. Null when the value is missing or of another type.
    pub fn dwordValue(self: *Hive, path: []const u8, name: []const u8) ?u32 {
        const value = self.inner.getValue(path, name) catch return null;
        defer value.deinit(self.inner.gpa);
        return switch (value) {
            .dword => |number| number,
            else => null,
        };
    }

    /// A `REG_QWORD` value. Null when the value is missing or of another type.
    pub fn qwordValue(self: *Hive, path: []const u8, name: []const u8) ?u64 {
        const value = self.inner.getValue(path, name) catch return null;
        defer value.deinit(self.inner.gpa);
        return switch (value) {
            .qword => |number| number,
            .dword => |number| number,
            else => null,
        };
    }

    /// The registry type code of a value. In the SAM hive, a user name key's
    /// default value carries the user's RID as its type (the data is empty),
    /// which is how the original reads the RID.
    pub fn valueType(self: *Hive, path: []const u8, name: []const u8) ?u32 {
        const value = self.inner.getValue(path, name) catch return null;
        defer value.deinit(self.inner.gpa);
        return @backingInt(value.regType());
    }

    /// A binary value of any type, as its raw bytes, copied into `alloc`.
    pub fn binaryValue(self: *Hive, path: []const u8, name: []const u8, alloc: Allocator) error{OutOfMemory}!?[]const u8 {
        const value = self.inner.getValue(path, name) catch return null;
        defer value.deinit(self.inner.gpa);
        const raw = value.toBytes(self.inner.gpa) catch return null;
        defer self.inner.gpa.free(raw);
        return try alloc.dupe(u8, raw);
    }

    /// A `REG_MULTI_SZ` value, copied into `alloc` as one slice per string.
    pub fn multiSzValue(self: *Hive, path: []const u8, name: []const u8, alloc: Allocator) error{OutOfMemory}!?[][]const u8 {
        const value = self.inner.getValue(path, name) catch return null;
        defer value.deinit(self.inner.gpa);
        const items = switch (value) {
            .multi_sz => |items| items,
            else => return null,
        };
        const out = try alloc.alloc([]const u8, items.len);
        for (items, 0..) |item, index| out[index] = try alloc.dupe(u8, item);
        return out;
    }

    /// The first string of a `REG_MULTI_SZ` (ForensicsTool reads
    /// `getStringsValue(...)[0]`), or "" when the value is missing.
    pub fn firstMultiSz(self: *Hive, path: []const u8, name: []const u8, alloc: Allocator) error{OutOfMemory}![]const u8 {
        const items = (try self.multiSzValue(path, name, alloc)) orelse return "";
        if (items.len == 0) return "";
        return items[0];
    }

    /// The class name of the key at `path`, copied into `alloc`.
    ///
    /// The class name is not part of `regf`'s public key view; it is read from
    /// the raw `nk` cell, whose payload `regf.cell` exposes. The boot key of a
    /// SYSTEM hive is stored in the class names of four LSA subkeys.
    pub fn className(self: *Hive, path: []const u8, alloc: Allocator) error{OutOfMemory}!?[]const u8 {
        const cell = @import("regf_zig").cell;
        const key = self.inner.open(path) catch return null;
        defer key.deinit(self.inner.gpa);

        const payload = cell.cellPayload(self.inner.image(), key.offset, null) catch return null;
        // nk layout: class name offset (u32) at 0x30, class name length (u16)
        // at 0x4A, after the flags check that guards the key name at 0x4C.
        if (payload.len < 76) return null;
        const class_offset = std.mem.readInt(u32, payload[48..52], .little);
        const class_length = std.mem.readInt(u16, payload[74..76], .little);
        if (class_length == 0 or class_offset == 0xFFFF_FFFF) return null;

        const class_payload = cell.cellPayload(self.inner.image(), class_offset, null) catch return null;
        if (class_payload.len < class_length) return null;
        const raw = class_payload[0..class_length];
        return try alloc.dupe(u8, decodeNameBytes(raw));
    }
};

/// Decodes an nk name-class byte string: UTF-16LE when the high bytes say so,
/// ASCII otherwise (the compression flag covers the key name, not the class).
pub fn decodeNameBytes(raw: []const u8) []const u8 {
    if (raw.len < 2 or raw.len % 2 != 0) return raw;
    var utf16 = true;
    var index: usize = 1;
    while (index < raw.len) : (index += 2) {
        if (raw[index] != 0) {
            utf16 = false;
            break;
        }
    }
    if (!utf16) return raw;
    const out = alloc_static(raw.len / 2) catch return raw;
    for (0..raw.len / 2) |position| out[position] = raw[position * 2];
    return out[0 .. raw.len / 2];
}

// The class names this plugin reads (the boot key) are four short hex strings
// per hive; a fixed scratch buffer keeps the helper allocation-free.
var class_scratch: [256]u8 = undefined;

fn alloc_static(length: usize) ![]u8 {
    if (length > class_scratch.len) return error.OutOfMemory;
    return class_scratch[0..length];
}

/// FILETIME (100 ns intervals since 1601-01-01 UTC) to Unix seconds.
pub fn filetimeToUnix(filetime: u64) i64 {
    const seconds: i64 = @intCast(filetime / 10_000_000);
    return seconds - 11_644_473_600;
}

const testing = std.testing;

test "filetime conversion" {
    // 1970-01-01 00:00:00 UTC.
    try testing.expectEqual(@as(i64, 0), filetimeToUnix(116_444_736_000_000_000));
    // Zero stays 1601-01-01; callers filter it out.
    try testing.expectEqual(@as(i64, -11_644_473_600), filetimeToUnix(0));
}

test "name bytes decode ascii and utf16" {
    try testing.expectEqualStrings("abc", decodeNameBytes("abc"));
    try testing.expectEqualStrings("abc", decodeNameBytes(&.{ 'a', 0, 'b', 0, 'c', 0 }));
}
