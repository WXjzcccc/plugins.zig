//! Decoding of the registry's mount table: the `MountedDevices` key of a
//! SYSTEM hive.
//!
//! `MountedDevices` maps a *mount point name* to an opaque blob. The name is
//! either a DOS device path (`\DosDevices\C:`) or a volume identifier
//! (`\??\Volume{GUID}`), and the blob is one of three things:
//!
//! - **12 bytes**: an MBR-style partition location, `[disk signature: u32]
//!   [partition byte offset: u64]`, both little-endian. This is what the
//!   Windows kernel uses to find the volume again at boot.
//! - **even length, starting with `\0`**: a UTF-16LE device path, for hardware
//!   that has no partition table entry (CD-ROM, floppy).
//! - anything else: undecoded, kept as raw bytes.
//!
//! The names themselves are also UTF-16LE on disk; the library decodes them to
//! UTF-8 for us.

const std = @import("std");
const regf = @import("regf_zig");

const Allocator = std.mem.Allocator;

/// How a mount entry locates its volume.
pub const Kind = enum {
    /// `[signature: u32][offset: u64]` — an MBR partition.
    mbr_partition,
    /// A UTF-16LE device path (no partition table entry).
    device_path,
    /// Neither shape: raw bytes preserved.
    unknown,
};

/// An MBR partition location.
pub const MbrPartition = struct {
    /// MBR disk signature.
    disk_signature: u32,
    /// Byte offset of the partition from the start of the disk.
    offset: u64,

    /// Offset in mebibytes, for display.
    pub fn offsetMiB(self: MbrPartition) u64 {
        return self.offset / (1024 * 1024);
    }
};

/// What a mount-point name refers to.
pub const MountPoint = union(enum) {
    /// A DOS drive letter, e.g. `C:`.
    drive_letter: []const u8,
    /// A volume GUID, e.g. `a569de44-...`.
    volume_guid: []const u8,
    /// A volume with no drive letter: Windows stores these as `#{GUID}`.
    volume_marker: []const u8,
    /// Any other name, kept verbatim.
    other: []const u8,
};

/// One decoded `MountedDevices` value.
pub const Entry = struct {
    /// The raw registry value name, owned (UTF-8).
    name: []u8,
    /// The interpreted mount point, borrowed from `name`.
    point: MountPoint,
    kind: Kind,
    /// Valid when `kind == .mbr_partition`.
    mbr: MbrPartition = .{ .disk_signature = 0, .offset = 0 },
    /// Valid when `kind == .device_path`; owned UTF-8.
    device_path: ?[]u8 = null,
    /// Valid when `kind == .unknown`; owned copy of the raw bytes.
    raw: ?[]u8 = null,

    pub fn deinit(self: Entry, gpa: Allocator) void {
        gpa.free(self.name);
        if (self.device_path) |p| gpa.free(p);
        if (self.raw) |r| gpa.free(r);
    }
};

/// The decoded `MountedDevices` key.
pub const MountTable = struct {
    entries: []Entry,

    pub fn deinit(self: MountTable, gpa: Allocator) void {
        for (self.entries) |e| e.deinit(gpa);
        gpa.free(self.entries);
    }

    /// Number of entries that name a DOS drive letter.
    pub fn driveLetterCount(self: MountTable) usize {
        var n: usize = 0;
        for (self.entries) |e| {
            if (e.point == .drive_letter) n += 1;
        }
        return n;
    }
};

/// Reads and decodes `MountedDevices` from an already-loaded SYSTEM hive.
pub fn read(gpa: Allocator, hive: *regf.Hive) !MountTable {
    var values = try hive.listValues("MountedDevices", gpa);
    defer {
        for (values.items) |v| v.deinit(gpa);
        values.deinit(gpa);
    }

    var entries: std.ArrayList(Entry) = .empty;
    errdefer {
        for (entries.items) |e| e.deinit(gpa);
        entries.deinit(gpa);
    }
    try entries.ensureTotalCapacity(gpa, values.items.len);

    for (values.items) |v| {
        const bytes = switch (v.value) {
            .binary => |b| b,
            // A non-binary value is not something Windows writes here, but a
            // hive is untrusted input: keep it rather than failing the read.
            else => continue,
        };
        entries.appendAssumeCapacity(try decodeEntry(gpa, v.name, bytes));
    }
    return .{ .entries = try entries.toOwnedSlice(gpa) };
}

fn decodeEntry(gpa: Allocator, value_name: []const u8, bytes: []const u8) !Entry {
    const name = try gpa.dupe(u8, value_name);
    errdefer gpa.free(name);

    var entry: Entry = .{
        .name = name,
        .point = classify(name),
        .kind = .unknown,
    };

    if (bytes.len == 12) {
        entry.kind = .mbr_partition;
        entry.mbr = .{
            .disk_signature = std.mem.readInt(u32, bytes[0..4], .little),
            .offset = std.mem.readInt(u64, bytes[4..12], .little),
        };
    } else if (looksLikeUtf16Path(bytes)) {
        entry.kind = .device_path;
        entry.device_path = try decodeUtf16z(gpa, bytes);
    } else {
        entry.raw = try gpa.dupe(u8, bytes);
    }
    return entry;
}

/// Splits a mount-point name into its interesting part.
fn classify(name: []const u8) MountPoint {
    const dos = "\\DosDevices\\";
    if (std.mem.startsWith(u8, name, dos)) {
        const rest = name[dos.len..];
        if (isDriveLetter(rest)) return .{ .drive_letter = rest };
        return .{ .other = rest };
    }
    const vol_prefix = "\\??\\Volume{";
    if (std.mem.startsWith(u8, name, vol_prefix)) {
        // Trim the leading `\??\Volume{` and the trailing `}`.
        var rest = name[vol_prefix.len..];
        if (rest.len != 0 and rest[rest.len - 1] == '}') rest = rest[0 .. rest.len - 1];
        return .{ .volume_guid = rest };
    }
    // A volume with no drive letter: `#{GUID}`.
    if (name.len > 4 and name[0] == '#' and name[1] == '{' and name[name.len - 1] == '}') {
        return .{ .volume_marker = name[2 .. name.len - 1] };
    }
    return .{ .other = name };
}

/// True for `X:` where X is a single ASCII letter.
fn isDriveLetter(s: []const u8) bool {
    return s.len == 2 and std.ascii.isAlphabetic(s[0]) and s[1] == ':';
}

/// True when the blob is an even-length UTF-16LE string starting with `\`.
fn looksLikeUtf16Path(bytes: []const u8) bool {
    return bytes.len >= 4 and bytes.len % 2 == 0 and bytes[0] == '\\' and bytes[1] == 0;
}

/// Decodes UTF-16LE up to the first NUL. Unpaired surrogates become U+FFFD.
fn decodeUtf16z(gpa: Allocator, bytes: []const u8) ![]u8 {
    const units = try gpa.alloc(u16, bytes.len / 2);
    defer gpa.free(units);
    for (units, 0..) |*u, i| u.* = std.mem.readInt(u16, bytes[i * 2 ..][0..2], .little);

    var end: usize = 0;
    while (end < units.len and units[end] != 0) : (end += 1) {}
    return std.unicode.utf16LeToUtf8Alloc(gpa, units[0..end]) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        // Malformed UTF-16: keep the bytes rather than dropping the entry.
        else => gpa.dupe(u8, bytes),
    };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Renders the mount table as a human-readable report into `writer`.
pub fn render(writer: *std.Io.Writer, table: MountTable) std.Io.Writer.Error!void {
    try writer.print("Mounted devices: {d} entries ({d} drive letters)\n", .{
        table.entries.len,
        table.driveLetterCount(),
    });

    if (table.driveLetterCount() != 0) {
        try writer.writeAll("\nDrive letters\n");
        for (table.entries) |e| {
            switch (e.point) {
                .drive_letter => |letter| {
                    try writer.print("  {s:<3} ", .{letter});
                    try renderTarget(writer, e);
                    // A drive letter and the volume GUID it belongs to share
                    // the same target blob: show the link.
                    if (volumeGuidFor(&table, e)) |guid| {
                        try writer.print("\n      volume: {s}", .{guid});
                    }
                    try writer.writeAll("\n");
                },
                else => {},
            }
        }
    }

    var any_volume = false;
    for (table.entries) |e| {
        if (e.point == .volume_guid) any_volume = true;
    }
    if (any_volume) {
        try writer.writeAll("\nVolumes\n");
        for (table.entries) |e| {
            switch (e.point) {
                .volume_guid => |guid| {
                    try writer.print("  {s}\n      ", .{guid});
                    try renderTarget(writer, e);
                    if (driveLetterFor(&table, e)) |letter| {
                        try writer.print("\n      mounted at: {s}", .{letter});
                    }
                    try writer.writeAll("\n");
                },
                else => {},
            }
        }
    }

    var any_marker = false;
    for (table.entries) |e| {
        if (e.point == .volume_marker) any_marker = true;
    }
    if (any_marker) {
        try writer.writeAll("\nVolumes without a drive letter\n");
        for (table.entries) |e| {
            switch (e.point) {
                .volume_marker => |guid| {
                    try writer.print("  {s}\n      ", .{guid});
                    try renderTarget(writer, e);
                    try writer.writeAll("\n");
                },
                else => {},
            }
        }
    }

    var any_other = false;
    for (table.entries) |e| {
        if (e.point == .other) any_other = true;
    }
    if (any_other) {
        try writer.writeAll("\nOther entries\n");
        for (table.entries) |e| {
            switch (e.point) {
                .other => |n| {
                    try writer.print("  {s}\n      ", .{n});
                    try renderTarget(writer, e);
                    try writer.writeAll("\n");
                },
                else => {},
            }
        }
    }
}

/// The GUID of the volume whose target is identical to `e`'s, if any.
fn volumeGuidFor(table: *const MountTable, e: Entry) ?[]const u8 {
    for (table.entries) |other| {
        switch (other.point) {
            .volume_guid => |guid| if (sameTarget(e, other)) return guid,
            else => {},
        }
    }
    return null;
}

/// The drive letter whose target is identical to `e`'s, if any.
fn driveLetterFor(table: *const MountTable, e: Entry) ?[]const u8 {
    for (table.entries) |other| {
        switch (other.point) {
            .drive_letter => |letter| if (sameTarget(e, other)) return letter,
            else => {},
        }
    }
    return null;
}

/// True when two entries describe the same volume.
fn sameTarget(a: Entry, b: Entry) bool {
    if (a.kind != b.kind) return false;
    return switch (a.kind) {
        .mbr_partition => a.mbr.disk_signature == b.mbr.disk_signature and a.mbr.offset == b.mbr.offset,
        .device_path => std.mem.eql(u8, a.device_path.?, b.device_path.?),
        .unknown => std.mem.eql(u8, a.raw.?, b.raw.?),
    };
}

fn renderTarget(writer: *std.Io.Writer, e: Entry) std.Io.Writer.Error!void {
    switch (e.kind) {
        .mbr_partition => try writer.print(
            "MBR partition: disk signature 0x{x:0>8}, offset {d} bytes ({d} MiB)",
            .{ e.mbr.disk_signature, e.mbr.offset, e.mbr.offsetMiB() },
        ),
        .device_path => try writer.print("device path: {s}", .{e.device_path.?}),
        .unknown => {
            try writer.print("undecoded ({d} bytes): ", .{e.raw.?.len});
            for (e.raw.?[0..@min(e.raw.?.len, 24)]) |b| try writer.print("{x:0>2}", .{b});
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Builds a synthetic SYSTEM hive holding a `MountedDevices` key with one entry
/// of each shape. No machine data: the signature and GUIDs are made up.
fn syntheticSystem(gpa: Allocator) !regf.Hive {
    var h = try regf.Hive.initEmpty(gpa, "SYSTEM");
    errdefer h.deinit();

    var k = try h.createKey("MountedDevices");
    k.deinit(gpa);

    // An MBR partition: signature 0xDEADBEEF, offset 1 MiB. The volume GUID
    // below points at the same partition, as Windows records both names.
    {
        const blob = try gpa.alloc(u8, 12);
        defer gpa.free(blob);
        std.mem.writeInt(u32, blob[0..4], 0xDEADBEEF, .little);
        std.mem.writeInt(u64, blob[4..12], 1 << 20, .little);
        const v: regf.RegValue = .{ .binary = blob };
        try h.setValue("MountedDevices", "\\DosDevices\\C:", v);
    }
    // The volume GUID for the same partition.
    {
        const blob = try gpa.alloc(u8, 12);
        defer gpa.free(blob);
        std.mem.writeInt(u32, blob[0..4], 0xDEADBEEF, .little);
        std.mem.writeInt(u64, blob[4..12], 1 << 20, .little);
        const v: regf.RegValue = .{ .binary = blob };
        try h.setValue("MountedDevices", "\\??\\Volume{11111111-2222-3333-4444-555555555555}", v);
    }
    // A volume with no drive letter, at a different offset.
    {
        const blob = try gpa.alloc(u8, 12);
        defer gpa.free(blob);
        std.mem.writeInt(u32, blob[0..4], 0xDEADBEEF, .little);
        std.mem.writeInt(u64, blob[4..12], 2 << 20, .little);
        const v: regf.RegValue = .{ .binary = blob };
        try h.setValue("MountedDevices", "#{22222222-3333-4444-5555-666666666666}", v);
    }
    // A device path (a CD-ROM has no partition entry).
    {
        const path = "\\??\\IDE#CdRomExample#5&1&0.0.0";
        const units = try std.unicode.utf8ToUtf16LeAlloc(gpa, path);
        defer gpa.free(units);
        const blob = try gpa.alloc(u8, units.len * 2 + 2);
        defer gpa.free(blob);
        for (units, 0..) |u, i| std.mem.writeInt(u16, blob[i * 2 ..][0..2], u, .little);
        blob[units.len * 2] = 0;
        blob[units.len * 2 + 1] = 0;
        const v: regf.RegValue = .{ .binary = blob };
        try h.setValue("MountedDevices", "\\DosDevices\\D:", v);
    }
    // Something neither shape.
    {
        const blob = try gpa.dupe(u8, &.{ 1, 2, 3, 4, 5 });
        defer gpa.free(blob);
        const v: regf.RegValue = .{ .binary = blob };
        try h.setValue("MountedDevices", "\\DosDevices\\Z:", v);
    }
    return h;
}

test "classify splits drive letters, volumes and everything else" {
    const letter = classify("\\DosDevices\\C:");
    try testing.expectEqualStrings("C:", letter.drive_letter);

    const vol = classify("\\??\\Volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}");
    try testing.expectEqualStrings("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", vol.volume_guid);

    const other = classify("\\DosDevices\\MountPoint");
    try testing.expectEqualStrings("MountPoint", other.other);
}

test "drive letter detection is strict" {
    try testing.expect(isDriveLetter("C:"));
    try testing.expect(isDriveLetter("z:"));
    try testing.expect(!isDriveLetter("C"));
    try testing.expect(!isDriveLetter("CC:"));
    try testing.expect(!isDriveLetter("1:"));
    try testing.expect(!isDriveLetter(""));
}

test "a synthetic SYSTEM hive decodes all three shapes" {
    const gpa = testing.allocator;
    var h = try syntheticSystem(gpa);
    defer h.deinit();

    const table = try read(gpa, &h);
    defer table.deinit(gpa);

    try testing.expectEqual(@as(usize, 5), table.entries.len);
    try testing.expectEqual(@as(usize, 3), table.driveLetterCount());

    for (table.entries) |e| {
        switch (e.point) {
            .drive_letter => |letter| {
                if (std.mem.eql(u8, letter, "C:")) {
                    try testing.expectEqual(Kind.mbr_partition, e.kind);
                    try testing.expectEqual(@as(u32, 0xDEADBEEF), e.mbr.disk_signature);
                    try testing.expectEqual(@as(u64, 1 << 20), e.mbr.offset);
                    try testing.expectEqual(@as(u64, 1), e.mbr.offsetMiB());
                } else if (std.mem.eql(u8, letter, "D:")) {
                    try testing.expectEqual(Kind.device_path, e.kind);
                    try testing.expectEqualStrings(
                        "\\??\\IDE#CdRomExample#5&1&0.0.0",
                        e.device_path.?,
                    );
                } else if (std.mem.eql(u8, letter, "Z:")) {
                    try testing.expectEqual(Kind.unknown, e.kind);
                    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5 }, e.raw.?);
                }
            },
            .volume_guid => |guid| {
                try testing.expectEqualStrings(
                    "11111111-2222-3333-4444-555555555555",
                    guid,
                );
                try testing.expectEqual(Kind.mbr_partition, e.kind);
                // Shares its target with C:.
                try testing.expectEqual(@as(u64, 1 << 20), e.mbr.offset);
            },
            .volume_marker => |guid| {
                try testing.expectEqualStrings("22222222-3333-4444-5555-666666666666", guid);
                try testing.expectEqual(Kind.mbr_partition, e.kind);
                try testing.expectEqual(@as(u64, 2 << 20), e.mbr.offset);
                // No drive letter for this one.
                try testing.expect(driveLetterFor(&table, e) == null);
            },
            .other => try testing.expect(false),
        }
    }

    // The drive letter and the volume GUID share a target, so each must find
    // the other.
    for (table.entries) |e| {
        switch (e.point) {
            .drive_letter => |letter| {
                if (std.mem.eql(u8, letter, "C:")) {
                    try testing.expectEqualStrings(
                        "11111111-2222-3333-4444-555555555555",
                        volumeGuidFor(&table, e).?,
                    );
                }
            },
            .volume_guid => |guid| {
                if (std.mem.eql(u8, guid, "11111111-2222-3333-4444-555555555555")) {
                    try testing.expectEqualStrings("C:", driveLetterFor(&table, e).?);
                }
            },
            else => {},
        }
    }
}

test "the report renders every entry" {
    const gpa = testing.allocator;
    var h = try syntheticSystem(gpa);
    defer h.deinit();

    const table = try read(gpa, &h);
    defer table.deinit(gpa);

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try render(&out.writer, table);
    const text = out.writer.buffered();

    try testing.expect(std.mem.indexOf(u8, text, "5 entries") != null);
    try testing.expect(std.mem.indexOf(u8, text, "3 drive letters") != null);
    try testing.expect(std.mem.indexOf(u8, text, "C:") != null);
    try testing.expect(std.mem.indexOf(u8, text, "0xdeadbeef") != null);
    try testing.expect(std.mem.indexOf(u8, text, "1 MiB") != null);
    try testing.expect(std.mem.indexOf(u8, text, "device path:") != null);
    try testing.expect(std.mem.indexOf(u8, text, "undecoded (5 bytes)") != null);
    try testing.expect(std.mem.indexOf(u8, text, "11111111-2222-3333-4444-555555555555") != null);
}

test "a hive without MountedDevices is a key-not-found error" {
    const gpa = testing.allocator;
    var h = try regf.Hive.initEmpty(gpa, "SYSTEM");
    defer h.deinit();
    try testing.expectError(error.KeyNotFound, read(gpa, &h));
}
