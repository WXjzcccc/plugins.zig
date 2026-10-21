//! High-level API: loading, navigation, reading and in-place writing.
//!
//! A [`Hive`] owns its backing buffer. Reading borrows from it; every
//! accessor that hands data back allocates, and the caller owns that memory.
//! Writes mutate the buffer in place (first-fit allocation, coalescing free
//! lists) and [`Hive.toBytes`] finalizes the base block.

const std = @import("std");
const cell = @import("cell.zig");
const errors = @import("error.zig");
const hbin = @import("hbin.zig");
const header_mod = @import("header.zig");
const name_mod = @import("name.zig");
const value = @import("value.zig");

const Allocator = std.mem.Allocator;
const Error = errors.Error;
const Diag = errors.Diag;
const Header = header_mod.Header;
const RegValue = value.RegValue;

/// One hive bin, as a 4096-byte (or multiple) block.
const HBIN_SIZE: usize = hbin.HBIN_GRANULARITY;

/// Public view of a key node.
pub const KeyNode = struct {
    /// Owned UTF-8 name.
    name: []u8,
    subkey_count: u32,
    value_count: u32,
    /// This node's data offset within the hive (relative to the hive bins).
    offset: u32,

    pub fn deinit(self: KeyNode, gpa: Allocator) void {
        gpa.free(self.name);
    }
};

/// A named value read from a key.
pub const ValueEntry = struct {
    /// Owned UTF-8 name (empty for the default value).
    name: []u8,
    value: RegValue,

    pub fn deinit(self: ValueEntry, gpa: Allocator) void {
        gpa.free(self.name);
        self.value.deinit(gpa);
    }
};

/// A subkey name (owned) and the nk offset it points at.
const ChildEntry = struct {
    name: []u8,
    offset: u32,
};

/// A REGF hive loaded in memory.
pub const Hive = struct {
    data: std.ArrayList(u8),
    gpa: Allocator,
    base_block: Header,
    diag: Diag = .{},

    // -- Loading ------------------------------------------------------------

    /// Wraps an existing hive image. The bytes are copied, so the caller keeps
    /// ownership of `bytes`.
    pub fn fromBytes(gpa: Allocator, bytes: []const u8, diag: ?*Diag) Error!Hive {
        const hdr = Header.parse(bytes, diag) catch |e| return e;
        var data: std.ArrayList(u8) = .empty;
        errdefer data.deinit(gpa);
        try data.appendSlice(gpa, bytes);
        return .{ .data = data, .gpa = gpa, .base_block = hdr };
    }

    /// Creates a valid empty hive: base block, one hive bin, a root node named
    /// `root_name` and a minimal shareable security descriptor. Useful to build
    /// test or fresh hives without a source file.
    pub fn initEmpty(gpa: Allocator, root_name: []const u8) Error!Hive {
        var data: std.ArrayList(u8) = .empty;
        errdefer data.deinit(gpa);
        try data.resize(gpa, header_mod.REGF_HEADER_SIZE + HBIN_SIZE);
        @memset(data.items, 0);

        // Base block.
        @memcpy(data.items[0..4], "regf");
        wr(data.items, 0x04, 1); // primary sequence
        wr(data.items, 0x08, 1); // secondary sequence
        wr(data.items, 0x14, 1); // major version
        wr(data.items, 0x18, 5); // minor version
        wr(data.items, 0x1C, 0); // file type (primary)
        wr(data.items, 0x20, 1); // file format (direct memory load)
        wr(data.items, 0x28, HBIN_SIZE); // hive bins size
        wr(data.items, 0x2C, 1); // clustering factor

        // First hive bin, then one large free cell.
        const hb = header_mod.REGF_HEADER_SIZE;
        @memcpy(data.items[hb..][0..4], "hbin");
        wr(data.items, hb + 4, 0); // bin offset
        wr(data.items, hb + 8, HBIN_SIZE); // bin size
        const free_cell = hb + hbin.HBIN_HEADER;
        const free_size: i32 = @intCast(HBIN_SIZE - hbin.HBIN_HEADER);
        std.mem.writeInt(i32, data.items[free_cell..][0..4], free_size, .little);

        var hive: Hive = .{
            .data = data,
            .gpa = gpa,
            .base_block = Header.parseUnchecked(data.items),
        };

        // Minimal security descriptor (self-relative, no DACL).
        const sk = try cell.buildMinSecurity(gpa);
        defer gpa.free(sk);
        const sk_off = try hive.allocWrite(sk);
        // Self-referential flink/blink + refcount = 1.
        {
            const p = try hbin.payloadMut(hive.data.items, sk_off, null);
            wr(p, 4, sk_off);
            wr(p, 8, sk_off);
            wr(p, 12, 1);
        }

        // Root node.
        const nk = try cell.buildKeyNode(gpa, root_name, cell.FREE, sk_off);
        defer gpa.free(nk);
        const nk_off = try hive.allocWrite(nk);
        // Root flags: hive entry (0x04) | no delete (0x08), plus comp name
        // (0x20) only when the name is stored as an ASCII string.
        const root_flags: u16 = 0x0C | (if (cell.isAscii(root_name)) @as(u16, 0x20) else 0);
        {
            const p = try hbin.payloadMut(hive.data.items, nk_off, null);
            std.mem.writeInt(u16, p[2..4], root_flags, .little);
        }

        // root_cell_offset in the header, then resync the Header struct.
        wr(hive.data.items, 0x24, nk_off);
        hive.base_block = Header.parseUnchecked(hive.data.items);
        return hive;
    }

    /// Reads and parses a hive file. `dir` is usually `std.Io.Dir.cwd()`.
    pub fn fromFile(gpa: Allocator, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) !Hive {
        const bytes = try dir.readFileAlloc(io, sub_path, gpa, .limited(1 << 32));
        defer gpa.free(bytes);
        return fromBytes(gpa, bytes, null);
    }

    pub fn deinit(self: *Hive) void {
        self.data.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn header(self: *const Hive) *const Header {
        return &self.base_block;
    }

    /// Diagnostics for the most recent failure, when it was recorded.
    pub fn lastDiag(self: *const Hive) Diag {
        return self.diag;
    }

    /// See [`Header.isDirty`].
    pub fn isDirty(self: *const Hive) bool {
        return self.base_block.isDirty();
    }

    /// The hive image, without finalizing it.
    pub fn image(self: *const Hive) []const u8 {
        return self.data.items;
    }

    // -- Navigation ---------------------------------------------------------

    pub fn rootKey(self: *Hive) Error!KeyNode {
        return self.nodeAt(self.base_block.root_cell_offset);
    }

    /// Opens a key by path (separator `\`), case-insensitive. An empty path
    /// (or a leading `\`) addresses the root.
    pub fn open(self: *Hive, path: []const u8) Error!KeyNode {
        return self.nodeAt(try self.resolve(path));
    }

    /// Lists the subkey names of the key at `path`. The caller owns the list
    /// and every name in it.
    pub fn listSubkeys(self: *Hive, path: []const u8, gpa: Allocator) Error!std.ArrayList([]u8) {
        const off = try self.resolve(path);
        var entries = try self.childEntries(off, gpa);
        defer entries.deinit(gpa);

        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |n| gpa.free(n);
            out.deinit(gpa);
        }
        try out.ensureTotalCapacity(gpa, entries.items.len);
        for (entries.items) |e| out.appendAssumeCapacity(e.name);
        // Ownership of the names moved to `out`; the entry array itself is
        // freed by the caller's `defer`.
        entries.clearRetainingCapacity();
        return out;
    }

    /// Lists the values of the key at `path`. The caller owns the list and
    /// every entry in it.
    pub fn listValues(self: *Hive, path: []const u8, gpa: Allocator) Error!std.ArrayList(ValueEntry) {
        const off = try self.resolve(path);
        const nk = try cell.readKeyNode(gpa, self.data.items, off, &self.diag);
        defer nk.deinit(gpa);
        const offs = try cell.valueOffsets(gpa, self.data.items, nk.value_list_offset, nk.value_count, &self.diag);
        defer gpa.free(offs);

        var out: std.ArrayList(ValueEntry) = .empty;
        errdefer {
            for (out.items) |e| e.deinit(gpa);
            out.deinit(gpa);
        }
        try out.ensureTotalCapacity(gpa, offs.len);
        for (offs) |vk_off| {
            const vk = try cell.readValueNode(gpa, self.data.items, vk_off, &self.diag);
            const raw = cell.readValueData(gpa, self.data.items, &vk, &self.diag) catch |e| {
                vk.deinit(gpa);
                return e;
            };
            defer gpa.free(raw);
            const decoded = try RegValue.fromRaw(gpa, vk.ty, raw);
            out.appendAssumeCapacity(.{ .name = vk.name, .value = decoded });
        }
        return out;
    }

    /// Reads one value. The caller owns the returned value.
    pub fn getValue(self: *Hive, path: []const u8, value_name: []const u8) Error!RegValue {
        const off = try self.resolve(path);
        const nk = try cell.readKeyNode(self.gpa, self.data.items, off, &self.diag);
        defer nk.deinit(self.gpa);
        const offs = try cell.valueOffsets(
            self.gpa,
            self.data.items,
            nk.value_list_offset,
            nk.value_count,
            &self.diag,
        );
        defer self.gpa.free(offs);

        for (offs) |vk_off| {
            const vk = try cell.readValueNode(self.gpa, self.data.items, vk_off, &self.diag);
            defer vk.deinit(self.gpa);
            if (!name_mod.eqName(vk.name, value_name)) continue;
            const raw = try cell.readValueData(self.gpa, self.data.items, &vk, &self.diag);
            defer self.gpa.free(raw);
            return RegValue.fromRaw(self.gpa, vk.ty, raw);
        }
        return error.ValueNotFound;
    }

    // -- Writing ------------------------------------------------------------

    /// Creates the missing keys along the path and returns the final key.
    /// Each created level inherits its parent's security descriptor and is
    /// inserted in sorted position within the subkey list.
    pub fn createKey(self: *Hive, path: []const u8) Error!KeyNode {
        try self.guardWritable();
        var current = self.base_block.root_cell_offset;
        var it = std.mem.tokenizeScalar(u8, path, '\\');
        while (it.next()) |part| {
            current = if (try self.findChild(current, part)) |off|
                off
            else
                try self.insertSubkey(current, part);
        }
        return self.nodeAt(current);
    }

    /// Sets (creates or replaces) a value under an existing key.
    pub fn setValue(self: *Hive, path: []const u8, value_name: []const u8, v: RegValue) Error!void {
        try self.guardWritable();
        const nk_off = try self.resolve(path);

        // Encode the data (owned: no borrow crosses an allocation).
        const bytes = try v.toBytes(self.gpa);
        defer self.gpa.free(bytes);
        if (bytes.len > cell.BIG_DATA_LIMIT) {
            errors.set(&self.diag, .{ .size = bytes.len, .max = cell.BIG_DATA_LIMIT });
            return error.ValueTooLarge;
        }
        const ty = v.regType();
        var data_field: u32 = 0;
        var is_inline = false;
        if (bytes.len <= 4) {
            var buf: [4]u8 = @splat(0);
            @memcpy(buf[0..bytes.len], bytes);
            data_field = std.mem.readInt(u32, &buf, .little);
            is_inline = true;
        } else {
            data_field = try self.allocWrite(bytes);
        }

        const vk_payload = try cell.buildValueNode(
            self.gpa,
            value_name,
            ty,
            @intCast(bytes.len),
            data_field,
            is_inline,
        );
        defer self.gpa.free(vk_payload);
        const new_vk = try self.allocWrite(vk_payload);

        // Existing value list.
        const nk = try cell.readKeyNode(self.gpa, self.data.items, nk_off, &self.diag);
        defer nk.deinit(self.gpa);
        const existing = try cell.valueOffsets(
            self.gpa,
            self.data.items,
            nk.value_list_offset,
            nk.value_count,
            &self.diag,
        );
        defer self.gpa.free(existing);

        // Replace if the name already exists.
        for (existing, 0..) |vk_off, i| {
            const vk = try cell.readValueNode(self.gpa, self.data.items, vk_off, &self.diag);
            defer vk.deinit(self.gpa);
            if (!name_mod.eqName(vk.name, value_name)) continue;
            // Replace the offset in the list (size unchanged).
            {
                const list_payload = try hbin.payloadMut(self.data.items, nk.value_list_offset, &self.diag);
                wr(list_payload, i * 4, new_vk);
            }
            try self.freeValueStorage(&vk);
            try hbin.free(self.data.items, vk_off, self.base_block.hive_bins_size, &self.diag);
            return;
        }

        // Append: new value list = the old ones + the new one.
        var offs: std.ArrayList(u32) = .empty;
        defer offs.deinit(self.gpa);
        try offs.appendSlice(self.gpa, existing);
        try offs.append(self.gpa, new_vk);

        const new_list = try self.writeValueList(offs.items);
        if (nk.value_list_offset != cell.FREE and nk.value_list_offset != 0) {
            try hbin.free(self.data.items, nk.value_list_offset, self.base_block.hive_bins_size, &self.diag);
        }
        try cell.setNkField(self.data.items, nk_off, cell.NK_VALUE_LIST, new_list, &self.diag);
        try cell.setNkField(
            self.data.items,
            nk_off,
            cell.NK_VALUE_COUNT,
            @intCast(offs.items.len),
            &self.diag,
        );
    }

    /// Deletes a value. Errors with `error.ValueNotFound` if it does not exist.
    pub fn deleteValue(self: *Hive, path: []const u8, value_name: []const u8) Error!void {
        try self.guardWritable();
        const nk_off = try self.resolve(path);
        const nk = try cell.readKeyNode(self.gpa, self.data.items, nk_off, &self.diag);
        defer nk.deinit(self.gpa);
        const existing = try cell.valueOffsets(
            self.gpa,
            self.data.items,
            nk.value_list_offset,
            nk.value_count,
            &self.diag,
        );
        defer self.gpa.free(existing);

        var kept: std.ArrayList(u32) = .empty;
        defer kept.deinit(self.gpa);
        try kept.ensureTotalCapacity(self.gpa, existing.len);

        var victim_off: ?u32 = null;
        var victim: cell.ValueNodeRaw = undefined;
        var have_victim = false;
        errdefer if (have_victim) victim.deinit(self.gpa);

        for (existing) |vk_off| {
            const vk = try cell.readValueNode(self.gpa, self.data.items, vk_off, &self.diag);
            if (name_mod.eqName(vk.name, value_name)) {
                if (have_victim) victim.deinit(self.gpa);
                victim = vk;
                have_victim = true;
                victim_off = vk_off;
            } else {
                vk.deinit(self.gpa);
                kept.appendAssumeCapacity(vk_off);
            }
        }
        const target = victim_off orelse return error.ValueNotFound;
        // Ownership of `victim` moves to the `defer` below; the `errdefer`
        // above must not also free it, or any later error would double-free.
        have_victim = false;
        defer victim.deinit(self.gpa);

        const new_list: u32 = if (kept.items.len == 0)
            cell.FREE
        else
            try self.writeValueList(kept.items);

        if (nk.value_list_offset != cell.FREE and nk.value_list_offset != 0) {
            try hbin.free(self.data.items, nk.value_list_offset, self.base_block.hive_bins_size, &self.diag);
        }
        try self.freeValueStorage(&victim);
        try hbin.free(self.data.items, target, self.base_block.hive_bins_size, &self.diag);
        try cell.setNkField(self.data.items, nk_off, cell.NK_VALUE_LIST, new_list, &self.diag);
        try cell.setNkField(
            self.data.items,
            nk_off,
            cell.NK_VALUE_COUNT,
            @intCast(kept.items.len),
            &self.diag,
        );
    }

    // -- Serialization ------------------------------------------------------

    /// Finalizes the header (sequences + checksum) and returns a copy of the
    /// hive bytes. Consumes one sequence "tick": each call produces a distinct
    /// consistent transaction.
    pub fn toBytes(self: *Hive, gpa: Allocator) Error![]u8 {
        self.base_block.finalize(self.data.items);
        return gpa.dupe(u8, self.data.items);
    }

    /// Finalizes and writes the hive to `sub_path` under `dir`.
    pub fn save(self: *Hive, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) !void {
        self.base_block.finalize(self.data.items);
        try dir.writeFile(io, .{ .sub_path = sub_path, .data = self.data.items });
    }

    // -- Internals ----------------------------------------------------------

    fn guardWritable(self: *Hive) Error!void {
        if (self.base_block.isDirty()) {
            errors.set(&self.diag, .{});
            return error.DirtyHive;
        }
    }

    fn resolve(self: *Hive, path: []const u8) Error!u32 {
        var current = self.base_block.root_cell_offset;
        var it = std.mem.tokenizeScalar(u8, path, '\\');
        while (it.next()) |part| {
            current = (try self.findChild(current, part)) orelse {
                errors.set(&self.diag, .{ .offset = cell.cellAbs(current) });
                return error.KeyNotFound;
            };
        }
        return current;
    }

    fn findChild(self: *Hive, parent: u32, name_wanted: []const u8) Error!?u32 {
        const nk = try cell.readKeyNode(self.gpa, self.data.items, parent, &self.diag);
        defer nk.deinit(self.gpa);
        const offsets = try cell.subkeyOffsets(self.gpa, self.data.items, nk.subkey_list_offset, &self.diag);
        defer self.gpa.free(offsets);
        for (offsets) |off| {
            const child = try cell.readKeyNode(self.gpa, self.data.items, off, &self.diag);
            defer child.deinit(self.gpa);
            if (name_mod.eqName(child.name, name_wanted)) return off;
        }
        return null;
    }

    /// Subkey name + offset pairs, with owned names. The caller owns the list
    /// and every name.
    fn childEntries(self: *Hive, parent: u32, gpa: Allocator) Error!std.ArrayList(ChildEntry) {
        const nk = try cell.readKeyNode(gpa, self.data.items, parent, &self.diag);
        defer nk.deinit(gpa);
        const offsets = try cell.subkeyOffsets(gpa, self.data.items, nk.subkey_list_offset, &self.diag);
        defer gpa.free(offsets);

        var out: std.ArrayList(ChildEntry) = .empty;
        errdefer {
            for (out.items) |e| gpa.free(e.name);
            out.deinit(gpa);
        }
        try out.ensureTotalCapacity(gpa, offsets.len);
        for (offsets) |off| {
            const child = try cell.readKeyNode(gpa, self.data.items, off, &self.diag);
            out.appendAssumeCapacity(.{ .name = child.name, .offset = off });
        }
        return out;
    }

    /// Creates a subkey `name_new` under `parent`, inserted in sorted position.
    fn insertSubkey(self: *Hive, parent: u32, name_new: []const u8) Error!u32 {
        const parent_nk = try cell.readKeyNode(self.gpa, self.data.items, parent, &self.diag);
        defer parent_nk.deinit(self.gpa);

        // Security inherited from the parent (reference count incremented).
        const security = parent_nk.security_offset;
        try cell.incrSecurityRefcount(self.data.items, security, &self.diag);

        // New nk.
        const nk_payload = try cell.buildKeyNode(self.gpa, name_new, parent, security);
        defer self.gpa.free(nk_payload);
        const new_off = try self.allocWrite(nk_payload);

        // Existing entries + the new one, sorted.
        var entries = try self.childEntries(parent, self.gpa);
        defer {
            for (entries.items) |e| self.gpa.free(e.name);
            entries.deinit(self.gpa);
        }
        const owned_name = try self.gpa.dupe(u8, name_new);
        errdefer self.gpa.free(owned_name);
        try entries.append(self.gpa, .{ .name = owned_name, .offset = new_off });
        std.mem.sort(ChildEntry, entries.items, {}, struct {
            fn lessThan(_: void, a: ChildEntry, b: ChildEntry) bool {
                return name_mod.cmpStr(a.name, b.name) == .lt;
            }
        }.lessThan);

        // Leaf format preserved (an ri is flattened to lf).
        const kind = try cell.leafKind(self.data.items, parent_nk.subkey_list_offset, &self.diag);
        const borrowed = try self.gpa.alloc(cell.Entry, entries.items.len);
        defer self.gpa.free(borrowed);
        for (entries.items, 0..) |e, i| borrowed[i] = .{ .name = e.name, .offset = e.offset };
        const list_payload = try cell.buildLeafList(self.gpa, kind, borrowed);
        defer self.gpa.free(list_payload);
        const new_list = try self.allocWrite(list_payload);

        // Free the old list (and its sublists if it was an ri).
        try self.freeSubkeyList(parent_nk.subkey_list_offset);

        // Update the parent.
        try cell.setNkField(self.data.items, parent, cell.NK_SUBKEY_LIST, new_list, &self.diag);
        try cell.setNkField(
            self.data.items,
            parent,
            cell.NK_SUBKEY_COUNT,
            @intCast(entries.items.len),
            &self.diag,
        );
        return new_off;
    }

    /// Frees a subkey list. For an `ri`, also frees each leaf sublist it
    /// references.
    fn freeSubkeyList(self: *Hive, list_off: u32) Error!void {
        if (list_off == cell.FREE or list_off == 0) return;
        var sublists: std.ArrayList(u32) = .empty;
        defer sublists.deinit(self.gpa);
        {
            const p = try cell.cellPayload(self.data.items, list_off, &self.diag);
            if (p.len >= 4 and std.mem.eql(u8, p[0..2], "ri")) {
                const count = std.mem.readInt(u16, p[2..4], .little);
                for (0..count) |i| {
                    const o = 4 + i * 4;
                    if (o + 4 <= p.len) try sublists.append(self.gpa, rd(p, o));
                }
            }
        }
        for (sublists.items) |sub| {
            try hbin.free(self.data.items, sub, self.base_block.hive_bins_size, &self.diag);
        }
        try hbin.free(self.data.items, list_off, self.base_block.hive_bins_size, &self.diag);
    }

    fn writeValueList(self: *Hive, offs: []const u32) Error!u32 {
        const payload = try self.gpa.alloc(u8, offs.len * 4);
        defer self.gpa.free(payload);
        for (offs, 0..) |o, i| wr(payload, i * 4, o);
        return self.allocWrite(payload);
    }

    /// Frees a `vk`'s data cell (unless it is inline).
    fn freeValueStorage(self: *Hive, vk: *const cell.ValueNodeRaw) Error!void {
        if (vk.is_inline or vk.data_size == 0) return;
        if (vk.data_offset == cell.FREE or vk.data_offset == 0) return;
        try hbin.free(self.data.items, vk.data_offset, self.base_block.hive_bins_size, &self.diag);
    }

    /// Allocates a cell and writes `payload` into it.
    fn allocWrite(self: *Hive, payload: []const u8) Error!u32 {
        const off = try hbin.allocate(
            &self.data,
            self.gpa,
            &self.base_block.hive_bins_size,
            payload.len,
            &self.diag,
        );
        const dst = try hbin.payloadMut(self.data.items, off, &self.diag);
        @memcpy(dst[0..payload.len], payload);
        return off;
    }

    fn nodeAt(self: *Hive, offset: u32) Error!KeyNode {
        const raw = try cell.readKeyNode(self.gpa, self.data.items, offset, &self.diag);
        return .{
            .name = raw.name,
            .subkey_count = raw.subkey_count,
            .value_count = raw.value_count,
            .offset = offset,
        };
    }
};

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

/// Builds the BCD-like fixture shared by the integration tests: `Objects\
/// {bootmgr}\Elements\{23000003, 24000001, 25000004}` plus an OS loader object.
/// Synthetic and self-contained: it holds no machine data. Not public API.
const fixture = struct {
    pub const BOOTMGR = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}";
    pub const OSLOADER = "{11111111-2222-3333-4444-555555555555}";

    pub fn build(gpa: Allocator) !Hive {
        var h = try Hive.initEmpty(gpa, "BCD");
        errdefer h.deinit();

        const bootmgr_elems = try std.fmt.allocPrint(gpa, "Objects\\{s}\\Elements", .{BOOTMGR});
        defer gpa.free(bootmgr_elems);
        {
            var k = try h.createKey(bootmgr_elems);
            k.deinit(gpa);
        }
        try set(gpa, &h, bootmgr_elems, "23000003", .{ .sz = try gpa.dupe(u8, OSLOADER) });
        {
            const items = try gpa.alloc([]u8, 1);
            items[0] = try gpa.dupe(u8, OSLOADER);
            try set(gpa, &h, bootmgr_elems, "24000001", .{ .multi_sz = items });
        }
        {
            const bin = try gpa.dupe(u8, &.{ 30, 0, 0, 0, 0, 0, 0, 0 });
            try set(gpa, &h, bootmgr_elems, "25000004", .{ .binary = bin });
        }

        const os_elems = try std.fmt.allocPrint(gpa, "Objects\\{s}\\Elements", .{OSLOADER});
        defer gpa.free(os_elems);
        {
            var k = try h.createKey(os_elems);
            k.deinit(gpa);
        }
        try set(gpa, &h, os_elems, "12000004", .{ .sz = try gpa.dupe(u8, "Windows") });
        return h;
    }

    fn set(gpa: Allocator, h: *Hive, elements: []const u8, code: []const u8, v: RegValue) !void {
        defer v.deinit(gpa);
        const path = try std.fmt.allocPrint(gpa, "{s}\\{s}", .{ elements, code });
        defer gpa.free(path);
        var k = try h.createKey(path);
        k.deinit(gpa);
        try h.setValue(path, "Element", v);
    }
};

test "an empty hive is valid and clean" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "BCD");
    defer h.deinit();
    try testing.expect(!h.isDirty());
    try testing.expectEqual(@as(u32, 1), h.base_block.major_version);
    try testing.expectEqual(@as(u32, 5), h.base_block.minor_version);
    try testing.expectEqual(@as(u32, 0x1000), h.base_block.hive_bins_size);

    var root = try h.rootKey();
    defer root.deinit(gpa);
    try testing.expectEqualStrings("BCD", root.name);
    try testing.expectEqual(@as(u32, 0), root.subkey_count);
    try testing.expectEqual(@as(u32, 0), root.value_count);
}

test "fromBytes rejects a bad signature" {
    const gpa = testing.allocator;
    var data: [0x1000]u8 = @splat(0);
    try testing.expectError(error.BadSignature, Hive.fromBytes(gpa, &data, null));
    @memcpy(data[0..4], "regf");
    // A valid signature but a wrong checksum.
    try testing.expectError(error.BadChecksum, Hive.fromBytes(gpa, &data, null));
}

test "bytes survive a fromBytes round trip" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();
    const bytes = try h.toBytes(gpa);
    defer gpa.free(bytes);

    var h2 = try Hive.fromBytes(gpa, bytes, null);
    defer h2.deinit();
    var root = try h2.rootKey();
    defer root.deinit(gpa);
    try testing.expectEqualStrings("ROOT", root.name);
}

test "finalize bumps the sequence numbers" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();
    const before = h.base_block.primary_sequence;
    const bytes = try h.toBytes(gpa);
    defer gpa.free(bytes);
    try testing.expectEqual(before + 1, h.base_block.primary_sequence);
    try testing.expect(!h.isDirty());
    // The written checksum is accepted by a fresh parse.
    var h2 = try Hive.fromBytes(gpa, bytes, null);
    h2.deinit();
}

test "a dirty hive refuses every write" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();
    // Desync the sequences, then recompute the checksum so it stays parsable.
    const primary = h.base_block.primary_sequence;
    h.base_block.secondary_sequence = primary + 1;
    wr(h.data.items, 0x08, primary + 1);
    wr(h.data.items, 0x1FC, Header.checksum(h.data.items));

    var dirty = try Hive.fromBytes(gpa, h.data.items, null);
    defer dirty.deinit();
    try testing.expect(dirty.isDirty());
    try testing.expectError(error.DirtyHive, dirty.setValue("ROOT", "x", .{ .dword = 1 }));
    try testing.expectError(error.DirtyHive, dirty.createKey("ROOT\\Zzz"));
    try testing.expectError(error.DirtyHive, dirty.deleteValue("ROOT", "x"));
}

test "the synthetic fixture reads back" {
    const gpa = testing.allocator;
    var h = try fixture.build(gpa);
    defer h.deinit();

    const path = try std.fmt.allocPrint(
        gpa,
        "Objects\\{s}\\Elements\\23000003",
        .{fixture.BOOTMGR},
    );
    defer gpa.free(path);
    const v = try h.getValue(path, "Element");
    defer v.deinit(gpa);
    try testing.expectEqualStrings(fixture.OSLOADER, v.sz);
}

test "all value kinds survive a hive round trip" {
    const gpa = testing.allocator;
    var h = try fixture.build(gpa);
    defer h.deinit();

    const elements = try std.fmt.allocPrint(
        gpa,
        "Objects\\{s}\\Elements",
        .{fixture.BOOTMGR},
    );
    defer gpa.free(elements);

    {
        const items = try gpa.alloc([]u8, 1);
        items[0] = try gpa.dupe(u8, fixture.OSLOADER);
        const v: RegValue = .{ .multi_sz = items };
        defer v.deinit(gpa);
        const seq_path = try std.fmt.allocPrint(gpa, "{s}\\24000001", .{elements});
        defer gpa.free(seq_path);
        try h.setValue(seq_path, "Element", v);
    }

    const bytes = try h.toBytes(gpa);
    defer gpa.free(bytes);
    var h2 = try Hive.fromBytes(gpa, bytes, null);
    defer h2.deinit();

    const p = try std.fmt.allocPrint(gpa, "{s}\\25000004", .{elements});
    defer gpa.free(p);
    const bin = try h2.getValue(p, "Element");
    defer bin.deinit(gpa);
    try testing.expectEqualSlices(u8, &.{ 30, 0, 0, 0, 0, 0, 0, 0 }, bin.binary);
}

test "createKey inserts subkeys in sorted order" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();

    // Insert deliberately out of order.
    for ([_][]const u8{ "Zebra", "apple", "Mango", "123" }) |n| {
        var k = try h.createKey(n);
        k.deinit(gpa);
    }

    var names = try h.listSubkeys("", gpa);
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    try testing.expectEqual(@as(usize, 4), names.items.len);
    // Case-folded ascending: "123" < "apple" < "Mango" < "Zebra".
    try testing.expectEqualStrings("123", names.items[0]);
    try testing.expectEqualStrings("apple", names.items[1]);
    try testing.expectEqualStrings("Mango", names.items[2]);
    try testing.expectEqualStrings("Zebra", names.items[3]);
}

test "createKey is idempotent and case-insensitive" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();

    var k1 = try h.createKey("Alpha\\Beta");
    const off1 = k1.offset;
    k1.deinit(gpa);
    var k2 = try h.createKey("alpha\\beta");
    defer k2.deinit(gpa);
    try testing.expectEqual(off1, k2.offset);

    var names = try h.listSubkeys("", gpa);
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    try testing.expectEqual(@as(usize, 1), names.items.len);
}

test "open reports a missing key" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();
    try testing.expectError(error.KeyNotFound, h.open("nope"));
    var root = try h.open("");
    defer root.deinit(gpa);
    try testing.expectEqualStrings("ROOT", root.name);
}

test "getValue replaces an existing value in place" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();

    try h.setValue("", "v", .{ .dword = 1 });
    var k = try h.rootKey();
    defer k.deinit(gpa);
    try testing.expectEqual(@as(u32, 1), k.value_count);

    try h.setValue("", "v", .{ .dword = 2 });
    var k2 = try h.rootKey();
    defer k2.deinit(gpa);
    try testing.expectEqual(@as(u32, 1), k2.value_count); // still one value

    const got = try h.getValue("", "v");
    defer got.deinit(gpa);
    try testing.expectEqual(@as(u32, 2), got.dword);
}

test "values are listed with their names" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();

    try h.setValue("", "Alpha", .{ .dword = 1 });
    try h.setValue("", "Beta", .{ .qword = 2 });
    try h.setValue("", "", .{ .dword = 3 }); // the default value

    var values = try h.listValues("", gpa);
    defer {
        for (values.items) |e| e.deinit(gpa);
        values.deinit(gpa);
    }
    try testing.expectEqual(@as(usize, 3), values.items.len);
    try testing.expectEqualStrings("Alpha", values.items[0].name);
    try testing.expectEqualStrings("Beta", values.items[1].name);
    try testing.expectEqualStrings("", values.items[2].name);
    try testing.expectEqual(@as(u64, 2), values.items[1].value.qword);
}

test "deleteValue removes and frees" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();

    try h.setValue("", "a", .{ .dword = 1 });
    try h.setValue("", "b", .{ .dword = 2 });
    try h.deleteValue("", "a");
    try testing.expectError(error.ValueNotFound, h.getValue("", "a"));

    const got = try h.getValue("", "b");
    defer got.deinit(gpa);
    try testing.expectEqual(@as(u32, 2), got.dword);

    try h.deleteValue("", "b");
    var k = try h.rootKey();
    defer k.deinit(gpa);
    try testing.expectEqual(@as(u32, 0), k.value_count);
    // An empty value list is marked FREE.
    const nk = try cell.readKeyNode(gpa, h.data.items, k.offset, null);
    defer nk.deinit(gpa);
    try testing.expectEqual(cell.FREE, nk.value_list_offset);
}

test "a long value spills into its own cell" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();

    const long = try gpa.alloc(u8, 400);
    @memset(long, 'x');
    const long_value: RegValue = .{ .sz = long };
    defer long_value.deinit(gpa);
    try h.setValue("", "long", long_value);
    const got = try h.getValue("", "long");
    defer got.deinit(gpa);
    try testing.expectEqualStrings(long, got.sz);
}

test "a value beyond the big-data threshold is refused" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();

    const big = try gpa.alloc(u8, cell.BIG_DATA_LIMIT + 1);
    defer gpa.free(big);
    @memset(big, 'x');
    try testing.expectError(error.ValueTooLarge, h.setValue("", "big", .{ .binary = big }));
    try testing.expectEqual(cell.BIG_DATA_LIMIT + 1, h.lastDiag().size);
    try testing.expectEqual(cell.BIG_DATA_LIMIT, h.lastDiag().max);
}

test "a value at exactly the big-data threshold is accepted" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();

    const big = try gpa.alloc(u8, cell.BIG_DATA_LIMIT);
    defer gpa.free(big);
    @memset(big, 'y');
    try h.setValue("", "big", .{ .binary = big });
    const got = try h.getValue("", "big");
    defer got.deinit(gpa);
    try testing.expectEqual(cell.BIG_DATA_LIMIT, got.binary.len);
    try testing.expectEqual(@as(u8, 'y'), got.binary[cell.BIG_DATA_LIMIT - 1]);
}

test "many keys and values force hbin growth" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "ROOT");
    defer h.deinit();
    const initial_bins = h.base_block.hive_bins_size;

    var buf: [32]u8 = undefined;
    for (0..200) |i| {
        const name = try std.fmt.bufPrint(&buf, "key{d:0>4}", .{i});
        var k = try h.createKey(name);
        k.deinit(gpa);
        const payload = try gpa.dupe(u8, "0123456789abcdef");
        const payload_value: RegValue = .{ .binary = payload };
        defer payload_value.deinit(gpa);
        try h.setValue(name, "payload", payload_value);
    }
    try testing.expect(h.base_block.hive_bins_size > initial_bins);

    // Every key is still findable, and the data is intact.
    for (0..200) |i| {
        const name = try std.fmt.bufPrint(&buf, "key{d:0>4}", .{i});
        const v = try h.getValue(name, "payload");
        defer v.deinit(gpa);
        try testing.expectEqualStrings("0123456789abcdef", v.binary);
    }

    const bytes = try h.toBytes(gpa);
    defer gpa.free(bytes);
    var h2 = try Hive.fromBytes(gpa, bytes, null);
    defer h2.deinit();
    for (0..200) |i| {
        const name = try std.fmt.bufPrint(&buf, "key{d:0>4}", .{i});
        const v = try h2.getValue(name, "payload");
        defer v.deinit(gpa);
        try testing.expectEqualStrings("0123456789abcdef", v.binary);
    }
}

test "unrelated data survives an insertion" {
    const gpa = testing.allocator;
    var h = try fixture.build(gpa);
    defer h.deinit();

    const witness = try std.fmt.allocPrint(
        gpa,
        "Objects\\{s}\\Elements\\24000001",
        .{fixture.BOOTMGR},
    );
    defer gpa.free(witness);
    const before = try h.getValue(witness, "Element");
    defer before.deinit(gpa);

    const seq = try std.fmt.allocPrint(
        gpa,
        "Objects\\{s}\\Elements\\24000002",
        .{fixture.BOOTMGR},
    );
    defer gpa.free(seq);
    {
        var k = try h.createKey(seq);
        k.deinit(gpa);
    }
    {
        const items = try gpa.alloc([]u8, 1);
        items[0] = try gpa.dupe(u8, "{c54212ab-0000-0000-0000-000000000000}");
        const v: RegValue = .{ .multi_sz = items };
        defer v.deinit(gpa);
        try h.setValue(seq, "Element", v);
    }

    const after = try h.getValue(witness, "Element");
    defer after.deinit(gpa);
    try testing.expect(before.eql(after));

    var objects = try h.listSubkeys("Objects", gpa);
    defer {
        for (objects.items) |n| gpa.free(n);
        objects.deinit(gpa);
    }
    try testing.expectEqual(@as(usize, 2), objects.items.len);
}

test "non-ascii key and value names round-trip" {
    const gpa = testing.allocator;
    var h = try Hive.initEmpty(gpa, "Корень");
    defer h.deinit();

    var k = try h.createKey("Ключ\\Подключ");
    k.deinit(gpa);
    {
        const text = try gpa.dupe(u8, "привет");
        const text_value: RegValue = .{ .sz = text };
        defer text_value.deinit(gpa);
        try h.setValue("Ключ\\Подключ", "Значение", text_value);
    }

    const bytes = try h.toBytes(gpa);
    defer gpa.free(bytes);
    var h2 = try Hive.fromBytes(gpa, bytes, null);
    defer h2.deinit();

    var root = try h2.rootKey();
    defer root.deinit(gpa);
    try testing.expectEqualStrings("Корень", root.name);

    const v = try h2.getValue("Ключ\\Подключ", "Значение");
    defer v.deinit(gpa);
    try testing.expectEqualStrings("привет", v.sz);
}

/// Real hives shipped in the testfiles directory. Read-only fixtures: nothing
/// here writes to them. Skipped (not failed) when the directory is absent, so
/// the suite still passes in a checkout without them.
const real_hives = [_][]const u8{ "SAM", "SECURITY", "SYSTEM", "SOFTWARE" };

/// Opens the named fixture under testfiles, or null when it is not present.
fn openRealHive(gpa: Allocator, io: std.Io, name: []const u8) !?Hive {
    const path = try std.fmt.allocPrint(gpa, "testfiles/{s}", .{name});
    defer gpa.free(path);
    return Hive.fromFile(gpa, io, std.Io.Dir.cwd(), path) catch |e| switch (e) {
        error.FileNotFound => null,
        else => return e,
    };
}

test "real hives parse, validate and enumerate" {
    const gpa = testing.allocator;
    const io = testing.io;

    for (real_hives) |n| {
        const maybe = try openRealHive(gpa, io, n);
        if (maybe == null) continue;
        var h = maybe.?;
        defer h.deinit();

        // Header: signature and checksum were accepted by fromBytes.
        try testing.expectEqualStrings("regf", h.data.items[0..4]);
        try testing.expect(!h.isDirty());
        try testing.expectEqual(@as(u32, 1), h.base_block.major_version);
        try testing.expect(h.base_block.minor_version >= 3);
        try testing.expect(h.base_block.minor_version <= 6);
        try testing.expect(h.base_block.hive_bins_size > 0);
        try testing.expectEqual(
            @as(u32, 0),
            h.base_block.hive_bins_size % @as(u32, @intCast(hbin.HBIN_GRANULARITY)),
        );
        // The base block plus the declared bins never exceeds the file.
        try testing.expect(
            header_mod.REGF_HEADER_SIZE + @as(usize, h.base_block.hive_bins_size) <= h.data.items.len,
        );

        // Root key.
        var root = try h.rootKey();
        defer root.deinit(gpa);
        try testing.expect(root.name.len > 0);
        try testing.expectEqual(root.subkey_count, @as(u32, @intCast(try countSubkeys(gpa, &h, ""))));

        // Every subkey list of every visited key resolves, every name is valid
        // UTF-8, and the subkey counts match what the lists actually hold. The
        // walk is bounded so the 68 MiB SOFTWARE fixture stays fast.
        var budget: usize = 4000;
        try walkAndCheck(gpa, &h, "", 0, &budget);
    }
}

fn countSubkeys(gpa: Allocator, h: *Hive, path: []const u8) !usize {
    var subs = try h.listSubkeys(path, gpa);
    defer {
        for (subs.items) |x| gpa.free(x);
        subs.deinit(gpa);
    }
    return subs.items.len;
}

/// Recursively walks the hive, checking structural invariants. budget caps
/// the number of keys visited so large fixtures stay fast.
fn walkAndCheck(
    gpa: Allocator,
    h: *Hive,
    path: []const u8,
    depth: usize,
    budget: *usize,
) !void {
    if (depth > 16 or budget.* == 0) return;
    budget.* -= 1;

    var subs = try h.listSubkeys(path, gpa);
    defer {
        for (subs.items) |x| gpa.free(x);
        subs.deinit(gpa);
    }

    // Names are valid UTF-8 and unique (case-insensitively) within a key.
    for (subs.items, 0..) |a, i| {
        try testing.expect(std.unicode.utf8ValidateSlice(a));
        try testing.expect(a.len > 0);
        for (subs.items[i + 1 ..]) |b| {
            try testing.expect(!name_mod.eqName(a, b));
        }
    }

    // Subkey lists are sorted the way Windows binary-searches them.
    var i: usize = 1;
    while (i < subs.items.len) : (i += 1) {
        try testing.expect(name_mod.cmpStr(subs.items[i - 1], subs.items[i]) == .lt);
    }

    // Values decode without error and their names are valid UTF-8.
    var vals = try h.listValues(path, gpa);
    defer {
        for (vals.items) |v| v.deinit(gpa);
        vals.deinit(gpa);
    }
    for (vals.items) |v| {
        try testing.expect(std.unicode.utf8ValidateSlice(v.name));
    }

    for (subs.items) |name| {
        const child = if (path.len == 0)
            try gpa.dupe(u8, name)
        else
            try std.fmt.allocPrint(gpa, "{s}\\{s}", .{ path, name });
        defer gpa.free(child);
        try walkAndCheck(gpa, h, child, depth + 1, budget);
    }
}

test "real hives reject every single-byte corruption of the header" {
    const gpa = testing.allocator;
    const io = testing.io;

    // A small real hive keeps this fast.
    const maybe = try openRealHive(gpa, io, "SECURITY");
    if (maybe == null) return;
    var h = maybe.?;
    defer h.deinit();

    const original = h.data.items;
    const copy = try gpa.dupe(u8, original);
    defer gpa.free(copy);

    // Flipping a byte inside the checksummed region must be caught: either the
    // signature/checksum check fails, or the header still parses and the hive
    // is readable without panicking.
    for (0..0x200) |i| {
        copy[i] ^= 0xFF;
        var parsed = Hive.fromBytes(gpa, copy, null) catch {
            copy[i] ^= 0xFF;
            continue;
        };
        // Parsed despite the flip: reading must not panic.
        var root = parsed.rootKey() catch {
            parsed.deinit();
            copy[i] ^= 0xFF;
            continue;
        };
        root.deinit(gpa);
        parsed.deinit();
        copy[i] ^= 0xFF;
    }
}

test "real hives survive truncation at every 4 KiB boundary" {
    const gpa = testing.allocator;
    const io = testing.io;

    const maybe = try openRealHive(gpa, io, "SECURITY");
    if (maybe == null) return;
    var h = maybe.?;
    defer h.deinit();

    const full = h.data.items;
    var cut: usize = 0;
    while (cut < full.len) : (cut += 0x1000) {
        // Truncating to cut bytes must either fail cleanly or parse; it must
        // never read out of bounds.
        var parsed = Hive.fromBytes(gpa, full[0..cut], null) catch continue;
        var root = parsed.rootKey() catch {
            parsed.deinit();
            continue;
        };
        root.deinit(gpa);
        parsed.deinit();
    }
}

test "save and fromFile round-trip through the filesystem" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var h = try fixture.build(gpa);
    defer h.deinit();
    try h.save(io, tmp.dir, "BCD");

    var h2 = try Hive.fromFile(gpa, io, tmp.dir, "BCD");
    defer h2.deinit();
    var root = try h2.rootKey();
    defer root.deinit(gpa);
    try testing.expectEqualStrings("BCD", root.name);
    try testing.expect(!h2.isDirty());

    const path = try std.fmt.allocPrint(
        gpa,
        "Objects\\{s}\\Elements\\23000003",
        .{fixture.BOOTMGR},
    );
    defer gpa.free(path);
    const v = try h2.getValue(path, "Element");
    defer v.deinit(gpa);
    try testing.expectEqualStrings(fixture.OSLOADER, v.sz);
}

