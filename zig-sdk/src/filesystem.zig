//! Filesystem parsers: the `fs.probe` / `fs.open` handshake and the browsing
//! calls of an opened session, mirroring `plugins/sdk/src/filesystem.rs`.
//!
//! The `fs.*` payloads did not change in LPP v2, so the DTOs below are the
//! same as the v1 SDK's; only the imports and the error codes (now uppercase)
//! differ. [`Attributes`] moved here from the deleted `results.zig`.
//!
//! A plugin registers one [`FileSystemParser`] per filesystem family it
//! understands; the host probes every Unknown partition with all of them and
//! opens the most confident one. `probe` and `open` are handed a [`source.Source`]
//! (the logical block device) plus a [`host.Context`] for host calls, progress
//! and cancellation. `open` returns a [`Volume`], a browsable session whose
//! node ids are opaque strings chosen by the plugin.
//!
//! Both handles are type-erased fat pointers built from a plain struct by
//! [`parserOf`] / [`volumeOf`], which is how a plugin connects its methods to
//! the vtable:
//!
//! ```zig
//! const std = @import("std");
//! const lc = @import("lovelycarve");
//! const filesystem = @import("filesystem.zig");
//!
//! const MyVolume = struct {
//!     source: lc.source.Source,
//!
//!     pub fn rootNode(self: *MyVolume, alloc: std.mem.Allocator) lc.Error!filesystem.FsNode {
//!         _ = self;
//!         return .{ .id = "root", .name = "/", .kind = .dir };
//!     }
//!
//!     pub fn children(
//!         self: *MyVolume,
//!         alloc: std.mem.Allocator,
//!         node_id: []const u8,
//!     ) lc.Error![]const filesystem.FsNode {
//!         _ = .{ self, alloc, node_id };
//!         return &.{};
//!     }
//!
//!     pub fn childrenPage(
//!         self: *MyVolume,
//!         alloc: std.mem.Allocator,
//!         node_id: []const u8,
//!         limit: usize,
//!         cursor: ?[]const u8,
//!     ) lc.Error!filesystem.NodePage {
//!         return filesystem.defaultChildrenPage(MyVolume, self, alloc, node_id, limit, cursor);
//!     }
//!
//!     pub fn stat(
//!         self: *MyVolume,
//!         alloc: std.mem.Allocator,
//!         node_id: []const u8,
//!     ) lc.Error!filesystem.FsStat {
//!         _ = .{ self, alloc, node_id };
//!         return .{ .node_id = node_id };
//!     }
//!
//!     pub fn read(
//!         self: *MyVolume,
//!         alloc: std.mem.Allocator,
//!         node_id: []const u8,
//!         offset: u64,
//!         length: usize,
//!     ) lc.Error![]u8 {
//!         _ = .{ node_id, offset };
//!         return self.source.read(alloc, offset, length);
//!     }
//!
//!     pub fn close(self: *MyVolume, alloc: std.mem.Allocator) void {
//!         _ = .{ self, alloc };
//!     }
//! };
//!
//! const MyParser = struct {
//!     pub fn filesystem(self: *MyParser) []const u8 {
//!         _ = self;
//!         return "myfs";
//!     }
//!
//!     pub fn probe(
//!         self: *MyParser,
//!         ctx: lc.Context,
//!         source: *const lc.source.Source,
//!     ) lc.Error!filesystem.Probe {
//!         _ = .{ self, ctx, source };
//!         return filesystem.Probe.noMatch();
//!     }
//!
//!     pub fn open(
//!         self: *MyParser,
//!         ctx: lc.Context,
//!         source: *const lc.source.Source,
//!         options: lc.wire.Value,
//!     ) lc.Error!filesystem.Volume {
//!         _ = .{ self, ctx, options };
//!         const volume = try ctx.alloc.create(MyVolume);
//!         volume.* = .{ .source = source.retain() };
//!         return filesystem.volumeOf(MyVolume, volume);
//!     }
//! };
//!
//! var parser = MyParser{};
//!
//! pub const plugin = lc.Plugin{
//!     .id = "com.example.myfs",
//!     .parsers = &.{filesystem.parserOf(MyParser, &parser)},
//! };
//! ```
//!
//! The two builders use `@This()` to name the concrete type, so the vtable is
//! built at compile time from methods of exactly these names and shapes:
//!
//! * a volume needs `rootNode`, `children`, `childrenPage`, `stat`, `read` and
//!   `close`, each taking `*T` plus the parameters of the matching vtable
//!   entry (`alloc`, and `node_id` / `offset` / `length` where they apply);
//! * a parser needs `filesystem`, `probe` and `open`, each taking `*T` plus
//!   `host.Context`, `*const source.Source` and `wire.Value` where they apply.
//!
//! A missing or misspelled method is a compile error at the `...Of` call site.
//!
//! Threading: the host may serve several sources at once, so parser and volume
//! methods can run concurrently. Anything shared needs its own lock — Zig
//! 0.17 has `std.atomic.Mutex` (spin with `tryLock` / `unlock`), not
//! `std.Thread.Mutex`. The host bounds each call with a deadline (15 s for
//! `stat`, 60 s for listings, 120 s for reads).
//!
//! Every slice, map and array returned here is allocated from the caller's
//! per-call arena and owned by it: never free what you return, and never let
//! `&.{...}` (a stack temporary) escape a function — build maps and arrays with
//! `value.map` / `value.array` / `slice`, which copy.

const std = @import("std");

const wire = @import("wire.zig");
const value = @import("value.zig");
const sdk = @import("error.zig");
const host = @import("host.zig");
const source = @import("source.zig");

/// What a node is: a directory, a regular file, a symbolic link, or space that
/// a deleted file used to occupy.
pub const NodeKind = enum {
    dir,
    file,
    symlink,
    unallocated,

    /// The name the host expects on the wire.
    pub fn name(self: NodeKind) []const u8 {
        return @tagName(self);
    }
};

/// The MIME type reported when a volume has no better one; the host's `FsStat`
/// requires a non-empty string.
pub const DEFAULT_MIME = "application/octet-stream";

/// RFC 3339 timestamps of a node; every field is optional, and absent fields
/// are sent as `nil`.
///
/// Strings, not integers: the host parses each value with
/// `chrono::DateTime::parse_from_rfc3339` and rejects anything else, so
/// `"2023-11-14T22:13:20Z"` is the only accepted form.
pub const Timestamps = struct {
    modified: ?[]const u8 = null,
    accessed: ?[]const u8 = null,
    created: ?[]const u8 = null,
    mft_changed: ?[]const u8 = null,
    birth: ?[]const u8 = null,

    /// The `timestamps` field of an [`FsNode`]: a map of the fields that are
    /// present, as RFC 3339 strings.
    pub fn toValue(self: Timestamps, alloc: std.mem.Allocator) sdk.Error!wire.Value {
        return value.map(alloc, &.{
            value.entry("modified", value.optionalString(self.modified)),
            value.entry("accessed", value.optionalString(self.accessed)),
            value.entry("created", value.optionalString(self.created)),
            value.entry("mft_changed", value.optionalString(self.mft_changed)),
            value.entry("birth", value.optionalString(self.birth)),
        });
    }
};

/// Copies `items` into `alloc`.
///
/// `&.{...}` is a stack temporary, so a list built inline cannot be returned
/// as is; this copy is what makes the result outlive the function that built
/// it. (It was `results.slice` in the v1 SDK.)
pub fn slice(comptime T: type, alloc: std.mem.Allocator, items: []const T) sdk.Error![]const T {
    return alloc.dupe(T, items);
}

/// Ordered attribute map with dictionary semantics: inserting an existing key
/// replaces its value in place. Keys are namespaced (`linux.user`).
pub const Attributes = struct {
    entries: std.ArrayList(wire.Entry) = .empty,

    pub const Entry = wire.Entry;

    /// Inserts `key`, replacing an existing entry in place.
    pub fn put(self: *Attributes, alloc: std.mem.Allocator, key: []const u8, item: wire.Value) sdk.Error!void {
        for (self.entries.items) |*existing| {
            if (std.mem.eql(u8, existing.key, key)) {
                existing.value = item;
                return;
            }
        }
        try self.entries.append(alloc, .{ .key = key, .value = item });
    }

    /// Inserts `item` for `some`, `nil` for `null`.
    pub fn putOptional(
        self: *Attributes,
        alloc: std.mem.Allocator,
        key: []const u8,
        item: ?wire.Value,
    ) sdk.Error!void {
        return self.put(alloc, key, item orelse .nil);
    }

    pub fn get(self: *const Attributes, key: []const u8) ?wire.Value {
        for (self.entries.items) |existing| {
            if (std.mem.eql(u8, existing.key, key)) return existing.value;
        }
        return null;
    }

    pub fn contains(self: *const Attributes, key: []const u8) bool {
        return self.get(key) != null;
    }

    pub fn len(self: *const Attributes) usize {
        return self.entries.items.len;
    }

    /// Inserts every entry of `other`, replacing existing keys.
    pub fn update(self: *Attributes, alloc: std.mem.Allocator, other: *const Attributes) sdk.Error!void {
        for (other.entries.items) |entry| try self.put(alloc, entry.key, entry.value);
    }

    pub fn toValue(self: *const Attributes, alloc: std.mem.Allocator) sdk.Error!wire.Value {
        return value.map(alloc, self.entries.items);
    }
};

/// One directory entry (`FsNode` of the frozen `fs.*` methods).
pub const FsNode = struct {
    id: []const u8,
    name: []const u8,
    parent_id: ?[]const u8 = null,
    kind: NodeKind = .file,
    size: u64 = 0,
    deleted: bool = false,
    inode: ?u64 = null,
    timestamps: Timestamps = .{},
    link_target: ?[]const u8 = null,
    /// Namespaced extension attributes (at most 64).
    attributes: Attributes = .{},

    /// The `fs.children` node map: every field is always present, with `nil`
    /// for the optionals and a nested map for the timestamps.
    pub fn toValue(self: FsNode, alloc: std.mem.Allocator) sdk.Error!wire.Value {
        return value.map(alloc, &.{
            value.entry("id", value.str(self.id)),
            value.entry("name", value.str(self.name)),
            value.entry("parent_id", value.optionalString(self.parent_id)),
            value.entry("kind", value.str(self.kind.name())),
            value.entry("size", value.uint(self.size)),
            value.entry("deleted", value.boolean(self.deleted)),
            value.entry("inode", value.optionalUintValue(self.inode)),
            value.entry("timestamps", try self.timestamps.toValue(alloc)),
            value.entry("link_target", value.optionalString(self.link_target)),
            value.entry("attributes", try self.attributes.toValue(alloc)),
        });
    }
};

/// File metadata (`FsStat` of the frozen `fs.*` methods).
pub const FsStat = struct {
    node_id: []const u8,
    size: u64 = 0,
    inode: ?u64 = null,
    /// Permission bits, `nil` when the filesystem has none. `u16` because the
    /// host's `FsStat` DTO declares `mode: Option<u16>`; a wider value would
    /// fail host deserialization.
    mode: ?u16 = null,
    /// The host's `FsStat` declares `mime: String` (serde default
    /// `application/octet-stream`) and rejects an empty one, so this field is
    /// never `nil` on the wire.
    mime: []const u8 = DEFAULT_MIME,
    magic_hex: ?[]const u8 = null,
    entropy: ?f64 = null,
    attributes: Attributes = .{},

    /// The `fs.stat` map. `mode` and `entropy` are `nil` when unset.
    pub fn toValue(self: FsStat, alloc: std.mem.Allocator) sdk.Error!wire.Value {
        return value.map(alloc, &.{
            value.entry("node_id", value.str(self.node_id)),
            value.entry("size", value.uint(self.size)),
            value.entry("inode", value.optionalUintValue(self.inode)),
            value.entry("mode", value.optionalUintValue(if (self.mode) |mode| mode else null)),
            value.entry("mime", value.str(self.mime)),
            value.entry("magic_hex", value.optionalString(self.magic_hex)),
            value.entry("entropy", value.optionalFloat(self.entropy)),
            value.entry("attributes", try self.attributes.toValue(alloc)),
        });
    }
};

/// One page of a directory listing (`fs.children_page`).
pub const NodePage = struct {
    items: []const FsNode,
    /// Opaque cursor of the next page; `null` on the last page.
    next_cursor: ?[]const u8 = null,
    total: ?u64 = null,

    /// The `fs.children_page` reply: `items` as an array of node maps, plus
    /// the cursor and the total count.
    pub fn toValue(self: NodePage, alloc: std.mem.Allocator) sdk.Error!wire.Value {
        const items = try slice(FsNode, alloc, self.items);
        const encoded = try alloc.alloc(wire.Value, items.len);
        for (items, encoded) |node, *slot| slot.* = try node.toValue(alloc);

        return value.map(alloc, &.{
            value.entry("items", .{ .array = encoded }),
            value.entry("next_cursor", value.optionalString(self.next_cursor)),
            value.entry("total", value.optionalUintValue(self.total)),
        });
    }
};

/// The result of probing one source (`fs.probe`).
pub const Probe = struct {
    /// Confidence 0.0 – 1.0 that the source holds this filesystem.
    confidence: f64 = 0,
    label: ?[]const u8 = null,

    /// No match: zero confidence, no label. A parser should return this rather
    /// than an error when the source is simply not its filesystem, because the
    /// host treats "no match" differently from "probe failed".
    pub fn noMatch() Probe {
        return .{ .confidence = 0, .label = null };
    }
};

/// An opened filesystem session. Node ids are opaque strings chosen by the
/// plugin; the host never interprets them.
///
/// Calls can arrive concurrently from several host threads, so internal state
/// needs its own locking.
pub const Volume = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        rootNode: *const fn (ptr: *anyopaque, alloc: std.mem.Allocator) sdk.Error!FsNode,
        children: *const fn (
            ptr: *anyopaque,
            alloc: std.mem.Allocator,
            node_id: []const u8,
        ) sdk.Error![]const FsNode,
        childrenPage: *const fn (
            ptr: *anyopaque,
            alloc: std.mem.Allocator,
            node_id: []const u8,
            limit: usize,
            cursor: ?[]const u8,
        ) sdk.Error!NodePage,
        stat: *const fn (
            ptr: *anyopaque,
            alloc: std.mem.Allocator,
            node_id: []const u8,
        ) sdk.Error!FsStat,
        read: *const fn (
            ptr: *anyopaque,
            alloc: std.mem.Allocator,
            node_id: []const u8,
            offset: u64,
            length: usize,
        ) sdk.Error![]u8,
        close: *const fn (ptr: *anyopaque, alloc: std.mem.Allocator) void,
    };

    /// The id of the directory the host starts browsing from.
    pub fn rootNode(self: Volume, alloc: std.mem.Allocator) sdk.Error!FsNode {
        return self.vtable.rootNode(self.ptr, alloc);
    }

    /// Every child of `node_id`, unpaged. Prefer [`Volume.childrenPage`] for
    /// large directories.
    pub fn children(
        self: Volume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
    ) sdk.Error![]const FsNode {
        return self.vtable.children(self.ptr, alloc, node_id);
    }

    /// One page of `children`.
    pub fn childrenPage(
        self: Volume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
        limit: usize,
        cursor: ?[]const u8,
    ) sdk.Error!NodePage {
        return self.vtable.childrenPage(self.ptr, alloc, node_id, limit, cursor);
    }

    pub fn stat(
        self: Volume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
    ) sdk.Error!FsStat {
        return self.vtable.stat(self.ptr, alloc, node_id);
    }

    /// Reads up to `length` bytes of a file node at `offset` (at most 4 MiB
    /// per call); returns fewer bytes at the end of the file.
    pub fn read(
        self: Volume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
        offset: u64,
        length: usize,
    ) sdk.Error![]u8 {
        return self.vtable.read(self.ptr, alloc, node_id, offset, length);
    }

    /// Called when the host closes the session. `alloc` is the allocator the
    /// host had available for the close call, not the one `open` used.
    pub fn close(self: Volume, alloc: std.mem.Allocator) void {
        self.vtable.close(self.ptr, alloc);
    }
};

/// Wraps `ptr` in a [`Volume`] whose vtable calls `T`'s methods.
///
/// `T` needs `rootNode`, `children`, `childrenPage`, `stat`, `read` and
/// `close` with the shapes of [`Volume.VTable`] (a leading `*T` instead of
/// `*anyopaque`); see the module header for a full example. The build fails at
/// the call site when one is missing or misspelled.
pub fn volumeOf(comptime T: type, ptr: anytype) Volume {
    comptime assertInstancePtr(T, @TypeOf(ptr));
    const vtable = struct {
        fn rootNode(raw: *anyopaque, alloc: std.mem.Allocator) sdk.Error!FsNode {
            return as(T, raw).rootNode(alloc);
        }

        fn children(
            raw: *anyopaque,
            alloc: std.mem.Allocator,
            node_id: []const u8,
        ) sdk.Error![]const FsNode {
            return as(T, raw).children(alloc, node_id);
        }

        fn childrenPage(
            raw: *anyopaque,
            alloc: std.mem.Allocator,
            node_id: []const u8,
            limit: usize,
            cursor: ?[]const u8,
        ) sdk.Error!NodePage {
            return as(T, raw).childrenPage(alloc, node_id, limit, cursor);
        }

        fn stat(
            raw: *anyopaque,
            alloc: std.mem.Allocator,
            node_id: []const u8,
        ) sdk.Error!FsStat {
            return as(T, raw).stat(alloc, node_id);
        }

        fn read(
            raw: *anyopaque,
            alloc: std.mem.Allocator,
            node_id: []const u8,
            offset: u64,
            length: usize,
        ) sdk.Error![]u8 {
            return as(T, raw).read(alloc, node_id, offset, length);
        }

        fn close(raw: *anyopaque, alloc: std.mem.Allocator) void {
            as(T, raw).close(alloc);
        }

        const VTable = Volume.VTable;
    };

    return .{
        .ptr = @constCast(ptr),
        .vtable = &vtable.VTable{
            .rootNode = vtable.rootNode,
            .children = vtable.children,
            .childrenPage = vtable.childrenPage,
            .stat = vtable.stat,
            .read = vtable.read,
            .close = vtable.close,
        },
    };
}

/// The default [`Volume.VTable.childrenPage`]: lists every child and pages it
/// with an offset cursor, which is what the host sees when a volume does not
/// override `childrenPage`.
///
/// The cursor is the decimal offset of the next item, so `null` starts at 0,
/// an unparsable cursor is `INVALID_PARAMS`, and `total` is always reported.
/// Large directories should implement their own paging instead of walking
/// every child.
pub fn defaultChildrenPage(
    comptime T: type,
    volume: *T,
    alloc: std.mem.Allocator,
    node_id: []const u8,
    limit: usize,
    cursor: ?[]const u8,
) sdk.Error!NodePage {
    const items = try volume.children(alloc, node_id);
    const total = items.len;
    const start = if (cursor) |text|
        std.fmt.parseUnsigned(usize, text, 10) catch
            return sdk.fail("INVALID_PARAMS", "invalid children_page cursor")
    else
        0;
    const from: usize = @min(start, total);
    const end: usize = @min(from +| (if (limit > 1) limit else 1), total);
    const next: ?[]const u8 = if (end < total)
        try std.fmt.allocPrint(alloc, "{d}", .{end})
    else
        null;

    return .{
        .items = items[from..end],
        .next_cursor = next,
        .total = @intCast(total),
    };
}

/// A parser for one filesystem family (a `[[filesystem]]` entry in the LPP v2
/// manifest).
///
/// The host probes every Unknown partition with all filesystem plugins and
/// opens it with the most confident one. Implementations must be thread-safe:
/// calls for different sources can arrive concurrently.
pub const FileSystemParser = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Filesystem name; must match a `filesystem` capability in plugin.toml.
        filesystem: *const fn (ptr: *anyopaque) []const u8,
        /// Confidence (0.0 – 1.0) that `source` holds this filesystem. Probing
        /// should read only a few blocks.
        probe: *const fn (
            ptr: *anyopaque,
            ctx: host.Context,
            source: *const source.Source,
        ) sdk.Error!Probe,
        /// Opens `source` as a browsable session. `options` is the host's
        /// `fs.open` options map (currently empty).
        open: *const fn (
            ptr: *anyopaque,
            ctx: host.Context,
            source: *const source.Source,
            options: wire.Value,
        ) sdk.Error!Volume,
    };

    pub fn filesystem(self: FileSystemParser) []const u8 {
        return self.vtable.filesystem(self.ptr);
    }

    pub fn probe(
        self: FileSystemParser,
        ctx: host.Context,
        source_: *const source.Source,
    ) sdk.Error!Probe {
        return self.vtable.probe(self.ptr, ctx, source_);
    }

    pub fn open(
        self: FileSystemParser,
        ctx: host.Context,
        source_: *const source.Source,
        options: wire.Value,
    ) sdk.Error!Volume {
        return self.vtable.open(self.ptr, ctx, source_, options);
    }
};

/// Wraps `ptr` in a [`FileSystemParser`] whose vtable calls `T`'s methods.
///
/// `T` needs `filesystem`, `probe` and `open` with the shapes of
/// [`FileSystemParser.VTable`] (a leading `*T` instead of `*anyopaque`); see
/// the module header for a full example. The build fails at the call site when
/// one is missing or misspelled.
pub fn parserOf(comptime T: type, ptr: anytype) FileSystemParser {
    comptime assertInstancePtr(T, @TypeOf(ptr));
    const vtable = struct {
        fn filesystem(raw: *anyopaque) []const u8 {
            return as(T, raw).filesystem();
        }

        fn probe(
            raw: *anyopaque,
            ctx: host.Context,
            source_: *const source.Source,
        ) sdk.Error!Probe {
            return as(T, raw).probe(ctx, source_);
        }

        fn open(
            raw: *anyopaque,
            ctx: host.Context,
            source_: *const source.Source,
            options: wire.Value,
        ) sdk.Error!Volume {
            return as(T, raw).open(ctx, source_, options);
        }

        const VTable = FileSystemParser.VTable;
    };

    return .{
        .ptr = @constCast(ptr),
        .vtable = &vtable.VTable{
            .filesystem = vtable.filesystem,
            .probe = vtable.probe,
            .open = vtable.open,
        },
    };
}

/// Recovers `*T` from the erased pointer of a vtable entry.
/// `anytype` so a stateless implementation can pass a `*const T`; the pointer
/// is stored as `*anyopaque` and every other type is a compile error.
fn assertInstancePtr(comptime T: type, comptime P: type) void {
    if (P != *T and P != *const T) {
        @compileError("expected *" ++ @typeName(T) ++ " or *const " ++ @typeName(T) ++
            ", found " ++ @typeName(P));
    }
}

fn as(comptime T: type, ptr: *anyopaque) *T {
    return @ptrCast(@alignCast(ptr));
}

const testing = std.testing;

test "a node encodes every field with its kind name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var attributes: Attributes = .{};
    try attributes.put(alloc, "linux.inode", wire.uint(7));

    const node = FsNode{
        .id = "n1",
        .name = "内核",
        .parent_id = "root",
        .kind = .symlink,
        .size = 4096,
        .deleted = true,
        .inode = 7,
        .timestamps = .{
            .modified = "2023-11-14T22:13:20Z",
            .birth = "2020-09-13T12:26:40Z",
        },
        .link_target = "/boot/vmlinuz",
        .attributes = attributes,
    };

    const encoded = try node.toValue(alloc);
    try testing.expectEqualStrings("n1", encoded.getString("id").?);
    try testing.expectEqualStrings("内核", encoded.getString("name").?);
    try testing.expectEqualStrings("root", encoded.getString("parent_id").?);
    try testing.expectEqualStrings("symlink", encoded.getString("kind").?);
    try testing.expectEqual(@as(u64, 4096), encoded.getUint("size").?);
    try testing.expect(encoded.get("deleted").?.boolean);
    try testing.expectEqual(@as(u64, 7), encoded.getUint("inode").?);
    try testing.expectEqualStrings("/boot/vmlinuz", encoded.getString("link_target").?);
    try testing.expectEqual(@as(u64, 7), encoded.get("attributes").?.getUint("linux.inode").?);

    const timestamps = encoded.get("timestamps").?;
    try testing.expectEqualStrings("2023-11-14T22:13:20Z", timestamps.getString("modified").?);
    try testing.expectEqualStrings("2020-09-13T12:26:40Z", timestamps.getString("birth").?);
    // Absent fields are `nil`, never missing: the host reads all five.
    try testing.expectEqual(wire.Value.nil, timestamps.get("accessed").?);
    try testing.expectEqual(wire.Value.nil, timestamps.get("mft_changed").?);
    try testing.expectEqual(wire.Value.nil, timestamps.get("created").?);
    try testing.expectEqualStrings("modified", timestamps.map[0].key);

    // A round trip through the codec proves the reply is wire-valid.
    const decoded = try wire.decode(alloc, try wire.encode(alloc, encoded));
    try testing.expectEqualStrings("内核", decoded.getString("name").?);
    try testing.expectEqualStrings("symlink", decoded.getString("kind").?);
}

test "every node kind keeps its wire name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const cases = [_]struct { kind: NodeKind, name: []const u8 }{
        .{ .kind = .dir, .name = "dir" },
        .{ .kind = .file, .name = "file" },
        .{ .kind = .symlink, .name = "symlink" },
        .{ .kind = .unallocated, .name = "unallocated" },
    };
    for (cases) |case| {
        const encoded = try (FsNode{ .id = "n", .name = "n", .kind = case.kind }).toValue(alloc);
        try testing.expectEqualStrings(case.name, encoded.getString("kind").?);
    }
    // A node with nothing set still emits every field, optionals as `nil`.
    const bare = try (FsNode{ .id = "n", .name = "n" }).toValue(alloc);
    try testing.expectEqual(@as(usize, 10), bare.map.len);
    try testing.expectEqual(wire.Value.nil, bare.get("parent_id").?);
    try testing.expectEqual(wire.Value.nil, bare.get("inode").?);
    try testing.expectEqual(wire.Value.nil, bare.get("link_target").?);
    try testing.expectEqual(@as(usize, 0), bare.get("attributes").?.map.len);
}

test "a stat encodes mode and entropy as nil when unset" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const full = try (FsStat{
        .node_id = "data",
        .size = 12,
        .inode = 3,
        .mode = 0o644,
        .mime = "text/plain",
        .magic_hex = "89504e47",
        .entropy = 7.25,
    }).toValue(alloc);
    try testing.expectEqualStrings("data", full.getString("node_id").?);
    try testing.expectEqual(@as(u64, 12), full.getUint("size").?);
    try testing.expectEqual(@as(u64, 0o644), full.getUint("mode").?);
    // The host DTO is Option<u16>, so the Zig field has to be u16 too.
    try testing.expect(@TypeOf(@as(FsStat, undefined).mode) == ?u16);
    try testing.expectEqualStrings("text/plain", full.getString("mime").?);
    try testing.expectEqualStrings("89504e47", full.getString("magic_hex").?);
    try testing.expectEqual(@as(f64, 7.25), full.get("entropy").?.float);

    const bare = try (FsStat{ .node_id = "data" }).toValue(alloc);
    try testing.expectEqual(@as(usize, 8), bare.map.len);
    try testing.expectEqual(wire.Value.nil, bare.get("mode").?);
    // mime is always a string: the host DTO is `mime: String`, not an Option.
    try testing.expectEqualStrings(DEFAULT_MIME, bare.getString("mime").?);
    try testing.expectEqual(wire.Value.nil, bare.get("magic_hex").?);
    try testing.expectEqual(wire.Value.nil, bare.get("entropy").?);
    try testing.expectEqual(@as(u64, 0), bare.getUint("size").?);
}

test "a node page encodes its items, cursor and total" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const items = try slice(FsNode, alloc, &.{
        .{ .id = "n0", .name = "0" },
        .{ .id = "n1", .name = "1", .kind = .dir },
    });
    const encoded = try (NodePage{
        .items = items,
        .next_cursor = "2",
        .total = 5,
    }).toValue(alloc);

    try testing.expectEqual(@as(usize, 2), encoded.get("items").?.array.len);
    try testing.expectEqualStrings("n1", encoded.get("items").?.array[1].getString("id").?);
    try testing.expectEqualStrings("dir", encoded.get("items").?.array[1].getString("kind").?);
    try testing.expectEqualStrings("2", encoded.getString("next_cursor").?);
    try testing.expectEqual(@as(u64, 5), encoded.getUint("total").?);

    const last = try (NodePage{ .items = &.{} }).toValue(alloc);
    try testing.expectEqual(@as(usize, 0), last.get("items").?.array.len);
    try testing.expectEqual(wire.Value.nil, last.get("next_cursor").?);
    try testing.expectEqual(wire.Value.nil, last.get("total").?);
}

test "a probe with no match reports zero confidence" {
    const probe = Probe.noMatch();
    try testing.expectEqual(@as(f64, 0), probe.confidence);
    try testing.expectEqual(null, probe.label);

    const matched = Probe{ .confidence = 0.5, .label = "raw" };
    try testing.expect(matched.confidence > probe.confidence);
    try testing.expectEqualStrings("raw", matched.label.?);
}

const FakeVolume = struct {
    close_calls: usize = 0,

    pub fn rootNode(self: *FakeVolume, alloc: std.mem.Allocator) sdk.Error!FsNode {
        _ = .{ self, alloc };
        return .{ .id = "root", .name = "/", .kind = .dir };
    }

    pub fn children(
        self: *FakeVolume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
    ) sdk.Error![]const FsNode {
        _ = self;
        if (!std.mem.eql(u8, node_id, "root")) return &.{};
        return slice(FsNode, alloc, &.{
            .{ .id = "n0", .name = "0" },
            .{ .id = "n1", .name = "1" },
            .{ .id = "n2", .name = "2" },
            .{ .id = "n3", .name = "3" },
            .{ .id = "n4", .name = "4" },
        });
    }

    pub fn childrenPage(
        self: *FakeVolume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
        limit: usize,
        cursor: ?[]const u8,
    ) sdk.Error!NodePage {
        return defaultChildrenPage(FakeVolume, self, alloc, node_id, limit, cursor);
    }

    pub fn stat(
        self: *FakeVolume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
    ) sdk.Error!FsStat {
        _ = self;
        if (!std.mem.eql(u8, node_id, "n0")) {
            return sdk.fail("NOT_FOUND", "no such node");
        }
        _ = alloc;
        return .{ .node_id = node_id, .size = 12 };
    }

    pub fn read(
        self: *FakeVolume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
        offset: u64,
        length: usize,
    ) sdk.Error![]u8 {
        _ = self;
        if (!std.mem.eql(u8, node_id, "n0")) {
            return sdk.fail("NOT_FOUND", "no such node");
        }
        _ = offset;
        const data = try alloc.alloc(u8, length);
        @memset(data, 'x');
        return data;
    }

    pub fn close(self: *FakeVolume, alloc: std.mem.Allocator) void {
        _ = alloc;
        self.close_calls += 1;
    }
};

test "volumeOf round-trips every call through the vtable" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var fake = FakeVolume{};
    const volume = volumeOf(FakeVolume, &fake);

    const root = try volume.rootNode(alloc);
    try testing.expectEqualStrings("root", root.id);
    try testing.expectEqualStrings("dir", root.kind.name());

    const children = try volume.children(alloc, "root");
    try testing.expectEqual(@as(usize, 5), children.len);
    try testing.expectEqualStrings("n4", children[4].id);
    try testing.expectEqual(@as(usize, 0), (try volume.children(alloc, "other")).len);

    const page = try volume.stat(alloc, "n0");
    try testing.expectEqual(@as(u64, 12), page.size);
    try testing.expectError(error.Fault, volume.stat(alloc, "n9"));
    try testing.expectEqualStrings("NOT_FOUND", sdk.codeOf(error.Fault));
    _ = sdk.take();

    const data = try volume.read(alloc, "n0", 5, 3);
    try testing.expectEqualSlices(u8, "xxx", data);
    try testing.expectError(error.Fault, volume.read(alloc, "n9", 0, 1));
    _ = sdk.take();

    volume.close(alloc);
    try testing.expectEqual(@as(usize, 1), fake.close_calls);
}

test "the default page walks an offset cursor" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var fake = FakeVolume{};
    const volume = volumeOf(FakeVolume, &fake);

    const first = try volume.childrenPage(alloc, "root", 2, null);
    try testing.expectEqual(@as(usize, 2), first.items.len);
    try testing.expectEqualStrings("n0", first.items[0].id);
    try testing.expectEqualStrings("2", first.next_cursor.?);
    try testing.expectEqual(@as(u64, 5), first.total.?);

    const second = try volume.childrenPage(alloc, "root", 2, first.next_cursor);
    try testing.expectEqual(@as(usize, 2), second.items.len);
    try testing.expectEqualStrings("n2", second.items[0].id);
    try testing.expectEqualStrings("4", second.next_cursor.?);

    // A cursor past the end yields an empty last page, not an error.
    const last = try volume.childrenPage(alloc, "root", 2, "4");
    try testing.expectEqual(@as(usize, 1), last.items.len);
    try testing.expectEqualStrings("n4", last.items[0].id);
    try testing.expectEqual(null, last.next_cursor);
    try testing.expectEqual(@as(u64, 5), last.total.?);

    const past = try volume.childrenPage(alloc, "root", 2, "99");
    try testing.expectEqual(@as(usize, 0), past.items.len);
    try testing.expectEqual(null, past.next_cursor);

    // `limit` is clamped to at least one item per page.
    const clamped = try volume.childrenPage(alloc, "root", 0, null);
    try testing.expectEqual(@as(usize, 1), clamped.items.len);
    try testing.expectEqualStrings("1", clamped.next_cursor.?);

    // An unparsable cursor is INVALID_PARAMS, as in the Rust reference.
    try testing.expectError(
        error.Fault,
        volume.childrenPage(alloc, "root", 2, "not-a-number"),
    );
    try testing.expectEqualStrings("INVALID_PARAMS", sdk.codeOf(error.Fault));
    try testing.expectEqualStrings("invalid children_page cursor", sdk.messageOf(error.Fault));
    _ = sdk.take();
}

const FakeParser = struct {
    pub fn filesystem(self: *FakeParser) []const u8 {
        _ = self;
        return "fake";
    }

    pub fn probe(
        self: *FakeParser,
        ctx: host.Context,
        source_: *const source.Source,
    ) sdk.Error!Probe {
        _ = self;
        _ = .{ ctx, source_ };
        return Probe{ .confidence = 0.25, .label = "fake" };
    }

    pub fn open(
        self: *FakeParser,
        ctx: host.Context,
        source_: *const source.Source,
        options: wire.Value,
    ) sdk.Error!Volume {
        _ = self;
        _ = .{ ctx, source_ };
        if (options.get("fail") != null) return sdk.fail("INVALID_PARAMS", "no");
        const volume = try ctx.arena.create(FakeVolume);
        volume.* = .{};
        return volumeOf(FakeVolume, volume);
    }
};

test "parserOf round-trips probe and open through the vtable" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var cancelled = std.atomic.Value(bool).init(false);
    const ctx = host.Context{
        .host = undefined,
        .cancelled = &cancelled,
        .arena = alloc,
        .alloc = alloc,
    };

    var fake = FakeParser{};
    const parser = parserOf(FakeParser, &fake);
    try testing.expectEqualStrings("fake", parser.filesystem());

    const probe = try parser.probe(ctx, undefined);
    try testing.expectEqual(@as(f64, 0.25), probe.confidence);
    try testing.expectEqualStrings("fake", probe.label.?);

    const options = try value.map(alloc, &.{value.entry("empty", .nil)});
    const volume = try parser.open(ctx, undefined, options);
    const root = try volume.rootNode(alloc);
    try testing.expectEqualStrings("root", root.id);

    const refusing = try value.map(alloc, &.{value.entry("fail", value.boolean(true))});
    try testing.expectError(error.Fault, parser.open(ctx, undefined, refusing));
    try testing.expectEqualStrings("INVALID_PARAMS", sdk.codeOf(error.Fault));
    _ = sdk.take();
}
