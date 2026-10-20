//! LPP v2 method names, limits and payloads, shared by the SDK, the host and
//! LovelyCarve.
//!
//! Payloads are MessagePack maps keyed by field name (the Rust SDK writes them
//! with rmp_serde::to_vec_named). Unknown fields are ignored and optional
//! fields may be missing, so a later minor revision can add fields without
//! breaking either side.
//!
//! Every type has two decoders:
//!
//! * fromValueWith(alloc, value) allocates list storage from alloc and borrows
//!   strings from value, so the result lives as long as the arena that decoded
//!   the frame. Use it whenever an allocator is at hand.
//! * fromValue(value) is the allocator-free form: it borrows strings the same
//!   way but allocates list storage from a thread-local scratch arena. The
//!   result stays valid for the rest of the host call; call resetDecoder to
//!   free that arena between calls.

const std = @import("std");

const wire = @import("wire.zig");
const sdk = @import("error.zig");

/// The LPP version this SDK speaks.
pub const VERSION: u16 = 2;

/// Largest byte count one file.read returns.
pub const MAX_READ: u64 = 4 * 1024 * 1024;
/// Most ranges of one file.readv.
pub const MAX_READV_RANGES: usize = 64;
/// Most bytes of one file.readv (leaves room for framing in 8 MiB).
pub const MAX_READV_BYTES: u64 = 8 * 1024 * 1024 - 4096;
/// Most nodes of one view.list page.
pub const MAX_LIST_PAGE: u64 = 512;
/// Most records of one run.emit batch.
pub const MAX_BATCH_RECORDS: usize = 4096;
/// Most paths one view.find returns before RESOURCE_LIMIT.
pub const MAX_FIND_RESULTS: usize = 4096;
/// Most ranges of one source.readv.
pub const MAX_SOURCE_READV_RANGES: usize = 128;
/// Most bytes of one source.readv.
pub const MAX_SOURCE_READV_BYTES: u64 = 8 * 1024 * 1024 - 4096;

/// Every LPP v2 method name.
pub const method = struct {
    pub const hello = "plugin.hello";
    pub const shutdown = "plugin.shutdown";

    pub const run_start = "run.start";
    pub const run_emit = "run.emit";
    pub const run_warn = "run.warn";
    pub const run_progress = "run.progress";

    pub const file_read = "file.read";
    pub const file_readv = "file.readv";
    pub const file_materialize = "file.materialize";
    pub const file_release = "file.release";

    pub const view_stat = "view.stat";
    pub const view_open = "view.open";
    pub const view_list = "view.list";
    pub const view_find = "view.find";

    pub const source_info = "source.info";
    pub const source_read = "source.read";
    pub const source_readv = "source.readv";
};

/// An empty MessagePack map, for payload fields that default to an empty map.
pub const empty_map: wire.Value = .{ .map = &.{} };

// ---------------------------------------------------------------- decoding

threadlocal var scratch: ?std.heap.ArenaAllocator = null;

/// The scratch arena behind the allocator-free fromValue decoders of this
/// thread.
fn decoder() std.mem.Allocator {
    if (scratch == null) scratch = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    const arena = if (scratch) |*state| state else unreachable;
    return arena.allocator();
}

/// Frees the list storage handed out by the allocator-free decoders on this
/// thread. Nothing may use a value decoded with fromValue afterwards.
pub fn resetDecoder() void {
    if (scratch) |*arena| _ = arena.reset(.retain_capacity);
}

fn requiredString(value: wire.Value, key: []const u8) sdk.Error![]const u8 {
    const found = value.get(key) orelse
        return sdk.failfmt("INVALID_PARAMS", "{s} is missing", .{key});
    return switch (found) {
        .string => |text| text,
        else => sdk.failfmt("INVALID_PARAMS", "{s} must be a string", .{key}),
    };
}

fn optionalString(value: wire.Value, key: []const u8) ?[]const u8 {
    return value.getString(key);
}

fn requiredUint(value: wire.Value, key: []const u8) sdk.Error!u64 {
    const found = value.get(key) orelse
        return sdk.failfmt("INVALID_PARAMS", "{s} is missing", .{key});
    return switch (found) {
        .uint => |number| number,
        .int => |number| if (number >= 0)
            @intCast(number)
        else
            sdk.failfmt("INVALID_PARAMS", "{s} must be an unsigned integer", .{key}),
        else => sdk.failfmt("INVALID_PARAMS", "{s} must be an unsigned integer", .{key}),
    };
}

fn uintOr(value: wire.Value, key: []const u8, default: u64) u64 {
    return switch (value.get(key) orelse return default) {
        .uint => |number| number,
        .int => |number| if (number >= 0) @intCast(number) else default,
        else => default,
    };
}

fn boolOr(value: wire.Value, key: []const u8, default: bool) bool {
    return switch (value.get(key) orelse return default) {
        .boolean => |flag| flag,
        else => default,
    };
}

/// A nested map field; a missing or nil field is an empty map.
fn objectOr(value: wire.Value, key: []const u8) wire.Value {
    const found = value.get(key) orelse return empty_map;
    return switch (found) {
        .map => found,
        else => empty_map,
    };
}

fn requiredObject(value: wire.Value, key: []const u8) sdk.Error!wire.Value {
    const found = value.get(key) orelse
        return sdk.failfmt("INVALID_PARAMS", "{s} is missing", .{key});
    return switch (found) {
        .map => found,
        else => sdk.failfmt("INVALID_PARAMS", "{s} must be a map", .{key}),
    };
}

/// An array field; a missing or nil field is an empty list.
fn arrayOr(value: wire.Value, key: []const u8) []const wire.Value {
    return switch (value.get(key) orelse return &.{}) {
        .array => |items| items,
        else => &.{},
    };
}

fn stringOrNull(text: ?[]const u8) wire.Value {
    return if (text) |slice| wire.str(slice) else .nil;
}

// ----------------------------------------------------------------- payloads

/// File system timestamps (RFC 3339) as the file system records them.
pub const Timestamps = struct {
    modified: ?[]const u8 = null,
    accessed: ?[]const u8 = null,
    created: ?[]const u8 = null,
    changed: ?[]const u8 = null,
    birth: ?[]const u8 = null,

    pub fn fromValue(value: wire.Value) sdk.Error!Timestamps {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!Timestamps {
        _ = alloc;
        return .{
            .modified = optionalString(value, "modified"),
            .accessed = optionalString(value, "accessed"),
            .created = optionalString(value, "created"),
            .changed = optionalString(value, "changed"),
            .birth = optionalString(value, "birth"),
        };
    }

    pub fn toValue(self: Timestamps, alloc: std.mem.Allocator) wire.Error!wire.Value {
        return wire.mapOf(alloc, &.{
            wire.entry("modified", stringOrNull(self.modified)),
            wire.entry("accessed", stringOrNull(self.accessed)),
            wire.entry("created", stringOrNull(self.created)),
            wire.entry("changed", stringOrNull(self.changed)),
            wire.entry("birth", stringOrNull(self.birth)),
        });
    }
};

/// A read-only file handle issued for one run.
pub const FileInfo = struct {
    file_id: []const u8,
    name: []const u8,
    size: u64,
    mime: ?[]const u8 = null,
    /// Path inside the run's view (for files opened through one).
    view_path: ?[]const u8 = null,
    /// Volume key the file lives on (part:1).
    root: ?[]const u8 = null,
    /// Path inside that volume.
    root_path: ?[]const u8 = null,
    node_id: ?[]const u8 = null,
    deleted: bool = false,
    timestamps: Timestamps = .{},

    pub fn fromValue(value: wire.Value) sdk.Error!FileInfo {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!FileInfo {
        return .{
            .file_id = try requiredString(value, "file_id"),
            .name = optionalString(value, "name") orelse "",
            .size = uintOr(value, "size", 0),
            .mime = optionalString(value, "mime"),
            .view_path = optionalString(value, "view_path"),
            .root = optionalString(value, "root"),
            .root_path = optionalString(value, "root_path"),
            .node_id = optionalString(value, "node_id"),
            .deleted = boolOr(value, "deleted", false),
            .timestamps = try Timestamps.fromValueWith(alloc, objectOr(value, "timestamps")),
        };
    }

    pub fn toValue(self: FileInfo, alloc: std.mem.Allocator) wire.Error!wire.Value {
        return wire.mapOf(alloc, &.{
            wire.entry("file_id", wire.str(self.file_id)),
            wire.entry("name", wire.str(self.name)),
            wire.entry("size", wire.uint(self.size)),
            wire.entry("mime", stringOrNull(self.mime)),
            wire.entry("view_path", stringOrNull(self.view_path)),
            wire.entry("root", stringOrNull(self.root)),
            wire.entry("root_path", stringOrNull(self.root_path)),
            wire.entry("node_id", stringOrNull(self.node_id)),
            wire.entry("deleted", .{ .boolean = self.deleted }),
            wire.entry("timestamps", try self.timestamps.toValue(alloc)),
        });
    }
};

/// A detected operating-system installation.
pub const SystemInfo = struct {
    /// Stable id inside the evidence (linux@part:2).
    id: []const u8,
    /// linux, windows, macos, esxi, mikrotik, openwrt or dingtalk.
    family: []const u8,
    product: []const u8,
    version: ?[]const u8 = null,
    /// Volume key of the root (system) volume.
    root: []const u8,

    pub fn fromValue(value: wire.Value) sdk.Error!SystemInfo {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!SystemInfo {
        _ = alloc;
        return .{
            .id = try requiredString(value, "id"),
            .family = try requiredString(value, "family"),
            .product = optionalString(value, "product") orelse "",
            .version = optionalString(value, "version"),
            .root = optionalString(value, "root") orelse "",
        };
    }

    pub fn toValue(self: SystemInfo, alloc: std.mem.Allocator) wire.Error!wire.Value {
        return wire.mapOf(alloc, &.{
            wire.entry("id", wire.str(self.id)),
            wire.entry("family", wire.str(self.family)),
            wire.entry("product", wire.str(self.product)),
            wire.entry("version", stringOrNull(self.version)),
            wire.entry("root", wire.str(self.root)),
        });
    }
};

/// One mount of a view: path (empty for the root, home, C:) shows volume root.
pub const MountInfo = struct {
    path: []const u8,
    root: []const u8,
    /// Where the mapping came from: root, fstab, drive_letter or volume.
    source: []const u8,

    pub fn fromValue(value: wire.Value) sdk.Error!MountInfo {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!MountInfo {
        _ = alloc;
        return .{
            .path = optionalString(value, "path") orelse "",
            .root = optionalString(value, "root") orelse "",
            .source = optionalString(value, "source") orelse "",
        };
    }

    pub fn toValue(self: MountInfo, alloc: std.mem.Allocator) wire.Error!wire.Value {
        return wire.mapOf(alloc, &.{
            wire.entry("path", wire.str(self.path)),
            wire.entry("root", wire.str(self.root)),
            wire.entry("source", wire.str(self.source)),
        });
    }
};

/// A read-only path tree issued for one run.
pub const ViewInfo = struct {
    view_id: []const u8,
    label: []const u8,
    system: ?SystemInfo = null,
    /// How the view's top-level paths map to volumes.
    mounts: []const MountInfo = &.{},

    pub fn fromValue(value: wire.Value) sdk.Error!ViewInfo {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!ViewInfo {
        const items = arrayOr(value, "mounts");
        const mounts = try alloc.alloc(MountInfo, items.len);
        for (items, mounts) |item, *slot| {
            slot.* = try MountInfo.fromValueWith(alloc, item);
        }
        const system: ?SystemInfo = if (value.get("system")) |system_value|
            switch (system_value) {
                .map => try SystemInfo.fromValueWith(alloc, system_value),
                else => null,
            }
        else
            null;
        return .{
            .view_id = try requiredString(value, "view_id"),
            .label = optionalString(value, "label") orelse "",
            .system = system,
            .mounts = mounts,
        };
    }

    pub fn toValue(self: ViewInfo, alloc: std.mem.Allocator) wire.Error!wire.Value {
        const mounts = try alloc.alloc(wire.Value, self.mounts.len);
        for (self.mounts, mounts) |mount, *slot| slot.* = try mount.toValue(alloc);
        return wire.mapOf(alloc, &.{
            wire.entry("view_id", wire.str(self.view_id)),
            wire.entry("label", wire.str(self.label)),
            wire.entry("system", if (self.system) |system| try system.toValue(alloc) else .nil),
            wire.entry("mounts", .{ .array = mounts }),
        });
    }
};

/// What a run looks at.
pub const Target = union(enum) {
    /// The run's inputs are the files to analyze.
    files,
    /// One detected operating system, its volumes mounted in one tree.
    system: ViewInfo,
    /// Every volume of the evidence, each a top-level directory named by its
    /// volume key.
    evidence: ViewInfo,

    pub fn fromValue(value: wire.Value) sdk.Error!Target {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!Target {
        const kind = try requiredString(value, "kind");
        if (std.mem.eql(u8, kind, "files")) return .files;
        if (std.mem.eql(u8, kind, "system")) {
            return .{ .system = try ViewInfo.fromValueWith(alloc, try requiredObject(value, "view")) };
        }
        if (std.mem.eql(u8, kind, "evidence")) {
            return .{ .evidence = try ViewInfo.fromValueWith(alloc, try requiredObject(value, "view")) };
        }
        return sdk.failfmt("INVALID_PARAMS", "target kind {s} is unknown", .{kind});
    }

    pub fn toValue(self: Target, alloc: std.mem.Allocator) wire.Error!wire.Value {
        return switch (self) {
            .files => wire.mapOf(alloc, &.{wire.entry("kind", wire.str("files"))}),
            .system => |info| wire.mapOf(alloc, &.{
                wire.entry("kind", wire.str("system")),
                wire.entry("view", try info.toValue(alloc)),
            }),
            .evidence => |info| wire.mapOf(alloc, &.{
                wire.entry("kind", wire.str("evidence")),
                wire.entry("view", try info.toValue(alloc)),
            }),
        };
    }
};

/// run.start: run one analyzer to completion. The reply is RunFinish.
pub const RunStart = struct {
    run_id: []const u8,
    analyzer: []const u8,
    target: Target,
    /// Files the host resolved for the run: the selected file of a files run,
    /// or the matches of the analyzer's declared inputs.
    inputs: []const FileInfo = &.{},
    options: wire.Value = empty_map,
    /// Evidence profile facts known before the run (timezone, ...).
    profile: wire.Value = empty_map,
    /// UI locale (zh-CN, en) for text the analyzer writes itself.
    locale: []const u8 = "",

    pub fn fromValue(value: wire.Value) sdk.Error!RunStart {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!RunStart {
        const items = arrayOr(value, "inputs");
        const inputs = try alloc.alloc(FileInfo, items.len);
        for (items, inputs) |item, *slot| slot.* = try FileInfo.fromValueWith(alloc, item);
        return .{
            .run_id = try requiredString(value, "run_id"),
            .analyzer = try requiredString(value, "analyzer"),
            .target = try Target.fromValueWith(alloc, try requiredObject(value, "target")),
            .inputs = inputs,
            .options = objectOr(value, "options"),
            .profile = objectOr(value, "profile"),
            .locale = optionalString(value, "locale") orelse "",
        };
    }

    pub fn toValue(self: RunStart, alloc: std.mem.Allocator) wire.Error!wire.Value {
        const inputs = try alloc.alloc(wire.Value, self.inputs.len);
        for (self.inputs, inputs) |info, *slot| slot.* = try info.toValue(alloc);
        return wire.mapOf(alloc, &.{
            wire.entry("run_id", wire.str(self.run_id)),
            wire.entry("analyzer", wire.str(self.analyzer)),
            wire.entry("target", try self.target.toValue(alloc)),
            wire.entry("inputs", .{ .array = inputs }),
            wire.entry("options", self.options),
            wire.entry("profile", self.profile),
            wire.entry("locale", wire.str(self.locale)),
        });
    }
};

/// The reply to run.start.
pub const RunFinish = struct {
    summary: ?[]const u8 = null,

    pub fn fromValue(value: wire.Value) sdk.Error!RunFinish {
        return .{ .summary = optionalString(value, "summary") };
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!RunFinish {
        _ = alloc;
        return fromValue(value);
    }

    pub fn toValue(self: RunFinish, alloc: std.mem.Allocator) wire.Error!wire.Value {
        return wire.mapOf(alloc, &.{wire.entry("summary", stringOrNull(self.summary))});
    }
};

/// run.emit: one batch of records, answered with EmitAck once the host stored
/// it (the batch is the plugin's backpressure).
pub const EmitAck = struct {
    accepted: u64,

    pub fn fromValue(value: wire.Value) sdk.Error!EmitAck {
        return .{ .accepted = try requiredUint(value, "accepted") };
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!EmitAck {
        _ = alloc;
        return fromValue(value);
    }

    pub fn toValue(self: EmitAck, alloc: std.mem.Allocator) wire.Error!wire.Value {
        return wire.mapOf(alloc, &.{wire.entry("accepted", wire.uint(self.accepted))});
    }
};

/// A directory entry or path lookup result.
pub const NodeInfo = struct {
    name: []const u8,
    /// file, dir, link or other.
    kind: []const u8,
    size: u64 = 0,
    deleted: bool = false,
    link_target: ?[]const u8 = null,
    timestamps: Timestamps = .{},

    pub fn fromValue(value: wire.Value) sdk.Error!NodeInfo {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!NodeInfo {
        return .{
            .name = optionalString(value, "name") orelse "",
            .kind = optionalString(value, "kind") orelse "other",
            .size = uintOr(value, "size", 0),
            .deleted = boolOr(value, "deleted", false),
            .link_target = optionalString(value, "link_target"),
            .timestamps = try Timestamps.fromValueWith(alloc, objectOr(value, "timestamps")),
        };
    }

    pub fn toValue(self: NodeInfo, alloc: std.mem.Allocator) wire.Error!wire.Value {
        return wire.mapOf(alloc, &.{
            wire.entry("name", wire.str(self.name)),
            wire.entry("kind", wire.str(self.kind)),
            wire.entry("size", wire.uint(self.size)),
            wire.entry("deleted", .{ .boolean = self.deleted }),
            wire.entry("link_target", stringOrNull(self.link_target)),
            wire.entry("timestamps", try self.timestamps.toValue(alloc)),
        });
    }
};

/// view.list: one page of a directory and the directory's total count.
pub const NodePage = struct {
    nodes: []const NodeInfo = &.{},
    total: u64 = 0,

    pub fn fromValue(value: wire.Value) sdk.Error!NodePage {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!NodePage {
        const items = arrayOr(value, "nodes");
        const nodes = try alloc.alloc(NodeInfo, items.len);
        for (items, nodes) |item, *slot| slot.* = try NodeInfo.fromValueWith(alloc, item);
        return .{
            .nodes = nodes,
            .total = uintOr(value, "total", 0),
        };
    }

    pub fn toValue(self: NodePage, alloc: std.mem.Allocator) wire.Error!wire.Value {
        const nodes = try alloc.alloc(wire.Value, self.nodes.len);
        for (self.nodes, nodes) |node, *slot| slot.* = try node.toValue(alloc);
        return wire.mapOf(alloc, &.{
            wire.entry("nodes", .{ .array = nodes }),
            wire.entry("total", wire.uint(self.total)),
        });
    }
};

/// view.find: paths matching glob patterns (double star crosses directories,
/// star and question mark stay inside one name; ASCII case-insensitive).
pub const FindPage = struct {
    paths: [][]const u8 = &.{},
    visited: u64 = 0,
    cursor: ?[]const u8 = null,

    pub fn fromValue(value: wire.Value) sdk.Error!FindPage {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!FindPage {
        const items = arrayOr(value, "paths");
        const paths = try alloc.alloc([]const u8, items.len);
        for (items, paths) |item, *slot| {
            slot.* = switch (item) {
                .string => |text| text,
                else => return sdk.fail("INVALID_PARAMS", "view.find paths must be strings"),
            };
        }
        return .{
            .paths = paths,
            .visited = uintOr(value, "visited", 0),
            .cursor = optionalString(value, "cursor"),
        };
    }

    pub fn toValue(self: FindPage, alloc: std.mem.Allocator) wire.Error!wire.Value {
        const paths = try alloc.alloc(wire.Value, self.paths.len);
        for (self.paths, paths) |path, *slot| slot.* = wire.str(path);
        return wire.mapOf(alloc, &.{
            wire.entry("paths", .{ .array = paths }),
            wire.entry("visited", wire.uint(self.visited)),
            wire.entry("cursor", stringOrNull(self.cursor)),
        });
    }
};

/// A host-owned temporary copy of a file (file.materialize).
pub const Lease = struct {
    lease_id: []const u8,
    path: []const u8,
    size: u64 = 0,

    pub fn fromValue(value: wire.Value) sdk.Error!Lease {
        return fromValueWith(decoder(), value);
    }

    pub fn fromValueWith(alloc: std.mem.Allocator, value: wire.Value) sdk.Error!Lease {
        _ = alloc;
        return .{
            .lease_id = try requiredString(value, "lease_id"),
            .path = try requiredString(value, "path"),
            .size = uintOr(value, "size", 0),
        };
    }

    pub fn toValue(self: Lease, alloc: std.mem.Allocator) wire.Error!wire.Value {
        return wire.mapOf(alloc, &.{
            wire.entry("lease_id", wire.str(self.lease_id)),
            wire.entry("path", wire.str(self.path)),
            wire.entry("size", wire.uint(self.size)),
        });
    }
};

const testing = std.testing;

test "run.start round-trips through values" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const view = ViewInfo{
        .view_id = "view-1",
        .label = "Kali",
        .system = .{
            .id = "linux@part:0",
            .family = "linux",
            .product = "Kali GNU/Linux",
            .version = "2024.1",
            .root = "part:0",
        },
        .mounts = try alloc.dupe(MountInfo, &.{
            .{ .path = "", .root = "part:0", .source = "root" },
            .{ .path = "home", .root = "part:1", .source = "fstab" },
        }),
    };
    const start = RunStart{
        .run_id = "run-1",
        .analyzer = "base",
        .target = .{ .system = view },
        .inputs = try alloc.dupe(FileInfo, &.{.{
            .file_id = "f1",
            .name = "os-release",
            .size = 3,
            .view_path = "etc/os-release",
            .root = "part:0",
            .root_path = "etc/os-release",
        }}),
        .options = try wire.mapOf(alloc, &.{
            wire.entry("items", try wire.arrayOf(alloc, &.{wire.str("users")})),
        }),
        .profile = empty_map,
        .locale = "zh-CN",
    };

    const encoded = try start.toValue(alloc);
    const decoded = try RunStart.fromValueWith(alloc, encoded);
    try testing.expectEqualStrings("run-1", decoded.run_id);
    try testing.expectEqualStrings("base", decoded.analyzer);
    try testing.expectEqualStrings("zh-CN", decoded.locale);
    try testing.expectEqual(@as(usize, 1), decoded.inputs.len);
    try testing.expectEqualStrings("etc/os-release", decoded.inputs[0].root_path.?);
    const system = decoded.target.system.system.?;
    try testing.expectEqualStrings("2024.1", system.version.?);
    try testing.expectEqual(@as(usize, 2), decoded.target.system.mounts.len);
    try testing.expectEqualStrings("part:1", decoded.target.system.mounts[1].root);
    try testing.expectEqualStrings(
        "users",
        decoded.options.get("items").?.array[0].string,
    );
    try testing.expectEqual(0, decoded.profile.map.len);
}

test "files target decodes from a bare kind" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const value = try wire.mapOf(alloc, &.{wire.entry("kind", wire.str("files"))});
    const target = try Target.fromValueWith(alloc, value);
    try testing.expectEqual(Target.files, target);
}

test "missing optional fields default" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const value = try wire.mapOf(alloc, &.{
        wire.entry("file_id", wire.str("f1")),
        wire.entry("name", wire.str("a.bin")),
        wire.entry("size", wire.uint(3)),
        wire.entry("future_field", .{ .boolean = true }),
    });
    const info = try FileInfo.fromValueWith(alloc, value);
    try testing.expectEqual(null, info.root);
    try testing.expectEqual(null, info.timestamps.modified);
    try testing.expect(!info.deleted);

    const timestamps = try Timestamps.fromValueWith(alloc, empty_map);
    try testing.expectEqual(null, timestamps.birth);
    const encoded = try timestamps.toValue(alloc);
    try testing.expectEqual(wire.Value.nil, encoded.get("modified").?);
}

test "node and find pages decode their lists" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const page_value = try wire.mapOf(alloc, &.{
        wire.entry("nodes", try wire.arrayOf(alloc, &.{
            try wire.mapOf(alloc, &.{
                wire.entry("name", wire.str("etc")),
                wire.entry("kind", wire.str("dir")),
            }),
        })),
        wire.entry("total", wire.uint(1)),
    });
    const page = try NodePage.fromValueWith(alloc, page_value);
    try testing.expectEqual(@as(u64, 1), page.total);
    try testing.expectEqualStrings("dir", page.nodes[0].kind);

    const find_value = try wire.mapOf(alloc, &.{
        wire.entry("paths", try wire.arrayOf(alloc, &.{
            wire.str("etc/passwd"),
            wire.str("etc/hostname"),
        })),
        wire.entry("visited", wire.uint(12)),
    });
    const found = try FindPage.fromValueWith(alloc, find_value);
    try testing.expectEqual(@as(usize, 2), found.paths.len);
    try testing.expectEqual(@as(u64, 12), found.visited);
    try testing.expectEqual(null, found.cursor);
}

test "the allocator-free decoder borrows from the value" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer resetDecoder();

    const value = try wire.mapOf(alloc, &.{
        wire.entry("run_id", wire.str("run-9")),
        wire.entry("analyzer", wire.str("base")),
        wire.entry("target", try wire.mapOf(alloc, &.{wire.entry("kind", wire.str("files"))})),
        wire.entry("inputs", try wire.arrayOf(alloc, &.{
            try wire.mapOf(alloc, &.{
                wire.entry("file_id", wire.str("f1")),
                wire.entry("name", wire.str("a")),
                wire.entry("size", wire.uint(1)),
            }),
        })),
    });
    const start = try RunStart.fromValue(value);
    try testing.expectEqualStrings("run-9", start.run_id);
    try testing.expectEqual(@as(usize, 1), start.inputs.len);
    try testing.expectEqual(0, start.options.map.len);
}
