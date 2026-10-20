//! Path access to a system or evidence view.
//!
//! A system view is one detected operating system with its volumes mounted in
//! one tree (Linux mounts from /etc/fstab, Windows drive letters as top-level
//! `C:` directories). An evidence view shows every volume of the evidence as a
//! top-level directory named by its volume key (`part:1`). Paths are
//! `/`-separated and relative to the view (`etc/passwd`); `..` is refused by
//! the host. `stat` and `open` follow symbolic links, `list` does not.
//!
//! Host calls used here: `view.stat`, `view.open`, `view.list` and
//! `view.find` (see `protocol.method`).

const std = @import("std");

const file = @import("file.zig");
const glob = @import("glob.zig");
const host = @import("host.zig");
const protocol = @import("protocol.zig");
const record = @import("record.zig");
const sdk = @import("error.zig");
const value = @import("value.zig");
const wire = @import("wire.zig");

/// What a node is on the wire.
pub const NodeKind = enum {
    file,
    dir,
    link,
    other,

    /// The `kind` the host sends.
    pub fn fromStr(text: []const u8) NodeKind {
        if (std.mem.eql(u8, text, "file")) return .file;
        if (std.mem.eql(u8, text, "dir")) return .dir;
        if (std.mem.eql(u8, text, "link")) return .link;
        return .other;
    }

    /// The wire name.
    pub fn name(self: NodeKind) []const u8 {
        return @tagName(self);
    }
};

/// A directory entry or path lookup result.
pub const Node = struct {
    name: []const u8,
    kind: NodeKind = .other,
    size: u64 = 0,
    deleted: bool = false,
    link_target: ?[]const u8 = null,
    timestamps: protocol.Timestamps = .{},

    pub fn fromInfo(info: protocol.NodeInfo) Node {
        return .{
            .name = info.name,
            .kind = NodeKind.fromStr(info.kind),
            .size = info.size,
            .deleted = info.deleted,
            .link_target = info.link_target,
            .timestamps = info.timestamps,
        };
    }

    pub fn isFile(self: Node) bool {
        return self.kind == .file;
    }

    pub fn isDir(self: Node) bool {
        return self.kind == .dir;
    }
};

/// A view issued for one run.
pub const View = struct {
    ctx: host.Context,
    info: protocol.ViewInfo,

    /// Wraps the `ViewInfo` of a `run.start` target.
    pub fn init(ctx: host.Context, info: protocol.ViewInfo) View {
        return .{ .ctx = ctx, .info = info };
    }

    pub fn id(self: View) []const u8 {
        return self.info.view_id;
    }

    pub fn label(self: View) []const u8 {
        return self.info.label;
    }

    /// The operating system of a system view.
    pub fn system(self: View) ?protocol.SystemInfo {
        return self.info.system;
    }

    pub fn mounts(self: View) []const protocol.MountInfo {
        return self.info.mounts;
    }

    pub fn context(self: View) host.Context {
        return self.ctx;
    }

    /// The evidence address of a view path: the volume its longest mount
    /// prefix shows and the path inside that volume.
    ///
    /// Use it as a record source when the record names a file the analyzer
    /// did not open. A path outside every mount is reported with the path
    /// alone, exactly as the host would.
    pub fn source(self: View, path: []const u8) record.SourceRef {
        var parts = std.ArrayList([]const u8).empty;
        defer parts.deinit(self.ctx.arena);
        appendParts(self.ctx.arena, &parts, path) catch return .{ .path = path };

        var best_depth: usize = 0;
        var best: ?protocol.MountInfo = null;
        for (self.info.mounts) |mount| {
            var prefix = std.ArrayList([]const u8).empty;
            defer prefix.deinit(self.ctx.arena);
            appendParts(self.ctx.arena, &prefix, mount.path) catch continue;
            if (prefix.items.len > parts.items.len) continue;
            var matches = true;
            for (prefix.items, parts.items[0..prefix.items.len]) |left, right| {
                if (!std.ascii.eqlIgnoreCase(left, right)) {
                    matches = false;
                    break;
                }
            }
            if (matches and prefix.items.len >= best_depth) {
                best_depth = prefix.items.len;
                best = mount;
            }
        }

        if (best) |mount| {
            return .{
                .root = mount.root,
                .path = joinParts(self.ctx.arena, parts.items[best_depth..]) catch path,
            };
        }
        return .{ .path = joinParts(self.ctx.arena, parts.items) catch path };
    }

    /// The node at `path`, or `null` when it does not exist.
    pub fn stat(self: View, path: []const u8) sdk.Error!?Node {
        const reply = try self.ctx.callHost(protocol.method.view_stat, try value.map(
            self.ctx.arena,
            &.{
                value.entry("view_id", value.str(self.info.view_id)),
                value.entry("path", value.str(path)),
            },
        ));
        return switch (reply) {
            .nil => null,
            .map => Node.fromInfo(try protocol.NodeInfo.fromValueWith(self.ctx.arena, reply)),
            else => sdk.failf(
                self.ctx.arena,
                "PROTOCOL_ERROR",
                "view.stat must reply with a node map or nil",
                .{},
            ),
        };
    }

    pub fn exists(self: View, path: []const u8) sdk.Error!bool {
        return (try self.stat(path)) != null;
    }

    pub fn isFile(self: View, path: []const u8) sdk.Error!bool {
        const node = try self.stat(path) orelse return false;
        return node.isFile();
    }

    pub fn isDir(self: View, path: []const u8) sdk.Error!bool {
        const node = try self.stat(path) orelse return false;
        return node.isDir();
    }

    /// Entries of the directory at `path` (empty for the view root).
    ///
    /// Pages `view.list` by `skip`/`limit` until the reported total is
    /// reached, and fails with `PROTOCOL_ERROR` if the host sends an
    /// inconsistent page or a total that changes between pages. A missing
    /// directory surfaces the host's `VIEW_PATH_NOT_FOUND`.
    pub fn list(self: View, path: []const u8) sdk.Error![]Node {
        const alloc = self.ctx.arena;
        var nodes: std.ArrayList(Node) = .empty;
        errdefer nodes.deinit(alloc);

        var expected_total: ?u64 = null;
        while (true) {
            try self.ctx.checkCancelled();
            const reply = try self.ctx.callHost(protocol.method.view_list, try value.map(alloc, &.{
                value.entry("view_id", value.str(self.info.view_id)),
                value.entry("path", value.str(path)),
                value.entry("skip", value.uint(nodes.items.len)),
                value.entry("limit", value.uint(protocol.MAX_LIST_PAGE)),
            }));
            const page = try protocol.NodePage.fromValueWith(alloc, reply);

            const consistent = (expected_total == null or expected_total.? == page.total) and
                page.nodes.len <= protocol.MAX_LIST_PAGE and
                nodes.items.len + page.nodes.len <= page.total and
                (page.nodes.len > 0 or nodes.items.len == page.total);
            if (!consistent) {
                return sdk.fail(
                    "PROTOCOL_ERROR",
                    "view.list returned an inconsistent page or a changing total",
                );
            }
            expected_total = page.total;

            try nodes.ensureUnusedCapacity(alloc, page.nodes.len);
            for (page.nodes) |info| nodes.appendAssumeCapacity(Node.fromInfo(info));
            if (nodes.items.len == page.total) return nodes.toOwnedSlice(alloc);
        }
    }

    /// [`View.list`], with a missing directory listing as empty.
    pub fn listOrEmpty(self: View, path: []const u8) sdk.Error![]Node {
        return self.list(path) catch |err| {
            if (err == error.PathNotFound or sdk.hasCode(err, "VIEW_PATH_NOT_FOUND")) {
                return &.{};
            }
            return err;
        };
    }

    /// A handle to the file at `path`, or `null` when it does not exist.
    ///
    /// Fails with the host's `VIEW_NOT_A_FILE` for a directory.
    pub fn open(self: View, path: []const u8) sdk.Error!?file.FileRef {
        const reply = try self.ctx.callHost(protocol.method.view_open, try value.map(
            self.ctx.arena,
            &.{
                value.entry("view_id", value.str(self.info.view_id)),
                value.entry("path", value.str(path)),
            },
        ));
        return switch (reply) {
            .nil => null,
            .map => file.FileRef.init(
                self.ctx,
                try protocol.FileInfo.fromValueWith(self.ctx.arena, reply),
            ),
            else => sdk.failf(
                self.ctx.arena,
                "PROTOCOL_ERROR",
                "view.open must reply with a file map or nil",
                .{},
            ),
        };
    }

    /// The whole file at `path` (see [`file.FileRef.readAll`]), or `null`.
    pub fn read(self: View, path: []const u8, cap: u64) sdk.Error!?[]u8 {
        const opened = try self.open(path) orelse return null;
        return try opened.readAll(cap);
    }

    /// The first `cap` bytes of `path` as text, or `null`.
    pub fn readText(self: View, path: []const u8, cap: u64) sdk.Error!?[]const u8 {
        const opened = try self.open(path) orelse return null;
        return try opened.readText(cap);
    }

    /// [`View.readText`] split into lines.
    pub fn readLines(self: View, path: []const u8, cap: u64) sdk.Error!?[]const []const u8 {
        const opened = try self.open(path) orelse return null;
        return try opened.readLines(cap);
    }

    /// Every file path matching one of `patterns` (see `glob`), sorted and
    /// de-duplicated.
    ///
    /// The host walks the view in bounded batches; deleted entries and links
    /// are skipped, and more than [`protocol.MAX_FIND_RESULTS`] matches fail
    /// with `RESOURCE_LIMIT` rather than returning a partial list.
    pub fn find(self: View, patterns: []const []const u8) sdk.Error![]const []const u8 {
        const alloc = self.ctx.arena;
        for (patterns) |pattern| {
            if (glob.validate(pattern)) |message| {
                return sdk.failf(
                    alloc,
                    "INVALID_PARAMS",
                    "invalid pattern {s}: {s}",
                    .{ pattern, message },
                );
            }
        }

        const pattern_values = try alloc.alloc(wire.Value, patterns.len);
        for (patterns, pattern_values) |pattern, *slot| slot.* = wire.str(pattern);

        var paths: std.ArrayList([]const u8) = .empty;
        errdefer paths.deinit(alloc);
        var cursor: ?[]const u8 = null;
        var visited: u64 = 0;
        while (true) {
            try self.ctx.checkCancelled();
            const params = try value.map(alloc, &.{
                value.entry("view_id", value.str(self.info.view_id)),
                value.entry("patterns", .{ .array = pattern_values }),
                value.entry("cursor", value.optionalString(cursor)),
            });
            const page = try protocol.FindPage.fromValueWith(
                alloc,
                try self.ctx.callHost(protocol.method.view_find, params),
            );
            if (page.visited < visited) {
                return sdk.fail("PROTOCOL_ERROR", "view.find went backwards");
            }
            visited = page.visited;
            try paths.appendSlice(alloc, page.paths);
            if (paths.items.len > protocol.MAX_FIND_RESULTS) {
                return sdk.failf(
                    alloc,
                    "RESOURCE_LIMIT",
                    "more than {d} paths match",
                    .{protocol.MAX_FIND_RESULTS},
                );
            }
            if (page.cursor) |next| {
                cursor = next;
            } else {
                std.mem.sort([]const u8, paths.items, {}, lessThan);
                return dedupe(alloc, paths.items);
            }
        }
    }
};

fn lessThan(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn dedupe(alloc: std.mem.Allocator, paths: [][]const u8) sdk.Error![]const []const u8 {
    if (paths.len == 0) return paths;
    var unique: usize = 1;
    for (paths[1..]) |path| {
        if (!std.mem.eql(u8, path, paths[unique - 1])) {
            paths[unique] = path;
            unique += 1;
        }
    }
    return alloc.realloc(paths, unique);
}

/// Splits `path` at `/`, dropping empty segments.
fn appendParts(
    alloc: std.mem.Allocator,
    parts: *std.ArrayList([]const u8),
    path: []const u8,
) sdk.Error!void {
    var index: usize = 0;
    while (index < path.len) {
        while (index < path.len and path[index] == '/') index += 1;
        const start = index;
        while (index < path.len and path[index] != '/') index += 1;
        if (index > start) try parts.append(alloc, path[start..index]);
    }
}

/// Joins `parts` with `/`.
fn joinParts(alloc: std.mem.Allocator, parts: []const []const u8) sdk.Error![]const u8 {
    if (parts.len == 0) return "";
    var length: usize = parts.len - 1;
    for (parts) |part| length += part.len;
    const joined = try alloc.alloc(u8, length);
    var position: usize = 0;
    for (parts, 0..) |part, index| {
        if (index > 0) {
            joined[position] = '/';
            position += 1;
        }
        @memcpy(joined[position..][0..part.len], part);
        position += part.len;
    }
    return joined;
}

const testing = std.testing;

const TestHost = struct {
    alloc: std.mem.Allocator,
    calls: std.ArrayList([]const u8) = .empty,
    params: std.ArrayList(wire.Value) = .empty,
    replies: []const wire.Value,

    fn call(
        context: ?*anyopaque,
        method: abi.Bytes,
        params: abi.Bytes,
        out: *abi.Buffer,
    ) callconv(.c) i32 {
        const self: *TestHost = @ptrCast(@alignCast(context.?));
        const name = self.alloc.dupe(u8, method.slice()) catch return abi.STATUS_ERROR;
        self.calls.append(self.alloc, name) catch return abi.STATUS_ERROR;
        const decoded = wire.decode(std.heap.c_allocator, params.slice()) catch
            return abi.STATUS_ERROR;
        self.params.append(self.alloc, decoded) catch return abi.STATUS_ERROR;

        // The last scripted reply repeats, so a test can call a method twice
        // without scripting the same answer again.
        const index = @min(self.calls.items.len - 1, self.replies.len -| 1);
        if (self.replies.len == 0) return abi.STATUS_ERROR;
        const encoded = wire.encode(std.heap.c_allocator, self.replies[index]) catch
            return abi.STATUS_ERROR;
        out.* = abi.Buffer.fromOwned(encoded);
        return abi.STATUS_OK;
    }

    fn freeBuffer(_: ?*anyopaque, buffer: *abi.Buffer) callconv(.c) void {
        buffer.freeOwned(std.heap.c_allocator);
    }

    fn log(_: ?*anyopaque, _: u32, _: abi.Bytes) callconv(.c) void {}
};

var test_cancelled = std.atomic.Value(bool).init(false);

fn testContext(alloc: std.mem.Allocator, stub: *TestHost) host.Context {
    return .{
        .host = host.HostConnection.init(.{
            .abi_version = abi.ABI_VERSION,
            .struct_size = abi.HOST_API_SIZE,
            .context = stub,
            .call = TestHost.call,
            .free_buffer = TestHost.freeBuffer,
            .log = TestHost.log,
        }),
        .cancelled = &test_cancelled,
        .arena = alloc,
        .alloc = alloc,
    };
}

fn fixtureView() protocol.ViewInfo {
    return .{
        .view_id = "view-1",
        .label = "Kali",
        .system = .{
            .id = "linux@part:0",
            .family = "linux",
            .product = "Kali GNU/Linux",
            .root = "part:0",
        },
        .mounts = &.{
            .{ .path = "", .root = "part:0", .source = "root" },
            .{ .path = "home", .root = "part:1", .source = "fstab" },
        },
    };
}

test "a view exposes its info and the system" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const view = View.init(testContext(alloc, undefined), fixtureView());
    try testing.expectEqualStrings("view-1", view.id());
    try testing.expectEqualStrings("Kali", view.label());
    try testing.expectEqualStrings("linux", view.system().?.family);
    try testing.expectEqual(@as(usize, 2), view.mounts().len);
}

test "a source maps the longest mount prefix to a volume" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const view = View.init(testContext(alloc, undefined), fixtureView());

    const passwd = view.source("etc/passwd");
    try testing.expectEqualStrings("part:0", passwd.root.?);
    try testing.expectEqualStrings("etc/passwd", passwd.path.?);
    try testing.expectEqual(null, passwd.offset);

    const history = view.source("/home/kali/.bash_history");
    try testing.expectEqualStrings("part:1", history.root.?);
    try testing.expectEqualStrings("kali/.bash_history", history.path.?);

    // Mount prefixes compare ASCII case-insensitively, like the host's views.
    const upper = view.source("HOME/kali/.bash_history");
    try testing.expectEqualStrings("part:1", upper.root.?);

    // The view root itself.
    const root = view.source("");
    try testing.expectEqualStrings("part:0", root.root.?);
    try testing.expectEqualStrings("", root.path.?);
}

test "stat decodes a node or reports a missing path" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    const node = try wire.mapOf(alloc, &.{
        wire.entry("name", wire.str("passwd")),
        wire.entry("kind", wire.str("file")),
        wire.entry("size", wire.uint(1024)),
        wire.entry("timestamps", try wire.mapOf(alloc, &.{
            wire.entry("modified", wire.str("2024-01-02T03:04:05Z")),
        })),
    });
    var stub = TestHost{ .alloc = alloc, .replies = &.{ node, wire.Value.nil } };
    const view = View.init(testContext(alloc, &stub), fixtureView());

    const found = (try view.stat("etc/passwd")).?;
    try testing.expectEqualStrings("passwd", found.name);
    try testing.expect(found.isFile());
    try testing.expectEqual(@as(u64, 1024), found.size);
    try testing.expectEqualStrings("2024-01-02T03:04:05Z", found.timestamps.modified.?);
    try testing.expectEqualStrings(protocol.method.view_stat, stub.calls.items[0]);
    try testing.expectEqualStrings("view-1", stub.params.items[0].getString("view_id").?);
    try testing.expectEqualStrings("etc/passwd", stub.params.items[0].getString("path").?);

    try testing.expectEqual(null, try view.stat("etc/missing"));
    try testing.expect(!try view.exists("etc/missing"));
    try testing.expect(!try view.isFile("etc/missing"));
}

test "list pages until the reported total and rejects an inconsistent page" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    const page = try wire.mapOf(alloc, &.{
        wire.entry("nodes", try wire.arrayOf(alloc, &.{
            try wire.mapOf(alloc, &.{
                wire.entry("name", wire.str("passwd")),
                wire.entry("kind", wire.str("file")),
            }),
            try wire.mapOf(alloc, &.{
                wire.entry("name", wire.str("shadow")),
                wire.entry("kind", wire.str("file")),
            }),
        })),
        wire.entry("total", wire.uint(3)),
    });
    const rest = try wire.mapOf(alloc, &.{
        wire.entry("nodes", try wire.arrayOf(alloc, &.{
            try wire.mapOf(alloc, &.{
                wire.entry("name", wire.str("hostname")),
                wire.entry("kind", wire.str("file")),
            }),
        })),
        wire.entry("total", wire.uint(3)),
    });
    var stub = TestHost{ .alloc = alloc, .replies = &.{ page, rest } };
    const view = View.init(testContext(alloc, &stub), fixtureView());

    const nodes = try view.list("etc");
    try testing.expectEqual(@as(usize, 3), nodes.len);
    try testing.expectEqualStrings("hostname", nodes[2].name);
    try testing.expectEqual(@as(usize, 2), stub.calls.items.len);
    try testing.expectEqual(@as(u64, 0), stub.params.items[0].getUint("skip").?);
    try testing.expectEqual(@as(u64, 2), stub.params.items[1].getUint("skip").?);
    try testing.expectEqual(@as(u64, protocol.MAX_LIST_PAGE), stub.params.items[1].getUint("limit").?);

    // A page that does not add up is a protocol error.
    var bad = TestHost{ .alloc = alloc, .replies = &.{
        try wire.mapOf(alloc, &.{
            wire.entry("nodes", try wire.arrayOf(alloc, &.{})),
            wire.entry("total", wire.uint(2)),
        }),
    } };
    const broken = View.init(testContext(alloc, &bad), fixtureView());
    try testing.expectError(error.Fault, broken.list("etc"));
    try testing.expectEqualStrings("PROTOCOL_ERROR", sdk.codeOf(error.Fault));
}

test "listOrEmpty turns a missing directory into an empty list" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    const FaultHost = struct {
        fn call(
            _: ?*anyopaque,
            _: abi.Bytes,
            _: abi.Bytes,
            out: *abi.Buffer,
        ) callconv(.c) i32 {
            const fault = wire.mapOf(std.heap.c_allocator, &.{
                wire.entry("code", wire.str("VIEW_PATH_NOT_FOUND")),
                wire.entry("message", wire.str("etc/nope does not exist")),
            }) catch return abi.STATUS_ERROR;
            const encoded = wire.encode(std.heap.c_allocator, fault) catch return abi.STATUS_ERROR;
            out.* = abi.Buffer.fromOwned(encoded);
            return abi.STATUS_ERROR;
        }
    };
    const ctx = host.Context{
        .host = host.HostConnection.init(.{
            .abi_version = abi.ABI_VERSION,
            .struct_size = abi.HOST_API_SIZE,
            .context = null,
            .call = FaultHost.call,
            .free_buffer = TestHost.freeBuffer,
            .log = TestHost.log,
        }),
        .cancelled = &test_cancelled,
        .arena = alloc,
        .alloc = alloc,
    };
    const view = View.init(ctx, fixtureView());
    try testing.expectError(error.Fault, view.list("etc/nope"));
    try testing.expectEqualStrings("VIEW_PATH_NOT_FOUND", sdk.codeOf(error.Fault));
    sdk.clear();
    try testing.expectEqual(@as(usize, 0), (try view.listOrEmpty("etc/nope")).len);
}

test "open returns a file handle or nil" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    const info = try wire.mapOf(alloc, &.{
        wire.entry("file_id", wire.str("file-1")),
        wire.entry("name", wire.str("passwd")),
        wire.entry("size", wire.uint(8)),
        wire.entry("view_path", wire.str("etc/passwd")),
        wire.entry("root", wire.str("part:0")),
        wire.entry("root_path", wire.str("etc/passwd")),
    });
    var stub = TestHost{
        .alloc = alloc,
        .replies = &.{ info, wire.Value.nil, info, value.bytes("root:x:0"), wire.Value.nil },
    };
    const view = View.init(testContext(alloc, &stub), fixtureView());

    const opened = (try view.open("etc/passwd")).?;
    try testing.expectEqualStrings("file-1", opened.id());
    try testing.expectEqualStrings("part:0", opened.source().root.?);

    try testing.expectEqual(null, try view.open("etc/missing"));
    try testing.expectEqualStrings("root:x:0", (try view.readText("etc/passwd", 64)).?);
    try testing.expectEqual(null, try view.readText("etc/missing", 64));
}

test "find validates patterns, pages cursors and caps results" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    const first = try wire.mapOf(alloc, &.{
        wire.entry("paths", try wire.arrayOf(alloc, &.{
            wire.str("etc/passwd"),
            wire.str("etc/hostname"),
        })),
        wire.entry("visited", wire.uint(4)),
        wire.entry("cursor", wire.str("next")),
    });
    const second = try wire.mapOf(alloc, &.{
        wire.entry("paths", try wire.arrayOf(alloc, &.{
            wire.str("etc/passwd"),
            wire.str("home/kali/.bash_history"),
        })),
        wire.entry("visited", wire.uint(9)),
    });
    var stub = TestHost{ .alloc = alloc, .replies = &.{ first, second } };
    const view = View.init(testContext(alloc, &stub), fixtureView());

    const paths = try view.find(&.{"etc/*"});
    try testing.expectEqual(@as(usize, 3), paths.len);
    try testing.expectEqualStrings("etc/hostname", paths[0]);
    try testing.expectEqualStrings("etc/passwd", paths[1]);
    try testing.expectEqualStrings("home/kali/.bash_history", paths[2]);
    try testing.expectEqualStrings(protocol.method.view_find, stub.calls.items[0]);
    try testing.expectEqual(wire.Value.nil, stub.params.items[0].get("cursor").?);
    try testing.expectEqualStrings("next", stub.params.items[1].getString("cursor").?);

    // An invalid pattern never reaches the host.
    const before = stub.calls.items.len;
    try testing.expectError(error.Fault, view.find(&.{""}));
    try testing.expectEqualStrings("INVALID_PARAMS", sdk.codeOf(error.Fault));
    try testing.expectEqual(before, stub.calls.items.len);
    sdk.clear();

    // A total that goes backwards is a protocol error.
    var backwards = TestHost{ .alloc = alloc, .replies = &.{
        try wire.mapOf(alloc, &.{
            wire.entry("paths", try wire.arrayOf(alloc, &.{})),
            wire.entry("visited", wire.uint(5)),
            wire.entry("cursor", wire.str("next")),
        }),
        try wire.mapOf(alloc, &.{
            wire.entry("paths", try wire.arrayOf(alloc, &.{})),
            wire.entry("visited", wire.uint(2)),
        }),
    } };
    const broken = View.init(testContext(alloc, &backwards), fixtureView());
    try testing.expectError(error.Fault, broken.find(&.{"etc/*"}));
    try testing.expectEqualStrings("PROTOCOL_ERROR", sdk.codeOf(error.Fault));
}

const abi = @import("abi.zig");
