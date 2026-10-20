//! Read-only file handles issued by the host for one run.
//!
//! A [`FileRef`] is an opaque logical file: an input of the run, or a file
//! opened through the run's view. It never exposes the evidence path; every
//! read is clamped at the end of the file, and the bytes, strings and lists it
//! returns come from the per-call arena of the [`host.Context`], so the caller
//! never frees them.
//!
//! Host calls used here: `file.read`, `file.readv`, `file.materialize` and
//! `file.release` (see `protocol.method`).

const std = @import("std");

const host = @import("host.zig");
const protocol = @import("protocol.zig");
const record = @import("record.zig");
const sdk = @import("error.zig");
const text = @import("text.zig");
const value = @import("value.zig");
const wire = @import("wire.zig");

/// An opaque, read-only logical file: an input of the run or a file opened
/// through its view.
///
/// The public fields mirror `protocol.FileInfo`; the accessor methods only
/// add defaults, so either form works. (`info` is a field, not a method: Zig
/// cannot declare both with the same name.)
pub const FileRef = struct {
    ctx: host.Context,
    info: protocol.FileInfo,

    /// Wraps the `FileInfo` of a `view.open` reply or of a run input.
    pub fn init(ctx: host.Context, info: protocol.FileInfo) FileRef {
        return .{ .ctx = ctx, .info = info };
    }

    pub fn id(self: FileRef) []const u8 {
        return self.info.file_id;
    }

    /// Display name; not a host path.
    pub fn name(self: FileRef) []const u8 {
        return self.info.name;
    }

    pub fn size(self: FileRef) u64 {
        return self.info.size;
    }

    pub fn mime(self: FileRef) ?[]const u8 {
        return self.info.mime;
    }

    /// Path inside the run's view, when the file was opened through one.
    pub fn viewPath(self: FileRef) ?[]const u8 {
        return self.info.view_path;
    }

    /// Volume key the file lives on (`part:1`).
    pub fn root(self: FileRef) ?[]const u8 {
        return self.info.root;
    }

    /// Path inside that volume.
    pub fn rootPath(self: FileRef) ?[]const u8 {
        return self.info.root_path;
    }

    pub fn deleted(self: FileRef) bool {
        return self.info.deleted;
    }

    pub fn timestamps(self: FileRef) protocol.Timestamps {
        return self.info.timestamps;
    }

    pub fn context(self: FileRef) host.Context {
        return self.ctx;
    }

    /// Provenance of the whole file: the volume key, the path inside the
    /// volume (or the view path when the host sent no volume path) and the
    /// node id, when the host reported one.
    pub fn source(self: FileRef) record.SourceRef {
        return .{
            .root = self.info.root,
            .path = self.info.root_path orelse self.info.view_path,
            .node_id = self.info.node_id,
        };
    }

    /// Provenance of `length` bytes at `offset`.
    pub fn sourceAt(self: FileRef, offset: u64, length: u64) record.SourceRef {
        return self.source().at(offset, length);
    }

    /// Reads up to `length` bytes at `offset`, clamped at the end of the file
    /// and paged through `file.read` in [`protocol.MAX_READ`] chunks.
    pub fn readAt(self: FileRef, offset: u64, length: usize) sdk.Error![]u8 {
        const alloc = self.ctx.arena;
        if (length == 0 or offset >= self.info.size) return alloc.alloc(u8, 0);
        const end: u64 = @min(offset +| @as(u64, length), self.info.size);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(alloc);
        try out.ensureTotalCapacity(alloc, @intCast(end - offset));

        var position = offset;
        while (position < end) {
            const want: u64 = @min(end - position, protocol.MAX_READ);
            const chunk = try self.readHost(position, want);
            if (chunk.len == 0) break;
            if (chunk.len > want) {
                return sdk.fail("PROTOCOL_ERROR", "file.read returned more bytes than requested");
            }
            try out.appendSlice(alloc, chunk);
            position += chunk.len;
        }
        return out.toOwnedSlice(alloc);
    }

    /// The whole file.
    ///
    /// Fails with `RESOURCE_LIMIT` when the file is larger than `cap`, and
    /// with `SHORT_READ` when the host returns fewer bytes than the file's
    /// size: a truncated read is never treated as complete.
    pub fn readAll(self: FileRef, cap: u64) sdk.Error![]u8 {
        if (self.info.size > cap) {
            return sdk.failf(
                self.ctx.arena,
                "RESOURCE_LIMIT",
                "{s} is {d} bytes; the limit is {d}",
                .{ self.info.name, self.info.size, cap },
            );
        }
        const length = std.math.cast(usize, self.info.size) orelse std.math.maxInt(usize);
        const bytes = try self.readAt(0, length);
        if (bytes.len != self.info.size) {
            return sdk.failf(
                self.ctx.arena,
                "SHORT_READ",
                "{s}: read {d} of {d} bytes",
                .{ self.info.name, bytes.len, self.info.size },
            );
        }
        return bytes;
    }

    /// The first `cap` bytes as text (UTF-8, invalid bytes replaced).
    pub fn readText(self: FileRef, cap: u64) sdk.Error![]const u8 {
        const length = @min(self.info.size, cap);
        const bytes = try self.readAt(0, std.math.cast(usize, length) orelse std.math.maxInt(usize));
        return text.decodeLossy(self.ctx.arena, bytes);
    }

    /// [`FileRef.readText`] split into lines (Python `splitlines` semantics).
    pub fn readLines(self: FileRef, cap: u64) sdk.Error![]const []const u8 {
        const body = try self.readText(cap);
        return text.splitLines(self.ctx.arena, body);
    }

    /// Several ranges in one host call. The host accepts at most
    /// [`protocol.MAX_READV_RANGES`] ranges totalling at most
    /// [`protocol.MAX_READV_BYTES`] bytes, and replies with one byte slice per
    /// range, in order.
    pub fn readv(self: FileRef, ranges: []const value.Range) sdk.Error![]const []const u8 {
        if (ranges.len > protocol.MAX_READV_RANGES) {
            return sdk.failf(
                self.ctx.arena,
                "RESOURCE_LIMIT",
                "file.readv accepts at most {d} ranges",
                .{protocol.MAX_READV_RANGES},
            );
        }
        var total: u64 = 0;
        for (ranges) |range| total += range.length;
        if (total > protocol.MAX_READV_BYTES) {
            return sdk.failf(
                self.ctx.arena,
                "RESOURCE_LIMIT",
                "file.readv accepts at most {d} bytes",
                .{protocol.MAX_READV_BYTES},
            );
        }

        const alloc = self.ctx.arena;
        const reply = try self.ctx.callHost(protocol.method.file_readv, try value.map(alloc, &.{
            value.entry("file_id", value.str(self.info.file_id)),
            value.entry("ranges", try value.ranges(alloc, ranges)),
        }));
        return value.intoByteList(alloc, reply, protocol.method.file_readv);
    }

    /// Asks the host for a stable copy of the file on disk and returns the
    /// lease that keeps it alive; release it with
    /// [`MaterializedFile.release`].
    ///
    /// Requires the `file_materialize` permission in `plugin.toml`.
    pub fn materialize(self: FileRef) sdk.Error!MaterializedFile {
        const reply = try self.ctx.callHost(protocol.method.file_materialize, try value.map(
            self.ctx.arena,
            &.{value.entry("file_id", value.str(self.info.file_id))},
        ));
        const lease = try protocol.Lease.fromValueWith(self.ctx.arena, reply);
        return .{
            .ctx = self.ctx,
            .path = lease.path,
            .size = lease.size,
            .lease_id = lease.lease_id,
        };
    }

    /// One `file.read` call; the bytes belong to the arena the reply was
    /// decoded into.
    fn readHost(self: FileRef, offset: u64, length: u64) sdk.Error![]const u8 {
        const reply = try self.ctx.callHost(protocol.method.file_read, try value.map(
            self.ctx.arena,
            &.{
                value.entry("file_id", value.str(self.info.file_id)),
                value.entry("offset", value.uint(offset)),
                value.entry("length", value.uint(length)),
            },
        ));
        return value.intoBytes(reply, protocol.method.file_read);
    }
};

/// A file the host copied to a path the plugin can open itself, plus the lease
/// that keeps that copy alive.
///
/// There is no automatic release: the host also drops every lease when the run
/// ends, but a long run that materializes many files should call [`release`]
/// as soon as the copy is no longer needed.
pub const MaterializedFile = struct {
    ctx: host.Context,
    /// Path of the host's copy.
    path: []const u8,
    /// Size of the materialized copy, as reported by the host.
    size: u64 = 0,
    /// Host lease id; `null` once released (or when the host sent none).
    lease_id: ?[]const u8 = null,

    /// Releases the lease (`file.release`). Calling it twice is a no-op.
    ///
    /// Errors are reported to the caller because only it knows whether the
    /// copy is still needed; the run end releases whatever is left anyway.
    pub fn release(self: *MaterializedFile) sdk.Error!void {
        const lease_id = self.lease_id orelse return;
        self.lease_id = null;
        _ = try self.ctx.callHost(protocol.method.file_release, try value.map(
            self.ctx.arena,
            &.{value.entry("lease_id", value.str(lease_id))},
        ));
    }
};

const testing = std.testing;

const TestHost = struct {
    calls: std.ArrayList([]const u8) = .empty,
    params: std.ArrayList(wire.Value) = .empty,
    replies: []const wire.Value,
    statuses: []const i32 = &.{},
    alloc: std.mem.Allocator,

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
        if (self.replies.len == 0) return abi.STATUS_ERROR;
        const index = @min(self.calls.items.len - 1, self.replies.len -| 1);
        const status = if (index < self.statuses.len) self.statuses[index] else abi.STATUS_OK;
        const encoded = wire.encode(std.heap.c_allocator, self.replies[index]) catch
            return abi.STATUS_ERROR;
        out.* = abi.Buffer.fromOwned(encoded);
        return status;
    }

    fn freeBuffer(_: ?*anyopaque, buffer: *abi.Buffer) callconv(.c) void {
        buffer.freeOwned(std.heap.c_allocator);
    }

    fn log(_: ?*anyopaque, _: u32, _: abi.Bytes) callconv(.c) void {}
};

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

var test_cancelled = std.atomic.Value(bool).init(false);

fn fileInfo(size: u64) protocol.FileInfo {
    return .{
        .file_id = "file-7",
        .name = "notes.txt",
        .size = size,
        .view_path = "home/kali/notes.txt",
        .root = "part:1",
        .root_path = "kali/notes.txt",
        .node_id = "node-9",
    };
}

test "a file read is paged, clamped at the end and stops on an empty chunk" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    var stub = TestHost{
        .alloc = alloc,
        .replies = &.{ value.bytes("ab"), value.bytes("cd") },
    };
    const ctx = testContext(alloc, &stub);
    const file = FileRef.init(ctx, fileInfo(4));

    try testing.expectEqualStrings("abcd", try file.readAt(0, 1024));
    try testing.expectEqual(@as(usize, 2), stub.calls.items.len);
    try testing.expectEqualStrings(protocol.method.file_read, stub.calls.items[0]);
    try testing.expectEqualStrings("file-7", stub.params.items[0].getString("file_id").?);
    try testing.expectEqual(@as(u64, 0), stub.params.items[0].getUint("offset").?);
    try testing.expectEqual(@as(u64, 4), stub.params.items[0].getUint("length").?);
    try testing.expectEqual(@as(u64, 2), stub.params.items[1].getUint("offset").?);

    // Nothing to read: no host call at all.
    try testing.expectEqualStrings("", try file.readAt(4, 16));
    try testing.expectEqualStrings("", try file.readAt(0, 0));
    try testing.expectEqual(@as(usize, 2), stub.calls.items.len);
}

test "a file read stops when the host answers with an empty chunk" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    var stub = TestHost{ .alloc = alloc, .replies = &.{value.bytes("")} };
    const ctx = testContext(alloc, &stub);
    const file = FileRef.init(ctx, fileInfo(64));

    try testing.expectEqualStrings("", try file.readAt(0, 64));
    try testing.expectEqual(@as(usize, 1), stub.calls.items.len);
}

test "a file read rejects a non-binary reply" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    var stub = TestHost{ .alloc = alloc, .replies = &.{wire.str("not bytes")} };
    const ctx = testContext(alloc, &stub);
    const file = FileRef.init(ctx, fileInfo(4));

    try testing.expectError(error.Fault, file.readAt(0, 4));
    try testing.expectEqualStrings("PROTOCOL_ERROR", sdk.codeOf(error.Fault));
}

test "readAll enforces the cap and reports a short read" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    var capped = TestHost{ .alloc = alloc, .replies = &.{value.bytes("ab")} };
    const capped_file = FileRef.init(testContext(alloc, &capped), fileInfo(8));
    try testing.expectError(error.Fault, capped_file.readAll(4));
    try testing.expectEqualStrings("RESOURCE_LIMIT", sdk.codeOf(error.Fault));
    // The cap is checked before any host call.
    try testing.expectEqual(@as(usize, 0), capped.calls.items.len);
    sdk.clear();

    // The host returned fewer bytes than the file's size.
    var short_stub = TestHost{
        .alloc = alloc,
        .replies = &.{ value.bytes("ab"), value.bytes("") },
    };
    const short = FileRef.init(testContext(alloc, &short_stub), fileInfo(4));
    try testing.expectError(error.Fault, short.readAll(1024));
    try testing.expectEqualStrings("SHORT_READ", sdk.codeOf(error.Fault));
}

test "a file reads as lossy text and as lines" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    var stub = TestHost{ .alloc = alloc, .replies = &.{value.bytes("a\nb\n")} };
    const ctx = testContext(alloc, &stub);
    const file = FileRef.init(ctx, fileInfo(4));

    const lines = try file.readLines(64);
    try testing.expectEqual(@as(usize, 2), lines.len);
    try testing.expectEqualStrings("a", lines[0]);
    try testing.expectEqualStrings("b", lines[1]);
    // `cap` limits the read, not the line count.
    try testing.expectEqual(@as(u64, 4), stub.params.items[0].getUint("length").?);

    var invalid = TestHost{ .alloc = alloc, .replies = &.{value.bytes("h\xff")} };
    const lossy = FileRef.init(testContext(alloc, &invalid), fileInfo(2));
    try testing.expectEqualStrings("h\xef\xbf\xbd", try lossy.readText(16));
}

test "a file readv returns one byte slice per range" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    const list = [_]wire.Value{ value.bytes("ab"), value.bytes("cde") };
    var stub = TestHost{
        .alloc = alloc,
        .replies = &.{try wire.arrayOf(alloc, &list)},
    };
    const ctx = testContext(alloc, &stub);
    const file = FileRef.init(ctx, fileInfo(16));

    const ranges = [_]value.Range{
        .{ .offset = 0, .length = 2 },
        .{ .offset = 8, .length = 3 },
    };
    const slices = try file.readv(&ranges);
    try testing.expectEqual(@as(usize, 2), slices.len);
    try testing.expectEqualStrings("ab", slices[0]);
    try testing.expectEqualStrings("cde", slices[1]);

    const sent = stub.params.items[0].get("ranges").?;
    try testing.expectEqual(@as(usize, 2), sent.array.len);
    try testing.expectEqual(@as(u64, 8), sent.array[1].array[0].uint);
    try testing.expectEqual(@as(u64, 3), sent.array[1].array[1].uint);
}

test "readv rejects more ranges than the host accepts" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    var stub = TestHost{ .alloc = alloc, .replies = &.{} };
    const ctx = testContext(alloc, &stub);
    const file = FileRef.init(ctx, fileInfo(16));

    const ranges = try alloc.alloc(value.Range, protocol.MAX_READV_RANGES + 1);
    for (ranges) |*range| range.* = .{ .offset = 0, .length = 1 };
    try testing.expectError(error.Fault, file.readv(ranges));
    try testing.expectEqualStrings("RESOURCE_LIMIT", sdk.codeOf(error.Fault));
    try testing.expectEqual(@as(usize, 0), stub.calls.items.len);
}

test "materializing a file yields a lease that can be released once" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    defer sdk.clear();

    const lease = try wire.mapOf(alloc, &.{
        wire.entry("lease_id", wire.str("lease-1")),
        wire.entry("path", wire.str("/tmp/lc/file-7")),
        wire.entry("size", wire.uint(4096)),
    });
    var stub = TestHost{
        .alloc = alloc,
        .replies = &.{ lease, wire.Value.nil },
    };
    const ctx = testContext(alloc, &stub);
    const file = FileRef.init(ctx, fileInfo(4096));

    var materialized = try file.materialize();
    try testing.expectEqualStrings("/tmp/lc/file-7", materialized.path);
    try testing.expectEqual(@as(u64, 4096), materialized.size);
    try testing.expectEqualStrings("lease-1", materialized.lease_id.?);

    try materialized.release();
    try testing.expectEqual(@as(usize, 2), stub.calls.items.len);
    try testing.expectEqualStrings(protocol.method.file_release, stub.calls.items[1]);
    try testing.expectEqualStrings("lease-1", stub.params.items[1].getString("lease_id").?);
    try testing.expectEqual(null, materialized.lease_id);

    // A spent lease makes no further host call.
    try materialized.release();
    try testing.expectEqual(@as(usize, 2), stub.calls.items.len);
}

test "the source of a file is its evidence address" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const file = FileRef.init(testContext(alloc, undefined), fileInfo(4));
    const source = file.source();
    try testing.expectEqualStrings("part:1", source.root.?);
    try testing.expectEqualStrings("kali/notes.txt", source.path.?);
    try testing.expectEqualStrings("node-9", source.node_id.?);

    const part = file.sourceAt(16, 4);
    try testing.expectEqual(@as(u64, 16), part.offset.?);
    try testing.expectEqual(@as(u64, 4), part.length.?);

    // Without a volume path the view path is used instead.
    var info = fileInfo(4);
    info.root_path = null;
    const fallback = FileRef.init(testContext(alloc, undefined), info).source();
    try testing.expectEqualStrings("home/kali/notes.txt", fallback.path.?);
}

const abi = @import("abi.zig");
