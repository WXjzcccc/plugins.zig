//! Logical block sources handed to filesystem parsers.

const std = @import("std");

const wire = @import("wire.zig");
const value = @import("value.zig");
const sdk = @import("error.zig");
const host = @import("host.zig");
const abi = @import("abi.zig");

/// Largest byte count the host returns for one `*.read` call.
pub const MAX_HOST_READ: usize = 4 * 1024 * 1024;

const BLOCK_SIZE: u64 = 64 * 1024;
const CACHE_BLOCKS: usize = 64;

/// A read-only logical block device: a raw image, a partition slice, a
/// decrypted view, or any other host-managed source.
///
/// Reads that fit inside one 64 KiB block go through a small LRU cache of such
/// blocks, which saves host round trips for parsers that walk structures sector
/// by sector. A `Source` is reference counted: the runtime holds one reference
/// per cached source and takes another for every parser call, so the source
/// stays valid while any call is still using it.
pub const Source = struct {
    inner: *Inner,

    const Block = struct { offset: u64, data: []u8 };

    const Inner = struct {
        refs: std.atomic.Value(usize) = .init(1),
        conn: host.HostConnection,
        /// Owns `source_id` and the cached blocks; the runtime's allocator, so
        /// a source outlives the call that opened it.
        alloc: std.mem.Allocator,
        source_id: []const u8,
        size: u64,
        sector_size: u32,
        /// Held across a whole `read`, so a host round trip on a cold block
        /// cannot race a concurrent reader of the same source.
        lock: std.atomic.Mutex = .unlocked,
        blocks: std.ArrayList(Block) = .empty,
    };

    /// Opens a source and asks the host for its geometry (`source.info`).
    /// `alloc` owns the source itself; `scratch` only holds the decoded reply.
    pub fn open(
        alloc: std.mem.Allocator,
        scratch: std.mem.Allocator,
        conn: host.HostConnection,
        source_id: []const u8,
    ) sdk.Error!Source {
        const info = try conn.call(scratch, "source.info", try value.map(scratch, &.{
            value.entry("source_id", value.str(source_id)),
        }));
        const inner = try alloc.create(Inner);
        errdefer alloc.destroy(inner);
        inner.* = .{
            .conn = conn,
            .alloc = alloc,
            .source_id = try alloc.dupe(u8, source_id),
            .size = try value.requiredUint(info, "size"),
            .sector_size = std.math.cast(u32, value.optionalUint(info, "sector_size") orelse 512) orelse 512,
        };
        return .{ .inner = inner };
    }

    pub fn retain(self: Source) Source {
        _ = self.inner.refs.fetchAdd(1, .monotonic);
        return self;
    }

    pub fn release(self: Source) void {
        if (self.inner.refs.fetchSub(1, .acq_rel) == 1) {
            const alloc = self.inner.alloc;
            for (self.inner.blocks.items) |cached| alloc.free(cached.data);
            self.inner.blocks.deinit(alloc);
            alloc.free(self.inner.source_id);
            alloc.destroy(self.inner);
        }
    }

    pub fn id(self: Source) []const u8 {
        return self.inner.source_id;
    }

    pub fn size(self: Source) u64 {
        return self.inner.size;
    }

    pub fn sectorSize(self: Source) u32 {
        return self.inner.sector_size;
    }

    /// Reads up to `length` bytes at `offset`, clamped at the end of the
    /// source. The result is allocated from `alloc`.
    pub fn read(
        self: Source,
        alloc: std.mem.Allocator,
        offset: u64,
        length: usize,
    ) sdk.Error![]u8 {
        if (length == 0 or offset >= self.inner.size) return alloc.alloc(u8, 0);
        const end = @min(offset +| @as(u64, length), self.inner.size);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(alloc);
        try out.ensureTotalCapacity(alloc, @intCast(end - offset));

        // Large reads never hit the block cache: one host call returns up to
        // `MAX_HOST_READ` bytes, which beats filling 64 KiB blocks.
        if (end - offset > BLOCK_SIZE) {
            var position = offset;
            while (position < end) {
                const chunk = try self.readHost(alloc, position, @min(end - position, MAX_HOST_READ));
                if (chunk.len == 0) break;
                try out.appendSlice(alloc, chunk);
                position += chunk.len;
            }
            return out.toOwnedSlice(alloc);
        }

        lockInner(self.inner);
        defer unlockInner(self.inner);
        var position = offset;
        while (position < end) {
            const block_offset = position - position % BLOCK_SIZE;
            const data = try self.block(alloc, block_offset);
            const start: usize = @intCast(position - block_offset);
            if (start >= data.len) break;
            const take = @min(@as(usize, @intCast(end - position)), data.len - start);
            try out.appendSlice(alloc, data[start .. start + take]);
            position += take;
        }
        return out.toOwnedSlice(alloc);
    }

    /// Reads several ranges in one host call (at most 128 ranges, 8 MiB).
    pub fn readv(
        self: Source,
        alloc: std.mem.Allocator,
        ranges: []const value.Range,
    ) sdk.Error![]const []const u8 {
        const reply = try self.inner.conn.call(alloc, "source.readv", try value.map(alloc, &.{
            value.entry("source_id", value.str(self.inner.source_id)),
            value.entry("ranges", try value.ranges(alloc, ranges)),
        }));
        return value.intoByteList(alloc, reply, "source.readv");
    }

    /// One `source.read`. Callers must hold `inner.lock` when this touches the
    /// block cache; `readv` and the large-read path call it without it.
    fn readHost(
        self: Source,
        alloc: std.mem.Allocator,
        offset: u64,
        length: u64,
    ) sdk.Error![]const u8 {
        const reply = try self.inner.conn.call(alloc, "source.read", try value.map(alloc, &.{
            value.entry("source_id", value.str(self.inner.source_id)),
            value.entry("offset", value.uint(offset)),
            value.entry("length", value.uint(length)),
        }));
        const bytes = try value.intoBytes(reply, "source.read");
        if (bytes.len > length) {
            return sdk.fail("PROTOCOL_ERROR", "source.read returned more bytes than requested");
        }
        return bytes;
    }

    /// The cached block at `block_offset`, read from the host on a miss.
    /// Callers must hold `inner.lock`.
    fn block(self: Source, alloc: std.mem.Allocator, block_offset: u64) sdk.Error![]const u8 {
        const inner = self.inner;
        for (inner.blocks.items, 0..) |cached, index| {
            if (cached.offset != block_offset) continue;
            // Move the hit to the back: the list is an LRU queue.
            const hit = inner.blocks.orderedRemove(index);
            inner.blocks.appendAssumeCapacity(hit);
            return hit.data;
        }

        const length = @min(inner.size - block_offset, BLOCK_SIZE);
        const fresh = try alloc.dupe(u8, try self.readHost(alloc, block_offset, length));
        errdefer alloc.free(fresh);

        // The block belongs to the source, not to the calling request, so it
        // is copied into the source's own allocator before being cached.
        const data = try inner.alloc.dupe(u8, fresh);
        alloc.free(fresh);

        if (inner.blocks.items.len == CACHE_BLOCKS) {
            const evicted = inner.blocks.orderedRemove(0);
            inner.alloc.free(evicted.data);
        }
        inner.blocks.appendAssumeCapacity(.{ .offset = block_offset, .data = data });
        return data;
    }
};

fn lockInner(inner: *Source.Inner) void {
    while (!inner.lock.tryLock()) std.atomic.spinLoopHint();
}

fn unlockInner(inner: *Source.Inner) void {
    inner.lock.unlock();
}

const testing = std.testing;

test "a source keeps its geometry from source.info" {
    // The host is stubbed out here: `open` only reaches for it through the
    // connection, so a table with a fake `call` is enough to exercise the
    // decode path.
    const Stub = struct {
        fn call(
            context: ?*anyopaque,
            method: abi.Bytes,
            params: abi.Bytes,
            out: *abi.Buffer,
        ) callconv(.c) i32 {
            _ = context;
            _ = params;
            if (!std.mem.eql(u8, method.slice(), "source.info")) return abi.STATUS_ERROR;
            const payload = "\x81\xa4size\xce\x00\x10\x00\x00";
            const copy = std.heap.c_allocator.dupe(u8, payload) catch return abi.STATUS_ERROR;
            out.* = abi.Buffer.fromOwned(copy);
            return abi.STATUS_OK;
        }
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const table = abi.HostApiV1{
        .abi_version = abi.ABI_VERSION,
        .struct_size = abi.HOST_API_SIZE,
        .context = null,
        .call = Stub.call,
        .free_buffer = freeStubBuffer,
        .log = logStub,
    };
    const source = try Source.open(alloc, alloc, host.HostConnection.init(table), "src-1");
    defer source.release();
    try testing.expectEqualStrings("src-1", source.id());
    try testing.expectEqual(@as(u64, 1024 * 1024), source.size());
    try testing.expectEqual(@as(u32, 512), source.sectorSize());
}

fn freeStubBuffer(context: ?*anyopaque, buffer: *abi.Buffer) callconv(.c) void {
    _ = context;
    buffer.freeOwned(std.heap.c_allocator);
}

fn logStub(context: ?*anyopaque, level: u32, message: abi.Bytes) callconv(.c) void {
    _ = context;
    _ = level;
    _ = message;
}
