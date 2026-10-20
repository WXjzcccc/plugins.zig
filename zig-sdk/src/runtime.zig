//! The plugin side of the C ABI: one [`Instance`] per entry-point call turns
//! host requests into calls on the registered analyzers and parsers.
//!
//! A plugin never writes the ABI plumbing itself. It declares
//!
//! ```zig
//! const lc = @import("lovelycarve");
//!
//! pub const plugin = lc.Plugin{ .id = "org.example.demo", ... };
//!
//! comptime {
//!     lc.exportPlugin(@This());
//! }
//! ```
//!
//! and this module exports `lovelycarve_plugin_v1`, answers `plugin.hello`,
//! dispatches `run.start` and every `fs.*` method, and tracks cancellation.

const std = @import("std");

const abi = @import("abi.zig");
const wire = @import("wire.zig");
const value = @import("value.zig");
const sdk = @import("error.zig");
const host = @import("host.zig");
const protocol = @import("protocol.zig");
const schema = @import("schema.zig");
const source_mod = @import("source.zig");
const filesystem = @import("filesystem.zig");
const run_mod = @import("run.zig");
const plugin_mod = @import("plugin.zig");

/// Probed sources kept for the following `fs.open`.
const MAX_CACHED_SOURCES: usize = 16;

/// One host-to-plugin method.
pub const Method = enum {
    shutdown,
    run_start,
    probe,
    open,
    close,
    children,
    children_page,
    stat,
    read_range,

    fn parse(name: []const u8) ?Method {
        const table = .{
            .{ "plugin.shutdown", Method.shutdown },
            .{ "run.start", Method.run_start },
            .{ "fs.probe", Method.probe },
            .{ "fs.open", Method.open },
            .{ "fs.close", Method.close },
            .{ "fs.children", Method.children },
            .{ "fs.children_page", Method.children_page },
            .{ "fs.stat", Method.stat },
            .{ "fs.read_range", Method.read_range },
        };
        inline for (table) |row| {
            if (std.mem.eql(u8, name, row[0])) return row[1];
        }
        return null;
    }
};

/// A spin lock around one piece of instance state.
///
/// `std.atomic.Mutex` needs no `Io` handle, which is what makes it usable from
/// a C ABI callback. Host calls for one instance can arrive on several threads
/// at once, so every map below has one.
const Lock = struct {
    inner: std.atomic.Mutex = .unlocked,

    fn acquire(self: *Lock) void {
        while (!self.inner.tryLock()) std.atomic.spinLoopHint();
    }

    fn release(self: *Lock) void {
        self.inner.unlock();
    }
};

/// An open filesystem session: the volume plus a reference to the source it
/// was opened from, so the source outlives the session even if the cache
/// evicts it.
const Session = struct {
    volume: filesystem.Volume,
    source: source_mod.Source,
};

/// All state of one plugin instance.
pub const Instance = struct {
    plugin: *const plugin_mod.Plugin,
    host: host.HostConnection,
    /// Outlives every call: the maps below, their keys, the record schemas and
    /// the reply buffers.
    alloc: std.mem.Allocator,
    /// `profile.fact` plus every registered record type, in registration
    /// order. Owned by `alloc`.
    records: []const schema.RecordSchema,

    sources_lock: Lock = .{},
    sources: std.StringHashMapUnmanaged(source_mod.Source) = .empty,

    selected_lock: Lock = .{},
    selected: std.StringHashMapUnmanaged(usize) = .empty,

    sessions_lock: Lock = .{},
    sessions: std.StringHashMapUnmanaged(Session) = .empty,

    calls_lock: Lock = .{},
    calls: std.AutoHashMapUnmanaged(u64, *std.atomic.Value(bool)) = .empty,

    next_session: std.atomic.Value(u64) = std.atomic.Value(u64).init(1),

    pub fn create(
        alloc: std.mem.Allocator,
        plugin: *const plugin_mod.Plugin,
        api: abi.HostApiV1,
    ) ?*Instance {
        const instance = alloc.create(Instance) catch return null;
        const records = plugin.allRecords(alloc) catch {
            alloc.destroy(instance);
            return null;
        };
        instance.* = .{
            .plugin = plugin,
            .host = host.HostConnection.init(api),
            .alloc = alloc,
            .records = records,
        };
        return instance;
    }

    /// Closes every session and frees everything the instance owns. The host
    /// calls this through the `destroy` callback.
    pub fn destroy(self: *Instance) void {
        self.closeSessions();
        {
            self.sources_lock.acquire();
            defer self.sources_lock.release();
            var it = self.sources.iterator();
            while (it.next()) |item| {
                item.value_ptr.release();
                self.alloc.free(item.key_ptr.*);
            }
            self.sources.deinit(self.alloc);
        }
        {
            self.selected_lock.acquire();
            defer self.selected_lock.release();
            var it = self.selected.iterator();
            while (it.next()) |item| self.alloc.free(item.key_ptr.*);
            self.selected.deinit(self.alloc);
        }
        {
            self.calls_lock.acquire();
            defer self.calls_lock.release();
            var it = self.calls.valueIterator();
            while (it.next()) |flag| self.alloc.destroy(flag.*);
            self.calls.deinit(self.alloc);
        }
        self.alloc.free(self.records);
        self.alloc.destroy(self);
    }

    /// One host request: register its cancellation flag, dispatch, and drop
    /// the flag again even when the method fails.
    fn handle(
        self: *Instance,
        call_id: u64,
        method_name: []const u8,
        params: wire.Value,
        arena: std.mem.Allocator,
    ) sdk.Error!wire.Value {
        const method = Method.parse(method_name) orelse return sdk.failf(
            arena,
            "METHOD_NOT_FOUND",
            "plugin method {s} is not available",
            .{method_name},
        );

        const flag = self.alloc.create(std.atomic.Value(bool)) catch return error.OutOfMemory;
        flag.* = std.atomic.Value(bool).init(false);
        {
            self.calls_lock.acquire();
            defer self.calls_lock.release();
            self.calls.put(self.alloc, call_id, flag) catch {
                self.alloc.destroy(flag);
                return error.OutOfMemory;
            };
        }
        defer {
            self.calls_lock.acquire();
            defer self.calls_lock.release();
            _ = self.calls.fetchRemove(call_id);
            self.alloc.destroy(flag);
        }

        const ctx = host.Context{
            .host = self.host,
            .cancelled = flag,
            .arena = arena,
            .alloc = self.alloc,
        };
        return self.dispatch(ctx, method, params);
    }

    fn dispatch(
        self: *Instance,
        ctx: host.Context,
        method: Method,
        params: wire.Value,
    ) sdk.Error!wire.Value {
        return switch (method) {
            .shutdown => blk: {
                self.closeSessions();
                break :blk .nil;
            },
            .run_start => self.runStart(ctx, params),
            .probe => self.probe(ctx, try value.requiredStr(params, "source_id")),
            .open => self.open(
                ctx,
                try value.requiredStr(params, "source_id"),
                value.get(params, "options") orelse .nil,
            ),
            .close => self.close(ctx, try value.requiredStr(params, "session_id")),
            .children, .children_page, .stat, .read_range => self.browse(ctx, method, params),
        };
    }

    /// `run.start`: run one analyzer to completion. The reply is
    /// `{summary: <string|null>}`.
    fn runStart(self: *Instance, ctx: host.Context, params: wire.Value) sdk.Error!wire.Value {
        const start = try protocol.RunStart.fromValueWith(ctx.arena, params);
        const analyzer = self.plugin.findAnalyzer(start.analyzer) orelse return sdk.failf(
            ctx.arena,
            "INVALID_ANALYZER",
            "analyzer {s} is not registered",
            .{start.analyzer},
        );
        var run = try run_mod.Run.init(ctx, start, self.records);
        try analyzer.call(&run);
        const finish = try run.finish();
        return wire.mapOf(ctx.arena, &.{
            wire.entry("summary", value.optionalString(finish.summary)),
        }) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => sdk.fail("PROTOCOL_ERROR", "could not encode the run result"),
        };
    }

    fn probe(
        self: *Instance,
        ctx: host.Context,
        source_id: []const u8,
    ) sdk.Error!wire.Value {
        const parsers = self.plugin.parsers;
        if (parsers.len == 0) return sdk.fail("NO_PARSER", "no filesystem parser registered");
        const src = try self.source(ctx, source_id);
        defer src.release();

        var best_index: ?usize = null;
        var best: filesystem.Probe = filesystem.Probe.noMatch();
        for (parsers, 0..) |parser, index| {
            const probed = try parser.probe(ctx, &src);
            const best_confidence: f64 = if (best_index != null) best.confidence else 0;
            if (probed.confidence > best_confidence) {
                best = probed;
                best_index = index;
            }
        }

        // A probe without a match still names a declared filesystem, so the
        // host can tell "no match" from "undeclared filesystem".
        const filesystem_name = if (best_index) |index| name: {
            try self.select(source_id, index);
            break :name parsers[index].filesystem();
        } else parsers[0].filesystem();

        return value.map(ctx.arena, &.{
            value.entry("filesystem", value.str(filesystem_name)),
            value.entry("confidence", .{ .float = best.confidence }),
            value.entry("label", value.optionalString(best.label)),
        });
    }

    /// Remembers which parser won the probe for this source.
    fn select(self: *Instance, source_id: []const u8, index: usize) sdk.Error!void {
        self.selected_lock.acquire();
        defer self.selected_lock.release();
        if (self.selected.getPtr(source_id)) |slot| {
            slot.* = index;
            return;
        }
        const key = self.alloc.dupe(u8, source_id) catch return error.OutOfMemory;
        self.selected.put(self.alloc, key, index) catch {
            self.alloc.free(key);
            return error.OutOfMemory;
        };
    }

    fn open(
        self: *Instance,
        ctx: host.Context,
        source_id: []const u8,
        options: wire.Value,
    ) sdk.Error!wire.Value {
        const parsers = self.plugin.parsers;
        if (parsers.len == 0) return sdk.fail("NO_PARSER", "no filesystem parser registered");

        // Take the probed source out of the cache; the session keeps its own
        // reference so eviction cannot pull it out from under the volume.
        const src = try self.takeSource(ctx, source_id);
        defer src.release();
        const session_ref = src.retain();
        errdefer session_ref.release();

        const parser_index = blk: {
            self.selected_lock.acquire();
            defer self.selected_lock.release();
            const index = self.selected.get(source_id) orelse 0;
            break :blk if (index < parsers.len) index else 0;
        };
        const volume = try parsers[parser_index].open(ctx, &src, options);
        errdefer volume.close(ctx.arena);

        const root_node = try volume.rootNode(ctx.arena);
        const session_id = try std.fmt.allocPrint(
            ctx.arena,
            "session-{d}",
            .{self.next_session.fetchAdd(1, .monotonic)},
        );
        // Built before the session is registered: after the insert there is no
        // failure path left, so `errdefer session_ref.release()` cannot fire on
        // a session the map now owns.
        const reply = try value.map(ctx.arena, &.{
            value.entry("session_id", value.str(session_id)),
            value.entry("root_node", try root_node.toValue(ctx.arena)),
        });
        const key = self.alloc.dupe(u8, session_id) catch return error.OutOfMemory;
        {
            self.sessions_lock.acquire();
            defer self.sessions_lock.release();
            self.sessions.put(self.alloc, key, .{
                .volume = volume,
                .source = session_ref,
            }) catch {
                self.alloc.free(key);
                return error.OutOfMemory;
            };
        }
        return reply;
    }

    fn close(self: *Instance, ctx: host.Context, session_id: []const u8) sdk.Error!wire.Value {
        const removed = blk: {
            self.sessions_lock.acquire();
            defer self.sessions_lock.release();
            break :blk self.sessions.fetchRemove(session_id);
        };
        if (removed) |item| {
            item.value.volume.close(ctx.arena);
            item.value.source.release();
            self.alloc.free(item.key);
        }
        return .nil;
    }

    fn browse(
        self: *Instance,
        ctx: host.Context,
        method: Method,
        params: wire.Value,
    ) sdk.Error!wire.Value {
        const session_id = try value.requiredStr(params, "session_id");
        const volume = blk: {
            self.sessions_lock.acquire();
            defer self.sessions_lock.release();
            const session = self.sessions.get(session_id) orelse
                return sdk.fail("INVALID_SESSION", "filesystem session does not exist");
            break :blk session.volume;
        };
        const node_id = try value.requiredStr(params, "node_id");
        const alloc = ctx.arena;

        return switch (method) {
            .children => blk: {
                const nodes = try volume.children(alloc, node_id);
                const encoded = try alloc.alloc(wire.Value, nodes.len);
                for (nodes, 0..) |node, index| encoded[index] = try node.toValue(alloc);
                break :blk .{ .array = encoded };
            },
            .children_page => blk: {
                const limit = std.math.cast(usize, try value.requiredUint(params, "limit")) orelse
                    std.math.maxInt(usize);
                const cursor = value.optionalStr(params, "cursor");
                const page = try volume.childrenPage(alloc, node_id, limit, cursor);
                break :blk try page.toValue(alloc);
            },
            .stat => blk: {
                const stat = try volume.stat(alloc, node_id);
                break :blk try stat.toValue(alloc);
            },
            .read_range => blk: {
                const offset = try value.requiredUint(params, "offset");
                const length = std.math.cast(usize, try value.requiredUint(params, "length")) orelse
                    return sdk.invalidParams(alloc, "length does not fit this host", .{});
                break :blk value.bytes(try volume.read(alloc, node_id, offset, length));
            },
            else => sdk.fail("METHOD_NOT_FOUND", "not a filesystem session method"),
        };
    }

    /// A source from the cache, or a freshly opened one. The caller owns the
    /// returned reference and must release it.
    fn source(
        self: *Instance,
        ctx: host.Context,
        source_id: []const u8,
    ) sdk.Error!source_mod.Source {
        {
            self.sources_lock.acquire();
            defer self.sources_lock.release();
            if (self.sources.get(source_id)) |cached| return cached.retain();
        }
        const opened = try source_mod.Source.open(self.alloc, ctx.arena, self.host, source_id);
        {
            self.sources_lock.acquire();
            defer self.sources_lock.release();
            if (self.sources.count() >= MAX_CACHED_SOURCES) self.clearSourcesLocked();
            if (self.sources.getPtr(source_id)) |slot| {
                slot.release();
                slot.* = opened.retain();
            } else {
                const key = self.alloc.dupe(u8, source_id) catch return error.OutOfMemory;
                self.sources.put(self.alloc, key, opened.retain()) catch {
                    self.alloc.free(key);
                    return error.OutOfMemory;
                };
            }
        }
        return opened;
    }

    /// Removes a cached source, transferring the cache's reference to the
    /// caller (or opening a fresh one when the cache has no entry).
    fn takeSource(
        self: *Instance,
        ctx: host.Context,
        source_id: []const u8,
    ) sdk.Error!source_mod.Source {
        {
            self.sources_lock.acquire();
            defer self.sources_lock.release();
            if (self.sources.fetchRemove(source_id)) |item| {
                self.alloc.free(item.key);
                return item.value;
            }
        }
        return source_mod.Source.open(self.alloc, ctx.arena, self.host, source_id);
    }

    /// Drops every cached source. Sessions hold their own references, so a
    /// volume never loses the source it was opened from.
    fn clearSourcesLocked(self: *Instance) void {
        var it = self.sources.iterator();
        while (it.next()) |item| {
            item.value_ptr.release();
            self.alloc.free(item.key_ptr.*);
        }
        self.sources.clearRetainingCapacity();
    }

    fn cancel(self: *Instance, call_id: u64) void {
        self.calls_lock.acquire();
        defer self.calls_lock.release();
        if (self.calls.get(call_id)) |flag| flag.store(true, .release);
    }

    fn closeSessions(self: *Instance) void {
        self.sessions_lock.acquire();
        defer self.sessions_lock.release();
        var it = self.sessions.iterator();
        while (it.next()) |item| {
            item.value_ptr.volume.close(self.alloc);
            item.value_ptr.source.release();
            self.alloc.free(item.key_ptr.*);
        }
        self.sessions.clearRetainingCapacity();
    }
};

/// Exports `root.plugin` as the plugin entry point, under the symbol the host
/// looks up. Call it once per plugin library, from a comptime block:
///
/// ```zig
/// comptime {
///     lc.exportPlugin(@This());
/// }
/// ```
///
/// `root` is the plugin's root source file, which must declare
/// `pub const plugin = lc.Plugin{...}`.
pub fn exportPlugin(comptime root: type) void {
    const plugin: *const plugin_mod.Plugin = switch (@typeInfo(@TypeOf(root.plugin))) {
        .pointer => root.plugin,
        else => &root.plugin,
    };
    const Exports = struct {
        fn entryPoint(
            host_ptr: ?*const abi.HostApiV1,
            plugin_out: ?*abi.PluginApiV1,
        ) callconv(.c) i32 {
            return entry(host_ptr, plugin_out, plugin);
        }
    };
    @export(&Exports.entryPoint, .{ .name = abi.ENTRY_SYMBOL, .linkage = .strong });
}

/// Creates an instance of `plugin` and fills in the plugin table.
///
/// The host calls this once per instance; each call gets fresh state.
pub fn entry(
    host_ptr: ?*const abi.HostApiV1,
    plugin_out: ?*abi.PluginApiV1,
    plugin: *const plugin_mod.Plugin,
) i32 {
    const host_api = host_ptr orelse return abi.STATUS_INVALID_ARGUMENT;
    const output = plugin_out orelse return abi.STATUS_INVALID_ARGUMENT;

    // Refuse rather than crash when the host is a different ABI generation.
    if (host_api.abi_version != abi.ABI_VERSION or host_api.struct_size < abi.HOST_API_SIZE) {
        return abi.STATUS_ABI_MISMATCH;
    }

    // libc's allocator, so a buffer allocated here can be freed by the host's
    // C runtime and vice versa. Requires `link_libc` in build.zig.
    const instance = Instance.create(std.heap.c_allocator, plugin, host_api.*) orelse
        return abi.STATUS_ERROR;

    output.* = .{
        .abi_version = abi.ABI_VERSION,
        .struct_size = abi.PLUGIN_API_SIZE,
        .instance = instance,
        .describe = describe,
        .call = call,
        .cancel = cancel,
        .free_buffer = freeBuffer,
        .destroy = destroy,
    };
    return abi.STATUS_OK;
}

fn instanceOf(instance_ptr: ?*anyopaque) ?*Instance {
    const raw = instance_ptr orelse return null;
    return @ptrCast(@alignCast(raw));
}

/// Sent once, before any work: protocol version, identity, analyzers,
/// record schemas and their hash.
fn describe(instance_ptr: ?*anyopaque, out: ?*abi.Buffer) callconv(.c) i32 {
    const instance = instanceOf(instance_ptr) orelse return abi.STATUS_INVALID_ARGUMENT;
    const output = out orelse return abi.STATUS_INVALID_ARGUMENT;

    var arena_state = std.heap.ArenaAllocator.init(instance.alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    instance.plugin.validate(arena) catch |err| return replyFault(
        instance,
        output,
        arena,
        err,
    );
    const hello = instance.plugin.hello(arena) catch |err| return replyFault(
        instance,
        output,
        arena,
        err,
    );
    return replyValue(instance, output, hello);
}

/// Every host-to-plugin request arrives here.
fn call(
    instance_ptr: ?*anyopaque,
    call_id: u64,
    method_bytes: abi.Bytes,
    params_bytes: abi.Bytes,
    out: ?*abi.Buffer,
) callconv(.c) i32 {
    const instance = instanceOf(instance_ptr) orelse return abi.STATUS_INVALID_ARGUMENT;
    const output = out orelse return abi.STATUS_INVALID_ARGUMENT;

    // One arena per call: the decoded params, the reply and every temporary
    // string are freed together when this returns.
    var arena_state = std.heap.ArenaAllocator.init(instance.alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A fault recorded by an earlier call must never be attributed to this one.
    sdk.clear();
    const params = wire.decode(arena, params_bytes.slice()) catch |err| return replyFault(
        instance,
        output,
        arena,
        if (err == error.OutOfMemory) error.OutOfMemory else sdk.fail(
            "INVALID_PARAMS",
            "the request payload is not valid MessagePack",
        ),
    );

    const result = instance.handle(call_id, method_bytes.slice(), params, arena) catch |err|
        return replyFault(instance, output, arena, err);
    return replyValue(instance, output, result);
}

/// Cooperative cancellation: the host may ask while `call` is still running,
/// so this only sets a flag that the running call checks.
fn cancel(instance_ptr: ?*anyopaque, call_id: u64) callconv(.c) void {
    const instance = instanceOf(instance_ptr) orelse return;
    instance.cancel(call_id);
}

/// Frees a reply buffer the plugin allocated. The host calls this; the plugin
/// never calls it on its own replies.
fn freeBuffer(instance_ptr: ?*anyopaque, buffer: ?*abi.Buffer) callconv(.c) void {
    const instance = instanceOf(instance_ptr) orelse return;
    const target = buffer orelse return;
    target.freeOwned(instance.alloc);
}

fn destroy(instance_ptr: ?*anyopaque) callconv(.c) void {
    const instance = instanceOf(instance_ptr) orelse return;
    instance.destroy();
}

/// Encodes `payload` into a reply buffer owned by the instance allocator and
/// reports success.
fn replyValue(instance: *Instance, out: *abi.Buffer, payload: wire.Value) i32 {
    const bytes = wire.encode(instance.alloc, payload) catch
        return replyRaw(instance, out, "RESOURCE_LIMIT", "out of memory");
    out.* = abi.Buffer.fromOwned(bytes);
    return abi.STATUS_OK;
}

/// A `STATUS_ERROR` reply carrying `err` as `{code, message}`.
fn replyFault(
    instance: *Instance,
    out: *abi.Buffer,
    arena: std.mem.Allocator,
    err: sdk.Error,
) i32 {
    const code = sdk.codeOf(err);
    const message = sdk.messageOf(err);
    // The message may point into the arena that is about to be freed.
    sdk.clear();
    const payload = wire.mapOf(arena, &.{
        wire.entry("code", wire.str(code)),
        wire.entry("message", wire.str(message)),
    }) catch return abi.STATUS_ERROR;
    _ = replyValue(instance, out, payload);
    return abi.STATUS_ERROR;
}

/// A `STATUS_ERROR` reply built from literals, for the path where the call's
/// arena is already unusable.
fn replyRaw(instance: *Instance, out: *abi.Buffer, code: []const u8, message: []const u8) i32 {
    var arena_state = std.heap.ArenaAllocator.init(instance.alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const payload = wire.mapOf(arena, &.{
        wire.entry("code", wire.str(code)),
        wire.entry("message", wire.str(message)),
    }) catch return abi.STATUS_ERROR;
    _ = replyValue(instance, out, payload);
    return abi.STATUS_ERROR;
}

const testing = std.testing;

test "every LPP method parses and nothing else does" {
    try testing.expectEqual(Method.shutdown, Method.parse("plugin.shutdown").?);
    try testing.expectEqual(Method.run_start, Method.parse("run.start").?);
    try testing.expectEqual(Method.probe, Method.parse("fs.probe").?);
    try testing.expectEqual(Method.open, Method.parse("fs.open").?);
    try testing.expectEqual(Method.close, Method.parse("fs.close").?);
    try testing.expectEqual(Method.children, Method.parse("fs.children").?);
    try testing.expectEqual(Method.children_page, Method.parse("fs.children_page").?);
    try testing.expectEqual(Method.stat, Method.parse("fs.stat").?);
    try testing.expectEqual(Method.read_range, Method.parse("fs.read_range").?);
    try testing.expectEqual(null, Method.parse("fs.unknown"));
    try testing.expectEqual(null, Method.parse("analyzer.analyze"));
    try testing.expectEqual(null, Method.parse(""));
}
