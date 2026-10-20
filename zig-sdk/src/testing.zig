//! Test doubles: a fake host call table plus a driver, so a plugin can be
//! exercised through the real C ABI without a running LovelyCarve.
//!
//! `zig
//! const std = @import("std");
//! const lc = @import("lovelycarve");
//! const testing = lc.testing;
//!
//! const Host = struct {
//!     fn handle(
//!         _: ?*anyopaque,
//!         alloc: std.mem.Allocator,
//!         method: []const u8,
//!         params: lc.wire.Value,
//!     ) testing.Reply {
//!         _ = params;
//!         if (std.mem.eql(u8, method, "view.stat")) {
//!             return .{ .value = lc.wire.mapOf(alloc, &.{
//!                 lc.wire.entry("name", lc.wire.str("os-release")),
//!                 lc.wire.entry("kind", lc.wire.str("file")),
//!             }) catch return .empty };
//!         }
//!         return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
//!     }
//! };
//!
//! test "the plugin answers the handshake" {
//!     var stub = testing.Stub.init(std.testing.allocator, null, Host.handle);
//!     defer stub.deinit();
//!     var api = stub.api();
//!     var plugin = try testing.entry(&api, &@import("root.zig").plugin);
//!     defer plugin.destroy(plugin.instance);
//!
//!     const hello = try testing.describe(std.testing.allocator, &plugin);
//!     try std.testing.expectEqualStrings("com.example.plugin", hello.getString("plugin").?);
//! }
//! `
//!
//! The stub answers the methods the SDK sends on its own — `run.emit`,
//! `run.progress`, `run.warn` and `file.release` — and records them, so a
//! handler only deals with the evidence side (`view.*`, `file.read`,
//! `file.readv`, `file.materialize`, `source.*`). A `run.start` therefore
//! runs end to end: the emitted batches land in [`Stub.emits`].

const std = @import("std");

const abi = @import("abi.zig");
const protocol = @import("protocol.zig");
const wire = @import("wire.zig");
const sdk = @import("error.zig");
const plugin_mod = @import("plugin.zig");
const runtime = @import("runtime.zig");

/// What a stub host answers one method with.
pub const Reply = union(enum) {
    /// A payload the plugin decodes as the method's result.
    value: wire.Value,
    /// `STATUS_OK` with no payload.
    empty,
    /// `STATUS_ERROR` with a `{code, message}` reply.
    fault: struct { code: []const u8, message: []const u8 },
};

/// Answers one host method.
///
/// `params` is the decoded request payload (`.nil` when the request carried
/// none) and `alloc` is the stub's arena, freed when the stub is deinitialized;
/// the payload of a [`Reply.value`] is re-encoded before the stub returns, so
/// it only has to live for the handler call.
pub const Handler = *const fn (
    state: ?*anyopaque,
    alloc: std.mem.Allocator,
    method: []const u8,
    params: wire.Value,
) Reply;

/// One ABI log line.
pub const LogLine = struct {
    level: u32,
    message: []const u8,
};

/// One `run.progress` call.
pub const Progress = struct {
    current: u64,
    total: ?u64,
    message: ?[]const u8,
};

/// One `run.warn` call.
pub const Warning = struct {
    code: []const u8,
    message: []const u8,
    file_id: ?[]const u8,
};

/// One `run.emit` batch, exactly as the plugin sent it.
pub const EmitBatch = struct {
    run_id: []const u8,
    /// The `{type, values, title?, severity?, sources?}` maps of the batch.
    records: []const wire.Value,
};

/// A `HostApiV1` that answers from a function instead of a real host.
///
/// Take [`api`] once the stub sits where it will stay: the plugin table keeps
/// a pointer to it, and to the stub itself through `context`.
pub const Stub = struct {
    state: ?*anyopaque,
    handler: Handler,
    alloc: std.mem.Allocator,
    /// Every decoded payload and recorded string lives here and dies with
    /// `deinit`, so the lists below never own their elements.
    arena: std.heap.ArenaAllocator,

    /// Every method the plugin called, in order.
    calls: std.ArrayList([]const u8) = .empty,
    /// Every `log` line, in order.
    logs: std.ArrayList(LogLine) = .empty,
    /// Every `run.progress` call, in order.
    progress: std.ArrayList(Progress) = .empty,
    /// Every `run.warn` call, in order.
    warnings: std.ArrayList(Warning) = .empty,
    /// Every `run.emit` batch, in order.
    emits: std.ArrayList(EmitBatch) = .empty,

    pub fn init(alloc: std.mem.Allocator, state: ?*anyopaque, handler: Handler) Stub {
        return .{
            .state = state,
            .handler = handler,
            .alloc = alloc,
            .arena = std.heap.ArenaAllocator.init(alloc),
        };
    }

    pub fn deinit(self: *Stub) void {
        self.calls.deinit(self.alloc);
        self.logs.deinit(self.alloc);
        self.progress.deinit(self.alloc);
        self.warnings.deinit(self.alloc);
        self.emits.deinit(self.alloc);
        self.arena.deinit();
    }

    pub fn api(self: *Stub) abi.HostApiV1 {
        return .{
            .abi_version = abi.ABI_VERSION,
            .struct_size = abi.HOST_API_SIZE,
            .context = self,
            .call = hostCall,
            .free_buffer = freeBuffer,
            .log = log,
        };
    }

    /// How many times the plugin called `method`.
    pub fn callCount(self: *const Stub, method: []const u8) usize {
        var count: usize = 0;
        for (self.calls.items) |name| {
            if (std.mem.eql(u8, name, method)) count += 1;
        }
        return count;
    }

    pub fn saw(self: *const Stub, method: []const u8) bool {
        return self.callCount(method) > 0;
    }

    /// Every record of every batch, in emission order.
    pub fn emittedRecords(self: *const Stub, alloc: std.mem.Allocator) sdk.Error![]wire.Value {
        var total: usize = 0;
        for (self.emits.items) |batch| total += batch.records.len;
        const records = try alloc.alloc(wire.Value, total);
        var position: usize = 0;
        for (self.emits.items) |batch| {
            @memcpy(records[position..][0..batch.records.len], batch.records);
            position += batch.records.len;
        }
        return records;
    }

    /// How many records the run emitted in total.
    pub fn emittedCount(self: *const Stub) u64 {
        var total: u64 = 0;
        for (self.emits.items) |batch| total += batch.records.len;
        return total;
    }

    fn instance(context: ?*anyopaque) *Stub {
        const raw = context orelse return @ptrFromInt(@alignOf(Stub));
        return @ptrCast(@alignCast(raw));
    }

    fn hostCall(
        context: ?*anyopaque,
        method_bytes: abi.Bytes,
        params_bytes: abi.Bytes,
        out: ?*abi.Buffer,
    ) callconv(.c) i32 {
        const self = instance(context);
        const output = out orelse return abi.STATUS_INVALID_ARGUMENT;
        const alloc = self.arena.allocator();
        const method = method_bytes.slice();

        if (alloc.dupe(u8, method)) |name| {
            self.calls.append(self.alloc, name) catch {};
        } else |_| {}

        const params = wire.decode(alloc, params_bytes.slice()) catch
            return writeFault(output, "PROTOCOL_ERROR", "params are not MessagePack");

        // The run methods belong to the host side of the SDK, so the stub
        // answers them itself and a handler never sees them.
        if (std.mem.eql(u8, method, protocol.method.run_emit)) {
            return self.emitBatch(output, alloc, params);
        }
        if (std.mem.eql(u8, method, protocol.method.run_progress)) {
            self.recordProgress(alloc, params) catch {};
            return abi.STATUS_OK;
        }
        if (std.mem.eql(u8, method, protocol.method.run_warn)) {
            self.recordWarning(alloc, params) catch {};
            return abi.STATUS_OK;
        }
        if (std.mem.eql(u8, method, protocol.method.file_release)) {
            return abi.STATUS_OK;
        }

        return switch (self.handler(self.state, alloc, method, params)) {
            .value => |payload| writeValue(output, payload),
            .empty => abi.STATUS_OK,
            .fault => |fault| writeFault(output, fault.code, fault.message),
        };
    }

    fn emitBatch(self: *Stub, output: *abi.Buffer, alloc: std.mem.Allocator, params: wire.Value) i32 {
        const run_id = params.getString("run_id") orelse "";
        const records = switch (params.get("records") orelse wire.Value.nil) {
            .array => |items| items,
            else => return writeFault(output, "INVALID_PARAMS", "run.emit records must be an array"),
        };
        self.emits.append(self.alloc, .{ .run_id = run_id, .records = records }) catch
            return abi.STATUS_ERROR;
        const ack = wire.mapOf(alloc, &.{
            wire.entry("accepted", wire.uint(records.len)),
        }) catch return abi.STATUS_ERROR;
        return writeValue(output, ack);
    }

    fn recordProgress(self: *Stub, alloc: std.mem.Allocator, params: wire.Value) !void {
        const message = params.getString("message");
        try self.progress.append(self.alloc, .{
            .current = params.getUint("current") orelse 0,
            .total = params.getUint("total"),
            .message = if (message) |text| try alloc.dupe(u8, text) else null,
        });
    }

    fn recordWarning(self: *Stub, alloc: std.mem.Allocator, params: wire.Value) !void {
        try self.warnings.append(self.alloc, .{
            .code = try alloc.dupe(u8, params.getString("code") orelse ""),
            .message = try alloc.dupe(u8, params.getString("message") orelse ""),
            .file_id = if (params.getString("file_id")) |id| try alloc.dupe(u8, id) else null,
        });
    }

    fn freeBuffer(_: ?*anyopaque, buffer: *abi.Buffer) callconv(.c) void {
        buffer.freeOwned(std.heap.c_allocator);
    }

    fn log(context: ?*anyopaque, level: u32, message: abi.Bytes) callconv(.c) void {
        const self = instance(context);
        const text = self.arena.allocator().dupe(u8, message.slice()) catch return;
        self.logs.append(self.alloc, .{ .level = level, .message = text }) catch {};
    }

    fn writeValue(out: *abi.Buffer, payload: wire.Value) i32 {
        const encoded = wire.encode(std.heap.c_allocator, payload) catch return abi.STATUS_ERROR;
        out.* = abi.Buffer.fromOwned(encoded);
        return abi.STATUS_OK;
    }

    fn writeFault(out: *abi.Buffer, code: []const u8, message: []const u8) i32 {
        const reply = wire.mapOf(std.heap.c_allocator, &.{
            wire.entry("code", wire.str(code)),
            wire.entry("message", wire.str(message)),
        }) catch return abi.STATUS_ERROR;
        _ = writeValue(out, reply);
        return abi.STATUS_ERROR;
    }
};

/// `wire.encode` with codec failures mapped to LPP codes, like every other
/// boundary in the SDK.
fn encode(alloc: std.mem.Allocator, payload: wire.Value) sdk.Error![]u8 {
    return wire.encode(alloc, payload) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => sdk.fail("PROTOCOL_ERROR", "the payload is not encodable as MessagePack"),
    };
}

/// `wire.decode` with codec failures mapped to LPP codes.
fn decode(alloc: std.mem.Allocator, bytes: []const u8) sdk.Error!wire.Value {
    return wire.decode(alloc, bytes) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => sdk.fail("PROTOCOL_ERROR", "the reply is not valid MessagePack"),
    };
}

/// The outcome of one host-to-plugin call.
pub const CallResult = struct {
    status: i32,
    /// The decoded reply of a successful call; `null` when the reply was empty.
    payload: ?wire.Value = null,
    /// The `{code, message}` of a failed call.
    fault: ?sdk.Fault = null,
};

/// Drives one host-to-plugin call through the plugin table.
pub fn call(
    alloc: std.mem.Allocator,
    table: *const abi.PluginApiV1,
    call_id: u64,
    method: []const u8,
    params: wire.Value,
) sdk.Error!CallResult {
    const encoded = try encode(alloc, params);
    defer alloc.free(encoded);

    var out: abi.Buffer = abi.Buffer.empty;
    const status = table.call(
        table.instance,
        call_id,
        abi.Bytes.fromSlice(method),
        abi.Bytes.fromSlice(encoded),
        &out,
    );
    defer if (out.data != null) table.free_buffer(table.instance, &out);

    if (out.data == null or out.len == 0) return .{ .status = status };

    const decoded = try decode(alloc, out.slice());
    if (status == abi.STATUS_OK) return .{ .status = status, .payload = decoded };

    // Record the fault so the caller can read its code and message back.
    sdk.clear();
    _ = @intFromError(sdk.fromValue(decoded));
    return .{ .status = status, .fault = sdk.peek() };
}

/// [`call`], then an error unless the reply was `STATUS_OK`. A `STATUS_ERROR`
/// reply becomes the plugin's own error, code and message intact.
pub fn callOk(
    alloc: std.mem.Allocator,
    table: *const abi.PluginApiV1,
    call_id: u64,
    method: []const u8,
    params: wire.Value,
) sdk.Error!?wire.Value {
    const result = try call(alloc, table, call_id, method, params);
    if (result.status == abi.STATUS_OK) return result.payload;
    if (result.fault) |fault| return sdk.fail(fault.code, fault.message);
    return sdk.fail("PLUGIN_PANIC", "the plugin failed without a {code, message} reply");
}

/// Calls `describe` and decodes the `plugin.hello` payload.
pub fn describe(alloc: std.mem.Allocator, table: *const abi.PluginApiV1) sdk.Error!wire.Value {
    var out: abi.Buffer = abi.Buffer.empty;
    const status = table.describe(table.instance, &out);
    defer if (out.data != null) table.free_buffer(table.instance, &out);

    if (status != abi.STATUS_OK) {
        if (out.data != null and out.len > 0) {
            return sdk.fromValue(try decode(alloc, out.slice()));
        }
        return sdk.fail("PLUGIN_PANIC", "describe failed without a reply");
    }
    const data = out.data orelse return sdk.fail("PROTOCOL_ERROR", "describe replied with nothing");
    return decode(alloc, data[0..out.len]);
}

/// [`runtime.entry`] with the status code turned into an error.
pub fn entry(host: *const abi.HostApiV1, plugin: *const plugin_mod.Plugin) sdk.Error!abi.PluginApiV1 {
    var table: abi.PluginApiV1 = undefined;
    const status = runtime.entry(host, &table, plugin);
    if (status == abi.STATUS_OK) return table;
    return sdk.fail(statusCode(status), "the plugin entry point refused this host");
}

fn statusCode(status: i32) []const u8 {
    return switch (status) {
        abi.STATUS_ABI_MISMATCH => "PROTOCOL_ERROR",
        abi.STATUS_INVALID_ARGUMENT => "INVALID_PARAMS",
        abi.STATUS_PANIC => "PLUGIN_PANIC",
        else => "HOST_ERROR",
    };
}

const testing = std.testing;

const run_mod = @import("run.zig");
const schema = @import("schema.zig");
const host_mod = @import("host.zig");
const value = @import("value.zig");

/// One record type and one analyzer, so the driver below runs a real
/// `run.start` through the ABI.
const RELEASE_SCHEMA = schema.RecordSchema.new("demo.release", "系统信息", &.{
    schema.Field.new("key", "英文名称", .text).asKey(),
    schema.Field.new("value", "值", .text),
});

const Fixture = struct {
    fn analyze(run: *const run_mod.Run) sdk.Error!void {
        const view = try run.requireView();
        const file = (try view.open("etc/os-release")) orelse return;
        const lines = try file.readLines(1 << 20);
        for (lines) |line| {
            const index = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            try run.record(RELEASE_SCHEMA.record_type, &.{
                wire.str(line[0..index]),
                wire.str(line[index + 1 ..]),
            }).from(&file).emit();
        }
        try run.progress(1, 1, "done");
        run.setSummary("os-release");
    }

    fn handle(
        _: ?*anyopaque,
        alloc: std.mem.Allocator,
        method: []const u8,
        params: wire.Value,
    ) Reply {
        _ = params;
        if (std.mem.eql(u8, method, protocol.method.view_stat)) {
            return .{ .value = wire.mapOf(alloc, &.{
                wire.entry("name", wire.str("os-release")),
                wire.entry("kind", wire.str("file")),
                wire.entry("size", wire.uint(8)),
            }) catch return oom() };
        }
        if (std.mem.eql(u8, method, protocol.method.view_open)) {
            return .{ .value = wire.mapOf(alloc, &.{
                wire.entry("file_id", wire.str("file-1")),
                wire.entry("name", wire.str("os-release")),
                wire.entry("size", wire.uint(8)),
                wire.entry("view_path", wire.str("etc/os-release")),
                wire.entry("root", wire.str("part:0")),
                wire.entry("root_path", wire.str("etc/os-release")),
            }) catch return oom() };
        }
        if (std.mem.eql(u8, method, protocol.method.file_read)) {
            return .{ .value = value.bytes("A=1\nB=2\n") };
        }
        return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
    }

    fn oom() Reply {
        return .{ .fault = .{ .code = "RESOURCE_LIMIT", .message = "out of memory" } };
    }

    const plugin = plugin_mod.Plugin{
        .id = "com.example.testing",
        .records = &.{RELEASE_SCHEMA},
        .analyzers = &.{plugin_mod.analyzer("release", analyze)},
    };
};

test "a stub drives the handshake and a run.start end to end" {
    var stub = Stub.init(testing.allocator, null, Fixture.handle);
    defer stub.deinit();

    var api = stub.api();
    var table = try entry(&api, &Fixture.plugin);
    defer table.destroy(table.instance);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const hello = try describe(arena, &table);
    try testing.expectEqual(@as(u64, protocol.VERSION), hello.getUint("protocol").?);
    try testing.expectEqualStrings("com.example.testing", hello.getString("plugin").?);
    try testing.expectEqualStrings("0.2.0", hello.getString("sdk").?);
    try testing.expectEqualStrings("release", hello.get("analyzers").?.array[0].string);
    try testing.expectEqualStrings("demo.release", hello.get("records").?.array[1].getString("type").?);

    const start = try (protocol.RunStart{
        .run_id = "run-1",
        .analyzer = "release",
        .target = .{ .system = .{
            .view_id = "view-1",
            .label = "Linux",
            .system = .{
                .id = "linux@part:0",
                .family = "linux",
                .product = "Linux",
                .root = "part:0",
            },
            .mounts = &.{.{ .path = "", .root = "part:0", .source = "root" }},
        } },
        .locale = "zh-CN",
    }).toValue(arena);
    const finish = (try callOk(arena, &table, 2, protocol.method.run_start, start)).?;
    try testing.expectEqualStrings("os-release", finish.getString("summary").?);

    // The batches reached the stub, with one record per reported field.
    // How many records go into one batch is the run's business, so only the
    // total and the batch metadata are asserted here.
    try testing.expect(stub.emits.items.len > 0);
    try testing.expectEqual(@as(u64, 2), stub.emittedCount());
    for (stub.emits.items) |batch| {
        try testing.expectEqualStrings("run-1", batch.run_id);
        try testing.expect(batch.records.len > 0);
    }
    const records = try stub.emittedRecords(arena);
    try testing.expectEqualStrings("demo.release", records[0].getString("type").?);
    try testing.expectEqualStrings("A", records[0].get("values").?.array[0].string);
    try testing.expectEqualStrings("1", records[0].get("values").?.array[1].string);
    try testing.expectEqualStrings(
        "etc/os-release",
        records[0].get("sources").?.array[0].getString("path").?,
    );

    // view.open / file.read came from the handler; the run methods were
    // answered by the stub itself.
    try testing.expect(stub.saw(protocol.method.view_open));
    try testing.expect(stub.saw(protocol.method.file_read));
    try testing.expect(stub.saw(protocol.method.run_emit));
    try testing.expectEqual(@as(usize, 1), stub.progress.items.len);
    try testing.expectEqual(@as(u64, 1), stub.progress.items[0].current);
    try testing.expectEqualStrings("done", stub.progress.items[0].message.?);
    try testing.expectEqual(@as(usize, 0), stub.warnings.items.len);
}

test "the stub records progress, warnings and logs on its own" {
    var stub = Stub.init(testing.allocator, null, Fixture.handle);
    defer stub.deinit();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cancelled = std.atomic.Value(bool).init(false);
    const ctx = host_mod.Context{
        .host = host_mod.HostConnection.init(stub.api()),
        .cancelled = &cancelled,
        .arena = arena,
        .alloc = testing.allocator,
    };

    _ = try ctx.callHost(protocol.method.run_progress, try value.map(arena, &.{
        value.entry("run_id", value.str("run-1")),
        value.entry("current", value.uint(1)),
        value.entry("total", value.uint(2)),
        value.entry("message", value.str("halfway")),
    }));
    _ = try ctx.callHost(protocol.method.run_warn, try value.map(arena, &.{
        value.entry("run_id", value.str("run-1")),
        value.entry("code", value.str("MALFORMED_LINE")),
        value.entry("message", value.str("line 3")),
    }));
    _ = try ctx.callHost(protocol.method.file_release, try value.map(arena, &.{
        value.entry("lease_id", value.str("lease-1")),
    }));
    ctx.log(.info, "hello");

    try testing.expectEqual(@as(usize, 1), stub.progress.items.len);
    try testing.expectEqual(@as(u64, 1), stub.progress.items[0].current);
    try testing.expectEqual(@as(?u64, 2), stub.progress.items[0].total);
    try testing.expectEqualStrings("halfway", stub.progress.items[0].message.?);
    try testing.expectEqual(@as(usize, 1), stub.warnings.items.len);
    try testing.expectEqualStrings("MALFORMED_LINE", stub.warnings.items[0].code);
    try testing.expectEqual(null, stub.warnings.items[0].file_id);
    try testing.expectEqual(@as(usize, 1), stub.logs.items.len);
    try testing.expectEqualStrings("hello", stub.logs.items[0].message);
    try testing.expectEqual(abi.LOG_INFO, stub.logs.items[0].level);
    try testing.expect(stub.saw(protocol.method.file_release));
}

test "an unknown method and an unknown analyzer are error replies" {
    var stub = Stub.init(testing.allocator, null, Fixture.handle);
    defer stub.deinit();

    var api = stub.api();
    var table = try entry(&api, &Fixture.plugin);
    defer table.destroy(table.instance);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const unknown = try call(arena, &table, 3, "view.nope", .nil);
    try testing.expectEqual(abi.STATUS_ERROR, unknown.status);
    try testing.expectEqualStrings("METHOD_NOT_FOUND", unknown.fault.?.code);
    try testing.expect(unknown.payload == null);

    const missing = try call(arena, &table, 4, protocol.method.run_start, try wire.mapOf(
        arena,
        &.{
            wire.entry("run_id", wire.str("run-1")),
            wire.entry("analyzer", wire.str("nope")),
            wire.entry("target", try wire.mapOf(arena, &.{wire.entry("kind", wire.str("files"))})),
        },
    ));
    try testing.expectEqual(abi.STATUS_ERROR, missing.status);
    try testing.expectEqualStrings("INVALID_ANALYZER", missing.fault.?.code);
}

test "entry reports a mismatched host ABI as an error" {
    var stub = Stub.init(testing.allocator, null, Fixture.handle);
    defer stub.deinit();

    var api = stub.api();
    api.abi_version = 99;
    try testing.expectEqual(@as(sdk.Error, error.Fault), entry(&api, &Fixture.plugin));
    try testing.expectEqualStrings("PROTOCOL_ERROR", sdk.codeOf(error.Fault));
    sdk.clear();
}
