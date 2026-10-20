//! The host as seen from plugin code: synchronous LPP calls, per-request
//! cancellation and diagnostics.
//!
//! Plugin code never builds a `HostConnection`; the runtime creates one per
//! instance and hands a [`Context`] to every analyzer and parser call.

const std = @import("std");

const abi = @import("abi.zig");
const wire = @import("wire.zig");
const sdk = @import("error.zig");

pub const LogLevel = enum(u32) {
    err = abi.LOG_ERROR,
    warn = abi.LOG_WARN,
    info = abi.LOG_INFO,
    debug = abi.LOG_DEBUG,
};

/// The host function table of one plugin instance. Cheap to copy, and safe to
/// use from any thread for as long as the instance lives.
pub const HostConnection = struct {
    api: abi.HostApiV1,

    pub fn init(api: abi.HostApiV1) HostConnection {
        return .{ .api = api };
    }

    /// One plugin -> host method. `alloc` holds the encoded params, the
    /// decoded reply and any error text, so pass the per-call arena of the
    /// [`Context`] you are serving.
    pub fn call(
        self: HostConnection,
        alloc: std.mem.Allocator,
        method: []const u8,
        params: wire.Value,
    ) sdk.Error!wire.Value {
        const encoded = wire.encode(alloc, params) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return sdk.fail("PROTOCOL_ERROR", "could not encode the request payload"),
        };
        defer alloc.free(encoded);

        var reply = abi.Buffer.empty;
        const status = self.api.call(
            self.api.context,
            abi.Bytes.fromSlice(method),
            abi.Bytes.fromSlice(encoded),
            &reply,
        );
        // The host owns the reply until we release it through its own
        // `free_buffer`, even when the call failed.
        defer self.api.free_buffer(self.api.context, &reply);

        const payload = reply.slice();
        const decoded = if (payload.len == 0)
            wire.Value.nil
        else
            wire.decode(alloc, payload) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return sdk.failfmt(
                    "PROTOCOL_ERROR",
                    "host call {s} returned an invalid MessagePack payload",
                    .{method},
                ),
            };

        return switch (status) {
            abi.STATUS_OK => decoded,
            abi.STATUS_ERROR => sdk.fromValue(decoded),
            else => sdk.failfmt(
                "HOST_ERROR",
                "host call {s} failed with ABI status {d}",
                .{ method, status },
            ),
        };
    }

    /// One line to the LovelyCarve log (target `plugin`).
    pub fn log(self: HostConnection, level: LogLevel, message: []const u8) void {
        self.api.log(self.api.context, @backingInt(level), abi.Bytes.fromSlice(message));
    }
};

/// The host request a piece of plugin code is serving: cancellation, the
/// allocators for this call, and the connection for log output.
///
/// Every host call made through a handle bound to a context fails with
/// `CANCELLED` once the host cancels the request, so analyzers that read
/// evidence stop promptly. Long CPU-only loops should also poll
/// [`Context.checkCancelled`].
///
/// `arena` is reset when the call returns: it is the place for every string,
/// list and map the plugin builds for its reply. `alloc` outlives the call and
/// is only for state the plugin keeps between calls, such as filesystem
/// sessions.
pub const Context = struct {
    host: HostConnection,
    cancelled: *const std.atomic.Value(bool),
    arena: std.mem.Allocator,
    alloc: std.mem.Allocator,

    pub fn isCancelled(self: Context) bool {
        return self.cancelled.load(.acquire);
    }

    pub fn checkCancelled(self: Context) sdk.Error!void {
        if (self.isCancelled()) return sdk.cancelled();
    }

    /// Writes one line to the LovelyCarve log (target `plugin`).
    pub fn log(self: Context, level: LogLevel, message: []const u8) void {
        self.host.log(level, message);
    }

    /// A host call that respects cancellation. Replies are allocated from
    /// `self.arena`.
    pub fn callHost(
        self: Context,
        method: []const u8,
        params: wire.Value,
    ) sdk.Error!wire.Value {
        try self.checkCancelled();
        sdk.clear();
        return self.host.call(self.arena, method, params);
    }
};
