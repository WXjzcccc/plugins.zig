//! LPP v2 errors: a stable machine-readable `code` plus a human-readable
//! `message`, carried across the ABI as the `{code, message}` map of a
//! `STATUS_ERROR` reply.
//!
//! Zig error values cannot carry a payload, so the message travels in a
//! thread-local slot: `fail` / `failf` record it and return `error.Fault`. The
//! runtime drains the slot with `take` when it converts a failure into the
//! reply map, and clears it before each call. A few codes are common enough to
//! get their own error value, so plugin code can `switch` on them without
//! reading the slot.
//!
//! Codes are the uppercase LPP v2 names the host matches on (`CANCELLED`,
//! `INVALID_PARAMS`, …); they are the same strings `plugins/sdk/src/error.rs`
//! produces.

const std = @import("std");

const wire = @import("wire.zig");

/// Every failure the SDK can report. Codes returned by the host (for example
/// `VIEW_PATH_NOT_FOUND` or `RESOURCE_LIMIT`) keep their own value; anything
/// else arrives as `Fault` and is read back with `take`.
pub const Error = error{
    /// An arbitrary `{code, message}` pair recorded by `fail` / `failf`.
    Fault,
    OutOfMemory,
    InvalidParams,
    InvalidAnalyzer,
    InvalidSession,
    NoParser,
    MethodNotFound,
    NotFound,
    PathNotFound,
    ResourceLimit,
    Cancelled,
    ProtocolError,
    HostError,
    Panic,
    /// A record value does not match its schema.
    InvalidRecord,
    /// The analyzer emitted a record type it never registered.
    UnknownRecordType,
};

pub const Fault = struct {
    code: []const u8,
    message: []const u8,
};

/// The fault of the call running on this thread. Thread-local because the host
/// may run several calls of one instance at once.
threadlocal var slot: ?Fault = null;

/// Records `code`/`message` and returns `error.Fault`.
///
/// `message` must outlive the reply; the per-call arena of `Context.arena` is
/// the right place for anything formatted.
pub fn fail(code: []const u8, message: []const u8) Error {
    slot = .{ .code = code, .message = message };
    return error.Fault;
}

/// `fail` with a formatted message allocated from `alloc`.
pub fn failf(
    alloc: std.mem.Allocator,
    code: []const u8,
    comptime format: []const u8,
    args: anytype,
) Error {
    const message = std.fmt.allocPrint(alloc, format, args) catch return error.OutOfMemory;
    return fail(code, message);
}

/// `fail` with a message formatted into a per-thread scratch buffer, for
/// helpers that have no allocator at hand. The buffer is reused by the next
/// formatting fault on the same thread, which is safe because a fault is
/// drained by the runtime before the call returns.
pub fn failfmt(code: []const u8, comptime format: []const u8, args: anytype) Error {
    const message = std.fmt.bufPrint(&scratch, format, args) catch "message too long";
    return fail(code, message);
}

threadlocal var scratch: [512]u8 = undefined;

pub fn invalidParams(alloc: std.mem.Allocator, comptime format: []const u8, args: anytype) Error {
    return failf(alloc, "INVALID_PARAMS", format, args);
}

pub fn protocolError(alloc: std.mem.Allocator, comptime format: []const u8, args: anytype) Error {
    return failf(alloc, "PROTOCOL_ERROR", format, args);
}

pub fn hostError(alloc: std.mem.Allocator, comptime format: []const u8, args: anytype) Error {
    return failf(alloc, "HOST_ERROR", format, args);
}

/// A path the host could not resolve: `error.PathNotFound`, with the message
/// left in the fault slot so the reply reads "`path` does not exist".
///
/// It is the *named* error, not `error.Fault`, so callers can write
/// `catch |err| if (err == error.PathNotFound) continue;` — `codeOf` maps it
/// to `VIEW_PATH_NOT_FOUND` either way.
pub fn pathNotFound(alloc: std.mem.Allocator, path: []const u8) Error {
    const message = std.fmt.allocPrint(alloc, "{s} does not exist", .{path}) catch
        return error.OutOfMemory;
    slot = .{ .code = "VIEW_PATH_NOT_FOUND", .message = message };
    return error.PathNotFound;
}

pub fn cancelled() Error {
    return fail("CANCELLED", "request cancelled");
}

/// Reads and clears the slot. The runtime calls this once per failed call,
/// before the slot can be overwritten by an unrelated fault.
pub fn take() ?Fault {
    const fault = slot;
    slot = null;
    return fault;
}

/// Reads the slot without clearing it.
pub fn peek() ?Fault {
    return slot;
}

/// Clears the slot; called before every host call so a stale fault can never
/// be attributed to a later failure.
pub fn clear() void {
    slot = null;
}

/// The stable code of `err`. `error.Fault` reports the recorded code, or
/// `PLUGIN_ERROR` when the slot is empty (which only happens when plugin code
/// returns `error.Fault` itself instead of using `fail`).
pub fn codeOf(err: Error) []const u8 {
    return switch (err) {
        error.Fault => if (slot) |fault| fault.code else "PLUGIN_ERROR",
        error.OutOfMemory => "RESOURCE_LIMIT",
        error.InvalidParams => "INVALID_PARAMS",
        error.InvalidAnalyzer => "INVALID_ANALYZER",
        error.InvalidSession => "INVALID_SESSION",
        error.NoParser => "NO_PARSER",
        error.MethodNotFound => "METHOD_NOT_FOUND",
        error.NotFound => "NOT_FOUND",
        error.PathNotFound => "VIEW_PATH_NOT_FOUND",
        error.ResourceLimit => "RESOURCE_LIMIT",
        error.Cancelled => "CANCELLED",
        error.ProtocolError => "PROTOCOL_ERROR",
        error.HostError => "HOST_ERROR",
        error.Panic => "PLUGIN_PANIC",
        error.InvalidRecord => "INVALID_RECORD",
        error.UnknownRecordType => "UNKNOWN_RECORD_TYPE",
    };
}

/// A human-readable message: the recorded fault text, or the code itself.
pub fn messageOf(err: Error) []const u8 {
    // A named error may still have a message recorded for it (`pathNotFound`
    // does), so prefer the slot when its code agrees with `err`.
    if (err != error.Fault) {
        if (slot) |fault| {
            if (std.mem.eql(u8, fault.code, codeOf(err))) return fault.message;
        }
    }
    return switch (err) {
        error.Fault => if (slot) |fault| fault.message else "plugin error",
        error.Cancelled => "request cancelled",
        error.OutOfMemory => "out of memory",
        error.InvalidParams => "invalid parameters",
        error.InvalidAnalyzer => "unknown analyzer",
        error.InvalidSession => "filesystem session does not exist",
        error.NoParser => "no filesystem parser registered",
        error.MethodNotFound => "method not found",
        error.NotFound => "not found",
        error.PathNotFound => "path does not exist",
        error.ResourceLimit => "resource limit exceeded",
        error.ProtocolError => "protocol error",
        error.HostError => "host call failed",
        error.Panic => "plugin panicked",
        error.InvalidRecord => "record does not match its schema",
        error.UnknownRecordType => "record type is not registered",
    };
}

/// Whether `err` is a cancellation: the named error, or a host reply with the
/// `CANCELLED` code.
pub fn isCancelled(err: Error) bool {
    return err == error.Cancelled or (err == error.Fault and hasCode(err, "CANCELLED"));
}

/// True when `err` carries the protocol code `code` (`METHOD_NOT_FOUND`,
/// `VIEW_PATH_NOT_FOUND`, `RESOURCE_LIMIT`, ...).
pub fn hasCode(err: Error, code: []const u8) bool {
    return std.mem.eql(u8, codeOf(err), code);
}

/// `{code, message}` for a `STATUS_ERROR` reply.
pub fn toValue(alloc: std.mem.Allocator, err: Error) wire.Error!wire.Value {
    return wire.mapOf(alloc, &.{
        wire.entry("code", wire.str(codeOf(err))),
        wire.entry("message", wire.str(messageOf(err))),
    });
}

/// Reads a `{code, message}` reply; anything else becomes `PROTOCOL_ERROR`.
pub fn fromValue(value: wire.Value) Error {
    const code = value.getString("code") orelse
        return fail("PROTOCOL_ERROR", "error reply is not a {code, message} map");
    const message = value.getString("message") orelse
        return fail("PROTOCOL_ERROR", "error reply is not a {code, message} map");
    // Keep the host's own code when the slot survives the reply: plugin code
    // switches on the named errors for the common cases.
    if (std.mem.eql(u8, code, "CANCELLED")) return cancelled();
    return fail(code, message);
}

/// True when a reply value carries an error code.
pub fn isFaultValue(value: wire.Value) bool {
    return value.getString("code") != null;
}

const testing = std.testing;

test "codes round-trip through the fault slot" {
    defer clear();

    try testing.expectEqual(@as(Error, error.Fault), fail("RESOURCE_LIMIT", "too big"));
    try testing.expectEqualStrings("RESOURCE_LIMIT", codeOf(error.Fault));
    try testing.expectEqualStrings("too big", messageOf(error.Fault));
    try testing.expect(hasCode(error.Fault, "RESOURCE_LIMIT"));
    try testing.expectEqualStrings("RESOURCE_LIMIT", take().?.code);
    // Drained: the next Fault has no recorded code.
    try testing.expectEqualStrings("PLUGIN_ERROR", codeOf(error.Fault));
    try testing.expectEqual(null, take());
}

test "named errors map to their LPP codes" {
    try testing.expectEqualStrings("CANCELLED", codeOf(error.Cancelled));
    try testing.expectEqualStrings("VIEW_PATH_NOT_FOUND", codeOf(error.PathNotFound));
    try testing.expectEqualStrings("METHOD_NOT_FOUND", codeOf(error.MethodNotFound));
    try testing.expectEqualStrings("INVALID_RECORD", codeOf(error.InvalidRecord));
    try testing.expect(isCancelled(error.Cancelled));
    try testing.expect(!isCancelled(error.NotFound));
}

test "failf formats into the caller arena" {
    defer clear();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const err = invalidParams(arena.allocator(), "{s} must be a string", .{"size"});
    try testing.expectEqualStrings("INVALID_PARAMS", codeOf(err));
    try testing.expectEqualStrings("size must be a string", messageOf(err));
}

test "host errors keep their code and cancellation is recognised" {
    defer clear();

    const value = try wire.mapOf(testing.allocator, &.{
        wire.entry("code", wire.str("VIEW_PATH_NOT_FOUND")),
        wire.entry("message", wire.str("etc/missing does not exist")),
    });
    defer testing.allocator.free(value.map);

    const err = fromValue(value);
    try testing.expectEqualStrings("VIEW_PATH_NOT_FOUND", codeOf(err));
    try testing.expectEqualStrings("etc/missing does not exist", messageOf(err));
    _ = take();

    const cancelled_value = try wire.mapOf(testing.allocator, &.{
        wire.entry("code", wire.str("CANCELLED")),
        wire.entry("message", wire.str("run cancelled")),
    });
    defer testing.allocator.free(cancelled_value.map);
    try testing.expect(isCancelled(fromValue(cancelled_value)));
    _ = take();
}
