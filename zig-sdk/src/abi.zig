//! LovelyCarve plugin C ABI v1 — a direct mirror of
//! `sdk/include/lovelycarve_plugin.h`, which is the authoritative definition.
//! If they ever disagree, the header wins.
//!
//! You should not need to edit this file. It only exists because Zig cannot
//! include a C header without a C toolchain.
//!
//! The ABI is unchanged from SDK 0.1.0: one entry symbol, one host table, one
//! plugin table. What changed in 0.2.0 is the protocol the tables carry (LPP
//! v2, see `protocol.zig`) and the payload of `describe` (`plugin.hello`).

const std = @import("std");

/// Version of this table layout. The host refuses anything else.
pub const ABI_VERSION: u32 = 1;

/// The exported entry point, NUL-terminated for `GetProcAddress` / `dlsym`.
pub const ENTRY_SYMBOL = "lovelycarve_plugin_v1";

pub const STATUS_OK: i32 = 0;
pub const STATUS_ERROR: i32 = 1;
pub const STATUS_INVALID_ARGUMENT: i32 = 2;
pub const STATUS_ABI_MISMATCH: i32 = 3;
pub const STATUS_PANIC: i32 = 4;

/// Status names, for the log line a failed handshake writes.
pub fn statusName(status: i32) []const u8 {
    return switch (status) {
        STATUS_OK => "ok",
        STATUS_ERROR => "error",
        STATUS_INVALID_ARGUMENT => "invalid argument",
        STATUS_ABI_MISMATCH => "ABI mismatch",
        STATUS_PANIC => "panic",
        else => "unknown status",
    };
}

pub const LOG_ERROR: u32 = 1;
pub const LOG_WARN: u32 = 2;
pub const LOG_INFO: u32 = 3;
pub const LOG_DEBUG: u32 = 4;

/// Borrowed bytes. Valid only for the duration of the call that supplied them:
/// if you need to keep them, copy them.
pub const Bytes = extern struct {
    data: ?[*]const u8,
    len: usize,

    pub fn fromSlice(bytes: []const u8) Bytes {
        return .{ .data = bytes.ptr, .len = bytes.len };
    }

    pub fn slice(self: Bytes) []const u8 {
        const ptr = self.data orelse return &.{};
        return ptr[0..self.len];
    }
};

/// Owned bytes. Whoever fills it in owns it; the other side frees it through
/// that side's `free_buffer`.
pub const Buffer = extern struct {
    data: ?[*]u8,
    len: usize,
    capacity: usize,

    pub const empty: Buffer = .{ .data = null, .len = 0, .capacity = 0 };

    /// Borrows the buffer the other side filled in, before it is released.
    pub fn slice(self: Buffer) []const u8 {
        const ptr = self.data orelse return &.{};
        return ptr[0..self.len];
    }

    pub fn fromOwned(bytes: []u8) Buffer {
        return .{ .data = bytes.ptr, .len = bytes.len, .capacity = bytes.len };
    }

    pub fn freeOwned(self: *Buffer, alloc: std.mem.Allocator) void {
        if (self.data) |ptr| alloc.free(ptr[0..self.capacity]);
        self.* = Buffer.empty;
    }
};

pub const HostCallFn = *const fn (?*anyopaque, Bytes, Bytes, *Buffer) callconv(.c) i32;
pub const HostFreeBufferFn = *const fn (?*anyopaque, *Buffer) callconv(.c) void;
pub const HostLogFn = *const fn (?*anyopaque, u32, Bytes) callconv(.c) void;

/// What the host offers the plugin. The table and `context` stay valid for as
/// long as the instance exists.
pub const HostApiV1 = extern struct {
    abi_version: u32,
    struct_size: u32,
    context: ?*anyopaque,
    call: HostCallFn,
    free_buffer: HostFreeBufferFn,
    log: HostLogFn,
};

pub const DescribeFn = *const fn (?*anyopaque, *Buffer) callconv(.c) i32;
pub const CallFn = *const fn (?*anyopaque, u64, Bytes, Bytes, *Buffer) callconv(.c) i32;
pub const CancelFn = *const fn (?*anyopaque, u64) callconv(.c) void;
pub const FreeBufferFn = *const fn (?*anyopaque, *Buffer) callconv(.c) void;
pub const DestroyFn = *const fn (?*anyopaque) callconv(.c) void;

/// What the plugin hands back. The host reads `instance` on every call, so it
/// must point at your plugin state and stay valid until `destroy`.
pub const PluginApiV1 = extern struct {
    abi_version: u32,
    struct_size: u32,
    instance: ?*anyopaque,
    describe: DescribeFn,
    call: CallFn,
    cancel: CancelFn,
    free_buffer: FreeBufferFn,
    destroy: DestroyFn,
};

pub const HOST_API_SIZE: u32 = @sizeOf(HostApiV1);
pub const PLUGIN_API_SIZE: u32 = @sizeOf(PluginApiV1);

comptime {
    // The layouts have to match the C header exactly, or the host reads
    // garbage. Only checked on 64-bit targets because the offsets differ on
    // 32-bit ones.
    if (@sizeOf(usize) == 8) {
        std.debug.assert(@offsetOf(Bytes, "len") == 8);
        std.debug.assert(@offsetOf(Buffer, "len") == 8);
        std.debug.assert(@offsetOf(Buffer, "capacity") == 16);
        std.debug.assert(@offsetOf(HostApiV1, "context") == 8);
        std.debug.assert(@offsetOf(HostApiV1, "call") == 16);
        std.debug.assert(@offsetOf(PluginApiV1, "instance") == 8);
        std.debug.assert(@offsetOf(PluginApiV1, "describe") == 16);
    }
}
