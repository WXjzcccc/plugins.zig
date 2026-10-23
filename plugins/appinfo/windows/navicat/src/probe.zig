//! Dev tool: run the extraction over a real hive file from disk and print
//! what the plugin would emit — no host involved.
//!
//!   zig build probe
//!   zig-out/bin/probe.exe NTUSER.DAT [more.hives ...]

const std = @import("std");
const hive_mod = @import("core/hive.zig");
const navicat = @import("core/navicat.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len < 2) {
        std.debug.print("usage: probe <NTUSER.DAT> [more.hives ...]\n", .{});
        std.process.exit(2);
    }

    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();

    for (args[1..]) |path| {
        _ = scratch.reset(.retain_capacity);
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, scratch.allocator(), .limited(1 << 30)) catch |err| {
            std.debug.print("cannot read {s}: {t}\n", .{ path, err });
            continue;
        };
        var values: std.heap.ArenaAllocator = .init(gpa);
        defer values.deinit();
        var hive = hive_mod.Hive.open(values.allocator(), bytes) catch |err| {
            std.debug.print("{s}: not a hive ({t})\n", .{ std.fs.path.basename(path), err });
            continue;
        };
        std.debug.print("\n== {s} ==\n", .{std.fs.path.basename(path)});
        const connections = try navicat.collect(values.allocator(), &hive);
        if (connections.len == 0) {
            std.debug.print("  (no Navicat connections)\n", .{});
        }
        for (connections) |connection| {
            std.debug.print("  [{s}] {s}\n", .{ @tagName(connection.conn_type), connection.name });
            std.debug.print("    {s}@{s}:{d} db={s} auth={s}\n", .{
                connection.username,      connection.host,
                connection.port orelse 0, connection.database,
                connection.auth_mode,
            });
            std.debug.print("    password: {s}\n", .{connection.password});
            std.debug.print("    cache: {s} encrypted={} saved={?}\n", .{
                connection.cache_path,
                connection.encrypted orelse false,
                connection.saved_password,
            });
        }
    }
}
