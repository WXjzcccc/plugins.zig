//! Dev tool: run the extraction over a real hive file from disk and print
//! what the plugin would emit — no host involved.
//!
//!   zig build probe
//!   zig-out/bin/probe.exe [--master <password>] NTUSER.DAT [more.hives ...]

const std = @import("std");
const hive_mod = @import("core/hive.zig");
const mobaxterm = @import("core/mobaxterm.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var master: []const u8 = "";
    var start: usize = 1;
    if (args.len > 2 and std.mem.eql(u8, args[1], "--master")) {
        master = args[2];
        start = 3;
    }
    if (args.len <= start) {
        std.debug.print("usage: probe [--master <password>] <NTUSER.DAT> [more.hives ...]\n", .{});
        std.process.exit(2);
    }

    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();

    for (args[start..]) |path| {
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
        const report = try mobaxterm.collect(values.allocator(), &hive, master);
        for (report.passwords) |password| {
            std.debug.print("  P [{s}] {s} -> {s}\n", .{ password.protocol, password.account_host, password.password });
        }
        for (report.credentials) |credential| {
            std.debug.print("  C [{s}] user={s} -> {s}\n", .{ credential.name, credential.username, credential.password });
        }
        if (report.passwords.len == 0 and report.credentials.len == 0) {
            std.debug.print("  (no MobaXterm passwords or credentials)\n", .{});
        }
    }
}
