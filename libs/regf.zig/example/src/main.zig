//! `example` — a small demo of the `regf_zig` library.
//!
//! Opens a SYSTEM hive and prints the mount table stored in its
//! `MountedDevices` key: the drive letters, volume GUIDs and device paths that
//! Windows uses to locate volumes at boot.
//!
//! The hive is only ever *read*. `testfiles/SYSTEM` ships with this repository;
//! pass a different path as the first argument to inspect another hive.

const std = @import("std");

const example = @import("example");
const regf = @import("regf_zig");

/// Used when no path is given on the command line.
const default_hive = "testfiles/SYSTEM";

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const path = if (args.len > 1) args[1] else default_hive;

    // The path is relative to the process working directory, which is the
    // repository root when run via `zig build run`.
    const cwd = std.Io.Dir.cwd();

    // Read the file, then parse it. Doing it in two steps keeps the parse
    // errors (`regf.Error`) separate from I/O errors, which is what makes the
    // `Diag` diagnostics usable.
    const bytes = cwd.readFileAlloc(io, path, gpa, .limited(1 << 32)) catch |err| {
        std.debug.print("cannot read {s}: {s}\n", .{ path, @errorName(err) });
        return err;
    };
    defer gpa.free(bytes);

    var diag: regf.Diag = .{};
    var hive = regf.Hive.fromBytes(gpa, bytes, &diag) catch |err| {
        var buf: [256]u8 = undefined;
        std.debug.print("cannot parse {s}: {s}\n", .{ path, regf.describe(err, diag, &buf) });
        return err;
    };
    defer hive.deinit();

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const w = &out.writer;

    // Header facts, so the output proves which hive was read.
    try w.print("hive: {s}\n", .{path});
    try w.print("  format: REGF {d}.{d}, {d} bytes of hive bins, {d} bytes on disk\n", .{
        hive.base_block.major_version,
        hive.base_block.minor_version,
        hive.base_block.hive_bins_size,
        hive.image().len,
    });
    try w.print("  sequence: {d}/{d}{s}\n", .{
        hive.base_block.primary_sequence,
        hive.base_block.secondary_sequence,
        if (hive.isDirty()) " (dirty: unreconciled transaction log)" else " (clean)",
    });

    var root = try hive.rootKey();
    defer root.deinit(gpa);
    try w.print("  root key: {s}\n\n", .{root.name});

    // The interesting part: MountedDevices.
    const table = example.mount.read(gpa, &hive) catch |err| switch (err) {
        error.KeyNotFound => {
            try w.writeAll("this hive has no MountedDevices key\n");
            try flush(io, w.buffered());
            return;
        },
        else => return err,
    };
    defer table.deinit(gpa);

    try example.mount.render(w, table);

    // Which control set is current, and how many services it holds — a second
    // example of navigating the hive by path.
    const current = hive.getValue("Select", "Current") catch null;
    if (current) |c| {
        defer c.deinit(gpa);
        const set_name = try std.fmt.allocPrint(gpa, "ControlSet{d:0>3}", .{c.dword});
        defer gpa.free(set_name);
        var services = hive.listSubkeys(set_name, gpa) catch null;
        if (services) |*s| {
            defer {
                for (s.items) |n| gpa.free(n);
                s.deinit(gpa);
            }
            try w.print("\ncurrent control set: {s} ({d} subkeys)\n", .{ set_name, s.items.len });
        }
    }

    try flush(io, w.buffered());
}

/// Writes `bytes` to stdout.
fn flush(io: std.Io, bytes: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var writer: std.Io.File.Writer = .init(.stdout(), io, &buf);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

test {
    // Pull in the demo module's tests.
    _ = example.mount;
}
