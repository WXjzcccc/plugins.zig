//! Prints the plugin's `plugin.hello` as the JSON document `schema.json`
//! carries — the same output `lc-plugin-host --describe --library <lib>`
//! produces, without loading the dynamic library.
//!
//!   zig build schema        # writes zig-out/schema.json
//!
//! The host compares the document with plugin.toml at every handshake, so
//! it must be regenerated whenever a schema changes.

const std = @import("std");
const lc = @import("lovelycarve");
const plugin_root = @import("plugin");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    // The plugin's own validation runs first: a bad id or schema must fail
    // the build, not the handshake.
    try plugin_root.plugin.validate(arena);
    const document = try plugin_root.plugin.helloJson(arena);

    const document_with_newline = try std.fmt.allocPrint(arena, "{s}\n", .{document});

    const output = if (args.len > 1) args[1] else null;
    if (output) |path| {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = document_with_newline });
    } else {
        var buffer: [4096]u8 = undefined;
        var stdout = std.Io.File.stdout().writer(io, &buffer);
        try stdout.interface.writeAll(document_with_newline);
        try stdout.interface.flush();
    }
}
