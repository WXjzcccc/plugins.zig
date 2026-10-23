//! Prints the plugin's `plugin.hello` as the JSON document `schema.json`
//! carries — the same output `lc-plugin-host --describe --library <lib>`
//! produces, without loading the dynamic library.
//!
//! `zig build schema` runs it with an output path (`addOutputFileArg`), so the
//! document is a build artifact:
//!
//!   zig build schema        # writes zig-out/schema.json
//!
//! It cannot be run with `zig run src/describe.zig`: the `plugin` and
//! `lovelycarve` imports are wired by build.zig.
//!
//! The document lists the protocol version, the plugin id, the SDK version, the
//! analyzers and filesystems the library implements, every record schema and
//! their `schema_hash`. The host compares all of it with plugin.toml at every
//! handshake, so the file must be regenerated whenever a schema changes.

const std = @import("std");
const lc = @import("lovelycarve");
const plugin_root = @import("plugin");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    // The plugin's own validation runs first: a bad id or schema must fail the
    // build, not the handshake.
    try plugin_root.plugin.validate(arena);
    const document = try plugin_root.plugin.helloJson(arena);

    // One trailing newline, on both paths: the loader's `--describe` ends its
    // output with one, so `diff` between the two documents stays clean.
    const document_with_newline = try std.fmt.allocPrint(arena, "{s}\n", .{document});

    // The build system appends the output path (`addOutputFileArg`); without
    // one the document goes to stdout.
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
