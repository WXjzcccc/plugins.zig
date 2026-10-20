//! What a plugin declares about itself: its record types, analyzers and
//! filesystem parsers, and the `plugin.hello` document the host checks the
//! package manifest against.

const std = @import("std");

const wire = @import("wire.zig");
const value = @import("value.zig");
const json = @import("json.zig");
const sdk = @import("error.zig");
const schema = @import("schema.zig");
const record = @import("record.zig");
const filesystem = @import("filesystem.zig");
const run_mod = @import("run.zig");

/// The LPP version this SDK speaks; `plugin.hello` reports it and the package
/// manifest must declare `protocol = 2`.
pub const PROTOCOL_VERSION: u16 = 2;

/// Version reported in `plugin.hello` as `sdk`.
pub const SDK_VERSION = "0.2.0";

/// One analyzer: the id its manifest declares and the function that runs it.
///
/// The function runs on a host worker thread and may block. It emits records
/// through the [`run_mod.Run`] it receives and returns once the analysis is
/// complete; an error discards everything the run emitted.
pub const Analyzer = struct {
    id: []const u8,
    run: *const fn (*const run_mod.Run) sdk.Error!void,

    pub fn call(self: Analyzer, run: *const run_mod.Run) sdk.Error!void {
        return self.run(run);
    }
};

/// Builds the analyzer table entry for `id` and the function `analyze`.
pub fn analyzer(id: []const u8, analyze: *const fn (*const run_mod.Run) sdk.Error!void) Analyzer {
    return .{ .id = id, .run = analyze };
}

/// One plugin library: an identity plus every record type and capability it
/// registers.
///
/// A plugin declares exactly one of these as `pub const plugin`:
///
/// ```zig
/// const lc = @import("lovelycarve");
///
/// pub const plugin = lc.Plugin{
///     .id = "org.example.osrelease",
///     .records = &.{RELEASE_SCHEMA},
///     .analyzers = &.{lc.analyzer("osrelease", analyze)},
/// };
/// ```
///
/// `id` must match `plugin.toml`; the host refuses a mismatch, an analyzer the
/// manifest declares but the library does not register, and record schemas that
/// differ from the package's `schema.json` (compared by `schemaHash`).
pub const Plugin = struct {
    id: []const u8,
    /// Record types this plugin emits. The built-in `profile.fact` type is
    /// registered automatically by [`Plugin.allRecords`].
    records: []const schema.RecordSchema = &.{},
    analyzers: []const Analyzer = &.{},
    parsers: []const filesystem.FileSystemParser = &.{},

    /// Every record type, `profile.fact` first, in registration order.
    pub fn allRecords(self: *const Plugin, alloc: std.mem.Allocator) sdk.Error![]schema.RecordSchema {
        const records = try alloc.alloc(schema.RecordSchema, self.records.len + 1);
        records[0] = record.profileFactSchema();
        @memcpy(records[1..], self.records);
        return records;
    }

    /// The registered analyzer with this id, if any.
    pub fn findAnalyzer(self: *const Plugin, id: []const u8) ?Analyzer {
        for (self.analyzers) |entry| {
            if (std.mem.eql(u8, entry.id, id)) return entry;
        }
        return null;
    }

    /// Checks ids and schemas; a plugin that fails is refused at the handshake.
    pub fn validate(self: *const Plugin, alloc: std.mem.Allocator) sdk.Error!void {
        if (!validPluginId(self.id)) {
            return sdk.failfmt(
                "PLUGIN_INVALID",
                "plugin id {s} must be 1..=128 ASCII letters, digits, '.', '-' or '_'",
                .{self.id},
            );
        }
        const records = try self.allRecords(alloc);
        defer alloc.free(records);
        if (records.len > schema.MAX_RECORD_TYPES) {
            return sdk.fail("PLUGIN_INVALID", "a plugin registers at most 256 record types");
        }
        for (records, 0..) |entry, index| {
            entry.validate() catch return sdk.failfmt(
                "PLUGIN_INVALID",
                "record type {s} is invalid",
                .{entry.record_type},
            );
            for (records[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier.record_type, entry.record_type)) {
                    return sdk.failfmt(
                        "PLUGIN_INVALID",
                        "record type {s} is registered twice",
                        .{entry.record_type},
                    );
                }
            }
        }
        for (self.analyzers, 0..) |entry, index| {
            if (!schema.validIdentifier(entry.id)) {
                return sdk.failfmt(
                    "PLUGIN_INVALID",
                    "analyzer id {s} must be a lowercase identifier",
                    .{entry.id},
                );
            }
            for (self.analyzers[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier.id, entry.id)) {
                    return sdk.failfmt(
                        "PLUGIN_INVALID",
                        "analyzer {s} is registered twice",
                        .{entry.id},
                    );
                }
            }
        }
        for (self.parsers, 0..) |parser, index| {
            for (self.parsers[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier.filesystem(), parser.filesystem())) {
                    return sdk.failfmt(
                        "PLUGIN_INVALID",
                        "filesystem {s} is registered twice",
                        .{parser.filesystem()},
                    );
                }
            }
        }
    }

    /// The `plugin.hello` payload: protocol version, identity, the analyzers
    /// and filesystems the library implements, its record schemas and their
    /// hash.
    pub fn hello(self: *const Plugin, alloc: std.mem.Allocator) sdk.Error!wire.Value {
        const records = try self.allRecords(alloc);

        const analyzer_values = try alloc.alloc(wire.Value, self.analyzers.len);
        for (self.analyzers, 0..) |entry, index| {
            analyzer_values[index] = wire.str(entry.id);
        }
        const filesystem_values = try alloc.alloc(wire.Value, self.parsers.len);
        for (self.parsers, 0..) |parser, index| {
            filesystem_values[index] = wire.str(parser.filesystem());
        }
        const record_values = try alloc.alloc(wire.Value, records.len);
        for (records, 0..) |entry, index| record_values[index] = try entry.toValue(alloc);

        return value.map(alloc, &.{
            value.entry("protocol", value.uint(PROTOCOL_VERSION)),
            value.entry("plugin", value.str(self.id)),
            value.entry("sdk", value.str(SDK_VERSION)),
            value.entry("analyzers", .{ .array = analyzer_values }),
            value.entry("filesystems", .{ .array = filesystem_values }),
            value.entry("records", .{ .array = record_values }),
            value.entry("schema_hash", value.str(try schema.schemaHash(alloc, records))),
        });
    }

    /// [`Plugin.hello`] as the JSON document `schema.json` carries.
    pub fn helloJson(self: *const Plugin, alloc: std.mem.Allocator) sdk.Error![]u8 {
        const document = try self.hello(alloc);
        return json.writePretty(alloc, document) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => sdk.fail("PROTOCOL_ERROR", "could not encode the plugin description"),
        };
    }
};

/// The manifest's own rule: 1..=128 ASCII letters, digits, '.', '-' or '_'.
fn validPluginId(id: []const u8) bool {
    if (id.len == 0 or id.len > 128) return false;
    for (id) |byte| {
        const ok = std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '-' or byte == '_';
        if (!ok) return false;
    }
    return true;
}
