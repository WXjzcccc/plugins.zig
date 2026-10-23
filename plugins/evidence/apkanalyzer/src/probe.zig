//! Development probe: analysis of one APK, with per-field schema checks.
//!
//!   zig build probe -- <file.apk>
//!
//! It runs the same conversion the analyzers run and validates every value
//! against its schema field, printing the first offending field with its value.
//! The analyzers themselves must never emit an invalid record, so this tool is
//! how a schema/conversion mismatch is found without guessing.

const std = @import("std");

const lc = @import("lovelycarve");
const engine = @import("core/analysis/engine.zig");
const conversion = @import("plugin/conversion.zig");
const records = @import("plugin/records.zig");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        var buffer: [256]u8 = undefined;
        var out = std.Io.File.stderr().writer(io, &buffer);
        try out.interface.writeAll("usage: probe <file.apk>\n");
        try out.interface.flush();
        return error.MissingArgument;
    }

    const path = args[1];
    const data = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 30));

    var analysis = try engine.analyzeBytes(arena, data, .{ .retain_entries = true });
    defer analysis.deinit();
    const info = &analysis.info;

    var buffer: [64 * 1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &buffer);
    const out = &stdout.interface;
    defer out.flush() catch {};

    try out.print("package={s} components={d} permissions={d} features={d} signers={d}\n", .{
        info.package_name orelse "?",
        info.components.len,
        info.permissions.len,
        info.features.len,
        info.signing.signers.len,
    });

    var invalid: usize = 0;
    invalid += try check(out, arena, records.INFO, try conversion.infoValues(arena, path, &analysis));
    for (info.components) |component| {
        invalid += try check(out, arena, records.COMPONENT, try conversion.componentValues(arena, path, component));
    }
    for (info.permissions) |permission| {
        invalid += try check(out, arena, records.PERMISSION, try conversion.permissionValues(arena, path, permission));
    }
    for (info.features) |feature| {
        invalid += try check(out, arena, records.FEATURE, try conversion.featureValues(arena, path, feature));
    }
    for (info.application_meta_data) |item| {
        invalid += try check(out, arena, records.METADATA, try conversion.metadataValues(arena, path, item));
    }
    for (info.signing.signers) |signer| {
        invalid += try check(out, arena, records.SIGNER, try conversion.signerValues(arena, path, signer));
        for (signer.certificates) |certificate| {
            invalid += try check(
                out,
                arena,
                records.CERTIFICATE,
                try conversion.certificateValues(arena, path, signer.scheme, certificate),
            );
        }
    }
    for (info.protections) |detection| {
        invalid += try check(out, arena, records.DETECTION, try conversion.detectionValues(arena, path, "protection", detection));
    }
    for (info.frameworks) |detection| {
        invalid += try check(out, arena, records.DETECTION, try conversion.detectionValues(arena, path, "framework", detection));
    }
    for (info.archive.entries) |entry| {
        invalid += try check(out, arena, records.ENTRY, try conversion.entryValues(arena, path, entry));
    }
    for (analysis.diagnostics) |diagnostic| {
        invalid += try check(out, arena, records.DIAGNOSTIC, try conversion.diagnosticValues(arena, path, diagnostic));
    }

    try out.print("invalid values: {d}\n", .{invalid});
}

fn check(
    out: *std.Io.Writer,
    alloc: std.mem.Allocator,
    schema: lc.RecordSchema,
    values: []const lc.wire.Value,
) !usize {
    if (values.len != schema.fields.len) {
        try out.print("COUNT {s}: {d} values for {d} fields\n", .{ schema.record_type, values.len, schema.fields.len });
        return 1;
    }
    var invalid: usize = 0;
    for (schema.fields, values) |field, value| {
        lc.schema.validateValue(field, value) catch |err| {
            try out.print("INVALID {s}.{s} kind={s} value={any} error={s}\n", .{
                schema.record_type,
                field.id,
                @tagName(field.kind),
                value,
                @errorName(err),
            });
            invalid += 1;
        };
        _ = alloc;
    }
    return invalid;
}
