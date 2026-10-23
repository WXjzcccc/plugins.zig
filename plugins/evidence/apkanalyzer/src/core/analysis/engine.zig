const std = @import("std");
const limits_mod = @import("../limits.zig");
const model = @import("../model.zig");
const zip = @import("../../utils/zip/archive.zig");
const axml = @import("../android/axml/document.zig");
const manifest = @import("../android/manifest/parser.zig");
const resource_config = @import("../android/resources/config.zig");
const resource_table = @import("../android/resources/table.zig");
const resource_resolver = @import("../android/resources/resolver.zig");
const signing_parser = @import("../signing/parser.zig");
const catalog = @import("catalog.zig");
const logging = @import("../../utils/logging.zig");
const signing_info = @import("signing_info.zig");
const icon = @import("icon.zig");

const log = logging.scoped(.apk_analysis);

pub const Options = struct {
    limits: limits_mod.Limits = .defaults,
    locale: ?[]const u8 = null,
    density: ?u16 = null,
    parse_resources: bool = true,
    parse_signatures: bool = true,
    /// Keep the APK bytes in the analysis, for callers that extract entries
    /// after parsing. Doubles the memory the analysis holds.
    retain_archive_bytes: bool = false,
    /// Keep the central-directory entry list without the bytes behind it.
    retain_entries: bool = false,
};

pub const Error = error{
    ApkTooLarge,
    TooManyArchiveEntries,
    DeclaredUncompressedSizeTooLarge,
    ArchiveSizeOverflow,
    MissingManifest,
    DuplicateCriticalEntry,
    CompressionRatioTooHigh,
    InvalidLocale,
};

/// Analyzes the bytes of one APK.
///
/// The plugin runtime reads the evidence through its read-only file handle and
/// passes the buffer in; `backing_allocator` only has to outlive the returned
/// analysis, which owns every string through its own arena.
pub fn analyzeBytes(
    backing_allocator: std.mem.Allocator,
    data: []const u8,
    options: Options,
) !model.Analysis {
    log.info(@src(), "analysis started bytes={d} resources={} signatures={}", .{
        data.len,
        options.parse_resources,
        options.parse_signatures,
    });
    if (data.len > options.limits.max_apk_size) {
        log.err(@src(), "APK rejected because size exceeds limit bytes={d} limit={d}", .{ data.len, options.limits.max_apk_size });
        return error.ApkTooLarge;
    }

    var analysis = model.Analysis.init(backing_allocator);
    errdefer analysis.deinit();
    const result_allocator = analysis.allocator();

    analysis.info.file_size = data.len;
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &sha256, .{});
    analysis.info.sha256 = sha256;

    const requested_locale = resolveResourceLocale(options.locale) catch |err| {
        log.warn(@src(), "invalid resource locale value={s} error={s}", .{ options.locale orelse "", @errorName(err) });
        return error.InvalidLocale;
    };

    var archive = zip.Archive.init(backing_allocator, data) catch |err| {
        log.err(@src(), "ZIP archive parsing failed error={s}", .{@errorName(err)});
        return err;
    };
    defer archive.deinit();
    if (archive.entries.len > options.limits.max_entries) {
        log.err(@src(), "archive entry limit exceeded entries={d} limit={d}", .{ archive.entries.len, options.limits.max_entries });
        return error.TooManyArchiveEntries;
    }
    populateArchiveInfo(&analysis.info.archive, archive.entries, options.limits) catch |err| {
        log.err(@src(), "archive statistics rejected error={s}", .{@errorName(err)});
        return err;
    };
    if (options.retain_archive_bytes or options.retain_entries) {
        analysis.info.archive.entries = try copyArchiveEntries(result_allocator, archive.entries);
    }
    if (options.retain_archive_bytes) {
        analysis.archive_bytes = try result_allocator.dupe(u8, data);
    }
    log.info(@src(), "ZIP archive parsed entries={d} compressed_bytes={d} uncompressed_bytes={d}", .{
        analysis.info.archive.file_count,
        analysis.info.archive.compressed_size,
        analysis.info.archive.uncompressed_size,
    });

    var diagnostics: std.ArrayList(model.Diagnostic) = .empty;
    defer diagnostics.deinit(result_allocator);

    const manifest_entry = (findUniqueEntry(&archive, "AndroidManifest.xml") catch |err| {
        log.err(@src(), "manifest entry lookup failed error={s}", .{@errorName(err)});
        return err;
    }) orelse {
        log.err(@src(), "APK does not contain AndroidManifest.xml", .{});
        return error.MissingManifest;
    };
    checkCompressionRatio(manifest_entry, options.limits) catch |err| {
        log.err(@src(), "manifest compression ratio rejected error={s}", .{@errorName(err)});
        return err;
    };
    const manifest_bytes = archive.extractAlloc(
        backing_allocator,
        manifest_entry,
        .{ .max_output_size = @min(
            @as(u64, options.limits.max_entry_uncompressed_size),
            64 * 1024 * 1024,
        ) },
    ) catch |err| {
        log.err(@src(), "manifest extraction failed error={s}", .{@errorName(err)});
        return err;
    };
    defer backing_allocator.free(manifest_bytes);

    var document = axml.Document.parse(backing_allocator, manifest_bytes) catch |err| {
        log.err(@src(), "binary manifest parsing failed error={s}", .{@errorName(err)});
        return err;
    };
    defer document.deinit();
    manifest.apply(result_allocator, &document, &analysis.info) catch |err| {
        log.err(@src(), "manifest model extraction failed error={s}", .{@errorName(err)});
        return err;
    };
    log.info(@src(), "manifest parsed package={s} permissions={d} components={d}", .{
        analysis.info.package_name orelse "",
        analysis.info.permissions.len,
        analysis.info.components.len,
    });

    if (options.parse_resources) {
        analyzeResources(
            backing_allocator,
            result_allocator,
            &archive,
            &analysis.info,
            .{
                .locale = requested_locale,
                .density = options.density,
            },
            options.limits,
        ) catch |err| {
            if (err == error.OutOfMemory) return err;
            log.warn(@src(), "resource parsing failed error={s}", .{@errorName(err)});
            try diagnostics.append(result_allocator, .{
                .stage = .resources,
                .severity = .warning,
                .code = "resources_parse_failed",
                .message = @errorName(err),
                .entry_name = "resources.arsc",
            });
        };
    } else {
        log.info(@src(), "resource parsing skipped by options", .{});
    }

    if (options.parse_signatures) {
        if (signing_parser.parseWithOptions(
            backing_allocator,
            &archive,
            signing_parser.ParseOptions.fromLimits(options.limits),
        )) |parsed_signing| {
            var temporary = parsed_signing;
            defer signing_parser.deinitSigningInfo(backing_allocator, &temporary);
            analysis.info.signing = try signing_info.copyInfo(result_allocator, temporary);
            log.info(@src(), "signing parsed signers={d} v1={} v2={} v3={} v31={}", .{
                analysis.info.signing.signers.len,
                analysis.info.signing.has_v1,
                analysis.info.signing.has_v2,
                analysis.info.signing.has_v3,
                analysis.info.signing.has_v31,
            });
        } else |err| {
            if (err == error.OutOfMemory) return err;
            log.warn(@src(), "signing parsing failed error={s}", .{@errorName(err)});
            try diagnostics.append(result_allocator, .{
                .stage = .signing,
                .severity = .warning,
                .code = "signing_parse_failed",
                .message = @errorName(err),
            });
        }
    } else {
        log.info(@src(), "signing parsing skipped by options", .{});
    }

    catalog.enrichAndDetect(result_allocator, &archive, &analysis.info) catch |err| {
        log.err(@src(), "catalog enrichment failed error={s}", .{@errorName(err)});
        return err;
    };
    log.info(@src(), "catalog enrichment completed protections={d} frameworks={d}", .{
        analysis.info.protections.len,
        analysis.info.frameworks.len,
    });

    analysis.diagnostics = try diagnostics.toOwnedSlice(result_allocator);
    log.info(@src(), "analysis completed diagnostics={d}", .{analysis.diagnostics.len});
    return analysis;
}

fn copyArchiveEntries(allocator: std.mem.Allocator, entries: []const zip.Entry) std.mem.Allocator.Error![]const model.ArchiveEntry {
    const copies = try allocator.alloc(model.ArchiveEntry, entries.len);
    for (entries, 0..) |entry, index| copies[index] = .{
        .name = try allocator.dupe(u8, entry.name),
        .method = @backingInt(entry.method),
        .flags = entry.flags,
        .crc32 = entry.crc32,
        .compressed_size = entry.compressed_size,
        .uncompressed_size = entry.uncompressed_size,
        .local_header_offset = entry.local_header_offset,
        .central_header_offset = entry.central_header_offset,
        .is_directory = entry.isDirectory(),
    };
    return copies;
}

/// The resource locale of one analysis: the requested tag (the analyzer's
/// `locale` option, or the run's UI locale when it is left empty), or none,
/// which selects Android's default resources.
///
/// The standalone analyzer fell back to the locale of the machine it ran on; a
/// plugin has no such fallback, because an analysis must not depend on the
/// examiner's own system.
fn resolveResourceLocale(explicit_locale: ?[]const u8) resource_config.Error!?resource_config.Locale {
    const locale = explicit_locale orelse {
        log.info(@src(), "resource locale selected source=default", .{});
        return null;
    };
    if (locale.len == 0) return null;
    const parsed = try resource_config.Locale.parse(locale);
    log.info(@src(), "resource locale selected source=explicit locale={s}", .{locale});
    return parsed;
}

test "explicit resource locale takes precedence" {
    const locale = (try resolveResourceLocale("zh-CN")).?;
    try std.testing.expectEqualStrings("zh", locale.languageSlice());
    try std.testing.expectEqualStrings("CN", locale.regionSlice());
    try std.testing.expectEqual(null, try resolveResourceLocale(null));
    try std.testing.expectEqual(null, try resolveResourceLocale(""));
}

fn populateArchiveInfo(
    output: *model.ArchiveInfo,
    entries: []const zip.Entry,
    limits: limits_mod.Limits,
) Error!void {
    var compressed: u64 = 0;
    var uncompressed: u64 = 0;
    for (entries) |entry| {
        compressed = std.math.add(u64, compressed, entry.compressed_size) catch
            return error.ArchiveSizeOverflow;
        uncompressed = std.math.add(u64, uncompressed, entry.uncompressed_size) catch
            return error.ArchiveSizeOverflow;
    }
    if (uncompressed > limits.max_total_uncompressed_size) {
        return error.DeclaredUncompressedSizeTooLarge;
    }
    output.* = .{
        .file_count = entries.len,
        .compressed_size = compressed,
        .uncompressed_size = uncompressed,
    };
}

fn findUniqueEntry(archive: *const zip.Archive, name: []const u8) Error!?*const zip.Entry {
    var found: ?*const zip.Entry = null;
    for (archive.entries, 0..) |entry, index| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (found != null) return error.DuplicateCriticalEntry;
        found = &archive.entries[index];
    }
    return found;
}

fn checkCompressionRatio(entry: *const zip.Entry, limits: limits_mod.Limits) Error!void {
    if (entry.uncompressed_size == 0) return;
    if (entry.compressed_size == 0) return error.CompressionRatioTooHigh;
    const ratio = entry.uncompressed_size / entry.compressed_size;
    if (ratio > limits.max_compression_ratio) return error.CompressionRatioTooHigh;
}

fn analyzeResources(
    scratch_allocator: std.mem.Allocator,
    result_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    info: *model.ApkInfo,
    selection: resource_resolver.Selection,
    limits: limits_mod.Limits,
) !void {
    const entry = (try findUniqueEntry(archive, "resources.arsc")) orelse {
        log.info(@src(), "resource table is absent", .{});
        return;
    };
    log.info(@src(), "resource table parsing started compressed_bytes={d} uncompressed_bytes={d}", .{ entry.compressed_size, entry.uncompressed_size });
    try checkCompressionRatio(entry, limits);
    const encoded = try archive.extractAlloc(
        scratch_allocator,
        entry,
        .{ .max_output_size = limits.max_entry_uncompressed_size },
    );
    defer scratch_allocator.free(encoded);

    var table = try resource_table.Table.parse(scratch_allocator, encoded);
    defer table.deinit();

    const packages = try result_allocator.alloc(model.ResourcePackage, table.packages.len);
    var value_count: usize = 0;
    for (table.packages, 0..) |package, package_index| {
        packages[package_index] = .{
            .id = package.id,
            .name = try result_allocator.dupe(u8, package.name),
        };
        for (package.types) |type_value| {
            for (type_value.entries) |maybe_entry| {
                if (maybe_entry != null) value_count = std.math.add(usize, value_count, 1) catch
                    return error.ArchiveSizeOverflow;
            }
        }
    }

    info.resources = .{
        .present = true,
        .packages = packages,
        .value_count = value_count,
    };
    try resolveManifestValues(result_allocator, &table, selection, info);
    icon.extractApplicationIcon(
        scratch_allocator,
        result_allocator,
        archive,
        &table,
        info,
        selection,
        limits,
    ) catch |err| {
        if (err == error.OutOfMemory) return err;
        log.warn(@src(), "application icon extraction failed error={s}", .{@errorName(err)});
    };
    log.info(@src(), "resource table parsed packages={d} values={d} resolved={d} unresolved={d} icon_bytes={d}", .{
        info.resources.packages.len,
        info.resources.value_count,
        info.resources.resolved_references,
        info.resources.unresolved_references,
        info.icon_bytes.len,
    });
}

fn resolveManifestValues(
    allocator: std.mem.Allocator,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    info: *model.ApkInfo,
) std.mem.Allocator.Error!void {
    try resolveValue(allocator, table, selection, &info.application_label, &info.resources);
    try resolveValue(allocator, table, selection, &info.application_icon, &info.resources);
    try resolveValue(allocator, table, selection, &info.application_round_icon, &info.resources);
    try resolveValue(allocator, table, selection, &info.version_name, &info.resources);

    const application_meta_data = @constCast(info.application_meta_data);
    for (application_meta_data) |*item| {
        try resolveValue(allocator, table, selection, &item.value, &info.resources);
    }

    const components = @constCast(info.components);
    for (components) |*component| {
        try resolveValue(allocator, table, selection, &component.label, &info.resources);
        try resolveValue(allocator, table, selection, &component.icon, &info.resources);
        const component_meta_data = @constCast(component.meta_data);
        for (component_meta_data) |*item| {
            try resolveValue(allocator, table, selection, &item.value, &info.resources);
        }
    }
}

fn resolveValue(
    allocator: std.mem.Allocator,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    value: *model.Value,
    statistics: *model.ResourceInfo,
) std.mem.Allocator.Error!void {
    if (value.kind != .reference or value.data == 0) return;
    const resolution = resource_resolver.resolve(table, value.data, selection) catch |err| {
        log.debug(@src(), "manifest resource value resolution failed resource_id=0x{x:0>8} error={s}", .{
            value.data,
            @errorName(err),
        });
        statistics.unresolved_references += 1;
        return;
    };
    const resolved = resolution.string_value orelse {
        statistics.unresolved_references += 1;
        return;
    };
    value.resolved = try allocator.dupe(u8, resolved);
    statistics.resolved_references += 1;
}

test "unique critical entry detection rejects ambiguity" {
    const entries = [_]zip.Entry{
        .{
            .name = "AndroidManifest.xml",
            .method = .store,
            .flags = 0,
            .crc32 = 0,
            .compressed_size = 0,
            .uncompressed_size = 0,
            .local_header_offset = 0,
            .central_header_offset = 0,
        },
        .{
            .name = "AndroidManifest.xml",
            .method = .store,
            .flags = 0,
            .crc32 = 0,
            .compressed_size = 0,
            .uncompressed_size = 0,
            .local_header_offset = 0,
            .central_header_offset = 0,
        },
    };
    const archive: zip.Archive = .{
        .allocator = std.testing.allocator,
        .data = &.{},
        .entries = @constCast(&entries),
    };
    try std.testing.expectError(
        error.DuplicateCriticalEntry,
        findUniqueEntry(&archive, "AndroidManifest.xml"),
    );
}
