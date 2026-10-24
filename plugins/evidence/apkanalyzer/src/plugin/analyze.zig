//! One APK, from evidence bytes to records.
//!
//! The parser core (src/core, src/utils) works on an in-memory buffer, so this
//! module owns the two things around it: reading the file through the run's
//! read-only handle, and turning the parsed model into the records of
//! records.zig. Both analyzers (evidence scope and files scope) share it.
//!
//! Memory: the run's arena lives for the whole run, so a large APK is not read
//! through it. The buffer and the analysis arena use libc's allocator and are
//! released after every package, which keeps a run over thousands of APKs to
//! one package at a time.

const std = @import("std");

const lc = @import("lovelycarve");
const engine = @import("../core/analysis/engine.zig");
const limits_mod = @import("../core/limits.zig");
const model = @import("../core/model.zig");
const conversion = @import("conversion.zig");
const records = @import("records.zig");

/// The buffer allocator of one package: libc, so it is independent of the
/// run's arena and can be released between packages.
const package_allocator = std.heap.c_allocator;

/// Largest package read unless the run asks for more.
///
/// The parser holds the whole APK in memory and unpacks single entries on top
/// of that, while plugin.toml caps the process at 2 GiB; half of that keeps a
/// package plus its scratch buffers inside the limit. The parser's own ceiling
/// (2 GiB) stays the hard limit, so the max_size option can only lower this.
pub const DEFAULT_MAX_SIZE: u64 = 1024 * 1024 * 1024;

/// What one run should emit (the analyzer's items option).
pub const Items = struct {
    info: bool = true,
    components: bool = true,
    permissions: bool = true,
    features: bool = true,
    metadata: bool = true,
    signing: bool = true,
    detections: bool = true,
    entries: bool = false,
    diagnostics: bool = true,
    icon: bool = true,

    pub const all = Items{};

    /// Reads the items multi-choice option (an absent or empty selection means
    /// every group) and the separate entries flag, which is off unless asked for:
    /// a package can hold a quarter of a million entries.
    pub fn fromOptions(options: lc.Options) Items {
        return .{
            .info = options.wants("items", "info"),
            .components = options.wants("items", "components"),
            .permissions = options.wants("items", "permissions"),
            .features = options.wants("items", "features"),
            .metadata = options.wants("items", "metadata"),
            .signing = options.wants("items", "signing"),
            .detections = options.wants("items", "detections"),
            .entries = options.flag("entries"),
            .diagnostics = options.wants("items", "diagnostics"),
            .icon = options.wants("items", "icon"),
        };
    }
};

/// The parser settings of one run.
pub const Settings = struct {
    items: Items = .all,
    locale: ?[]const u8 = null,
    density: ?u16 = null,
    /// Largest package read, in bytes.
    max_size: u64 = DEFAULT_MAX_SIZE,

    pub fn fromOptions(options: lc.Options) Settings {
        var settings = Settings{ .items = Items.fromOptions(options) };
        if (options.text("locale")) |locale| {
            if (locale.len != 0) settings.locale = locale;
        }
        if (options.text("density")) |density| {
            settings.density = std.fmt.parseInt(u16, std.mem.trim(u8, density, " \t"), 10) catch null;
        }
        if (options.text("max_size")) |megabytes| {
            const trimmed = std.mem.trim(u8, megabytes, " \t");
            if (trimmed.len != 0) {
                const parsed = std.fmt.parseInt(u64, trimmed, 10) catch 0;
                if (parsed != 0) settings.max_size = @min(
                    parsed * 1024 * 1024,
                    limits_mod.Limits.defaults.max_apk_size,
                );
            }
        }
        return settings;
    }
};

/// Why one package could not be analyzed.
pub const Failure = struct {
    code: []const u8,
    message: []const u8,
};

/// The display path of a file: its path inside the run's view, else the path
/// inside its volume, else its name.
pub fn displayPath(file: lc.FileRef) []const u8 {
    return file.viewPath() orelse file.rootPath() orelse file.name();
}

/// Reads the whole file into a libc-owned buffer.
///
/// FileRef.readAll would allocate from the run's arena, which outlives the
/// package; this copies each host chunk into alloc instead, so the caller can
/// free the buffer as soon as the package is done.
fn readWhole(file: lc.FileRef, alloc: std.mem.Allocator, cap: u64) ![]u8 {
    const size = file.size();
    if (size > cap) return error.TooLarge;
    const length = std.math.cast(usize, size) orelse return error.TooLarge;
    const buffer = try alloc.alloc(u8, length);
    errdefer alloc.free(buffer);

    var position: usize = 0;
    while (position < length) {
        const want: u64 = @min(length - position, lc.MAX_HOST_READ);
        const reply = try file.context().callHost(lc.protocol.method.file_read, try lc.value.map(
            file.context().arena,
            &.{
                lc.value.entry("file_id", lc.value.str(file.id())),
                lc.value.entry("offset", lc.value.uint(position)),
                lc.value.entry("length", lc.value.uint(want)),
            },
        ));
        const chunk = try lc.value.intoBytes(reply, lc.protocol.method.file_read);
        if (chunk.len == 0 or chunk.len > want) return error.ShortRead;
        @memcpy(buffer[position..][0..chunk.len], chunk);
        position += chunk.len;
    }
    return buffer;
}

/// Analyzes one file and emits its records. Returns null on success, or the
/// failure the caller should report as a run warning.
pub fn analyzeFile(
    run: *const lc.Run,
    file: lc.FileRef,
    settings: Settings,
) lc.Error!?Failure {
    const path = displayPath(file);
    if (file.size() == 0) {
        return .{ .code = "APK_EMPTY", .message = try message(run, "{s} is empty", .{path}) };
    }
    if (file.size() > settings.max_size) {
        return .{ .code = "APK_TOO_LARGE", .message = try message(
            run,
            "{s} is {d} bytes; the limit is {d}",
            .{ path, file.size(), settings.max_size },
        ) };
    }

    const data = readWhole(file, package_allocator, settings.max_size) catch |err| {
        return .{ .code = "APK_READ_FAILED", .message = try message(
            run,
            "reading {s} failed: {s}",
            .{ path, @errorName(err) },
        ) };
    };
    defer package_allocator.free(data);

    var analysis = engine.analyzeBytes(package_allocator, data, .{
        .limits = .defaults,
        .locale = settings.locale,
        .density = settings.density,
        .parse_resources = settings.items.info or settings.items.signing or settings.items.icon,
        .parse_signatures = settings.items.signing,
        .retain_entries = settings.items.entries,
    }) catch |err| {
        return .{ .code = analysisErrorCode(err), .message = try message(
            run,
            "analyzing {s} failed: {s}",
            .{ path, @errorName(err) },
        ) };
    };
    defer analysis.deinit();

    // Record identity is the package name; a package whose manifest did not
    // carry one falls back to its file name so rows stay distinguishable.
    const package_name = analysis.info.package_name orelse std.fs.path.basename(path);

    // The record values of this package live in a scratch arena: a run over a
    // whole evidence item would otherwise keep every value of every package
    // until the run ends. Emitted records are already encoded by then.
    var scratch_state = std.heap.ArenaAllocator.init(package_allocator);
    defer scratch_state.deinit();
    try emitAll(run, file, package_name, &analysis, settings.items, scratch_state.allocator());
    return null;
}

fn analysisErrorCode(err: anyerror) []const u8 {
    return switch (err) {
        error.MissingManifest => "APK_NO_MANIFEST",
        error.ApkTooLarge => "APK_TOO_LARGE",
        error.TooManyArchiveEntries => "APK_TOO_MANY_ENTRIES",
        error.DeclaredUncompressedSizeTooLarge => "APK_EXPANSION_TOO_LARGE",
        error.CompressionRatioTooHigh => "APK_COMPRESSION_RATIO",
        error.DuplicateCriticalEntry => "APK_DUPLICATE_ENTRY",
        error.InvalidLocale => "APK_INVALID_LOCALE",
        error.OutOfMemory => "OUT_OF_MEMORY",
        else => "APK_PARSE_FAILED",
    };
}

/// Formats a warning message in the run's arena (warnings are stored with the
/// run, so they must outlive this call).
fn message(run: *const lc.Run, comptime format: []const u8, args: anytype) lc.Error![]const u8 {
    return std.fmt.allocPrint(run.context().arena, format, args);
}

/// Emits every record group of one analyzed package.
fn emitAll(
    run: *const lc.Run,
    file: lc.FileRef,
    package_name: []const u8,
    analysis: *const model.Analysis,
    items: Items,
    alloc: std.mem.Allocator,
) lc.Error!void {
    const info = &analysis.info;

    if (items.info) {
        const values = try conversion.infoValues(alloc, package_name, analysis);
        try run.record(records.INFO_TYPE, values).from(&file).emit();
    }

    if (items.components) {
        for (info.components) |component| {
            const values = try conversion.componentValues(alloc, package_name, component);
            try run.record(records.COMPONENT_TYPE, values).from(&file).emit();
        }
    }

    if (items.permissions) {
        for (info.permissions) |permission| {
            const values = try conversion.permissionValues(alloc, package_name, permission);
            var record = run.record(records.PERMISSION_TYPE, values).from(&file);
            if (permission.risk == .dangerous) record = record.severity(.high);
            try record.emit();
        }
    }

    if (items.features) {
        for (info.features) |feature| {
            const values = try conversion.featureValues(alloc, package_name, feature);
            try run.record(records.FEATURE_TYPE, values).from(&file).emit();
        }
    }

    if (items.metadata) {
        for (info.application_meta_data) |item| {
            const values = try conversion.metadataValues(alloc, package_name, item);
            try run.record(records.METADATA_TYPE, values).from(&file).emit();
        }
    }

    if (items.signing) {
        for (info.signing.signers) |signer| {
            const values = try conversion.signerValues(alloc, package_name, signer);
            try run.record(records.SIGNER_TYPE, values).from(&file).emit();
            for (signer.certificates) |certificate| {
                const cert_values = try conversion.certificateValues(alloc, package_name, signer.scheme, certificate);
                try run.record(records.CERTIFICATE_TYPE, cert_values).from(&file).emit();
            }
        }
    }

    if (items.detections) {
        for (info.protections) |detection| {
            const values = try conversion.detectionValues(alloc, package_name, "protection", detection);
            try run.record(records.DETECTION_TYPE, values).from(&file).emit();
        }
        for (info.frameworks) |detection| {
            const values = try conversion.detectionValues(alloc, package_name, "framework", detection);
            try run.record(records.DETECTION_TYPE, values).from(&file).emit();
        }
    }

    if (items.entries) {
        for (info.archive.entries) |entry| {
            const values = try conversion.entryValues(alloc, package_name, entry);
            try run.record(records.ENTRY_TYPE, values).from(&file).emit();
        }
    }

    if (items.icon) {
        if (info.icon_bytes.len != 0 or info.icon_svg.len != 0) {
            const values = try conversion.iconValues(alloc, package_name, analysis);
            try run.record(records.ICON_TYPE, values).from(&file).emit();
        }
    }

    if (items.diagnostics) {
        for (analysis.diagnostics) |diagnostic| {
            const values = try conversion.diagnosticValues(alloc, package_name, diagnostic);
            try run.record(records.DIAGNOSTIC_TYPE, values).from(&file).emit();
        }
    }
}

const testing = std.testing;

test "settings read the option values the host sends" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const none = Settings.fromOptions(lc.Options.init(.nil));
    try testing.expect(none.items.info);
    try testing.expect(none.items.signing);
    try testing.expect(!none.items.entries);
    try testing.expect(none.items.metadata);
    try testing.expectEqual(null, none.locale);

    const values = try lc.value.map(alloc, &.{
        lc.value.entry("items", try lc.value.array(alloc, &.{ lc.value.str("info"), lc.value.str("entries") })),
        lc.value.entry("locale", lc.value.str("zh-CN")),
        lc.value.entry("density", lc.value.str("480")),
        lc.value.entry("max_size", lc.value.str("128")),
        lc.value.entry("entries", lc.value.boolean(true)),
    });
    const settings = Settings.fromOptions(lc.Options.init(values));
    try testing.expect(settings.items.info);
    try testing.expect(settings.items.entries);
    try testing.expect(!settings.items.components);
    try testing.expectEqualStrings("zh-CN", settings.locale.?);
    try testing.expectEqual(@as(u16, 480), settings.density.?);
    try testing.expectEqual(@as(u64, 128 * 1024 * 1024), settings.max_size);
}

test "a blank max_size keeps the parser limit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const values = try lc.value.map(alloc, &.{
        lc.value.entry("max_size", lc.value.str("  ")),
        lc.value.entry("density", lc.value.str("not-a-number")),
    });
    const settings = Settings.fromOptions(lc.Options.init(values));
    try testing.expectEqual(DEFAULT_MAX_SIZE, settings.max_size);
    try testing.expect(DEFAULT_MAX_SIZE < limits_mod.Limits.defaults.max_apk_size);
    try testing.expectEqual(null, settings.density);
}
