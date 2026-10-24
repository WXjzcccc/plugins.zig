const std = @import("std");
const limits_mod = @import("../limits.zig");
const model = @import("../model.zig");
const zip = @import("../../utils/zip/archive.zig");
const axml = @import("axml_zig");
const resource_table = @import("../android/resources/table.zig");
const resource_resolver = @import("../android/resources/resolver.zig");
const logging = @import("../../utils/logging.zig");

const log = logging.scoped(.apk_analysis);

fn checkCompressionRatio(entry: *const zip.Entry, limits: limits_mod.Limits) error{CompressionRatioTooHigh}!void {
    if (entry.uncompressed_size > limits.max_entry_uncompressed_size) return error.CompressionRatioTooHigh;
    if (entry.compressed_size == 0) return error.CompressionRatioTooHigh;
    const ratio = entry.uncompressed_size / entry.compressed_size;
    if (ratio > limits.max_compression_ratio) return error.CompressionRatioTooHigh;
}

pub fn extractApplicationIcon(
    scratch_allocator: std.mem.Allocator,
    result_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    table: *const resource_table.Table,
    info: *model.ApkInfo,
    selection: resource_resolver.Selection,
    limits: limits_mod.Limits,
) !void {
    const icon_value = launcherIconValue(info) orelse if (info.application_round_icon.kind == .reference and info.application_round_icon.data != 0)
        &info.application_round_icon
    else
        &info.application_icon;
    if (icon_value.kind != .reference or icon_value.data == 0) return;
    log.debug(@src(), "application icon resource selected source={s} resource_id=0x{x:0>8}", .{
        if (launcherIconValue(info) != null)
            "launcherActivity"
        else if (icon_value == &info.application_round_icon)
            "roundIcon"
        else
            "icon",
        icon_value.data,
    });

    if (try findAdaptiveIconEntries(
        scratch_allocator,
        archive,
        table,
        selection,
        limits,
        icon_value.data,
    )) |entries| {
        info.icon_entry = try result_allocator.dupe(u8, entries.foreground.name);
        info.icon_bytes = try extractIconEntryBytes(
            scratch_allocator,
            result_allocator,
            archive,
            limits,
            entries.foreground,
        );
        info.icon_background_bytes = try extractIconEntryBytes(
            scratch_allocator,
            result_allocator,
            archive,
            limits,
            entries.background,
        );
        log.info(@src(), "adaptive icon layers extracted foreground={s} background={s}", .{
            entries.foreground.name,
            entries.background.name,
        });
        return;
    }

    var visited: [16]u32 = undefined;
    const entry = findIconResourceEntry(
        scratch_allocator,
        archive,
        table,
        selection,
        limits,
        icon_value.data,
        &visited,
        0,
    ) catch |err| {
        if (err == error.OutOfMemory) return err;
        log.warn(@src(), "icon resource lookup failed resource_id=0x{x:0>8} error={s}", .{
            icon_value.data,
            @errorName(err),
        });
        return;
    } orelse null;
    if (entry) |bitmap_entry| {
        try checkCompressionRatio(bitmap_entry, limits);

        const bytes = try archive.extractAlloc(
            scratch_allocator,
            bitmap_entry,
            .{ .max_output_size = @min(@as(u64, limits.max_entry_uncompressed_size), 4 * 1024 * 1024) },
        );
        defer scratch_allocator.free(bytes);
        info.icon_entry = try logicalResourcePath(result_allocator, table, selection, icon_value.data, bitmap_entry.name) orelse
            try result_allocator.dupe(u8, bitmap_entry.name);
        info.icon_bytes = try result_allocator.dupe(u8, bytes);
        return;
    }

    var vector_visited: [16]u32 = undefined;
    const svg = try findIconVectorSvg(
        scratch_allocator,
        archive,
        table,
        selection,
        limits,
        icon_value.data,
        &vector_visited,
        0,
    ) orelse return;
    defer scratch_allocator.free(svg);
    info.icon_svg = try result_allocator.dupe(u8, svg);
    log.info(@src(), "application icon vector extracted bytes={d}", .{info.icon_svg.len});
}

fn launcherIconValue(info: *const model.ApkInfo) ?*const model.Value {
    const launcher_activity = info.launcher_activity orelse return null;
    for (info.components) |*component| {
        if (!std.mem.eql(u8, component.name, launcher_activity)) continue;
        if (component.icon.kind == .reference and component.icon.data != 0) return &component.icon;
    }
    return null;
}

fn logicalResourcePath(
    allocator: std.mem.Allocator,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    resource_id: u32,
    physical_path: []const u8,
) std.mem.Allocator.Error!?[]const u8 {
    const match = resource_resolver.lookup(table, resource_id, selection) catch return null;
    const decoded = resource_table.ResourceId.fromInt(resource_id);
    const package = table.findPackage(decoded.package_id) orelse return null;
    const local_type_id = package.localTypeId(decoded.type_id) orelse return null;
    const entry_index: usize = decoded.entry_id;
    const extension_start = std.mem.lastIndexOfScalar(u8, physical_path, '.') orelse return null;
    const extension = physical_path[extension_start..];

    for (package.types) |type_value| {
        if (type_value.id != local_type_id or entry_index >= type_value.entries.len) continue;
        const entry = type_value.entries[entry_index] orelse continue;
        const value = switch (entry.value) {
            .simple => |simple| simple,
            .complex => continue,
        };
        const string_index = value.stringIndex() orelse continue;
        const path = table.global_strings.get(string_index) catch continue;
        if (!std.mem.eql(u8, path, physical_path)) continue;
        const directory = try logicalResourceDirectory(allocator, match.type_name, type_value.config.density);
        defer allocator.free(directory);
        const logical_path = try std.fmt.allocPrint(allocator, "res/{s}/{s}{s}", .{
            directory,
            match.key_name,
            extension,
        });
        log.debug(@src(), "resource path reconstructed physical={s} logical={s}", .{ physical_path, logical_path });
        return logical_path;
    }
    return null;
}

fn logicalResourceDirectory(allocator: std.mem.Allocator, type_name: []const u8, density: u16) std.mem.Allocator.Error![]const u8 {
    const qualifier: ?[]const u8 = switch (density) {
        0 => null,
        120 => "ldpi",
        160 => "mdpi",
        213 => "tvdpi",
        240 => "hdpi",
        320 => "xhdpi",
        480 => "xxhdpi",
        640 => "xxxhdpi",
        0xfffe => "anydpi",
        0xffff => "nodpi",
        else => return std.fmt.allocPrint(allocator, "{s}-{d}dpi", .{ type_name, density }),
    };
    if (qualifier) |value| return std.fmt.allocPrint(allocator, "{s}-{s}", .{ type_name, value });
    return allocator.dupe(u8, type_name);
}

const AdaptiveIconEntries = struct {
    background: *const zip.Entry,
    foreground: *const zip.Entry,
};

fn findAdaptiveIconEntries(
    scratch_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    limits: limits_mod.Limits,
    resource_id: u32,
) std.mem.Allocator.Error!?AdaptiveIconEntries {
    const resolution = resource_resolver.resolve(table, resource_id, selection) catch |err| {
        log.debug(@src(), "adaptive icon resource resolution failed resource_id=0x{x:0>8} error={s}", .{
            resource_id,
            @errorName(err),
        });
        return null;
    };
    const path = resolution.string_value orelse return null;
    const xml_entry = archive.findEntry(path) orelse return null;
    if (!isXmlPath(xml_entry.name)) return null;
    checkCompressionRatio(xml_entry, limits) catch |err| {
        log.warn(@src(), "adaptive icon XML compression ratio rejected entry={s} error={s}", .{
            xml_entry.name,
            @errorName(err),
        });
        return null;
    };
    const bytes = archive.extractAlloc(
        scratch_allocator,
        xml_entry,
        .{ .max_output_size = @min(@as(u64, limits.max_entry_uncompressed_size), 4 * 1024 * 1024) },
    ) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        log.warn(@src(), "adaptive icon XML extraction failed entry={s} error={s}", .{ xml_entry.name, @errorName(err) });
        return null;
    };
    defer scratch_allocator.free(bytes);

    var document = axml.Document.parse(scratch_allocator, bytes) catch |err| {
        log.warn(@src(), "adaptive icon XML parsing failed entry={s} error={s}", .{ xml_entry.name, @errorName(err) });
        return null;
    };
    defer document.deinit();

    var background: ?*const zip.Entry = null;
    var foreground: ?*const zip.Entry = null;
    var background_visited: [16]u32 = undefined;
    var foreground_visited: [16]u32 = undefined;
    for (document.events) |event| {
        const element = switch (event) {
            .start_element => |value| value,
            else => continue,
        };
        const target, const visited = if (std.mem.eql(u8, element.name, "background"))
            .{ &background, &background_visited }
        else if (std.mem.eql(u8, element.name, "foreground"))
            .{ &foreground, &foreground_visited }
        else
            continue;
        if (target.* != null) continue;
        target.* = try findIconResourceInElement(
            scratch_allocator,
            archive,
            table,
            selection,
            limits,
            element,
            null,
            visited,
            0,
        );
    }
    if (background) |background_entry| {
        if (foreground) |foreground_entry| {
            return .{ .background = background_entry, .foreground = foreground_entry };
        }
    }
    return null;
}

fn extractIconEntryBytes(
    scratch_allocator: std.mem.Allocator,
    result_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    limits: limits_mod.Limits,
    entry: *const zip.Entry,
) ![]const u8 {
    try checkCompressionRatio(entry, limits);
    const bytes = try archive.extractAlloc(
        scratch_allocator,
        entry,
        .{ .max_output_size = @min(@as(u64, limits.max_entry_uncompressed_size), 4 * 1024 * 1024) },
    );
    defer scratch_allocator.free(bytes);
    return result_allocator.dupe(u8, bytes);
}

fn findIconResourceEntry(
    scratch_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    limits: limits_mod.Limits,
    resource_id: u32,
    visited: *[16]u32,
    depth: usize,
) std.mem.Allocator.Error!?*const zip.Entry {
    if (resource_id == 0 or depth >= visited.len) return null;
    for (visited[0..depth]) |seen| if (seen == resource_id) return null;
    visited[depth] = resource_id;

    const resolution = resource_resolver.resolve(table, resource_id, selection) catch |err| {
        log.debug(@src(), "icon resource resolution failed resource_id=0x{x:0>8} error={s}", .{
            resource_id,
            @errorName(err),
        });
        return null;
    };
    log.debug(@src(), "icon resource resolved resource_id=0x{x:0>8} type={s} name={s} path={?s} value_type=0x{x:0>2} value_data=0x{x:0>8} depth={d}", .{
        resource_id,
        resolution.match.type_name,
        resolution.match.key_name,
        resolution.string_value,
        if (resolution.value) |value| @backingInt(value.data_type) else 0xff,
        if (resolution.value) |value| value.data else 0,
        depth,
    });
    if (resolution.string_value) |path| {
        if (try findIconResourceAtPath(scratch_allocator, archive, table, selection, limits, path, visited, depth)) |entry| return entry;
    } else switch (resolution.match.entry.value) {
        .complex => |bag| {
            log.debug(@src(), "icon complex resource expanding resource_id=0x{x:0>8} maps={d}", .{ resource_id, bag.maps.len });
            for (bag.maps) |map| {
                if (map.value.referenceId()) |reference| {
                    if (try findIconResourceEntry(
                        scratch_allocator,
                        archive,
                        table,
                        selection,
                        limits,
                        reference,
                        visited,
                        depth + 1,
                    )) |entry| return entry;
                    continue;
                }
                const string_index = map.value.stringIndex() orelse continue;
                const path = table.global_strings.get(string_index) catch |err| {
                    log.warn(@src(), "icon complex resource string lookup failed resource_id=0x{x:0>8} map=0x{x:0>8} index={d} error={s}", .{
                        resource_id,
                        map.name,
                        string_index,
                        @errorName(err),
                    });
                    continue;
                };
                if (try findIconResourceAtPath(scratch_allocator, archive, table, selection, limits, path, visited, depth)) |entry| return entry;
            }
        },
        .simple => {},
    }

    if (try findIconResourceInAlternativeConfigs(
        scratch_allocator,
        archive,
        table,
        selection,
        limits,
        resource_id,
        visited,
        depth,
    )) |entry| return entry;

    for (archive.entries, 0..) |entry, index| {
        if (!isSupportedIconPath(entry.name)) continue;
        if (!iconNameMatches(entry.name, resolution.match.type_name, resolution.match.key_name)) continue;
        return &archive.entries[index];
    }
    return null;
}

fn findIconResourceInAlternativeConfigs(
    scratch_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    limits: limits_mod.Limits,
    resource_id: u32,
    visited: *[16]u32,
    depth: usize,
) std.mem.Allocator.Error!?*const zip.Entry {
    const decoded = resource_table.ResourceId.fromInt(resource_id);
    const package = table.findPackage(decoded.package_id) orelse return null;
    const local_type_id = package.localTypeId(decoded.type_id) orelse return null;
    const entry_index: usize = decoded.entry_id;
    var best: ?struct { path: []const u8, density: u16, priority: u16 } = null;

    for (package.types) |type_value| {
        if (type_value.id != local_type_id or entry_index >= type_value.entries.len) continue;
        const entry = type_value.entries[entry_index] orelse continue;
        const value = switch (entry.value) {
            .simple => |simple| simple,
            .complex => continue,
        };
        if (value.stringIndex()) |string_index| {
            const path = table.global_strings.get(string_index) catch |err| {
                log.warn(@src(), "icon alternative configuration string lookup failed resource_id=0x{x:0>8} index={d} error={s}", .{
                    resource_id,
                    string_index,
                    @errorName(err),
                });
                continue;
            };
            const archive_entry = archive.findEntry(path) orelse continue;
            if (!isSupportedIconPath(archive_entry.name) and !isXmlPath(archive_entry.name)) continue;
            const density = type_value.config.density;
            const priority = iconDensityPriority(density);
            if (best == null or priority > best.?.priority) {
                best = .{ .path = path, .density = density, .priority = priority };
            }
            continue;
        }
        if (value.referenceId()) |reference| {
            if (try findIconResourceEntry(
                scratch_allocator,
                archive,
                table,
                selection,
                limits,
                reference,
                visited,
                depth + 1,
            )) |icon_entry| return icon_entry;
        }
    }
    if (best) |candidate| {
        if (try findIconResourceAtPath(scratch_allocator, archive, table, selection, limits, candidate.path, visited, depth)) |icon_entry| {
            log.info(@src(), "icon alternative configuration selected resource_id=0x{x:0>8} density={d} preference=highest_density path={s}", .{
                resource_id,
                candidate.density,
                candidate.path,
            });
            return icon_entry;
        }
    }
    return null;
}

fn iconDensityPriority(density: u16) u16 {
    return switch (density) {
        0, 0xfffe, 0xffff => 0,
        else => density,
    };
}

fn findIconResourceAtPath(
    scratch_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    limits: limits_mod.Limits,
    path: []const u8,
    visited: *[16]u32,
    depth: usize,
) std.mem.Allocator.Error!?*const zip.Entry {
    const entry = archive.findEntry(path) orelse return null;
    if (isSupportedIconPath(entry.name)) return entry;
    if (!isXmlPath(entry.name)) return null;
    return findIconResourceInXml(
        scratch_allocator,
        archive,
        table,
        selection,
        limits,
        entry,
        visited,
        depth + 1,
    );
}

fn findIconResourceInXml(
    scratch_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    limits: limits_mod.Limits,
    xml_entry: *const zip.Entry,
    visited: *[16]u32,
    depth: usize,
) std.mem.Allocator.Error!?*const zip.Entry {
    checkCompressionRatio(xml_entry, limits) catch |err| {
        log.warn(@src(), "icon XML compression ratio rejected entry={s} error={s}", .{
            xml_entry.name,
            @errorName(err),
        });
        return null;
    };
    const bytes = archive.extractAlloc(
        scratch_allocator,
        xml_entry,
        .{ .max_output_size = @min(@as(u64, limits.max_entry_uncompressed_size), 4 * 1024 * 1024) },
    ) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        log.warn(@src(), "icon XML extraction failed entry={s} error={s}", .{
            xml_entry.name,
            @errorName(err),
        });
        return null;
    };
    defer scratch_allocator.free(bytes);

    var document = axml.Document.parse(scratch_allocator, bytes) catch |err| {
        log.warn(@src(), "icon XML parsing failed entry={s} error={s}", .{
            xml_entry.name,
            @errorName(err),
        });
        return null;
    };
    defer document.deinit();

    for (document.events) |event| {
        const element = switch (event) {
            .start_element => |value| value,
            else => continue,
        };
        for (element.attributes) |attribute| {
            log.debug(@src(), "icon XML attribute entry={s} element={s} name={s} type=0x{x:0>2} data=0x{x:0>8} raw={?s} reference=0x{x:0>8}", .{
                xml_entry.name,
                element.name,
                attribute.name,
                @backingInt(attribute.value.data_type),
                attribute.value.data,
                attribute.raw_value,
                attribute.value.referenceId() orelse 0,
            });
        }
    }

    // Adaptive icons keep their artwork in a foreground element and the solid
    // backing layer often appears first in the document.
    for (document.events) |event| {
        const element = switch (event) {
            .start_element => |value| value,
            else => continue,
        };
        if (!std.mem.eql(u8, element.name, "foreground")) continue;
        if (try findIconResourceInElement(
            scratch_allocator,
            archive,
            table,
            selection,
            limits,
            element,
            null,
            visited,
            depth,
        )) |entry| {
            log.info(@src(), "icon foreground selected XML entry={s} resource={s}", .{ xml_entry.name, entry.name });
            return entry;
        }
    }

    const preferred_attributes = [_][]const u8{ "src", "drawable", "icon" };
    for (preferred_attributes) |name| {
        for (document.events) |event| {
            const element = switch (event) {
                .start_element => |value| value,
                else => continue,
            };
            if (std.mem.eql(u8, element.name, "background")) continue;
            for (element.attributes) |attribute| {
                if (!std.mem.eql(u8, attribute.name, name)) continue;
                if (try findIconResourceInElement(
                    scratch_allocator,
                    archive,
                    table,
                    selection,
                    limits,
                    element,
                    name,
                    visited,
                    depth,
                )) |entry| return entry;
            }
        }
    }

    for (document.events) |event| {
        const element = switch (event) {
            .start_element => |value| value,
            else => continue,
        };
        if (try findIconResourceInElement(
            scratch_allocator,
            archive,
            table,
            selection,
            limits,
            element,
            null,
            visited,
            depth,
        )) |entry| return entry;
    }
    return null;
}

fn findIconResourceInElement(
    scratch_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    limits: limits_mod.Limits,
    element: axml.StartElement,
    attribute_name: ?[]const u8,
    visited: *[16]u32,
    depth: usize,
) std.mem.Allocator.Error!?*const zip.Entry {
    for (element.attributes) |attribute| {
        if (attribute_name) |name| {
            if (!std.mem.eql(u8, attribute.name, name)) continue;
        }
        const reference = attribute.value.referenceId() orelse continue;
        if (try findIconResourceEntry(
            scratch_allocator,
            archive,
            table,
            selection,
            limits,
            reference,
            visited,
            depth,
        )) |entry| return entry;
    }
    return null;
}

fn iconNameMatches(path: []const u8, type_name: []const u8, key_name: []const u8) bool {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return false;
    const directory = path[0..slash];
    const separator = std.mem.lastIndexOfScalar(u8, directory, '/') orelse return false;
    const directory_name = directory[separator + 1 ..];
    if (!std.mem.startsWith(u8, directory_name, type_name)) return false;

    const filename = path[slash + 1 ..];
    const dot = std.mem.lastIndexOfScalar(u8, filename, '.') orelse return false;
    return std.mem.eql(u8, filename[0..dot], key_name);
}

fn isSupportedIconPath(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".png") or
        std.mem.endsWith(u8, path, ".webp") or
        std.mem.endsWith(u8, path, ".jpg") or
        std.mem.endsWith(u8, path, ".jpeg");
}

fn isXmlPath(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".xml");
}

fn findIconVectorSvg(
    scratch_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    limits: limits_mod.Limits,
    resource_id: u32,
    visited: *[16]u32,
    depth: usize,
) std.mem.Allocator.Error!?[]u8 {
    if (resource_id == 0 or depth >= visited.len) return null;
    for (visited[0..depth]) |seen| if (seen == resource_id) return null;
    visited[depth] = resource_id;

    const resolution = resource_resolver.resolve(table, resource_id, selection) catch |err| {
        log.debug(@src(), "icon vector resource resolution failed resource_id=0x{x:0>8} error={s}", .{
            resource_id,
            @errorName(err),
        });
        return null;
    };
    const path = resolution.string_value orelse return null;
    const entry = archive.findEntry(path) orelse return null;
    if (!isXmlPath(entry.name)) return null;
    return findIconVectorSvgInXml(scratch_allocator, archive, table, selection, limits, entry, visited, depth + 1);
}

fn findIconVectorSvgInXml(
    scratch_allocator: std.mem.Allocator,
    archive: *const zip.Archive,
    table: *const resource_table.Table,
    selection: resource_resolver.Selection,
    limits: limits_mod.Limits,
    xml_entry: *const zip.Entry,
    visited: *[16]u32,
    depth: usize,
) std.mem.Allocator.Error!?[]u8 {
    checkCompressionRatio(xml_entry, limits) catch |err| {
        log.warn(@src(), "icon vector XML compression ratio rejected entry={s} error={s}", .{ xml_entry.name, @errorName(err) });
        return null;
    };
    const bytes = archive.extractAlloc(
        scratch_allocator,
        xml_entry,
        .{ .max_output_size = @min(@as(u64, limits.max_entry_uncompressed_size), 4 * 1024 * 1024) },
    ) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        log.warn(@src(), "icon vector XML extraction failed entry={s} error={s}", .{ xml_entry.name, @errorName(err) });
        return null;
    };
    defer scratch_allocator.free(bytes);

    var document = axml.Document.parse(scratch_allocator, bytes) catch |err| {
        log.warn(@src(), "icon vector XML parsing failed entry={s} error={s}", .{ xml_entry.name, @errorName(err) });
        return null;
    };
    defer document.deinit();

    if (androidVectorToSvg(scratch_allocator, document.events)) |svg| return svg;

    var background: ?[]u8 = null;
    var foreground: ?[]u8 = null;
    for (document.events) |event| {
        const element = switch (event) {
            .start_element => |value| value,
            else => continue,
        };
        const target = if (std.mem.eql(u8, element.name, "foreground"))
            &foreground
        else if (std.mem.eql(u8, element.name, "background"))
            &background
        else
            continue;
        for (element.attributes) |attribute| {
            const reference = attribute.value.referenceId() orelse continue;
            target.* = try findIconVectorSvg(scratch_allocator, archive, table, selection, limits, reference, visited, depth);
            if (target.* != null) break;
        }
    }
    if (foreground) |foreground_svg| {
        if (background) |background_svg| {
            const merged = mergeAdaptiveIconSvg(scratch_allocator, background_svg, foreground_svg);
            scratch_allocator.free(background_svg);
            scratch_allocator.free(foreground_svg);
            return merged;
        }
        return foreground_svg;
    }
    if (background) |background_svg| return background_svg;
    for (document.events) |event| {
        const element = switch (event) {
            .start_element => |value| value,
            else => continue,
        };
        for (element.attributes) |attribute| {
            if (attribute.value.referenceId()) |reference| {
                if (try findIconVectorSvg(scratch_allocator, archive, table, selection, limits, reference, visited, depth)) |svg| return svg;
            }
        }
    }
    return null;
}

fn mergeAdaptiveIconSvg(allocator: std.mem.Allocator, background: []const u8, foreground: []const u8) ?[]u8 {
    const background_header_end = std.mem.indexOfScalar(u8, background, '>') orelse return null;
    const foreground_header_end = std.mem.indexOfScalar(u8, foreground, '>') orelse return null;
    const background_footer_start = std.mem.lastIndexOf(u8, background, "</svg>") orelse return null;
    const foreground_footer_start = std.mem.lastIndexOf(u8, foreground, "</svg>") orelse return null;
    var merged: std.ArrayList(u8) = .empty;
    merged.appendSlice(allocator, background[0 .. background_header_end + 1]) catch return null;
    merged.appendSlice(allocator, background[background_header_end + 1 .. background_footer_start]) catch {
        merged.deinit(allocator);
        return null;
    };
    merged.appendSlice(allocator, foreground[foreground_header_end + 1 .. foreground_footer_start]) catch {
        merged.deinit(allocator);
        return null;
    };
    merged.appendSlice(allocator, "</svg>") catch {
        merged.deinit(allocator);
        return null;
    };
    return merged.toOwnedSlice(allocator) catch null;
}

fn androidVectorToSvg(allocator: std.mem.Allocator, events: []const axml.Event) ?[]u8 {
    const root = for (events) |event| switch (event) {
        .start_element => |element| if (std.mem.eql(u8, element.name, "vector")) break element,
        else => {},
    } else return null;
    const viewport_width = vectorNumberAttribute(root, "viewportWidth") orelse return null;
    const viewport_height = vectorNumberAttribute(root, "viewportHeight") orelse return null;
    if (!(viewport_width > 0) or !(viewport_height > 0)) return null;

    var output: std.ArrayList(u8) = .empty;
    var format_buffer: [128]u8 = undefined;
    const header = std.fmt.bufPrint(&format_buffer, "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {d} {d}\">", .{ viewport_width, viewport_height }) catch return null;
    output.appendSlice(allocator, header) catch return null;
    var path_count: usize = 0;
    for (events) |event| {
        const element = switch (event) {
            .start_element => |value| value,
            else => continue,
        };
        if (!std.mem.eql(u8, element.name, "path")) continue;
        const path_data = vectorStringAttribute(element, "pathData") orelse continue;
        const color = vectorColorAttribute(element, "fillColor") orelse continue;
        const path_start = std.fmt.bufPrint(&format_buffer, "<path d=\"", .{}) catch {
            output.deinit(allocator);
            return null;
        };
        output.appendSlice(allocator, path_start) catch {
            output.deinit(allocator);
            return null;
        };
        output.appendSlice(allocator, path_data) catch {
            output.deinit(allocator);
            return null;
        };
        const path_fill = std.fmt.bufPrint(&format_buffer, "\" fill=\"#{x:0>6}\"", .{color & 0x00ff_ffff}) catch {
            output.deinit(allocator);
            return null;
        };
        output.appendSlice(allocator, path_fill) catch {
            output.deinit(allocator);
            return null;
        };
        const alpha: u8 = @truncate(color >> 24);
        if (alpha != 255) {
            const opacity = std.fmt.bufPrint(&format_buffer, " fill-opacity=\"{d}\"", .{@as(f32, @floatFromInt(alpha)) / 255.0}) catch {
                output.deinit(allocator);
                return null;
            };
            output.appendSlice(allocator, opacity) catch {
                output.deinit(allocator);
                return null;
            };
        }
        output.appendSlice(allocator, "/>") catch {
            output.deinit(allocator);
            return null;
        };
        path_count += 1;
    }
    if (path_count == 0) {
        output.deinit(allocator);
        return null;
    }
    output.appendSlice(allocator, "</svg>") catch {
        output.deinit(allocator);
        return null;
    };
    return output.toOwnedSlice(allocator) catch null;
}

fn vectorStringAttribute(element: axml.StartElement, name: []const u8) ?[]const u8 {
    for (element.attributes) |attribute| {
        if (!std.mem.eql(u8, attribute.name, name)) continue;
        return attribute.raw_value orelse attribute.value_string;
    }
    return null;
}

fn vectorNumberAttribute(element: axml.StartElement, name: []const u8) ?f32 {
    for (element.attributes) |attribute| {
        if (!std.mem.eql(u8, attribute.name, name)) continue;
        return switch (attribute.value.data_type) {
            .float_value => @bitCast(attribute.value.data),
            .int_decimal, .int_hexadecimal => @floatFromInt(@as(i32, @bitCast(attribute.value.data))),
            else => if (attribute.raw_value orelse attribute.value_string) |value| std.fmt.parseFloat(f32, value) catch null else null,
        };
    }
    return null;
}

fn vectorColorAttribute(element: axml.StartElement, name: []const u8) ?u32 {
    for (element.attributes) |attribute| {
        if (!std.mem.eql(u8, attribute.name, name)) continue;
        return switch (attribute.value.data_type) {
            .color_argb8 => attribute.value.data,
            .color_rgb8 => 0xff00_0000 | attribute.value.data,
            else => null,
        };
    }
    return null;
}
