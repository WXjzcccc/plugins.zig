//! Stages a plugin package directory and packs it into an installable
//! `.lcpkg` — a ZIP archive of that directory with `plugin.toml` at the root.
//!
//!   zig build package
//!
//! or directly, from the plugin directory:
//!
//!   zig run scripts/pack.zig -- \
//!       --out dist \
//!       --platform windows-x64 \
//!       --plugin plugin.toml \
//!       --library zig-out/lib/zigtemplate.dll \
//!       --schema zig-out/schema.json \
//!       [--readme README.md] [--locales locales]
//!
//! It writes two things under `--out`:
//!
//!   <id>-<version>-<platform>/          the staged package directory
//!   <id>-<version>-<platform>.lcpkg     the archive of that directory
//!
//! The staged directory holds `plugin.toml`, the library under the platform
//! file name the manifest resolves to, `schema.json`, an optional `README.md`
//! and `locales/`, `build.json` (provenance) and `SHA256SUMS.txt` (one
//! `<hex>  <relative path>` line per file, sorted).
//!
//! The ZIP writer is built in: STORED entries (method 0) with a CRC-32, so no
//! external tool and no third-party dependency is involved. STORED keeps the
//! library bytes untouched and the archive trivially inspectable.

const std = @import("std");

/// Files that describe the package instead of being part of it; written last
/// so the checksum file never lists itself.
const BUILD_INFO = "build.json";
const CHECKSUMS = "SHA256SUMS.txt";

const usage =
    \\usage: pack --out <dir> --platform <tag> --plugin <plugin.toml>
    \\            --library <library> --schema <schema.json>
    \\            [--readme <README.md>] [--locales <dir>]
    \\
    \\  --out       directory for the staged package and the .lcpkg archive
    \\  --platform  windows-x64 | linux-x64 | linux-arm64 | macos-x64 | macos-arm64
    \\  --plugin    the package manifest
    \\  --library   the built plugin library
    \\  --schema    schema.json produced from that library
    \\  --readme    optional package guide, shipped as README.md
    \\  --locales   optional locales/ directory
    \\
;

pub fn main(init: std.process.Init) !void {
    const alloc = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();

    const arguments = parseArguments(try init.minimal.args.toSlice(arena)) catch |err| {
        std.debug.print("pack: {t}\n\n{s}", .{ err, usage });
        std.process.exit(2);
    };
    pack(alloc, io, arguments) catch |err| {
        std.debug.print("pack: {s}: {t}\n", .{ arguments.plugin, err });
        std.process.exit(1);
    };
}

const Arguments = struct {
    /// Directory the staged package and the archive go to (zig-out).
    out: []const u8 = "zig-out",
    /// Package platform tag (windows-x64, linux-x64, linux-arm64, macos-x64,
    /// macos-arm64).
    platform: []const u8 = "",
    plugin: []const u8 = "",
    library: []const u8 = "",
    schema: []const u8 = "",
    /// Optional package guide, shipped as README.md.
    readme: ?[]const u8 = null,
    /// Optional translations directory.
    locales: ?[]const u8 = null,
};

fn parseArguments(argv: []const [:0]const u8) !Arguments {
    var parsed = Arguments{};
    var index: usize = 1;
    while (index < argv.len) : (index += 1) {
        const flag = argv[index];
        index += 1;
        if (index >= argv.len) return error.MissingValue;
        const value = argv[index];
        if (std.mem.eql(u8, flag, "--out")) {
            parsed.out = value;
        } else if (std.mem.eql(u8, flag, "--platform")) {
            parsed.platform = value;
        } else if (std.mem.eql(u8, flag, "--plugin")) {
            parsed.plugin = value;
        } else if (std.mem.eql(u8, flag, "--library")) {
            parsed.library = value;
        } else if (std.mem.eql(u8, flag, "--schema")) {
            parsed.schema = value;
        } else if (std.mem.eql(u8, flag, "--readme")) {
            parsed.readme = value;
        } else if (std.mem.eql(u8, flag, "--locales")) {
            parsed.locales = value;
        } else {
            return error.UnknownOption;
        }
    }
    if (parsed.platform.len == 0 or parsed.plugin.len == 0 or parsed.library.len == 0 or
        parsed.schema.len == 0)
    {
        return error.MissingOption;
    }
    return parsed;
}

/// One file of the staged package.
const Entry = struct {
    /// Path inside the package directory, forward slashes.
    name: []const u8,
    data: []const u8,
};

fn pack(alloc: std.mem.Allocator, io: std.Io, arguments: Arguments) !void {
    const cwd = std.Io.Dir.cwd();

    // The manifest is read first: id and version name the outputs, and
    // `library` decides the file name inside the package.
    const manifest_text = try cwd.readFileAlloc(io, arguments.plugin, alloc, .limited(1 << 20));
    const manifest = try Manifest.parse(manifest_text);

    const stage_name = try std.fmt.allocPrint(alloc, "{s}-{s}-{s}", .{
        manifest.id,
        manifest.version,
        arguments.platform,
    });
    defer alloc.free(stage_name);
    const stage_path = try std.fs.path.join(alloc, &.{ arguments.out, stage_name });
    defer alloc.free(stage_path);
    const archive_path = try std.fmt.allocPrint(alloc, "{s}.lcpkg", .{stage_path});
    defer alloc.free(archive_path);

    var entries: std.ArrayList(Entry) = .empty;
    defer {
        for (entries.items) |entry| {
            alloc.free(entry.name);
            alloc.free(entry.data);
        }
        entries.deinit(alloc);
    }

    // plugin.toml
    try entries.append(alloc, .{
        .name = try alloc.dupe(u8, "plugin.toml"),
        .data = manifest_text,
    });
    // The library, under the platform file name the manifest resolves to.
    const library_name = try manifest.libraryFileName(alloc, arguments.platform);
    try entries.append(alloc, .{
        .name = library_name,
        .data = try cwd.readFileAlloc(io, arguments.library, alloc, .unlimited),
    });
    try entries.append(alloc, .{
        .name = try alloc.dupe(u8, "schema.json"),
        .data = try cwd.readFileAlloc(io, arguments.schema, alloc, .limited(16 << 20)),
    });
    if (arguments.readme) |readme| {
        try entries.append(alloc, .{
            .name = try alloc.dupe(u8, "README.md"),
            .data = try cwd.readFileAlloc(io, readme, alloc, .limited(16 << 20)),
        });
    }

    // locales/, when the plugin ships translations.
    if (arguments.locales) |locales| {
        const directory: ?std.Io.Dir = cwd.openDir(io, locales, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => null,
            else => return err,
        };
        if (directory) |open| {
            defer open.close(io);
            var iterator = open.iterate();
            while (try iterator.next(io)) |item| {
                if (item.kind == .directory) continue;
                if (!std.mem.endsWith(u8, item.name, ".toml")) continue;
                try entries.append(alloc, .{
                    .name = try std.fmt.allocPrint(alloc, "locales/{s}", .{item.name}),
                    .data = try open.readFileAlloc(io, item.name, alloc, .limited(4 << 20)),
                });
            }
        }
    }

    // Provenance: what produced this package.
    const built_at = try timestamp(alloc, io);
    defer alloc.free(built_at);
    const build_info = try std.fmt.allocPrint(alloc,
        \\{{
        \\  "plugin": "{s}",
        \\  "version": "{s}",
        \\  "protocol": 2,
        \\  "platform": "{s}",
        \\  "library": "{s}",
        \\  "builtAt": "{s}"
        \\}}
        \\
    , .{
        manifest.id,
        manifest.version,
        arguments.platform,
        library_name,
        built_at,
    });
    try entries.append(alloc, .{ .name = try alloc.dupe(u8, BUILD_INFO), .data = build_info });

    // Start clean: a stale stage would otherwise leak into the archive.
    // `deleteTree` returns quietly when the path does not exist.
    try cwd.deleteTree(io, stage_path);
    try cwd.createDirPath(io, stage_path);

    // Stage every file, then checksum the staged files. SHA256SUMS.txt is
    // written last, so it never lists itself.
    for (entries.items) |entry| {
        const destination = try std.fs.path.join(alloc, &.{ stage_path, entry.name });
        defer alloc.free(destination);
        if (std.fs.path.dirname(destination)) |parent| try cwd.createDirPath(io, parent);
        try cwd.writeFile(io, .{ .sub_path = destination, .data = entry.data });
    }
    const checksums = try checksumEntries(alloc, entries.items);
    defer alloc.free(checksums);
    const checksum_path = try std.fs.path.join(alloc, &.{ stage_path, CHECKSUMS });
    defer alloc.free(checksum_path);
    try cwd.writeFile(io, .{ .sub_path = checksum_path, .data = checksums });

    // Archive the staged directory: the files in stage order, then
    // SHA256SUMS.txt.
    var zip = Zip{ .io = io, .alloc = alloc };
    defer zip.deinit();
    for (entries.items) |entry| try zip.add(entry.name, entry.data);
    try zip.add(CHECKSUMS, checksums);
    try zip.finish(archive_path);

    std.debug.print("pack: staged  {s}\npack: archive {s}\n", .{ stage_path, archive_path });
}

/// `<sha256>  <relative path>` per staged file, sorted by path, with forward
/// slashes — the format `sha256sum -c` reads.
fn checksumEntries(alloc: std.mem.Allocator, entries: []const Entry) ![]u8 {
    const sorted = try alloc.dupe(Entry, entries);
    defer alloc.free(sorted);
    std.mem.sort(Entry, sorted, {}, struct {
        fn lessThan(_: void, left: Entry, right: Entry) bool {
            return std.mem.lessThan(u8, left.name, right.name);
        }
    }.lessThan);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    for (sorted) |entry| {
        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(entry.data, &digest, .{});
        try out.appendSlice(alloc, &std.fmt.bytesToHex(digest, .lower));
        try out.appendSlice(alloc, "  ");
        try out.appendSlice(alloc, entry.name);
        try out.append(alloc, '\n');
    }
    return out.toOwnedSlice(alloc);
}

/// The manifest fields the packager needs.
const Manifest = struct {
    id: []const u8,
    version: []const u8,
    /// `library` as written: a name without an extension (`zigtemplate`), or a
    /// relative path inside the package.
    library: []const u8,

    /// Reads the top-level keys of plugin.toml. The manifest is a flat table
    /// until the first `[[analyzer]]` / `[table]` header and the three keys
    /// are plain quoted strings, so a full TOML parser is not needed.
    fn parse(text: []const u8) !Manifest {
        var manifest = Manifest{ .id = "", .version = "", .library = "" };
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            if (line[0] == '[') break;
            const equals = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = std.mem.trim(u8, line[0..equals], " \t");
            const raw_value = stripComment(std.mem.trim(u8, line[equals + 1 ..], " \t"));
            // Only the three quoted string keys are read; every other
            // top-level key (protocol = 2, memory = "512MiB", ...) keeps its
            // own TOML syntax and is skipped.
            if (raw_value.len < 2 or raw_value[0] != '"' or raw_value[raw_value.len - 1] != '"') continue;
            const value = raw_value[1 .. raw_value.len - 1];
            if (std.mem.eql(u8, key, "id")) {
                manifest.id = value;
            } else if (std.mem.eql(u8, key, "version")) {
                manifest.version = value;
            } else if (std.mem.eql(u8, key, "library")) {
                manifest.library = value;
            }
        }
        if (manifest.id.len == 0) return error.ManifestWithoutId;
        if (manifest.version.len == 0) return error.ManifestWithoutVersion;
        if (manifest.library.len == 0) return error.ManifestWithoutLibrary;
        return manifest;
    }

    /// The library file name inside the package: `library` with the platform's
    /// prefix and suffix, exactly as the host resolves it.
    fn libraryFileName(self: Manifest, alloc: std.mem.Allocator, platform: []const u8) ![]u8 {
        const name = std.fs.path.basename(self.library);
        if (std.mem.endsWith(u8, name, ".dll") or std.mem.endsWith(u8, name, ".so") or
            std.mem.endsWith(u8, name, ".dylib"))
        {
            return alloc.dupe(u8, name);
        }
        const windows = std.mem.startsWith(u8, platform, "windows");
        const macos = std.mem.startsWith(u8, platform, "macos");
        return std.fmt.allocPrint(alloc, "{s}{s}{s}", .{
            if (windows) "" else "lib",
            name,
            if (windows) ".dll" else if (macos) ".dylib" else ".so",
        });
    }
};

/// A `key = value # comment` line: drops the comment outside quotes.
fn stripComment(raw: []const u8) []const u8 {
    if (raw.len == 0 or raw[0] != '"') {
        const hash = std.mem.indexOfScalar(u8, raw, '#') orelse return raw;
        return std.mem.trimEnd(u8, raw[0..hash], " \t");
    }
    // A quoted string may contain '#'; only a '#' after the closing quote
    // starts a comment.
    var index: usize = 1;
    while (index < raw.len) : (index += 1) {
        if (raw[index] == '"') {
            const rest = std.mem.trimStart(u8, raw[index + 1 ..], " \t");
            if (rest.len == 0 or rest[0] == '#') return raw[0 .. index + 1];
            return raw;
        }
    }
    return raw;
}

/// `YYYY-MM-DDTHH:MM:SSZ` for build.json.
fn timestamp(alloc: std.mem.Allocator, io: std.Io) ![]u8 {
    const seconds: i64 = @intCast(@divFloor(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(seconds) };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    return std.fmt.allocPrint(alloc, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        @as(u32, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });
}

// --------------------------------------------------------------------- ZIP

/// A ZIP writer with STORED entries: no compression, so the archive holds the
/// library bytes verbatim and needs no dependency. Entries are collected in
/// memory (a plugin package is a few megabytes) and written in one pass.
const Zip = struct {
    io: std.Io,
    alloc: std.mem.Allocator,
    entries: std.ArrayList(Staged) = .empty,
    /// DOS date and time of every entry: the current UTC time.
    dos_time: u16 = 0,
    dos_date: u16 = 0,
    stamped: bool = false,

    const Staged = struct {
        name: []const u8,
        data: []const u8,
        crc: u32,
        offset: u32,
    };

    fn deinit(self: *Zip) void {
        for (self.entries.items) |entry| self.alloc.free(entry.name);
        self.entries.deinit(self.alloc);
    }

    fn add(self: *Zip, name: []const u8, data: []const u8) !void {
        if (!self.stamped) {
            const stamp = try self.now();
            self.dos_time = stamp.time;
            self.dos_date = stamp.date;
            self.stamped = true;
        }
        var crc = std.hash.Crc32.init();
        crc.update(data);
        try self.entries.append(self.alloc, .{
            .name = try self.alloc.dupe(u8, name),
            .data = data,
            .crc = crc.final(),
            .offset = 0,
        });
    }

    fn finish(self: *Zip, path: []const u8) !void {
        const cwd = std.Io.Dir.cwd();
        var file = try cwd.createFile(self.io, path, .{});
        defer file.close(self.io);

        var offset: u32 = 0;
        for (self.entries.items) |*entry| {
            entry.offset = offset;
            offset = try std.math.add(u32, offset, @intCast(30 + entry.name.len + entry.data.len));
        }
        const directory_offset = offset;
        for (self.entries.items) |entry| {
            offset = try std.math.add(u32, offset, @intCast(46 + entry.name.len));
        }
        const directory_size = offset - directory_offset;
        if (self.entries.items.len > std.math.maxInt(u16)) return error.TooManyEntries;

        for (self.entries.items) |entry| {
            var header: [30]u8 = undefined;
            const size: u32 = @intCast(entry.data.len);
            writeInt(&header, 0, u32, 0x04034b50); // local file header
            writeInt(&header, 4, u16, 20); // version needed to extract (2.0)
            writeInt(&header, 6, u16, 0x0800); // bit 11: UTF-8 names
            writeInt(&header, 8, u16, 0); // STORED
            writeInt(&header, 10, u16, self.dos_time);
            writeInt(&header, 12, u16, self.dos_date);
            writeInt(&header, 14, u32, entry.crc);
            writeInt(&header, 18, u32, size); // compressed size
            writeInt(&header, 22, u32, size); // uncompressed size
            writeInt(&header, 26, u16, @intCast(entry.name.len));
            writeInt(&header, 28, u16, 0); // no extra field
            try file.writeStreamingAll(self.io, &header);
            try file.writeStreamingAll(self.io, entry.name);
            try file.writeStreamingAll(self.io, entry.data);
        }

        var directory: std.ArrayList(u8) = .empty;
        defer directory.deinit(self.alloc);
        for (self.entries.items) |entry| {
            var header: [46]u8 = undefined;
            const size: u32 = @intCast(entry.data.len);
            writeInt(&header, 0, u32, 0x02014b50); // central directory header
            writeInt(&header, 4, u16, 20); // version made by
            writeInt(&header, 6, u16, 20); // version needed
            writeInt(&header, 8, u16, 0x0800);
            writeInt(&header, 10, u16, 0); // STORED
            writeInt(&header, 12, u16, self.dos_time);
            writeInt(&header, 14, u16, self.dos_date);
            writeInt(&header, 16, u32, entry.crc);
            writeInt(&header, 20, u32, size);
            writeInt(&header, 24, u32, size);
            writeInt(&header, 28, u16, @intCast(entry.name.len));
            writeInt(&header, 30, u16, 0); // extra length
            writeInt(&header, 32, u16, 0); // comment length
            writeInt(&header, 34, u16, 0); // disk number
            writeInt(&header, 36, u16, 0); // internal attributes
            writeInt(&header, 38, u32, 0); // external attributes
            writeInt(&header, 42, u32, entry.offset);
            try directory.appendSlice(self.alloc, &header);
            try directory.appendSlice(self.alloc, entry.name);
        }
        try file.writeStreamingAll(self.io, directory.items);

        var end: [22]u8 = undefined;
        writeInt(&end, 0, u32, 0x06054b50); // end of central directory
        writeInt(&end, 4, u16, 0); // this disk
        writeInt(&end, 6, u16, 0); // disk with the central directory
        writeInt(&end, 8, u16, @intCast(self.entries.items.len));
        writeInt(&end, 10, u16, @intCast(self.entries.items.len));
        writeInt(&end, 12, u32, directory_size);
        writeInt(&end, 16, u32, directory_offset);
        writeInt(&end, 20, u16, 0); // no archive comment
        try file.writeStreamingAll(self.io, &end);
    }

    /// The current UTC time in DOS format (2-second resolution).
    fn now(self: *Zip) !struct { time: u16, date: u16 } {
        const seconds: i64 = @intCast(@divFloor(std.Io.Timestamp.now(self.io, .real).nanoseconds, std.time.ns_per_s));
        const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(seconds) };
        const year_day = epoch_seconds.getEpochDay().calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const day_seconds = epoch_seconds.getDaySeconds();
        const year: u16 = @intCast(@min(@as(i64, year_day.year), 2107));
        return .{
            .time = (@as(u16, day_seconds.getHoursIntoDay()) << 11) |
                (@as(u16, day_seconds.getMinutesIntoHour()) << 5) |
                (@as(u16, day_seconds.getSecondsIntoMinute()) / 2),
            .date = ((year - 1980) << 9) |
                (@as(u16, month_day.month.numeric()) << 5) |
                (@as(u16, month_day.day_index) + 1),
        };
    }
};

fn writeInt(header: []u8, offset: usize, comptime T: type, value: T) void {
    std.mem.writeInt(T, header[offset..][0..@sizeOf(T)], value, .little);
}
