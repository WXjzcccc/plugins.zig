const std = @import("std");
const cursor = @import("../io/cursor.zig");
const logging = @import("../logging.zig");

const Allocator = std.mem.Allocator;
const Cursor = cursor.Cursor;

const log = logging.scoped(.apk_archive);

const local_file_header_signature: u32 = 0x04034b50;
const central_directory_header_signature: u32 = 0x02014b50;
const end_of_central_directory_signature: u32 = 0x06054b50;
const zip64_end_of_central_directory_signature: u32 = 0x06064b50;
const zip64_end_locator_signature: u32 = 0x07064b50;
const central_directory_digital_signature: u32 = 0x05054b50;
const zip64_extra_id: u16 = 0x0001;

const local_header_len = 30;
const central_header_len = 46;
const eocd_len = 22;
const zip64_eocd_min_len = 56;
const zip64_locator_len = 20;

pub const CompressionMethod = enum(u16) {
    store = 0,
    deflate = 8,
    _,
};

pub const Entry = struct {
    /// Raw name bytes from the central directory. This slice borrows the APK.
    name: []const u8,
    method: CompressionMethod,
    flags: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: u64,
    central_header_offset: u64,

    pub fn isDirectory(self: Entry) bool {
        return self.name.len != 0 and self.name[self.name.len - 1] == '/';
    }
};

pub const ParseError = Allocator.Error || error{
    MissingEndOfCentralDirectory,
    TruncatedEndOfCentralDirectory,
    MissingZip64EndLocator,
    InvalidZip64EndLocator,
    MissingZip64EndRecord,
    InvalidZip64EndRecord,
    Zip64RecordMismatch,
    MultiDiskUnsupported,
    IntegerOverflow,
    InvalidCentralDirectoryBounds,
    InvalidCentralDirectory,
    TruncatedCentralDirectory,
    InvalidCentralDirectorySignature,
    CentralDirectorySizeMismatch,
    MalformedExtraField,
    MissingZip64Extra,
    MalformedZip64Extra,
};

pub const ExtractError = Allocator.Error || error{
    IntegerOverflow,
    EncryptedEntryUnsupported,
    UnsupportedCompressionMethod,
    TruncatedLocalHeader,
    InvalidLocalHeaderSignature,
    LocalHeaderMismatch,
    MalformedExtraField,
    MissingZip64Extra,
    MalformedZip64Extra,
    TruncatedEntryData,
    InvalidDeflateStream,
    OutputTooLarge,
    SizeMismatch,
    CrcMismatch,
    EntryNotFound,
};

pub const ExtractOptions = struct {
    /// Refuses allocation before decompression, for ZIP-bomb policy control.
    max_output_size: u64 = std.math.maxInt(u64),
};

pub const Archive = struct {
    allocator: Allocator,
    data: []const u8,
    entries: []Entry,

    /// Parses the central directory from an immutable in-memory APK/ZIP.
    /// `data` and all entry-name slices must outlive this archive.
    pub fn init(allocator: Allocator, data: []const u8) ParseError!Archive {
        return initImpl(allocator, data) catch |err| {
            log.err(@src(), "ZIP archive parsing failed bytes={d} error={s}", .{ data.len, @errorName(err) });
            return err;
        };
    }

    fn initImpl(allocator: Allocator, data: []const u8) ParseError!Archive {
        const directory = try readDirectoryInfo(data);
        log.debug(@src(), "central directory located offset={d} size={d} entries={d}", .{
            directory.offset,
            directory.size,
            directory.entry_count,
        });
        const cd_start = try toUsize(directory.offset);
        const cd_size = try toUsize(directory.size);
        const cd_end = try add(cd_start, cd_size);
        if (cd_end > data.len or cd_end > directory.end_limit) {
            return error.InvalidCentralDirectoryBounds;
        }

        const count = try toUsize(directory.entry_count);
        if (count > cd_size / central_header_len) {
            return error.InvalidCentralDirectory;
        }

        const entries = try allocator.alloc(Entry, count);
        errdefer allocator.free(entries);

        var cd = Cursor.init(data[cd_start..cd_end]);
        for (entries) |*entry| {
            const relative_header_offset = cd.offset();
            const fixed = cd.readBytes(central_header_len) catch {
                return error.TruncatedCentralDirectory;
            };
            if (readLe(u32, fixed, 0) != central_directory_header_signature) {
                return error.InvalidCentralDirectorySignature;
            }

            const flags = readLe(u16, fixed, 8);
            const method: CompressionMethod = @fromBackingInt(@intCast(readLe(u16, fixed, 10)));
            const crc32 = readLe(u32, fixed, 16);
            const compressed_32 = readLe(u32, fixed, 20);
            const uncompressed_32 = readLe(u32, fixed, 24);
            const name_len = readLe(u16, fixed, 28);
            const extra_len = readLe(u16, fixed, 30);
            const comment_len = readLe(u16, fixed, 32);
            const disk_start_16 = readLe(u16, fixed, 34);
            const local_offset_32 = readLe(u32, fixed, 42);

            const name = cd.readBytes(name_len) catch {
                return error.TruncatedCentralDirectory;
            };
            const extra = cd.readBytes(extra_len) catch {
                return error.TruncatedCentralDirectory;
            };
            cd.skip(comment_len) catch return error.TruncatedCentralDirectory;

            var values: Zip64Values = .{
                .uncompressed_size = uncompressed_32,
                .compressed_size = compressed_32,
                .local_header_offset = local_offset_32,
                .disk_start = disk_start_16,
            };
            const needs: Zip64Needs = .{
                .uncompressed_size = uncompressed_32 == std.math.maxInt(u32),
                .compressed_size = compressed_32 == std.math.maxInt(u32),
                .local_header_offset = local_offset_32 == std.math.maxInt(u32),
                .disk_start = disk_start_16 == std.math.maxInt(u16),
            };
            try applyZip64Extra(extra, needs, &values);
            if (values.disk_start != 0) return error.MultiDiskUnsupported;

            entry.* = .{
                .name = name,
                .method = method,
                .flags = flags,
                .crc32 = crc32,
                .compressed_size = values.compressed_size,
                .uncompressed_size = values.uncompressed_size,
                .local_header_offset = values.local_header_offset,
                .central_header_offset = try usizeToU64(try add(cd_start, relative_header_offset)),
            };
        }

        try validateCentralDirectoryTail(cd.data[cd.offset()..]);
        log.debug(@src(), "central directory parsed entries={d}", .{entries.len});
        return .{
            .allocator = allocator,
            .data = data,
            .entries = entries,
        };
    }

    pub fn deinit(self: *Archive) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn findEntry(self: *const Archive, name: []const u8) ?*const Entry {
        for (self.entries, 0..) |entry, index| {
            if (std.mem.eql(u8, entry.name, name)) return &self.entries[index];
        }
        return null;
    }

    /// Allocates and returns verified uncompressed entry bytes.
    /// The caller owns the returned slice.
    pub fn extractAlloc(
        self: *const Archive,
        allocator: Allocator,
        entry: *const Entry,
        options: ExtractOptions,
    ) ExtractError![]u8 {
        return extractAllocImpl(self, allocator, entry, options) catch |err| {
            log.err(@src(), "ZIP entry extraction failed name={s} error={s}", .{ entry.name, @errorName(err) });
            return err;
        };
    }

    fn extractAllocImpl(
        self: *const Archive,
        allocator: Allocator,
        entry: *const Entry,
        options: ExtractOptions,
    ) ExtractError![]u8 {
        log.debug(@src(), "extracting entry name={s} method={s} compressed_bytes={d} uncompressed_bytes={d}", .{
            entry.name,
            @tagName(entry.method),
            entry.compressed_size,
            entry.uncompressed_size,
        });
        if ((entry.flags & 0x0001) != 0 or (entry.flags & 0x0040) != 0) {
            return error.EncryptedEntryUnsupported;
        }
        switch (entry.method) {
            .store, .deflate => {},
            else => return error.UnsupportedCompressionMethod,
        }

        const local_offset = try toUsizeExtract(entry.local_header_offset);
        const fixed = sliceAtExtract(self.data, local_offset, local_header_len) catch {
            return error.TruncatedLocalHeader;
        };
        if (readLe(u32, fixed, 0) != local_file_header_signature) {
            return error.InvalidLocalHeaderSignature;
        }

        const local_flags = readLe(u16, fixed, 6);
        const local_method = readLe(u16, fixed, 8);
        const local_crc = readLe(u32, fixed, 14);
        const compressed_32 = readLe(u32, fixed, 18);
        const uncompressed_32 = readLe(u32, fixed, 22);
        const name_len = readLe(u16, fixed, 26);
        const extra_len = readLe(u16, fixed, 28);
        // Some packers set the UTF-8 filename marker only in the local header.
        // The central-directory name remains authoritative for extraction.
        const filename_encoding_flag: u16 = 0x0800;
        if ((local_flags & ~filename_encoding_flag) != (entry.flags & ~filename_encoding_flag) or
            local_method != @backingInt(entry.method))
        {
            return error.LocalHeaderMismatch;
        }
        if (local_flags != entry.flags) {
            log.debug(@src(), "local ZIP header filename encoding flag differs name={s} central_flags=0x{x:0>4} local_flags=0x{x:0>4}", .{
                entry.name,
                entry.flags,
                local_flags,
            });
        }

        const name_start = try addExtract(local_offset, local_header_len);
        const local_name = sliceAtExtract(self.data, name_start, name_len) catch {
            return error.TruncatedLocalHeader;
        };
        if (!std.mem.eql(u8, local_name, entry.name)) return error.LocalHeaderMismatch;
        const extra_start = try addExtract(name_start, name_len);
        const extra = sliceAtExtract(self.data, extra_start, extra_len) catch {
            return error.TruncatedLocalHeader;
        };

        var local_values: Zip64Values = .{
            .uncompressed_size = uncompressed_32,
            .compressed_size = compressed_32,
            .local_header_offset = 0,
            .disk_start = 0,
        };
        const local_needs: Zip64Needs = .{
            .uncompressed_size = uncompressed_32 == std.math.maxInt(u32),
            .compressed_size = compressed_32 == std.math.maxInt(u32),
        };
        applyZip64ExtraExtract(extra, local_needs, &local_values) catch |err| {
            log.warn(@src(), "local ZIP64 extra field rejected name={s} error={s}", .{ entry.name, @errorName(err) });
            return err;
        };

        const uses_data_descriptor = (entry.flags & 0x0008) != 0;
        if (!uses_data_descriptor) {
            if (local_crc != entry.crc32 or
                local_values.compressed_size != entry.compressed_size or
                local_values.uncompressed_size != entry.uncompressed_size)
            {
                return error.LocalHeaderMismatch;
            }
        } else {
            if (local_crc != 0 and local_crc != entry.crc32) return error.LocalHeaderMismatch;
            if (compressed_32 != 0 and local_values.compressed_size != entry.compressed_size) {
                return error.LocalHeaderMismatch;
            }
            if (uncompressed_32 != 0 and local_values.uncompressed_size != entry.uncompressed_size) {
                return error.LocalHeaderMismatch;
            }
        }

        const data_start = try addExtract(extra_start, extra_len);
        const compressed_len = try toUsizeExtract(entry.compressed_size);
        const compressed = sliceAtExtract(self.data, data_start, compressed_len) catch {
            return error.TruncatedEntryData;
        };
        if (entry.uncompressed_size > options.max_output_size) return error.OutputTooLarge;
        const output_len = try toUsizeExtract(entry.uncompressed_size);

        const output = switch (entry.method) {
            .store => store: {
                if (compressed_len != output_len) return error.SizeMismatch;
                break :store try allocator.dupe(u8, compressed);
            },
            .deflate => inflate: {
                const decoded = try allocator.alloc(u8, output_len);
                errdefer allocator.free(decoded);

                var input = std.Io.Reader.fixed(compressed);
                var decompressor = std.compress.flate.Decompress.init(&input, .raw, &.{});
                var writer = std.Io.Writer.fixed(decoded);
                _ = decompressor.reader.streamRemaining(&writer) catch |err| {
                    log.warn(@src(), "deflate decompression failed name={s} error={s}", .{ entry.name, @errorName(err) });
                    return switch (err) {
                        error.ReadFailed => error.InvalidDeflateStream,
                        error.WriteFailed => error.SizeMismatch,
                    };
                };
                if (writer.end != decoded.len) return error.SizeMismatch;
                if (input.seek != input.end) return error.InvalidDeflateStream;
                break :inflate decoded;
            },
            else => unreachable,
        };
        errdefer allocator.free(output);

        if (output.len != output_len) return error.SizeMismatch;
        if (std.hash.Crc32.hash(output) != entry.crc32) return error.CrcMismatch;
        log.debug(@src(), "entry extracted name={s} bytes={d}", .{ entry.name, output.len });
        return output;
    }

    pub fn extract(
        self: *const Archive,
        allocator: Allocator,
        entry: *const Entry,
    ) ExtractError![]u8 {
        return self.extractAlloc(allocator, entry, .{});
    }

    pub fn extractByName(
        self: *const Archive,
        allocator: Allocator,
        name: []const u8,
    ) ExtractError![]u8 {
        const entry = self.findEntry(name) orelse return error.EntryNotFound;
        return self.extract(allocator, entry);
    }

    pub fn extractByNameAlloc(
        self: *const Archive,
        allocator: Allocator,
        name: []const u8,
        options: ExtractOptions,
    ) ExtractError![]u8 {
        const entry = self.findEntry(name) orelse return error.EntryNotFound;
        return self.extractAlloc(allocator, entry, options);
    }
};

pub fn parse(allocator: Allocator, data: []const u8) ParseError!Archive {
    return Archive.init(allocator, data);
}

const DirectoryInfo = struct {
    offset: u64,
    size: u64,
    entry_count: u64,
    end_limit: usize,
};

fn readDirectoryInfo(data: []const u8) ParseError!DirectoryInfo {
    const eocd_offset = try findEndOfCentralDirectory(data);
    const record = data[eocd_offset..][0..eocd_len];
    const disk_number = readLe(u16, record, 4);
    const central_disk = readLe(u16, record, 6);
    const count_disk = readLe(u16, record, 8);
    const count_total = readLe(u16, record, 10);
    const size_32 = readLe(u32, record, 12);
    const offset_32 = readLe(u32, record, 16);

    if (disk_number != 0 or central_disk != 0) return error.MultiDiskUnsupported;

    const needs_zip64 = count_disk == std.math.maxInt(u16) or
        count_total == std.math.maxInt(u16) or
        size_32 == std.math.maxInt(u32) or
        offset_32 == std.math.maxInt(u32);
    if (!needs_zip64) {
        if (count_disk != count_total) return error.MultiDiskUnsupported;
        return .{
            .offset = offset_32,
            .size = size_32,
            .entry_count = count_total,
            .end_limit = eocd_offset,
        };
    }

    if (eocd_offset < zip64_locator_len) return error.MissingZip64EndLocator;
    const locator_offset = eocd_offset - zip64_locator_len;
    const locator = data[locator_offset..eocd_offset];
    if (readLe(u32, locator, 0) != zip64_end_locator_signature) {
        return error.MissingZip64EndLocator;
    }
    if (readLe(u32, locator, 4) != 0 or readLe(u32, locator, 16) != 1) {
        return error.MultiDiskUnsupported;
    }

    const zip64_offset = toUsize(readLe(u64, locator, 8)) catch {
        return error.InvalidZip64EndLocator;
    };
    const zip64_prefix = sliceAt(data, zip64_offset, zip64_eocd_min_len) catch {
        return error.MissingZip64EndRecord;
    };
    if (readLe(u32, zip64_prefix, 0) != zip64_end_of_central_directory_signature) {
        return error.MissingZip64EndRecord;
    }
    const record_payload_len = toUsize(readLe(u64, zip64_prefix, 4)) catch {
        return error.InvalidZip64EndRecord;
    };
    if (record_payload_len < 44) return error.InvalidZip64EndRecord;
    const record_end = add(zip64_offset, 12) catch return error.InvalidZip64EndRecord;
    const full_record_end = add(record_end, record_payload_len) catch {
        return error.InvalidZip64EndRecord;
    };
    if (full_record_end != locator_offset or full_record_end > data.len) {
        return error.InvalidZip64EndRecord;
    }

    const zip_disk = readLe(u32, zip64_prefix, 16);
    const zip_central_disk = readLe(u32, zip64_prefix, 20);
    const zip_count_disk = readLe(u64, zip64_prefix, 24);
    const zip_count_total = readLe(u64, zip64_prefix, 32);
    const zip_size = readLe(u64, zip64_prefix, 40);
    const zip_offset_value = readLe(u64, zip64_prefix, 48);
    if (zip_disk != 0 or zip_central_disk != 0 or zip_count_disk != zip_count_total) {
        return error.MultiDiskUnsupported;
    }

    try checkZip64U16(count_disk, zip_count_disk);
    try checkZip64U16(count_total, zip_count_total);
    try checkZip64U32(size_32, zip_size);
    try checkZip64U32(offset_32, zip_offset_value);
    return .{
        .offset = zip_offset_value,
        .size = zip_size,
        .entry_count = zip_count_total,
        .end_limit = zip64_offset,
    };
}

fn findEndOfCentralDirectory(data: []const u8) ParseError!usize {
    if (data.len < eocd_len) return error.MissingEndOfCentralDirectory;

    const max_search_len = eocd_len + std.math.maxInt(u16);
    const lower_bound = data.len - @min(data.len, max_search_len);
    var offset = data.len - eocd_len;
    while (true) {
        if (readLe(u32, data, offset) == end_of_central_directory_signature) {
            const comment_len = readLe(u16, data, offset + 20);
            const record_end = add(offset, eocd_len) catch {
                return error.TruncatedEndOfCentralDirectory;
            };
            const comment_end = add(record_end, comment_len) catch {
                return error.TruncatedEndOfCentralDirectory;
            };
            if (comment_end == data.len) return offset;
        }
        if (offset == lower_bound) break;
        offset -= 1;
    }
    return error.MissingEndOfCentralDirectory;
}

const Zip64Values = struct {
    uncompressed_size: u64,
    compressed_size: u64,
    local_header_offset: u64,
    disk_start: u32,
};

const Zip64Needs = struct {
    uncompressed_size: bool = false,
    compressed_size: bool = false,
    local_header_offset: bool = false,
    disk_start: bool = false,

    fn any(self: Zip64Needs) bool {
        return self.uncompressed_size or self.compressed_size or
            self.local_header_offset or self.disk_start;
    }
};

fn applyZip64Extra(
    extra: []const u8,
    needs: Zip64Needs,
    values: *Zip64Values,
) ParseError!void {
    return applyZip64ExtraImpl(extra, needs, values) catch |err| switch (err) {
        error.MalformedExtraField => error.MalformedExtraField,
        error.MissingZip64Extra => error.MissingZip64Extra,
        error.MalformedZip64Extra => error.MalformedZip64Extra,
    };
}

fn applyZip64ExtraExtract(
    extra: []const u8,
    needs: Zip64Needs,
    values: *Zip64Values,
) ExtractError!void {
    return applyZip64ExtraImpl(extra, needs, values);
}

fn applyZip64ExtraImpl(
    extra: []const u8,
    needs: Zip64Needs,
    values: *Zip64Values,
) error{ MalformedExtraField, MissingZip64Extra, MalformedZip64Extra }!void {
    var fields = Cursor.init(extra);
    var found = false;
    while (!fields.atEnd()) {
        if (fields.remaining() < 4) {
            for (fields.data[fields.offset()..]) |byte| {
                if (byte != 0) return error.MalformedExtraField;
            }
            break;
        }
        const field_id = fields.readInt(u16, .little) catch unreachable;
        const field_len = fields.readInt(u16, .little) catch unreachable;
        const payload = fields.readBytes(field_len) catch return error.MalformedExtraField;
        if (field_id != zip64_extra_id) continue;
        if (found) return error.MalformedZip64Extra;
        found = true;

        var zip64 = Cursor.init(payload);
        if (needs.uncompressed_size) {
            values.uncompressed_size = zip64.readInt(u64, .little) catch {
                return error.MalformedZip64Extra;
            };
        }
        if (needs.compressed_size) {
            values.compressed_size = zip64.readInt(u64, .little) catch {
                return error.MalformedZip64Extra;
            };
        }
        if (needs.local_header_offset) {
            values.local_header_offset = zip64.readInt(u64, .little) catch {
                return error.MalformedZip64Extra;
            };
        }
        if (needs.disk_start) {
            values.disk_start = zip64.readInt(u32, .little) catch {
                return error.MalformedZip64Extra;
            };
        }
    }
    if (needs.any() and !found) return error.MissingZip64Extra;
}

fn validateCentralDirectoryTail(tail: []const u8) ParseError!void {
    if (tail.len == 0) return;
    if (tail.len < 6 or readLe(u32, tail, 0) != central_directory_digital_signature) {
        return error.CentralDirectorySizeMismatch;
    }
    const payload_len = readLe(u16, tail, 4);
    const expected_len = add(6, payload_len) catch return error.CentralDirectorySizeMismatch;
    if (expected_len != tail.len) return error.CentralDirectorySizeMismatch;
}

fn checkZip64U16(value: u16, zip64_value: u64) ParseError!void {
    if (value != std.math.maxInt(u16) and value != zip64_value) {
        return error.Zip64RecordMismatch;
    }
}

fn checkZip64U32(value: u32, zip64_value: u64) ParseError!void {
    if (value != std.math.maxInt(u32) and value != zip64_value) {
        return error.Zip64RecordMismatch;
    }
}

fn readLe(comptime T: type, bytes: []const u8, offset: usize) T {
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .little);
}

fn add(a: usize, b: usize) error{IntegerOverflow}!usize {
    return cursor.checkedAdd(a, b) catch error.IntegerOverflow;
}

fn addExtract(a: usize, b: usize) ExtractError!usize {
    return cursor.checkedAdd(a, b) catch error.IntegerOverflow;
}

fn toUsize(value: u64) error{IntegerOverflow}!usize {
    return cursor.u64ToUsize(value) catch error.IntegerOverflow;
}

fn toUsizeExtract(value: u64) ExtractError!usize {
    return cursor.u64ToUsize(value) catch error.IntegerOverflow;
}

fn usizeToU64(value: usize) error{IntegerOverflow}!u64 {
    if (@bitSizeOf(usize) > @bitSizeOf(u64) and value > std.math.maxInt(u64)) {
        return error.IntegerOverflow;
    }
    return @intCast(value);
}

fn sliceAt(data: []const u8, start: usize, len: usize) Cursor.Error![]const u8 {
    return Cursor.init(data).sliceAt(start, len);
}

fn sliceAtExtract(
    data: []const u8,
    start: usize,
    len: usize,
) error{ IntegerOverflow, EndOfInput }![]const u8 {
    return Cursor.init(data).sliceAt(start, len);
}

const TestZipOptions = struct {
    method: CompressionMethod,
    compressed: []const u8,
    uncompressed: []const u8,
    crc32: u32,
    zip64_entry: bool = false,
    zip64_eocd: bool = false,
};

fn appendTestInt(
    list: *std.ArrayList(u8),
    allocator: Allocator,
    comptime T: type,
    value: T,
) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    try list.appendSlice(allocator, &bytes);
}

fn buildTestZip(allocator: Allocator, options: TestZipOptions) ![]u8 {
    const name = "a.txt";
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);

    try appendTestInt(&bytes, allocator, u32, local_file_header_signature);
    try appendTestInt(&bytes, allocator, u16, 20);
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(&bytes, allocator, u16, @backingInt(options.method));
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(&bytes, allocator, u32, options.crc32);
    try appendTestInt(&bytes, allocator, u32, @intCast(options.compressed.len));
    try appendTestInt(&bytes, allocator, u32, @intCast(options.uncompressed.len));
    try appendTestInt(&bytes, allocator, u16, name.len);
    try appendTestInt(&bytes, allocator, u16, 0);
    try bytes.appendSlice(allocator, name);
    try bytes.appendSlice(allocator, options.compressed);

    const cd_offset: u32 = @intCast(bytes.items.len);
    try appendTestInt(&bytes, allocator, u32, central_directory_header_signature);
    try appendTestInt(&bytes, allocator, u16, 45);
    try appendTestInt(&bytes, allocator, u16, if (options.zip64_entry) 45 else 20);
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(&bytes, allocator, u16, @backingInt(options.method));
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(&bytes, allocator, u32, options.crc32);
    try appendTestInt(
        &bytes,
        allocator,
        u32,
        if (options.zip64_entry) std.math.maxInt(u32) else @intCast(options.compressed.len),
    );
    try appendTestInt(
        &bytes,
        allocator,
        u32,
        if (options.zip64_entry) std.math.maxInt(u32) else @intCast(options.uncompressed.len),
    );
    try appendTestInt(&bytes, allocator, u16, name.len);
    try appendTestInt(&bytes, allocator, u16, if (options.zip64_entry) 28 else 0);
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(&bytes, allocator, u32, 0);
    try appendTestInt(
        &bytes,
        allocator,
        u32,
        if (options.zip64_entry) std.math.maxInt(u32) else 0,
    );
    try bytes.appendSlice(allocator, name);
    if (options.zip64_entry) {
        try appendTestInt(&bytes, allocator, u16, zip64_extra_id);
        try appendTestInt(&bytes, allocator, u16, 24);
        try appendTestInt(&bytes, allocator, u64, options.uncompressed.len);
        try appendTestInt(&bytes, allocator, u64, options.compressed.len);
        try appendTestInt(&bytes, allocator, u64, 0);
    }

    const cd_size: u32 = @intCast(bytes.items.len - cd_offset);
    if (options.zip64_eocd) {
        const zip64_offset: u64 = bytes.items.len;
        try appendTestInt(&bytes, allocator, u32, zip64_end_of_central_directory_signature);
        try appendTestInt(&bytes, allocator, u64, 44);
        try appendTestInt(&bytes, allocator, u16, 45);
        try appendTestInt(&bytes, allocator, u16, 45);
        try appendTestInt(&bytes, allocator, u32, 0);
        try appendTestInt(&bytes, allocator, u32, 0);
        try appendTestInt(&bytes, allocator, u64, 1);
        try appendTestInt(&bytes, allocator, u64, 1);
        try appendTestInt(&bytes, allocator, u64, cd_size);
        try appendTestInt(&bytes, allocator, u64, cd_offset);

        try appendTestInt(&bytes, allocator, u32, zip64_end_locator_signature);
        try appendTestInt(&bytes, allocator, u32, 0);
        try appendTestInt(&bytes, allocator, u64, zip64_offset);
        try appendTestInt(&bytes, allocator, u32, 1);
    }

    try appendTestInt(&bytes, allocator, u32, end_of_central_directory_signature);
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(&bytes, allocator, u16, 0);
    try appendTestInt(
        &bytes,
        allocator,
        u16,
        if (options.zip64_eocd) std.math.maxInt(u16) else 1,
    );
    try appendTestInt(
        &bytes,
        allocator,
        u16,
        if (options.zip64_eocd) std.math.maxInt(u16) else 1,
    );
    try appendTestInt(
        &bytes,
        allocator,
        u32,
        if (options.zip64_eocd) std.math.maxInt(u32) else cd_size,
    );
    try appendTestInt(
        &bytes,
        allocator,
        u32,
        if (options.zip64_eocd) std.math.maxInt(u32) else cd_offset,
    );
    try appendTestInt(&bytes, allocator, u16, 0);
    return bytes.toOwnedSlice(allocator);
}

test "parse and extract a stored entry" {
    const contents = "hello";
    const zip = try buildTestZip(std.testing.allocator, .{
        .method = .store,
        .compressed = contents,
        .uncompressed = contents,
        .crc32 = std.hash.Crc32.hash(contents),
    });
    defer std.testing.allocator.free(zip);

    var archive = try Archive.init(std.testing.allocator, zip);
    defer archive.deinit();
    try std.testing.expectEqual(@as(usize, 1), archive.entries.len);
    const entry = archive.findEntry("a.txt") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(CompressionMethod.store, entry.method);
    try std.testing.expectEqual(@as(u64, contents.len), entry.uncompressed_size);
    try std.testing.expectError(
        error.OutputTooLarge,
        archive.extractAlloc(std.testing.allocator, entry, .{ .max_output_size = 4 }),
    );

    const decoded = try archive.extract(std.testing.allocator, entry);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, contents, decoded);
}

test "zero alignment bytes may trail extra fields" {
    var values: Zip64Values = .{
        .uncompressed_size = 1,
        .compressed_size = 1,
        .local_header_offset = 0,
        .disk_start = 0,
    };
    try applyZip64Extra(&.{ 0, 0, 0 }, .{}, &values);
    try std.testing.expectError(
        error.MalformedExtraField,
        applyZip64Extra(&.{0xff}, .{}, &values),
    );
}

test "extract a raw deflate entry and verify CRC" {
    // One final RFC 1951 stored block, carried by ZIP compression method 8.
    const compressed = [_]u8{ 0x01, 0x05, 0x00, 0xfa, 0xff, 'h', 'e', 'l', 'l', 'o' };
    const contents = "hello";
    const zip = try buildTestZip(std.testing.allocator, .{
        .method = .deflate,
        .compressed = &compressed,
        .uncompressed = contents,
        .crc32 = std.hash.Crc32.hash(contents),
    });
    defer std.testing.allocator.free(zip);

    var archive = try Archive.init(std.testing.allocator, zip);
    defer archive.deinit();
    const decoded = try archive.extractByName(std.testing.allocator, "a.txt");
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, contents, decoded);
}

test "parse Zip64 entry extra and Zip64 end records" {
    const contents = "hello";
    const zip = try buildTestZip(std.testing.allocator, .{
        .method = .store,
        .compressed = contents,
        .uncompressed = contents,
        .crc32 = std.hash.Crc32.hash(contents),
        .zip64_entry = true,
        .zip64_eocd = true,
    });
    defer std.testing.allocator.free(zip);

    var archive = try Archive.init(std.testing.allocator, zip);
    defer archive.deinit();
    const entry = archive.findEntry("a.txt") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(u64, 5), entry.compressed_size);
    try std.testing.expectEqual(@as(u64, 5), entry.uncompressed_size);
    try std.testing.expectEqual(@as(u64, 0), entry.local_header_offset);
}

test "reject truncated EOCD and an out-of-bounds central directory" {
    try std.testing.expectError(
        error.MissingEndOfCentralDirectory,
        Archive.init(std.testing.allocator, "not a zip"),
    );

    const contents = "hello";
    const zip = try buildTestZip(std.testing.allocator, .{
        .method = .store,
        .compressed = contents,
        .uncompressed = contents,
        .crc32 = std.hash.Crc32.hash(contents),
    });
    defer std.testing.allocator.free(zip);
    try std.testing.expectError(
        error.MissingEndOfCentralDirectory,
        Archive.init(std.testing.allocator, zip[0 .. zip.len - 1]),
    );

    const eocd_offset = zip.len - eocd_len;
    std.mem.writeInt(u32, zip[eocd_offset + 16 ..][0..4], 0xfffffff0, .little);
    try std.testing.expectError(
        error.InvalidCentralDirectoryBounds,
        Archive.init(std.testing.allocator, zip),
    );
}

test "reject malformed Zip64 extra and CRC mismatch" {
    const contents = "hello";
    const malformed = try buildTestZip(std.testing.allocator, .{
        .method = .store,
        .compressed = contents,
        .uncompressed = contents,
        .crc32 = std.hash.Crc32.hash(contents),
        .zip64_entry = true,
    });
    defer std.testing.allocator.free(malformed);
    const central_offset = local_header_len + "a.txt".len + contents.len;
    const zip64_extra_offset = central_offset + central_header_len + "a.txt".len;
    std.mem.writeInt(u16, malformed[zip64_extra_offset + 2 ..][0..2], 1, .little);
    try std.testing.expectError(
        error.MalformedZip64Extra,
        Archive.init(std.testing.allocator, malformed),
    );

    const bad_crc = try buildTestZip(std.testing.allocator, .{
        .method = .store,
        .compressed = contents,
        .uncompressed = contents,
        .crc32 = 0,
    });
    defer std.testing.allocator.free(bad_crc);
    var archive = try Archive.init(std.testing.allocator, bad_crc);
    defer archive.deinit();
    try std.testing.expectError(
        error.CrcMismatch,
        archive.extractByName(std.testing.allocator, "a.txt"),
    );
}
