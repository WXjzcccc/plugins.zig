const std = @import("std");

const Allocator = std.mem.Allocator;

pub const v2_block_id: u32 = 0x7109871a;
pub const v3_block_id: u32 = 0xf05368c0;
pub const v31_block_id: u32 = 0x1b93ad61;
pub const source_stamp_block_id: u32 = 0x6dff800d;
/// Older source-stamp block identifier accepted by Android's source stamp
/// tooling. Both identifiers are reported as `source_stamp` by the high-level
/// parser.
pub const source_stamp_v1_block_id: u32 = 0x2b09189e;

pub const magic = "APK Sig Block 42";

pub const Error = Allocator.Error || error{
    IntegerOverflow,
    CentralDirectoryOutOfBounds,
    MissingEndOfCentralDirectory,
    InvalidEndOfCentralDirectory,
    MissingZip64Locator,
    InvalidZip64Locator,
    InvalidZip64Record,
    InvalidBlockSize,
    BlockSizeMismatch,
    TruncatedPair,
    InvalidPairLength,
    TruncatedLengthPrefixedField,
    TrailingData,
    MissingSigner,
    InvalidSdkRange,
    SdkRangeMismatch,
};

pub const Pair = struct {
    id: u32,
    value: []const u8,
    encoded_length: u64,
};

pub const Block = struct {
    allocator: Allocator,
    offset: usize,
    size: u64,
    pairs: []Pair,

    pub fn deinit(self: *Block) void {
        if (self.pairs.len != 0) self.allocator.free(self.pairs);
        self.* = undefined;
    }
};

pub const Digest = struct {
    algorithm_id: u32,
    digest: []const u8,
};

pub const Signature = struct {
    algorithm_id: u32,
    signature: []const u8,
};

pub const AdditionalAttribute = struct {
    id: u32,
    value: []const u8,
};

/// All byte slices borrow the APK Signing Block pair value. The arrays
/// themselves are owned by `ParsedScheme`.
pub const Signer = struct {
    signed_data: []const u8,
    digests: []Digest,
    certificate_ders: [][]const u8,
    additional_attributes: []AdditionalAttribute,
    min_sdk: ?u32,
    max_sdk: ?u32,
    signatures: []Signature,
    public_key: []const u8,
};

pub const SchemeKind = enum {
    v2,
    v3,
    v31,
};

pub const ParsedScheme = struct {
    allocator: Allocator,
    kind: SchemeKind,
    signers: []Signer,

    pub fn deinit(self: *ParsedScheme) void {
        for (self.signers) |*signer| deinitSigner(self.allocator, signer);
        if (self.signers.len != 0) self.allocator.free(self.signers);
        self.* = undefined;
    }
};

pub const SourceStampVersion = enum {
    v1,
    v2,
};

pub const SourceStampSchemeSignatures = struct {
    signature_scheme_id: u32,
    signatures: []Signature,
};

pub const ParsedSourceStamp = struct {
    allocator: Allocator,
    version: SourceStampVersion,
    certificate_der: []const u8,
    /// V1 signs one digest set directly.
    direct_signatures: []Signature,
    /// V2 carries a signature set for each APK signature scheme digest.
    scheme_signatures: []SourceStampSchemeSignatures,
    attributes: []AdditionalAttribute,
    attribute_signatures: []Signature,

    pub fn deinit(self: *ParsedSourceStamp) void {
        if (self.direct_signatures.len != 0) self.allocator.free(self.direct_signatures);
        for (self.scheme_signatures) |scheme| {
            if (scheme.signatures.len != 0) self.allocator.free(scheme.signatures);
        }
        if (self.scheme_signatures.len != 0) self.allocator.free(self.scheme_signatures);
        if (self.attributes.len != 0) self.allocator.free(self.attributes);
        if (self.attribute_signatures.len != 0) self.allocator.free(self.attribute_signatures);
        self.* = undefined;
    }
};

pub fn isSourceStampId(id: u32) bool {
    return id == source_stamp_block_id or id == source_stamp_v1_block_id;
}

/// Locates and parses the APK Signing Block immediately before the central
/// directory. `null` means the magic footer is absent; a present-but-malformed
/// block is an error.
pub fn parse(
    allocator: Allocator,
    apk: []const u8,
    central_directory_offset: usize,
) Error!?Block {
    if (central_directory_offset > apk.len) return error.CentralDirectoryOutOfBounds;
    if (central_directory_offset < 24) return null;

    const magic_start = central_directory_offset - magic.len;
    if (!std.mem.eql(u8, apk[magic_start..central_directory_offset], magic)) return null;

    const footer_size_offset = magic_start - 8;
    const size = readLe(u64, apk[footer_size_offset..][0..8]);
    if (size < 24) return error.InvalidBlockSize;
    const total_size = std.math.add(u64, size, 8) catch return error.IntegerOverflow;
    if (total_size > central_directory_offset) return error.InvalidBlockSize;
    const total_size_usize = toUsize(total_size) catch return error.IntegerOverflow;
    const block_start = central_directory_offset - total_size_usize;
    if (block_start > footer_size_offset or footer_size_offset - block_start < 8) {
        return error.InvalidBlockSize;
    }
    const header_size = readLe(u64, apk[block_start..][0..8]);
    if (header_size != size) return error.BlockSizeMismatch;

    var pairs: std.ArrayList(Pair) = .empty;
    errdefer pairs.deinit(allocator);
    var position = block_start + 8;
    while (position < footer_size_offset) {
        if (footer_size_offset - position < 8) return error.TruncatedPair;
        const pair_length = readLe(u64, apk[position..][0..8]);
        position += 8;
        if (pair_length < 4) return error.InvalidPairLength;
        const pair_length_usize = toUsize(pair_length) catch return error.IntegerOverflow;
        if (pair_length_usize > footer_size_offset - position) return error.TruncatedPair;
        const pair_end = position + pair_length_usize;
        const id = readLe(u32, apk[position..][0..4]);
        try pairs.append(allocator, .{
            .id = id,
            .value = apk[position + 4 .. pair_end],
            .encoded_length = pair_length,
        });
        position = pair_end;
    }
    if (position != footer_size_offset) return error.TruncatedPair;

    return .{
        .allocator = allocator,
        .offset = block_start,
        .size = size,
        .pairs = try pairs.toOwnedSlice(allocator),
    };
}

/// Finds the central-directory offset from EOCD/ZIP64 metadata. Archive users
/// should prefer the already-validated first central entry offset when one is
/// available, and use this for empty archives.
pub fn findCentralDirectoryOffset(apk: []const u8) Error!usize {
    const eocd_offset = try findEocd(apk);
    const eocd = apk[eocd_offset..];
    const disk_number = readLe(u16, eocd[4..6]);
    const central_disk = readLe(u16, eocd[6..8]);
    const entry_count_disk = readLe(u16, eocd[8..10]);
    const entry_count_total = readLe(u16, eocd[10..12]);
    if (disk_number != 0 or central_disk != 0 or entry_count_disk != entry_count_total) {
        return error.InvalidEndOfCentralDirectory;
    }
    const central_size32 = readLe(u32, eocd[12..16]);
    const offset32 = readLe(u32, eocd[16..][0..4]);
    if (offset32 != std.math.maxInt(u32)) {
        if (central_size32 == std.math.maxInt(u32)) return error.InvalidEndOfCentralDirectory;
        const offset: usize = @intCast(offset32);
        const central_size: usize = @intCast(central_size32);
        if (offset > eocd_offset or central_size > eocd_offset - offset) {
            return error.InvalidEndOfCentralDirectory;
        }
        return offset;
    }

    if (eocd_offset < 20) return error.MissingZip64Locator;
    const locator = apk[eocd_offset - 20 .. eocd_offset];
    if (readLe(u32, locator[0..4]) != 0x07064b50) return error.InvalidZip64Locator;
    if (readLe(u32, locator[4..8]) != 0 or readLe(u32, locator[16..20]) != 1) {
        return error.InvalidZip64Locator;
    }
    const record_offset = toUsize(readLe(u64, locator[8..16])) catch return error.IntegerOverflow;
    if (record_offset > apk.len or apk.len - record_offset < 56) return error.InvalidZip64Record;
    const record = apk[record_offset..];
    if (readLe(u32, record[0..4]) != 0x06064b50) return error.InvalidZip64Record;
    const record_payload_size = readLe(u64, record[4..12]);
    if (record_payload_size < 44) return error.InvalidZip64Record;
    const record_total_size = std.math.add(u64, record_payload_size, 12) catch {
        return error.IntegerOverflow;
    };
    const record_total_usize = toUsize(record_total_size) catch return error.IntegerOverflow;
    if (record_total_usize > apk.len - record_offset) return error.InvalidZip64Record;
    return toUsize(readLe(u64, record[48..56])) catch error.IntegerOverflow;
}

/// Parses all v2/v3/v3.1 signer records in one recognized ID-value pair.
pub fn parseScheme(allocator: Allocator, kind: SchemeKind, value: []const u8) Error!ParsedScheme {
    var outer = LpReader.init(value);
    const signers_field = try outer.readLengthPrefixed();
    try outer.requireEnd();

    var signer_reader = LpReader.init(signers_field);
    var signers: std.ArrayList(Signer) = .empty;
    errdefer {
        for (signers.items) |*signer| deinitSigner(allocator, signer);
        signers.deinit(allocator);
    }

    while (!signer_reader.atEnd()) {
        const signer_bytes = try signer_reader.readLengthPrefixed();
        var signer = try parseSigner(allocator, kind, signer_bytes);
        errdefer deinitSigner(allocator, &signer);
        try signers.append(allocator, signer);
    }
    if (signers.items.len == 0) return error.MissingSigner;

    return .{
        .allocator = allocator,
        .kind = kind,
        .signers = try signers.toOwnedSlice(allocator),
    };
}

/// Parses the certificate and signature records of a v1 or v2 source stamp.
/// The returned byte slices borrow `value`; only the structural arrays are
/// allocated. This does not verify any source-stamp signature.
pub fn parseSourceStamp(
    allocator: Allocator,
    version: SourceStampVersion,
    value: []const u8,
) Error!ParsedSourceStamp {
    var result: ParsedSourceStamp = .{
        .allocator = allocator,
        .version = version,
        .certificate_der = &.{},
        .direct_signatures = &.{},
        .scheme_signatures = &.{},
        .attributes = &.{},
        .attribute_signatures = &.{},
    };
    errdefer result.deinit();

    var outer = LpReader.init(value);
    const stamp_block = try outer.readLengthPrefixed();
    try outer.requireEnd();

    var fields = LpReader.init(stamp_block);
    result.certificate_der = try fields.readLengthPrefixed();
    if (result.certificate_der.len == 0) return error.TruncatedLengthPrefixedField;

    switch (version) {
        .v1 => {
            result.direct_signatures = try parseSignatureSequence(
                allocator,
                try fields.readLengthPrefixed(),
            );
        },
        .v2 => {
            result.scheme_signatures = try parseSourceStampSchemeSignatures(
                allocator,
                try fields.readLengthPrefixed(),
            );
            if (!fields.atEnd()) {
                const encoded_attributes = try fields.readLengthPrefixed();
                result.attribute_signatures = try parseSignatureSequence(
                    allocator,
                    try fields.readLengthPrefixed(),
                );
                var attributes = LpReader.init(encoded_attributes);
                result.attributes = try parseAttributeSequence(
                    allocator,
                    try attributes.readLengthPrefixed(),
                );
                try attributes.requireEnd();
            }
        },
    }
    try fields.requireEnd();
    return result;
}

fn parseSourceStampSchemeSignatures(
    allocator: Allocator,
    encoded: []const u8,
) Error![]SourceStampSchemeSignatures {
    var fields = LpReader.init(encoded);
    var output: std.ArrayList(SourceStampSchemeSignatures) = .empty;
    errdefer {
        for (output.items) |scheme| {
            if (scheme.signatures.len != 0) allocator.free(scheme.signatures);
        }
        output.deinit(allocator);
    }
    while (!fields.atEnd()) {
        var record = LpReader.init(try fields.readLengthPrefixed());
        const signature_scheme_id = try record.readU32();
        const signatures = try parseSignatureSequence(
            allocator,
            try record.readLengthPrefixed(),
        );
        errdefer if (signatures.len != 0) allocator.free(signatures);
        try record.requireEnd();
        try output.append(allocator, .{
            .signature_scheme_id = signature_scheme_id,
            .signatures = signatures,
        });
    }
    return output.toOwnedSlice(allocator);
}

fn parseSigner(allocator: Allocator, kind: SchemeKind, encoded: []const u8) Error!Signer {
    var result: Signer = .{
        .signed_data = &.{},
        .digests = &.{},
        .certificate_ders = &.{},
        .additional_attributes = &.{},
        .min_sdk = null,
        .max_sdk = null,
        .signatures = &.{},
        .public_key = &.{},
    };
    errdefer deinitSigner(allocator, &result);

    var fields = LpReader.init(encoded);
    result.signed_data = try fields.readLengthPrefixed();

    var outer_min_sdk: ?u32 = null;
    var outer_max_sdk: ?u32 = null;
    if (kind != .v2) {
        outer_min_sdk = try fields.readU32();
        outer_max_sdk = try fields.readU32();
        if (outer_min_sdk.? > outer_max_sdk.?) return error.InvalidSdkRange;
    }
    const signatures_field = try fields.readLengthPrefixed();
    result.public_key = try fields.readLengthPrefixed();
    try fields.requireEnd();

    const signed = try parseSignedData(allocator, kind, result.signed_data);
    result.digests = signed.digests;
    result.certificate_ders = signed.certificate_ders;
    result.additional_attributes = signed.additional_attributes;
    result.min_sdk = signed.min_sdk;
    result.max_sdk = signed.max_sdk;

    if (kind != .v2 and
        (result.min_sdk != outer_min_sdk or result.max_sdk != outer_max_sdk))
    {
        return error.SdkRangeMismatch;
    }
    result.signatures = try parseSignatureSequence(allocator, signatures_field);
    return result;
}

const ParsedSignedData = struct {
    digests: []Digest,
    certificate_ders: [][]const u8,
    additional_attributes: []AdditionalAttribute,
    min_sdk: ?u32,
    max_sdk: ?u32,
};

fn parseSignedData(
    allocator: Allocator,
    kind: SchemeKind,
    encoded: []const u8,
) Error!ParsedSignedData {
    var result: ParsedSignedData = .{
        .digests = &.{},
        .certificate_ders = &.{},
        .additional_attributes = &.{},
        .min_sdk = null,
        .max_sdk = null,
    };
    errdefer {
        if (result.digests.len != 0) allocator.free(result.digests);
        if (result.certificate_ders.len != 0) allocator.free(result.certificate_ders);
        if (result.additional_attributes.len != 0) allocator.free(result.additional_attributes);
    }

    var fields = LpReader.init(encoded);
    result.digests = try parseDigestSequence(allocator, try fields.readLengthPrefixed());
    result.certificate_ders = try parseCertificateSequence(allocator, try fields.readLengthPrefixed());
    if (kind != .v2) {
        result.min_sdk = try fields.readU32();
        result.max_sdk = try fields.readU32();
        if (result.min_sdk.? > result.max_sdk.?) return error.InvalidSdkRange;
    }
    result.additional_attributes = try parseAttributeSequence(
        allocator,
        try fields.readLengthPrefixed(),
    );
    if (kind == .v2 and fields.remaining() == 4) {
        const trailing_reserved = try fields.readU32();
        if (trailing_reserved != 0) return error.TrailingData;
    }
    try fields.requireEnd();
    return result;
}

fn parseDigestSequence(allocator: Allocator, encoded: []const u8) Error![]Digest {
    var fields = LpReader.init(encoded);
    var output: std.ArrayList(Digest) = .empty;
    errdefer output.deinit(allocator);
    while (!fields.atEnd()) {
        var record = LpReader.init(try fields.readLengthPrefixed());
        const algorithm_id = try record.readU32();
        const digest = try record.readLengthPrefixed();
        try record.requireEnd();
        try output.append(allocator, .{ .algorithm_id = algorithm_id, .digest = digest });
    }
    return output.toOwnedSlice(allocator);
}

fn parseSignatureSequence(allocator: Allocator, encoded: []const u8) Error![]Signature {
    var fields = LpReader.init(encoded);
    var output: std.ArrayList(Signature) = .empty;
    errdefer output.deinit(allocator);
    while (!fields.atEnd()) {
        var record = LpReader.init(try fields.readLengthPrefixed());
        const algorithm_id = try record.readU32();
        const signature = try record.readLengthPrefixed();
        try record.requireEnd();
        try output.append(allocator, .{ .algorithm_id = algorithm_id, .signature = signature });
    }
    return output.toOwnedSlice(allocator);
}

fn parseCertificateSequence(allocator: Allocator, encoded: []const u8) Error![][]const u8 {
    var fields = LpReader.init(encoded);
    var output: std.ArrayList([]const u8) = .empty;
    errdefer output.deinit(allocator);
    while (!fields.atEnd()) {
        const certificate = try fields.readLengthPrefixed();
        if (certificate.len == 0) return error.TruncatedLengthPrefixedField;
        try output.append(allocator, certificate);
    }
    return output.toOwnedSlice(allocator);
}

fn parseAttributeSequence(allocator: Allocator, encoded: []const u8) Error![]AdditionalAttribute {
    var fields = LpReader.init(encoded);
    var output: std.ArrayList(AdditionalAttribute) = .empty;
    errdefer output.deinit(allocator);
    while (!fields.atEnd()) {
        var attribute = LpReader.init(try fields.readLengthPrefixed());
        const id = try attribute.readU32();
        const value = attribute.remainingBytes();
        attribute.position = attribute.data.len;
        try output.append(allocator, .{ .id = id, .value = value });
    }
    return output.toOwnedSlice(allocator);
}

fn deinitSigner(allocator: Allocator, signer: *Signer) void {
    if (signer.digests.len != 0) allocator.free(signer.digests);
    if (signer.certificate_ders.len != 0) allocator.free(signer.certificate_ders);
    if (signer.additional_attributes.len != 0) allocator.free(signer.additional_attributes);
    if (signer.signatures.len != 0) allocator.free(signer.signatures);
    signer.* = undefined;
}

const LpReader = struct {
    data: []const u8,
    position: usize = 0,

    fn init(data: []const u8) LpReader {
        return .{ .data = data };
    }

    fn atEnd(self: LpReader) bool {
        return self.position == self.data.len;
    }

    fn remaining(self: LpReader) usize {
        return self.data.len - self.position;
    }

    fn readU32(self: *LpReader) Error!u32 {
        if (self.data.len - self.position < 4) return error.TruncatedLengthPrefixedField;
        const value = readLe(u32, self.data[self.position..][0..4]);
        self.position += 4;
        return value;
    }

    fn readLengthPrefixed(self: *LpReader) Error![]const u8 {
        const length: usize = @intCast(try self.readU32());
        if (length > self.data.len - self.position) return error.TruncatedLengthPrefixedField;
        const start = self.position;
        self.position += length;
        return self.data[start..self.position];
    }

    fn remainingBytes(self: LpReader) []const u8 {
        return self.data[self.position..];
    }

    fn requireEnd(self: LpReader) Error!void {
        if (!self.atEnd()) return error.TrailingData;
    }
};

fn findEocd(apk: []const u8) Error!usize {
    if (apk.len < 22) return error.MissingEndOfCentralDirectory;
    const earliest = apk.len -| (22 + std.math.maxInt(u16));
    var offset = apk.len - 22;
    while (true) {
        if (readLe(u32, apk[offset..][0..4]) == 0x06054b50) {
            const comment_length = readLe(u16, apk[offset + 20 ..][0..2]);
            if (@as(usize, comment_length) == apk.len - offset - 22) return offset;
        }
        if (offset == earliest) break;
        offset -= 1;
    }
    return error.MissingEndOfCentralDirectory;
}

fn readLe(comptime T: type, bytes: []const u8) T {
    return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
}

fn toUsize(value: u64) error{IntegerOverflow}!usize {
    if (@bitSizeOf(usize) < 64 and value > std.math.maxInt(usize)) return error.IntegerOverflow;
    return @intCast(value);
}

fn appendInt(
    list: *std.ArrayList(u8),
    allocator: Allocator,
    comptime T: type,
    value: T,
) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    try list.appendSlice(allocator, &bytes);
}

fn appendLp(list: *std.ArrayList(u8), allocator: Allocator, value: []const u8) !void {
    try appendInt(list, allocator, u32, @intCast(value.len));
    try list.appendSlice(allocator, value);
}

fn buildTestSchemeValue(allocator: Allocator, kind: SchemeKind) ![]u8 {
    var digest_record: std.ArrayList(u8) = .empty;
    defer digest_record.deinit(allocator);
    try appendInt(&digest_record, allocator, u32, 0x0103);
    try appendLp(&digest_record, allocator, &.{ 0xaa, 0xbb });
    var digests: std.ArrayList(u8) = .empty;
    defer digests.deinit(allocator);
    try appendLp(&digests, allocator, digest_record.items);

    var certificates: std.ArrayList(u8) = .empty;
    defer certificates.deinit(allocator);
    try appendLp(&certificates, allocator, &.{ 0x30, 0x00 });

    var signed_data: std.ArrayList(u8) = .empty;
    defer signed_data.deinit(allocator);
    try appendLp(&signed_data, allocator, digests.items);
    try appendLp(&signed_data, allocator, certificates.items);
    if (kind != .v2) {
        try appendInt(&signed_data, allocator, u32, 24);
        try appendInt(&signed_data, allocator, u32, 35);
    }
    try appendLp(&signed_data, allocator, &.{});

    var signature_record: std.ArrayList(u8) = .empty;
    defer signature_record.deinit(allocator);
    try appendInt(&signature_record, allocator, u32, 0x0103);
    try appendLp(&signature_record, allocator, &.{0xcc});
    var signatures: std.ArrayList(u8) = .empty;
    defer signatures.deinit(allocator);
    try appendLp(&signatures, allocator, signature_record.items);

    var signer: std.ArrayList(u8) = .empty;
    defer signer.deinit(allocator);
    try appendLp(&signer, allocator, signed_data.items);
    if (kind != .v2) {
        try appendInt(&signer, allocator, u32, 24);
        try appendInt(&signer, allocator, u32, 35);
    }
    try appendLp(&signer, allocator, signatures.items);
    try appendLp(&signer, allocator, &.{ 0x01, 0x02, 0x03 });

    var signers: std.ArrayList(u8) = .empty;
    defer signers.deinit(allocator);
    try appendLp(&signers, allocator, signer.items);
    try appendLp(&signers, allocator, signer.items);

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try appendLp(&result, allocator, signers.items);
    return result.toOwnedSlice(allocator);
}

fn buildTestBlock(allocator: Allocator, id: u32, value: []const u8) ![]u8 {
    var pair: std.ArrayList(u8) = .empty;
    defer pair.deinit(allocator);
    try appendInt(&pair, allocator, u64, @as(u64, value.len) + 4);
    try appendInt(&pair, allocator, u32, id);
    try pair.appendSlice(allocator, value);
    try appendInt(&pair, allocator, u64, 4);
    try appendInt(&pair, allocator, u32, 0xdeadbeef);

    const size: u64 = pair.items.len + 24;
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try appendInt(&result, allocator, u64, size);
    try result.appendSlice(allocator, pair.items);
    try appendInt(&result, allocator, u64, size);
    try result.appendSlice(allocator, magic);
    return result.toOwnedSlice(allocator);
}

test "APK Signing Block validates both sizes and exposes all pairs" {
    const encoded = try buildTestBlock(std.testing.allocator, v2_block_id, "value");
    defer std.testing.allocator.free(encoded);

    var block = (try parse(std.testing.allocator, encoded, encoded.len)).?;
    defer block.deinit();
    try std.testing.expectEqual(@as(usize, 2), block.pairs.len);
    try std.testing.expectEqual(v2_block_id, block.pairs[0].id);
    try std.testing.expectEqualSlices(u8, "value", block.pairs[0].value);
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), block.pairs[1].id);
    try std.testing.expectEqual(@as(usize, 0), block.pairs[1].value.len);

    var malformed = try std.testing.allocator.dupe(u8, encoded);
    defer std.testing.allocator.free(malformed);
    malformed[0] ^= 1;
    try std.testing.expectError(
        error.BlockSizeMismatch,
        parse(std.testing.allocator, malformed, malformed.len),
    );
}

test "v2 and v3 signer records preserve signed data, algorithms, key, cert, and SDK range" {
    inline for (.{ SchemeKind.v2, SchemeKind.v3, SchemeKind.v31 }) |kind| {
        const encoded = try buildTestSchemeValue(std.testing.allocator, kind);
        defer std.testing.allocator.free(encoded);
        var parsed = try parseScheme(std.testing.allocator, kind, encoded);
        defer parsed.deinit();

        try std.testing.expectEqual(@as(usize, 2), parsed.signers.len);
        const signer = parsed.signers[0];
        try std.testing.expect(signer.signed_data.len != 0);
        try std.testing.expectEqual(@as(u32, 0x0103), signer.digests[0].algorithm_id);
        try std.testing.expectEqual(@as(u32, 0x0103), signer.signatures[0].algorithm_id);
        try std.testing.expectEqualSlices(u8, &.{ 0x30, 0x00 }, signer.certificate_ders[0]);
        try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, signer.public_key);
        if (kind == .v2) {
            try std.testing.expectEqual(@as(?u32, null), signer.min_sdk);
        } else {
            try std.testing.expectEqual(@as(?u32, 24), signer.min_sdk);
            try std.testing.expectEqual(@as(?u32, 35), signer.max_sdk);
        }
    }
}

test "length-prefixed signer parsing rejects truncation" {
    const encoded = try buildTestSchemeValue(std.testing.allocator, .v2);
    defer std.testing.allocator.free(encoded);
    try std.testing.expectError(
        error.TruncatedLengthPrefixedField,
        parseScheme(std.testing.allocator, .v2, encoded[0 .. encoded.len - 1]),
    );
}

test "v2 source stamp exposes its certificate, per-scheme signatures, and attributes" {
    var signature_record: std.ArrayList(u8) = .empty;
    defer signature_record.deinit(std.testing.allocator);
    try appendInt(&signature_record, std.testing.allocator, u32, 0x0103);
    try appendLp(&signature_record, std.testing.allocator, &.{0xaa});
    var signatures: std.ArrayList(u8) = .empty;
    defer signatures.deinit(std.testing.allocator);
    try appendLp(&signatures, std.testing.allocator, signature_record.items);

    var scheme_record: std.ArrayList(u8) = .empty;
    defer scheme_record.deinit(std.testing.allocator);
    try appendInt(&scheme_record, std.testing.allocator, u32, 3);
    try appendLp(&scheme_record, std.testing.allocator, signatures.items);
    var schemes: std.ArrayList(u8) = .empty;
    defer schemes.deinit(std.testing.allocator);
    try appendLp(&schemes, std.testing.allocator, scheme_record.items);

    var attribute_record: std.ArrayList(u8) = .empty;
    defer attribute_record.deinit(std.testing.allocator);
    try appendInt(&attribute_record, std.testing.allocator, u32, 0xe43c5946);
    try attribute_record.appendSlice(std.testing.allocator, &.{ 1, 2, 3, 4 });
    var attributes_sequence: std.ArrayList(u8) = .empty;
    defer attributes_sequence.deinit(std.testing.allocator);
    try appendLp(&attributes_sequence, std.testing.allocator, attribute_record.items);
    var encoded_attributes: std.ArrayList(u8) = .empty;
    defer encoded_attributes.deinit(std.testing.allocator);
    try appendLp(&encoded_attributes, std.testing.allocator, attributes_sequence.items);

    var stamp: std.ArrayList(u8) = .empty;
    defer stamp.deinit(std.testing.allocator);
    try appendLp(&stamp, std.testing.allocator, &.{ 0x30, 0x00 });
    try appendLp(&stamp, std.testing.allocator, schemes.items);
    try appendLp(&stamp, std.testing.allocator, encoded_attributes.items);
    try appendLp(&stamp, std.testing.allocator, signatures.items);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try appendLp(&encoded, std.testing.allocator, stamp.items);

    var parsed = try parseSourceStamp(std.testing.allocator, .v2, encoded.items);
    defer parsed.deinit();
    try std.testing.expectEqualSlices(u8, &.{ 0x30, 0x00 }, parsed.certificate_der);
    try std.testing.expectEqual(@as(usize, 1), parsed.scheme_signatures.len);
    try std.testing.expectEqual(@as(u32, 3), parsed.scheme_signatures[0].signature_scheme_id);
    try std.testing.expectEqual(@as(u32, 0x0103), parsed.scheme_signatures[0].signatures[0].algorithm_id);
    try std.testing.expectEqual(@as(usize, 1), parsed.attributes.len);
    try std.testing.expectEqual(@as(u32, 0xe43c5946), parsed.attributes[0].id);
    try std.testing.expectEqual(@as(usize, 1), parsed.attribute_signatures.len);
}
