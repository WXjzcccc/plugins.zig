const std = @import("std");
const apk_block = @import("apk_block.zig");
const cms = @import("cms.zig");
const limits_mod = @import("../limits.zig");
const model = @import("../model.zig");
const x509 = @import("x509.zig");
const zip = @import("../../utils/zip/archive.zig");
const logging = @import("../../utils/logging.zig");

const log = logging.scoped(.apk_signing);

const Allocator = std.mem.Allocator;

pub const ParseError = apk_block.Error || cms.ParseError || x509.ParseError || zip.ExtractError;

pub const ParseOptions = struct {
    /// Hard cap applied before inflating each META-INF signature container.
    max_v1_entry_size: u64 = 64 * 1024 * 1024,
    max_signers: usize = 4096,
    max_certificates_per_signer: usize = 4096,
    max_der_nodes_per_certificate: usize = 1_000_000,
    max_der_depth: usize = 64,

    pub fn fromLimits(limits: limits_mod.Limits) ParseOptions {
        return .{
            .max_v1_entry_size = @min(
                @as(u64, @intCast(limits.max_entry_uncompressed_size)),
                64 * 1024 * 1024,
            ),
            .max_signers = @min(limits.max_der_nodes, 4096),
            .max_certificates_per_signer = @min(limits.max_der_nodes, 4096),
            .max_der_nodes_per_certificate = limits.max_der_nodes,
            .max_der_depth = limits.max_der_depth,
        };
    }
};

/// Parses APK v1/v2/v3/v3.1/source-stamp signing structures into the shared
/// model. All reachable slices are owned by `allocator`.
///
/// This function performs no cryptographic verification. In particular,
/// `cryptographic_verification_performed` is always false even when all
/// structures are well formed.
pub fn parse(allocator: Allocator, archive: *const zip.Archive) ParseError!model.SigningInfo {
    return parseWithOptions(allocator, archive, .{});
}

pub fn parseWithOptions(
    allocator: Allocator,
    archive: *const zip.Archive,
    options: ParseOptions,
) ParseError!model.SigningInfo {
    return parseWithOptionsImpl(allocator, archive, options) catch |err| {
        log.err(@src(), "signature parsing failed archive_entries={d} error={s}", .{ archive.entries.len, @errorName(err) });
        return err;
    };
}

fn parseWithOptionsImpl(
    allocator: Allocator,
    archive: *const zip.Archive,
    options: ParseOptions,
) ParseError!model.SigningInfo {
    log.info(@src(), "signature parsing started archive_entries={d}", .{archive.entries.len});
    var info: model.SigningInfo = .{};
    var signers: std.ArrayList(model.Signer) = .empty;
    errdefer {
        for (signers.items) |*signer| deinitSigner(allocator, signer);
        signers.deinit(allocator);
    }

    const central_directory_offset = try apk_block.findCentralDirectoryOffset(archive.data);
    log.debug(@src(), "APK signing block lookup central_directory_offset={d}", .{central_directory_offset});
    if (try apk_block.parse(allocator, archive.data, central_directory_offset)) |parsed_value| {
        var block = parsed_value;
        defer block.deinit();

        for (block.pairs) |pair| {
            switch (pair.id) {
                apk_block.v2_block_id => {
                    info.has_v2 = true;
                    log.info(@src(), "APK Signature Scheme v2 block found", .{});
                    try appendScheme(allocator, .v2, .apk_v2, pair.value, options, &signers);
                },
                apk_block.v3_block_id => {
                    info.has_v3 = true;
                    log.info(@src(), "APK Signature Scheme v3 block found", .{});
                    try appendScheme(allocator, .v3, .apk_v3, pair.value, options, &signers);
                },
                apk_block.v31_block_id => {
                    info.has_v31 = true;
                    log.info(@src(), "APK Signature Scheme v3.1 block found", .{});
                    try appendScheme(allocator, .v31, .apk_v31, pair.value, options, &signers);
                },
                apk_block.source_stamp_block_id, apk_block.source_stamp_v1_block_id => {
                    info.has_source_stamp = true;
                    log.info(@src(), "APK source stamp block found", .{});
                    const version: apk_block.SourceStampVersion = if (pair.id == apk_block.source_stamp_block_id)
                        .v2
                    else
                        .v1;
                    if (signers.items.len >= options.max_signers) return error.InvalidPairLength;
                    try appendSourceStamp(allocator, version, pair.value, options, &signers);
                },
                else => {},
            }
        }
    }

    var v1_entry_count: usize = 0;
    for (archive.entries) |entry| {
        if (!isV1SignatureEntry(entry.name) or entry.isDirectory()) continue;
        log.debug(@src(), "JAR v1 signature container found entry={s}", .{entry.name});
        v1_entry_count += 1;
        if (v1_entry_count > options.max_signers) return error.InvalidSignedData;
        if (entry.uncompressed_size > options.max_v1_entry_size) return error.OutputTooLarge;
    }

    for (archive.entries, 0..) |entry, index| {
        if (!isV1SignatureEntry(entry.name) or entry.isDirectory()) continue;
        const encoded = try archive.extractAlloc(
            allocator,
            &archive.entries[index],
            .{ .max_output_size = options.max_v1_entry_size },
        );
        defer allocator.free(encoded);

        if (signers.items.len >= options.max_signers) return error.InvalidSignedData;
        const certificates = try cms.parseCertificatesWithOptions(
            allocator,
            encoded,
            .{
                .max_certificates = options.max_certificates_per_signer,
                .max_der_nodes_per_certificate = options.max_der_nodes_per_certificate,
                .max_der_depth = options.max_der_depth,
            },
        );
        var signer: model.Signer = .{
            .scheme = .jar_v1,
            .certificates = certificates,
        };
        errdefer deinitSigner(allocator, &signer);
        try signers.append(allocator, signer);
        info.has_v1 = true;
    }

    info.signers = try signers.toOwnedSlice(allocator);
    info.cryptographic_verification_performed = false;
    log.info(@src(), "signature parsing completed signers={d} v1={} v2={} v3={} v31={} source_stamp={}", .{
        info.signers.len,
        info.has_v1,
        info.has_v2,
        info.has_v3,
        info.has_v31,
        info.has_source_stamp,
    });
    return info;
}

pub fn deinitSigningInfo(allocator: Allocator, info: *model.SigningInfo) void {
    const mutable_signers = @constCast(info.signers);
    for (mutable_signers) |*signer| deinitSigner(allocator, signer);
    if (mutable_signers.len != 0) allocator.free(mutable_signers);
    info.* = undefined;
}

pub fn isV1SignatureEntry(name: []const u8) bool {
    const prefix = "META-INF/";
    if (name.len <= prefix.len or !startsWithIgnoreCase(name, prefix)) return false;
    const leaf = name[prefix.len..];
    if (std.mem.indexOfScalar(u8, leaf, '/')) |_| return false;
    return endsWithIgnoreCase(leaf, ".RSA") or
        endsWithIgnoreCase(leaf, ".DSA") or
        endsWithIgnoreCase(leaf, ".EC");
}

fn appendScheme(
    allocator: Allocator,
    kind: apk_block.SchemeKind,
    model_scheme: model.SignatureScheme,
    encoded: []const u8,
    options: ParseOptions,
    output: *std.ArrayList(model.Signer),
) ParseError!void {
    var parsed = try apk_block.parseScheme(allocator, kind, encoded);
    defer parsed.deinit();

    for (parsed.signers) |parsed_signer| {
        if (output.items.len >= options.max_signers or
            parsed_signer.certificate_ders.len > options.max_certificates_per_signer)
        {
            return error.InvalidPairLength;
        }
        var certificates: std.ArrayList(model.Certificate) = .empty;
        errdefer {
            for (certificates.items) |*certificate| x509.deinitCertificate(allocator, certificate);
            certificates.deinit(allocator);
        }
        for (parsed_signer.certificate_ders) |certificate_der| {
            var certificate = try x509.parseCertificateWithOptions(
                allocator,
                certificate_der,
                .{
                    .max_der_nodes = options.max_der_nodes_per_certificate,
                    .max_der_depth = options.max_der_depth,
                },
            );
            errdefer x509.deinitCertificate(allocator, &certificate);
            try certificates.append(allocator, certificate);
        }

        var signer: model.Signer = .{
            .scheme = model_scheme,
            .min_sdk = parsed_signer.min_sdk,
            .max_sdk = parsed_signer.max_sdk,
        };
        errdefer deinitSigner(allocator, &signer);
        signer.certificates = try certificates.toOwnedSlice(allocator);
        signer.signature_algorithm_ids = try copySignatureAlgorithms(allocator, parsed_signer.signatures);
        signer.digest_algorithm_ids = try copyDigestAlgorithms(allocator, parsed_signer.digests);
        try output.append(allocator, signer);
    }
}

fn appendSourceStamp(
    allocator: Allocator,
    version: apk_block.SourceStampVersion,
    encoded: []const u8,
    options: ParseOptions,
    output: *std.ArrayList(model.Signer),
) ParseError!void {
    var parsed = try apk_block.parseSourceStamp(allocator, version, encoded);
    defer parsed.deinit();

    var signer: model.Signer = .{ .scheme = .source_stamp };
    errdefer deinitSigner(allocator, &signer);

    const certificates = try allocator.alloc(model.Certificate, 1);
    certificates[0] = x509.parseCertificateWithOptions(
        allocator,
        parsed.certificate_der,
        .{
            .max_der_nodes = options.max_der_nodes_per_certificate,
            .max_der_depth = options.max_der_depth,
        },
    ) catch |err| {
        log.warn(@src(), "source-stamp certificate metadata parsing failed certificate_bytes={d} error={s}", .{ parsed.certificate_der.len, @errorName(err) });
        allocator.free(certificates);
        return err;
    };
    signer.certificates = certificates;

    var signature_algorithms: std.ArrayList(u32) = .empty;
    errdefer signature_algorithms.deinit(allocator);
    for (parsed.direct_signatures) |signature| {
        try signature_algorithms.append(allocator, signature.algorithm_id);
    }
    for (parsed.scheme_signatures) |scheme| {
        for (scheme.signatures) |signature| {
            try signature_algorithms.append(allocator, signature.algorithm_id);
        }
    }
    for (parsed.attribute_signatures) |signature| {
        try signature_algorithms.append(allocator, signature.algorithm_id);
    }
    signer.signature_algorithm_ids = try signature_algorithms.toOwnedSlice(allocator);
    try output.append(allocator, signer);
}

fn copySignatureAlgorithms(allocator: Allocator, values: []const apk_block.Signature) Allocator.Error![]u32 {
    if (values.len == 0) return &.{};
    const output = try allocator.alloc(u32, values.len);
    for (values, 0..) |value, index| output[index] = value.algorithm_id;
    return output;
}

fn copyDigestAlgorithms(allocator: Allocator, values: []const apk_block.Digest) Allocator.Error![]u32 {
    if (values.len == 0) return &.{};
    const output = try allocator.alloc(u32, values.len);
    for (values, 0..) |value, index| output[index] = value.algorithm_id;
    return output;
}

fn deinitSigner(allocator: Allocator, signer: *model.Signer) void {
    const certificates = @constCast(signer.certificates);
    for (certificates) |*certificate| x509.deinitCertificate(allocator, certificate);
    if (certificates.len != 0) allocator.free(certificates);
    if (signer.signature_algorithm_ids.len != 0) allocator.free(signer.signature_algorithm_ids);
    if (signer.digest_algorithm_ids.len != 0) allocator.free(signer.digest_algorithm_ids);
    signer.* = undefined;
}

fn startsWithIgnoreCase(value: []const u8, prefix: []const u8) bool {
    if (value.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(value[0..prefix.len], prefix);
}

fn endsWithIgnoreCase(value: []const u8, suffix: []const u8) bool {
    if (value.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(value[value.len - suffix.len ..], suffix);
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

fn buildSourceStampApk(allocator: Allocator) ![]u8 {
    var signature_record: std.ArrayList(u8) = .empty;
    defer signature_record.deinit(allocator);
    try appendInt(&signature_record, allocator, u32, 0x0103);
    try appendLp(&signature_record, allocator, &.{ 0xaa, 0xbb });
    var signatures: std.ArrayList(u8) = .empty;
    defer signatures.deinit(allocator);
    try appendLp(&signatures, allocator, signature_record.items);

    var stamp: std.ArrayList(u8) = .empty;
    defer stamp.deinit(allocator);
    try appendLp(&stamp, allocator, &x509.test_certificate_der);
    try appendLp(&stamp, allocator, signatures.items);
    var pair_value: std.ArrayList(u8) = .empty;
    defer pair_value.deinit(allocator);
    try appendLp(&pair_value, allocator, stamp.items);

    const pair_size: u64 = 4 + pair_value.items.len;
    const block_size: u64 = 8 + pair_size + 24;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try appendInt(&output, allocator, u64, block_size);
    try appendInt(&output, allocator, u64, pair_size);
    try appendInt(&output, allocator, u32, apk_block.source_stamp_v1_block_id);
    try output.appendSlice(allocator, pair_value.items);
    try appendInt(&output, allocator, u64, block_size);
    try output.appendSlice(allocator, apk_block.magic);

    const central_directory_offset: u32 = @intCast(output.items.len);
    try appendInt(&output, allocator, u32, 0x06054b50);
    try appendInt(&output, allocator, u16, 0);
    try appendInt(&output, allocator, u16, 0);
    try appendInt(&output, allocator, u16, 0);
    try appendInt(&output, allocator, u16, 0);
    try appendInt(&output, allocator, u32, 0);
    try appendInt(&output, allocator, u32, central_directory_offset);
    try appendInt(&output, allocator, u16, 0);
    return output.toOwnedSlice(allocator);
}

test "high-level parser recognizes source stamp without claiming verification" {
    const encoded = try buildSourceStampApk(std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    var archive = try zip.Archive.init(std.testing.allocator, encoded);
    defer archive.deinit();

    var info = try parse(std.testing.allocator, &archive);
    defer deinitSigningInfo(std.testing.allocator, &info);
    try std.testing.expect(info.has_source_stamp);
    try std.testing.expect(!info.cryptographic_verification_performed);
    try std.testing.expectEqual(@as(usize, 1), info.signers.len);
    try std.testing.expectEqual(model.SignatureScheme.source_stamp, info.signers[0].scheme);
    try std.testing.expectEqual(@as(usize, 1), info.signers[0].certificates.len);
    try std.testing.expectEqualStrings("Apps", info.signers[0].certificates[0].subject.common_name.?);
    try std.testing.expectEqualSlices(u32, &.{0x0103}, info.signers[0].signature_algorithm_ids);
}

test "v1 signature entry matching is exact and ASCII case-insensitive" {
    try std.testing.expect(isV1SignatureEntry("META-INF/CERT.RSA"));
    try std.testing.expect(isV1SignatureEntry("meta-inf/sign.ec"));
    try std.testing.expect(!isV1SignatureEntry("META-INF/CERT.SF"));
    try std.testing.expect(!isV1SignatureEntry("assets/META-INF/CERT.RSA"));
    try std.testing.expect(!isV1SignatureEntry("META-INF/nested/CERT.RSA"));
}

test "v1 extraction obeys the configured inflation cap" {
    const name = "META-INF/CERT.RSA";
    const payload = "0123456789";
    var local: std.ArrayList(u8) = .empty;
    defer local.deinit(std.testing.allocator);
    try appendInt(&local, std.testing.allocator, u32, 0x04034b50);
    try appendInt(&local, std.testing.allocator, u16, 20);
    try appendInt(&local, std.testing.allocator, u16, 0);
    try appendInt(&local, std.testing.allocator, u16, @backingInt(zip.CompressionMethod.store));
    try appendInt(&local, std.testing.allocator, u16, 0);
    try appendInt(&local, std.testing.allocator, u16, 0);
    try appendInt(&local, std.testing.allocator, u32, std.hash.Crc32.hash(payload));
    try appendInt(&local, std.testing.allocator, u32, payload.len);
    try appendInt(&local, std.testing.allocator, u32, payload.len);
    try appendInt(&local, std.testing.allocator, u16, name.len);
    try appendInt(&local, std.testing.allocator, u16, 0);
    try local.appendSlice(std.testing.allocator, name);
    try local.appendSlice(std.testing.allocator, payload);
    const central_directory_offset = local.items.len;
    try appendInt(&local, std.testing.allocator, u32, 0x06054b50);
    try appendInt(&local, std.testing.allocator, u16, 0);
    try appendInt(&local, std.testing.allocator, u16, 0);
    try appendInt(&local, std.testing.allocator, u16, 0);
    try appendInt(&local, std.testing.allocator, u16, 0);
    try appendInt(&local, std.testing.allocator, u32, 0);
    try appendInt(&local, std.testing.allocator, u32, @intCast(central_directory_offset));
    try appendInt(&local, std.testing.allocator, u16, 0);

    var entries = [_]zip.Entry{.{
        .name = name,
        .method = .store,
        .flags = 0,
        .crc32 = std.hash.Crc32.hash(payload),
        .compressed_size = payload.len,
        .uncompressed_size = payload.len,
        .local_header_offset = 0,
        .central_header_offset = central_directory_offset,
    }};
    const archive: zip.Archive = .{
        .allocator = std.testing.allocator,
        .data = local.items,
        .entries = &entries,
    };
    try std.testing.expectError(
        error.OutputTooLarge,
        parseWithOptions(std.testing.allocator, &archive, .{ .max_v1_entry_size = 1 }),
    );
}
