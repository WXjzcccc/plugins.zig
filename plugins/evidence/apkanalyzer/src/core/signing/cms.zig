const std = @import("std");
const der = @import("der.zig");
const model = @import("../model.zig");
const x509 = @import("x509.zig");

const Allocator = std.mem.Allocator;

pub const Options = struct {
    max_certificates: usize = 4096,
    max_der_nodes_per_certificate: usize = 1_000_000,
    max_der_depth: usize = 64,
};

pub const ParseError = Allocator.Error || der.Error || x509.ParseError || error{
    NotSignedData,
    InvalidSignedData,
};

const signed_data_oid = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02 };

/// Extracts every ordinary X.509 Certificate choice from a CMS SignedData
/// ContentInfo. Other CertificateChoices are skipped, as they are not X.509
/// certificates representable by `model.Certificate`.
///
/// No CMS signature, message digest, or certificate chain is verified.
pub fn parseCertificates(allocator: Allocator, encoded: []const u8) ParseError![]model.Certificate {
    return parseCertificatesWithOptions(allocator, encoded, .{});
}

pub fn parseCertificatesWithOptions(
    allocator: Allocator,
    encoded: []const u8,
    options: Options,
) ParseError![]model.Certificate {
    const content_info = try der.parseSingle(encoded);
    try content_info.expectUniversal(.sequence, true);
    var content_info_fields = content_info.children();

    const content_type = try content_info_fields.requireNext();
    try content_type.expectUniversal(.object_identifier, false);
    if (!std.mem.eql(u8, content_type.content, &signed_data_oid)) return error.NotSignedData;

    const explicit_content = try content_info_fields.requireNext();
    if (explicit_content.class != .context_specific or
        explicit_content.tag_number != 0 or
        !explicit_content.constructed)
    {
        return error.InvalidSignedData;
    }
    try content_info_fields.requireEnd();

    var explicit_fields = explicit_content.children();
    const signed_data = try explicit_fields.requireNext();
    try explicit_fields.requireEnd();
    try signed_data.expectUniversal(.sequence, true);

    var fields = signed_data.children();
    const version = try fields.requireNext();
    try version.expectUniversal(.integer, false);
    if (version.content.len == 0) return error.InvalidSignedData;

    const digest_algorithms = try fields.requireNext();
    try digest_algorithms.expectUniversal(.set, true);
    try validateAlgorithmSet(allocator, digest_algorithms);

    const encapsulated_content_info = try fields.requireNext();
    try validateEncapsulatedContentInfo(encapsulated_content_info);

    var certificates: std.ArrayList(model.Certificate) = .empty;
    errdefer {
        for (certificates.items) |*certificate| x509.deinitCertificate(allocator, certificate);
        certificates.deinit(allocator);
    }

    var saw_certificates = false;
    var saw_revocations = false;
    var saw_signer_infos = false;
    while (try fields.next()) |field| {
        if (field.class == .context_specific and field.tag_number == 0 and field.constructed) {
            if (saw_certificates or saw_revocations or saw_signer_infos) return error.InvalidSignedData;
            saw_certificates = true;
            try appendCertificateSet(allocator, field, options, &certificates);
        } else if (field.class == .context_specific and field.tag_number == 1 and field.constructed) {
            if (saw_revocations or saw_signer_infos) return error.InvalidSignedData;
            saw_revocations = true;
            // RevocationInfoChoices is intentionally not interpreted.
            var revocations = field.children();
            while (try revocations.next()) |_| {}
        } else if (field.class == .universal and
            field.tag_number == @backingInt(der.UniversalTag.set) and
            field.constructed)
        {
            if (saw_signer_infos) return error.InvalidSignedData;
            saw_signer_infos = true;
            // Consume all SignerInfo values to enforce their DER boundaries.
            var signer_infos = field.children();
            while (try signer_infos.next()) |signer_info| {
                try signer_info.expectUniversal(.sequence, true);
            }
        } else {
            return error.InvalidSignedData;
        }
    }
    if (!saw_signer_infos) return error.InvalidSignedData;

    return certificates.toOwnedSlice(allocator);
}

pub fn deinitCertificates(allocator: Allocator, certificates: []model.Certificate) void {
    x509.deinitCertificates(allocator, certificates);
}

fn validateAlgorithmSet(allocator: Allocator, element: der.Element) ParseError!void {
    var algorithms = element.children();
    while (try algorithms.next()) |algorithm| {
        try algorithm.expectUniversal(.sequence, true);
        var fields = algorithm.children();
        const oid = try fields.requireNext();
        try oid.expectUniversal(.object_identifier, false);
        const decoded = try der.decodeOidAlloc(allocator, oid.content);
        allocator.free(decoded);
        if (try fields.next()) |_| {
            if ((try fields.next()) != null) return error.InvalidSignedData;
        }
    }
}

fn validateEncapsulatedContentInfo(element: der.Element) ParseError!void {
    try element.expectUniversal(.sequence, true);
    var fields = element.children();
    const content_type = try fields.requireNext();
    try content_type.expectUniversal(.object_identifier, false);

    if (try fields.next()) |content| {
        if (content.class != .context_specific or content.tag_number != 0 or !content.constructed) {
            return error.InvalidSignedData;
        }
        var explicit_fields = content.children();
        const octets = try explicit_fields.requireNext();
        try octets.expectUniversal(.octet_string, false);
        try explicit_fields.requireEnd();
    }
    try fields.requireEnd();
}

fn appendCertificateSet(
    allocator: Allocator,
    certificate_set: der.Element,
    options: Options,
    output: *std.ArrayList(model.Certificate),
) ParseError!void {
    // CertificateSet is IMPLICIT, so its content is the concatenation of
    // CertificateChoices rather than an inner SET element.
    var choices = certificate_set.children();
    while (try choices.next()) |choice| {
        if (choice.class != .universal or
            choice.tag_number != @backingInt(der.UniversalTag.sequence) or
            !choice.constructed)
        {
            // Extended/attribute/other certificate choices use context tags.
            if (choice.class != .context_specific) return error.InvalidSignedData;
            continue;
        }

        if (output.items.len >= options.max_certificates) return error.InvalidSignedData;

        var certificate = try x509.parseCertificateWithOptions(
            allocator,
            choice.encoded,
            .{
                .max_der_nodes = options.max_der_nodes_per_certificate,
                .max_der_depth = options.max_der_depth,
            },
        );
        errdefer x509.deinitCertificate(allocator, &certificate);
        try output.append(allocator, certificate);
    }
}

fn appendDerLength(list: *std.ArrayList(u8), allocator: Allocator, length: usize) !void {
    if (length < 128) {
        try list.append(allocator, @intCast(length));
        return;
    }
    if (length <= 0xff) {
        try list.appendSlice(allocator, &.{ 0x81, @intCast(length) });
        return;
    }
    try list.appendSlice(allocator, &.{
        0x82,
        @intCast((length >> 8) & 0xff),
        @intCast(length & 0xff),
    });
}

fn appendDer(
    list: *std.ArrayList(u8),
    allocator: Allocator,
    tag: u8,
    content: []const u8,
) !void {
    try list.append(allocator, tag);
    try appendDerLength(list, allocator, content.len);
    try list.appendSlice(allocator, content);
}

fn buildTestCms(allocator: Allocator) ![]u8 {
    var certificate_set_content: std.ArrayList(u8) = .empty;
    defer certificate_set_content.deinit(allocator);
    try certificate_set_content.appendSlice(allocator, &x509.test_certificate_der);
    try certificate_set_content.appendSlice(allocator, &x509.test_certificate_der);

    var certificate_set: std.ArrayList(u8) = .empty;
    defer certificate_set.deinit(allocator);
    try appendDer(&certificate_set, allocator, 0xa0, certificate_set_content.items);

    var signed_data_content: std.ArrayList(u8) = .empty;
    defer signed_data_content.deinit(allocator);
    try signed_data_content.appendSlice(allocator, &.{ 0x02, 0x01, 0x01 });
    try signed_data_content.appendSlice(allocator, &.{ 0x31, 0x00 });
    try signed_data_content.appendSlice(allocator, &.{
        0x30, 0x0b, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x07,
        0x01,
    });
    try signed_data_content.appendSlice(allocator, certificate_set.items);
    try signed_data_content.appendSlice(allocator, &.{ 0x31, 0x00 });

    var signed_data: std.ArrayList(u8) = .empty;
    defer signed_data.deinit(allocator);
    try appendDer(&signed_data, allocator, 0x30, signed_data_content.items);

    var explicit_content: std.ArrayList(u8) = .empty;
    defer explicit_content.deinit(allocator);
    try appendDer(&explicit_content, allocator, 0xa0, signed_data.items);

    var content_info_fields: std.ArrayList(u8) = .empty;
    defer content_info_fields.deinit(allocator);
    try content_info_fields.appendSlice(allocator, &.{
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    });
    try content_info_fields.appendSlice(allocator, explicit_content.items);

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try appendDer(&result, allocator, 0x30, content_info_fields.items);
    return result.toOwnedSlice(allocator);
}

test "CMS SignedData extracts every X.509 certificate choice" {
    const encoded = try buildTestCms(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    const certificates = try parseCertificates(std.testing.allocator, encoded);
    defer deinitCertificates(std.testing.allocator, certificates);
    try std.testing.expectEqual(@as(usize, 2), certificates.len);
    try std.testing.expectEqualStrings("Apps", certificates[0].subject.common_name.?);
    try std.testing.expectEqualStrings("Apps", certificates[1].subject.common_name.?);
}

test "CMS parser rejects a non-SignedData ContentInfo" {
    try std.testing.expectError(
        error.NotSignedData,
        parseCertificates(std.testing.allocator, &.{
            0x30, 0x0d,
            0x06, 0x09,
            0x2a, 0x86,
            0x48, 0x86,
            0xf7, 0x0d,
            0x01, 0x07,
            0x01, 0xa0,
            0x00,
        }),
    );
}
