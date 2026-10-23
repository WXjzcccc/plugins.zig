const std = @import("std");
const der = @import("der.zig");
const model = @import("../model.zig");
const algorithms = @import("algorithms.zig");
const logging = @import("../../utils/logging.zig");

const Allocator = std.mem.Allocator;
const log = logging.scoped(.apk_signing);

pub const ParseError = Allocator.Error || der.Error || error{
    InvalidCertificate,
    InvalidSerialNumber,
    InvalidBitString,
    TooManyDerNodes,
};

pub const Options = struct {
    max_der_nodes: usize = 1_000_000,
    max_der_depth: usize = 64,
};

/// Parses the reporting fields of one DER-encoded X.509 certificate.
///
/// This is deliberately a structural parser. It neither validates the
/// certificate signature nor establishes a trust chain.
pub fn parseCertificate(allocator: Allocator, encoded: []const u8) ParseError!model.Certificate {
    return parseCertificateWithOptions(allocator, encoded, .{});
}

pub fn parseCertificateWithOptions(
    allocator: Allocator,
    encoded: []const u8,
    options: Options,
) ParseError!model.Certificate {
    return parseCertificateWithOptionsImpl(allocator, encoded, options) catch |err| {
        log.warn(@src(), "X.509 certificate parsing failed bytes={d} error={s}", .{ encoded.len, @errorName(err) });
        return err;
    };
}

fn parseCertificateWithOptionsImpl(
    allocator: Allocator,
    encoded: []const u8,
    options: Options,
) ParseError!model.Certificate {
    try enforceNodeLimit(encoded, options);
    var certificate: model.Certificate = .{
        .version = 1,
        .md5 = undefined,
        .sha1 = undefined,
        .sha256 = undefined,
        .sha512 = undefined,
        .serial_number = &.{},
        .der = &.{},
    };
    errdefer deinitCertificate(allocator, &certificate);

    std.crypto.hash.sha2.Sha256.hash(encoded, &certificate.sha256, .{});
    std.crypto.hash.Md5.hash(encoded, &certificate.md5, .{});
    std.crypto.hash.Sha1.hash(encoded, &certificate.sha1, .{});
    std.crypto.hash.sha2.Sha512.hash(encoded, &certificate.sha512, .{});

    const root = try der.parseSingle(encoded);
    try root.expectUniversal(.sequence, true);
    var root_fields = root.children();

    const tbs = try root_fields.requireNext();
    try tbs.expectUniversal(.sequence, true);
    const outer_signature_algorithm = try root_fields.requireNext();
    const signature_value = try root_fields.requireNext();
    try expectBitString(signature_value);
    try root_fields.requireEnd();

    certificate.signature_algorithm_oid = try parseAlgorithmOidAlloc(
        allocator,
        outer_signature_algorithm,
    );
    certificate.signature_algorithm_name = try allocator.dupe(u8, algorithms.oidName(certificate.signature_algorithm_oid.?));

    var fields = tbs.children();
    var serial = try fields.requireNext();
    if (serial.class == .context_specific and serial.tag_number == 0 and serial.constructed) {
        var version_fields = serial.children();
        const version = try version_fields.requireNext();
        try version.expectUniversal(.integer, false);
        if (version.content.len != 1 or version.content[0] > 2) return error.InvalidCertificate;
        certificate.version = version.content[0] + 1;
        try version_fields.requireEnd();
        serial = try fields.requireNext();
    }
    try serial.expectUniversal(.integer, false);
    if (serial.content.len == 0) return error.InvalidSerialNumber;
    certificate.serial_number = try der.integerHexAlloc(allocator, serial.content);

    // TBSCertificate.signature. The outer AlgorithmIdentifier is the one
    // exposed in the model, but this one must still be structurally valid.
    const tbs_signature_algorithm = try fields.requireNext();
    const unused_tbs_oid = try parseAlgorithmOidAlloc(allocator, tbs_signature_algorithm);
    allocator.free(unused_tbs_oid);

    const issuer = try fields.requireNext();
    try parseName(allocator, issuer, &certificate.issuer);

    const validity = try fields.requireNext();
    try parseValidity(allocator, validity, &certificate);

    const subject = try fields.requireNext();
    try parseName(allocator, subject, &certificate.subject);

    const subject_public_key_info = try fields.requireNext();
    certificate.public_key_algorithm_oid = try parseSubjectPublicKeyInfoAlloc(
        allocator,
        subject_public_key_info,
        &certificate,
    );
    certificate.public_key_algorithm_name = try allocator.dupe(u8, algorithms.oidName(certificate.public_key_algorithm_oid.?));

    // Parse every remaining top-level TBSCertificate field so malformed DER
    // lengths are not silently hidden, while leaving extensions uninterpreted.
    while (try fields.next()) |_| {}

    certificate.der = try allocator.dupe(u8, encoded);
    return certificate;
}

fn enforceNodeLimit(encoded: []const u8, options: Options) ParseError!void {
    var node_count: usize = 0;
    try countDerNodes(encoded, options, &node_count, 0);
}

fn countDerNodes(
    encoded: []const u8,
    options: Options,
    node_count: *usize,
    depth: usize,
) ParseError!void {
    if (depth > options.max_der_depth) return error.TooManyDerNodes;
    var reader: der.Reader = .{ .data = encoded };
    while (try reader.next()) |element| {
        node_count.* = std.math.add(usize, node_count.*, 1) catch return error.TooManyDerNodes;
        if (node_count.* > options.max_der_nodes) return error.TooManyDerNodes;
        if (element.constructed and
            (element.class != .universal or
                element.tag_number == @backingInt(der.UniversalTag.sequence) or
                element.tag_number == @backingInt(der.UniversalTag.set)))
        {
            try countDerNodes(element.content, options, node_count, depth + 1);
        }
    }
}

pub fn deinitCertificate(allocator: Allocator, certificate: *model.Certificate) void {
    freeOptional(allocator, certificate.issuer.common_name);
    freeOptional(allocator, certificate.issuer.organization);
    freeOptional(allocator, certificate.issuer.organizational_unit);
    freeOptional(allocator, certificate.issuer.country);
    freeOptional(allocator, certificate.issuer.state);
    freeOptional(allocator, certificate.issuer.locality);
    freeOptional(allocator, certificate.subject.common_name);
    freeOptional(allocator, certificate.subject.organization);
    freeOptional(allocator, certificate.subject.organizational_unit);
    freeOptional(allocator, certificate.subject.country);
    freeOptional(allocator, certificate.subject.state);
    freeOptional(allocator, certificate.subject.locality);
    freeOptional(allocator, certificate.not_before);
    freeOptional(allocator, certificate.not_after);
    freeOptional(allocator, certificate.signature_algorithm_oid);
    freeOptional(allocator, certificate.signature_algorithm_name);
    freeOptional(allocator, certificate.public_key_algorithm_oid);
    freeOptional(allocator, certificate.public_key_algorithm_name);
    freeOptional(allocator, certificate.rsa_modulus);
    freeOptional(allocator, certificate.rsa_public_exponent);
    if (certificate.serial_number.len != 0) allocator.free(certificate.serial_number);
    if (certificate.der.len != 0) allocator.free(certificate.der);
    certificate.* = undefined;
}

pub fn deinitCertificates(allocator: Allocator, certificates: []model.Certificate) void {
    for (certificates) |*certificate| deinitCertificate(allocator, certificate);
    if (certificates.len != 0) allocator.free(certificates);
}

fn parseAlgorithmOidAlloc(allocator: Allocator, element: der.Element) ParseError![]u8 {
    try element.expectUniversal(.sequence, true);
    var fields = element.children();
    const oid = try fields.requireNext();
    try oid.expectUniversal(.object_identifier, false);
    const decoded = try der.decodeOidAlloc(allocator, oid.content);
    errdefer allocator.free(decoded);

    // AlgorithmIdentifier parameters are OPTIONAL and contain one ASN.1 value.
    if (try fields.next()) |_| {
        if ((try fields.next()) != null) return error.InvalidCertificate;
    }
    return decoded;
}

fn parseSubjectPublicKeyInfoAlloc(allocator: Allocator, element: der.Element, certificate: *model.Certificate) ParseError![]u8 {
    try element.expectUniversal(.sequence, true);
    var fields = element.children();
    const algorithm = try fields.requireNext();
    const oid = try parseAlgorithmOidAlloc(allocator, algorithm);
    errdefer allocator.free(oid);
    const public_key = try fields.requireNext();
    try expectBitString(public_key);
    try fields.requireEnd();
    if (std.mem.eql(u8, oid, "1.2.840.113549.1.1.1") and public_key.content.len > 1) {
        const rsa = der.parseSingle(public_key.content[1..]) catch |err| {
            log.warn(@src(), "RSA public-key details omitted error={s}", .{@errorName(err)});
            return oid;
        };
        rsa.expectUniversal(.sequence, true) catch |err| {
            log.warn(@src(), "RSA public-key details omitted error={s}", .{@errorName(err)});
            return oid;
        };
        var rsa_fields = rsa.children();
        const modulus = rsa_fields.requireNext() catch |err| {
            log.warn(@src(), "RSA public-key details omitted error={s}", .{@errorName(err)});
            return oid;
        };
        const exponent = rsa_fields.requireNext() catch |err| {
            log.warn(@src(), "RSA public-key details omitted error={s}", .{@errorName(err)});
            return oid;
        };
        modulus.expectUniversal(.integer, false) catch |err| {
            log.warn(@src(), "RSA public-key details omitted error={s}", .{@errorName(err)});
            return oid;
        };
        exponent.expectUniversal(.integer, false) catch |err| {
            log.warn(@src(), "RSA public-key details omitted error={s}", .{@errorName(err)});
            return oid;
        };
        rsa_fields.requireEnd() catch |err| {
            log.warn(@src(), "RSA public-key details omitted error={s}", .{@errorName(err)});
            return oid;
        };
        certificate.rsa_modulus = try der.integerHexAlloc(allocator, modulus.content);
        certificate.rsa_public_exponent = try integerDecimalAlloc(allocator, exponent.content);
        var modulus_bytes = modulus.content;
        while (modulus_bytes.len > 1 and modulus_bytes[0] == 0) modulus_bytes = modulus_bytes[1..];
        if (modulus_bytes.len != 0) {
            var leading_bits: u32 = 0;
            var first = modulus_bytes[0];
            while ((first & 0x80) == 0) : (first <<= 1) leading_bits += 1;
            certificate.public_key_bits = @intCast(modulus_bytes.len * 8 - leading_bits);
        }
    }
    return oid;
}

fn integerDecimalAlloc(allocator: Allocator, content: []const u8) Allocator.Error![]u8 {
    var value: u64 = 0;
    for (content) |byte| {
        value = std.math.mul(u64, value, 256) catch |err| {
            log.debug(@src(), "integer decimal conversion fell back to hexadecimal error={s}", .{@errorName(err)});
            return der.integerHexAlloc(allocator, content);
        };
        value = std.math.add(u64, value, byte) catch |err| {
            log.debug(@src(), "integer decimal conversion fell back to hexadecimal error={s}", .{@errorName(err)});
            return der.integerHexAlloc(allocator, content);
        };
    }
    return std.fmt.allocPrint(allocator, "{d}", .{value});
}

fn parseValidity(
    allocator: Allocator,
    element: der.Element,
    certificate: *model.Certificate,
) ParseError!void {
    try element.expectUniversal(.sequence, true);
    var fields = element.children();
    const not_before = try fields.requireNext();
    const not_after = try fields.requireNext();
    try expectTime(not_before);
    try expectTime(not_after);
    try fields.requireEnd();
    certificate.not_before = try der.decodeStringAlloc(allocator, not_before);
    certificate.not_after = try der.decodeStringAlloc(allocator, not_after);
}

fn expectTime(element: der.Element) ParseError!void {
    if (element.class != .universal or element.constructed) return error.UnexpectedTag;
    const tag: der.UniversalTag = @fromBackingInt(@intCast(element.tag_number));
    if (tag != .utc_time and tag != .generalized_time) return error.UnexpectedTag;
}

fn expectBitString(element: der.Element) ParseError!void {
    try element.expectUniversal(.bit_string, false);
    if (element.content.len == 0 or element.content[0] > 7) return error.InvalidBitString;
    if (element.content.len == 1 and element.content[0] != 0) return error.InvalidBitString;
    if (element.content.len > 1 and element.content[0] != 0) {
        const mask: u8 = (@as(u8, 1) << @intCast(element.content[0])) - 1;
        if ((element.content[element.content.len - 1] & mask) != 0) return error.InvalidBitString;
    }
}

fn parseName(allocator: Allocator, element: der.Element, name: *model.DistinguishedName) ParseError!void {
    try element.expectUniversal(.sequence, true);
    var rdns = element.children();
    while (try rdns.next()) |rdn| {
        try rdn.expectUniversal(.set, true);
        var attributes = rdn.children();
        while (try attributes.next()) |attribute| {
            try attribute.expectUniversal(.sequence, true);
            var fields = attribute.children();
            const oid = try fields.requireNext();
            try oid.expectUniversal(.object_identifier, false);
            const value = try fields.requireNext();
            try fields.requireEnd();

            const slot = nameSlot(name, oid.content) orelse continue;
            if (slot.* == null) slot.* = try der.decodeStringAlloc(allocator, value);
        }
    }
}

fn nameSlot(name: *model.DistinguishedName, oid: []const u8) ?*?[]const u8 {
    // All requested X.520 attributes share the 2.5.4 prefix (55 04).
    if (oid.len != 3 or oid[0] != 0x55 or oid[1] != 0x04) return null;
    return switch (oid[2]) {
        3 => &name.common_name,
        6 => &name.country,
        7 => &name.locality,
        8 => &name.state,
        10 => &name.organization,
        11 => &name.organizational_unit,
        else => null,
    };
}

fn freeOptional(allocator: Allocator, value: ?[]const u8) void {
    if (value) |bytes| if (bytes.len != 0) allocator.free(bytes);
}

// A compact, structurally valid test certificate. Its signature and key bytes
// are intentionally meaningless: this module reports structure, not validity.
pub const test_certificate_der = [_]u8{
    0x30, 0x81, 0x83,
    0x30, 0x6e, 0xa0,
    0x03, 0x02, 0x01,
    0x02, 0x02, 0x01,
    0x01, 0x30, 0x0d,
    0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01,
    0x01, 0x0b, 0x05,
    0x00, 0x30, 0x0f,
    0x31, 0x0d, 0x30,
    0x0b, 0x06, 0x03,
    0x55, 0x04, 0x03,
    0x0c, 0x04, 'T',
    'e',  's',  't',
    0x30, 0x1e, 0x17,
    0x0d, '2',  '4',
    '0',  '1',  '0',
    '1',  '0',  '0',
    '0',  '0',  '0',
    '0',  'Z',  0x17,
    0x0d, '3',  '4',
    '0',  '1',  '0',
    '1',  '0',  '0',
    '0',  '0',  '0',
    '0',  'Z',  0x30,
    0x0f, 0x31, 0x0d,
    0x30, 0x0b, 0x06,
    0x03, 0x55, 0x04,
    0x03, 0x0c, 0x04,
    'A',  'p',  'p',
    's',  0x30, 0x13,
    0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00,
    0x03, 0x02, 0x00,
    0x00, 0x30, 0x0d,
    0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01,
    0x01, 0x0b, 0x05,
    0x00, 0x03, 0x02,
    0x00, 0x00,
};

test "extract X.509 identity, validity, algorithms, serial, and fingerprint" {
    var certificate = try parseCertificate(std.testing.allocator, &test_certificate_der);
    defer deinitCertificate(std.testing.allocator, &certificate);

    try std.testing.expectEqualStrings("01", certificate.serial_number);
    try std.testing.expectEqualStrings("Test", certificate.issuer.common_name.?);
    try std.testing.expectEqualStrings("Apps", certificate.subject.common_name.?);
    try std.testing.expectEqualStrings("240101000000Z", certificate.not_before.?);
    try std.testing.expectEqualStrings("340101000000Z", certificate.not_after.?);
    try std.testing.expectEqualStrings("1.2.840.113549.1.1.11", certificate.signature_algorithm_oid.?);
    try std.testing.expectEqualStrings("1.2.840.113549.1.1.1", certificate.public_key_algorithm_oid.?);
    try std.testing.expectEqualSlices(u8, &test_certificate_der, certificate.der);

    var expected_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&test_certificate_der, &expected_sha256, .{});
    try std.testing.expectEqual(expected_sha256, certificate.sha256);
}

test "reject a certificate whose outer BIT STRING is truncated" {
    var malformed = test_certificate_der;
    malformed[malformed.len - 2] = 8;
    try std.testing.expectError(
        error.InvalidBitString,
        parseCertificate(std.testing.allocator, &malformed),
    );
}

test "X.509 node limit is enforced before field extraction" {
    try std.testing.expectError(
        error.TooManyDerNodes,
        parseCertificateWithOptions(
            std.testing.allocator,
            &test_certificate_der,
            .{ .max_der_nodes = 1 },
        ),
    );
}

test "X.509 names extract all requested X.520 attributes" {
    const encoded_name = [_]u8{
        0x30, 0x58,
        0x31, 0x0d,
        0x30, 0x0b,
        0x06, 0x03,
        0x55, 0x04,
        0x03, 0x0c,
        0x04, 'N',
        'a',  'm',
        'e',  0x31,
        0x0c, 0x30,
        0x0a, 0x06,
        0x03, 0x55,
        0x04, 0x0a,
        0x0c, 0x03,
        'O',  'r',
        'g',  0x31,
        0x0d, 0x30,
        0x0b, 0x06,
        0x03, 0x55,
        0x04, 0x0b,
        0x0c, 0x04,
        'U',  'n',
        'i',  't',
        0x31, 0x0b,
        0x30, 0x09,
        0x06, 0x03,
        0x55, 0x04,
        0x06, 0x0c,
        0x02, 'C',
        'N',  0x31,
        0x0e, 0x30,
        0x0c, 0x06,
        0x03, 0x55,
        0x04, 0x08,
        0x0c, 0x05,
        'S',  't',
        'a',  't',
        'e',  0x31,
        0x0d, 0x30,
        0x0b, 0x06,
        0x03, 0x55,
        0x04, 0x07,
        0x0c, 0x04,
        'C',  'i',
        't',  'y',
    };
    const name_element = try der.parseSingle(&encoded_name);
    var name: model.DistinguishedName = .{};
    defer {
        freeOptional(std.testing.allocator, name.common_name);
        freeOptional(std.testing.allocator, name.organization);
        freeOptional(std.testing.allocator, name.organizational_unit);
        freeOptional(std.testing.allocator, name.country);
        freeOptional(std.testing.allocator, name.state);
        freeOptional(std.testing.allocator, name.locality);
    }
    try parseName(std.testing.allocator, name_element, &name);
    try std.testing.expectEqualStrings("Name", name.common_name.?);
    try std.testing.expectEqualStrings("Org", name.organization.?);
    try std.testing.expectEqualStrings("Unit", name.organizational_unit.?);
    try std.testing.expectEqualStrings("CN", name.country.?);
    try std.testing.expectEqualStrings("State", name.state.?);
    try std.testing.expectEqualStrings("City", name.locality.?);
}
