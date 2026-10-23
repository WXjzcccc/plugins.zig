const std = @import("std");
const model = @import("../model.zig");

pub fn copyInfo(allocator: std.mem.Allocator, source: model.SigningInfo) !model.SigningInfo {
    const signers = try allocator.alloc(model.Signer, source.signers.len);
    for (source.signers, 0..) |signer, signer_index| {
        const certificates = try allocator.alloc(model.Certificate, signer.certificates.len);
        for (signer.certificates, 0..) |certificate, certificate_index| {
            certificates[certificate_index] = try copyCertificate(allocator, certificate);
        }
        signers[signer_index] = .{
            .scheme = signer.scheme,
            .min_sdk = signer.min_sdk,
            .max_sdk = signer.max_sdk,
            .certificates = certificates,
            .signature_algorithm_ids = try allocator.dupe(u32, signer.signature_algorithm_ids),
            .digest_algorithm_ids = try allocator.dupe(u32, signer.digest_algorithm_ids),
        };
    }
    return .{
        .signers = signers,
        .has_v1 = source.has_v1,
        .has_v2 = source.has_v2,
        .has_v3 = source.has_v3,
        .has_v31 = source.has_v31,
        .has_source_stamp = source.has_source_stamp,
        .cryptographic_verification_performed = source.cryptographic_verification_performed,
    };
}

fn copyCertificate(allocator: std.mem.Allocator, source: model.Certificate) !model.Certificate {
    return .{
        .version = source.version,
        .md5 = source.md5,
        .sha1 = source.sha1,
        .sha256 = source.sha256,
        .sha512 = source.sha512,
        .serial_number = try allocator.dupe(u8, source.serial_number),
        .issuer = try copyDistinguishedName(allocator, source.issuer),
        .subject = try copyDistinguishedName(allocator, source.subject),
        .not_before = try copyOptionalString(allocator, source.not_before),
        .not_after = try copyOptionalString(allocator, source.not_after),
        .signature_algorithm_oid = try copyOptionalString(allocator, source.signature_algorithm_oid),
        .signature_algorithm_name = try copyOptionalString(allocator, source.signature_algorithm_name),
        .public_key_algorithm_oid = try copyOptionalString(allocator, source.public_key_algorithm_oid),
        .public_key_algorithm_name = try copyOptionalString(allocator, source.public_key_algorithm_name),
        .public_key_bits = source.public_key_bits,
        .rsa_modulus = try copyOptionalString(allocator, source.rsa_modulus),
        .rsa_public_exponent = try copyOptionalString(allocator, source.rsa_public_exponent),
        .der = try allocator.dupe(u8, source.der),
    };
}

fn copyDistinguishedName(
    allocator: std.mem.Allocator,
    source: model.DistinguishedName,
) !model.DistinguishedName {
    return .{
        .common_name = try copyOptionalString(allocator, source.common_name),
        .organization = try copyOptionalString(allocator, source.organization),
        .organizational_unit = try copyOptionalString(allocator, source.organizational_unit),
        .country = try copyOptionalString(allocator, source.country),
        .state = try copyOptionalString(allocator, source.state),
        .locality = try copyOptionalString(allocator, source.locality),
    };
}

fn copyOptionalString(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) std.mem.Allocator.Error!?[]const u8 {
    return if (value) |present| try allocator.dupe(u8, present) else null;
}
