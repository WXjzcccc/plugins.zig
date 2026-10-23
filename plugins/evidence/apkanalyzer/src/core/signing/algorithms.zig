pub fn apkSignatureName(id: u32) []const u8 {
    return switch (id) {
        0x0101 => "RSA PKCS#1 v1.5 with SHA-256",
        0x0102 => "RSA PKCS#1 v1.5 with SHA-512",
        0x0103 => "ECDSA with SHA-256",
        0x0104 => "RSA PKCS#1 v1.5 with SHA-512",
        0x0105 => "DSA with SHA-256",
        0x0201 => "RSA-PSS with SHA-256",
        0x0202 => "RSA-PSS with SHA-512",
        0x0301 => "RSA PKCS#1 v1.5 with SHA-256",
        0x0302 => "RSA PKCS#1 v1.5 with SHA-512",
        else => "未知 APK 签名算法",
    };
}

pub fn digestName(id: u32) []const u8 {
    return switch (id) {
        1 => "SHA-256",
        2 => "SHA-512",
        0x0103 => "SHA-256",
        0x0104 => "SHA-512",
        else => "未知摘要算法",
    };
}

pub fn oidName(oid: []const u8) []const u8 {
    if (std.mem.eql(u8, oid, "1.2.840.113549.1.1.1")) return "RSA";
    if (std.mem.eql(u8, oid, "1.2.840.113549.1.1.5")) return "SHA-1 with RSA";
    if (std.mem.eql(u8, oid, "1.2.840.113549.1.1.11")) return "SHA-256 with RSA";
    if (std.mem.eql(u8, oid, "1.2.840.113549.1.1.12")) return "SHA-384 with RSA";
    if (std.mem.eql(u8, oid, "1.2.840.113549.1.1.13")) return "SHA-512 with RSA";
    if (std.mem.eql(u8, oid, "1.2.840.10045.2.1")) return "EC";
    if (std.mem.eql(u8, oid, "1.2.840.10040.4.1")) return "DSA";
    return "未知算法";
}

const std = @import("std");
