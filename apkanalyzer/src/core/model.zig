const std = @import("std");

pub const ValueKind = enum {
    null_value,
    string,
    reference,
    attribute,
    integer,
    boolean,
    color,
    float,
    dimension,
    fraction,
    unknown,
};

pub const Value = struct {
    kind: ValueKind = .null_value,
    raw: ?[]const u8 = null,
    resolved: ?[]const u8 = null,
    data: u32 = 0,

    pub fn display(self: Value) ?[]const u8 {
        return self.resolved orelse self.raw;
    }
};

pub const MetaData = struct {
    name: []const u8,
    value: Value,
};

pub const IntentFilter = struct {
    actions: []const []const u8 = &.{},
    categories: []const []const u8 = &.{},
    data: []const IntentData = &.{},
};

pub const IntentData = struct {
    scheme: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: ?[]const u8 = null,
    path: ?[]const u8 = null,
    path_prefix: ?[]const u8 = null,
    path_pattern: ?[]const u8 = null,
    mime_type: ?[]const u8 = null,
};

pub const ComponentKind = enum {
    activity,
    activity_alias,
    service,
    receiver,
    provider,
};

pub const Component = struct {
    kind: ComponentKind,
    name: []const u8,
    target_activity: ?[]const u8 = null,
    exported: ?bool = null,
    enabled: ?bool = null,
    permission: ?[]const u8 = null,
    process: ?[]const u8 = null,
    authorities: ?[]const u8 = null,
    label: Value = .{},
    icon: Value = .{},
    meta_data: []const MetaData = &.{},
    intent_filters: []const IntentFilter = &.{},
};

pub const Permission = struct {
    name: []const u8,
    max_sdk_version: ?u32 = null,
    uses_permission_flags: ?u32 = null,
    display_name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    risk: PermissionRisk = .normal,
};

pub const PermissionRisk = enum {
    normal,
    sensitive,
    dangerous,
    unknown,
};

pub const Feature = struct {
    name: ?[]const u8 = null,
    gl_es_version: ?u32 = null,
    required: ?bool = true,
};

pub const SdkInfo = struct {
    min: ?u32 = null,
    target: ?u32 = null,
    compile: ?u32 = null,
};

pub const SignatureScheme = enum {
    jar_v1,
    apk_v2,
    apk_v3,
    apk_v31,
    source_stamp,
};

pub const DistinguishedName = struct {
    common_name: ?[]const u8 = null,
    organization: ?[]const u8 = null,
    organizational_unit: ?[]const u8 = null,
    country: ?[]const u8 = null,
    state: ?[]const u8 = null,
    locality: ?[]const u8 = null,
};

pub const Certificate = struct {
    version: ?u8 = null,
    md5: [16]u8 = undefined,
    sha1: [20]u8 = undefined,
    sha256: [32]u8,
    sha512: [64]u8 = undefined,
    serial_number: []const u8,
    issuer: DistinguishedName = .{},
    subject: DistinguishedName = .{},
    not_before: ?[]const u8 = null,
    not_after: ?[]const u8 = null,
    signature_algorithm_oid: ?[]const u8 = null,
    signature_algorithm_name: ?[]const u8 = null,
    public_key_algorithm_oid: ?[]const u8 = null,
    public_key_algorithm_name: ?[]const u8 = null,
    public_key_bits: ?u32 = null,
    rsa_modulus: ?[]const u8 = null,
    rsa_public_exponent: ?[]const u8 = null,
    der: []const u8,
};

pub const Detection = struct {
    name: []const u8,
    evidence: []const []const u8 = &.{},
};

pub const Signer = struct {
    scheme: SignatureScheme,
    min_sdk: ?u32 = null,
    max_sdk: ?u32 = null,
    certificates: []const Certificate = &.{},
    signature_algorithm_ids: []const u32 = &.{},
    digest_algorithm_ids: []const u32 = &.{},
};

pub const SigningInfo = struct {
    signers: []const Signer = &.{},
    has_v1: bool = false,
    has_v2: bool = false,
    has_v3: bool = false,
    has_v31: bool = false,
    has_source_stamp: bool = false,
    cryptographic_verification_performed: bool = false,
};

pub const DiagnosticSeverity = enum {
    info,
    warning,
    error_value,
};

pub const DiagnosticStage = enum {
    input,
    archive,
    manifest,
    resources,
    signing,
};

pub const Diagnostic = struct {
    stage: DiagnosticStage,
    severity: DiagnosticSeverity,
    code: []const u8,
    message: []const u8,
    entry_name: ?[]const u8 = null,
    offset: ?u64 = null,
};

pub const ArchiveEntry = struct {
    name: []const u8,
    method: u16,
    flags: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: u64,
    central_header_offset: u64,
    is_directory: bool,
};

pub const ArchiveInfo = struct {
    file_count: usize = 0,
    compressed_size: u64 = 0,
    uncompressed_size: u64 = 0,
    entries: []const ArchiveEntry = &.{},
};

pub const ResourcePackage = struct {
    id: u8,
    name: []const u8,
};

pub const ResourceInfo = struct {
    present: bool = false,
    packages: []const ResourcePackage = &.{},
    value_count: usize = 0,
    resolved_references: usize = 0,
    unresolved_references: usize = 0,
};

pub const ApkInfo = struct {
    file_size: u64 = 0,
    sha256: ?[32]u8 = null,
    package_name: ?[]const u8 = null,
    application_label: Value = .{},
    application_icon: Value = .{},
    application_round_icon: Value = .{},
    icon_entry: ?[]const u8 = null,
    icon_bytes: []const u8 = &.{},
    icon_background_bytes: []const u8 = &.{},
    icon_svg: []const u8 = &.{},
    version_name: Value = .{},
    version_code: ?u64 = null,
    sdk: SdkInfo = .{},
    debuggable: ?bool = null,
    allow_backup: ?bool = null,
    launcher_activity: ?[]const u8 = null,
    permissions: []const Permission = &.{},
    features: []const Feature = &.{},
    application_meta_data: []const MetaData = &.{},
    components: []const Component = &.{},
    resources: ResourceInfo = .{},
    signing: SigningInfo = .{},
    protections: []const Detection = &.{},
    frameworks: []const Detection = &.{},
    archive: ArchiveInfo = .{},
};

/// Owns every slice reachable through `info`. Treat this type as move-only.
pub const Analysis = struct {
    arena: std.heap.ArenaAllocator,
    info: ApkInfo = .{},
    diagnostics: []const Diagnostic = &.{},
    /// Original APK bytes retained so GUI clients can safely extract entries.
    archive_bytes: []const u8 = &.{},

    pub fn init(backing_allocator: std.mem.Allocator) Analysis {
        return .{ .arena = .init(backing_allocator) };
    }

    pub fn allocator(self: *Analysis) std.mem.Allocator {
        return self.arena.allocator();
    }

    pub fn deinit(self: *Analysis) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

test "analysis owns copied data through its arena" {
    var analysis = Analysis.init(std.testing.allocator);
    defer analysis.deinit();

    analysis.info.package_name = try analysis.allocator().dupe(u8, "dev.example.app");
    try std.testing.expectEqualStrings("dev.example.app", analysis.info.package_name.?);
}
