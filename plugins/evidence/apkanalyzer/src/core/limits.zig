/// Resource limits applied while parsing untrusted APK input.
pub const Limits = struct {
    max_apk_size: usize = 2 * 1024 * 1024 * 1024,
    max_entries: usize = 250_000,
    max_entry_uncompressed_size: usize = 512 * 1024 * 1024,
    max_total_uncompressed_size: u64 = 8 * 1024 * 1024 * 1024,
    max_compression_ratio: u64 = 2_000,
    max_android_chunks: usize = 2_000_000,
    max_string_count: usize = 2_000_000,
    max_string_bytes: usize = 64 * 1024 * 1024,
    max_resource_entries: usize = 4_000_000,
    max_reference_depth: usize = 64,
    max_der_depth: usize = 64,
    max_der_nodes: usize = 1_000_000,

    pub const defaults: Limits = .{};
};

test "default limits are internally ordered" {
    const std = @import("std");
    const limits: Limits = .{};
    try std.testing.expect(limits.max_entry_uncompressed_size <= limits.max_total_uncompressed_size);
    try std.testing.expect(limits.max_reference_depth > 0);
}
