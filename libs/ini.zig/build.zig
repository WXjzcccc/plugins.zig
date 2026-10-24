const std = @import("std");

/// Builds the `ini_zig` library. This package is library-only: it exposes one
/// module (`ini_zig`) plus a test step.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The module consumers import as `@import("ini_zig")`.
    const mod = b.addModule("ini_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // `zig build test` runs the module's unit tests.
    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run the test suite");
    test_step.dependOn(&run_mod_tests.step);
}
