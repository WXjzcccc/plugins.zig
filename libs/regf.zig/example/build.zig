const std = @import("std");

/// Builds the `example` demo: an executable that reads a SYSTEM hive through the
/// `regf_zig` library and prints its mount table.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const regf_zig = b.dependency("regf_zig", .{ .target = target, .optimize = optimize });
    const regf_mod = regf_zig.module("regf_zig");

    // The demo's own logic, reusable and testable on its own.
    const mod = b.addModule("example", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "regf_zig", .module = regf_mod }},
    });

    // The command-line demo.
    const exe = b.addExecutable(.{
        .name = "example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "example", .module = mod },
                .{ .name = "regf_zig", .module = regf_mod },
            },
        }),
    });
    b.installArtifact(exe);

    // `zig build run` runs the demo from the repository root, so the default
    // hive path (`testfiles/SYSTEM`) resolves. Extra arguments are forwarded:
    //   zig build run -- ../testfiles/SOFTWARE
    const run_step = b.step("run", "Run the demo");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.setCwd(b.path(".."));
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    run_step.dependOn(&run_cmd.step);

    // `zig build test` runs both the module tests and the demo's tests.
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = mod })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = exe.root_module })).step);
}
