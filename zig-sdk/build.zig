//! LovelyCarve plugin SDK for Zig.
//!
//! This package is a library, not a plugin: it exports the module
//! `lovelycarve`, which a plugin library imports and re-exports the C ABI
//! entry point from. Build it with:
//!
//!   zig build test        # unit tests for the SDK itself

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The module a plugin depends on: `@import("lovelycarve")`.
    _ = b.addModule("lovelycarve", .{
        .root_source_file = b.path("src/lovelycarve.zig"),
        .target = target,
        .optimize = optimize,
        // The ABI hands buffers across the boundary, so the plugin library
        // links libc and uses `std.heap.c_allocator` for them.
        .link_libc = true,
    });

    const tests = b.addTest(.{
        .name = "lovelycarve-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lovelycarve.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
            .link_libc = true,
        }),
    });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);
}
