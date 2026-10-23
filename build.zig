//! Builds every plugin in this repository from one place.
//!
//!   zig build                  # every plugin library -> zig-out/lib/
//!   zig build test             # every plugin's unit tests
//!   zig build package          # every plugin's .lcpkg -> dist/
//!
//! The per-plugin build recipes live here: one table row per plugin, holding
//! its directory under `plugins/`, the library name from its plugin.toml and
//! the helper libraries it imports.
//! The individual plugin directories keep their own build.zig files for
//! standalone development (their `package` steps use the same shared
//! scripts/pack.zig and also write into dist/), but `zig build package` here
//! is the one-shot build of all installable packages.
//!
//! `scripts/pack.zig` stages each package directory (plugin.toml, the library
//! under its platform file name, schema.json — regenerated from the plugin's
//! describe tool on every run — and build.json + SHA256SUMS.txt) and archives
//! it as a STORED ZIP.

const std = @import("std");

const Plugin = struct {
    /// Short name, used for step and test names.
    name: []const u8,
    /// Directory of the plugin source, relative to the repository root. The
    /// layout mirrors the bundled plugin tree: `plugins/<group>/<plugin>`.
    dir: []const u8,
    /// The `library` field of the plugin's plugin.toml (artifact name).
    library: []const u8,
    /// Whether the plugin's root module imports `regf_zig`.
    regf: bool = false,
    /// Whether the plugin's root module imports `zig_cryptobin`.
    cryptobin: bool = false,
};

const plugins = [_]Plugin{
    .{ .name = "apkanalyzer", .dir = "plugins/evidence/apkanalyzer", .library = "apkanalyzer" },
    .{ .name = "winsysteminfo", .dir = "plugins/system/windows/winsysteminfo", .library = "winsysteminfo", .regf = true, .cryptobin = true },
    .{ .name = "navicat", .dir = "plugins/appinfo/windows/navicat", .library = "navicatanalyzer", .regf = true, .cryptobin = true },
    .{ .name = "mobaxterm", .dir = "plugins/appinfo/windows/mobaxterm", .library = "mobaxtermanalyzer", .regf = true, .cryptobin = true },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Ship ReleaseSafe by default: the plugin and the host share a process, so
    // keeping overflow and bounds checks turns a memory bug into a readable
    // panic instead of silent corruption. `-Doptimize=Debug` when debugging.
    const optimize = b.option(
        std.builtin.Optimize,
        "optimize",
        "Optimization mode (default ReleaseSafe)",
    ) orelse .safe;

    // The SDK package from build.zig.zon, built for the plugin target; a
    // second instance is built for the host so describe/pack run natively.
    const sdk = b.dependency("lovelycarve", .{
        .target = target,
        .optimize = optimize,
    });
    const host_sdk = b.dependency("lovelycarve", .{
        .target = b.graph.host,
        .optimize = .debug,
    });
    const regf = b.dependency("regf_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const host_regf = b.dependency("regf_zig", .{
        .target = b.graph.host,
        .optimize = .debug,
    });
    const cryptobin = b.dependency("zig_cryptobin", .{
        .target = target,
        .optimize = optimize,
    });
    const host_cryptobin = b.dependency("zig_cryptobin", .{
        .target = b.graph.host,
        .optimize = .debug,
    });

    // ------------------------------------------------------- shared packer

    // One pack tool serves every plugin of the repository.
    const pack_module = b.createModule(.{
        .root_source_file = b.path("scripts/pack.zig"),
        .target = b.graph.host,
        .optimize = .debug,
    });
    const pack_exe = b.addExecutable(.{ .name = "pack", .root_module = pack_module });

    // ------------------------------------------------------------- steps

    const test_step = b.step("test", "Run every plugin's unit tests");
    const package_step = b.step("package", "Package every plugin into dist/");

    for (plugins) |plugin| {
        // The plugin library, ReleaseSafe for the target.
        const module = b.createModule(.{
            .root_source_file = b.path(b.fmt("{s}/src/root.zig", .{plugin.dir})),
            .target = target,
            .optimize = optimize,
            // std.heap.c_allocator is libc malloc/free, so a buffer allocated
            // on one side of the ABI can be freed on the other.
            .link_libc = true,
        });
        module.addImport("lovelycarve", sdk.module("lovelycarve"));
        if (plugin.regf) module.addImport("regf_zig", regf.module("regf_zig"));
        if (plugin.cryptobin) module.addImport("zig_cryptobin", cryptobin.module("zig_cryptobin"));

        const library = b.addLibrary(.{
            .name = plugin.library,
            .root_module = module,
            .linkage = .dynamic,
            // Pin the LLVM backend: on Windows 0.17 emits the import library
            // (.lib) and a .pdb next to the DLL either way; this only decides
            // which code generator produces them.
            .use_llvm = true,
        });
        // Zig routes Windows DLLs to bin/ by default; plugin.toml expects the
        // library under lib/, so pin the install directory.
        b.getInstallStep().dependOn(&b.addInstallArtifact(library, .{
            .dest_dir = .{ .override = .lib },
        }).step);

        // The same plugin built for the host, tested in Debug.
        const host_root = b.createModule(.{
            .root_source_file = b.path(b.fmt("{s}/src/root.zig", .{plugin.dir})),
            .target = b.graph.host,
            .optimize = .debug,
            .link_libc = true,
        });
        host_root.addImport("lovelycarve", host_sdk.module("lovelycarve"));
        if (plugin.regf) host_root.addImport("regf_zig", host_regf.module("regf_zig"));
        if (plugin.cryptobin) host_root.addImport("zig_cryptobin", host_cryptobin.module("zig_cryptobin"));
        const tests = b.addTest(.{
            .name = b.fmt("{s}-test", .{plugin.name}),
            .root_module = host_root,
        });
        test_step.dependOn(&b.addRunArtifact(tests).step);

        // schema.json, regenerated from the plugin on every package run so it
        // always matches the library that ships.
        const describe_module = b.createModule(.{
            .root_source_file = b.path(b.fmt("{s}/src/describe.zig", .{plugin.dir})),
            .target = b.graph.host,
            .optimize = .debug,
            .link_libc = true,
        });
        describe_module.addImport("lovelycarve", host_sdk.module("lovelycarve"));
        describe_module.addImport("plugin", host_root);
        const describe_exe = b.addExecutable(.{
            .name = b.fmt("describe-{s}", .{plugin.name}),
            .root_module = describe_module,
        });
        const describe_run = b.addRunArtifact(describe_exe);
        const schema_path = describe_run.addOutputFileArg("schema.json");

        // The installable package, written into dist/ at the repository root.
        const pack_run = b.addRunArtifact(pack_exe);
        pack_run.addArg("--out");
        pack_run.addArg("dist");
        pack_run.addArgs(&.{ "--platform", platformName(target.result) });
        pack_run.addArg("--plugin");
        pack_run.addFileArg(b.path(b.fmt("{s}/plugin.toml", .{plugin.dir})));
        pack_run.addArg("--library");
        pack_run.addArtifactArg(library);
        pack_run.addArg("--schema");
        pack_run.addFileArg(schema_path);
        pack_run.has_side_effects = true;
        package_step.dependOn(&pack_run.step);
    }
}

/// The platform tag of a package archive name.
fn platformName(target: std.Target) []const u8 {
    return switch (target.os.tag) {
        .windows => switch (target.cpu.arch) {
            .x86_64 => "windows-x64",
            else => @panic("the template packages windows-x64 only"),
        },
        .linux => switch (target.cpu.arch) {
            .x86_64 => "linux-x64",
            .aarch64 => "linux-arm64",
            else => @panic("the template packages linux-x64 and linux-arm64 only"),
        },
        .macos => switch (target.cpu.arch) {
            .x86_64 => "macos-x64",
            .aarch64 => "macos-arm64",
            else => @panic("the template packages macos-x64 and macos-arm64 only"),
        },
        else => @panic("the template packages windows, linux and macos only"),
    };
}
