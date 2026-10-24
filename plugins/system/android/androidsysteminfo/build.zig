//! Builds the plugin, its `schema.json` and an installable package.
//!
//!   zig build                          # ReleaseSafe library into zig-out/lib/
//!   zig build test                     # unit tests (always Debug)
//!   zig build schema                   # zig-out/schema.json, from the library
//!   zig build package                  # zig-out/<id>-<version>-<platform>.lcpkg
//!
//! The library is named exactly like `library` in plugin.toml
//! (androidsysteminfo -> androidsysteminfo.dll / libandroidsysteminfo.so).

const std = @import("std");

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

    // The SDK package from build.zig.zon, built for the plugin's target; a
    // second instance is built for the host so describe/pack run natively.
    const sdk = b.dependency("lovelycarve", .{
        .target = target,
        .optimize = optimize,
    });
    const host_sdk = b.dependency("lovelycarve", .{
        .target = b.graph.host,
        .optimize = .debug,
    });
    const ini = b.dependency("ini_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const host_ini = b.dependency("ini_zig", .{
        .target = b.graph.host,
        .optimize = .debug,
    });
    const zqlite = b.dependency("zqlite", .{
        .target = target,
        .optimize = optimize,
        // Forensic read-only usage: trim what the amalgamation does not need.
        .sqlite3 = @as([]const []const u8, &.{
            "-std=c99",
            "-DSQLITE_THREADSAFE=1",
            "-DSQLITE_OMIT_DEPRECATED=1",
            "-DSQLITE_OMIT_LOAD_EXTENSION=1",
            "-DSQLITE_OMIT_TRACE=1",
            "-DSQLITE_OMIT_PROGRESS_CALLBACK=1",
            "-DSQLITE_OMIT_SHARED_CACHE=1",
            "-DSQLITE_OMIT_DECLTYPE=1",
            "-DSQLITE_DEFAULT_MEMSTATUS=0",
        }),
    });
    const host_zqlite = b.dependency("zqlite", .{
        .target = b.graph.host,
        .optimize = .debug,
        .sqlite3 = @as([]const []const u8, &.{"-std=c99"}),
    });

    // ------------------------------------------------------------- library

    const module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        // std.heap.c_allocator is libc malloc/free, so a buffer allocated on
        // one side of the ABI can be freed on the other; zqlite brings its
        // own statically linked SQLite.
        .link_libc = true,
    });
    module.addImport("lovelycarve", sdk.module("lovelycarve"));
    module.addImport("ini_zig", ini.module("ini_zig"));
    module.addImport("zqlite", zqlite.module("zqlite"));

    const library = b.addLibrary(.{
        .name = "androidsysteminfo",
        .root_module = module,
        .linkage = .dynamic,
        // Pin the LLVM backend. On Windows 0.17 emits the import library
        // (.lib) and a .pdb next to the DLL either way; this only decides
        // which code generator produces them.
        .use_llvm = true,
    });
    // Zig routes Windows DLLs to bin/ by default; plugin.toml expects the
    // library next to the manifest, so pin the install directory.
    b.getInstallStep().dependOn(&b.addInstallArtifact(library, .{
        .dest_dir = .{ .override = .lib },
    }).step);

    // ---------------------------------------------------------------- tests

    // The same host build of the plugin, tested in Debug.
    const host_root = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = b.graph.host,
        .optimize = .debug,
        .link_libc = true,
    });
    host_root.addImport("lovelycarve", host_sdk.module("lovelycarve"));
    host_root.addImport("ini_zig", host_ini.module("ini_zig"));
    host_root.addImport("zqlite", host_zqlite.module("zqlite"));
    const tests = b.addTest(.{
        .name = "androidsysteminfo-test",
        .root_module = host_root,
    });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);

    // --------------------------------------------------------------- probe

    // Dev tool: run the analysis core over real data-partition files.
    const probe_module = b.createModule(.{
        .root_source_file = b.path("src/probe.zig"),
        .target = b.graph.host,
        .optimize = .debug,
        .link_libc = true,
    });
    probe_module.addImport("lovelycarve", host_sdk.module("lovelycarve"));
    probe_module.addImport("ini_zig", host_ini.module("ini_zig"));
    probe_module.addImport("zqlite", host_zqlite.module("zqlite"));
    const probe_exe = b.addExecutable(.{ .name = "probe", .root_module = probe_module });
    const probe_install = b.addInstallArtifact(probe_exe, .{});
    const probe_step = b.step("probe", "Build the Android analysis probe (zig-out/bin/probe)");
    probe_step.dependOn(&probe_install.step);

    // --------------------------------------------------------------- schema

    // `src/describe.zig` prints the library's `plugin.hello` as JSON — the
    // same document `lc-plugin-host --describe` writes.
    const describe_module = b.createModule(.{
        .root_source_file = b.path("src/describe.zig"),
        .target = b.graph.host,
        .optimize = .debug,
        .link_libc = true,
    });
    describe_module.addImport("lovelycarve", host_sdk.module("lovelycarve"));
    describe_module.addImport("plugin", host_root);
    const describe_exe = b.addExecutable(.{
        .name = "describe",
        .root_module = describe_module,
    });
    const describe_run = b.addRunArtifact(describe_exe);
    const schema_path = describe_run.addOutputFileArg("schema.json");

    const schema_step = b.step("schema", "Write zig-out/schema.json from the library");
    schema_step.dependOn(&b.addInstallFileWithDir(schema_path, .prefix, "schema.json").step);

    // -------------------------------------------------------------- package

    const pack_module = b.createModule(.{
        .root_source_file = b.path("../../../../scripts/pack.zig"),
        .target = b.graph.host,
        .optimize = .debug,
    });
    const pack_exe = b.addExecutable(.{ .name = "pack", .root_module = pack_module });
    const pack_run = b.addRunArtifact(pack_exe);
    // The staged directory and the archive are written under the install
    // prefix (zig-out unless `--prefix` says otherwise).
    pack_run.addArg("--out");
    pack_run.addArg("../../../../dist");
    // Empty dist/ first, so it holds exactly the packages of this run.
    pack_run.addArg("--clean");
    pack_run.addArgs(&.{ "--platform", platformName(target.result) });
    pack_run.addArg("--plugin");
    pack_run.addFileArg(b.path("plugin.toml"));
    pack_run.addArg("--library");
    pack_run.addArtifactArg(library);
    pack_run.addArg("--schema");
    pack_run.addFileArg(schema_path);
    pack_run.step.dependOn(&library.step);
    const package_step = b.step("package", "Package the plugin into dist/");
    package_step.dependOn(&pack_run.step);
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
