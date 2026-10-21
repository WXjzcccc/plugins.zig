# regf.zig

Pure-Zig reader and in-place writer for Windows Registry hive files
(**REGF format**) — no C dependency, no code generation, nothing outside Zig's
`std`.

REGF is the format of registry hives: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`,
`NTUSER.DAT`, and the **BCD** (`\EFI\Microsoft\Boot\BCD`). The Rust ecosystem
has a gap here — `nt-hive` reads but does not write, `regf` only creates fresh
hives, and the complete solutions go through C bindings (`hivex`). `regf.zig`
targets the same missing slot: **reading + in-place writing**, in pure Zig, in
a single module you can drop into a bootloader, a forensics tool or a UEFI
utility.

The package is **library-only**: there is no executable, no `main`, no CLI.
You import the module as `regf_zig` and call it.

## Status

- [x] **Reading**: base block + XOR-32 checksum, key navigation (`nk`), subkey
      lists (`lf`/`lh`/`li`/`ri`, with `ri` sublists flattened recursively),
      values (`vk`) of every `REG_*` type (`REG_SZ`, `REG_EXPAND_SZ`,
      `REG_BINARY`, `REG_DWORD`, `REG_DWORD_BIG_ENDIAN`, `REG_LINK`,
      `REG_MULTI_SZ`, `REG_QWORD`, and unknown types as raw bytes), inline data
      (≤ 4 bytes stored in the `vk` data field) and big data (`db`).
- [x] **In-place writing**: first-fit allocation with splitting, freeing with
      forward coalescing, **sorted insertion** into subkey lists (required by
      Windows' binary search), key creation (security inherited from the parent,
      `sk` reference count incremented), setting/deleting values, checksum and
      sequence-number recomputation.
- [x] **Safety**: refuses to write to an unreconciled hive (pending transaction
      log); "big data" values are read but refused on write (`ValueTooLarge`)
      rather than producing a questionable hive.
- [x] **Hostile-input hardening**: a hive file is attacker-controlled data.
      Truncated images, bogus cell sizes, dangling offsets, cyclic `ri` lists
      and lying `vk` sizes all return an `Error` — never a panic, an
      out-of-bounds read, an integer-overflow trap or an unbounded recursion.
      This is enforced by a dedicated fuzz/robustness suite (see
      [Tests](#tests)).
- [x] **Tests**: 94 tests, zero leaks, validated against real Windows hives
      shipped in `testfiles/`.

### Accepted limitations

Carried over from the Rust implementation, and deliberate:

- Name case folding covers the **ASCII plane** (enough for standard registry
  names); non-ASCII names are compared code unit by code unit. Names are
  stored and returned as UTF-8, widened to UTF-16LE when the name is not ASCII.
- An `ri` list traversed during an insertion is rewritten as a single flat leaf
  list preserving the leaf kind (`lf`/`lh`/`li`), valid up to 65,535 subkeys,
  rather than rebalanced into a fresh `ri`. Nested `ri` lists are read
  recursively but bounded at depth 8 — far beyond anything Windows writes.
- Writing a single value is capped at **one cell** (< 16 KiB, `16344` bytes of
  data); beyond that `setValue` returns `error.ValueTooLarge` with
  `diag.size`/`diag.max` filled in. Big-data segments are still *read*; each
  segment is clamped to the spec's 16,344-byte maximum so that a segment cell's
  8-byte alignment padding is never spliced into the value.
- The hive is loaded entirely into memory (`Hive.fromBytes` copies). There is
  no memory-mapped or streaming mode.

## Requirements

Zig **0.17.0** or newer. No C dependency, no build-time codegen, no
dependencies in `build.zig.zon`.

## Usage

Add the package to your `build.zig.zon`, then create a module in `build.zig`:

```zig
const regf_zig = b.dependency("regf_zig", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("regf_zig", regf_zig.module("regf_zig"));
```

Read a hive from disk, walk it, write to it, and serialize it back:

```zig
const std = @import("std");
const regf = @import("regf_zig");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // Zig 0.17 I/O: file APIs need a `std.Io` value.
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var hive = try regf.Hive.fromFile(gpa, io, std.Io.Dir.cwd(), "SYSTEM");
    defer hive.deinit();

    var root = try hive.rootKey();
    defer root.deinit(gpa);
    std.debug.print("root = {s}\n", .{root.name});

    const current = try hive.getValue("Select", "Current");
    defer current.deinit(gpa);
    std.debug.print("Select\\Current = {d}\n", .{current.dword});

    // Writing mutates the image in place.
    var build = try hive.createKey("Setup\\Build");
    defer build.deinit(gpa);

    {
        const edition: regf.RegValue = .{ .sz = try gpa.dupe(u8, "Zig") };
        defer edition.deinit(gpa); // setValue copies: the caller keeps ownership
        try hive.setValue("Setup\\Build", "Edition", edition);
    }
    try hive.setValue("Setup\\Build", "Number", .{ .dword = 19045 });

    var values = try hive.listValues("Setup\\Build", gpa);
    defer {
        for (values.items) |entry| entry.deinit(gpa);
        values.deinit(gpa);
    }
    for (values.items) |entry| std.debug.print("  value {s}\n", .{entry.name});

    const image = try hive.toBytes(gpa);
    defer gpa.free(image);
    std.debug.print("image = {d} bytes\n", .{image.len});

    try hive.save(io, std.Io.Dir.cwd(), "SYSTEM");
}
```

Or build a hive from nothing, entirely in memory — useful for the BCD, which is
often generated rather than edited:

```zig
const regf = @import("regf_zig");

var hive = try regf.Hive.initEmpty(gpa, "BCD");
defer hive.deinit();

var objects = try hive.createKey("Objects\\{bootmgr}");
defer objects.deinit(gpa);

{
    const description: regf.RegValue = .{ .sz = try gpa.dupe(u8, "Windows Boot Manager") };
    defer description.deinit(gpa);
    try hive.setValue("Objects\\{bootmgr}", "Description", description);
}

var names = try hive.listSubkeys("", gpa);
defer {
    for (names.items) |n| gpa.free(n);
    names.deinit(gpa);
}

const image = try hive.toBytes(gpa);
defer gpa.free(image);
```

Paths use `\` as the separator and are case-insensitive; the empty path (or a
leading `\`) addresses the root key.

### Errors and diagnostics

Every fallible function returns an error union over `regf_zig.Error`:

| Error | Meaning |
| --- | --- |
| `BadSignature` | base block does not start with `regf` |
| `BadChecksum` | header XOR-32 checksum mismatch |
| `Truncated` | out-of-bounds read |
| `CorruptCell` | inconsistent cell size, signature, or list |
| `KeyNotFound` | path resolution failed |
| `ValueNotFound` | value name not found under the key |
| `DirtyHive` | write rejected: pending transaction log / sequence mismatch |
| `ValueTooLarge` | write rejected: data needs big-data segments |
| `OutOfMemory` | allocation failure |

Zig error sets cannot carry payloads, so the details the Rust API exposes as
enum fields travel through an optional `*Diag` out-parameter (here `bytes` is a
hive image and `value` a `RegValue`):

```zig
var diag: regf.Diag = .{};
var hive = regf.Hive.fromBytes(gpa, bytes, &diag) catch |err| {
    var buf: [128]u8 = undefined;
    std.debug.print("{s}\n", .{regf.describe(err, diag, &buf)});
    return err;
};
defer hive.deinit();

// After a failed write, the diagnostics are also on the hive itself:
hive.setValue("", "big", value) catch |err| {
    const d = hive.lastDiag();   // d.size, d.max for ValueTooLarge
    return err;
};
```

State and metadata are reachable without extra calls: `hive.isDirty()` reports
whether a write would be refused, `hive.base_block` is the parsed `Header`
(`hive_bins_size`, sequence numbers, versions), `hive.image()` borrows the
current (unfinalized) image, and `hive.header()` returns a pointer to the
`Header`.

## Memory ownership

There is no hidden allocation and no arena: everything is explicit.

- Every function that returns a `[]u8`, a `[][]u8` or an
  `std.ArrayList(T)` hands **ownership to the caller**, who must release it with
  the **same allocator** it was created with.
- `RegValue.deinit(gpa)`, `KeyNode.deinit(gpa)` and `ValueEntry.deinit(gpa)`
  release the buffers they own. `RegValue` owns its string/binary slices and
  every item of `multi_sz`.
- `Hive.deinit()` releases the hive image. `Hive.toBytes(gpa)` returns a
  **copy** — the caller owns it and the hive stays usable.
- `Hive.setValue` does **not** take ownership of the value: it encodes a copy
  into the image, so the caller must still `deinit` its `RegValue`. This is why
  the examples above wrap the owned string in a scoped block with `defer`.
- `Hive.listSubkeys` and `Hive.listValues` return a list you own *and* the
  names/values inside it — free each item, then the list.
- `Hive.fromBytes` copies the input bytes, so the caller keeps ownership of
  them; `Hive.fromFile` reads the file into memory and frees the intermediate.

Because `std.ArrayList(T)` is unmanaged in Zig 0.17, list methods take the
allocator: `list.append(gpa, item)`, `list.deinit(gpa)`, and a fresh list is
`.empty`.

## Tests

```sh
zig build test
```

The suite is **self-contained**: it builds synthetic BCD-shaped hives in memory
(`Hive.initEmpty` + `createKey`/`setValue`) and round-trips them, so no personal
hive is versioned and nothing outside the repository is read. It covers the base
block and checksum, every value type, inline and big data, sorted insertion,
allocation/freeing/coalescing, hbin growth, non-ASCII names, save/load, and a
robustness + fuzz suite (`src/robustness.zig`) asserting that malformed input
always produces an error rather than a panic, an out-of-bounds read, an
integer-overflow trap or an unbounded recursion. The whole suite runs in a
couple of seconds and is leak-checked by `std.testing.allocator`.

Real-hive validation uses **only** the fixtures in `testfiles/` — `SAM`,
`SECURITY`, `SYSTEM` and `SOFTWARE`, read-only. Those tests are skipped (not
failed) when the directory is absent, so the suite still passes in a bare
checkout. The tests never touch the live registry, and never shell out to
`reg save` / `reg query`; no hive is ever dumped from the running system.

## License

Licensed under either of, at your option:

- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this repository shall be dual-licensed as above, without any
additional terms or conditions.
