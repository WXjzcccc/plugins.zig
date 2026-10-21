//! `regf.zig` — a pure-Zig reader and in-place writer for Windows Registry
//! hive files (REGF format).
//!
//! REGF is the format of registry hives: `SYSTEM`, `SOFTWARE`, `SAM`,
//! `SECURITY`, `NTUSER.DAT`, and the **BCD**
//! (`\EFI\Microsoft\Boot\BCD`). This is a port of the Rust crate `regf-rs`
//! 0.1.1 to Zig 0.17, keeping the same public surface and semantics.
//!
//! # Example
//! ```zig
//! const regf = @import("regf_zig");
//!
//! var hive = try regf.Hive.fromFile(gpa, io, std.Io.Dir.cwd(), "SYSTEM");
//! defer hive.deinit();
//!
//! const root = try hive.rootKey();
//! defer root.deinit(gpa);
//! std.debug.print("root = {s}\n", .{root.name});
//!
//! const build = try hive.getValue("Select", "Current");
//! defer build.deinit(gpa);
//! std.debug.print("CurrentBuild = {d}\n", .{build.dword});
//! ```
//!
//! # Write safety
//! Any modification is rejected on a "dirty" hive (a pending transaction log,
//! see [`Hive.isDirty`]). Values larger than a single cell ("big data") are
//! read but not produced on write: `error.ValueTooLarge` is returned instead
//! of writing a corrupt hive.

const std = @import("std");

// Internal module handles. Kept private so the public surface is exactly the
// re-exports below; `name`, `cell` and `hbin` are exposed because their pure
// helpers (case folding, name hashing, cell/offset arithmetic) are useful to
// callers that already hold a hive image and want to inspect it directly.
const error_mod = @import("error.zig");
const header_mod = @import("header.zig");
const hive_mod = @import("hive.zig");

/// Windows key-name ordering, case folding and `lh` hashing.
pub const name = @import("name.zig");
/// Value typing and encoding.
pub const value = @import("value.zig");
/// Hive-bin and cell offset arithmetic.
pub const hbin = @import("hbin.zig");
/// REGF record codecs (`nk`, `vk`, `lf`/`lh`/`li`/`ri`, `sk`, `db`).
pub const cell = @import("cell.zig");

/// Errors raised when reading or writing a REGF hive.
pub const Error = error_mod.Error;
/// Diagnostic payload accompanying an [`Error`].
pub const Diag = error_mod.Diag;
/// Renders an error and its diagnostics into a caller-provided buffer.
pub const describe = error_mod.describe;

/// The 4096-byte base block that precedes the hive bins.
pub const Header = header_mod.Header;
/// Size of the base block (and start offset of the hive bins).
pub const REGF_HEADER_SIZE = header_mod.REGF_HEADER_SIZE;

/// A REGF hive loaded in memory.
pub const Hive = hive_mod.Hive;
/// Public view of a key node.
pub const KeyNode = hive_mod.KeyNode;
/// A named value read from a key.
pub const ValueEntry = hive_mod.ValueEntry;

/// A registry value's type (the `type` field of a `vk` cell).
pub const RegType = value.RegType;
/// A decoded registry value.
pub const RegValue = value.RegValue;

test {
    // Pull in every module's tests.
    _ = error_mod;
    _ = header_mod;
    _ = name;
    _ = value;
    _ = hbin;
    _ = cell;
    _ = hive_mod;
    // Hostile-input and fuzz tests: malformed hives must always yield an
    // error, never a panic, an out-of-bounds read or a leak.
    _ = @import("robustness.zig");
}
