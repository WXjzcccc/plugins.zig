//! `example` — demo support code for the `regf_zig` library.
//!
//! The reusable part lives in [`mount`]: it decodes the `MountedDevices` key of
//! a SYSTEM hive into structured entries (drive letters, volume GUIDs and
//! device paths) and renders them as a report.

/// Mount-table decoding for the `MountedDevices` key.
pub const mount = @import("mount.zig");

test {
    _ = mount;
}
