//! Thin re-export of the shared AXML library's bounds-checked cursor.
//!
//! The cursor implementation lives in `libs/axml.zig` so the library and this
//! plugin share one type; the ZIP reader here uses the same reader for its
//! headers. Import this module (or `axml_zig` directly) — never copy the type.

pub const Cursor = @import("axml_zig").cursor.Cursor;
pub const checkedAdd = @import("axml_zig").cursor.checkedAdd;
pub const u64ToUsize = @import("axml_zig").cursor.u64ToUsize;
