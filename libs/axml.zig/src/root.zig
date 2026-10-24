//! `axml.zig` — Android binary XML (AXML) reader for forensic parsing.
//!
//! AXML is the resource-compiled binary XML inside APK files: the manifest,
//! layouts and every other resource XML document. This module parses such
//! documents without interpreting their meaning, so plugins can extract
//! evidence from them. It was extracted from the LovelyCarve APK analyzer's
//! parser core and is shared by every plugin that reads AXML.
//!
//! Modules:
//!
//! - [`document`] — the document: string pools, resource map, parse events
//! - [`chunk`] — chunk headers and resource chunk types
//! - [`string_pool`] — UTF-8/UTF-16 string pools
//! - [`typed_value`] — attribute values (ints, floats, strings, references)
//! - [`cursor`] — the bounds-checked big-endian reader underneath
//! - [`logging`] — pluggable parse diagnostics (see the module doc)

pub const chunk = @import("chunk.zig");
pub const cursor = @import("cursor.zig");
pub const document = @import("document.zig");
pub const logging = @import("logging.zig");
pub const string_pool = @import("string_pool.zig");
pub const typed_value = @import("typed_value.zig");

// The document parser's public types, re-exported for call sites that spell
// them `axml.Document`, `axml.StartElement` and friends.
pub const Document = document.Document;
pub const StartElement = document.StartElement;
pub const Attribute = document.Attribute;
pub const Event = document.Event;
pub const Node = document.Node;

test {
    _ = chunk;
    _ = cursor;
    _ = document;
    _ = logging;
    _ = string_pool;
    _ = typed_value;
}
