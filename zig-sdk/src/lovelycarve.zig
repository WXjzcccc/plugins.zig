//! LovelyCarve plugin SDK for Zig — LPP v2 over the C ABI v1, behind one
//! import:
//!
//! ```zig
//! const lc = @import("lovelycarve");
//!
//! const RELEASE_SCHEMA = lc.RecordSchema.new("demo.release", "系统信息", &.{
//!     lc.Field.new("key", "英文名称", .text).asKey(),
//!     lc.Field.new("value", "值", .text),
//! });
//!
//! fn analyze(run: *const lc.Run) lc.Error!void {
//!     const view = try run.requireView();
//!     const file = (try view.open("etc/os-release")) orelse return;
//!     try run.record("demo.release", &.{ lc.wire.str("NAME"), lc.wire.str("Demo") })
//!         .from(&file)
//!         .emit();
//! }
//!
//! pub const plugin = lc.Plugin{
//!     .id = "com.example.demo",
//!     .records = &.{RELEASE_SCHEMA},
//!     .analyzers = &.{lc.analyzer("demo", analyze)},
//! };
//!
//! comptime {
//!     lc.exportPlugin(@This());
//! }
//! ```
//!
//! Every module is also reachable on its own (`@import("lovelycarve").wire`),
//! which keeps the SDK usable from tests that only need one piece.

/// The C ABI v1 layouts, mirroring `sdk/include/lovelycarve_plugin.h`.
pub const abi = @import("abi.zig");

/// The MessagePack subset LPP frames use, plus the dynamic `Value` type.
pub const wire = @import("wire.zig");

/// JSON output for `schema.json` (`lc-plugin-host --describe`).
pub const json = @import("json.zig");

/// Payload helpers: field lookup, optionals, ranges, byte replies.
pub const value = @import("value.zig");

/// The LPP error codes and the fault slot that carries their messages.
pub const errorcodes = @import("error.zig");
pub const Error = errorcodes.Error;
pub const Fault = errorcodes.Fault;

/// `splitLines` / `decodeLossy` for parsers of text evidence.
pub const text = @import("text.zig");

/// LPP v2 method names, limits and payload types (`run.start`, `file.*`, ...).
pub const protocol = @import("protocol.zig");

/// Record schemas: the typed shape of what an analyzer emits.
pub const schema = @import("schema.zig");
pub const Field = schema.Field;
pub const FieldKind = schema.FieldKind;
pub const PropertyLayout = schema.PropertyLayout;
pub const RecordSchema = schema.RecordSchema;

/// Records and their values: timestamps, severities, sources, dynamic records.
pub const record = @import("record.zig");
pub const DynamicRecord = record.DynamicRecord;
pub const Severity = record.Severity;
pub const SourceRef = record.SourceRef;
pub const Timestamp = record.Timestamp;

/// Path-pattern validation for declared inputs and `view.find`.
pub const glob = @import("glob.zig");

/// Host calls, cancellation and logging.
pub const host = @import("host.zig");
pub const Context = host.Context;
pub const HostConnection = host.HostConnection;
pub const LogLevel = host.LogLevel;

/// Read-only image sources handed to a filesystem parser.
pub const source = @import("source.zig");
pub const Source = source.Source;

/// Volumes, parsers and the frozen `fs.*` DTOs.
pub const filesystem = @import("filesystem.zig");
pub const Attributes = filesystem.Attributes;
pub const FileSystemParser = filesystem.FileSystemParser;
pub const FsNode = filesystem.FsNode;
pub const FsStat = filesystem.FsStat;
pub const NodeKind = filesystem.NodeKind;
pub const NodePage = filesystem.NodePage;
pub const Probe = filesystem.Probe;
pub const Timestamps = filesystem.Timestamps;
pub const Volume = filesystem.Volume;
/// Wraps a `Volume` implementation into the vtable the runtime calls.
pub const volumeOf = filesystem.volumeOf;
/// Wraps a `FileSystemParser` implementation into its vtable.
pub const parserOf = filesystem.parserOf;

/// Read-only file handles issued for one run.
pub const file = @import("file.zig");
pub const FileRef = file.FileRef;
pub const MaterializedFile = file.MaterializedFile;

/// A run's read-only path tree (`view.*`).
pub const view = @import("view.zig");
pub const Node = view.Node;
pub const ViewNodeKind = view.NodeKind;
pub const View = view.View;

/// What a plugin declares about itself: identity, record types, analyzers.
pub const plugin_mod = @import("plugin.zig");
pub const Plugin = plugin_mod.Plugin;
pub const analyzer = plugin_mod.analyzer;
pub const Analyzer = plugin_mod.Analyzer;

/// The run an analyzer works in and the records it emits.
pub const run = @import("run.zig");
pub const Emit = run.Emit;
pub const Options = run.Options;
pub const Profile = run.Profile;
pub const Run = run.Run;

/// The C ABI plumbing: the entry point, dispatch and cancellation.
pub const runtime = @import("runtime.zig");
pub const exportPlugin = runtime.exportPlugin;
pub const entry = runtime.entry;

/// Test doubles: a fake host table and a driver, so a plugin's own tests can
/// exercise the real C ABI without a running LovelyCarve.
pub const testing = @import("testing.zig");

/// The host read limit: one `file.read` / `source.read` returns at most 4 MiB.
pub const MAX_HOST_READ: usize = 4 * 1024 * 1024;

/// The LPP protocol version this SDK speaks.
pub const PROTOCOL_VERSION: u16 = 2;

test {
    // Pull every module's tests into `zig build test`.
    _ = abi;
    _ = wire;
    _ = json;
    _ = value;
    _ = errorcodes;
    _ = text;
    _ = protocol;
    _ = schema;
    _ = record;
    _ = glob;
    _ = host;
    _ = source;
    _ = filesystem;
    _ = file;
    _ = view;
    _ = run;
    _ = plugin_mod;
    _ = runtime;
    _ = testing;
}
