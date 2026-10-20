//! Analyzers and the run they work in.
//!
//! One Run is one execution of an analyzer: its target view, inputs, options,
//! the evidence profile facts known before it started, and the channel its
//! records go out on. The host answers a batch only after it stored the
//! records, so run.emit is also the run's backpressure.
//!
//! An analyzer receives a *const Run (the plugin table declares that shape, so
//! a run can be shared with helper code), which is why the emitter state lives
//! behind a small lock in Run.shared: emitting, the summary and the flush
//! counter are the only mutable parts of a run.
//!
//!     fn analyze(run: *const lc.Run) lc.Error!void {
//!         const view = try run.requireView();
//!         const file = (try view.open("etc/passwd")) orelse return;
//!         for (try file.readLines(1 << 20)) |line| {
//!             try run.record("demo.user", &.{lc.wire.str(line)}).from(&file).emit();
//!         }
//!         run.setSummary("1 行");
//!     }
//!
//! Records are validated against their schema before they are buffered, so an
//! analyzer that emits a record type it never registered fails with
//! UNKNOWN_RECORD_TYPE and a record whose values do not match its fields fails
//! with INVALID_RECORD.

const std = @import("std");

const file_mod = @import("file.zig");
const host = @import("host.zig");
const protocol = @import("protocol.zig");
const record_mod = @import("record.zig");
const schema = @import("schema.zig");
const sdk = @import("error.zig");
const value = @import("value.zig");
const view_mod = @import("view.zig");
const wire = @import("wire.zig");

/// Records buffered before a run.emit batch is sent.
pub const BATCH_RECORDS: usize = 1000;
/// Encoded bytes buffered before a batch is sent (well below one frame).
pub const BATCH_BYTES: usize = 2 * 1024 * 1024;
/// Largest single encoded record.
pub const MAX_RECORD_BYTES: usize = 6 * 1024 * 1024;

/// The options a run was started with (from the analyzer's declared options).
pub const Options = struct {
    values: wire.Value = protocol.empty_map,

    pub fn init(values: wire.Value) Options {
        return .{ .values = values };
    }

    /// The raw value of option id, when the host sent one.
    pub fn get(self: Options, id: []const u8) ?wire.Value {
        return self.values.get(id);
    }

    pub fn flag(self: Options, id: []const u8) bool {
        return switch (self.get(id) orelse return false) {
            .boolean => |enabled| enabled,
            else => false,
        };
    }

    pub fn text(self: Options, id: []const u8) ?[]const u8 {
        return switch (self.get(id) orelse return null) {
            .string => |text_value| text_value,
            else => null,
        };
    }

    /// The selected choices of a multi-choice option: an array of strings, or
    /// a single string. The list is allocated from alloc.
    pub fn list(
        self: Options,
        alloc: std.mem.Allocator,
        id: []const u8,
    ) error{OutOfMemory}![]const []const u8 {
        switch (self.get(id) orelse return &.{}) {
            .array => |items| {
                var selected: std.ArrayList([]const u8) = .empty;
                for (items) |item| {
                    switch (item) {
                        .string => |text_value| try selected.append(alloc, text_value),
                        else => {},
                    }
                }
                return selected.toOwnedSlice(alloc);
            },
            .string => |text_value| {
                const selected = try alloc.alloc([]const u8, 1);
                selected[0] = text_value;
                return selected;
            },
            else => return &.{},
        }
    }

    /// Whether choice of multi-choice option id is selected; an absent or
    /// empty selection selects every choice.
    pub fn wants(self: Options, id: []const u8, choice: []const u8) bool {
        const found = self.values.get(id) orelse return true;
        switch (found) {
            .array => |items| {
                if (items.len == 0) return true;
                for (items) |item| {
                    switch (item) {
                        .string => |text_value| if (std.mem.eql(u8, text_value, choice)) return true,
                        else => {},
                    }
                }
                return false;
            },
            .string => |text_value| return std.mem.eql(u8, text_value, choice),
            else => return true,
        }
    }
};

/// Evidence profile facts known when the run started.
pub const Profile = struct {
    values: wire.Value = protocol.empty_map,

    pub fn init(values: wire.Value) Profile {
        return .{ .values = values };
    }

    pub fn get(self: Profile, key: []const u8) ?wire.Value {
        return self.values.get(key);
    }

    pub fn text(self: Profile, key: []const u8) ?[]const u8 {
        return switch (self.get(key) orelse return null) {
            .string => |text_value| text_value,
            else => null,
        };
    }

    /// IANA time zone of the system (Asia/Shanghai), when known.
    pub fn timezone(self: Profile) ?[]const u8 {
        return self.text("timezone");
    }

    pub fn hostname(self: Profile) ?[]const u8 {
        return self.text("hostname");
    }
};

/// One encoded record waiting in the emit buffer.
const Buffered = struct {
    encoded: []u8,
};

/// The mutable part of a run: the emit buffer, the counters and the summary.
///
/// It sits behind a lock because a run is handed to the analyzer as a
/// *const Run; the lock is uncontended in practice (one analyzer runs one run
/// on one thread) but keeps a helper thread from corrupting the buffer.
const Shared = struct {
    lock: std.atomic.Mutex = .unlocked,
    /// Records buffered for the next run.emit, in emission order.
    buffered: std.ArrayList(Buffered) = .empty,
    /// Encoded bytes buffered for the next batch.
    buffered_bytes: usize = 0,
    /// Records emitted so far (buffered and sent).
    emitted: u64 = 0,
    summary: ?[]const u8 = null,

    fn acquire(self: *Shared) void {
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
    }

    fn release(self: *Shared) void {
        self.lock.unlock();
    }
};

/// One execution of an analyzer: its target, inputs, options and the channel
/// its records go out on.
pub const Run = struct {
    ctx: host.Context,
    run_id: []const u8,
    analyzer: []const u8,
    view: ?view_mod.View,
    inputs: []const file_mod.FileRef,
    options: Options,
    profile: Profile,
    locale: []const u8,
    schemas: []const schema.RecordSchema,
    shared: *Shared,

    /// Builds the run of one run.start: the view of a system or evidence
    /// target and one file handle per resolved input.
    pub fn init(
        ctx: host.Context,
        start: protocol.RunStart,
        schemas: []const schema.RecordSchema,
    ) sdk.Error!Run {
        const alloc = ctx.arena;
        const view: ?view_mod.View = switch (start.target) {
            .files => null,
            .system => |info| view_mod.View.init(ctx, info),
            .evidence => |info| view_mod.View.init(ctx, info),
        };
        const inputs = try alloc.alloc(file_mod.FileRef, start.inputs.len);
        for (start.inputs, inputs) |info, *slot| slot.* = file_mod.FileRef.init(ctx, info);
        const shared = try alloc.create(Shared);
        shared.* = .{};
        return .{
            .ctx = ctx,
            .run_id = start.run_id,
            .analyzer = start.analyzer,
            .view = view,
            .inputs = inputs,
            .options = Options.init(start.options),
            .profile = Profile.init(start.profile),
            .locale = start.locale,
            .schemas = schemas,
            .shared = shared,
        };
    }

    pub fn id(self: *const Run) []const u8 {
        return self.run_id;
    }

    pub fn analyzerId(self: *const Run) []const u8 {
        return self.analyzer;
    }

    /// The system or evidence view; null for a run over files.
    pub fn viewOrNull(self: *const Run) ?view_mod.View {
        return self.view;
    }

    /// The view, or INVALID_TARGET for a run over files.
    pub fn requireView(self: *const Run) sdk.Error!view_mod.View {
        return self.view orelse sdk.failf(
            self.ctx.arena,
            "INVALID_TARGET",
            "analyzer {s} needs a system or evidence view",
            .{self.analyzer},
        );
    }

    /// The operating system of a system run.
    pub fn system(self: *const Run) ?protocol.SystemInfo {
        const view = self.view orelse return null;
        return view.system();
    }

    /// Files resolved for the run: the selected file of a file run, or the
    /// matches of the analyzer's declared inputs.
    pub fn inputsOf(self: *const Run) []const file_mod.FileRef {
        return self.inputs;
    }

    pub fn optionValues(self: *const Run) Options {
        return self.options;
    }

    pub fn profileFacts(self: *const Run) Profile {
        return self.profile;
    }

    /// UI locale (zh-CN, en) for text the analyzer writes itself.
    pub fn uiLocale(self: *const Run) []const u8 {
        return self.locale;
    }

    pub fn context(self: *const Run) host.Context {
        return self.ctx;
    }

    pub fn isCancelled(self: *const Run) bool {
        return self.ctx.isCancelled();
    }

    pub fn checkCancelled(self: *const Run) sdk.Error!void {
        return self.ctx.checkCancelled();
    }

    pub fn log(self: *const Run, level: host.LogLevel, message: []const u8) void {
        self.ctx.log(level, message);
    }

    /// Emits a record without a source.
    pub fn emit(self: *const Run, record_type: []const u8, values: []const wire.Value) sdk.Error!void {
        return (Emit{ .run = self, .record_type = record_type, .values = values }).emit();
    }

    /// Starts a record with sources, a title or a severity.
    pub fn record(self: *const Run, record_type: []const u8, values: []const wire.Value) Emit {
        return .{ .run = self, .record_type = record_type, .values = values };
    }

    /// Starts a record of a run-time schema.
    pub fn dynamic(self: *const Run, dynamic_record: *const record_mod.DynamicRecord) Emit {
        return .{
            .run = self,
            .record_type = dynamic_record.schema.record_type,
            .values = dynamic_record.valuesSlice(),
        };
    }

    /// Starts a record from positional values of a registered record type
    /// (table-driven analyzers that build the values themselves).
    pub fn recordValues(self: *const Run, record_type: []const u8, values: []const wire.Value) Emit {
        return self.record(record_type, values);
    }

    /// Records an evidence profile fact (timezone, hostname, users, ...) that
    /// analyzers declaring requires on it read in later runs. The analyzer must
    /// declare the key in its manifest provides.
    pub fn provide(self: *const Run, key: []const u8, fact: wire.Value) sdk.Error!void {
        const system_id: wire.Value = if (self.system()) |info|
            wire.str(info.id)
        else
            .nil;
        return self.emit(record_mod.PROFILE_FACT, &.{ wire.str(key), fact, system_id });
    }

    /// Records something the run could not do. Warnings are kept with the
    /// run's results; they do not fail it.
    pub fn warn(self: *const Run, code: []const u8, message: []const u8) sdk.Error!void {
        return self.sendWarning(code, message, null);
    }

    /// Run.warn about one input file.
    pub fn warnFile(
        self: *const Run,
        file: file_mod.FileRef,
        code: []const u8,
        message: []const u8,
    ) sdk.Error!void {
        return self.sendWarning(code, message, file.id());
    }

    fn sendWarning(
        self: *const Run,
        code: []const u8,
        message: []const u8,
        file_id: ?[]const u8,
    ) sdk.Error!void {
        _ = try self.ctx.callHost(protocol.method.run_warn, try value.map(self.ctx.arena, &.{
            value.entry("run_id", value.str(self.run_id)),
            value.entry("code", value.str(code)),
            value.entry("message", value.str(message)),
            value.entry("file_id", value.optionalString(file_id)),
        }));
    }

    /// Reports progress to the task center.
    pub fn progress(
        self: *const Run,
        current: u64,
        total: ?u64,
        message: ?[]const u8,
    ) sdk.Error!void {
        _ = try self.ctx.callHost(protocol.method.run_progress, try value.map(self.ctx.arena, &.{
            value.entry("run_id", value.str(self.run_id)),
            value.entry("current", value.uint(current)),
            value.entry("total", value.optionalUintValue(total)),
            value.entry("message", value.optionalString(message)),
        }));
    }

    /// A one-line summary shown with the run (the host counts records and
    /// warnings itself).
    pub fn setSummary(self: *const Run, summary: []const u8) void {
        const shared = self.shared;
        shared.acquire();
        defer shared.release();
        shared.summary = summary;
    }

    /// Records emitted so far.
    pub fn emitted(self: *const Run) u64 {
        const shared = self.shared;
        shared.acquire();
        defer shared.release();
        return shared.emitted;
    }

    /// Validates one record against its schema, encodes it and buffers it for
    /// the next batch, sending the batch when it is full.
    fn push(
        self: *const Run,
        record_type: []const u8,
        values: []const wire.Value,
        title: ?[]const u8,
        severity: ?record_mod.Severity,
        sources: []const record_mod.SourceRef,
    ) sdk.Error!void {
        const record_schema = self.findSchema(record_type) orelse return sdk.failf(
            self.ctx.arena,
            "UNKNOWN_RECORD_TYPE",
            "record type {s} is not registered with Plugin.records",
            .{record_type},
        );
        record_schema.validateValues(values) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidRecord => return sdk.failf(
                self.ctx.arena,
                "INVALID_RECORD",
                "a {s} record does not match its schema",
                .{record_type},
            ),
        };
        const encoded = try self.encodeRecord(record_type, values, title, severity, sources);
        if (encoded.len > MAX_RECORD_BYTES) {
            return sdk.failf(
                self.ctx.arena,
                "RESOURCE_LIMIT",
                "a {s} record encodes to {d} bytes; the limit is {d}",
                .{ record_type, encoded.len, MAX_RECORD_BYTES },
            );
        }

        const shared = self.shared;
        var full = false;
        {
            shared.acquire();
            defer shared.release();
            try shared.buffered.append(self.ctx.arena, .{ .encoded = encoded });
            shared.buffered_bytes += encoded.len;
            shared.emitted += 1;
            full = shared.buffered.items.len >= BATCH_RECORDS or
                shared.buffered_bytes >= BATCH_BYTES;
        }
        if (full) try self.flush();
    }

    /// The registered schema of record_type, if any.
    pub fn findSchema(self: *const Run, record_type: []const u8) ?*const schema.RecordSchema {
        for (self.schemas) |*entry| {
            if (std.mem.eql(u8, entry.record_type, record_type)) return entry;
        }
        return null;
    }

    /// The wire record map: type, values and the optional title, severity and
    /// sources keys, omitted when unset.
    fn encodeRecord(
        self: *const Run,
        record_type: []const u8,
        values: []const wire.Value,
        title: ?[]const u8,
        severity: ?record_mod.Severity,
        sources: []const record_mod.SourceRef,
    ) sdk.Error![]u8 {
        const alloc = self.ctx.arena;
        var entries: std.ArrayList(wire.Entry) = .empty;
        try entries.append(alloc, wire.entry("type", wire.str(record_type)));
        try entries.append(alloc, wire.entry("values", .{ .array = values }));
        if (title) |text_value| try entries.append(alloc, wire.entry("title", wire.str(text_value)));
        if (severity) |level| try entries.append(alloc, wire.entry("severity", wire.str(level.asStr())));
        if (sources.len != 0) {
            const source_values = try alloc.alloc(wire.Value, sources.len);
            for (sources, source_values) |source, *slot| slot.* = try source.toValue(alloc);
            try entries.append(alloc, wire.entry("sources", .{ .array = source_values }));
        }
        const map = wire.mapOf(alloc, entries.items) catch |err| return codecFault(err);
        return wire.encode(alloc, map) catch |err| return codecFault(err);
    }

    /// Sends the buffered records. Runs flush on their own; analyzers only call
    /// this to bound memory between long phases.
    pub fn flush(self: *const Run) sdk.Error!void {
        const alloc = self.ctx.arena;
        const shared = self.shared;

        var batch: std.ArrayList(Buffered) = .empty;
        {
            shared.acquire();
            defer shared.release();
            if (shared.buffered.items.len == 0) return;
            // Take the batch out: a failed send drops it, exactly like a Rust
            // run whose host call failed.
            batch = shared.buffered;
            shared.buffered = .empty;
            shared.buffered_bytes = 0;
        }

        const record_values = try alloc.alloc(wire.Value, batch.items.len);
        for (batch.items, record_values) |buffered, *slot| {
            slot.* = wire.decode(alloc, buffered.encoded) catch
                return sdk.fail("PROTOCOL_ERROR", "a buffered record is not valid MessagePack");
        }

        try self.ctx.checkCancelled();
        const reply = try self.ctx.callHost(protocol.method.run_emit, try value.map(alloc, &.{
            value.entry("run_id", value.str(self.run_id)),
            value.entry("records", .{ .array = record_values }),
        }));
        const ack = try protocol.EmitAck.fromValueWith(alloc, reply);
        if (ack.accepted != record_values.len) {
            return sdk.failf(
                alloc,
                "PROTOCOL_ERROR",
                "host accepted {d} of {d} records",
                .{ ack.accepted, record_values.len },
            );
        }
    }

    /// Flushes and returns what run.start answers with.
    pub fn finish(self: *const Run) sdk.Error!protocol.RunFinish {
        try self.flush();
        const shared = self.shared;
        shared.acquire();
        defer shared.release();
        return .{ .summary = shared.summary };
    }
};

/// The MessagePack codec never fails for a record map (it holds strings,
/// numbers, lists and maps), so a failure here is a protocol fault.
fn codecFault(err: wire.Error) sdk.Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => sdk.fail("PROTOCOL_ERROR", "the record is not encodable as MessagePack"),
    };
}

/// A record being emitted (see Run.record).
///
/// A record is only sent by Emit.emit; the builder methods add sources, a
/// title or a severity.
pub const Emit = struct {
    run: *const Run,
    record_type: []const u8,
    values: []const wire.Value,
    title_text: ?[]const u8 = null,
    severity_level: ?record_mod.Severity = null,
    sources: []const record_mod.SourceRef = &.{},

    /// Adds file as a source.
    pub fn from(self: Emit, file: *const file_mod.FileRef) Emit {
        return self.source(file.source());
    }

    /// Adds a source.
    pub fn source(self: Emit, source_ref: record_mod.SourceRef) Emit {
        const alloc = self.run.ctx.arena;
        const sources = alloc.alloc(record_mod.SourceRef, self.sources.len + 1) catch return self;
        @memcpy(sources[0..self.sources.len], self.sources);
        sources[self.sources.len] = source_ref;
        var next = self;
        next.sources = sources;
        return next;
    }

    /// Narrows the last source to length bytes at offset.
    pub fn at(self: Emit, offset: u64, length: u64) Emit {
        if (self.sources.len == 0) return self;
        const alloc = self.run.ctx.arena;
        const sources = alloc.dupe(record_mod.SourceRef, self.sources) catch return self;
        sources[sources.len - 1] = sources[sources.len - 1].at(offset, length);
        var next = self;
        next.sources = sources;
        return next;
    }

    /// Notes where in the last source the record is (line 12).
    pub fn note(self: Emit, note_text: []const u8) Emit {
        if (self.sources.len == 0) return self;
        const alloc = self.run.ctx.arena;
        const sources = alloc.dupe(record_mod.SourceRef, self.sources) catch return self;
        sources[sources.len - 1] = sources[sources.len - 1].noteText(note_text);
        var next = self;
        next.sources = sources;
        return next;
    }

    pub fn title(self: Emit, text_value: []const u8) Emit {
        var next = self;
        next.title_text = text_value;
        return next;
    }

    pub fn severity(self: Emit, level: record_mod.Severity) Emit {
        var next = self;
        next.severity_level = level;
        return next;
    }

    /// Validates and sends the record (buffered until the batch is full).
    pub fn emit(self: Emit) sdk.Error!void {
        return self.run.push(self.record_type, self.values, self.title_text, self.severity_level, self.sources);
    }
};

const testing = std.testing;
const testing_stub = @import("testing.zig");

/// A handler for the evidence side: every method the run itself does not need.
fn noEvidence(
    _: ?*anyopaque,
    _: std.mem.Allocator,
    method: []const u8,
    _: wire.Value,
) testing_stub.Reply {
    return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
}

/// A context over a stub host, with the run's per-call arena.
fn testContext(
    stub: *testing_stub.Stub,
    alloc: std.mem.Allocator,
    cancelled: *std.atomic.Value(bool),
) host.Context {
    return .{
        .host = host.HostConnection.init(stub.api()),
        .cancelled = cancelled,
        .arena = alloc,
        .alloc = alloc,
    };
}

test "options read flags, text and selections" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const values = try value.map(alloc, &.{
        value.entry("deep", value.boolean(true)),
        value.entry("label", value.str("全部")),
        value.entry("items", try value.array(alloc, &.{ value.str("users"), value.str("groups") })),
        value.entry("single", try value.array(alloc, &.{value.str("only")})),
        value.entry("empty", try value.array(alloc, &.{})),
    });
    const options = Options.init(values);
    try testing.expect(options.flag("deep"));
    try testing.expect(!options.flag("missing"));
    try testing.expect(!options.flag("label"));
    try testing.expectEqualStrings("全部", options.text("label").?);
    try testing.expectEqual(null, options.text("deep"));

    const items = try options.list(alloc, "items");
    try testing.expectEqual(@as(usize, 2), items.len);
    try testing.expectEqualStrings("groups", items[1]);
    try testing.expectEqual(@as(usize, 0), (try options.list(alloc, "missing")).len);

    try testing.expect(options.wants("items", "users"));
    try testing.expect(!options.wants("items", "hosts"));
    try testing.expect(options.wants("empty", "anything"));
    try testing.expect(options.wants("missing", "anything"));
    try testing.expect(options.wants("single", "only"));
    try testing.expect(!options.wants("single", "other"));
}

test "profile facts read the known keys" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const facts = try value.map(alloc, &.{
        value.entry("timezone", value.str("Asia/Shanghai")),
        value.entry("hostname", value.str("kali")),
        value.entry("users", try value.array(alloc, &.{value.str("root")})),
    });
    const profile = Profile.init(facts);
    try testing.expectEqualStrings("Asia/Shanghai", profile.timezone().?);
    try testing.expectEqualStrings("kali", profile.hostname().?);
    try testing.expectEqual(null, profile.text("users"));
    try testing.expectEqual(null, Profile.init(protocol.empty_map).timezone());
}

test "a run validates, batches and answers run.start" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    var stub = testing_stub.Stub.init(testing.allocator, null, noEvidence);
    defer stub.deinit();
    var cancelled = std.atomic.Value(bool).init(false);

    const user_fields = [_]schema.Field{
        schema.Field.new("user", "用户", .text).asKey(),
        schema.Field.new("uid", "UID", .int),
    };
    const schemas = [_]schema.RecordSchema{
        record_mod.profileFactSchema(),
        schema.RecordSchema.new("test.user", "用户", &user_fields),
    };

    const start = protocol.RunStart{
        .run_id = "run-1",
        .analyzer = "base",
        .target = .{ .system = .{
            .view_id = "view-1",
            .label = "Kali",
            .system = .{
                .id = "linux@part:0",
                .family = "linux",
                .product = "Kali GNU/Linux",
                .root = "part:0",
            },
        } },
        .locale = "zh-CN",
    };
    const run = try Run.init(testContext(&stub, alloc, &cancelled), start, &schemas);
    try testing.expectEqualStrings("run-1", run.id());
    try testing.expectEqualStrings("base", run.analyzerId());
    try testing.expectEqualStrings("zh-CN", run.uiLocale());
    try testing.expectEqualStrings("linux@part:0", run.system().?.id);
    try testing.expectEqual(@as(usize, 0), run.inputsOf().len);
    const view = try run.requireView();
    try testing.expectEqualStrings("view-1", view.id());

    // The 1000th record fills the batch and sends it.
    var index: u64 = 0;
    while (index < BATCH_RECORDS) : (index += 1) {
        try run.emit("test.user", &.{ wire.str("root"), .{ .uint = index } });
    }
    try testing.expectEqual(@as(u64, BATCH_RECORDS), run.emitted());
    try testing.expectEqual(@as(usize, 1), stub.emits.items.len);
    try testing.expectEqual(@as(usize, BATCH_RECORDS), stub.emits.items[0].records.len);
    try testing.expectEqualStrings("run-1", stub.emits.items[0].run_id);
    const first = stub.emits.items[0].records[0];
    try testing.expectEqualStrings("test.user", first.getString("type").?);
    try testing.expectEqual(@as(usize, 2), first.get("values").?.array.len);
    try testing.expectEqualStrings("root", first.get("values").?.array[0].string);
    try testing.expectEqual(@as(u64, 0), first.get("values").?.array[1].uint);
    // Optional keys stay out of the record when they are not set.
    try testing.expectEqual(null, first.get("title"));
    try testing.expectEqual(null, first.get("severity"));
    try testing.expectEqual(null, first.get("sources"));

    // A profile fact names the system it belongs to.
    try run.provide("hostname", wire.str("kali"));
    try testing.expectEqual(@as(u64, BATCH_RECORDS + 1), run.emitted());
    run.setSummary("1 条记录");
    const finish = try run.finish();
    try testing.expectEqualStrings("1 条记录", finish.summary.?);
    try testing.expectEqual(@as(usize, 2), stub.emits.items.len);
    const fact = stub.emits.items[1].records[0];
    try testing.expectEqualStrings(record_mod.PROFILE_FACT, fact.getString("type").?);
    try testing.expectEqualStrings("hostname", fact.get("values").?.array[0].string);
    try testing.expectEqualStrings("kali", fact.get("values").?.array[1].string);
    try testing.expectEqualStrings("linux@part:0", fact.get("values").?.array[2].string);
}

test "sources, titles and severities reach the wire record" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    var stub = testing_stub.Stub.init(testing.allocator, null, noEvidence);
    defer stub.deinit();
    var cancelled = std.atomic.Value(bool).init(false);

    const fields = [_]schema.Field{schema.Field.new("user", "用户", .text)};
    const schemas = [_]schema.RecordSchema{schema.RecordSchema.new("test.user", "用户", &fields)};
    const start = protocol.RunStart{
        .run_id = "run-2",
        .analyzer = "base",
        .target = .files,
    };
    const run = try Run.init(testContext(&stub, alloc, &cancelled), start, &schemas);
    try testing.expectEqual(null, run.viewOrNull());
    try testing.expectError(error.Fault, run.requireView());
    try testing.expectEqualStrings("INVALID_TARGET", sdk.codeOf(error.Fault));
    _ = sdk.take();

    const source = (record_mod.SourceRef{
        .root = "part:1",
        .path = "etc/passwd",
    }).at(10, 20).noteText("line 3");
    try run.record("test.user", &.{wire.str("root")})
        .source(source)
        .title("root")
        .severity(.high)
        .emit();
    _ = try run.finish();

    const record_value = stub.emits.items[0].records[0];
    try testing.expectEqualStrings("root", record_value.getString("title").?);
    try testing.expectEqualStrings("high", record_value.getString("severity").?);
    const sources = record_value.get("sources").?.array;
    try testing.expectEqual(@as(usize, 1), sources.len);
    try testing.expectEqualStrings("part:1", sources[0].getString("root").?);
    try testing.expectEqualStrings("etc/passwd", sources[0].getString("path").?);
    try testing.expectEqual(@as(u64, 10), sources[0].getUint("offset").?);
    try testing.expectEqual(@as(u64, 20), sources[0].getUint("length").?);
    try testing.expectEqualStrings("line 3", sources[0].getString("note").?);
}

test "unknown record types and invalid values are refused before buffering" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    var stub = testing_stub.Stub.init(testing.allocator, null, noEvidence);
    defer stub.deinit();
    var cancelled = std.atomic.Value(bool).init(false);

    const fields = [_]schema.Field{schema.Field.new("uid", "UID", .int)};
    const schemas = [_]schema.RecordSchema{schema.RecordSchema.new("test.user", "用户", &fields)};
    const start = protocol.RunStart{
        .run_id = "run-3",
        .analyzer = "base",
        .target = .files,
    };
    const run = try Run.init(testContext(&stub, alloc, &cancelled), start, &schemas);

    try testing.expectError(error.Fault, run.emit("test.missing", &.{.nil}));
    try testing.expectEqualStrings("UNKNOWN_RECORD_TYPE", sdk.codeOf(error.Fault));
    _ = sdk.take();

    try testing.expectError(error.Fault, run.emit("test.user", &.{wire.str("not an int")}));
    try testing.expectEqualStrings("INVALID_RECORD", sdk.codeOf(error.Fault));
    _ = sdk.take();

    // A wrong number of values is an invalid record too.
    try testing.expectError(error.Fault, run.emit("test.user", &.{}));
    try testing.expectEqualStrings("INVALID_RECORD", sdk.codeOf(error.Fault));
    _ = sdk.take();

    try testing.expectEqual(@as(u64, 0), run.emitted());
    try testing.expectEqual(@as(usize, 0), stub.emits.items.len);
    try testing.expectEqual(@as(usize, 0), run.shared.buffered.items.len);
}

test "warnings, progress and cancellation reach the host" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    var stub = testing_stub.Stub.init(testing.allocator, null, noEvidence);
    defer stub.deinit();
    var cancelled = std.atomic.Value(bool).init(false);

    const start = protocol.RunStart{
        .run_id = "run-4",
        .analyzer = "base",
        .target = .files,
    };
    const run = try Run.init(testContext(&stub, alloc, &cancelled), start, &.{});

    try run.warn("MALFORMED_LINE", "line 3 has too few fields");
    try run.progress(3, 10, "reading");
    run.log(.info, "started");
    try testing.expect(stub.saw(protocol.method.run_warn));
    try testing.expect(stub.saw(protocol.method.run_progress));
    try testing.expectEqual(@as(usize, 1), stub.warnings.items.len);
    try testing.expectEqualStrings("MALFORMED_LINE", stub.warnings.items[0].code);
    try testing.expectEqual(@as(u64, 3), stub.progress.items[0].current);
    try testing.expectEqual(@as(?u64, 10), stub.progress.items[0].total);
    try testing.expectEqualStrings("reading", stub.progress.items[0].message.?);
    try testing.expectEqual(@as(usize, 1), stub.logs.items.len);

    // A cancelled run refuses further host calls.
    cancelled.store(true, .release);
    try testing.expect(run.isCancelled());
    try testing.expectError(error.Fault, run.progress(4, 10, null));
    try testing.expectEqualStrings("CANCELLED", sdk.codeOf(error.Fault));
    _ = sdk.take();
}
