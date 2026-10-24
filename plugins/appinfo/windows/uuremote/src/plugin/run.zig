//! The two analyzer entry points: an evidence-scope run over every
//! GameViewer file of the evidence item (plus NTUSER.DAT), and a files-scope
//! run over the files the user selected. Both walk the same analysis.

const std = @import("std");

const lc = @import("lovelycarve");
const analyze = @import("analyze.zig");

/// Evidence scope: run over every GameViewer file of the evidence item.
pub fn evidence(run: *const lc.Run) lc.Error!void {
    return analyze.analyzeRun(run);
}

/// Files scope: run over the selected files.
pub fn files(run: *const lc.Run) lc.Error!void {
    return analyze.analyzeRun(run);
}
