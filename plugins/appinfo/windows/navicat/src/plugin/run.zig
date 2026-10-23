//! The two analyzer entry points: an evidence-scope run over every NTUSER.DAT
//! of the evidence item, and a files-scope run over the hives the user
//! selected. Both walk the same analysis.

const std = @import("std");

const lc = @import("lovelycarve");
const analyze = @import("analyze.zig");

/// Evidence scope: run over every NTUSER.DAT of the evidence item.
pub fn evidence(run: *const lc.Run) lc.Error!void {
    return analyze.analyzeRun(run, run.inputsOf());
}

/// Files scope: run over the selected hives.
pub fn files(run: *const lc.Run) lc.Error!void {
    return analyze.analyzeRun(run, run.inputsOf());
}
