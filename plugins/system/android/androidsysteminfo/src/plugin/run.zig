//! The analyzer entry points: one per plugin.toml analyzer, all evidence
//! scope over the inputs the host resolved from the manifest patterns.

const std = @import("std");

const lc = @import("lovelycarve");
const analyze = @import("analyze.zig");

/// 系统信息：开机信息、框架版本属性与设备用户。
pub fn baseinfo(run: *const lc.Run) lc.Error!void {
    const items = analyze.BaseinfoItems.fromOptions(run.optionValues());
    return analyze.analyzeBaseinfo(run, run.inputsOf(), items);
}

/// 系统日志：bootlog.txt 全量 logcat、dropbox 条目与 ANR 记录。
pub fn syslog(run: *const lc.Run) lc.Error!void {
    const settings = try analyze.SyslogSettings.fromOptions(run.context().arena, run.optionValues());
    return analyze.analyzeSyslog(run, run.inputsOf(), settings);
}

/// 应用列表：packages.xml（ABX）+ packages.list 兜底。
pub fn applist(run: *const lc.Run) lc.Error!void {
    const items = analyze.ApplistItems.fromOptions(run.optionValues());
    return analyze.analyzeApplist(run, run.inputsOf(), items);
}

/// 网络与其他记录：Wi-Fi、蓝牙、ADB 授权、系统账号与 GNSS。
pub fn netrecords(run: *const lc.Run) lc.Error!void {
    const items = analyze.NetItems.fromOptions(run.optionValues());
    return analyze.analyzeNetrecords(run, run.inputsOf(), items);
}
