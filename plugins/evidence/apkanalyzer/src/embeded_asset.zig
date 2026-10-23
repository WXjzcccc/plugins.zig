//! Embedded detection catalogs of the analyzer.
//!
//! The APK analyzer ships the permission, packer/framework and build catalogs
//! it needs as JSON; embedding them keeps the plugin a single library with no
//! data files to install.

pub const apkpackdata = @embedFile("assets/data/apkpackdata.json");
pub const permission_descriptions = @embedFile("assets/data/permission_descriptions.json");
pub const sensitive_permissions = @embedFile("assets/data/sensitive_permissions.json");
pub const built_info = @embedFile("assets/data/built_info.json");
