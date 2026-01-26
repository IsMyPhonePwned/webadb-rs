//! Pure Rust parsers for bugreport data (no WASM deps).
//! Used by wasm when bugreport-analysis is enabled, and by tests on host.

/// Extract kernel version from kernel string
/// Format: "Linux version 6.6.50-android15-8-abA346BXXSBDYI1-4k (kleaf@build-host) ..."
/// Returns: "6.6.50-android15-8-abA346BXXSBDYI1-4k"
pub fn extract_kernel_version(kernel_str: &str) -> String {
    if kernel_str.starts_with("Linux version ") {
        let version_part = kernel_str[13..].trim_start();
        let version_end = version_part
            .find(char::is_whitespace)
            .or_else(|| version_part.find('('))
            .unwrap_or(version_part.len());
        version_part[..version_end].to_string()
    } else {
        if kernel_str.len() > 100 {
            format!("{}...", &kernel_str[..100])
        } else {
            kernel_str.to_string()
        }
    }
}

/// Parse ANR/crash JSON (anr_files, anr_trace).
/// Returns `Some(Value)` if input is valid JSON with `anr_files` or `anr_trace`, else `None`.
pub fn parse_anr_crash_json(data: &[u8]) -> Option<serde_json::Value> {
    use serde_json::Value;
    let v: Value = serde_json::from_slice(data).ok()?;
    let obj = v.as_object()?;
    if !obj.contains_key("anr_files") && !obj.contains_key("anr_trace") {
        return None;
    }
    let mut out = serde_json::Map::new();
    if obj.contains_key("anr_files") {
        out.insert("anr_files".to_string(), obj.get("anr_files")?.clone());
    }
    if obj.contains_key("anr_trace") {
        out.insert("anr_trace".to_string(), obj.get("anr_trace")?.clone());
    }
    Some(Value::Object(out))
}

/// Extract manufacturer and model from build fingerprint
/// Format: 'samsung/a34xeea/a34x:15/AP3A.240905.015.A2/A346BXXSBDYI1:user/release-keys'
/// Returns: (manufacturer, model)
pub fn extract_manufacturer_model(fingerprint: &str) -> (String, String) {
    let fp_clean = fingerprint.trim_matches('\'').trim_matches('"');
    let parts: Vec<&str> = fp_clean.split('/').collect();
    if parts.len() >= 3 {
        let mfr = parts[0].to_string();
        let device_part = parts[2];
        let model_name = if let Some(colon_pos) = device_part.find(':') {
            &device_part[..colon_pos]
        } else {
            device_part
        };
        (mfr, model_name.to_string())
    } else {
        ("Unknown".to_string(), "Unknown".to_string())
    }
}
