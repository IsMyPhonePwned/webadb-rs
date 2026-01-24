// Tests for parsers::extract_kernel_version and extract_manufacturer_model.
// Run with: cargo test --target <host> --no-default-features --features bugreport-analysis
// (e.g. ./test-host.sh --features bugreport-analysis)

#[cfg(feature = "bugreport-analysis")]
mod tests {
    use webadb_rs::parsers::{extract_kernel_version, extract_manufacturer_model};

    #[test]
    fn test_extract_kernel_version() {
        let kernel_str = "Linux version 6.6.50-android15-8-abA346BXXSBDYI1-4k (kleaf@build-host) (Android (11368308, +pgo, +bolt, +lto, +mlgo, based on r510928) clang version 18.0.0 (https://android.googlesource.com/toolchain/llvm-project 477610d4d0d988e69dbc3fae4fe86bff3f07f2b5), LLD 18.0.0) #1 SMP PREEMPT Tue Sep  9 02:53:03 UTC 2025";
        let result = extract_kernel_version(kernel_str);
        assert_eq!(result, "6.6.50-android15-8-abA346BXXSBDYI1-4k");
    }

    #[test]
    fn test_extract_kernel_version_with_whitespace() {
        let kernel_str = "Linux version 5.10.100 (build@host) #1";
        let result = extract_kernel_version(kernel_str);
        assert_eq!(result, "5.10.100");
    }

    #[test]
    fn test_extract_kernel_version_with_parenthesis() {
        let kernel_str = "Linux version 4.19.200-android12(abc123)";
        let result = extract_kernel_version(kernel_str);
        assert_eq!(result, "4.19.200-android12");
    }

    #[test]
    fn test_extract_kernel_version_no_prefix() {
        let kernel_str = "Some other kernel string";
        let result = extract_kernel_version(kernel_str);
        assert_eq!(result, "Some other kernel string");
    }

    #[test]
    fn test_extract_kernel_version_long_string() {
        let kernel_str = "This is a very long kernel string that doesn't start with Linux version and is longer than 100 characters so it should be truncated with ellipsis at the end";
        let result = extract_kernel_version(kernel_str);
        assert!(result.len() <= 103); // 100 + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_extract_manufacturer_model() {
        let fingerprint = "'samsung/a34xeea/a34x:15/AP3A.240905.015.A2/A346BXXSBDYI1:user/release-keys'";
        let (manufacturer, model) = extract_manufacturer_model(fingerprint);
        assert_eq!(manufacturer, "samsung");
        assert_eq!(model, "a34x");
    }

    #[test]
    fn test_extract_manufacturer_model_with_quotes() {
        let fingerprint = "\"google/pixel/pixel:14/UP1A.231005.007/11010380:user/release-keys\"";
        let (manufacturer, model) = extract_manufacturer_model(fingerprint);
        assert_eq!(manufacturer, "google");
        assert_eq!(model, "pixel");
    }

    #[test]
    fn test_extract_manufacturer_model_no_colon() {
        let fingerprint = "oneplus/OnePlus8/OnePlus8:11/RKQ1.201112.002/2105050000:user/release-keys";
        let (manufacturer, model) = extract_manufacturer_model(fingerprint);
        assert_eq!(manufacturer, "oneplus");
        assert_eq!(model, "OnePlus8");
    }

    #[test]
    fn test_extract_manufacturer_model_invalid_format() {
        let fingerprint = "invalid";
        let (manufacturer, model) = extract_manufacturer_model(fingerprint);
        assert_eq!(manufacturer, "Unknown");
        assert_eq!(model, "Unknown");
    }

    #[test]
    fn test_extract_manufacturer_model_short_format() {
        let fingerprint = "manufacturer/model";
        let (manufacturer, model) = extract_manufacturer_model(fingerprint);
        assert_eq!(manufacturer, "Unknown");
        assert_eq!(model, "Unknown");
    }
}
