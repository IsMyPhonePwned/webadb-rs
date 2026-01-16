use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

use super::auth::{AdbKeyPair, storage};
use super::client::AdbClient;
use super::transport::WebUsbTransport;

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Debug).ok();
}

/// Device information for JavaScript
#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct JsDeviceInfo {
    vendor_id: u16,
    product_id: u16,
    manufacturer: Option<String>,
    product: Option<String>,
    serial: Option<String>,
}

#[wasm_bindgen]
impl JsDeviceInfo {
    #[wasm_bindgen(getter)]
    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    #[wasm_bindgen(getter)]
    pub fn product_id(&self) -> u16 {
        self.product_id
    }

    #[wasm_bindgen(getter)]
    pub fn manufacturer(&self) -> Option<String> {
        self.manufacturer.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn product(&self) -> Option<String> {
        self.product.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn serial(&self) -> Option<String> {
        self.serial.clone()
    }
}

/// Main ADB interface for JavaScript
#[wasm_bindgen]
pub struct Adb {
    client: Option<AdbClient>,
}

#[wasm_bindgen]
impl Adb {
    /// Create a new ADB instance
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { client: None }
    }

    /// Request device and connect
    /// Returns device information as JSON
    #[wasm_bindgen]
    pub async fn connect(&mut self) -> Result<JsValue, JsValue> {
        // Get or create keypair
        let keypair = match storage::load_key() {
            Ok(Some(keypair)) => {
                log::info!("Loaded existing keypair from storage");
                keypair
            }
            _ => {
                log::info!("Generating new keypair");
                let keypair = AdbKeyPair::generate()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                
                storage::save_key(&keypair)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                
                keypair
            }
        };

        // Request device from user
        let transport = WebUsbTransport::request_device()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let device_info = transport.device_info();

        // Create and connect client
        let mut client = AdbClient::new(transport, keypair)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        client
            .connect()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        self.client = Some(client);

        // Return device info
        let info = JsDeviceInfo {
            vendor_id: device_info.vendor_id,
            product_id: device_info.product_id,
            manufacturer: device_info.manufacturer_name,
            product: device_info.product_name,
            serial: device_info.serial_number,
        };

        Ok(serde_wasm_bindgen::to_value(&info)?)
    }

    /// Execute a shell command
    #[wasm_bindgen]
    pub async fn shell(&mut self, command: String) -> Result<String, JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        client
            .shell(&command)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Get device properties
    #[wasm_bindgen]
    pub async fn get_properties(&mut self) -> Result<JsValue, JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        let props = client
            .get_properties()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(serde_wasm_bindgen::to_value(&props)?)
    }

    /// Reboot the device
    /// target can be "bootloader", "recovery", or null for normal reboot
    #[wasm_bindgen]
    pub async fn reboot(&mut self, target: Option<String>) -> Result<(), JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        client
            .reboot(target.as_deref())
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Disconnect from device
    #[wasm_bindgen]
    pub async fn disconnect(&mut self) -> Result<(), JsValue> {
        if let Some(client) = self.client.as_mut() {
            client
                .disconnect()
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }
        self.client = None;
        Ok(())
    }

    /// Check if connected
    #[wasm_bindgen]
    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    /// Generate a full bugreport (can take several minutes)
    /// Returns the bugreport as a Uint8Array
    #[wasm_bindgen]
    pub async fn bugreport(&mut self) -> Result<js_sys::Uint8Array, JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        let data = client
            .bugreport()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(js_sys::Uint8Array::from(&data[..]))
    }

    /// Generate a lightweight bugreport (much faster)
    /// Returns a text summary
    #[wasm_bindgen]
    pub async fn bugreport_lite(&mut self) -> Result<String, JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        client
            .bugreport_lite()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// List available bugreports on device
    /// Returns array of file paths
    #[wasm_bindgen]
    pub async fn list_bugreports(&mut self) -> Result<JsValue, JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        let paths = client
            .list_bugreports()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(serde_wasm_bindgen::to_value(&paths)?)
    }

    /// Download a specific bugreport by path
    /// Returns the file data as a Uint8Array
    #[wasm_bindgen]
    pub async fn download_bugreport(&mut self, path: String) -> Result<js_sys::Uint8Array, JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        let data = client
            .download_bugreport(&path)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(js_sys::Uint8Array::from(&data[..]))
    }

    /// Get logcat output (last n lines)
    #[wasm_bindgen]
    pub async fn logcat(&mut self, lines: u32) -> Result<String, JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        client
            .logcat(lines)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Clear logcat buffer
    #[wasm_bindgen]
    pub async fn logcat_clear(&mut self) -> Result<(), JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        client
            .logcat_clear()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Pull a file from the device
    /// Returns the file data as a Uint8Array
    #[wasm_bindgen]
    pub async fn pull_file(&mut self, path: String) -> Result<js_sys::Uint8Array, JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        let data = client
            .pull_file(&path)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(js_sys::Uint8Array::from(&data[..]))
    }

    /// Get file statistics
    #[wasm_bindgen]
    pub async fn stat_file(&mut self, path: String) -> Result<JsValue, JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        let stat = client
            .stat_file(&path)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        #[derive(Serialize)]
        struct FileStatJs {
            mode: u32,
            size: u32,
            mtime: u32,
            is_directory: bool,
            is_file: bool,
        }

        let stat_js = FileStatJs {
            mode: stat.mode,
            size: stat.size,
            mtime: stat.mtime,
            is_directory: stat.is_directory(),
            is_file: stat.is_file(),
        };

        Ok(serde_wasm_bindgen::to_value(&stat_js)?)
    }

    /// List directory contents
    #[wasm_bindgen]
    pub async fn list_directory(&mut self, path: String) -> Result<JsValue, JsValue> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;

        let entries = client
            .list_directory(&path)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        #[derive(Serialize)]
        struct DirEntryJs {
            name: String,
            mode: u32,
            size: u32,
            mtime: u32,
            is_directory: bool,
            is_file: bool,
        }

        let entries_js: Vec<DirEntryJs> = entries
            .into_iter()
            .map(|e| {
                let is_dir = e.is_directory();
                let is_file = e.is_file();
                DirEntryJs {
                    name: e.name,
                    mode: e.mode,
                    size: e.size,
                    mtime: e.mtime,
                    is_directory: is_dir,
                    is_file: is_file,
                }
            })
            .collect();

        Ok(serde_wasm_bindgen::to_value(&entries_js)?)
    }
    
    /// Get active stream count
    #[wasm_bindgen]
    pub fn active_stream_count(&self) -> usize {
        self.client
            .as_ref()
            .map(|c| c.active_stream_count())
            .unwrap_or(0)
    }
    
    /// Cleanup stale streams (>30 seconds old)
    #[wasm_bindgen]
    pub async fn cleanup_stale_streams(&mut self) -> Result<usize, JsValue> {
        let client = self.client.as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;
        
        Ok(client.cleanup_stale_streams().await)
    }
    
    /// Check device health
    #[wasm_bindgen]
    pub async fn health_check(&mut self) -> Result<bool, JsValue> {
        let client = self.client.as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;
        
        client.health_check()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
    
    /// Execute shell command with timeout
    #[wasm_bindgen]
    pub async fn shell_with_timeout(&mut self, command: String, timeout_ms: u32) -> Result<String, JsValue> {
        let client = self.client.as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;
        
        client.shell_with_timeout(&command, timeout_ms)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
    
    /// Push (upload) a file to device
    #[wasm_bindgen]
    pub async fn push_file(&mut self, data: Vec<u8>, remote_path: String) -> Result<(), JsValue> {
        let client = self.client.as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;
        
        client.push_file(&data, &remote_path)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
    
    /// Delete a file or directory
    #[wasm_bindgen]
    pub async fn delete_path(&mut self, remote_path: String) -> Result<(), JsValue> {
        let client = self.client.as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;
        
        client.delete_path(&remote_path)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
    
    /// Rename or move a file/directory
    #[wasm_bindgen]
    pub async fn rename_file(&mut self, old_path: String, new_path: String) -> Result<(), JsValue> {
        let client = self.client.as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;
        
        client.rename_file(&old_path, &new_path)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
    
    /// Create a directory (with parent directories)
    #[wasm_bindgen]
    pub async fn create_directory(&mut self, remote_path: String) -> Result<(), JsValue> {
        let client = self.client.as_mut()
            .ok_or_else(|| JsValue::from_str("Not connected"))?;
        
        client.create_directory(&remote_path)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }


    #[wasm_bindgen]
    #[cfg(feature = "bugreport-analysis")]
    pub async fn analyze_bugreport(&self, data: Vec<u8>) -> Result<JsValue, JsValue> {
        use bugreport_extractor_library::run_parsers_concurrently;
        use bugreport_extractor_library::parsers::{
            Parser as DataParser, ParserType, HeaderParser, BatteryParser, 
            PackageParser, ProcessParser, PowerParser
        };
        use bugreport_extractor_library::zip_utils;
        use std::sync::Arc;
        
        log::info!("🔍 [ANALYZE] Starting bugreport analysis");
        log::info!("📊 [ANALYZE] Data size: {} bytes ({:.2} MB)", data.len(), data.len() as f64 / 1_048_576.0);

        log::info!("🔄 [ANALYZE] Converting data to Arc<[u8]>...");

        let data_u8 = data.as_slice();
        let file_content: Arc<[u8]> = if zip_utils::is_zip_file(data_u8) {
            web_sys::console::log_1(&"Detected ZIP file, extracting dumpstate.txt...".into());
            
            let extracted = zip_utils::extract_dumpstate_from_zip_bytes(data_u8)
                .map_err(|e| JsValue::from_str(&format!("ZIP extraction failed: {}", e)))?;
            
            web_sys::console::log_1(&format!(
                "Extracted dumpstate.txt: {:.2} MB",
                extracted.len() as f64 / 1_048_576.0
            ).into());
            
            Arc::from(extracted)
        } else {
            log::info!(
                "Loading plain text file: {:.2} MB",
                data.len() as f64 / 1_048_576.0);
            
            Arc::from(data)
        };
        log::info!("✅ [ANALYZE] Data conversion complete");
        
        // Create parsers for the analysis we need
        log::info!("🔧 [ANALYZE] Creating parsers...");
        let mut parsers_to_run: Vec<(ParserType, Box<dyn DataParser + Send + Sync>)> = Vec::new();
        
        // Add Header parser for device info
        log::info!("  📝 [ANALYZE] Creating HeaderParser...");
        if let Ok(header_parser) = HeaderParser::new() {
            parsers_to_run.push((ParserType::Header, Box::new(header_parser)));
            log::info!("  ✅ [ANALYZE] HeaderParser created");
        } else {
            log::warn!("  ⚠️ [ANALYZE] Failed to create HeaderParser");
        }
        
        // Add Battery parser
        log::info!("  🔋 [ANALYZE] Creating BatteryParser...");
        if let Ok(battery_parser) = BatteryParser::new() {
            parsers_to_run.push((ParserType::Battery, Box::new(battery_parser)));
            log::info!("  ✅ [ANALYZE] BatteryParser created");
        } else {
            log::warn!("  ⚠️ [ANALYZE] Failed to create BatteryParser");
        }
        
        // Add Package parser
        log::info!("  📦 [ANALYZE] Creating PackageParser...");
        if let Ok(package_parser) = PackageParser::new() {
            parsers_to_run.push((ParserType::Package, Box::new(package_parser)));
            log::info!("  ✅ [ANALYZE] PackageParser created");
        } else {
            log::warn!("  ⚠️ [ANALYZE] Failed to create PackageParser");
        }
        
        // Add Process parser
        log::info!("  ⚙️ [ANALYZE] Creating ProcessParser...");
        if let Ok(process_parser) = ProcessParser::new() {
            parsers_to_run.push((ParserType::Process, Box::new(process_parser)));
            log::info!("  ✅ [ANALYZE] ProcessParser created");
        } else {
            log::warn!("  ⚠️ [ANALYZE] Failed to create ProcessParser");
        }
        
        // Add Power parser
        log::info!("  ⚡ [ANALYZE] Creating PowerParser...");
        if let Ok(power_parser) = PowerParser::new() {
            parsers_to_run.push((ParserType::Power, Box::new(power_parser)));
            log::info!("  ✅ [ANALYZE] PowerParser created");
        } else {
            log::warn!("  ⚠️ [ANALYZE] Failed to create PowerParser");
        }
        
        log::info!("✅ [ANALYZE] Created {} parsers", parsers_to_run.len());
        
        // Run parsers concurrently
        log::info!("🚀 [ANALYZE] Running {} parsers concurrently...", parsers_to_run.len());           
        let results = run_parsers_concurrently(file_content, parsers_to_run);

        log::info!("⏱️ [ANALYZE] Parsers completed");
        
        // Define summary structures
        #[derive(Serialize)]
        struct BugreportSummary {
            device_info: Option<DeviceInfoSummary>,
            battery_info: Option<BatteryInfoSummary>,
            process_count: usize,
            package_count: usize,
            has_security_analysis: bool,
            analysis_complete: bool,
            packages: Vec<PackageInstallationInfo>,
            processes: Vec<ProcessInfo>,
            battery_apps: Vec<BatteryAppInfo>,
            package_details: Vec<PackageDetails>,
            power_history: Vec<PowerHistory>,
        }
        
        #[derive(Serialize, Clone)]
        struct DeviceInfoSummary {
            manufacturer: String,
            model: String,
            android_version: String,
            build_id: String,
            kernel_version: String,
        }
        
        #[derive(Serialize, Clone)]
        struct BatteryInfoSummary {
            level: f32,
            health: String,
            temperature: f32,
            voltage: f32,
        }
        
        #[derive(Serialize, Clone)]
        struct PackageInstallationInfo {
            package_name: String,
            installer: String,
            timestamp: String,
            version_code: Option<u64>,
            success: bool,
            duration_seconds: Option<f64>,
            staged_dir: Option<String>,
        }
        
        #[derive(Serialize, Clone)]
        struct ProcessInfo {
            pid: u32,
            name: String,
            user: String,
            cpu_percent: f64,
            memory: String,
            virtual_memory: String,
            policy: String,
        }
        
        #[derive(Serialize, Clone)]
        struct BatteryAppInfo {
            package_name: String,
            uid: u32,
            cpu_system_time_ms: u64,
            cpu_user_time_ms: u64,
            total_cpu_time_ms: u64,
            network_rx_mobile: u64,
            network_rx_wifi: u64,
            network_tx_mobile: u64,
            network_tx_wifi: u64,
            total_network_bytes: u64,
            total_wakelock_time_ms: u64,
            total_job_time_ms: u64,
            foreground_service_time_ms: u64,
            total_job_count: u32,
        }
        
        #[derive(Serialize, Clone)]
        struct PackageUserInfo {
            user_id: Option<u32>,
            first_install_time: Option<String>,
            last_disabled_caller: Option<String>,
            data_dir: Option<String>,
            enabled: Option<u32>,
            installed: Option<bool>,
        }
        
        #[derive(Serialize, Clone)]
        struct PackageDetails {
            package_name: String,
            version_code: Option<u64>,
            version_name: Option<String>,
            app_id: Option<u32>,
            target_sdk: Option<u32>,
            min_sdk: Option<u32>,
            code_path: Option<String>,
            resource_path: Option<String>,
            flags: Option<String>,
            pkg_flags: Option<String>,
            primary_cpu_abi: Option<String>,
            installer_package_name: Option<String>,
            last_update_time: Option<String>,
            time_stamp: Option<String>,
            category: Option<String>,
            install_logs: Vec<serde_json::Value>,
            user_count: usize,
            users: Vec<PackageUserInfo>,
        }
        
        #[derive(Serialize, Clone)]
        struct PowerEvent {
            event_type: String,
            timestamp: Option<String>,
            details: Option<String>,
            flags: Option<String>,
        }
        
        #[derive(Serialize, Clone)]
        struct PowerHistory {
            timestamp: String,
            reason: Option<String>,
            history_events: Vec<PowerEvent>,
            stack_trace: Vec<String>,
        }
        
        // Extract data from results
        log::info!("📤 [ANALYZE] Extracting data from parser results...");
        let mut device_info = None;
        let mut battery_info = None;
        let mut process_count = 0;
        let mut package_count = 0;
        let mut packages = Vec::new();
        let mut processes: Vec<ProcessInfo> = Vec::new();
        let mut battery_apps: Vec<BatteryAppInfo> = Vec::new();
        let mut package_details: Vec<PackageDetails> = Vec::new();
        let mut power_history: Vec<PowerHistory> = Vec::new();
        
        for (parser_type, result, duration) in results {
            log::info!("  🔍 [ANALYZE] Processing {:?} result (took {:?})", parser_type, duration);
            
            match result {
                Ok(json_output) => {
                    log::info!("  ✅ [ANALYZE] {:?} parser succeeded", parser_type);
                    
                    
                    match parser_type {
                        ParserType::Header => {
                            log::info!("    📝 [ANALYZE] Extracting device info from Header...");
                            // Extract device info from header
                            if let Some(obj) = json_output.as_object() {
                                // Extract Android SDK version
                                let android_version = obj.get("Android SDK version")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown")
                                    .to_string();

                                // Extract Build ID
                                let build_id = obj.get("Build")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown")
                                    .to_string();
                                
                                // Extract Kernel version (extract version from full kernel string)
                                // Format: "Linux version 6.6.50-android15-8-abA346BXXSBDYI1-4k (kleaf@build-host) ..."
                                let kernel_version = extract_kernel_version(
                                    obj.get("Kernel")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Unknown")
                                );
                                
                                // Extract manufacturer and model from Build fingerprint
                                // Format: 'samsung/a34xeea/a34x:15/AP3A.240905.015.A2/A346BXXSBDYI1:user/release-keys'
                                let (manufacturer, model) = obj.get("Build fingerprint")
                                    .and_then(|v| v.as_str())
                                    .map(|fp| extract_manufacturer_model(fp))
                                    .unwrap_or_else(|| {
                                        // Fallback: try to extract from other fields
                                        let mfr = obj.get("manufacturer")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unknown")
                                            .to_string();
                                        let mdl = obj.get("model")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unknown")
                                            .to_string();
                                        (mfr, mdl)
                                    });
                                
                                log::info!("    📱 [ANALYZE] Device: {} {} (Android SDK {})", manufacturer, model, android_version);
                                
                                device_info = Some(DeviceInfoSummary {
                                    manufacturer,
                                    model,
                                    android_version,
                                    build_id,
                                    kernel_version,
                                });
                                log::info!("    ✅ [ANALYZE] Device info extracted successfully");
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Header result is not a JSON object");
                            }
                        },
                        ParserType::Battery => {
                            log::info!("    🔋 [ANALYZE] Extracting battery info...");
                            // Extract battery info - this parser returns app battery stats
                            if let Some(arr) = json_output.as_array() {
                                log::info!("    📊 [ANALYZE] Battery array has {} entries", arr.len());
                                
                                // Transform battery app data into BatteryAppInfo structs
                                for app_json in arr {
                                    if let Some(app_obj) = app_json.as_object() {
                                        let package_name = app_obj.get("package_name")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .trim_matches('"')
                                            .trim()
                                            .to_string();
                                        
                                        // Skip entries with empty package names (system-level entries)
                                        if package_name.is_empty() {
                                            continue;
                                        }
                                        
                                        let uid = app_obj.get("uid")
                                            .and_then(|v| v.as_u64())
                                            .map(|v| v as u32)
                                            .unwrap_or(0);
                                        
                                        let cpu_system_time_ms = app_obj.get("cpu_system_time_ms")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        
                                        let cpu_user_time_ms = app_obj.get("cpu_user_time_ms")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        
                                        let total_cpu_time_ms = cpu_system_time_ms + cpu_user_time_ms;
                                        
                                        let network_rx_mobile = app_obj.get("network_rx_mobile")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        
                                        let network_rx_wifi = app_obj.get("network_rx_wifi")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        
                                        let network_tx_mobile = app_obj.get("network_tx_mobile")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        
                                        let network_tx_wifi = app_obj.get("network_tx_wifi")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        
                                        let total_network_bytes = app_obj.get("total_network_bytes")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        
                                        let total_wakelock_time_ms = app_obj.get("total_wakelock_time_ms")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        
                                        let total_job_time_ms = app_obj.get("total_job_time_ms")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        
                                        let foreground_service_time_ms = app_obj.get("foreground_service_time_ms")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        
                                        let total_job_count = app_obj.get("total_job_count")
                                            .and_then(|v| v.as_u64())
                                            .map(|v| v as u32)
                                            .unwrap_or(0);
                                        
                                        battery_apps.push(BatteryAppInfo {
                                            package_name,
                                            uid,
                                            cpu_system_time_ms,
                                            cpu_user_time_ms,
                                            total_cpu_time_ms,
                                            network_rx_mobile,
                                            network_rx_wifi,
                                            network_tx_mobile,
                                            network_tx_wifi,
                                            total_network_bytes,
                                            total_wakelock_time_ms,
                                            total_job_time_ms,
                                            foreground_service_time_ms,
                                            total_job_count,
                                        });
                                    }
                                }
                                
                                log::info!("    ✅ [ANALYZE] Transformed {} battery app entries into BatteryAppInfo", battery_apps.len());
                                
                                // Note: BatteryInfoSummary (level, health, temperature, voltage) 
                                // is not available in this parser output - it may come from a different source
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Battery result is not an array");
                            }
                        },
                        ParserType::Process => {
                            log::info!("    ⚙️ [ANALYZE] Extracting process info...");
                            if let Some(arr) = json_output.as_array() {
                                process_count = arr.len();
                                log::info!("    ✅ [ANALYZE] Found {} processes", process_count);
                                
                                // Transform process data into ProcessInfo structs
                                for proc_json in arr {
                                    if let Some(proc_obj) = proc_json.as_object() {
                                        let pid = proc_obj.get("pid")
                                            .and_then(|v| v.as_u64())
                                            .map(|v| v as u32)
                                            .unwrap_or(0);
                                        
                                        let name = proc_obj.get("cmd")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unknown")
                                            .to_string();
                                        
                                        let user = proc_obj.get("user")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unknown")
                                            .to_string();
                                        
                                        // Calculate total CPU from all threads
                                        let cpu_percent = proc_obj.get("threads")
                                            .and_then(|threads| threads.as_array())
                                            .map(|threads| {
                                                threads.iter()
                                                    .filter_map(|t| t.as_object()
                                                        .and_then(|t_obj| t_obj.get("cpu_percent"))
                                                        .and_then(|cp| cp.as_f64()))
                                                    .sum::<f64>()
                                            })
                                            .unwrap_or(0.0);
                                        
                                        let memory = proc_obj.get("res")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("0")
                                            .to_string();
                                        
                                        let virtual_memory = proc_obj.get("virt")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("0")
                                            .to_string();
                                        
                                        let policy = proc_obj.get("pcy")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unknown")
                                            .to_string();
                                        
                                        processes.push(ProcessInfo {
                                            pid,
                                            name,
                                            user,
                                            cpu_percent,
                                            memory,
                                            virtual_memory,
                                            policy,
                                        });
                                    }
                                }
                                
                                log::info!("    ✅ [ANALYZE] Transformed {} processes into ProcessInfo", processes.len());
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Process result is not an array");
                            }
                        },
                        ParserType::Package => {
                            log::info!("    📦 [ANALYZE] Extracting package info...");
                            
                            // Helper function to parse install logs from an object
                            let mut parse_install_logs_from_obj = |obj: &serde_json::Map<String, serde_json::Value>| -> Option<usize> {
                                log::info!("    📦 [ANALYZE] Package object has keys: {:?}", obj.keys().collect::<Vec<_>>());
                                if let Some(install_logs) = obj.get("install_logs") {
                                    if let Some(arr) = install_logs.as_array() {
                                        let log_count = arr.len();
                                        log::info!("    ✅ [ANALYZE] Found {} install log entries", log_count);
                                        
                                        // Parse install logs to extract package installation information
                                        let mut install_map: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
                                        
                                        for log_entry in arr {
                                            if let Some(log_obj) = log_entry.as_object() {
                                                if let Some(event_type) = log_obj.get("event_type").and_then(|v| v.as_str()) {
                                                    if event_type == "START_INSTALL" {
                                                        // Store the start install event
                                                        if let Some(observer) = log_obj.get("observer").and_then(|v| v.as_str()) {
                                                            install_map.insert(observer.to_string(), log_entry.clone());
                                                        }
                                                    } else if event_type == "INSTALL_RESULT" {
                                                        // Match with START_INSTALL and create package info
                                                        if let Some(message) = log_obj.get("message").and_then(|v| v.as_str()) {
                                                            // Extract observer ID from message like "result of install: 1{39329309}"
                                                            if let Some(observer_start) = message.find('{') {
                                                                if let Some(observer_end) = message[observer_start + 1..].find('}') {
                                                                    let observer = &message[observer_start + 1..observer_start + 1 + observer_end];
                                                                    if let Some(start_install) = install_map.remove(observer) {
                                                                        if let Some(start_obj) = start_install.as_object() {
                                                                            let package_name = start_obj.get("pkg")
                                                                                .and_then(|v| v.as_str())
                                                                                .unwrap_or("Unknown")
                                                                                .to_string();
                                                                            let installer = start_obj.get("request_from")
                                                                                .and_then(|v| v.as_str())
                                                                                .unwrap_or("Unknown")
                                                                                .to_string();
                                                                            let timestamp = start_obj.get("timestamp")
                                                                                .and_then(|v| v.as_str())
                                                                                .unwrap_or("")
                                                                                .to_string();
                                                                            let version_code = start_obj.get("versionCode")
                                                                                .and_then(|v| v.as_u64());
                                                                            let staged_dir = start_obj.get("stagedDir")
                                                                                .and_then(|v| v.as_str())
                                                                                .map(|s| s.to_string());
                                                                            
                                                                            // Check if installation was successful (message contains "result of install: 1")
                                                                            let success = message.contains("result of install: 1");
                                                                            
                                                                            // Calculate duration if both timestamps are available
                                                                            // Parse timestamps (format: "2024-09-11 10:27:49.950")
                                                                            let duration_seconds = if let Some(result_timestamp) = log_obj.get("timestamp").and_then(|v| v.as_str()) {
                                                                                // Parse timestamps to calculate duration
                                                                                // Format: "YYYY-MM-DD HH:MM:SS.mmm" or "YYYY-MM-DD HH:MM:SS"
                                                                                let parse_to_seconds = |ts: &str| -> Option<f64> {
                                                                                    // Split into date and time parts
                                                                                    let parts: Vec<&str> = ts.trim().split(' ').collect();
                                                                                    if parts.len() >= 2 {
                                                                                        let date_parts: Vec<&str> = parts[0].split('-').collect();
                                                                                        let time_parts: Vec<&str> = parts[1].split(':').collect();
                                                                                        if date_parts.len() == 3 && time_parts.len() >= 3 {
                                                                                            if let (Ok(year), Ok(month), Ok(day), Ok(hour), Ok(min), Ok(sec)) = (
                                                                                                date_parts[0].parse::<i32>(),
                                                                                                date_parts[1].parse::<u32>(),
                                                                                                date_parts[2].parse::<u32>(),
                                                                                                time_parts[0].parse::<u32>(),
                                                                                                time_parts[1].parse::<u32>(),
                                                                                                time_parts[2].split('.').next().unwrap_or("0").parse::<u32>(),
                                                                                            ) {
                                                                                                // Convert to total seconds since 2000-01-01 (arbitrary epoch for relative calculation)
                                                                                                // This is just for calculating differences, not absolute time
                                                                                                let days = (year - 2000) * 365 + (year - 1999) / 4 + 
                                                                                                          ((month - 1) as i32 * 30) + (day as i32);
                                                                                                let total_seconds = (days as f64 * 86400.0) + 
                                                                                                                   (hour as f64 * 3600.0) + 
                                                                                                                   (min as f64 * 60.0) + 
                                                                                                                   (sec as f64);
                                                                                                return Some(total_seconds);
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                    None
                                                                                };
                                                                                
                                                                                if let (Some(start_ts), Some(end_ts)) = (parse_to_seconds(&timestamp), parse_to_seconds(result_timestamp)) {
                                                                                    let diff = end_ts - start_ts;
                                                                                    if diff >= 0.0 {
                                                                                        Some(diff)
                                                                                    } else {
                                                                                        None
                                                                                    }
                                                                                } else {
                                                                                    None
                                                                                }
                                                                            } else {
                                                                                None
                                                                            };
                                                                            
                                                                            packages.push(PackageInstallationInfo {
                                                                                package_name,
                                                                                installer,
                                                                                timestamp,
                                                                                version_code,
                                                                                success,
                                                                                duration_seconds,
                                                                                staged_dir,
                                                                            });
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        
                                        log::info!("    ✅ [ANALYZE] Parsed {} package installations from {} log entries", packages.len(), log_count);
                                        Some(log_count)
                                    } else {
                                        log::warn!("    ⚠️ [ANALYZE] install_logs is not an array: {:?}", install_logs);
                                        None
                                    }
                                } else {
                                    log::warn!("    ⚠️ [ANALYZE] No install_logs key in package data. Available keys: {:?}", obj.keys().collect::<Vec<_>>());
                                    None
                                }
                            };
                            
                            // PackageParser may return {packages: [...], install_logs: [...], client_pids: [...]} as object or wrapped in array
                            // First, check for the new "packages" array
                            let mut parse_packages_array = |obj: &serde_json::Map<String, serde_json::Value>| {
                                if let Some(packages_arr) = obj.get("packages").and_then(|v| v.as_array()) {
                                    log::info!("    📦 [ANALYZE] Found packages array with {} entries", packages_arr.len());
                                    
                                    for pkg_json in packages_arr {
                                        if let Some(pkg_obj) = pkg_json.as_object() {
                                            let package_name = pkg_obj.get("package_name")
                                                .or_else(|| pkg_obj.get("pkg"))
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("Unknown")
                                                .to_string();
                                            
                                            let version_code = pkg_obj.get("versionCode")
                                                .and_then(|v| v.as_u64());
                                            
                                            let version_name = pkg_obj.get("versionName")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let app_id = pkg_obj.get("appId")
                                                .and_then(|v| v.as_u64())
                                                .map(|v| v as u32);
                                            
                                            let target_sdk = pkg_obj.get("targetSdk")
                                                .and_then(|v| v.as_u64())
                                                .map(|v| v as u32);
                                            
                                            let min_sdk = pkg_obj.get("minSdk")
                                                .and_then(|v| v.as_u64())
                                                .map(|v| v as u32);
                                            
                                            let code_path = pkg_obj.get("codePath")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let resource_path = pkg_obj.get("resourcePath")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let flags = pkg_obj.get("flags")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let pkg_flags = pkg_obj.get("pkgFlags")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let primary_cpu_abi = pkg_obj.get("primaryCpuAbi")
                                                .and_then(|v| v.as_str())
                                                .filter(|s| s != &"null")
                                                .map(|s| s.to_string());
                                            
                                            let installer_package_name = pkg_obj.get("installerPackageName")
                                                .and_then(|v| v.as_str())
                                                .filter(|s| s != &"null")
                                                .map(|s| s.to_string());
                                            
                                            let last_update_time = pkg_obj.get("lastUpdateTime")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let time_stamp = pkg_obj.get("timeStamp")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let category = pkg_obj.get("category")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            // Extract install_logs array
                                            let install_logs = pkg_obj.get("install_logs")
                                                .and_then(|v| v.as_array())
                                                .map(|arr| arr.clone())
                                                .unwrap_or_default();
                                            
                                            // Parse users array
                                            let mut users_info = Vec::new();
                                            if let Some(users_arr) = pkg_obj.get("users").and_then(|v| v.as_array()) {
                                                for user_json in users_arr {
                                                    if let Some(user_obj) = user_json.as_object() {
                                                        let user_id = user_obj.get("user_id")
                                                            .and_then(|v| v.as_u64())
                                                            .map(|v| v as u32);
                                                        
                                                        let first_install_time = user_obj.get("firstInstallTime")
                                                            .and_then(|v| v.as_str())
                                                            .map(|s| s.to_string());
                                                        
                                                        let last_disabled_caller = user_obj.get("lastDisabledCaller")
                                                            .and_then(|v| v.as_str())
                                                            .filter(|s| s != &"null" && !s.is_empty())
                                                            .map(|s| s.to_string());
                                                        
                                                        let data_dir = user_obj.get("dataDir")
                                                            .and_then(|v| v.as_str())
                                                            .map(|s| s.to_string());
                                                        
                                                        let enabled = user_obj.get("enabled")
                                                            .and_then(|v| v.as_u64())
                                                            .map(|v| v as u32);
                                                        
                                                        let installed = user_obj.get("installed")
                                                            .and_then(|v| v.as_bool());
                                                        
                                                        users_info.push(PackageUserInfo {
                                                            user_id,
                                                            first_install_time,
                                                            last_disabled_caller,
                                                            data_dir,
                                                            enabled,
                                                            installed,
                                                        });
                                                    }
                                                }
                                            }
                                            
                                            let user_count = users_info.len();
                                            
                                            package_details.push(PackageDetails {
                                                package_name,
                                                version_code,
                                                version_name,
                                                app_id,
                                                target_sdk,
                                                min_sdk,
                                                code_path,
                                                resource_path,
                                                flags,
                                                pkg_flags,
                                                primary_cpu_abi,
                                                installer_package_name,
                                                last_update_time,
                                                time_stamp,
                                                category,
                                                install_logs,
                                                user_count,
                                                users: users_info,
                                            });
                                        }
                                    }
                                    
                                    log::info!("    ✅ [ANALYZE] Parsed {} package details", package_details.len());
                                    Some(packages_arr.len())
                                } else {
                                    None
                                }
                            };
                            
                            // Try to parse packages array first
                            // The packages key might be in a different element of the array than install_logs
                            let mut parsed_packages = false;
                            if let Some(obj) = json_output.as_object() {
                                if parse_packages_array(obj).is_some() {
                                    parsed_packages = true;
                                }
                                // Also try to parse install_logs for backward compatibility
                                if let Some(count) = parse_install_logs_from_obj(obj) {
                                    package_count = count;
                                }
                            } else if let Some(arr) = json_output.as_array() {
                                log::info!("    📦 [ANALYZE] Package result is an array with {} elements", arr.len());
                                
                                // Iterate through all array elements to find packages and install_logs
                                for (idx, elem) in arr.iter().enumerate() {
                                    if let Some(obj) = elem.as_object() {
                                        log::info!("    📦 [ANALYZE] Checking array element {} with keys: {:?}", idx, obj.keys().collect::<Vec<_>>());
                                        
                                        // Check for packages array in this element
                                        if parse_packages_array(obj).is_some() {
                                            parsed_packages = true;
                                            log::info!("    ✅ [ANALYZE] Found packages array in element {}", idx);
                                        }
                                        
                                        // Also check for install_logs in this element
                                        if let Some(count) = parse_install_logs_from_obj(obj) {
                                            package_count = count;
                                            log::info!("    ✅ [ANALYZE] Found install_logs in element {}", idx);
                                        }
                                    }
                                }
                                
                                if !parsed_packages {
                                    log::warn!("    ⚠️ [ANALYZE] No packages array found in any array element");
                                }
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Package result is not an object or array");
                            }
                            
                            // Update package_count from package_details if we parsed packages
                            if parsed_packages && !package_details.is_empty() {
                                package_count = package_details.len();
                            }
                        },
                        ParserType::Power => {
                            log::info!("    ⚡ [ANALYZE] Extracting power history...");
                            // PowerParser returns an object with timestamp keys
                            if let Some(obj) = json_output.as_object() {
                                log::info!("    📊 [ANALYZE] Power object has {} entries", obj.len());
                                
                                for (timestamp_key, entry_value) in obj {
                                    if let Some(entry_obj) = entry_value.as_object() {
                                        let reason = entry_obj.get("reason")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string());
                                        
                                        // Parse history_events
                                        let mut events = Vec::new();
                                        if let Some(events_arr) = entry_obj.get("history_events").and_then(|v| v.as_array()) {
                                            for event_json in events_arr {
                                                if let Some(event_obj) = event_json.as_object() {
                                                    let event_type = event_obj.get("event_type")
                                                        .and_then(|v| v.as_str())
                                                        .unwrap_or("")
                                                        .to_string();
                                                    
                                                    let timestamp = event_obj.get("timestamp")
                                                        .and_then(|v| v.as_str())
                                                        .map(|s| s.to_string());
                                                    
                                                    let details = event_obj.get("details")
                                                        .and_then(|v| v.as_str())
                                                        .map(|s| s.to_string());
                                                    
                                                    let flags = event_obj.get("flags")
                                                        .and_then(|v| v.as_str())
                                                        .map(|s| s.to_string());
                                                    
                                                    events.push(PowerEvent {
                                                        event_type,
                                                        timestamp,
                                                        details,
                                                        flags,
                                                    });
                                                }
                                            }
                                        }
                                        
                                        // Parse stack_trace
                                        let mut stack_trace = Vec::new();
                                        if let Some(stack_arr) = entry_obj.get("stack_trace").and_then(|v| v.as_array()) {
                                            for line in stack_arr {
                                                if let Some(line_str) = line.as_str() {
                                                    stack_trace.push(line_str.to_string());
                                                }
                                            }
                                        }
                                        
                                        power_history.push(PowerHistory {
                                            timestamp: timestamp_key.clone(),
                                            reason,
                                            history_events: events,
                                            stack_trace,
                                        });
                                    }
                                }
                                
                                log::info!("    ✅ [ANALYZE] Parsed {} power history entries", power_history.len());
                                
                                // Sort by timestamp (most recent first)
                                power_history.sort_by(|a, b| {
                                    // Parse timestamp format: "YY/MM/DD HH:MM:SS"
                                    let parse_timestamp = |ts: &str| -> Option<(i32, u32, u32, u32, u32, u32)> {
                                        let parts: Vec<&str> = ts.trim().split(' ').collect();
                                        if parts.len() >= 2 {
                                            let date_parts: Vec<&str> = parts[0].split('/').collect();
                                            let time_parts: Vec<&str> = parts[1].split(':').collect();
                                            if date_parts.len() == 3 && time_parts.len() >= 3 {
                                                if let (Ok(year), Ok(month), Ok(day), Ok(hour), Ok(min), Ok(sec)) = (
                                                    date_parts[0].parse::<i32>(),
                                                    date_parts[1].parse::<u32>(),
                                                    date_parts[2].parse::<u32>(),
                                                    time_parts[0].parse::<u32>(),
                                                    time_parts[1].parse::<u32>(),
                                                    time_parts[2].parse::<u32>(),
                                                ) {
                                                    // Assume 20XX for years < 50, 19XX otherwise
                                                    let full_year = if year < 50 { 2000 + year } else { 1900 + year };
                                                    return Some((full_year, month, day, hour, min, sec));
                                                }
                                            }
                                        }
                                        None
                                    };
                                    
                                    match (parse_timestamp(&b.timestamp), parse_timestamp(&a.timestamp)) {
                                        (Some(b_ts), Some(a_ts)) => b_ts.cmp(&a_ts),
                                        (Some(_), None) => std::cmp::Ordering::Less,
                                        (None, Some(_)) => std::cmp::Ordering::Greater,
                                        (None, None) => b.timestamp.cmp(&a.timestamp),
                                    }
                                });
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Power result is not an object");
                            }
                        },
                        _ => {
                            log::info!("    ℹ️ [ANALYZE] Skipping {:?} (not used in summary)", parser_type);
                        }
                    }
                }
                Err(e) => {
                    log::error!("  ❌ [ANALYZE] {:?} parser failed: {}", parser_type, e);
                }
            }
        }
        
        // Sort packages by timestamp (newest first)
        // Parse timestamps for proper comparison
        packages.sort_by(|a, b| {
            // Parse timestamp format: "YYYY-MM-DD HH:MM:SS.mmm" or "YYYY-MM-DD HH:MM:SS"
            let parse_timestamp = |ts: &str| -> Option<(i32, u32, u32, u32, u32, u32, u32)> {
                let parts: Vec<&str> = ts.trim().split(' ').collect();
                if parts.len() >= 2 {
                    let date_parts: Vec<&str> = parts[0].split('-').collect();
                    let time_parts: Vec<&str> = parts[1].split(':').collect();
                    if date_parts.len() == 3 && time_parts.len() >= 3 {
                        // Parse seconds and milliseconds (format: "SS.mmm" or "SS")
                        let sec_part = time_parts[2];
                        let sec_millis: Vec<&str> = sec_part.split('.').collect();
                        let sec = sec_millis[0].parse::<u32>().ok()?;
                        let millis = if sec_millis.len() > 1 {
                            sec_millis[1].parse::<u32>().ok().unwrap_or(0)
                        } else {
                            0
                        };
                        
                        if let (Ok(year), Ok(month), Ok(day), Ok(hour), Ok(min)) = (
                            date_parts[0].parse::<i32>(),
                            date_parts[1].parse::<u32>(),
                            date_parts[2].parse::<u32>(),
                            time_parts[0].parse::<u32>(),
                            time_parts[1].parse::<u32>(),
                        ) {
                            return Some((year, month, day, hour, min, sec, millis));
                        }
                    }
                }
                None
            };
            
            match (parse_timestamp(&b.timestamp), parse_timestamp(&a.timestamp)) {
                (Some(b_ts), Some(a_ts)) => {
                    // Compare: year, month, day, hour, min, sec, millis
                    b_ts.cmp(&a_ts)
                }
                (Some(_), None) => std::cmp::Ordering::Less, // b has valid timestamp, a doesn't - b comes first
                (None, Some(_)) => std::cmp::Ordering::Greater, // a has valid timestamp, b doesn't - a comes first
                (None, None) => b.timestamp.cmp(&a.timestamp), // Fallback to string comparison
            }
        });
        
        // Sort processes by total CPU usage (descending - highest CPU first), then by PID (ascending)
        processes.sort_by(|a, b| {
            // First sort by CPU (descending - highest first)
            match b.cpu_percent.partial_cmp(&a.cpu_percent) {
                Some(std::cmp::Ordering::Equal) => {
                    // If CPU is equal, sort by PID (ascending)
                    a.pid.cmp(&b.pid)
                }
                Some(ordering) => ordering,
                None => {
                    // If comparison fails, fall back to PID
                    a.pid.cmp(&b.pid)
                }
            }
        });
        
        // Sort battery apps by total CPU time (descending - highest CPU first), then by package name
        battery_apps.sort_by(|a, b| {
            // First sort by total CPU time (descending - highest first)
            match b.total_cpu_time_ms.cmp(&a.total_cpu_time_ms) {
                std::cmp::Ordering::Equal => {
                    // If CPU is equal, sort by package name (ascending)
                    a.package_name.cmp(&b.package_name)
                }
                ordering => ordering,
            }
        });
        
        // Calculate unique package count (count distinct package names, ignoring versions)
        let unique_package_count = {
            let mut unique_packages = std::collections::HashSet::new();
            for pkg in &packages {
                unique_packages.insert(pkg.package_name.clone());
            }
            unique_packages.len()
        };
        
        // Sort package_details by time_stamp (most recent first)
        // Parse timestamp format: "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DD HH:MM:SS.mmm"
        package_details.sort_by(|a, b| {
            let parse_timestamp = |ts: &Option<String>| -> Option<(i32, u32, u32, u32, u32, u32, u32)> {
                let ts_str = ts.as_ref()?;
                let parts: Vec<&str> = ts_str.trim().split(' ').collect();
                if parts.len() >= 2 {
                    let date_parts: Vec<&str> = parts[0].split('-').collect();
                    let time_parts: Vec<&str> = parts[1].split(':').collect();
                    if date_parts.len() == 3 && time_parts.len() >= 3 {
                        // Parse seconds and milliseconds (format: "SS.mmm" or "SS")
                        let sec_part = time_parts[2];
                        let sec_millis: Vec<&str> = sec_part.split('.').collect();
                        let sec = sec_millis[0].parse::<u32>().ok()?;
                        let millis = if sec_millis.len() > 1 {
                            sec_millis[1].parse::<u32>().ok().unwrap_or(0)
                        } else {
                            0
                        };
                        
                        if let (Ok(year), Ok(month), Ok(day), Ok(hour), Ok(min)) = (
                            date_parts[0].parse::<i32>(),
                            date_parts[1].parse::<u32>(),
                            date_parts[2].parse::<u32>(),
                            time_parts[0].parse::<u32>(),
                            time_parts[1].parse::<u32>(),
                        ) {
                            return Some((year, month, day, hour, min, sec, millis));
                        }
                    }
                }
                None
            };
            
            match (parse_timestamp(&b.time_stamp), parse_timestamp(&a.time_stamp)) {
                (Some(b_ts), Some(a_ts)) => {
                    // Compare: year, month, day, hour, min, sec, millis (descending - newest first)
                    b_ts.cmp(&a_ts)
                }
                (Some(_), None) => std::cmp::Ordering::Less, // b has valid timestamp, a doesn't - b comes first
                (None, Some(_)) => std::cmp::Ordering::Greater, // a has valid timestamp, b doesn't - a comes first
                (None, None) => {
                    // If both lack timestamps, fall back to package name
                    a.package_name.cmp(&b.package_name)
                }
            }
        });
        
        log::info!("📊 [ANALYZE] Building summary...");
        let summary = BugreportSummary {
            device_info: device_info.clone(),
            battery_info: battery_info.clone(),
            process_count,
            package_count: unique_package_count,
            has_security_analysis: false, // Detection would be separate
            analysis_complete: true,
            packages: packages.clone(),
            processes: processes.clone(),
            battery_apps: battery_apps.clone(),
            package_details: package_details.clone(),
            power_history: power_history.clone(),
        };
        
        log::info!("✅ [ANALYZE] Analysis complete!");
        log::info!("📱 [ANALYZE] Device: {:?}", device_info.as_ref().map(|d| format!("{} {}", d.manufacturer, d.model)));
        log::info!("🔋 [ANALYZE] Battery: {:?}", battery_info.as_ref().map(|b| format!("{}%", b.level)));
        log::info!("⚙️ [ANALYZE] Processes: {}", process_count);
        log::info!("📦 [ANALYZE] Unique packages: {} ({} total installations)", unique_package_count, packages.len());
        log::info!("⚡ [ANALYZE] Power history events: {}", power_history.len());
        
        Ok(serde_wasm_bindgen::to_value(&summary)?)
    }

    /// Analyze a bugreport and get detailed security analysis
    /// Returns detailed security findings as JSON
    #[wasm_bindgen]
    #[cfg(feature = "bugreport-analysis")]
    pub async fn analyze_bugreport_security(&self, data: Vec<u8>) -> Result<JsValue, JsValue> {
        use bugreport_extractor_library::run_parsers_concurrently;
        use bugreport_extractor_library::parsers::{
            Parser as DataParser, ParserType, BatteryParser
        };
        use bugreport_extractor_library::parsers::battery_parser::AppBatteryStats;
        use bugreport_extractor_library::detection::detector::ExploitationDetector;
        use std::sync::Arc;
        
        log::info!("Starting security analysis ({} bytes)", data.len());
        
        let file_content: Arc<[u8]> = Arc::from(data.as_slice());
        
        // Create battery parser for exploitation detection
        let mut parsers_to_run: Vec<(ParserType, Box<dyn DataParser + Send + Sync>)> = Vec::new();
        if let Ok(battery_parser) = BatteryParser::new() {
            parsers_to_run.push((ParserType::Battery, Box::new(battery_parser)));
        }
        
        let results = run_parsers_concurrently(file_content, parsers_to_run);
        
        // Extract battery stats and run exploitation detection
        for (parser_type, result, _) in results {
            if parser_type == ParserType::Battery {
                if let Ok(json_output) = result {
                    let apps: Vec<AppBatteryStats> = serde_json::from_value(json_output)
                        .map_err(|e| JsValue::from_str(&format!("Failed to parse battery stats: {}", e)))?;
                    
                    let detector = ExploitationDetector::new();
                    let exploitation = detector.detect_exploitation(&apps);
                    
                    log::info!("Security analysis found {} potential issues", exploitation.len());
                    return Ok(serde_wasm_bindgen::to_value(&exploitation)?);
                }
            }
        }
        
        Err(JsValue::from_str("No security findings detected"))
    }

    /// Analyze a bugreport downloaded from device path
    /// Downloads the bugreport and analyzes it in one step
    #[wasm_bindgen]
    #[cfg(feature = "bugreport-analysis")]
    pub async fn analyze_bugreport_from_device(&mut self, path: String) -> Result<JsValue, JsValue> {
        log::info!("Downloading and analyzing bugreport from: {}", path);
        
        // Download the bugreport
        let data = self.download_bugreport(path).await?;
        
        // Convert Uint8Array to Vec<u8>
        let vec = js_sys::Uint8Array::new(&data).to_vec();
        
        // Analyze it
        self.analyze_bugreport(vec).await
    }

    /// Get full bugreport data as JSON for inspection
    #[wasm_bindgen]
    #[cfg(feature = "bugreport-analysis")]
    pub async fn get_bugreport_full_data(&self, data: Vec<u8>) -> Result<JsValue, JsValue> {
        use bugreport_extractor_library::run_parsers_concurrently;
        use bugreport_extractor_library::parsers::{
            Parser as DataParser, ParserType, HeaderParser, BatteryParser, 
            PackageParser, ProcessParser, PowerParser, UsbParser
        };
        use std::sync::Arc;
        
        log::info!("Extracting full bugreport data ({} bytes)", data.len());
        
        let file_content: Arc<[u8]> = Arc::from(data.as_slice());
        
        // Create all available parsers
        let mut parsers_to_run: Vec<(ParserType, Box<dyn DataParser + Send + Sync>)> = Vec::new();
        
        if let Ok(p) = HeaderParser::new() { parsers_to_run.push((ParserType::Header, Box::new(p))); }
        if let Ok(p) = BatteryParser::new() { parsers_to_run.push((ParserType::Battery, Box::new(p))); }
        if let Ok(p) = PackageParser::new() { parsers_to_run.push((ParserType::Package, Box::new(p))); }
        if let Ok(p) = ProcessParser::new() { parsers_to_run.push((ParserType::Process, Box::new(p))); }
        if let Ok(p) = PowerParser::new() { parsers_to_run.push((ParserType::Power, Box::new(p))); }
        if let Ok(p) = UsbParser::new() { parsers_to_run.push((ParserType::Usb, Box::new(p))); }
        
        let results = run_parsers_concurrently(file_content, parsers_to_run);
        
        // Convert results to a structured JSON object
        use serde_json::{Map, Value};
        let mut full_data = Map::new();
        
        for (parser_type, result, duration) in results {
            let parser_name = format!("{:?}", parser_type).to_lowercase();
            
            match result {
                Ok(json_output) => {
                    let mut parser_result = Map::new();
                    parser_result.insert("data".to_string(), json_output);
                    parser_result.insert("duration_ms".to_string(), Value::from(duration.as_millis() as u64));
                    parser_result.insert("success".to_string(), Value::from(true));
                    
                    full_data.insert(parser_name, Value::Object(parser_result));
                }
                Err(e) => {
                    let mut parser_result = Map::new();
                    parser_result.insert("error".to_string(), Value::from(e.to_string()));
                    parser_result.insert("success".to_string(), Value::from(false));
                    
                    full_data.insert(parser_name, Value::Object(parser_result));
                }
            }
        }
        
        log::info!("Parsed bugreport with {} parsers", full_data.len());
        
        Ok(serde_wasm_bindgen::to_value(&full_data)?)
    }
}

/// Generate a new RSA keypair and save it
#[wasm_bindgen]
pub fn generate_keypair() -> Result<(), JsValue> {
    let keypair = AdbKeyPair::generate()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    storage::save_key(&keypair)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(())
}

/// Remove stored keypair
#[wasm_bindgen]
pub fn remove_keypair() -> Result<(), JsValue> {
    storage::remove_key()
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Check if a keypair is stored
#[wasm_bindgen]
pub fn has_keypair() -> Result<bool, JsValue> {
    match storage::load_key() {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

/// Extract kernel version from kernel string
/// Format: "Linux version 6.6.50-android15-8-abA346BXXSBDYI1-4k (kleaf@build-host) ..."
/// Returns: "6.6.50-android15-8-abA346BXXSBDYI1-4k"
#[cfg(feature = "bugreport-analysis")]
pub fn extract_kernel_version(kernel_str: &str) -> String {
    // Extract version from "Linux version 6.6.50-android15-8-abA346BXXSBDYI1-4k ..."
    if let Some(version_start) = kernel_str.find("Linux version ") {
        let version_part = &kernel_str[version_start + 13..]; // Skip "Linux version "
        // Trim leading whitespace first
        let version_part = version_part.trim_start();
        // Find first whitespace or opening parenthesis
        let version_end = version_part
            .find(char::is_whitespace)
            .or_else(|| version_part.find('('))
            .unwrap_or(version_part.len());
        
        version_part[..version_end].to_string()
    } else {
        // If "Linux version " not found, return the whole string (truncated if too long)
        if kernel_str.len() > 100 {
            format!("{}...", &kernel_str[..100])
        } else {
            kernel_str.to_string()
        }
    }
}

/// Extract manufacturer and model from build fingerprint
/// Format: 'samsung/a34xeea/a34x:15/AP3A.240905.015.A2/A346BXXSBDYI1:user/release-keys'
/// Returns: (manufacturer, model)
#[cfg(feature = "bugreport-analysis")]
pub fn extract_manufacturer_model(fingerprint: &str) -> (String, String) {
    // Remove quotes if present
    let fp_clean = fingerprint.trim_matches('\'').trim_matches('"');
    // Split by '/' - format is manufacturer/codename/device:...
    let parts: Vec<&str> = fp_clean.split('/').collect();
    if parts.len() >= 3 {
        let mfr = parts[0].to_string();
        // Model is usually in the device part (third element)
        // Format: "device:version" or just "device"
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
