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
            PackageParser, ProcessParser
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
            logcat_lines: usize,
            has_security_analysis: bool,
            analysis_complete: bool,
            raw_json: Vec<serde_json::Value>,
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
        
        // Extract data from results
        log::info!("📤 [ANALYZE] Extracting data from parser results...");
        let mut device_info = None;
        let mut battery_info = None;
        let mut process_count = 0;
        let mut package_count = 0;
        let mut raw_json = Vec::new();
        
        for (parser_type, result, duration) in results {
            log::info!("  🔍 [ANALYZE] Processing {:?} result (took {:?})", parser_type, duration);
            
            match result {
                Ok(json_output) => {
                    log::info!("  ✅ [ANALYZE] {:?} parser succeeded", parser_type);
                    
                    // Store the raw JSON output for the frontend
                    // PackageParser already returns {install_logs: [...], client_pids: [...]}
                    // so we don't need to wrap it
                    if parser_type == ParserType::Package {
                        log::info!("  📦 [ANALYZE] Package parser output structure:");
                        log::info!("    Type checks: is_object={}, is_array={}, is_null={}", 
                            json_output.is_object(), json_output.is_array(), json_output.is_null());
                        
                        if let Some(obj) = json_output.as_object() {
                            let keys: Vec<_> = obj.keys().collect();
                            log::info!("    Keys: {:?}", keys);
                            
                            for key in &keys {
                                if let Some(value) = obj.get(*key) {
                                    if let Some(arr) = value.as_array() {
                                        log::info!("    {} is an array with {} entries", key, arr.len());
                                    } else if let Some(obj2) = value.as_object() {
                                        log::info!("    {} is an object with {} keys", key, obj2.len());
                                    } else {
                                        log::info!("    {} is a scalar value", key);
                                    }
                                }
                            }
                            
                            if let Some(install_logs) = obj.get("install_logs") {
                                if let Some(arr) = install_logs.as_array() {
                                    log::info!("    ✅ install_logs is an array with {} entries", arr.len());
                                } else {
                                    log::warn!("    ⚠️ install_logs is not an array!");
                                }
                            } else {
                                log::warn!("    ⚠️ No install_logs key found!");
                            }
                        } else if let Some(arr) = json_output.as_array() {
                            log::warn!("    ⚠️ PackageParser returned an array with {} elements instead of an object!", arr.len());
                        } else {
                            log::error!("    ❌ PackageParser returned unexpected type (not object or array)!");
                        }
                    }
                    
                    raw_json.push(json_output.clone());
                    
                    match parser_type {
                        ParserType::Header => {
                            log::info!("    📝 [ANALYZE] Extracting device info from Header...");
                            // Extract device info from header
                            if let Some(obj) = json_output.as_object() {
                                let manufacturer = obj.get("manufacturer")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown")
                                    .to_string();
                                let model = obj.get("model")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown")
                                    .to_string();
                                let android_version = obj.get("android_version")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown")
                                    .to_string();
                                
                                log::info!("    📱 [ANALYZE] Device: {} {} (Android {})", manufacturer, model, android_version);
                                
                                device_info = Some(DeviceInfoSummary {
                                    manufacturer,
                                    model,
                                    android_version,
                                    build_id: obj.get("build_id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Unknown")
                                        .to_string(),
                                    kernel_version: obj.get("kernel_version")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Unknown")
                                        .to_string(),
                                });
                                log::info!("    ✅ [ANALYZE] Device info extracted successfully");
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Header result is not a JSON object");
                            }
                        },
                        ParserType::Battery => {
                            log::info!("    🔋 [ANALYZE] Extracting battery info...");
                            // Extract battery info
                            if let Some(arr) = json_output.as_array() {
                                log::info!("    📊 [ANALYZE] Battery array has {} entries", arr.len());
                                if let Some(first) = arr.first() {
                                    if let Some(obj) = first.as_object() {
                                        let level = obj.get("battery_level")
                                            .and_then(|v| v.as_f64())
                                            .unwrap_or(0.0) as f32;
                                        let health = obj.get("health")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unknown")
                                            .to_string();
                                        
                                        log::info!("    🔋 [ANALYZE] Battery: {}%, Health: {}", level, health);
                                        
                                        battery_info = Some(BatteryInfoSummary {
                                            level,
                                            health,
                                            temperature: obj.get("temperature")
                                                .and_then(|v| v.as_f64())
                                                .unwrap_or(0.0) as f32,
                                            voltage: obj.get("voltage")
                                                .and_then(|v| v.as_f64())
                                                .unwrap_or(0.0) as f32,
                                        });
                                        log::info!("    ✅ [ANALYZE] Battery info extracted successfully");
                                    } else {
                                        log::warn!("    ⚠️ [ANALYZE] Battery array first element is not an object");
                                    }
                                } else {
                                    log::warn!("    ⚠️ [ANALYZE] Battery array is empty");
                                }
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Battery result is not an array");
                            }
                        },
                        ParserType::Process => {
                            log::info!("    ⚙️ [ANALYZE] Extracting process info...");
                            if let Some(arr) = json_output.as_array() {
                                process_count = arr.len();
                                log::info!("    ✅ [ANALYZE] Found {} processes", process_count);
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Process result is not an array");
                            }
                        },
                        ParserType::Package => {
                            log::info!("    📦 [ANALYZE] Extracting package info...");
                            
                            // Log the type and a sample of the data
                            log::info!("    📦 [ANALYZE] Package data type: is_object={}, is_array={}, is_null={}, is_string={}", 
                                json_output.is_object(), 
                                json_output.is_array(),
                                json_output.is_null(),
                                json_output.is_string()
                            );
                            
                            // Log the actual value (truncated)
                            let json_str = json_output.to_string();
                            let preview = if json_str.len() > 500 {
                                format!("{}... (truncated, total {} chars)", &json_str[..500], json_str.len())
                            } else {
                                json_str
                            };
                            log::info!("    📦 [ANALYZE] Package data preview: {}", preview);
                            
                            // PackageParser returns {install_logs: [...], client_pids: [...]}
                            if let Some(obj) = json_output.as_object() {
                                log::info!("    📦 [ANALYZE] Package object has keys: {:?}", obj.keys().collect::<Vec<_>>());
                                if let Some(install_logs) = obj.get("install_logs") {
                                    if let Some(arr) = install_logs.as_array() {
                                        package_count = arr.len();
                                        log::info!("    ✅ [ANALYZE] Found {} install log entries", package_count);
                                        if package_count > 0 {
                                            log::info!("    📦 [ANALYZE] First install log entry: {:?}", 
                                                arr.first().map(|v| v.to_string().chars().take(200).collect::<String>()));
                                        }
                                    } else {
                                        log::warn!("    ⚠️ [ANALYZE] install_logs is not an array: {:?}", install_logs);
                                    }
                                } else {
                                    log::warn!("    ⚠️ [ANALYZE] No install_logs key in package data. Available keys: {:?}", obj.keys().collect::<Vec<_>>());
                                }
                            } else if let Some(arr) = json_output.as_array() {
                                log::warn!("    ⚠️ [ANALYZE] Package result is an array with {} elements, expected an object with install_logs", arr.len());
                                if arr.len() > 0 {
                                    log::info!("    📦 [ANALYZE] First array element: {:?}", arr.first().map(|v| v.to_string().chars().take(200).collect::<String>()));
                                }
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Package result is not an object or array");
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
        
        log::info!("📊 [ANALYZE] Building summary...");
        let summary = BugreportSummary {
            device_info: device_info.clone(),
            battery_info: battery_info.clone(),
            process_count,
            package_count,
            logcat_lines: 0, // We'd need to add LogcatParser for this
            has_security_analysis: false, // Detection would be separate
            analysis_complete: true,
            raw_json,
        };
        
        log::info!("✅ [ANALYZE] Analysis complete!");
        log::info!("📱 [ANALYZE] Device: {:?}", device_info.as_ref().map(|d| format!("{} {}", d.manufacturer, d.model)));
        log::info!("🔋 [ANALYZE] Battery: {:?}", battery_info.as_ref().map(|b| format!("{}%", b.level)));
        log::info!("⚙️ [ANALYZE] Processes: {}", process_count);
        log::info!("📦 [ANALYZE] Packages: {}", package_count);
        
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