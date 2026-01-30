use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

use super::auth::{AdbKeyPair, storage};
use super::client::AdbClient;
use super::transport::WebUsbTransport;
#[cfg(feature = "bugreport-analysis")]
use super::parsers::{extract_kernel_version, extract_manufacturer_model, parse_anr_crash_json};

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
        log::info!("[WASM] connect() called");
        // Get or create keypair
        let keypair = match storage::load_key() {
            Ok(Some(keypair)) => {
                log::info!("[WASM] Loaded existing keypair from storage");
                keypair
            }
            Ok(None) => {
                log::info!("[WASM] No keypair found, generating new one");
                let keypair = AdbKeyPair::generate()
                    .map_err(|e| {
                        log::error!("[WASM] Failed to generate keypair: {}", e);
                        JsValue::from_str(&e.to_string())
                    })?;
                
                storage::save_key(&keypair)
                    .map_err(|e| {
                        log::error!("[WASM] Failed to save keypair: {}", e);
                        JsValue::from_str(&e.to_string())
                    })?;
                
                log::info!("[WASM] New keypair generated and saved");
                keypair
            }
            Err(e) => {
                log::warn!("[WASM] Error loading keypair, generating new one: {}", e);
                let keypair = AdbKeyPair::generate()
                    .map_err(|e| {
                        log::error!("[WASM] Failed to generate keypair: {}", e);
                        JsValue::from_str(&e.to_string())
                    })?;
                
                storage::save_key(&keypair)
                    .map_err(|e| {
                        log::error!("[WASM] Failed to save keypair: {}", e);
                        JsValue::from_str(&e.to_string())
                    })?;
                
                keypair
            }
        };

        // Request device from user
        log::info!("[WASM] Requesting USB device from user");
        let transport = WebUsbTransport::request_device()
            .await
            .map_err(|e| {
                log::error!("[WASM] Failed to request device: {}", e);
                JsValue::from_str(&e.to_string())
            })?;

        let device_info = transport.device_info();
        log::info!("[WASM] Device selected: vendor_id={}, product_id={}, serial={:?}", 
                   device_info.vendor_id, 
                   device_info.product_id,
                   device_info.serial_number);

        // Create and connect client
        log::info!("[WASM] Creating ADB client");
        let mut client = AdbClient::new(transport, keypair)
            .await
            .map_err(|e| {
                log::error!("[WASM] Failed to create ADB client: {}", e);
                JsValue::from_str(&e.to_string())
            })?;

        log::info!("[WASM] Connecting to device");
        client
            .connect()
            .await
            .map_err(|e| {
                log::error!("[WASM] Failed to connect: {}", e);
                JsValue::from_str(&e.to_string())
            })?;

        log::info!("[WASM] Connection successful");
        self.client = Some(client);

        // Return device info
        let info = JsDeviceInfo {
            vendor_id: device_info.vendor_id,
            product_id: device_info.product_id,
            manufacturer: device_info.manufacturer_name,
            product: device_info.product_name,
            serial: device_info.serial_number,
        };

        log::info!("[WASM] connect() completed successfully");
        Ok(serde_wasm_bindgen::to_value(&info)?)
    }

    /// Execute a shell command
    #[wasm_bindgen]
    pub async fn shell(&mut self, command: String) -> Result<String, JsValue> {
        log::info!("[WASM] shell() called with command: {}", command);
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] shell() called but not connected");
                JsValue::from_str("Not connected")
            })?;

        log::debug!("[WASM] Executing shell command via client");
        let result = client
            .shell(&command)
            .await
            .map_err(|e| {
                log::error!("[WASM] shell() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;
        
        log::info!("[WASM] shell() completed, result length: {} chars", result.len());
        Ok(result)
    }

    /// Get device properties
    #[wasm_bindgen]
    pub async fn get_properties(&mut self) -> Result<JsValue, JsValue> {
        log::info!("[WASM] get_properties() called");
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] get_properties() called but not connected");
                JsValue::from_str("Not connected")
            })?;

        log::debug!("[WASM] Fetching properties from client");
        let props = client
            .get_properties()
            .await
            .map_err(|e| {
                log::error!("[WASM] get_properties() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;

        log::info!("[WASM] get_properties() retrieved {} properties", props.len());
        let js_value = serde_wasm_bindgen::to_value(&props)
            .map_err(|e| {
                log::error!("[WASM] Failed to serialize properties: {}", e);
                JsValue::from_str(&format!("Serialization error: {}", e))
            })?;
        
        log::debug!("[WASM] get_properties() completed successfully");
        Ok(js_value)
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
        log::info!("[WASM] disconnect() called");
        if let Some(client) = self.client.as_mut() {
            log::debug!("[WASM] Disconnecting client");
            client
                .disconnect()
                .await
                .map_err(|e| {
                    log::error!("[WASM] disconnect() failed: {}", e);
                    JsValue::from_str(&e.to_string())
                })?;
            log::info!("[WASM] Client disconnected successfully");
        } else {
            log::warn!("[WASM] disconnect() called but no client exists");
        }
        self.client = None;
        log::info!("[WASM] disconnect() completed");
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
        log::info!("[WASM] bugreport() called (full bugreport)");
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] bugreport() called but not connected");
                JsValue::from_str("Not connected")
            })?;

        log::info!("[WASM] Generating full bugreport (this may take several minutes)");
        let data = client
            .bugreport()
            .await
            .map_err(|e| {
                log::error!("[WASM] bugreport() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;

        log::info!("[WASM] bugreport() completed, size: {} bytes ({:.2} MB)", 
                   data.len(), 
                   data.len() as f64 / 1_048_576.0);
        Ok(js_sys::Uint8Array::from(&data[..]))
    }

    /// Generate a lightweight bugreport (much faster)
    /// Returns a text summary
    #[wasm_bindgen]
    pub async fn bugreport_lite(&mut self) -> Result<String, JsValue> {
        log::info!("[WASM] bugreport_lite() called");
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] bugreport_lite() called but not connected");
                JsValue::from_str("Not connected")
            })?;

        log::debug!("[WASM] Generating lite bugreport");
        let result = client
            .bugreport_lite()
            .await
            .map_err(|e| {
                log::error!("[WASM] bugreport_lite() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;
        
        log::info!("[WASM] bugreport_lite() completed, result length: {} chars", result.len());
        Ok(result)
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
        log::info!("[WASM] logcat() called with lines={}", lines);
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] logcat() called but not connected");
                JsValue::from_str("Not connected")
            })?;

        log::debug!("[WASM] Fetching logcat from client");
        let result = client
            .logcat(lines)
            .await
            .map_err(|e| {
                log::error!("[WASM] logcat() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;
        
        log::info!("[WASM] logcat() completed, result length: {} chars", result.len());
        Ok(result)
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
        log::info!("[WASM] pull_file() called with path: {}", path);
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] pull_file() called but not connected");
                JsValue::from_str("Not connected")
            })?;

        log::debug!("[WASM] Pulling file via client");
        let data = client
            .pull_file(&path)
            .await
            .map_err(|e| {
                log::error!("[WASM] pull_file() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;

        log::info!("[WASM] pull_file() completed, size: {} bytes", data.len());
        Ok(js_sys::Uint8Array::from(&data[..]))
    }

    /// Get file statistics
    #[wasm_bindgen]
    pub async fn stat_file(&mut self, path: String) -> Result<JsValue, JsValue> {
        log::info!("[WASM] stat_file() called with path: {}", path);
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] stat_file() called but not connected");
                JsValue::from_str("Not connected")
            })?;

        log::debug!("[WASM] Getting file stats via client");
        let stat = client
            .stat_file(&path)
            .await
            .map_err(|e| {
                log::error!("[WASM] stat_file() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;
        
        log::info!("[WASM] stat_file() completed, size: {} bytes, is_dir: {}", stat.size, stat.is_directory());

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
        log::info!("[WASM] list_directory() called with path: {}", path);
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] list_directory() called but not connected");
                JsValue::from_str("Not connected")
            })?;

        log::debug!("[WASM] Listing directory via client");
        let entries = client
            .list_directory(&path)
            .await
            .map_err(|e| {
                log::error!("[WASM] list_directory() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;
        
        log::info!("[WASM] list_directory() found {} entries", entries.len());

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
        log::info!("[WASM] cleanup_stale_streams() called");
        let client = self.client.as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] cleanup_stale_streams() called but not connected");
                JsValue::from_str("Not connected")
            })?;
        
        log::debug!("[WASM] Cleaning up stale streams via client");
        let cleaned = client.cleanup_stale_streams().await;
        log::info!("[WASM] cleanup_stale_streams() completed, cleaned {} streams", cleaned);
        Ok(cleaned)
    }
    
    /// Check device health
    #[wasm_bindgen]
    pub async fn health_check(&mut self) -> Result<bool, JsValue> {
        log::info!("[WASM] health_check() called");
        let client = self.client.as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] health_check() called but not connected");
                JsValue::from_str("Not connected")
            })?;
        
        log::debug!("[WASM] Performing health check via client");
        let healthy = client.health_check()
            .await
            .map_err(|e| {
                log::error!("[WASM] health_check() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;
        
        log::info!("[WASM] health_check() completed, healthy: {}", healthy);
        Ok(healthy)
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
        log::info!("[WASM] push_file() called with path: {}, size: {} bytes", remote_path, data.len());
        let client = self.client.as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] push_file() called but not connected");
                JsValue::from_str("Not connected")
            })?;
        
        log::debug!("[WASM] Pushing file via client");
        client.push_file(&data, &remote_path)
            .await
            .map_err(|e| {
                log::error!("[WASM] push_file() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;
        
        log::info!("[WASM] push_file() completed successfully");
        Ok(())
    }
    
    /// Delete a file or directory
    #[wasm_bindgen]
    pub async fn delete_path(&mut self, remote_path: String) -> Result<(), JsValue> {
        log::info!("[WASM] delete_path() called with path: {}", remote_path);
        let client = self.client.as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] delete_path() called but not connected");
                JsValue::from_str("Not connected")
            })?;
        
        log::debug!("[WASM] Deleting path via client");
        client.delete_path(&remote_path)
            .await
            .map_err(|e| {
                log::error!("[WASM] delete_path() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;
        
        log::info!("[WASM] delete_path() completed successfully");
        Ok(())
    }
    
    /// Rename or move a file/directory
    #[wasm_bindgen]
    pub async fn rename_file(&mut self, old_path: String, new_path: String) -> Result<(), JsValue> {
        log::info!("[WASM] rename_file() called: {} -> {}", old_path, new_path);
        let client = self.client.as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] rename_file() called but not connected");
                JsValue::from_str("Not connected")
            })?;
        
        log::debug!("[WASM] Renaming file via client");
        client.rename_file(&old_path, &new_path)
            .await
            .map_err(|e| {
                log::error!("[WASM] rename_file() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;
        
        log::info!("[WASM] rename_file() completed successfully");
        Ok(())
    }
    
    /// Create a directory (with parent directories)
    #[wasm_bindgen]
    pub async fn create_directory(&mut self, remote_path: String) -> Result<(), JsValue> {
        log::info!("[WASM] create_directory() called with path: {}", remote_path);
        let client = self.client.as_mut()
            .ok_or_else(|| {
                log::error!("[WASM] create_directory() called but not connected");
                JsValue::from_str("Not connected")
            })?;
        
        log::debug!("[WASM] Creating directory via client");
        client.create_directory(&remote_path)
            .await
            .map_err(|e| {
                log::error!("[WASM] create_directory() failed: {}", e);
                JsValue::from_str(&e.to_string())
            })?;
        
        log::info!("[WASM] create_directory() completed successfully");
        Ok(())
    }


    #[wasm_bindgen]
    #[cfg(feature = "bugreport-analysis")]
    pub async fn analyze_bugreport(&self, data: Vec<u8>, rules: String) -> Result<JsValue, JsValue> {
        use bugreport_extractor_library::run_parsers_concurrently;
        use bugreport_extractor_library::parsers::{
            Parser as DataParser, ParserType, HeaderParser, BatteryParser,
            PackageParser, ProcessParser, PowerParser, NetworkParser, BluetoothParser, UsbParser,
            CrashParser,
        };
        use bugreport_extractor_library::zip_utils;
        use bugreport_extractor_library::detection::sigma::extract_all_log_entries;
        use sigma_zero::engine::SigmaEngine;
        use sigma_zero::models::SigmaRule;
        use std::sync::Arc;

        log::info!("🔍 [ANALYZE] Starting bugreport analysis");
        log::info!("📊 [ANALYZE] Data size: {} bytes ({:.2} MB)", data.len(), data.len() as f64 / 1_048_576.0);

        log::info!("🔄 [ANALYZE] Converting data to Arc<[u8]>...");

        let data_u8 = data.as_slice();
        let file_content: Arc<[u8]> = if zip_utils::is_zip_file(data_u8) {
            log::info!("📦 [ANALYZE] Detected ZIP file, extracting dumpstate...");
            web_sys::console::log_1(&"Detected ZIP file, extracting dumpstate...".into());
            
            // Always use manual extraction to ensure we get the correct file
            // The library function may pick wrong files (e.g., setupwizard.txt in dump directories)
            log::info!("🔍 [ANALYZE] Using manual extraction to find files starting with 'dumpstate'...");
            match manual_extract_dumpstate(data_u8) {
                Ok(extracted) => {
                    if extracted.is_empty() {
                        log::error!("❌ [ANALYZE] Manual extraction returned empty dumpstate!");
                        return Err(JsValue::from_str(
                            "ZIP extraction returned empty dumpstate. No file found with filename starting with 'dumpstate'. Please check the browser console for details."
                        ));
                    }
                    
                    log::info!(
                        "✅ [ANALYZE] Extracted dumpstate: {:.2} MB ({} bytes)",
                        extracted.len() as f64 / 1_048_576.0,
                        extracted.len()
                    );
                    web_sys::console::log_1(&format!(
                        "Extracted dumpstate: {:.2} MB",
                        extracted.len() as f64 / 1_048_576.0
                    ).into());
                    
                    Arc::from(extracted)
                }
                Err(e) => {
                    let error_msg = format!("{}", e);
                    log::error!("❌ [ANALYZE] Manual ZIP extraction failed: {}", error_msg);
                    log::error!("❌ [ANALYZE] Common causes:");
                    log::error!("  - No file found with filename starting with 'dumpstate'");
                    log::error!("  - ZIP file is corrupted or incomplete");
                    log::error!("  - Different ZIP structure than expected");
                    log::error!("❌ [ANALYZE] Suggestion: Extract the ZIP manually and upload dumpstate.txt directly");
                    return Err(JsValue::from_str(&format!(
                        "ZIP extraction failed: {}. Please extract the ZIP manually and upload dumpstate.txt directly.",
                        error_msg
                    )));
                }
            }
        } else {
            log::info!(
                "📄 [ANALYZE] Loading plain text file: {:.2} MB",
                data.len() as f64 / 1_048_576.0
            );
            
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
        
        // Add Network parser
        log::info!("  🌐 [ANALYZE] Creating NetworkParser...");
        if let Ok(network_parser) = NetworkParser::new() {
            parsers_to_run.push((ParserType::Network, Box::new(network_parser)));
            log::info!("  ✅ [ANALYZE] NetworkParser created");
        } else {
            log::warn!("  ⚠️ [ANALYZE] Failed to create NetworkParser");
        }
        
        // Add Bluetooth parser
        log::info!("  📶 [ANALYZE] Creating BluetoothParser...");
        if let Ok(bluetooth_parser) = BluetoothParser::new() {
            parsers_to_run.push((ParserType::Bluetooth, Box::new(bluetooth_parser)));
            log::info!("  ✅ [ANALYZE] BluetoothParser created");
        } else {
            log::warn!("  ⚠️ [ANALYZE] Failed to create BluetoothParser");
        }
        
        log::info!("  🔌 [ANALYZE] Creating UsbParser...");
        if let Ok(usb_parser) = UsbParser::new() {
            parsers_to_run.push((ParserType::Usb, Box::new(usb_parser)));
            log::info!("  ✅ [ANALYZE] UsbParser created");
        } else {
            log::warn!("  ⚠️ [ANALYZE] Failed to create UsbParser");
        }

        log::info!("  💥 [ANALYZE] Creating CrashParser...");
        if let Ok(crash_parser) = CrashParser::new() {
            parsers_to_run.push((ParserType::Crash, Box::new(crash_parser)));
            log::info!("  ✅ [ANALYZE] CrashParser created");
        } else {
            log::warn!("  ⚠️ [ANALYZE] Failed to create CrashParser");
        }
        
        log::info!("✅ [ANALYZE] Created {} parsers", parsers_to_run.len());

        // Crash/ANR info structures (parsed from parse_anr_crash_json or CrashParser)
        #[derive(Serialize, Deserialize, Clone, Default)]
        struct StackFrameSummary {
            #[serde(default)]
            file_loc: Option<String>,
            #[serde(default)]
            frame_type: Option<String>,
            #[serde(default)]
            line_number: Option<u32>,
            #[serde(default)]
            method: Option<String>,
            // Native frame fields (for native stack traces)
            #[serde(default)]
            address: Option<String>,
            #[serde(default)]
            details: Option<String>,
            #[serde(default)]
            library: Option<String>,
        }
        #[derive(Serialize, Deserialize, Clone, Default)]
        struct ThreadSummary {
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            priority: Option<u32>,
            #[serde(default)]
            tid: Option<u64>,
            #[serde(default)]
            status: Option<String>,
            #[serde(default)]
            is_daemon: Option<bool>,
            #[serde(default)]
            properties: Option<std::collections::HashMap<String, String>>,
            #[serde(default)]
            stack_trace: Vec<StackFrameSummary>,
        }
        #[derive(Serialize, Deserialize, Clone, Default)]
        struct AnrTraceSummary {
            #[serde(default)]
            subject: Option<String>,
            #[serde(default)]
            header: Option<std::collections::HashMap<String, serde_json::Value>>,
            #[serde(default)]
            process_info: Option<std::collections::HashMap<String, serde_json::Value>>,
            #[serde(default)]
            threads: Vec<ThreadSummary>,
        }
        #[derive(Serialize, Deserialize, Clone, Default)]
        struct AnrFileEntry {
            #[serde(default)]
            filename: Option<String>,
            #[serde(default)]
            group: Option<String>,
            #[serde(default)]
            owner: Option<String>,
            #[serde(default)]
            permissions: Option<String>,
            #[serde(default)]
            size: Option<u64>,
            #[serde(default)]
            timestamp: Option<String>,
        }
        #[derive(Serialize, Deserialize, Clone, Default)]
        struct AnrFilesSummary {
            #[serde(default)]
            files: Vec<AnrFileEntry>,
            #[serde(default)]
            total_size: Option<u64>,
        }
        #[derive(Serialize, Deserialize, Clone, Default)]
        struct CrashInfoSummary {
            #[serde(default)]
            anr_files: Option<AnrFilesSummary>,
            #[serde(default)]
            anr_trace: Option<AnrTraceSummary>,
            // Tombstones is an array of tombstone objects (preserved as Value since structure may vary)
            #[serde(default)]
            tombstones: Option<Vec<serde_json::Value>>,
        }

        // Try to parse as ANR/crash JSON first (in case the input is a JSON file from crash tools)
        let mut crash_info: Option<CrashInfoSummary> = parse_anr_crash_json(file_content.as_ref())
            .and_then(|v| serde_json::from_value::<CrashInfoSummary>(v).ok());
        
        // Run parsers concurrently
        log::info!("🚀 [ANALYZE] Running {} parsers concurrently...", parsers_to_run.len());
        let results = run_parsers_concurrently(file_content, parsers_to_run);

        log::info!("⏱️ [ANALYZE] Parsers completed");


        #[derive(Serialize)]
        struct SigmaMatchSummary {
            rule_id: Option<String>,
            rule_title: String,
            level: Option<String>,
            matched_log: serde_json::Value,
        }

        // Run Sigma rule evaluation if rules were provided
        let sigma_matches: Option<Vec<SigmaMatchSummary>> = if rules.trim().is_empty() {
            log::info!("📋 [ANALYZE] No Sigma rules provided, skipping rule evaluation");
            None
        } else {
            log::info!("📋 [ANALYZE] Loading Sigma rules and evaluating log entries...");
            let mut all_rules: Vec<SigmaRule> = Vec::new();
            for part in rules.split("\n---\n") {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Ok(r) = serde_yaml::from_str::<SigmaRule>(part) {
                    all_rules.push(r);
                } else if let Ok(v) = serde_yaml::from_str::<Vec<SigmaRule>>(part) {
                    all_rules.extend(v);
                } else {
                    log::warn!("  ⚠️ [ANALYZE] Failed to parse a Sigma rule YAML document, skipping");
                }
            }
            if all_rules.is_empty() {
                log::warn!("  ⚠️ [ANALYZE] No valid Sigma rules loaded");
                None
            } else {
                log::info!("  ✅ [ANALYZE] Loaded {} Sigma rules", all_rules.len());
                let mut engine = SigmaEngine::new(None);
                engine.rules = all_rules.into_iter().map(Arc::new).collect();
                let all_entries = extract_all_log_entries(&results);
                let total_entries: usize = all_entries.iter().map(|t| t.1.len()).sum();
                log::info!("  📊 [ANALYZE] Evaluating {} log entries from {} parsers", total_entries, all_entries.len());
                let mut matches_vec: Vec<SigmaMatchSummary> = Vec::new();
                for (parser_type, log_entries) in all_entries {
                    for log in log_entries {
                        for rule_match in engine.evaluate_log_entry(&log) {
                            // Build matched_log from log.fields to avoid LogEntry/serde roundtrip;
                            // log.fields is the HashMap that was populated by extract_all_log_entries.
                            let mut map = log.fields.clone();
                            map.insert("source".to_string(), serde_json::Value::String(format!("{:?}", parser_type)));
                            let matched_log = serde_json::to_value(&map).unwrap_or_else(|e| {
                                log::warn!("[ANALYZE] Sigma matched_log from fields failed: {}", e);
                                serde_json::json!({"source": format!("{:?}", parser_type), "_error": "from_fields_failed"})
                            });
                            matches_vec.push(SigmaMatchSummary {
                                rule_id: rule_match.rule_id.clone(),
                                rule_title: rule_match.rule_title.clone(),
                                level: rule_match.level.clone(),
                                matched_log,
                            });
                        }
                    }
                }
                log::info!("  ✅ [ANALYZE] Sigma evaluation complete: {} matches", matches_vec.len());
                Some(matches_vec)
            }
        };

        // Define summary structures
        #[derive(Serialize)]
        struct BugreportSummary {
            device_info: Option<DeviceInfoSummary>,
            battery_info: Option<BatteryInfoSummary>,
            process_count: usize,
            package_count: usize,
            has_security_analysis: bool,
            analysis_complete: bool,
            sigma_matches: Option<Vec<SigmaMatchSummary>>,
            packages: Vec<PackageInstallationInfo>,
            processes: Vec<ProcessInfo>,
            battery_apps: Vec<BatteryAppInfo>,
            package_details: Vec<PackageDetails>,
            power_history: Vec<PowerHistory>,
            network_info: Vec<NetworkInfo>,
            network_stats: Vec<NetworkStats>,
            sockets: Vec<SocketInfo>,
            bluetooth_info: Option<BluetoothInfo>,
            usb_info: Option<UsbInfo>,
            crash_info: Option<CrashInfoSummary>,
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
            stopped: Option<bool>,
            suspended: Option<bool>,
            hidden: Option<bool>,
            install_reason: Option<u32>,
            permissions: Option<serde_json::Value>,
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
            data_dir: Option<String>,
            flags: Option<String>,
            pkg_flags: Option<String>,
            private_flags: Option<String>,
            primary_cpu_abi: Option<String>,
            installer_package_name: Option<String>,
            initiating_package_name: Option<String>,
            originating_package_name: Option<String>,
            last_update_time: Option<String>,
            time_stamp: Option<String>,
            category: Option<String>,
            signatures: Option<String>,
            apk_signing_version: Option<String>,
            package_source: Option<String>,
            permissions: Option<serde_json::Value>,
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
        
        #[derive(Serialize, Clone)]
        struct NetworkInfo {
            interface_name: Option<String>,
            ip_address: Option<String>,
            mac_address: Option<String>,
            state: Option<String>,
            rx_bytes: Option<u64>,
            tx_bytes: Option<u64>,
            rx_packets: Option<u64>,
            tx_packets: Option<u64>,
            mtu: Option<u32>,
        }
        
        #[derive(Serialize, Clone)]
        struct NetworkStats {
            network_type: Option<String>,
            wifi_network_name: Option<String>,
            rx_bytes: Option<u64>,
            tx_bytes: Option<u64>,
            rx_packets: Option<u64>,
            tx_packets: Option<u64>,
            default_network: Option<bool>,
            metered: Option<bool>,
            rat_type: Option<String>,
            subscriber_id: Option<String>,
        }
        
        #[derive(Serialize, Clone)]
        struct SocketInfo {
            protocol: Option<String>,
            local_address: Option<String>,
            local_ip: Option<String>,
            local_port: Option<u16>,
            remote_address: Option<String>,
            remote_ip: Option<String>,
            remote_port: Option<u16>,
            state: Option<String>,
            uid: Option<u32>,
            inode: Option<u64>,
            recv_q: Option<u64>,
            send_q: Option<u64>,
            socket_key: Option<String>,
            additional_info: Option<String>,
        }
        
        #[derive(Serialize, Clone)]
        struct AdapterProperties {
            a2dp_offload_enabled: Option<bool>,
            address: Option<String>,
            connection_state: Option<String>,
            discovering: Option<bool>,
            discovery_end_ms: Option<u64>,
            max_connected_audio_devices: Option<u32>,
            name: Option<String>,
            sar_history: Option<String>,
            sar_status: Option<String>,
            sar_type: Option<String>,
            state: Option<String>,
        }
        
        #[derive(Serialize, Clone)]
        struct BluetoothDevice {
            connected: Option<bool>,
            device_class: Option<String>,
            device_type: Option<u32>,
            identity_address: Option<String>,
            link_type: Option<u32>,
            mac_address: Option<String>,
            manufacturer: Option<u32>,
            masked_address: Option<String>,
            name: Option<String>,
            services: Vec<String>,
            transport_type: Option<String>,
        }
        
        #[derive(Serialize, Clone)]
        struct BluetoothInfo {
            adapter_properties: Option<AdapterProperties>,
            devices: Vec<BluetoothDevice>,
        }
        
        #[derive(Serialize, Clone)]
        struct UsbEvent {
            action: Option<String>,
            driver: Option<String>,
            interface: Option<String>,
            raw_line: Option<String>,
            timestamp: Option<String>,
        }
        
        #[derive(Serialize, Clone)]
        struct ConnectedDevice {
            driver: Option<String>,
            events: Vec<UsbEvent>,
            first_seen: Option<String>,
            interface: Option<String>,
            last_action: Option<String>,
            last_seen: Option<String>,
            pid: Option<String>,
            vid: Option<String>,
        }
        
        #[derive(Serialize, Clone)]
        struct UsbPort {
            connected: Option<bool>,
            current_mode: Option<String>,
            first_seen: Option<String>,
            id: Option<String>,
            last_state_change: Option<String>,
        }
        
        #[derive(Serialize, Clone)]
        struct UsbInfo {
            connected_devices: Vec<ConnectedDevice>,
            ports: Vec<UsbPort>,
        }
        
        // Extract data from results
        log::info!("📤 [ANALYZE] Extracting data from parser results...");
        let mut device_info = None;
        let battery_info = None;
        let mut process_count = 0;
        let mut packages = Vec::new();
        let mut processes: Vec<ProcessInfo> = Vec::new();
        let mut battery_apps: Vec<BatteryAppInfo> = Vec::new();
        let mut package_details: Vec<PackageDetails> = Vec::new();
        let mut power_history: Vec<PowerHistory> = Vec::new();
        let mut network_info: Vec<NetworkInfo> = Vec::new();
        let mut network_stats: Vec<NetworkStats> = Vec::new();
        let mut sockets: Vec<SocketInfo> = Vec::new();
        let mut bluetooth_info: Option<BluetoothInfo> = None;
        let mut usb_info: Option<UsbInfo> = None;
        
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
                                            
                                            let data_dir = pkg_obj.get("dataDir")
                                                .and_then(|v| v.as_str())
                                                .filter(|s| s != &"null")
                                                .map(|s| s.to_string());
                                            
                                            let flags = pkg_obj.get("flags")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let pkg_flags = pkg_obj.get("pkgFlags")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let private_flags = pkg_obj.get("privateFlags")
                                                .or_else(|| pkg_obj.get("privatePkgFlags"))
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
                                            
                                            let initiating_package_name = pkg_obj.get("initiatingPackageName")
                                                .and_then(|v| v.as_str())
                                                .filter(|s| s != &"null")
                                                .map(|s| s.to_string());
                                            
                                            let originating_package_name = pkg_obj.get("originatingPackageName")
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
                                            
                                            let signatures = pkg_obj.get("signatures")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let apk_signing_version = pkg_obj.get("apkSigningVersion")
                                                .and_then(|v| {
                                                    v.as_str().map(|s| s.to_string())
                                                        .or_else(|| v.as_u64().map(|n| n.to_string()))
                                                });
                                            
                                            let package_source = pkg_obj.get("packageSource")
                                                .and_then(|v| {
                                                    v.as_str().map(|s| s.to_string())
                                                        .or_else(|| v.as_u64().map(|n| n.to_string()))
                                                });
                                            
                                            // Extract package-level permissions
                                            let permissions = pkg_obj.get("permissions").cloned();
                                            
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
                                                        
                                                        let stopped = user_obj.get("stopped")
                                                            .and_then(|v| v.as_bool());
                                                        
                                                        let suspended = user_obj.get("suspended")
                                                            .and_then(|v| v.as_bool());
                                                        
                                                        let hidden = user_obj.get("hidden")
                                                            .and_then(|v| v.as_bool());
                                                        
                                                        let install_reason = user_obj.get("installReason")
                                                            .and_then(|v| v.as_u64())
                                                            .map(|v| v as u32);
                                                        
                                                        let permissions = user_obj.get("permissions").cloned();
                                                        
                                                        users_info.push(PackageUserInfo {
                                                            user_id,
                                                            first_install_time,
                                                            last_disabled_caller,
                                                            data_dir,
                                                            enabled,
                                                            installed,
                                                            stopped,
                                                            suspended,
                                                            hidden,
                                                            install_reason,
                                                            permissions,
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
                                                data_dir,
                                                flags,
                                                pkg_flags,
                                                private_flags,
                                                primary_cpu_abi,
                                                installer_package_name,
                                                initiating_package_name,
                                                originating_package_name,
                                                last_update_time,
                                                time_stamp,
                                                category,
                                                signatures,
                                                apk_signing_version,
                                                package_source,
                                                permissions,
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
                                parsed_packages = parse_packages_array(obj).is_some();
                                // Also try to parse install_logs for backward compatibility
                                let _ = parse_install_logs_from_obj(obj);
                                if !parsed_packages {
                                    log::warn!("    ⚠️ [ANALYZE] No packages array found in object");
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
                                        if parse_install_logs_from_obj(obj).is_some() {
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
                        ParserType::Network => {
                            log::info!("    🌐 [ANALYZE] Extracting network info...");
                            // NetworkParser returns an object with "interfaces", "network_stats", and "sockets" keys
                            if let Some(obj) = json_output.as_object() {
                                log::info!("    📊 [ANALYZE] Network result is an object with keys: {:?}", obj.keys().collect::<Vec<_>>());
                                
                                // Parse interfaces array
                                if let Some(interfaces_arr) = obj.get("interfaces").and_then(|v| v.as_array()) {
                                    log::info!("    📊 [ANALYZE] Found {} network interfaces", interfaces_arr.len());
                                    
                                    for net_json in interfaces_arr {
                                        if let Some(net_obj) = net_json.as_object() {
                                            let interface_name = net_obj.get("name")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            // Extract IP addresses from ip_addresses array
                                            let ip_address = net_obj.get("ip_addresses")
                                                .and_then(|v| v.as_array())
                                                .and_then(|arr| {
                                                    if arr.is_empty() {
                                                        None
                                                    } else {
                                                        // Get first IP address, or join all if multiple
                                                        arr.first()
                                                            .and_then(|v| v.as_str())
                                                            .map(|s| s.to_string())
                                                    }
                                                });
                                            
                                            // Extract state from flags array
                                            let state = net_obj.get("flags")
                                                .and_then(|v| v.as_array())
                                                .map(|flags_arr| {
                                                    flags_arr.iter()
                                                        .filter_map(|f| f.as_str())
                                                        .collect::<Vec<_>>()
                                                        .join(", ")
                                                });
                                            
                                            let rx_bytes = net_obj.get("rx_bytes")
                                                .and_then(|v| v.as_u64());
                                            
                                            let tx_bytes = net_obj.get("tx_bytes")
                                                .and_then(|v| v.as_u64());
                                            
                                            // Note: rx_packets and tx_packets are not in the interface data
                                            // They might be in network_stats instead
                                            
                                            let mtu = net_obj.get("mtu")
                                                .and_then(|v| v.as_u64())
                                                .map(|v| v as u32);
                                            
                                            network_info.push(NetworkInfo {
                                                interface_name,
                                                ip_address,
                                                mac_address: None, // Not in the interface data
                                                state,
                                                rx_bytes,
                                                tx_bytes,
                                                rx_packets: None, // Not in interface data
                                                tx_packets: None, // Not in interface data
                                                mtu,
                                            });
                                        }
                                    }
                                    
                                    log::info!("    ✅ [ANALYZE] Parsed {} network interfaces", network_info.len());
                                } else {
                                    log::warn!("    ⚠️ [ANALYZE] No 'interfaces' array found in network data");
                                }
                                
                                // Parse network_stats array
                                if let Some(stats_arr) = obj.get("network_stats").and_then(|v| v.as_array()) {
                                    log::info!("    📊 [ANALYZE] Found {} network stats entries", stats_arr.len());
                                    
                                    for stat_json in stats_arr {
                                        if let Some(stat_obj) = stat_json.as_object() {
                                            let network_type = stat_obj.get("network_type")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let wifi_network_name = stat_obj.get("wifi_network_name")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let rx_bytes = stat_obj.get("rx_bytes")
                                                .and_then(|v| v.as_u64());
                                            
                                            let tx_bytes = stat_obj.get("tx_bytes")
                                                .and_then(|v| v.as_u64());
                                            
                                            let rx_packets = stat_obj.get("rx_packets")
                                                .and_then(|v| v.as_u64());
                                            
                                            let tx_packets = stat_obj.get("tx_packets")
                                                .and_then(|v| v.as_u64());
                                            
                                            let default_network = stat_obj.get("default_network")
                                                .and_then(|v| v.as_bool());
                                            
                                            let metered = stat_obj.get("metered")
                                                .and_then(|v| v.as_bool());
                                            
                                            let rat_type = stat_obj.get("rat_type")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let subscriber_id = stat_obj.get("subscriber_id")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            network_stats.push(NetworkStats {
                                                network_type,
                                                wifi_network_name,
                                                rx_bytes,
                                                tx_bytes,
                                                rx_packets,
                                                tx_packets,
                                                default_network,
                                                metered,
                                                rat_type,
                                                subscriber_id,
                                            });
                                        }
                                    }
                                    
                                    log::info!("    ✅ [ANALYZE] Parsed {} network stats entries", network_stats.len());
                                } else {
                                    log::warn!("    ⚠️ [ANALYZE] No 'network_stats' array found in network data");
                                }
                                
                                // Parse sockets array
                                if let Some(sockets_arr) = obj.get("sockets").and_then(|v| v.as_array()) {
                                    log::info!("    📊 [ANALYZE] Found {} socket entries", sockets_arr.len());
                                    
                                    for socket_json in sockets_arr {
                                        if let Some(socket_obj) = socket_json.as_object() {
                                            let protocol = socket_obj.get("protocol")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let local_address = socket_obj.get("local_address")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let local_ip = socket_obj.get("local_ip")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let local_port = socket_obj.get("local_port")
                                                .and_then(|v| v.as_u64())
                                                .map(|v| v as u16);
                                            
                                            let remote_address = socket_obj.get("remote_address")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let remote_ip = socket_obj.get("remote_ip")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let remote_port = socket_obj.get("remote_port")
                                                .and_then(|v| v.as_u64())
                                                .map(|v| v as u16);
                                            
                                            let state = socket_obj.get("state")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let uid = socket_obj.get("uid")
                                                .and_then(|v| v.as_u64())
                                                .map(|v| v as u32);
                                            
                                            let inode = socket_obj.get("inode")
                                                .and_then(|v| v.as_u64());
                                            
                                            let recv_q = socket_obj.get("recv_q")
                                                .and_then(|v| v.as_u64());
                                            
                                            let send_q = socket_obj.get("send_q")
                                                .and_then(|v| v.as_u64());
                                            
                                            let socket_key = socket_obj.get("socket_key")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            let additional_info = socket_obj.get("additional_info")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                            
                                            sockets.push(SocketInfo {
                                                protocol,
                                                local_address,
                                                local_ip,
                                                local_port,
                                                remote_address,
                                                remote_ip,
                                                remote_port,
                                                state,
                                                uid,
                                                inode,
                                                recv_q,
                                                send_q,
                                                socket_key,
                                                additional_info,
                                            });
                                        }
                                    }
                                    
                                    log::info!("    ✅ [ANALYZE] Parsed {} socket entries", sockets.len());
                                } else {
                                    log::warn!("    ⚠️ [ANALYZE] No 'sockets' array found in network data");
                                }
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Network result is not an object");
                            }
                        },
                        ParserType::Bluetooth => {
                            log::info!("    📶 [ANALYZE] Extracting Bluetooth info...");
                            if let Some(obj) = json_output.as_object() {
                                log::info!("    📊 [ANALYZE] Bluetooth result is an object with keys: {:?}", obj.keys().collect::<Vec<_>>());
                                
                                let mut adapter_properties: Option<AdapterProperties> = None;
                                let mut devices: Vec<BluetoothDevice> = Vec::new();
                                
                                // Parse adapter_properties
                                if let Some(adapter_obj) = obj.get("adapter_properties").and_then(|v| v.as_object()) {
                                    log::info!("    📊 [ANALYZE] Found adapter_properties");
                                    
                                    adapter_properties = Some(AdapterProperties {
                                        a2dp_offload_enabled: adapter_obj.get("A2dpOffloadEnabled").and_then(|v| v.as_bool()),
                                        address: adapter_obj.get("Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        connection_state: adapter_obj.get("ConnectionState").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        discovering: adapter_obj.get("Discovering").and_then(|v| v.as_bool()),
                                        discovery_end_ms: adapter_obj.get("DiscoveryEndMs").and_then(|v| v.as_u64()),
                                        max_connected_audio_devices: adapter_obj.get("MaxConnectedAudioDevices").and_then(|v| v.as_u64()).map(|v| v as u32),
                                        name: adapter_obj.get("Name").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        sar_history: adapter_obj.get("SarHistory").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        sar_status: adapter_obj.get("SarStatus").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        sar_type: adapter_obj.get("SarType").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        state: adapter_obj.get("State").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                    });
                                    
                                    log::info!("    ✅ [ANALYZE] Parsed adapter properties");
                                } else {
                                    log::warn!("    ⚠️ [ANALYZE] No 'adapter_properties' found in Bluetooth data");
                                }
                                
                                // Parse devices array
                                if let Some(devices_arr) = obj.get("devices").and_then(|v| v.as_array()) {
                                    log::info!("    📊 [ANALYZE] Found {} Bluetooth devices", devices_arr.len());
                                    
                                    for device_json in devices_arr {
                                        if let Some(device_obj) = device_json.as_object() {
                                            let services = device_obj.get("services")
                                                .and_then(|v| v.as_array())
                                                .map(|arr| {
                                                    arr.iter()
                                                        .filter_map(|s| s.as_str().map(|s| s.to_string()))
                                                        .collect()
                                                })
                                                .unwrap_or_default();
                                            
                                            let device_class = device_obj.get("device_class")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string())
                                                .or_else(|| {
                                                    device_obj.get("device_class")
                                                        .and_then(|v| v.as_u64())
                                                        .map(|v| format!("0x{:06x}", v))
                                                });
                                            
                                            devices.push(BluetoothDevice {
                                                connected: device_obj.get("connected").and_then(|v| v.as_bool()),
                                                device_class,
                                                device_type: device_obj.get("device_type").and_then(|v| v.as_u64()).map(|v| v as u32),
                                                identity_address: device_obj.get("identity_address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                link_type: device_obj.get("link_type").and_then(|v| v.as_u64()).map(|v| v as u32),
                                                mac_address: device_obj.get("mac_address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                manufacturer: device_obj.get("manufacturer").and_then(|v| v.as_u64()).map(|v| v as u32),
                                                masked_address: device_obj.get("masked_address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                name: device_obj.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                services,
                                                transport_type: device_obj.get("transport_type").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                            });
                                        }
                                    }
                                    
                                    log::info!("    ✅ [ANALYZE] Parsed {} Bluetooth devices", devices.len());
                                } else {
                                    log::warn!("    ⚠️ [ANALYZE] No 'devices' array found in Bluetooth data");
                                }
                                
                                bluetooth_info = Some(BluetoothInfo {
                                    adapter_properties,
                                    devices,
                                });
                                
                                log::info!("    ✅ [ANALYZE] Bluetooth info extracted successfully");
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] Bluetooth result is not an object");
                            }
                        },
                        ParserType::Crash => {
                            if crash_info.is_none() {
                                crash_info = serde_json::from_value::<CrashInfoSummary>(json_output).ok();
                            }
                        },
                        ParserType::Usb => {
                            log::info!("    🔌 [ANALYZE] Extracting USB info...");
                            if let Some(arr) = json_output.as_array() {
                                log::info!("    📊 [ANALYZE] USB array has {} entries", arr.len());
                                
                                let mut all_connected_devices = Vec::new();
                                let mut all_ports = Vec::new();
                                
                                for entry_json in arr {
                                    if let Some(entry_obj) = entry_json.as_object() {
                                        // Extract connected_devices
                                        if let Some(devices_arr) = entry_obj.get("connected_devices").and_then(|v| v.as_array()) {
                                            for device_json in devices_arr {
                                                if let Some(device_obj) = device_json.as_object() {
                                                    let mut events = Vec::new();
                                                    if let Some(events_arr) = device_obj.get("events").and_then(|v| v.as_array()) {
                                                        for event_json in events_arr {
                                                            if let Some(event_obj) = event_json.as_object() {
                                                                events.push(UsbEvent {
                                                                    action: event_obj.get("action").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                                    driver: event_obj.get("driver").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                                    interface: event_obj.get("interface").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                                    raw_line: event_obj.get("raw_line").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                                    timestamp: event_obj.get("timestamp").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                                });
                                                            }
                                                        }
                                                    }
                                                    
                                                    all_connected_devices.push(ConnectedDevice {
                                                        driver: device_obj.get("driver").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                        events,
                                                        first_seen: device_obj.get("first_seen").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                        interface: device_obj.get("interface").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                        last_action: device_obj.get("last_action").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                        last_seen: device_obj.get("last_seen").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                        pid: device_obj.get("pid").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                        vid: device_obj.get("vid").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                    });
                                                }
                                            }
                                        }
                                        
                                        // Extract ports
                                        if let Some(ports_arr) = entry_obj.get("ports").and_then(|v| v.as_array()) {
                                            for port_json in ports_arr {
                                                if let Some(port_obj) = port_json.as_object() {
                                                    all_ports.push(UsbPort {
                                                        connected: port_obj.get("connected").and_then(|v| v.as_bool()),
                                                        current_mode: port_obj.get("current_mode").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                        first_seen: port_obj.get("first_seen").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                        id: port_obj.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                        last_state_change: port_obj.get("last_state_change").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                usb_info = Some(UsbInfo {
                                    connected_devices: all_connected_devices,
                                    ports: all_ports,
                                });
                                
                                log::info!("    ✅ [ANALYZE] USB info extracted: {} devices, {} ports", 
                                    usb_info.as_ref().map(|u| u.connected_devices.len()).unwrap_or(0),
                                    usb_info.as_ref().map(|u| u.ports.len()).unwrap_or(0));
                            } else {
                                log::warn!("    ⚠️ [ANALYZE] USB result is not an array");
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
        
        // Calculate unique package count by combining both package_details and packages
        // This ensures we count all unique packages regardless of which source has the data
        let unique_package_count = {
            let mut unique_packages = std::collections::HashSet::new();
            // Add packages from package_details (installed packages)
            for pkg_detail in &package_details {
                unique_packages.insert(pkg_detail.package_name.clone());
            }
            // Also add packages from installation history (packages array)
            // This ensures we count all unique packages even if package_details is incomplete
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
            sigma_matches,
            packages: packages.clone(),
            processes: processes.clone(),
            battery_apps: battery_apps.clone(),
            package_details: package_details.clone(),
            power_history: power_history.clone(),
            network_info: network_info.clone(),
            network_stats: network_stats.clone(),
            sockets: sockets.clone(),
            bluetooth_info: bluetooth_info.clone(),
            usb_info: usb_info.clone(),
            crash_info: crash_info.clone(),
        };
        
        log::info!("✅ [ANALYZE] Analysis complete!");
        log::info!("📱 [ANALYZE] Device: {:?}", device_info.as_ref().map(|d| format!("{} {}", d.manufacturer, d.model)));
        log::info!("🔋 [ANALYZE] Battery: {:?}", battery_info.as_ref().map(|b| format!("{}%", b.level)));
        log::info!("⚙️ [ANALYZE] Processes: {}", process_count);
        log::info!("📦 [ANALYZE] Unique packages: {} ({} total installations)", unique_package_count, packages.len());
        log::info!("⚡ [ANALYZE] Power history events: {}", power_history.len());
        log::info!("🌐 [ANALYZE] Network interfaces: {}", network_info.len());
        log::info!("📊 [ANALYZE] Network stats: {}", network_stats.len());
        log::info!("🔌 [ANALYZE] Sockets: {}", sockets.len());
        if let Some(ref bt_info) = bluetooth_info {
            log::info!("📶 [ANALYZE] Bluetooth devices: {}", bt_info.devices.len());
        }
        if let Some(ref usb_info) = usb_info {
            log::info!("🔌 [ANALYZE] USB devices: {}, ports: {}", usb_info.connected_devices.len(), usb_info.ports.len());
        }
        
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
    /// Downloads the bugreport and analyzes it in one step.
    /// `rules` is YAML string of Sigma rules (can be concatenated with "\n---\n" as document separator).
    #[wasm_bindgen]
    #[cfg(feature = "bugreport-analysis")]
    pub async fn analyze_bugreport_from_device(&mut self, path: String, rules: String) -> Result<JsValue, JsValue> {
        log::info!("Downloading and analyzing bugreport from: {}", path);

        // Download the bugreport
        let data = self.download_bugreport(path).await?;

        // Convert Uint8Array to Vec<u8>
        let vec = js_sys::Uint8Array::new(&data).to_vec();

        // Analyze it
        self.analyze_bugreport(vec, rules).await
    }

    /// Get full bugreport data as JSON for inspection
    #[wasm_bindgen]
    #[cfg(feature = "bugreport-analysis")]
    pub async fn get_bugreport_full_data(&self, data: Vec<u8>) -> Result<JsValue, JsValue> {
        use bugreport_extractor_library::run_parsers_concurrently;
        use bugreport_extractor_library::parsers::{
            Parser as DataParser, ParserType, HeaderParser, BatteryParser, 
            PackageParser, ProcessParser, PowerParser, UsbParser, NetworkParser
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
        if let Ok(p) = NetworkParser::new() { parsers_to_run.push((ParserType::Network, Box::new(p))); }
        
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

/// Manual extraction of dumpstate from ZIP (fallback when library function fails)
#[allow(dead_code)] // Used conditionally in error handler
fn manual_extract_dumpstate(zip_data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::{Cursor, Read};
    use std::path::Path;
    
    let cursor = Cursor::new(zip_data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| format!("Failed to open ZIP archive: {}", e))?;
    
    // Collect all files whose filename starts with "dumpstate"
    let mut candidates: Vec<(String, u64)> = Vec::new();
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            let full_path = file.name().to_string();
            
            // Skip directories
            if full_path.ends_with('/') {
                continue;
            }
            
            // Get just the filename (not the path)
            let path = Path::new(&full_path);
            let file_name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            let file_name_lower = file_name.to_lowercase();
            
            // ONLY match files whose filename starts with "dumpstate"
            if file_name_lower.starts_with("dumpstate") {
                let size = file.size();
                if size > 1000 {  // Only consider files larger than 1KB
                    let full_path_clone = full_path.clone();
                    candidates.push((full_path, size));
                    log::info!("🔍 [MANUAL EXTRACT] Found dumpstate candidate: {} ({} bytes)", full_path_clone, size);
                }
            }
        }
    }
    
    if candidates.is_empty() {
        return Err("No file found with filename starting with 'dumpstate'".to_string());
    }
    
    // Sort by size (largest first) - prefer larger dumpstate files
    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    
    log::info!("🔍 [MANUAL EXTRACT] Found {} dumpstate file(s), trying largest first", candidates.len());
    
    // Try the largest file first (most likely to be the main dumpstate)
    for (name, size) in candidates.iter() {
        log::info!("🔍 [MANUAL EXTRACT] Trying: {} ({} bytes)", name, size);
        if let Ok(mut file) = archive.by_name(name) {
            let mut contents = Vec::new();
            if file.read_to_end(&mut contents).is_ok() && !contents.is_empty() {
                log::info!("✅ [MANUAL EXTRACT] Successfully extracted: {}", name);
                return Ok(contents);
            }
        }
    }
    
    Err("Found dumpstate files but failed to extract them".to_string())
}
