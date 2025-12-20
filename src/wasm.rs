use wasm_bindgen::prelude::*;
use crate::auth::{AdbKeyPair, storage};
use crate::client::AdbClient;
use crate::transport::WebUsbTransport;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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