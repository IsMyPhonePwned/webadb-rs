use super::protocol::{AdbError, Message};

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    UsbDevice, UsbDeviceFilter, UsbDeviceRequestOptions, UsbDirection,
    UsbInTransferResult, UsbOutTransferResult, UsbTransferStatus,
};

/// ADB USB interface class/subclass/protocol
const ADB_CLASS: u8 = 0xff;
const ADB_SUBCLASS: u8 = 0x42;
const ADB_PROTOCOL: u8 = 0x01;

/// WebUSB transport for ADB
pub struct WebUsbTransport {
    device: UsbDevice,
    endpoint_in: u8,
    endpoint_out: u8,
    interface_number: u8,
}

impl WebUsbTransport {
    /// Request device access from user
    pub async fn request_device() -> Result<Self, AdbError> {
        let window = web_sys::window()
            .ok_or_else(|| AdbError::UsbError("No window object".to_string()))?;
        
        let navigator = window.navigator();
        let usb = navigator.usb(); // Returns Usb directly, not Result

        // Create device filter for ADB devices
        let filter = UsbDeviceFilter::new();
        filter.set_class_code(ADB_CLASS);
        filter.set_subclass_code(ADB_SUBCLASS);
        filter.set_protocol_code(ADB_PROTOCOL);

        let filters = js_sys::Array::new();
        filters.push(&filter);

        let options = UsbDeviceRequestOptions::new(&filters);

        // Request device from user
        let promise = usb.request_device(&options);
        let device = JsFuture::from(promise)
            .await
            .map_err(|e| AdbError::UsbError(format!("Failed to request device: {:?}", e)))?;

        let device: UsbDevice = device
            .dyn_into()
            .map_err(|_| AdbError::UsbError("Invalid device type".to_string()))?;

        Self::open(device).await
    }

    /// Open an existing device
    pub async fn open(device: UsbDevice) -> Result<Self, AdbError> {
        // Open the device
        let promise = device.open();
        
        JsFuture::from(promise)
            .await
            .map_err(|e| AdbError::UsbError(format!("Failed to open device: {:?}", e)))?;

        // Find ADB interface and endpoints
        let configuration = device.configuration()
            .ok_or_else(|| AdbError::UsbError("No configuration available".to_string()))?;

        let interfaces = configuration.interfaces();
        let mut adb_interface = None;
        let mut endpoint_in = None;
        let mut endpoint_out = None;

        for i in 0..interfaces.length() {
            let interface: web_sys::UsbInterface = interfaces.get(i).dyn_into()
                .map_err(|_| AdbError::UsbError("Failed to get interface".to_string()))?;

            for j in 0..interface.alternates().length() {
                let alternate: web_sys::UsbAlternateInterface = interface.alternates().get(j).dyn_into()
                    .map_err(|_| AdbError::UsbError("Failed to get alternate".to_string()))?;

                if alternate.interface_class() == ADB_CLASS
                    && alternate.interface_subclass() == ADB_SUBCLASS
                    && alternate.interface_protocol() == ADB_PROTOCOL
                {
                    adb_interface = Some(interface.interface_number());

                    // Find endpoints
                    let endpoints = alternate.endpoints();
                    for k in 0..endpoints.length() {
                        let endpoint: web_sys::UsbEndpoint = endpoints.get(k).dyn_into()
                            .map_err(|_| AdbError::UsbError("Failed to get endpoint".to_string()))?;

                        match endpoint.direction() {
                            UsbDirection::In => {
                                endpoint_in = Some(endpoint.endpoint_number());
                            }
                            UsbDirection::Out => {
                                endpoint_out = Some(endpoint.endpoint_number());
                            }
                            _ => {}
                        }
                    }
                    break;
                }
            }

            if adb_interface.is_some() {
                break;
            }
        }

        let interface_number = adb_interface
            .ok_or_else(|| AdbError::UsbError("ADB interface not found".to_string()))?;
        let endpoint_in = endpoint_in
            .ok_or_else(|| AdbError::UsbError("IN endpoint not found".to_string()))?;
        let endpoint_out = endpoint_out
            .ok_or_else(|| AdbError::UsbError("OUT endpoint not found".to_string()))?;

        // Try to release interface first in case it's already claimed
        // This is safe to do - if not claimed, it will just fail silently
        let release_promise = device.release_interface(interface_number);
        let _ = JsFuture::from(release_promise).await;
        // Ignore errors - interface might not be claimed yet

        // Claim the interface
        let promise = device.claim_interface(interface_number);
        
        JsFuture::from(promise)
            .await
            .map_err(|e| {
                let error_str = format!("{:?}", e);
                let error_msg = if error_str.contains("already claimed") || error_str.contains("claimInterface") {
                    format!(
                        "Failed to claim USB interface. The interface may be in use by another application. \
                        Please: 1) Close any other ADB tools (adb, Android Studio, etc.), \
                        2) Disconnect and reconnect your device, \
                        3) Refresh this page and try again. Error: {:?}", e
                    )
                } else {
                    format!("Failed to claim interface: {:?}", e)
                };
                AdbError::UsbError(error_msg)
            })?;

        Ok(Self {
            device,
            endpoint_in,
            endpoint_out,
            interface_number,
        })
    }

    /// Send raw data to device
    pub async fn write(&self, data: &[u8]) -> Result<(), AdbError> {
        let array = js_sys::Uint8Array::from(data);
        let promise = self.device.transfer_out_with_u8_array(self.endpoint_out, &array)
            .map_err(|e| AdbError::UsbError(format!("Failed to initiate transfer: {:?}", e)))?;
        
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| AdbError::UsbError(format!("Write failed: {:?}", e)))?;

        let result: UsbOutTransferResult = result
            .dyn_into()
            .map_err(|_| AdbError::UsbError("Invalid transfer result".to_string()))?;

        match result.status() {
            UsbTransferStatus::Ok => Ok(()),
            _ => Err(AdbError::UsbError(format!("Transfer status: {:?}", result.status()))),
        }
    }

    /// Read raw data from device
    pub async fn read(&self, length: u32) -> Result<Vec<u8>, AdbError> {
        let promise = self.device.transfer_in(self.endpoint_in, length);
        
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| AdbError::UsbError(format!("Read failed: {:?}", e)))?;

        let result: UsbInTransferResult = result
            .dyn_into()
            .map_err(|_| AdbError::UsbError("Invalid transfer result".to_string()))?;

        match result.status() {
            UsbTransferStatus::Ok => {
                let data = result.data()
                    .ok_or_else(|| AdbError::UsbError("No data in transfer".to_string()))?;
                
                Ok(js_sys::Uint8Array::new(&data.buffer()).to_vec())
            }
            _ => Err(AdbError::UsbError(format!("Transfer status: {:?}", result.status()))),
        }
    }

    /// Send an ADB message
    pub async fn send_message(&self, message: &Message, data: &[u8]) -> Result<(), AdbError> {
        // Send header
        let header = message.to_bytes();
        self.write(&header).await?;

        // Send data if present
        if !data.is_empty() {
            self.write(data).await?;
        }

        Ok(())
    }

    /// Receive an ADB message
    pub async fn recv_message(&self) -> Result<(Message, Vec<u8>), AdbError> {
        // Read header (24 bytes)
        let header_bytes = self.read(24).await?;
        let message = Message::from_bytes(&header_bytes)?;

        // Read data if present
        let data = if message.data_length > 0 {
            let data = self.read(message.data_length).await?;
            
            // Verify checksum
            if !message.verify_data(&data) {
                return Err(AdbError::InvalidMessage(
                    "Data checksum mismatch".to_string(),
                ));
            }
            
            data
        } else {
            Vec::new()
        };

        Ok((message, data))
    }

    /// Close the connection
    pub async fn close(&self) -> Result<(), AdbError> {
        // Try to release interface - ignore if device already disconnected
        let promise = self.device.release_interface(self.interface_number);
        
        if let Err(e) = JsFuture::from(promise).await {
            let error_str = format!("{:?}", e);
            // Ignore errors if device is already disconnected
            if !error_str.contains("NotFoundError") && !error_str.contains("disconnected") {
                return Err(AdbError::UsbError(format!("Failed to release interface: {:?}", e)));
            }
            // Device already disconnected, no need to release
        }

        // Try to close device - ignore if device already disconnected
        let promise = self.device.close();
        
        if let Err(e) = JsFuture::from(promise).await {
            let error_str = format!("{:?}", e);
            // Ignore errors if device is already disconnected
            if !error_str.contains("NotFoundError") && !error_str.contains("disconnected") {
                return Err(AdbError::UsbError(format!("Failed to close device: {:?}", e)));
            }
            // Device already disconnected, no need to close
        }

        Ok(())
    }

    /// Get device information
    pub fn device_info(&self) -> DeviceInfo {
        DeviceInfo {
            vendor_id: self.device.vendor_id(),
            product_id: self.device.product_id(),
            manufacturer_name: self.device.manufacturer_name(),
            product_name: self.device.product_name(),
            serial_number: self.device.serial_number(),
        }
    }
}

/// Device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer_name: Option<String>,
    pub product_name: Option<String>,
    pub serial_number: Option<String>,
}