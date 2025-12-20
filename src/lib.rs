//! Rust WebADB - ADB (Android Debug Bridge) implementation for WebUSB in Rust
//!
//! This library provides a WebAssembly-compatible implementation of the Android Debug Bridge
//! protocol, allowing web applications to communicate with Android devices via WebUSB.
//!
//! # Example
//!
//! ```javascript
//! import init, { Adb } from './pkg/rust_webadb.js';
//!
//! async function main() {
//!     await init();
//!     
//!     const adb = new Adb();
//!     
//!     // Connect to device (will prompt user to select device)
//!     const deviceInfo = await adb.connect();
//!     console.log('Connected to:', deviceInfo);
//!     
//!     // Execute shell command
//!     const output = await adb.shell('ls /sdcard');
//!     console.log('Output:', output);
//!     
//!     // Get device properties
//!     const props = await adb.get_properties();
//!     console.log('Properties:', props);
//!     
//!     // Disconnect
//!     await adb.disconnect();
//! }
//! ```

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod auth;
pub mod client;
pub mod protocol;
pub mod sync;
pub mod transport;
pub mod wasm;

// Re-export main types
pub use auth::AdbKeyPair;
pub use client::AdbClient;
pub use protocol::{AdbError, Command, ConnectionState, Message};
pub use transport::{WebUsbTransport, DeviceInfo};
pub use wasm::Adb;