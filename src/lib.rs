//! Rust WebADB - ADB (Android Debug Bridge) implementation for WebUSB in Rust
//!
//! This library provides a WebAssembly-compatible implementation of the Android Debug Bridge
//! protocol, allowing web applications to communicate with Android devices via WebUSB.

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