use std::fmt;
use thiserror::Error;

/// ADB protocol version
pub const ADB_VERSION: u32 = 0x01000000;

/// Maximum data payload size
pub const MAX_PAYLOAD: u32 = 256 * 1024;

/// ADB command constants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Command {
    /// Synchronize
    Sync = 0x434e5953,
    /// Connect
    Cnxn = 0x4e584e43,
    /// Authentication
    Auth = 0x48545541,
    /// Open stream
    Open = 0x4e45504f,
    /// OK/Ready
    Okay = 0x59414b4f,
    /// Close stream
    Clse = 0x45534c43,
    /// Write data
    Wrte = 0x45545257,
}

impl Command {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x434e5953 => Some(Command::Sync),
            0x4e584e43 => Some(Command::Cnxn),
            0x48545541 => Some(Command::Auth),
            0x4e45504f => Some(Command::Open),
            0x59414b4f => Some(Command::Okay),
            0x45534c43 => Some(Command::Clse),
            0x45545257 => Some(Command::Wrte),
            _ => None,
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Sync => write!(f, "SYNC"),
            Command::Cnxn => write!(f, "CNXN"),
            Command::Auth => write!(f, "AUTH"),
            Command::Open => write!(f, "OPEN"),
            Command::Okay => write!(f, "OKAY"),
            Command::Clse => write!(f, "CLSE"),
            Command::Wrte => write!(f, "WRTE"),
        }
    }
}

/// Authentication types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthType {
    /// Token (challenge from device)
    Token = 1,
    /// Signature (response to challenge)
    Signature = 2,
    /// RSA public key
    RsaPublicKey = 3,
}

/// ADB message header (24 bytes)
#[derive(Debug, Clone)]
pub struct Message {
    pub command: Command,
    pub arg0: u32,
    pub arg1: u32,
    pub data_length: u32,
    pub data_crc32: u32,
    pub magic: u32,
}

impl Message {
    /// Create a new message
    pub fn new(command: Command, arg0: u32, arg1: u32, data: &[u8]) -> Self {
        let data_length = data.len() as u32;
        let data_crc32 = if data.is_empty() {
            0
        } else {
            checksum(data)
        };
        let magic = (command as u32) ^ 0xffffffff;

        Self {
            command,
            arg0,
            arg1,
            data_length,
            data_crc32,
            magic,
        }
    }

    /// Serialize message to bytes (little-endian)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&(self.command as u32).to_le_bytes());
        bytes.extend_from_slice(&self.arg0.to_le_bytes());
        bytes.extend_from_slice(&self.arg1.to_le_bytes());
        bytes.extend_from_slice(&self.data_length.to_le_bytes());
        bytes.extend_from_slice(&self.data_crc32.to_le_bytes());
        bytes.extend_from_slice(&self.magic.to_le_bytes());
        bytes
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdbError> {
        if bytes.len() < 24 {
            return Err(AdbError::InvalidMessage(
                "Message too short".to_string(),
            ));
        }

        let command = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let command = Command::from_u32(command)
            .ok_or_else(|| AdbError::InvalidMessage(format!("Unknown command: 0x{:08x}", command)))?;

        let arg0 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let arg1 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let data_length = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let data_crc32 = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let magic = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);

        // Verify magic
        if magic != (command as u32) ^ 0xffffffff {
            return Err(AdbError::InvalidMessage(
                "Magic checksum mismatch".to_string(),
            ));
        }

        Ok(Self {
            command,
            arg0,
            arg1,
            data_length,
            data_crc32,
            magic,
        })
    }

    /// Verify data checksum
    pub fn verify_data(&self, data: &[u8]) -> bool {
        if self.data_length as usize != data.len() {
            return false;
        }
        if data.is_empty() {
            return self.data_crc32 == 0;
        }
        checksum(data) == self.data_crc32
    }
}

/// Calculate CRC32 checksum for ADB protocol
pub fn checksum(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}

/// ADB connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Error,
}

/// Stream information
#[derive(Debug, Clone)]
pub struct Stream {
    pub local_id: u32,
    pub remote_id: u32,
}

/// ADB errors
#[derive(Error, Debug)]
pub enum AdbError {
    #[error("USB error: {0}")]
    UsbError(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Stream error: {0}")]
    StreamError(String),

    #[error("Timeout")]
    Timeout,

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Not connected")]
    NotConnected,
}

#[cfg(feature = "webusb")]
impl From<wasm_bindgen::JsValue> for AdbError {
    fn from(value: wasm_bindgen::JsValue) -> Self {
        AdbError::UsbError(format!("{:?}", value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_conversion() {
        assert_eq!(Command::from_u32(0x434e5953), Some(Command::Sync));
        assert_eq!(Command::from_u32(0x4e584e43), Some(Command::Cnxn));
        assert_eq!(Command::from_u32(0x48545541), Some(Command::Auth));
        assert_eq!(Command::from_u32(0x4e45504f), Some(Command::Open));
        assert_eq!(Command::from_u32(0x59414b4f), Some(Command::Okay));
        assert_eq!(Command::from_u32(0x45534c43), Some(Command::Clse));
        assert_eq!(Command::from_u32(0x45545257), Some(Command::Wrte));
        assert_eq!(Command::from_u32(0x12345678), None);
    }

    #[test]
    fn test_message_serialization() {
        let data = b"test data";
        let message = Message::new(Command::Cnxn, 0x01000000, 4096, data);

        let bytes = message.to_bytes();
        assert_eq!(bytes.len(), 24);

        let deserialized = Message::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.command, Command::Cnxn);
        assert_eq!(deserialized.arg0, 0x01000000);
        assert_eq!(deserialized.arg1, 4096);
        assert_eq!(deserialized.data_length, data.len() as u32);
    }

    #[test]
    fn test_checksum() {
        let data = b"Hello, ADB!";
        let sum = checksum(data);
        
        // Checksum should be sum of all bytes
        let expected: u32 = data.iter().map(|&b| b as u32).sum();
        assert_eq!(sum, expected);
    }

    #[test]
    fn test_message_verify_data() {
        let data = b"test data";
        let message = Message::new(Command::Wrte, 1, 2, data);
        
        assert!(message.verify_data(data));
        assert!(!message.verify_data(b"wrong data"));
    }

    #[test]
    fn test_empty_data_checksum() {
        let message = Message::new(Command::Okay, 0, 0, &[]);
        assert_eq!(message.data_crc32, 0);
        assert!(message.verify_data(&[]));
    }

    #[test]
    fn test_magic_calculation() {
        let message = Message::new(Command::Cnxn, 0, 0, &[]);
        assert_eq!(message.magic, (Command::Cnxn as u32) ^ 0xffffffff);
    }
}