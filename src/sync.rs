use super::protocol::AdbError;

/// Sync protocol commands (for file operations)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyncCommand {
    /// List directory
    List = 0x5453494c, // "LIST"
    /// Send file to device
    Send = 0x444e4553, // "SEND"
    /// Receive file from device
    Recv = 0x56434552, // "RECV"
    /// Get file stats
    Stat = 0x54415453, // "STAT"
    /// Data packet
    Data = 0x41544144, // "DATA"
    /// Done/Success
    Done = 0x454e4f44, // "DONE"
    /// Fail/Error
    Fail = 0x4c494146, // "FAIL"
    /// Directory entry
    Dent = 0x544e4544, // "DENT"
}

impl SyncCommand {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x5453494c => Some(SyncCommand::List),
            0x444e4553 => Some(SyncCommand::Send),
            0x56434552 => Some(SyncCommand::Recv),
            0x54415453 => Some(SyncCommand::Stat),
            0x41544144 => Some(SyncCommand::Data),
            0x454e4f44 => Some(SyncCommand::Done),
            0x4c494146 => Some(SyncCommand::Fail),
            0x544e4544 => Some(SyncCommand::Dent),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> [u8; 4] {
        (*self as u32).to_le_bytes()
    }
}

/// Sync packet structure
pub struct SyncPacket {
    pub command: SyncCommand,
    pub data: Vec<u8>,
}

impl SyncPacket {
    /// Create a new sync packet
    pub fn new(command: SyncCommand, data: Vec<u8>) -> Self {
        Self { command, data }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.command.as_bytes());
        bytes.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdbError> {
        if bytes.len() < 8 {
            return Err(AdbError::InvalidMessage("Sync packet too short".to_string()));
        }

        let cmd_bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
        let cmd_u32 = u32::from_le_bytes(cmd_bytes);
        let command = SyncCommand::from_u32(cmd_u32)
            .ok_or_else(|| AdbError::InvalidMessage(format!("Unknown sync command: 0x{:08x}", cmd_u32)))?;

        let length = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;

        if bytes.len() < 8 + length {
            return Err(AdbError::InvalidMessage("Sync packet data truncated".to_string()));
        }

        let data = bytes[8..8 + length].to_vec();

        Ok(Self { command, data })
    }
}

/// File statistics from STAT command
#[derive(Debug, Clone)]
pub struct FileStat {
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
}

impl FileStat {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdbError> {
        if bytes.len() < 12 {
            return Err(AdbError::InvalidMessage("File stat too short".to_string()));
        }

        let mode = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mtime = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        Ok(Self { mode, size, mtime })
    }

    pub fn is_directory(&self) -> bool {
        (self.mode & 0o170000) == 0o040000
    }

    pub fn is_file(&self) -> bool {
        (self.mode & 0o170000) == 0o100000
    }
}

/// Directory entry from LIST/DENT
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
}

impl DirEntry {
    pub fn is_directory(&self) -> bool {
        (self.mode & 0o170000) == 0o040000
    }

    pub fn is_file(&self) -> bool {
        (self.mode & 0o170000) == 0o100000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_command_conversion() {
        assert_eq!(SyncCommand::from_u32(0x5453494c), Some(SyncCommand::List));
        assert_eq!(SyncCommand::from_u32(0x444e4553), Some(SyncCommand::Send));
        assert_eq!(SyncCommand::from_u32(0x56434552), Some(SyncCommand::Recv));
        assert_eq!(SyncCommand::from_u32(0x54415453), Some(SyncCommand::Stat));
    }

    #[test]
    fn test_sync_packet_serialization() {
        let data = b"test".to_vec();
        let packet = SyncPacket::new(SyncCommand::Data, data.clone());
        let bytes = packet.to_bytes();

        assert_eq!(&bytes[0..4], &SyncCommand::Data.as_bytes());
        assert_eq!(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), data.len() as u32);
        assert_eq!(&bytes[8..], data.as_slice());
    }

    #[test]
    fn test_file_stat() {
        let mut bytes = vec![0u8; 12];
        // mode: 0o100644 (regular file, rw-r--r--)
        bytes[0..4].copy_from_slice(&0o100644u32.to_le_bytes());
        // size: 1234
        bytes[4..8].copy_from_slice(&1234u32.to_le_bytes());
        // mtime: timestamp
        bytes[8..12].copy_from_slice(&1234567890u32.to_le_bytes());

        let stat = FileStat::from_bytes(&bytes).unwrap();
        assert!(stat.is_file());
        assert!(!stat.is_directory());
        assert_eq!(stat.size, 1234);
    }
}