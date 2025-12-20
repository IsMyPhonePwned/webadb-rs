use webadb_rs::sync::*;

#[test]
fn test_sync_command_conversion() {
    assert_eq!(SyncCommand::from_u32(0x5453494c), Some(SyncCommand::List));
    assert_eq!(SyncCommand::from_u32(0x444e4553), Some(SyncCommand::Send));
    assert_eq!(SyncCommand::from_u32(0x56434552), Some(SyncCommand::Recv));
    assert_eq!(SyncCommand::from_u32(0x54415453), Some(SyncCommand::Stat));
    assert_eq!(SyncCommand::from_u32(0x41544144), Some(SyncCommand::Data));
    assert_eq!(SyncCommand::from_u32(0x454e4f44), Some(SyncCommand::Done));
    assert_eq!(SyncCommand::from_u32(0x4c494146), Some(SyncCommand::Fail));
    assert_eq!(SyncCommand::from_u32(0x544e4544), Some(SyncCommand::Dent));
}
#[test]
fn test_sync_command_invalid() {
    assert_eq!(SyncCommand::from_u32(0xDEADBEEF), None);
    assert_eq!(SyncCommand::from_u32(0x00000000), None);
    assert_eq!(SyncCommand::from_u32(0xFFFFFFFF), None);
}
#[test]
fn test_sync_command_as_bytes() {
    assert_eq!(SyncCommand::List.as_bytes(), [0x4c, 0x49, 0x53, 0x54]); // "LIST" in little-endian
    assert_eq!(SyncCommand::Send.as_bytes(), [0x53, 0x45, 0x4e, 0x44]); // "SEND"
    assert_eq!(SyncCommand::Data.as_bytes(), [0x44, 0x41, 0x54, 0x41]); // "DATA"
    assert_eq!(SyncCommand::Done.as_bytes(), [0x44, 0x4f, 0x4e, 0x45]); // "DONE"
    assert_eq!(SyncCommand::Fail.as_bytes(), [0x46, 0x41, 0x49, 0x4c]); // "FAIL"
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
fn test_sync_packet_empty_data() {
    let packet = SyncPacket::new(SyncCommand::Done, vec![]);
    let bytes = packet.to_bytes();
    
    assert_eq!(bytes.len(), 8); // 4 bytes command + 4 bytes length
    assert_eq!(&bytes[0..4], &SyncCommand::Done.as_bytes());
    assert_eq!(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), 0);
}
#[test]
fn test_sync_packet_large_data() {
    let data = vec![0x42u8; 65536]; // 64KB of data
    let packet = SyncPacket::new(SyncCommand::Data, data.clone());
    let bytes = packet.to_bytes();
    
    assert_eq!(bytes.len(), 8 + 65536);
    assert_eq!(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), 65536);
    assert_eq!(&bytes[8..], data.as_slice());
}
#[test]
fn test_sync_packet_deserialization() {
    let data = b"hello world".to_vec();
    let packet = SyncPacket::new(SyncCommand::Send, data.clone());
    let bytes = packet.to_bytes();
    
    let deserialized = SyncPacket::from_bytes(&bytes).unwrap();
    assert_eq!(deserialized.command, SyncCommand::Send);
    assert_eq!(deserialized.data, data);
}
#[test]
fn test_sync_packet_deserialization_error_too_short() {
    let bytes = vec![0x44, 0x41, 0x54, 0x41]; // Only command, no length
    let result = SyncPacket::from_bytes(&bytes);
    assert!(result.is_err());
    
    let bytes = vec![0x44, 0x41, 0x54, 0x41, 0x04, 0x00, 0x00]; // Missing one byte
    let result = SyncPacket::from_bytes(&bytes);
    assert!(result.is_err());
}
#[test]
fn test_sync_packet_deserialization_error_truncated_data() {
    let mut bytes = vec![0u8; 8];
    bytes[0..4].copy_from_slice(&SyncCommand::Data.as_bytes());
    bytes[4..8].copy_from_slice(&10u32.to_le_bytes()); // Says 10 bytes but we'll provide only 5
    bytes.extend_from_slice(b"hello"); // Only 5 bytes
    
    let result = SyncPacket::from_bytes(&bytes);
    assert!(result.is_err());
}
#[test]
fn test_sync_packet_deserialization_error_invalid_command() {
    let mut bytes = vec![0u8; 12];
    bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes()); // Invalid command
    bytes[4..8].copy_from_slice(&4u32.to_le_bytes());
    bytes[8..12].copy_from_slice(b"test");
    
    let result = SyncPacket::from_bytes(&bytes);
    assert!(result.is_err());
}
#[test]
fn test_sync_packet_roundtrip() {
    let test_cases = vec![
        (SyncCommand::List, vec![]),
        (SyncCommand::Send, b"file.txt,0644".to_vec()),
        (SyncCommand::Data, vec![0x00, 0x01, 0x02, 0x03]),
        (SyncCommand::Done, vec![0x12, 0x34, 0x56, 0x78]),
        (SyncCommand::Fail, b"Permission denied".to_vec()),
    ];
    
    for (cmd, data) in test_cases {
        let packet = SyncPacket::new(cmd, data.clone());
        let bytes = packet.to_bytes();
        let deserialized = SyncPacket::from_bytes(&bytes).unwrap();
        
        assert_eq!(deserialized.command, cmd);
        assert_eq!(deserialized.data, data);
    }
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
    assert_eq!(stat.mtime, 1234567890);
}
#[test]
fn test_file_stat_directory() {
    let mut bytes = vec![0u8; 12];
    // mode: 0o040755 (directory, rwxr-xr-x)
    bytes[0..4].copy_from_slice(&0o040755u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0u32.to_le_bytes()); // Directories have size 0
    bytes[8..12].copy_from_slice(&1234567890u32.to_le_bytes());
    let stat = FileStat::from_bytes(&bytes).unwrap();
    assert!(!stat.is_file());
    assert!(stat.is_directory());
    assert_eq!(stat.mode, 0o040755);
}
#[test]
fn test_file_stat_error_too_short() {
    let bytes = vec![0u8; 11]; // One byte short
    let result = FileStat::from_bytes(&bytes);
    assert!(result.is_err());
    
    let bytes = vec![0u8; 8]; // Way too short
    let result = FileStat::from_bytes(&bytes);
    assert!(result.is_err());
}
#[test]
fn test_dir_entry_is_directory() {
    let entry = DirEntry {
        name: "folder".to_string(),
        mode: 0o040755, // Directory mode
        size: 0,
        mtime: 0,
    };
    
    assert!(entry.is_directory());
    assert!(!entry.is_file());
}
#[test]
fn test_dir_entry_is_file() {
    let entry = DirEntry {
        name: "file.txt".to_string(),
        mode: 0o100644, // Regular file mode
        size: 1234,
        mtime: 0,
    };
    
    assert!(!entry.is_directory());
    assert!(entry.is_file());
}
#[test]
fn test_dir_entry_symlink() {
    let entry = DirEntry {
        name: "link".to_string(),
        mode: 0o120777, // Symlink mode
        size: 10,
        mtime: 0,
    };
    
    // Symlinks are neither files nor directories in our simple check
    assert!(!entry.is_directory());
    assert!(!entry.is_file());
}
#[test]
fn test_dir_entry_special_files() {
    // Block device
    let block_dev = DirEntry {
        name: "sda".to_string(),
        mode: 0o060660,
        size: 0,
        mtime: 0,
    };
    assert!(!block_dev.is_directory());
    assert!(!block_dev.is_file());
    
    // Character device
    let char_dev = DirEntry {
        name: "null".to_string(),
        mode: 0o020666,
        size: 0,
        mtime: 0,
    };
    assert!(!char_dev.is_directory());
    assert!(!char_dev.is_file());
}