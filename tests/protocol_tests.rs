use webadb_rs::protocol::*;

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
fn test_command_display() {
    assert_eq!(format!("{}", Command::Sync), "SYNC");
    assert_eq!(format!("{}", Command::Cnxn), "CNXN");
    assert_eq!(format!("{}", Command::Auth), "AUTH");
    assert_eq!(format!("{}", Command::Open), "OPEN");
    assert_eq!(format!("{}", Command::Okay), "OKAY");
    assert_eq!(format!("{}", Command::Clse), "CLSE");
    assert_eq!(format!("{}", Command::Wrte), "WRTE");
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
fn test_message_roundtrip() {
    let test_cases: Vec<(Command, u32, u32, &[u8])> = vec![
        (Command::Sync, 0, 0, b"" as &[u8]),
        (Command::Cnxn, ADB_VERSION, MAX_PAYLOAD, b"host::" as &[u8]),
        (Command::Auth, 1, 0, b"token data" as &[u8]),
        (Command::Open, 5, 0, b"shell:ls" as &[u8]),
        (Command::Okay, 5, 10, b"" as &[u8]),
        (Command::Clse, 5, 10, b"" as &[u8]),
        (Command::Wrte, 5, 10, b"output data" as &[u8]),
    ];
    
    for (cmd, arg0, arg1, data) in test_cases {
        let message = Message::new(cmd, arg0, arg1, data);
        let bytes = message.to_bytes();
        let deserialized = Message::from_bytes(&bytes).unwrap();
        
        assert_eq!(deserialized.command, cmd);
        assert_eq!(deserialized.arg0, arg0);
        assert_eq!(deserialized.arg1, arg1);
        assert_eq!(deserialized.data_length, data.len() as u32);
    }
}

#[test]
fn test_message_from_bytes_too_short() {
    let bytes = vec![0u8; 20]; // Too short (need 24)
    assert!(Message::from_bytes(&bytes).is_err());
    
    let bytes = vec![0u8; 0]; // Empty
    assert!(Message::from_bytes(&bytes).is_err());
}

#[test]
fn test_message_from_bytes_invalid_command() {
    let mut bytes = vec![0u8; 24];
    bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes()); // Invalid command
    assert!(Message::from_bytes(&bytes).is_err());
}

#[test]
fn test_message_from_bytes_invalid_magic() {
    let message = Message::new(Command::Cnxn, 0, 0, b"");
    let mut bytes = message.to_bytes();
    
    // Corrupt the magic field
    bytes[8..12].copy_from_slice(&0x12345678u32.to_le_bytes());
    
    assert!(Message::from_bytes(&bytes).is_err());
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
fn test_checksum_empty() {
    assert_eq!(checksum(b""), 0);
}

#[test]
fn test_checksum_overflow() {
    // Test with data that would overflow if not using wrapping add
    let data = vec![0xFF; 1000];
    let sum = checksum(&data);
    assert_eq!(sum, 0xFF * 1000);
}

#[test]
fn test_message_verify_data() {
    let data = b"test data";
    let message = Message::new(Command::Wrte, 1, 2, data);
    
    assert!(message.verify_data(data));
    assert!(!message.verify_data(b"wrong data"));
    assert!(!message.verify_data(b""));
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
    
    let message = Message::new(Command::Wrte, 0, 0, &[]);
    assert_eq!(message.magic, (Command::Wrte as u32) ^ 0xffffffff);
}

#[test]
fn test_constants() {
    assert_eq!(ADB_VERSION, 0x01000000);
    assert_eq!(MAX_PAYLOAD, 256 * 1024);
}

#[test]
fn test_adb_error_display() {
    let err = AdbError::NotConnected;
    assert_eq!(format!("{}", err), "Not connected");
    
    let err = AdbError::InvalidMessage("test".to_string());
    assert!(format!("{}", err).contains("test"));
    
    let err = AdbError::IoError("io error".to_string());
    assert!(format!("{}", err).contains("io error"));
}

#[test]
fn test_large_payload() {
    let data = vec![0x42; MAX_PAYLOAD as usize];
    let message = Message::new(Command::Wrte, 1, 2, &data);
    
    assert_eq!(message.data_length, MAX_PAYLOAD);
    assert!(message.verify_data(&data));
}

#[test]
fn test_message_new_computes_correct_checksum() {
    let data = b"some test data";
    let message = Message::new(Command::Wrte, 1, 2, data);
    
    let expected_checksum = checksum(data);
    assert_eq!(message.data_crc32, expected_checksum);
}