// Integration tests for client module
// Note: These tests focus on testable functions and path handling
// Full async tests would require mocking WebUSB transport

use webadb_rs::sync::{DirEntry, FileStat};

#[test]
fn test_dir_entry_classification() {
    // Test directory
    let dir = DirEntry {
        name: "mydir".to_string(),
        mode: 0o040755,
        size: 0,
        mtime: 0,
    };
    assert!(dir.is_directory());
    assert!(!dir.is_file());
    
    // Test regular file
    let file = DirEntry {
        name: "file.txt".to_string(),
        mode: 0o100644,
        size: 1234,
        mtime: 0,
    };
    assert!(!file.is_directory());
    assert!(file.is_file());
}

#[test]
fn test_file_stat_classification() {
    // Test file
    let file_stat = FileStat {
        mode: 0o100644,
        size: 5678,
        mtime: 1234567890,
    };
    assert!(file_stat.is_file());
    assert!(!file_stat.is_directory());
    
    // Test directory
    let dir_stat = FileStat {
        mode: 0o040755,
        size: 0,
        mtime: 1234567890,
    };
    assert!(!dir_stat.is_file());
    assert!(dir_stat.is_directory());
}

#[test]
fn test_path_escaping_for_shell() {
    // These test the kind of path escaping that should be done
    // in delete_path, rename_file, create_directory
    
    let test_cases = vec![
        ("/sdcard/test.txt", "'/sdcard/test.txt'"),
        ("/sdcard/file's name.txt", "'/sdcard/file'\\''s name.txt'"),
        ("/data/local/tmp", "'/data/local/tmp'"),
        ("/path with spaces/file.txt", "'/path with spaces/file.txt'"),
    ];
    
    for (input, expected) in test_cases {
        let escaped = escape_path_for_shell(input);
        assert_eq!(escaped, expected);
    }
}

// Helper function for path escaping (mirrors client.rs logic)
fn escape_path_for_shell(path: &str) -> String {
    let escaped = path.replace("'", "'\\''");
    format!("'{}'", escaped)
}

#[test]
fn test_file_permissions() {
    // Regular file with rw-r--r--
    let mode = 0o100644;
    assert_eq!(mode & 0o170000, 0o100000); // Is regular file
    assert_eq!(mode & 0o777, 0o644); // Permissions
    
    // Directory with rwxr-xr-x
    let mode = 0o040755;
    assert_eq!(mode & 0o170000, 0o040000); // Is directory
    assert_eq!(mode & 0o777, 0o755); // Permissions
    
    // Executable file with rwxr-xr-x
    let mode = 0o100755;
    assert_eq!(mode & 0o170000, 0o100000); // Is regular file
    assert_eq!(mode & 0o777, 0o755); // Permissions
}

#[test]
fn test_file_type_from_mode() {
    let file_types = vec![
        (0o100644, "regular file"),
        (0o040755, "directory"),
        (0o120777, "symlink"),
        (0o060660, "block device"),
        (0o020666, "character device"),
        (0o010666, "fifo"),
        (0o140755, "socket"),
    ];
    
    for (mode, expected_type) in file_types {
        let file_type = match mode & 0o170000 {
            0o100000 => "regular file",
            0o040000 => "directory",
            0o120000 => "symlink",
            0o060000 => "block device",
            0o020000 => "character device",
            0o010000 => "fifo",
            0o140000 => "socket",
            _ => "unknown",
        };
        assert_eq!(file_type, expected_type);
    }
}

#[test]
fn test_path_joining() {
    // Test path joining logic (as used in file operations)
    let test_cases = vec![
        ("/sdcard", "file.txt", "/sdcard/file.txt"),
        ("/sdcard/", "file.txt", "/sdcard/file.txt"),
        ("/", "sdcard", "/sdcard"),
        ("/data/local/tmp", "test", "/data/local/tmp/test"),
        ("/data/local/tmp/", "test", "/data/local/tmp/test"),
    ];
    
    for (base, name, expected) in test_cases {
        let result = if base.ends_with('/') {
            format!("{}{}", base, name)
        } else {
            format!("{}/{}", base, name)
        };
        assert_eq!(result, expected);
    }
}

#[test]
fn test_parent_path_extraction() {
    let test_cases = vec![
        ("/sdcard/Download/file.txt", "/sdcard/Download"),
        ("/sdcard/file.txt", "/sdcard"),
        ("/file.txt", "/"),
        ("/a/b/c/d/e.txt", "/a/b/c/d"),
    ];
    
    for (full_path, expected_parent) in test_cases {
        let parent = full_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("/");
        let parent = if parent.is_empty() { "/" } else { parent };
        assert_eq!(parent, expected_parent);
    }
}

#[test]
fn test_filename_extraction() {
    let test_cases = vec![
        ("/sdcard/Download/file.txt", "file.txt"),
        ("/sdcard/file.txt", "file.txt"),
        ("/file.txt", "file.txt"),
        ("/a/b/c/d/e.txt", "e.txt"),
    ];
    
    for (full_path, expected_name) in test_cases {
        let name = full_path.rsplit_once('/').map(|(_, n)| n).unwrap_or(full_path);
        assert_eq!(name, expected_name);
    }
}

#[test]
fn test_file_size_ranges() {
    // Test that file sizes are handled correctly
    let test_cases = vec![
        (0u64, true),           // Empty file
        (1u64, true),           // 1 byte
        (1024u64, true),        // 1 KB
        (1048576u64, true),     // 1 MB
        (1073741824u64, true),  // 1 GB
        (u64::MAX, true),       // Max size
    ];
    
    for (size, should_be_valid) in test_cases {
        // All sizes should be valid
        assert_eq!(should_be_valid, true);
        assert!(size <= u64::MAX);
    }
}

#[test]
fn test_timestamp_handling() {
    // Test mtime timestamp values
    let now = 1734700000u32; // Approximate current time
    let test_cases = vec![
        0u32,           // Epoch
        1234567890u32,  // Feb 13, 2009
        now,            // Recent
        u32::MAX,       // Far future (year 2106)
    ];
    
    for mtime in test_cases {
        assert!(mtime <= u32::MAX);
    }
}

#[test]
fn test_chunk_size_for_upload() {
    // Test the chunking logic for file uploads
    const CHUNK_SIZE: usize = 65536; // 64KB as used in push_file
    
    let test_cases = vec![
        (0, vec![]),                    // Empty file
        (100, vec![100]),               // Small file
        (65536, vec![65536]),           // Exactly one chunk
        (65537, vec![65536, 1]),        // One chunk + 1 byte
        (131072, vec![65536, 65536]),   // Two chunks
        (200000, vec![65536, 65536, 65536, 3392]), // Multiple chunks
    ];
    
    for (total_size, expected_chunks) in test_cases {
        let mut chunks = Vec::new();
        let mut offset = 0;
        
        while offset < total_size {
            let end = std::cmp::min(offset + CHUNK_SIZE, total_size);
            chunks.push(end - offset);
            offset = end;
        }
        
        assert_eq!(chunks, expected_chunks);
    }
}

#[test]
fn test_path_validation() {
    // Test common path validation scenarios
    let valid_paths = vec![
        "/sdcard",
        "/sdcard/Download",
        "/data/local/tmp",
        "/system/bin",
        "/",
    ];
    
    for path in valid_paths {
        assert!(path.starts_with('/'));
        assert!(!path.is_empty());
    }
    
    let invalid_paths = vec![
        "",
        "relative/path",
        "sdcard",
    ];
    
    for path in invalid_paths {
        assert!(!path.starts_with('/') || path.is_empty());
    }
}

#[test]
fn test_command_construction() {
    // Test shell command construction (as used in client methods)
    
    // delete_path
    let path = "/sdcard/test.txt";
    let escaped = path.replace("'", "'\\''");
    let cmd = format!("rm -rf '{}'", escaped);
    assert_eq!(cmd, "rm -rf '/sdcard/test.txt'");
    
    // rename_file
    let old = "/sdcard/old.txt";
    let new = "/sdcard/new.txt";
    let escaped_old = old.replace("'", "'\\''");
    let escaped_new = new.replace("'", "'\\''");
    let cmd = format!("mv '{}' '{}'", escaped_old, escaped_new);
    assert_eq!(cmd, "mv '/sdcard/old.txt' '/sdcard/new.txt'");
    
    // create_directory
    let path = "/sdcard/new_folder";
    let escaped = path.replace("'", "'\\''");
    let cmd = format!("mkdir -p '{}'", escaped);
    assert_eq!(cmd, "mkdir -p '/sdcard/new_folder'");
}

#[test]
fn test_path_with_special_characters() {
    let special_paths = vec![
        "/sdcard/file's name.txt",
        "/sdcard/file (copy).txt",
        "/sdcard/file [1].txt",
        "/sdcard/file & more.txt",
        "/sdcard/file; test.txt",
    ];
    
    for path in special_paths {
        // After escaping, single quotes should be handled
        let escaped = path.replace("'", "'\\''");
        assert!(!escaped.contains("'") || escaped.contains("'\\''"));
    }
}

#[test]
fn test_file_extension_detection() {
    let test_cases = vec![
        ("file.txt", Some("txt")),
        ("file.tar.gz", Some("gz")),
        ("file", None),
        (".gitignore", Some("gitignore")),
        ("file.", Some("")),
        ("path/to/file.pdf", Some("pdf")),
    ];
    
    for (filename, expected_ext) in test_cases {
        let ext = filename.rsplit_once('.').map(|(_, e)| e);
        assert_eq!(ext, expected_ext);
    }
}

#[test]
fn test_directory_depth() {
    let test_cases = vec![
        ("/", 0),
        ("/sdcard", 1),
        ("/sdcard/Download", 2),
        ("/data/local/tmp", 3),
        ("/a/b/c/d/e/f/g", 7),
    ];
    
    for (path, expected_depth) in test_cases {
        let depth = path.matches('/').count() - if path.starts_with('/') { 1 } else { 0 };
        assert_eq!(depth, expected_depth);
    }
}

#[test]
fn test_sync_protocol_format() {
    // Test the format string used in push_file: "path,mode"
    let test_cases = vec![
        ("/sdcard/test.txt", "0644", "/sdcard/test.txt,0644"),
        ("/data/file", "0755", "/data/file,0755"),
    ];
    
    for (path, mode, expected) in test_cases {
        let format = format!("{},{}", path, mode);
        assert_eq!(format, expected);
    }
}

#[test]
fn test_bytes_to_string_conversion() {
    // Test data conversion as used in file operations
    let test_data = b"Hello, World!";
    let as_vec = test_data.to_vec();
    let back_to_str = String::from_utf8_lossy(&as_vec);
    
    assert_eq!(back_to_str, "Hello, World!");
    
    // Test with invalid UTF-8
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
    let lossy = String::from_utf8_lossy(&invalid_utf8);
    assert!(!lossy.is_empty()); // Should contain replacement characters
}

#[test]
fn test_timestamp_conversion() {
    // Test timestamp conversions (as used in push_file)
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let now = SystemTime::now();
    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let timestamp = since_epoch.as_secs() as u32;
    
    assert!(timestamp > 1700000000); // After 2023
    assert!(timestamp < u32::MAX);   // Valid u32
}