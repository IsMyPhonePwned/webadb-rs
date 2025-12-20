use crate::auth::AdbKeyPair;
use crate::protocol::{
    AdbError, Command, ConnectionState, Message, Stream, ADB_VERSION, AuthType,
};
use crate::transport::WebUsbTransport;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

/// Stream with activity tracking
#[derive(Clone)]
struct TrackedStream {
    stream: Stream,
    last_activity: f64, // Timestamp in ms
}

/// Main ADB client
pub struct AdbClient {
    transport: WebUsbTransport,
    keypair: AdbKeyPair,
    state: ConnectionState,
    next_local_id: u32,
    streams: HashMap<u32, TrackedStream>,
    system_identity: String,
    last_health_check: f64,
}

impl AdbClient {
    /// Create a new ADB client
    pub async fn new(
        transport: WebUsbTransport,
        keypair: AdbKeyPair,
    ) -> Result<Self, AdbError> {
        let device_info = transport.device_info();
        let system_identity = format!(
            "host::rust-webadb:{}",
            device_info.serial_number.unwrap_or_else(|| "unknown".to_string())
        );

        Ok(Self {
            transport,
            keypair,
            state: ConnectionState::Disconnected,
            next_local_id: 1,
            streams: HashMap::new(),
            system_identity,
            last_health_check: Self::now(),
        })
    }
    
    /// Get current timestamp
    fn now() -> f64 {
        js_sys::Date::now()
    }
    
    /// Get active stream count
    pub fn active_stream_count(&self) -> usize {
        self.streams.len()
    }
    
    /// Cleanup stale streams (older than 30 seconds)
    pub async fn cleanup_stale_streams(&mut self) -> usize {
        let now = Self::now();
        let stale_ids: Vec<u32> = self.streams.iter()
            .filter(|(_, ts)| now - ts.last_activity > 30000.0)
            .map(|(id, _)| *id)
            .collect();
        
        for id in &stale_ids {
            if let Some(ts) = self.streams.get(id) {
                let clse = Message::new(Command::Clse, *id, ts.stream.remote_id, &[]);
                let _ = self.transport.send_message(&clse, &[]).await;
            }
            self.streams.remove(id);
        }
        
        stale_ids.len()
    }
    
    /// Health check with rate limiting
    pub async fn health_check(&mut self) -> Result<bool, AdbError> {
        let now = Self::now();
        if now - self.last_health_check < 5000.0 {
            return Ok(true);
        }
        self.last_health_check = now;
        
        match self.shell_with_timeout("echo ping", 2000).await {
            Ok(out) => Ok(out.trim() == "ping"),
            Err(_) => Ok(false),
        }
    }
    
    /// Execute shell command with timeout
    pub async fn shell_with_timeout(&mut self, command: &str, timeout_ms: u32) -> Result<String, AdbError> {
        let dest = format!("shell:{}", command);
        let local_id = self.open_stream(&dest).await?;
        let start = Self::now();
        let timeout = timeout_ms as f64;
        let mut output = Vec::new();

        loop {
            if Self::now() - start > timeout {
                let _ = self.close_stream(local_id).await;
                return Err(AdbError::IoError(format!("Timeout after {}ms", timeout_ms)));
            }
            
            match self.read_stream().await {
                Ok((_, data)) => output.extend_from_slice(&data),
                Err(AdbError::StreamError(msg)) if msg.contains("closed") => break,
                Err(e) => {
                    let _ = self.close_stream(local_id).await;
                    return Err(e);
                }
            }
        }

        self.close_stream(local_id).await?;
        String::from_utf8(output).map_err(|e| AdbError::IoError(format!("Invalid UTF-8: {}", e)))
    }

    /// Connect to the device
    pub async fn connect(&mut self) -> Result<(), AdbError> {
        self.state = ConnectionState::Connecting;

        // Send CNXN message
        let data = self.system_identity.as_bytes();
        let message = Message::new(
            Command::Cnxn,
            ADB_VERSION,
            4096, // max data size
            data,
        );

        self.transport.send_message(&message, data).await?;

        // Wait for response
        let (response, response_data) = self.transport.recv_message().await?;

        match response.command {
            Command::Cnxn => {
                // Device accepted connection without auth
                self.state = ConnectionState::Connected;
                Ok(())
            }
            Command::Auth => {
                // Device requires authentication
                self.authenticate(response, response_data).await
            }
            _ => Err(AdbError::ConnectionFailed(format!(
                "Unexpected response: {}",
                response.command
            ))),
        }
    }

    /// Handle authentication
    async fn authenticate(
        &mut self,
        auth_message: Message,
        token: Vec<u8>,
    ) -> Result<(), AdbError> {
        self.state = ConnectionState::Authenticating;

        match auth_message.arg0 {
            1 => {
                // TOKEN - sign the token and send back
                let signature = self.keypair.sign_token(&token)?;
                let message = Message::new(Command::Auth, AuthType::Signature as u32, 0, &signature);
                self.transport.send_message(&message, &signature).await?;

                // Wait for response
                let (response, response_data) = self.transport.recv_message().await?;

                match response.command {
                    Command::Cnxn => {
                        // Authentication successful
                        self.state = ConnectionState::Connected;
                        Ok(())
                    }
                    Command::Auth if response.arg0 == 1 => {
                        // Device didn't accept signature, try sending public key
                        self.send_public_key().await
                    }
                    _ => Err(AdbError::AuthenticationFailed(format!(
                        "Unexpected response: {}",
                        response.command
                    ))),
                }
            }
            _ => Err(AdbError::AuthenticationFailed(format!(
                "Unknown auth type: {}",
                auth_message.arg0
            ))),
        }
    }

    /// Send public key to device
    async fn send_public_key(&mut self) -> Result<(), AdbError> {
        let public_key = self.keypair.get_public_key("rust-webadb")?;
        let message = Message::new(
            Command::Auth,
            AuthType::RsaPublicKey as u32,
            0,
            &public_key,
        );

        self.transport.send_message(&message, &public_key).await?;

        // Wait for user to accept on device, then receive CNXN
        let (response, _) = self.transport.recv_message().await?;

        match response.command {
            Command::Cnxn => {
                self.state = ConnectionState::Connected;
                Ok(())
            }
            _ => Err(AdbError::AuthenticationFailed(
                "Device rejected public key".to_string(),
            )),
        }
    }

    /// Open a new stream
    async fn open_stream(&mut self, destination: &str) -> Result<u32, AdbError> {
        if self.state != ConnectionState::Connected {
            return Err(AdbError::NotConnected);
        }

        let local_id = self.next_local_id;
        self.next_local_id += 1;

        let data = format!("{}\0", destination);
        let message = Message::new(Command::Open, local_id, 0, data.as_bytes());

        self.transport.send_message(&message, data.as_bytes()).await?;

        // Wait for OKAY response - but drain stale messages first
        // We might receive WRTE/OKAY from previous streams
        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = 10;
        
        loop {
            attempts += 1;
            if attempts > MAX_ATTEMPTS {
                return Err(AdbError::StreamError(
                    "Failed to open stream: too many stale messages".to_string()
                ));
            }
            
            let (response, response_data) = self.transport.recv_message().await?;

            match response.command {
                Command::Okay => {
                    // Check if this OKAY is for our stream
                    if response.arg1 == local_id {
                        let stream = Stream {
                            local_id,
                            remote_id: response.arg0,
                        };
                        let tracked = TrackedStream {
                            stream,
                            last_activity: Self::now(),
                        };
                        self.streams.insert(local_id, tracked);
                        return Ok(local_id);
                    } else {
                        // OKAY for different stream - skip and continue
                        continue;
                    }
                }
                Command::Clse => {
                    // Check if this CLSE is for our stream
                    if response.arg1 == local_id {
                        // Device rejected the stream - send CLSE acknowledgment back
                        let clse = Message::new(Command::Clse, local_id, response.arg0, &[]);
                        let _ = self.transport.send_message(&clse, &[]).await;
                        
                        let error_msg = if !response_data.is_empty() {
                            String::from_utf8_lossy(&response_data).to_string()
                        } else {
                            format!("Stream '{}' rejected by device", destination)
                        };
                        
                        return Err(AdbError::StreamError(format!(
                            "Failed to open stream: {}",
                            error_msg
                        )));
                    } else {
                        // CLSE for different stream - handle it
                        if let Some(old_tracked) = self.streams.get(&response.arg1) {
                            // Send CLSE acknowledgment for the old stream
                            let clse = Message::new(Command::Clse, response.arg1, old_tracked.stream.remote_id, &[]);
                            let _ = self.transport.send_message(&clse, &[]).await;
                            self.streams.remove(&response.arg1);
                        }
                        continue;
                    }
                }
                Command::Wrte => {
                    // Data for an old stream - send OKAY and skip
                    let old_local_id = response.arg1;
                    if let Some(old_tracked) = self.streams.get(&old_local_id) {
                        let okay = Message::new(Command::Okay, old_local_id, old_tracked.stream.remote_id, &[]);
                        let _ = self.transport.send_message(&okay, &[]).await;
                    }
                    continue;
                }
                _ => {
                    // Unexpected message - skip it
                    continue;
                }
            }
        }
    }

    /// Write data to a stream
    async fn write_stream(&mut self, local_id: u32, data: &[u8]) -> Result<(), AdbError> {
        let remote_id = self
            .streams
            .get(&local_id)
            .ok_or(AdbError::StreamError("Stream not found".to_string()))?
            .stream.remote_id;

        let message = Message::new(Command::Wrte, local_id, remote_id, data);
        self.transport.send_message(&message, data).await?;

        // Update activity
        if let Some(tracked) = self.streams.get_mut(&local_id) {
            tracked.last_activity = Self::now();
        }

        // Wait for OKAY
        let (response, _) = self.transport.recv_message().await?;
        
        match response.command {
            Command::Okay => Ok(()),
            _ => Err(AdbError::StreamError("Write not acknowledged".to_string())),
        }
    }

    /// Read data from a stream
    async fn read_stream(&mut self) -> Result<(u32, Vec<u8>), AdbError> {
        // Loop to skip OKAY messages (flow control)
        loop {
            let (message, data) = self.transport.recv_message().await?;

            match message.command {
                Command::Wrte => {
                    let local_id = message.arg1; // arg1 is the remote_id (our local_id)
                    
                    // Try to find the stream
                    let tracked = self.streams.get(&local_id);
                    
                    if let Some(tracked) = tracked {
                        // Send OKAY acknowledgment
                        let okay = Message::new(Command::Okay, local_id, tracked.stream.remote_id, &[]);
                        self.transport.send_message(&okay, &[]).await?;
                        
                        // Update activity
                        if let Some(t) = self.streams.get_mut(&local_id) {
                            t.last_activity = Self::now();
                        }
                        
                        return Ok((local_id, data));
                    } else {
                        // Stream not found - this can happen if device sends data after we closed
                        // Send OKAY anyway to avoid blocking the device, then treat as closed
                        let okay = Message::new(Command::Okay, local_id, message.arg0, &[]);
                        let _ = self.transport.send_message(&okay, &[]).await;
                        
                        // If we got data, return it even though stream is closed
                        if !data.is_empty() {
                            return Ok((local_id, data));
                        }
                        
                        // No data and stream closed - signal closure
                        return Err(AdbError::StreamError("Stream closed by device".to_string()));
                    }
                }
                Command::Okay => {
                    // Flow control acknowledgment - just skip it and continue reading
                    continue;
                }
                Command::Clse => {
                    // Stream closed
                    return Err(AdbError::StreamError("Stream closed by device".to_string()));
                }
                _ => {
                    return Err(AdbError::StreamError(format!(
                        "Unexpected message: {}",
                        message.command
                    )));
                }
            }
        }
    }

    /// Close a stream
    async fn close_stream(&mut self, local_id: u32) -> Result<(), AdbError> {
        // Get stream info - if not found, already closed
        let remote_id = match self.streams.get(&local_id) {
            Some(tracked) => tracked.stream.remote_id,
            None => {
                // Stream already closed/removed - this is fine
                return Ok(());
            }
        };

        // Send CLSE message
        let message = Message::new(Command::Clse, local_id, remote_id, &[]);
        if let Err(_) = self.transport.send_message(&message, &[]).await {
            // Failed to send CLSE - device might be disconnected
            // Clean up anyway
            self.streams.remove(&local_id);
            return Ok(());
        }

        // Wait for CLSE response
        match self.transport.recv_message().await {
            Ok((response, _)) => {
                match response.command {
                    Command::Clse => {
                        // Normal close
                        self.streams.remove(&local_id);
                        Ok(())
                    }
                    _ => {
                        // Got something else - maybe device already closed
                        // Clean up anyway
                        self.streams.remove(&local_id);
                        Ok(())
                    }
                }
            }
            Err(_) => {
                // Error receiving response - device might be disconnected
                // Clean up anyway
                self.streams.remove(&local_id);
                Ok(())
            }
        }
    }

    /// Execute a shell command and return output
    pub async fn shell(&mut self, command: &str) -> Result<String, AdbError> {
        let destination = format!("shell:{}", command);
        let local_id = self.open_stream(&destination).await?;

        let mut output = Vec::new();

        // Read until stream closes
        loop {
            match self.read_stream().await {
                Ok((_, data)) => {
                    output.extend_from_slice(&data);
                }
                Err(AdbError::StreamError(msg)) if msg.contains("closed") => {
                    break;
                }
                Err(e) => {
                    // Try to close stream on error, but ignore if it fails
                    let _ = self.close_stream(local_id).await;
                    return Err(e);
                }
            }
        }

        // Stream closed naturally, still need to send CLSE and cleanup
        self.close_stream(local_id).await?;

        String::from_utf8(output)
            .map_err(|e| AdbError::IoError(format!("Invalid UTF-8: {}", e)))
    }
    

    /// Get device properties
    pub async fn get_properties(&mut self) -> Result<HashMap<String, String>, AdbError> {
        let output = self.shell("getprop").await?;
        
        let mut props = HashMap::new();
        for line in output.lines() {
            if let Some((key, value)) = parse_property_line(line) {
                props.insert(key, value);
            }
        }

        Ok(props)
    }

    /// Reboot the device
    pub async fn reboot(&mut self, target: Option<&str>) -> Result<(), AdbError> {
        let command = match target {
            Some("bootloader") => "reboot:bootloader",
            Some("recovery") => "reboot:recovery",
            _ => "reboot:",
        };
        
        let local_id = self.open_stream(command).await?;
        self.close_stream(local_id).await?;
        Ok(())
    }

    /// Pull a file from device
    pub async fn pull_file(&mut self, remote_path: &str) -> Result<Vec<u8>, AdbError> {
        use crate::sync::{SyncCommand, SyncPacket};

        // Open sync connection
        let local_id = self.open_stream("sync:").await?;

        // Send RECV command with path (just the path bytes, no null terminator)
        let recv_data = remote_path.as_bytes().to_vec();
        let recv_packet = SyncPacket::new(SyncCommand::Recv, recv_data);
        
        if let Err(e) = self.write_stream(local_id, &recv_packet.to_bytes()).await {
            let _ = self.close_stream(local_id).await;
            return Err(e);
        }

        // Read data packets
        let mut file_data = Vec::new();
        let mut buffer = Vec::new();
        
        loop {
            let (_, data) = match self.read_stream().await {
                Ok(result) => result,
                Err(AdbError::StreamError(msg)) if msg.contains("closed") => {
                    break;
                }
                Err(e) => {
                    let _ = self.close_stream(local_id).await;
                    return Err(e);
                }
            };
            
            if data.is_empty() {
                break;
            }
            
            buffer.extend_from_slice(&data);
            
            // Process all complete packets in buffer
            loop {
                if buffer.len() < 8 {
                    break;
                }
                
                let length = u32::from_le_bytes([
                    buffer[4], buffer[5], buffer[6], buffer[7],
                ]) as usize;
                
                let packet_size = 8 + length;
                
                if buffer.len() < packet_size {
                    break;
                }
                
                // Extract and parse packet
                let packet_data = buffer.drain(..packet_size).collect::<Vec<u8>>();
                let packet = match SyncPacket::from_bytes(&packet_data) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = self.close_stream(local_id).await;
                        return Err(e);
                    }
                };
                
                match packet.command {
                    SyncCommand::Data => {
                        file_data.extend_from_slice(&packet.data);
                    }
                    SyncCommand::Done => {
                        self.close_stream(local_id).await?;
                        return Ok(file_data);
                    }
                    SyncCommand::Fail => {
                        let error_msg = String::from_utf8_lossy(&packet.data);
                        let _ = self.close_stream(local_id).await;
                        return Err(AdbError::IoError(format!("Pull failed: {}", error_msg)));
                    }
                    _ => {
                        let _ = self.close_stream(local_id).await;
                        return Err(AdbError::IoError(format!("Unexpected sync command: {:?}", packet.command)));
                    }
                }
            }
        }
        
        self.close_stream(local_id).await?;
        Ok(file_data)
    }

    /// Get file statistics
    pub async fn stat_file(&mut self, remote_path: &str) -> Result<crate::sync::FileStat, AdbError> {
        use crate::sync::{SyncCommand, SyncPacket, FileStat};

        let local_id = self.open_stream("sync:").await?;

        // Send STAT command
        let stat_packet = SyncPacket::new(SyncCommand::Stat, remote_path.as_bytes().to_vec());
        if let Err(e) = self.write_stream(local_id, &stat_packet.to_bytes()).await {
            let _ = self.close_stream(local_id).await;
            return Err(e);
        }

        // Read response - might need to accumulate data
        let mut buffer = Vec::new();
        
        loop {
            let (_, data) = match self.read_stream().await {
                Ok(result) => result,
                Err(AdbError::StreamError(msg)) if msg.contains("closed") => {
                    // Stream closed without response
                    let _ = self.close_stream(local_id).await;
                    return Err(AdbError::IoError("Stream closed before receiving stat response".to_string()));
                }
                Err(e) => {
                    let _ = self.close_stream(local_id).await;
                    return Err(e);
                }
            };
            
            // If we get empty data, something is wrong
            if data.is_empty() {
                let _ = self.close_stream(local_id).await;
                return Err(AdbError::IoError("No stat response received".to_string()));
            }
            
            buffer.extend_from_slice(&data);
            
            // Check if we have a complete packet (at least 8 bytes for header)
            if buffer.len() >= 8 {
                let length = u32::from_le_bytes([
                    buffer[4],
                    buffer[5],
                    buffer[6],
                    buffer[7],
                ]) as usize;
                
                let packet_size = 8 + length;
                
                if buffer.len() >= packet_size {
                    // We have a complete packet
                    let packet_data = buffer[..packet_size].to_vec();
                    
                    let packet = match SyncPacket::from_bytes(&packet_data) {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = self.close_stream(local_id).await;
                            return Err(e);
                        }
                    };

                    let stat = match packet.command {
                        SyncCommand::Stat => match FileStat::from_bytes(&packet.data) {
                            Ok(s) => s,
                            Err(e) => {
                                let _ = self.close_stream(local_id).await;
                                return Err(e);
                            }
                        },
                        SyncCommand::Fail => {
                            let error_msg = String::from_utf8_lossy(&packet.data);
                            let _ = self.close_stream(local_id).await;
                            return Err(AdbError::IoError(format!("Stat failed: {}", error_msg)));
                        }
                        _ => {
                            let _ = self.close_stream(local_id).await;
                            return Err(AdbError::IoError(format!("Unexpected sync command: {:?}", packet.command)));
                        }
                    };

                    self.close_stream(local_id).await?;
                    return Ok(stat);
                }
            }
            // If we don't have a complete packet yet, loop and read more data
        }
    }

    /// Generate and retrieve a full bugreport (can take several minutes)
    /// 
    /// WARNING: This is VERY SLOW:
    /// - Generation: 2-5 minutes (device generates the report)
    /// - Download: 1-3 minutes (large file ~10-50MB)
    /// 
    /// RECOMMENDED: Use list_bugreports() + download_bugreport() instead
    /// to download previously generated reports instantly.
    pub async fn bugreport(&mut self) -> Result<Vec<u8>, AdbError> {
        // Try bugreportz first (Android 7.0+, generates ZIP)
        let local_id = match self.open_stream("shell:bugreportz").await {
            Ok(id) => id,
            Err(_) => {
                // bugreportz not supported, try regular bugreport
                match self.open_stream("shell:bugreport").await {
                    Ok(id) => id,
                    Err(_) => {
                        return Err(AdbError::IoError(
                            "Bugreport command not available. Use list_bugreports() to download existing reports.".to_string()
                        ));
                    }
                }
            }
        };

        let mut report_data = Vec::new();

        // Read bugreport output (takes 2-5 minutes for device to generate)
        // Note: No progress updates during generation - device is working
        loop {
            match self.read_stream().await {
                Ok((_, data)) => {
                    if data.is_empty() {
                        break;
                    }
                    report_data.extend_from_slice(&data);
                }
                Err(AdbError::StreamError(msg)) if msg.contains("closed") => {
                    break;
                }
                Err(e) => {
                    let _ = self.close_stream(local_id).await;
                    return Err(e);
                }
            }
        }

        self.close_stream(local_id).await?;
        
        // bugreportz outputs the path to the ZIP file
        // Format: "OK:/data/user_de/0/com.android.shell/files/bugreports/bugreport-XXXXX.zip"
        let output = String::from_utf8_lossy(&report_data);
        
        if output.starts_with("OK:") {
            // Extract file path
            let lines: Vec<&str> = output.lines().collect();
            if let Some(first_line) = lines.first() {
                if let Some(path) = first_line.strip_prefix("OK:") {
                    let path = path.trim();
                    
                    // Now pull the large file (1-3 minutes for large bugreports)
                    return self.pull_file(path).await.map_err(|e| {
                        AdbError::IoError(format!(
                            "Bugreport generated at '{}' but failed to download: {}. \
                             You can try list_bugreports() and download_bugreport('{}') to retry.", 
                            path, e, path
                        ))
                    });
                }
            }
        }
        
        // Old-style bugreport returned data directly
        if report_data.is_empty() {
            return Err(AdbError::IoError(
                "Bugreport generation timed out or returned no data. \
                 Try list_bugreports() to download existing reports instead.".to_string()
            ));
        }
        
        Ok(report_data)
    }

    /// List available bugreports on device
    /// Returns list of bugreport file paths
    pub async fn list_bugreports(&mut self) -> Result<Vec<String>, AdbError> {
        // Common bugreport directories
        let directories = vec![
            "/data/user_de/0/com.android.shell/files/bugreports",
            "/data/data/com.android.shell/files/bugreports",
            "/bugreports",
        ];

        let mut bugreports = Vec::new();

        for dir in directories {
            // Try to list directory - now uses shell fallback automatically
            match self.list_directory(dir).await {
                Ok(entries) => {
                    for entry in entries {
                        // Filter for bugreport files (ZIP or TXT)
                        if entry.name.starts_with("bugreport-") && 
                           (entry.name.ends_with(".zip") || entry.name.ends_with(".txt")) {
                            let full_path = format!("{}/{}", dir, entry.name);
                            bugreports.push(full_path);
                        }
                    }
                }
                Err(_) => {
                    // Directory doesn't exist or not accessible, skip
                    continue;
                }
            }
        }

        Ok(bugreports)
    }

    /// Download a specific bugreport by path
    pub async fn download_bugreport(&mut self, path: &str) -> Result<Vec<u8>, AdbError> {
        self.pull_file(path).await
    }

    /// Generate a lightweight bugreport (faster, less comprehensive)
    pub async fn bugreport_lite(&mut self) -> Result<String, AdbError> {
        // Use shell command for a lighter bugreport
        let commands = vec![
            "echo '=== Device Info ==='",
            "getprop | grep -E 'ro.product|ro.build|ro.hardware'",
            "echo ''",
            "echo '=== System Info ==='",
            "uname -a",
            "uptime",
            "cat /proc/meminfo | head -20",
            "cat /proc/cpuinfo | grep -E 'processor|model name|Hardware' | head -20",
            "echo ''",
            "echo '=== Storage ==='",
            "df -h",
            "echo ''",
            "echo '=== Processes (top 20 by memory) ==='",
            "ps -A -o pid,user,vsz,rss,name | sort -k4 -rn | head -20",
            "echo ''",
            "echo '=== Network ==='",
            "ip addr show",
            "echo ''",
            "echo '=== Recent Logcat ==='",
            "logcat -d -t 100",
        ];

        let combined_command = commands.join(" && ");
        self.shell(&combined_command).await
    }

    /// Get logcat output (last n lines)
    pub async fn logcat(&mut self, lines: u32) -> Result<String, AdbError> {
        let command = format!("logcat -d -t {}", lines);
        self.shell(&command).await
    }

    /// Clear logcat buffer
    pub async fn logcat_clear(&mut self) -> Result<(), AdbError> {
        self.shell("logcat -c").await?;
        Ok(())
    }

    /// List directory contents
    /// Uses shell ls command for reliability (sync protocol can hang)
    pub async fn list_directory(&mut self, path: &str) -> Result<Vec<crate::sync::DirEntry>, AdbError> {
        // Use shell command directly - it's more reliable and never hangs
        self.list_directory_shell(path).await
    }

    /// List directory using shell ls command
    async fn list_directory_shell(&mut self, path: &str) -> Result<Vec<crate::sync::DirEntry>, AdbError> {
        use crate::sync::DirEntry;
        
        // Use ls with specific format - escape single quotes in path
        let escaped_path = path.replace("'", "'\\''");
        let command = format!("ls -la '{}'", escaped_path);
        
        let output = match self.shell(&command).await {
            Ok(o) => o,
            Err(e) => {
                // If ls fails, try without -a flag (some devices don't support it)
                let command = format!("ls -l '{}'", escaped_path);
                self.shell(&command).await
                    .map_err(|_| e)? // Return original error if this also fails
            }
        };
        
        let mut entries = Vec::new();
        
        for line in output.lines() {
            // Skip empty lines and total line
            let line = line.trim();
            if line.is_empty() || line.starts_with("total") {
                continue;
            }
            
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 {
                continue;
            }
            
            let mode_str = parts[0];
            let size = parts[4].parse::<u32>().unwrap_or(0);
            
            // Name is everything after column 7 (to handle spaces in names)
            let name = parts[7..].join(" ");
            
            // Skip . and ..
            if name == "." || name == ".." {
                continue;
            }
            
            // Convert mode string to numeric
            let mut mode = 0u32;
            if mode_str.starts_with('d') { mode |= 0o040000; } // Directory
            if mode_str.starts_with('l') { mode |= 0o120000; } // Symlink
            if mode_str.starts_with('-') { mode |= 0o100000; } // Regular file
            if mode_str.starts_with('b') { mode |= 0o060000; } // Block device
            if mode_str.starts_with('c') { mode |= 0o020000; } // Char device
            
            entries.push(DirEntry {
                name,
                mode,
                size,
                mtime: 0, // ls -la doesn't give us easy mtime parsing
            });
        }
        
        Ok(entries)
    }

    /// Disconnect from device
    pub async fn disconnect(&self) -> Result<(), AdbError> {
        self.transport.close().await
    }
}

/// Parse a property line from getprop output
/// Format: [key]: [value]
fn parse_property_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if !line.starts_with('[') {
        return None;
    }

    let parts: Vec<&str> = line.split("]: [").collect();
    if parts.len() != 2 {
        return None;
    }

    let key = parts[0].trim_start_matches('[').to_string();
    let value = parts[1].trim_end_matches(']').to_string();

    Some((key, value))
}