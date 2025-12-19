<p align="center"><img width="240" src="./.github/logo.png"></p>
<h2 align="center">WEBADB RUST</h2>

# Rust WebADB

<div align="center">

![Powered By: IsMyPhonePwned](https://img.shields.io/badge/androguard-green?style=for-the-badge&label=Powered%20by&link=https%3A%2F%2Fgithub.com%2Fandroguard)

</div>

A pure Rust implementation of the Android Debug Bridge (ADB) protocol compiled to WebAssembly, enabling direct communication with Android devices from web browsers using WebUSB.

## 🌟 Features

- **Pure WebUSB**: Direct USB communication without ADB server
- **Zero Dependencies**: No native ADB installation required
- **Cross-Platform**: Works in any WebUSB-compatible browser (Chrome, Edge, Opera)
- **Full WASM**: Compiled to WebAssembly for native performance in the browser
- **Comprehensive ADB Protocol**: 
  - Device authentication with RSA key pairs
  - Shell command execution
  - File operations (pull/push)
  - Directory listing
  - Bugreport generation and management
  - Logcat viewing
  - Device properties and information

## 🚀 Quick Start

### Prerequisites

- Rust toolchain (1.70+)
- wasm-pack (`cargo install wasm-pack`)
- A WebUSB-compatible browser (Chrome 61+, Edge 79+, Opera 48+)
- Android device with USB debugging enabled

### Building

```bash
# Clone the repository
cd rust-webadb

# Build for release
./clean-build.sh

# Or manually:
rm -rf target/ pkg/
wasm-pack build --target web --release
```

The compiled WASM module will be in the `pkg/` directory.

### Running

1. **Start a local web server:**
   ```bash
   python3 -m http.server 8000
   # or
   npx serve
   ```

2. **Open in browser:**
   ```
   http://localhost:8000/bugreport.html
   ```

3. **Connect your Android device:**
   - Enable USB debugging on your Android device
   - Click "Connect to Device" in the web interface
   - Select your device from the WebUSB picker
   - Accept the RSA key fingerprint on your device

## 📱 Supported Devices

- Android 4.2.2+ (API level 17+)
- Any device with USB debugging enabled
- Both rooted and non-rooted devices

## 🔧 Usage

### Web Interface (bugreport.html)

The included web interface provides:

- **Device Connection**: WebUSB device selection and authentication
- **Device Information**: Model, Android version, serial number, battery status
- **Bug Reports**: 
  - Generate new bugreports (lite or full)
  - List and download existing bugreports from device
  - Real-time download progress with debug panel
- **Logcat**: View and download device logs
- **File Browser**: Navigate device filesystem and download files
- **Shell**: Execute shell commands

### Programmatic Usage

```javascript
import init, { AdbClient } from './pkg/webadb_rs.js';

// Initialize WASM module
await init();

// Create client and connect
const client = await AdbClient.connect_usb();

// Execute shell commands
const output = await client.shell('ls -la /sdcard');
console.log(output);

// Get device properties
const props = await client.get_properties();
console.log('Android version:', props['ro.build.version.release']);

// Pull a file
const fileData = await client.pull_file('/sdcard/Download/file.txt');

// List directory
const entries = await client.list_directory('/sdcard');
entries.forEach(entry => {
    console.log(`${entry.name} - ${entry.size} bytes`);
});

// Get logcat
const logs = await client.logcat(100);

// Disconnect
await client.disconnect();
```


## 🐛 Known Issues

- **Large File Downloads**: Files >50MB may be slow due to WebUSB bandwidth limitations
- **Safari Not Supported**: WebUSB is not available in Safari
- **Firefox Not Supported**: WebUSB is experimental in Firefox (requires flag)
- **Full Bugreport Generation**: Takes 5-10 minutes (2-5 min device generation + 1-5 min download)
  - **Recommended**: Use "List Available Bugreports" to download existing reports instantly

## 💡 Tips

1. **Bugreports**: Always use "List Available Bugreports" first - it's much faster than generating new ones
2. **Shell Commands**: Most standard Unix commands work (ls, cat, grep, ps, etc.)
3. **File Paths**: Use absolute paths (e.g., `/sdcard/Download/file.txt`)
4. **Permissions**: Some operations require root access
5. **Debug Panel**: When downloading files, a debug panel shows real-time progress, speed, and logs

## 🔬 Technical Details

### ADB Protocol Implementation

- **Connection**: USB bulk transfer endpoints
- **Authentication**: SHA1-signed RSA-2048 challenge-response
- **Streams**: Multiplexed bidirectional channels
- **Messages**: OPEN, OKAY, WRTE, CLSE commands
- **Sync Protocol**: Separate protocol for file operations (LIST, RECV, SEND, STAT)

### Protocol Commands

| Command | Description |
|---------|-------------|
| CNXN | Initial connection handshake |
| AUTH | Authentication challenge/response |
| OPEN | Open a new stream |
| OKAY | Acknowledgment / flow control |
| WRTE | Write data to stream |
| CLSE | Close stream |

### Sync Protocol

The sync protocol is used for file operations over a `sync:` stream:

| Command | Description |
|---------|-------------|
| LIST | List directory contents (returns DENT packets) |
| RECV | Receive file from device (returns DATA packets) |
| SEND | Send file to device |
| STAT | Get file statistics |
| DATA | File data chunk |
| DONE | Operation complete |
| FAIL | Operation failed |
| DENT | Directory entry |

## 🛠️ Development

### Building for Development

```bash
wasm-pack build --target web --dev
```

### Debugging

- Use browser DevTools Console for JavaScript errors
- Check Network tab for WebUSB communication
- Rust panics will show in console with detailed stack traces
- Enable the debug panel in bugreport.html for file transfer diagnostics

## 📄 License

This project is open source. See LICENSE file for details.


## 🙏 Acknowledgments

- Inspired by [webadb](https://github.com/yume-chan/ya-webadb) project
- [WebUSB API](https://wicg.github.io/webusb/)
- ADB protocol reverse engineering by Google's Android team
- Reference implementation by Synacktiv [Synacktiv ADB Client](https://github.com/synacktiv/adb_client)
