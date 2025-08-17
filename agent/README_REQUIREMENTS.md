# Requirements File Documentation

## 📁 Single Requirements File

**File**: `requirements.txt` - This is the ONLY requirements file you need.

## 🎯 What This File Contains

The `requirements.txt` file contains **ALL** dependencies needed for the stealth agent, organized into logical sections:

### 🔧 Core Dependencies (Required)
- **requests** - HTTP communication
- **cryptography** - Encryption/decryption
- **psutil** - System monitoring
- **numpy** - Numerical operations
- **Pillow** - Image processing
- **mss** - Screenshot functionality

### 📹 Surveillance & Monitoring
- **opencv-python** - Webcam functionality
- **pynput** - Keylogging
- **pyautogui** - GUI automation
- **keyboard** - Alternative keylogging

### 🖥️ System Interaction (Windows)
- **pywin32** - Windows API access
- **wmi** - Windows Management Instrumentation
- **pywinauto** - Windows automation

### 🌐 Network & Security
- **dnspython** - DNS tunneling
- **pycryptodome** - Advanced encryption
- **pyOpenSSL** - SSL/TLS support

### 📊 File & System Monitoring
- **watchdog** - File system monitoring
- **py-cpuinfo** - CPU information
- **GPUtil** - GPU monitoring

### 🎵 Audio & Multimedia
- **pyaudio** - Audio capture
- **sounddevice** - Alternative audio
- **imageio** - Image format support
- **imageio-ffmpeg** - Video support

### 🔬 Scientific Computing
- **scipy** - Signal processing

### 🛠️ Build Tools (Development)
- **pyinstaller** - Executable creation

## 🚀 Installation

```bash
# Install all dependencies
python -m pip install --user -r requirements.txt

# Or install specific sections (examples)
python -m pip install --user requests cryptography psutil  # Core only
python -m pip install --user opencv-python numpy Pillow    # Surveillance only
```

## ⚠️ Important Notes

1. **Single File**: Only use `requirements.txt` - all other requirements files have been removed
2. **Platform Specific**: Some packages are marked for specific platforms (Windows/Linux/macOS)
3. **Optional Tools**: UPX compression and PyArmor obfuscation are commented out by default
4. **Version Pinning**: All packages have minimum version requirements for compatibility

## 🔍 Troubleshooting

- **OpenCV Issues**: Make sure `opencv-python` is installed correctly
- **Permission Errors**: Use `--user` flag for user-level installation
- **Platform Errors**: Some packages are platform-specific and will be ignored on other platforms

## 📋 Removed Files

The following duplicate requirements files have been removed:
- ❌ `requirements_clean.txt`
- ❌ `requirements_stealth.txt` 
- ❌ `requirements_surveillance_minimal.txt`

**Keep only**: `requirements.txt` ✅
