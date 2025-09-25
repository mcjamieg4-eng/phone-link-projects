# Essential Reverse Engineering CLI Commands

## APK Analysis & Decompilation

### APKTool
```bash
# Decompile APK
java -jar apktool.jar d app.apk -o output_dir

# Rebuild APK
java -jar apktool.jar b output_dir -o rebuilt.apk

# Get APK info
java -jar apktool.jar info app.apk
```

### JADX (Java Decompiler)
```bash
# Decompile to Java source
jadx app.apk -d output_dir

# Export as Gradle project
jadx app.apk -d output_dir --export-gradle

# Decompile specific classes
jadx app.apk -c com.example.MainActivity
```

### AAPT (Android Asset Packaging Tool)
```bash
# Dump APK info
aapt dump badging app.apk

# List APK contents
aapt list app.apk

# Extract specific resources
aapt dump resources app.apk
```

## Binary Analysis

### Strings
```bash
# Extract readable strings
strings binary_file

# Case-insensitive search
strings binary_file | grep -i "password"

# Minimum string length
strings -n 10 binary_file
```

### Hexdump/xxd
```bash
# View hex dump
xxd binary_file

# Search for hex patterns
xxd binary_file | grep "deadbeef"

# Create hex patch
xxd -r -p patch.hex > patched_binary
```

### objdump (Linux/ELF)
```bash
# Disassemble binary
objdump -d binary_file

# Show section headers
objdump -h binary_file

# Display symbols
objdump -t binary_file
```

### file
```bash
# Identify file type
file unknown_binary

# Verbose output
file -v binary_file
```

## Network Analysis

### Wireshark/tshark
```bash
# Capture packets
tshark -i eth0 -w capture.pcap

# Filter HTTP traffic
tshark -r capture.pcap -Y "http"

# Extract HTTP objects
tshark -r capture.pcap --export-objects http,output_dir
```

### nmap
```bash
# Port scan
nmap -sS target_ip

# Service version detection
nmap -sV target_ip

# Script scan
nmap -sC target_ip
```

### curl
```bash
# Send HTTP requests
curl -X POST -d "data=value" http://target.com/api

# Save response headers
curl -D headers.txt http://target.com

# Follow redirects with verbose output
curl -Lv http://target.com
```

## Android Debugging

### ADB (Android Debug Bridge)
```bash
# List devices
adb devices

# Install APK
adb install app.apk

# Pull files from device
adb pull /data/data/com.app/file.db

# Push files to device
adb push local_file /sdcard/

# Shell access
adb shell

# Logcat monitoring
adb logcat | grep "MyApp"

# Forward ports
adb forward tcp:8080 tcp:8080
```

### Frida
```bash
# List running processes
frida-ps -U

# Attach to process
frida -U -n "com.example.app" -l script.js

# Spawn and attach
frida -U -f "com.example.app" -l script.js --no-pause

# Trace function calls
frida-trace -U -i "open*" com.example.app
```

## Web Application Testing

### Burp Suite CLI
```bash
# Run headless scan
java -jar burpsuite_pro.jar --project-file=project.burp --unpause-spider-and-scanner
```

### OWASP ZAP
```bash
# Quick scan
zap-baseline.py -t http://target.com

# Full scan
zap-full-scan.py -t http://target.com
```

### sqlmap
```bash
# Test for SQL injection
sqlmap -u "http://target.com/page?id=1"

# Dump database
sqlmap -u "http://target.com/page?id=1" --dump

# Get shell
sqlmap -u "http://target.com/page?id=1" --os-shell
```

## Assembly & Disassembly

### radare2
```bash
# Open binary for analysis
r2 binary_file

# Analyze all functions
r2 -A binary_file

# Disassemble function
r2 -c "pdf @ main" binary_file

# Search for strings
r2 -c "iz" binary_file
```

### Ghidra (CLI via headless)
```bash
# Analyze binary
analyzeHeadless project_dir project_name -import binary_file -postScript analyze.py
```

## Memory Analysis

### Volatility
```bash
# Identify OS profile
volatility -f memory.dump imageinfo

# List processes
volatility -f memory.dump --profile=Win7SP1x64 pslist

# Dump process memory
volatility -f memory.dump --profile=Win7SP1x64 memdump -p PID -D output_dir
```

## Cryptography

### OpenSSL
```bash
# Generate RSA key
openssl genrsa -out private.pem 2048

# View certificate details
openssl x509 -in cert.pem -text -noout

# Encrypt/decrypt files
openssl enc -aes-256-cbc -in file.txt -out file.enc
openssl enc -d -aes-256-cbc -in file.enc -out file.txt
```

### hashcat
```bash
# Crack MD5 hashes
hashcat -m 0 hashes.txt wordlist.txt

# Crack WPA/WPA2
hashcat -m 2500 capture.hccapx wordlist.txt
```

## File System Analysis

### dd
```bash
# Create disk image
dd if=/dev/sda of=disk_image.dd bs=4096

# Extract specific sectors
dd if=disk_image.dd of=boot_sector.bin bs=512 count=1
```

### binwalk
```bash
# Analyze firmware
binwalk firmware.bin

# Extract embedded files
binwalk -e firmware.bin

# Search for specific signatures
binwalk --signature firmware.bin
```

## Windows PE Analysis

### PE-bear (CLI alternatives)
```bash
# Using objdump for PE files
objdump -p pe_file.exe

# Using strings
strings pe_file.exe | grep -i "dll"
```

## Useful One-liners

### Find SUID binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```

### Search for passwords in files
```bash
grep -r -i "password" /path/to/search/
```

### Monitor file changes
```bash
inotifywait -m -r -e modify /path/to/monitor/
```

### Extract URLs from text
```bash
grep -oP 'https?://[^\s]+' file.txt
```

### Base64 decode/encode
```bash
echo "encoded_string" | base64 -d
echo "plain_text" | base64
```

## Quick Setup Commands

### Install essential tools (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install wireshark tshark nmap curl git python3-pip
pip3 install frida-tools
```

### Download and setup APKTool
```bash
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar
chmod +x apktool
sudo mv apktool /usr/local/bin/
sudo mv apktool_2.7.0.jar /usr/local/bin/apktool.jar
```

### Setup JADX
```bash
wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
unzip jadx-1.4.7.zip
sudo mv jadx/bin/jadx /usr/local/bin/
```

## Essential Environment Variables

```bash
# Add tools to PATH
export PATH=$PATH:/opt/tools/bin

# Android SDK
export ANDROID_HOME=/opt/android-sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools

# Java (if needed)
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk
```