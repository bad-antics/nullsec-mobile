<!-- 
SEO Keywords: NullSec Mobile, Android security app, iOS security app, mobile pentesting,
network scanner app, WiFi analyzer, packet capture, mobile hacking tools, security toolkit,
penetration testing mobile, Android hacking, iOS security research, mobile red team,
bad-antics, AnonAntics, NullSec Framework, mobile security suite
-->

<div align="center">

# 📱 NullSec Mobile

### Security Toolkit for Android & iOS

[![Discord](https://img.shields.io/badge/🔑_GET_KEYS-discord.gg/killers-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/killers)
[![Twitter](https://img.shields.io/badge/Twitter-@AnonAntics-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://twitter.com/AnonAntics)
[![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/bad-antics/nullsec-mobile)
[![iOS](https://img.shields.io/badge/iOS-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/bad-antics/nullsec-mobile)

```
 ███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗███████╗ ██████╗
 ████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔════╝██╔════╝
 ██╔██╗ ██║██║   ██║██║     ██║     ███████╗█████╗  ██║     
 ██║╚██╗██║██║   ██║██║     ██║     ╚════██║██╔══╝  ██║     
 ██║ ╚████║╚██████╔╝███████╗███████╗███████║███████╗╚██████╗
 ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝
                    [ MOBILE SECURITY SUITE ]
```

### 🔓 **[Join discord.gg/killers](https://discord.gg/killers)** for premium features & support!

</div>

---

## 🎯 Features

| Tool | Android | iOS | Description |
|------|:-------:|:---:|-------------|
| 🔍 **Network Scanner** | ✅ | ✅ | Discover devices, open ports, services |
| 📶 **WiFi Analyzer** | ✅ | ⚠️ | Signal strength, channel analysis, security |
| 🌐 **Packet Capture** | ✅ | ⚠️ | Network traffic analysis (root required) |
| 🔐 **Hash Tools** | ✅ | ✅ | Generate & crack common hashes |
| 🔑 **Password Gen** | ✅ | ✅ | Secure password generator |
| 📡 **Ping/Trace** | ✅ | ✅ | Network diagnostics |
| 🛡️ **Vuln Scanner** | ✅ | ✅ | Check for common vulnerabilities |
| 📋 **Clipboard Monitor** | ✅ | ❌ | Monitor clipboard for sensitive data |
| 🔓 **Crypto Tools** | ✅ | ✅ | Encode/decode, encrypt/decrypt |
| 📱 **Device Info** | ✅ | ✅ | Hardware, software, security info |

⚠️ = Limited functionality due to OS restrictions

---

## 📦 Installation

### Android

```bash
# Download APK from releases
# Or build from source:
cd android
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

### iOS

```bash
# Requires Xcode and Apple Developer account
cd ios
pod install
open NullSec.xcworkspace
# Build and run on device
```

---

## 🛠️ Tools Overview

### 🔍 Network Scanner

Fast multi-threaded network discovery:
- ARP scan for local network
- TCP/UDP port scanning
- Service detection
- OS fingerprinting
- Export results to JSON/CSV

### 📶 WiFi Analyzer

Comprehensive wireless analysis:
- Signal strength mapping
- Channel overlap detection
- Security type identification
- Hidden network detection
- WPS vulnerability check

### 🔐 Hash Tools

Hash generation and analysis:
- MD5, SHA1, SHA256, SHA512
- NTLM, bcrypt support
- Hash identification
- Rainbow table lookup (premium)

### 🔓 Crypto Tools

Encoding and encryption:
- Base64, Base32, Hex
- AES, RSA encryption
- JWT decode/encode
- Certificate analysis

---

## 📂 Project Structure

```
nullsec-mobile/
├── android/
│   ├── app/
│   │   └── src/main/
│   │       ├── java/com/nullsec/mobile/
│   │       │   ├── MainActivity.kt
│   │       │   ├── tools/
│   │       │   │   ├── NetworkScanner.kt
│   │       │   │   ├── WifiAnalyzer.kt
│   │       │   │   ├── HashTools.kt
│   │       │   │   └── CryptoTools.kt
│   │       │   └── ui/
│   │       └── res/
│   └── build.gradle
├── ios/
│   └── NullSec/
│       ├── Tools/
│       ├── Views/
│       └── Models/
├── shared/
│   └── algorithms/
└── assets/
```

---

## 🔑 Premium Features

Some features require a **premium key** from Discord:

| Feature | Free | Premium |
|---------|:----:|:-------:|
| Network Scanner | 10 hosts | Unlimited |
| Port Scan Range | 1-1024 | 1-65535 |
| Hash Cracking | 1000 hashes | Unlimited |
| Export Results | JSON only | JSON/CSV/XML |
| Ad-Free | ❌ | ✅ |
| Priority Support | ❌ | ✅ |

### 🎮 **[Get Premium at discord.gg/killers](https://discord.gg/killers)**

---

## ⚠️ Requirements

### Android
- Android 8.0+ (API 26)
- Root access for some features
- Location permission for WiFi scanning

### iOS
- iOS 14.0+
- Jailbreak for advanced features
- Network extension entitlements

---

## 🔧 Building from Source

### Android

```bash
# Clone repo
git clone https://github.com/bad-antics/nullsec-mobile.git
cd nullsec-mobile/android

# Build debug APK
./gradlew assembleDebug

# Build release APK (requires signing)
./gradlew assembleRelease
```

### iOS

```bash
cd nullsec-mobile/ios
pod install
xcodebuild -workspace NullSec.xcworkspace -scheme NullSec -configuration Release
```

---

## ⚠️ Disclaimer

This app is for **authorized security testing** and **educational purposes** only.

- Only scan networks you own or have permission to test
- Respect privacy and local laws
- The developers are not responsible for misuse

---

<div align="center">

### 💀 NullSec Mobile - Part of the NullSec Framework

[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=for-the-badge&logo=github)](https://github.com/bad-antics)
[![Discord](https://img.shields.io/badge/🔑_DISCORD-discord.gg/killers-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/killers)

**© 2025-2026 [@AnonAntics](https://twitter.com/AnonAntics)**

### 🔓 **[JOIN DISCORD FOR PREMIUM KEYS](https://discord.gg/killers)** 🔓

</div>
