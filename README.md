<div align="center">

# 🏭 SCADA Network Risk Assessment System

### *A Comprehensive Industrial Control System Security Platform*

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Status](https://img.shields.io/badge/status-stable-success.svg)
![Security](https://img.shields.io/badge/security-testing-red.svg)

**🎯 Purpose:** Advanced Risk Assessment and Security Testing for SCADA Networks
**✅ Version:** 3.0 - Production Ready

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [System Architecture](#-system-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Supported Devices](#-supported-devices--vendors)
- [Configuration](#-configuration)
- [Security](#-security-considerations)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

---

## 🌟 Overview

This system provides a **complete environment** for assessing security risks in **SCADA** (Supervisory Control and Data Acquisition) networks. It simulates real industrial devices, performs vulnerability scanning, and integrates with the **National Vulnerability Database (NVD)** to provide accurate security assessments.

<div align="center">

```
┌─────────────────────────────────────────────────────────────┐
│  🔧 Device Simulation  →  🔍 Vulnerability Scan  →  📊 Risk Analysis  │
└─────────────────────────────────────────────────────────────┘
```

</div>

### 🎯 Key Highlights

> **✨ Real Network Traffic** - Authentic SCADA protocol simulation
> **🏢 Multi-Vendor Support** - 14+ devices from 8+ major vendors
> **🔐 NVD Integration** - Real-time CVE data from NIST
> **📈 Risk Assessment** - Comprehensive security analysis
> **🌐 Network Scanner** - Active vulnerability detection
> **💻 Interactive GUI** - PyQt6-based interface

---

## 🚀 Features

### 🎨 Core Capabilities

<table>
<tr>
<td width="50%">

#### 🌐 **Network Simulation**
- Real network traffic generation
- Authentic SCADA protocol packets
- Multi-device orchestration
- Traffic statistics tracking

</td>
<td width="50%">

#### 🔍 **Vulnerability Assessment**
- NVD CVE database integration
- CVSS score analysis
- Real-time vulnerability scanning
- Risk scoring algorithms

</td>
</tr>
<tr>
<td width="50%">

#### 🖥️ **Interactive Interface**
- PyQt6-based modern GUI
- Multiple monitoring tabs
- Real-time data visualization
- Device management console

</td>
<td width="50%">

#### 🔧 **Device Management**
- 14+ pre-configured devices
- Protocol-specific handlers
- Port configuration
- Enable/disable controls

</td>
</tr>
</table>

---

## 🔌 Supported Industrial Protocols

<div align="center">

| Protocol | Description | Icon | Port |
|:--------:|:------------|:----:|:----:|
| **Modbus TCP** | Standard industrial communication | 🔧 | 502 |
| **DNP3** | Distributed Network Protocol (Power) | ⚡ | 20000 |
| **S7comm** | Siemens proprietary protocol | 🏭 | 102 |
| **EtherNet/IP** | Rockwell Automation protocol | 🔌 | 44818 |
| **Modicon** | Schneider Electric protocol | 🔩 | 502 |

</div>

---

## 🏭 Supported Devices & Vendors

<div align="center">

| Vendor | Device Model | Protocol | Default Port | Status |
|:------:|:-------------|:--------:|:------------:|:------:|
| **ABB** | RTU560 | Modbus TCP | 502 | ✅ |
| **SEL** | SEL-3622 | DNP3 | 20000 | ✅ |
| **Siemens** | S7-1200 | S7comm | 102 | ✅ |
| **Rockwell** | CompactLogix | EtherNet/IP | 44818 | ✅ |
| **Schneider** | Modicon M580 | Modicon | 502 | ✅ |
| **GE** | Multilin 850 | DNP3 | 20000 | ✅ |
| **Honeywell** | HC900 | Modbus | 502 | ✅ |
| **Mitsubishi** | FX5U | Modbus | 502 | ✅ |
| **Omron** | NJ-series | EtherNet/IP | 44818 | ✅ |

</div>

---

## 🏗️ System Architecture

<div align="center">

```
┌─────────────────────────────────────────────────────────────────┐
│                     🖥️  GUI Interface (PyQt6)                    │
├─────────────────────────────────────────────────────────────────┤
│  📊 Monitor  │  🔧 Devices  │  🔍 Scanner  │  🛡️  Vulnerabilities │
└────────┬────────────────────────────────────────────────┬────────┘
         │                                                │
    ┌────▼────────────────────────────────────────────────▼─────┐
    │              🎮 SCADA Server Core                         │
    │  • Device Management    • Traffic Monitoring              │
    │  • Protocol Handlers    • Risk Calculation                │
    └────┬──────────────────────────────────────────────────┬───┘
         │                                                  │
    ┌────▼────────────────────┐              ┌─────────────▼──────┐
    │  🔌 Device Simulators    │              │  🌐 NVD API Client │
    │  • Modbus               │              │  • CVE Database    │
    │  • DNP3                 │              │  • CVSS Scores     │
    │  • S7comm               │              │  • Vulnerability   │
    │  • EtherNet/IP          │              │    Search          │
    └─────────────────────────┘              └────────────────────┘
```

</div>

### 📦 Main Components

| Component | Description | Technology |
|-----------|-------------|------------|
| 🔌 **NVD API Client** | Fetches real CVE vulnerability data from NIST | REST API |
| 🏭 **Device Simulators** | Implements protocol-specific device behavior | Python Sockets |
| 🖧 **SCADA Server** | Manages multiple device instances | Threading |
| 🔍 **Network Scanner** | Performs active vulnerability scanning | Port Scanning |
| 📊 **Risk Assessment Engine** | Calculates security risk scores | CVSS Analysis |
| 💻 **GUI Interface** | Multi-tab monitoring and control | PyQt6 |

---

## 📥 Installation

### ⚙️ Requirements

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)
![PyQt6](https://img.shields.io/badge/PyQt6-6.0+-41CD52?style=flat&logo=qt&logoColor=white)

<details>
<summary>📋 <b>View Full Dependencies</b></summary>

```bash
# Core dependencies
PyQt6>=6.0.0
requests>=2.25.0

# Standard library (included with Python)
socket, threading, time, random, json, struct
datetime, collections, typing, logging
```

</details>

### 🔧 Installation Steps

#### **Step 1: Clone the Repository**

```bash
git clone <repository-url>
cd Scada
```

#### **Step 2: Install Dependencies**

```bash
pip install PyQt6 requests
```

#### **Step 3: Run the Application**

```bash
python "scada_risk_system (1).py"
```

> 💡 **Tip:** Use a virtual environment for cleaner dependency management!

---

## 🎮 Usage

### ⚡ Quick Start Guide

<div align="center">

```
1️⃣  Launch Application  →  2️⃣  Configure Devices  →  3️⃣  Run Scans  →  4️⃣  Analyze Results
```

</div>

#### **1️⃣ Launch the Application**

```bash
python "scada_risk_system (1).py"
```

> ✅ The system automatically configures **14 default devices** on startup

#### **2️⃣ Navigate Through Tabs**

| Tab | Icon | Purpose |
|-----|:----:|---------|
| **SCADA Monitor** | 📊 | View real-time device status and traffic |
| **Device Manager** | 🔧 | Enable/disable devices, configure ports |
| **Network Scanner** | 🔍 | Scan for vulnerabilities and open ports |
| **Vulnerability Analysis** | 🛡️ | Search CVEs and view risk assessments |

---

## ⚙️ Configuration

### 🔧 Device Manager

<details>
<summary><b>📝 Adding & Managing Devices</b></summary>

Use the **Device Manager** tab to:
- ✅ Enable/disable devices
- 🔌 Change port configurations
- 📈 Monitor traffic statistics
- 🔄 Restart device services

</details>

### 🔍 Network Scanner Configuration

```yaml
Configuration Options:
  ├─ Target IP Range: 192.168.1.0/24
  ├─ Port Range: 1-65535
  ├─ Scan Timeout: 1-10 seconds
  └─ Scan Type: Quick / Full / Custom
```

**Steps:**
1. 🎯 Go to the Scanner tab
2. ⚙️ Configure scan parameters
3. ▶️ Click "Start Scan"
4. 📊 Review detected devices and vulnerabilities

### 🛡️ Vulnerability Analysis

> **🔍 Search CVE Database**

Enter search terms to find vulnerabilities:
- 🏭 "SCADA"
- 🔧 "Modbus"
- 🏢 "ICS"
- ⚡ "DNP3"

**View Details:**
- 🆔 CVE ID
- 📊 CVSS Score
- ⚠️ Severity Rating
- 📝 Description
- 📅 Published Date

---

## 🔐 NVD API Integration

<div align="center">

![NVD](https://img.shields.io/badge/NVD-API_v2.0-blue?style=for-the-badge)
![NIST](https://img.shields.io/badge/NIST-Integrated-green?style=for-the-badge)

</div>

### 🌐 API Configuration

**Base URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0`

### 🔑 Setting up NVD API Key (Recommended)

<details>
<summary><b>📚 Click to Expand Setup Instructions</b></summary>

#### **Step 1: Request API Key**
Visit: https://nvd.nist.gov/developers/request-an-api-key

#### **Step 2: Configure Key**
Create a `.env` file:
```bash
NVD_API_KEY=your-api-key-here
```

#### **Step 3: Restart Application**

</details>

### 📊 Rate Limits

| Type | Rate Limit | Recommended For |
|:----:|:----------:|:----------------|
| ❌ **Without Key** | 5 req/30s | Testing |
| ✅ **With Key** | 50 req/30s | Production |

---

## 🛡️ Security Considerations

### ⚠️ Authorized Use Only

<div align="center">

> ⚠️ **IMPORTANT**: This tool is designed for authorized security testing only!

</div>

✅ **Appropriate Use Cases:**
- 🔐 Authorized penetration testing
- 🛡️ Security assessments and audits
- 🏭 Industrial control system vulnerability testing
- 📊 Risk assessment and compliance validation
- 🔬 Security research and development
- 📖 Security training and education

### ⚠️ Important Warnings

| Warning | Description |
|:-------:|:------------|
| 🔒 | **Only use on isolated networks** or with proper authorization |
| 🚫 | **Do not deploy on production SCADA systems** without permission |
| ✅ | **Complies with CVE/NVD terms of service** for vulnerability data |
| 🌐 | Simulated devices should **never be exposed to the internet** |

---

## 🔬 Technical Details

### 🏭 Device Simulation Architecture

Each device simulator includes:

```
┌─────────────────────────────────────┐
│  🔌 Protocol Handler                │
│  ├─ Packet parsing & generation    │
│  ├─ State management                │
│  └─ Response logic                  │
├─────────────────────────────────────┤
│  📊 Measurement Engine              │
│  ├─ Realistic sensor values        │
│  ├─ Value ranges & constraints     │
│  └─ Temporal variation              │
├─────────────────────────────────────┤
│  📈 Traffic Statistics              │
│  ├─ Packets sent/received          │
│  ├─ Bytes transferred               │
│  └─ Connection counts               │
└─────────────────────────────────────┘
```

### 📊 Risk Calculation Methodology

Risk scores are calculated based on:

| Factor | Weight | Description |
|--------|:------:|-------------|
| 🔴 **CVE Vulnerabilities** | 40% | Number and severity of known CVEs |
| 📊 **CVSS Scores** | 30% | Base severity scores |
| 🌐 **Network Exposure** | 20% | Port accessibility and exposure |
| 🔐 **Protocol Security** | 10% | Inherent protocol security features |

---

## 🐛 Troubleshooting

### ❌ Common Issues & Solutions

<details>
<summary><b>🔴 Port Already in Use</b></summary>

**Check for port conflicts:**

```bash
# Linux/Mac
netstat -an | grep <port>
lsof -i :<port>

# Windows
netstat -an | findstr <port>
```

**Solution:** Change the port in Device Manager or stop conflicting service.

</details>

<details>
<summary><b>⚠️ NVD API Rate Limiting</b></summary>

**Symptoms:** "Rate limit exceeded" errors

**Solutions:**
1. 🔑 Set up an NVD API key (increases limit to 50 req/30s)
2. ⏱️ Wait between searches
3. 💾 Use the built-in cache for repeated searches

</details>

<details>
<summary><b>🔌 Device Connection Issues</b></summary>

**Checklist:**
- ✅ Firewall not blocking localhost connections
- ✅ Ports are available (not bound by other processes)
- ✅ Device is enabled in Device Manager
- ✅ Correct protocol selected

</details>

---

## 📊 System Monitoring

### 📈 Real-time Metrics

The system tracks:

| Metric | Description | Update Frequency |
|--------|-------------|:----------------:|
| 📦 **Packets** | Sent/received count | Real-time |
| 💾 **Bytes** | Data transfer volume | Real-time |
| 🔌 **Connections** | Active connections | Real-time |
| 📊 **Protocol Data** | Protocol-specific metrics | Real-time |

### 📝 Logging

```
Format: [timestamp] - [component] - [level] - [message]
Level: INFO
Output: Console + Application logs
```

---

## 📖 About This Project

The SCADA Network Risk Assessment System is a comprehensive security testing platform designed to help security professionals identify and assess vulnerabilities in industrial control systems.

**Key Capabilities:**
- ✅ Multi-vendor SCADA device simulation
- ✅ Real-time vulnerability assessment
- ✅ NIST NVD integration for CVE tracking
- ✅ Comprehensive risk scoring algorithms
- ✅ Professional-grade security analysis tools

This platform provides security teams with the tools needed to proactively identify and mitigate risks in critical infrastructure environments.

---

## 📚 Additional Resources

### 📖 Documentation

- 📘 [SCADA Protocols Guide](https://en.wikipedia.org/wiki/SCADA)
- 📗 [NVD API Documentation](https://nvd.nist.gov/developers)
- 📕 [CVE Database](https://cve.mitre.org/)
- 📙 [ICS-CERT Advisories](https://www.cisa.gov/ics)

### 🔗 Related Standards

- ⚙️ IEC 62443 - Industrial Communication Networks Security
- 🔐 NIST SP 800-82 - Guide to ICS Security
- 📊 ISO 27001 - Information Security Management

---

## 📦 Known Devices Configuration

On startup, the system auto-configures:

<div align="center">

| Device Type | Count | Vendors |
|:-----------:|:-----:|:--------|
| 🔧 **Modbus RTU** | 2 | ABB, Honeywell |
| ⚡ **DNP3 RTU** | 2 | SEL, GE |
| 🏭 **S7 PLC** | 3 | Siemens (multiple ports) |
| 🔌 **Rockwell PLC** | 2 | Different ports |
| 🔩 **Schneider Modicon** | 2 | Primary/Secondary |
| 🏢 **Mitsubishi PLC** | 1 | Standard config |
| 🔧 **Omron PLC** | 1 | Standard config |

**Total: 14 Devices**

</div>

---

## 🤝 Contributing

Contributions and feedback are welcome! To get involved:

- 📧 Review the code documentation
- 🐛 Report bugs and issues
- ✅ Ensure all dependencies are installed correctly
- 💬 Submit feature requests or improvements
- 🔧 Follow secure coding practices
- 📝 Document any new features or changes

---

## 📄 License

<div align="center">

![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

**Open Source Security Testing Platform**

⚠️ Use responsibly and only on authorized systems

</div>

---

## 📞 Technical Support

### 🆘 Getting Help

1. 📋 Check the application logs
2. ✅ Verify all dependencies are installed
3. 🌐 Ensure proper network configuration
4. 📖 Review the [Troubleshooting](#-troubleshooting) section

---

## 📌 Version History

<div align="center">

| Version | Status | Features |
|:-------:|:------:|:---------|
| **v3.0** | ✅ Current | All bugs fixed, complete implementation |
| | | NVD integration, multi-vendor support, full GUI |

</div>

---

<div align="center">

### ⚠️ **Important Notice**

**This is a professional security testing and simulation platform.**
**Always use responsibly and only on authorized networks.**

**Legal Notice:** Unauthorized access to computer systems is illegal. This tool is provided for legitimate security testing purposes only.

---

Built for Industrial Cybersecurity Professionals

![SCADA](https://img.shields.io/badge/SCADA-Security-red?style=for-the-badge)
![ICS](https://img.shields.io/badge/ICS-Testing-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-Powered-green?style=for-the-badge&logo=python&logoColor=white)

---

**🌟 Star this repository if you find it useful for your security assessments! 🌟**

</div>
