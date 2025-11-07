<div align="center">

# 🏭 SCADA Network Risk Assessment System

### *A Comprehensive Industrial Control System Security Testing & Analysis Platform*

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Status](https://img.shields.io/badge/status-stable-success.svg)
![Security](https://img.shields.io/badge/security-testing-red.svg)
![Devices](https://img.shields.io/badge/devices-14-brightgreen.svg)
![Protocols](https://img.shields.io/badge/protocols-5-blue.svg)
![Vendors](https://img.shields.io/badge/vendors-8-orange.svg)

**🎯 Purpose:** Comprehensive ICS Security Testing & Risk Assessment Platform
**✅ Version:** 3.0 - All Bugs Fixed - Production Ready

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

This system provides a **comprehensive security testing platform** for **SCADA** (Supervisory Control and Data Acquisition) and **Industrial Control Systems (ICS)**. It simulates 14 real industrial devices from 8 major vendors, performs vulnerability scanning, integrates with the **NIST National Vulnerability Database (NVD)**, and includes advanced features like **Intrusion Detection System (IDS)**, **AI-powered analysis**, and **attack simulation** capabilities.

<div align="center">

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ 🔧 Device Simulation → 📦 Packet Capture → 🔬 IDS Analysis → 🔍 Vulnerability │
│ Scan → 🛡️ NIST Risk Assessment → 🤖 AI Analysis → 📊 Recommendations        │
└──────────────────────────────────────────────────────────────────────────────┘
```

</div>

### 🎯 Key Highlights

> **✨ Real Network Traffic** - Authentic SCADA protocol simulation
> **🏢 Multi-Vendor Support** - 14 devices from 8 major vendors
> **🔐 NVD Integration** - Real-time CVE data from NIST
> **📈 Risk Assessment** - Comprehensive NIST-based security analysis
> **🌐 Network Scanner** - Active vulnerability detection
> **💻 Interactive GUI** - PyQt6-based interface with 10 specialized tabs
> **🔬 IDS Integration** - Built-in Intrusion Detection System
> **🤖 AI-Powered Analysis** - Intelligent vulnerability prediction
> **⚠️ Attack Simulation** - Security testing and penetration testing tools

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
- Real-time traffic statistics and packet capture
- Support for Modbus TCP, DNP3, S7comm, EtherNet/IP

</td>
<td width="50%">

#### 🔍 **Vulnerability Assessment**
- NVD CVE database integration (NIST API 2.0)
- CVSS score analysis (v2, v3.0, v3.1)
- Real-time vulnerability scanning
- NIST-based risk scoring framework
- Device-specific vulnerability search

</td>
</tr>
<tr>
<td width="50%">

#### 🖥️ **Interactive Interface**
- PyQt6-based modern GUI
- 10 specialized monitoring tabs
- Real-time data visualization
- Comprehensive device management console
- Export reports and diagnostics

</td>
<td width="50%">

#### 🔧 **Device Management**
- 14 pre-configured industrial devices
- 8 major vendor support (ABB, Siemens, Rockwell, Schneider, GE, Honeywell, Mitsubishi, Omron)
- Protocol-specific handlers
- Dynamic port configuration
- Start/stop controls per device

</td>
</tr>
<tr>
<td width="50%">

#### 🔬 **Advanced Security Features**
- Intrusion Detection System (IDS)
- Packet analysis and inspection
- Attack simulation capabilities
- Network anomaly detection
- Security event logging

</td>
<td width="50%">

#### 🤖 **AI & Analytics**
- AI-powered vulnerability prediction
- Automated security recommendations
- Risk trend analysis
- Compliance assessment
- Remediation guidance

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

| Device ID | Vendor | Device Model | Protocol | Default Port | Status |
|:---------:|:------:|:-------------|:--------:|:------------:|:------:|
| **RTU_001** | **ABB** | RTU560 | Modbus TCP | 502 | ✅ |
| **RTU_002** | **Schneider Electric** | ION7650 | DNP3 | 20000 | ✅ |
| **PLC_001** | **Siemens** | S7-1200 | S7comm | 102 | ✅ |
| **PLC_002** | **Siemens** | S7-300 | S7comm | 1102 | ✅ |
| **PLC_003** | **Siemens** | S7-1500 | S7comm | 2102 | ✅ |
| **AB_001** | **Rockwell** | MicroLogix | EtherNet/IP | 44818 | ✅ |
| **AB_002** | **Rockwell** | CompactLogix | EtherNet/IP | 44819 | ✅ |
| **MOD_001** | **Schneider** | Modicon M340 | Modicon | 5020 | ✅ |
| **MOD_002** | **Schneider** | Modicon M580 | Modicon | 5021 | ✅ |
| **GE_001** | **GE** | Multilin SR489 | DNP3/Modbus | 5030 | ✅ |
| **GE_002** | **GE** | Multilin D60 | DNP3/Modbus | 5031 | ✅ |
| **HON_001** | **Honeywell** | HC900 | Modbus | 5040 | ✅ |
| **MIT_001** | **Mitsubishi** | FX5U | Modbus | 5007 | ✅ |
| **OMR_001** | **Omron** | NJ-series | EtherNet/IP | 9600 | ✅ |

**Total: 14 Devices | 8 Vendors | 5 Protocols**

</div>

---

## 🏗️ System Architecture

<div align="center">

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                       🖥️  GUI Interface (PyQt6)                               │
├──────────────────────────────────────────────────────────────────────────────┤
│ 📊 Monitor │ ⚙️ Devices │ 📦 Packets │ 🔬 IDS │ 🔍 Scanner │ 🛡️ Vuln Assessment │
│ 🛡️ NIST Risk │ 📋 Recommendations │ 🤖 AI Analysis │ ⚠️ Attack Simulator      │
└────────┬─────────────────────────────────────────────────────────┬───────────┘
         │                                                          │
    ┌────▼──────────────────────────────────────────────────────────▼─────┐
    │                    🎮 SCADA Server Core                              │
    │  • Device Management       • Traffic Monitoring & Packet Capture     │
    │  • Protocol Handlers       • Risk Calculation Engine                 │
    │  • IDS Engine             • Attack Simulation Framework              │
    └────┬────────────────────────────────────────────────────┬────────────┘
         │                                                    │
    ┌────▼────────────────────────┐            ┌─────────────▼──────────────┐
    │  🔌 Device Simulators (14)   │            │  🌐 NVD API Client         │
    │  • Modbus TCP (5 devices)   │            │  • CVE Database (NIST 2.0) │
    │  • DNP3 (3 devices)         │            │  • CVSS v2/v3.0/v3.1       │
    │  • S7comm (3 devices)       │            │  • Vulnerability Search    │
    │  • EtherNet/IP (3 devices)  │            │  • Device-specific CVEs    │
    └─────────────────────────────┘            └────────────────────────────┘
```

</div>

### 📦 Main Components

| Component | Description | Technology |
|-----------|-------------|------------|
| 🔌 **NVD API Client** | Fetches real CVE vulnerability data from NIST API v2.0 | REST API, Requests |
| 🏭 **Device Simulators** | Implements protocol-specific device behavior for 14 devices | Python Sockets, Threading |
| 🖧 **SCADA Server** | Manages multiple device instances with traffic monitoring | Threading, QObject Signals |
| 🔍 **Network Scanner** | Performs active vulnerability and port scanning | Socket Programming |
| 📊 **Risk Assessment Engine** | NIST-based risk framework with CVSS analysis | CVSS v2/v3.0/v3.1 |
| 🔬 **IDS Engine** | Intrusion Detection System with packet analysis | Pattern Matching |
| 🤖 **AI Assessment** | Intelligent vulnerability prediction and analysis | AI Algorithms |
| ⚠️ **Attack Simulator** | Security testing with multiple attack vectors | Protocol Simulation |
| 💻 **GUI Interface** | Multi-tab monitoring and control (10 tabs) | PyQt6 |

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
cd SCADA_SECURITY_LAB
```

#### **Step 2: Install Dependencies**

```bash
pip install PyQt6 requests
```

#### **Step 3: Run the Application**

```bash
python scada_risk_system.py
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
python scada_risk_system.py
```

> ✅ The system automatically configures **14 default devices** on startup

#### **2️⃣ Navigate Through Tabs**

| Tab | Icon | Purpose |
|-----|:----:|---------|
| **SCADA Monitor** | 📊 | View real-time device status, measurements, and traffic statistics |
| **Device Manager** | ⚙️ | Enable/disable devices, configure ports, start/stop services |
| **Packets** | 📦 | Monitor network packet traffic in real-time |
| **Packet Analysis (IDS)** | 🔬 | Intrusion Detection System with packet analysis and threat detection |
| **Network Scanner** | 🔍 | Scan for vulnerabilities, open ports, and network devices |
| **Vulnerability Assessment** | 🛡️ | Search CVEs, view risk assessments, and analyze security issues |
| **NIST Risk Assessment** | 🛡️ | Comprehensive NIST-based risk analysis framework |
| **Analysis Recommendations** | 📋 | Automated security recommendations and remediation guidance |
| **AI Assessment** | 🤖 | AI-powered security analysis and vulnerability prediction |
| **Attack Simulator** | ⚠️ | Simulate various attack scenarios for security testing |

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

The SCADA Network Risk Assessment System is a comprehensive security testing and analysis platform designed to help security professionals, researchers, and industrial control system engineers identify and assess vulnerabilities in critical infrastructure.

**Key Capabilities:**
- ✅ **14 Industrial Device Simulators** - Authentic protocol implementations from 8 major vendors
- ✅ **Real-time Vulnerability Assessment** - NIST NVD integration with CVE tracking
- ✅ **Intrusion Detection System** - Built-in IDS with packet analysis and threat detection
- ✅ **NIST Risk Framework** - Comprehensive risk scoring based on NIST guidelines
- ✅ **AI-Powered Analysis** - Intelligent vulnerability prediction and security insights
- ✅ **Attack Simulation** - Security testing with multiple attack vectors
- ✅ **Network Traffic Analysis** - Real-time packet capture and protocol inspection
- ✅ **Automated Recommendations** - Actionable security guidance and remediation steps

**Platform Features:**
- 🔧 **10 Specialized Tabs** - Comprehensive monitoring and analysis interfaces
- 🌐 **5 Protocol Support** - Modbus TCP, DNP3, S7comm, EtherNet/IP, Modicon
- 📊 **Real-time Monitoring** - Live device status, measurements, and traffic statistics
- 🛡️ **CVSS v2/v3.0/v3.1** - Multi-version vulnerability scoring support
- 📈 **Export Capabilities** - Generate comprehensive security reports

This platform provides security teams with professional-grade tools needed to proactively identify, analyze, and mitigate risks in critical infrastructure and industrial control system environments.

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

| Device Type | Count | Vendors | Models |
|:-----------:|:-----:|:--------|:-------|
| 🔧 **Modbus TCP** | 5 | ABB, Honeywell, Mitsubishi, GE | RTU560, HC900, FX5U, Multilin |
| ⚡ **DNP3** | 3 | Schneider, GE | ION7650, SR489, D60 |
| 🏭 **Siemens S7** | 3 | Siemens | S7-1200, S7-300, S7-1500 |
| 🔌 **EtherNet/IP** | 3 | Rockwell, Omron | MicroLogix, CompactLogix, NJ-series |
| 🔩 **Modicon** | 2 | Schneider | M340, M580 |

**Total: 14 Devices across 8 Vendors**

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
