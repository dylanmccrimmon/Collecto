# Collecto

> [!CAUTION]
> This project is in its **beta phase** and may undergo significant changes. Use with care in production environments.
>

**Collecto** is a powerful PowerShell script designed to gather detailed hardware, software, and security information from Windows devices. Built for IT administrators, MSPs, and network managers, it provides a quick and automated way to inventory devices, check Windows 11 readiness, and capture hardware hashes for Intune registration. **Collecto** supports on-demand execution, scheduled reporting, and periodic check-ins—ensuring up-to-date insights without storing any data locally. With near no dependency on external PowerShell modules, it leverages CIM commands for efficient and direct system querying, making it efficient and highly compatible across Windows environments.

## 🚀 Features
- Collects **hardware details** such as device manufacturer, model, CPU, RAM, storage, TPM, etc.
- Retrieves **Windows licensing, activation status, and OS details**.
- Checks **Windows 11 readiness** by evaluating system hardware.
- Gathers **network information**, including MAC addresses and firewall status.
- Captures hardware hashes to assist IT admins in registering devices with Intune.
- Checks compliance items such as **firewall status**, installed **anti-virus software** and **encryption status**.
- Can be used for:
  - **One-time collection**
  - **Scheduled data collection** (via Task Scheduler)
  - **Periodic check-ins** with an API endpoint to determine when to report data.
- **No local data storage** — data is only sent to a configured reporting URL.

## 📌 Requirements
- **Windows (PowerShell 5.1+ or PowerShell Core)**
- **Administrator privileges** (recommended for full data access)
- **Internet access** (if using an external API for reporting)

## 🏃 Usage
Run the script with the required parameters:
```powershell
.\Collecto.ps1 -CustomerName "Acme Corp" -SiteName "London Office" -ReportingURL "https://api.example.com/report" -CheckInURL "https://api.example.com/checkin"
```
### Parameters:
| Parameter       | Description                                   | Required |
|----------------|-----------------------------------------------|----------|
| `-CustomerName` | The customer name for reference.            | ✅ Yes   |
| `-SiteName`     | The site or location name.                   | ✅ Yes   |
| `-ReportingURL` | The API endpoint to send collected data.     | ✅ Yes   |
| `-CheckInURL`   | (Optional) API endpoint to check-in first to check if data collection is required.   | ❌ No    |

### Example Output (JSON)
The output includes a **unique_device_id_hash**, which is a consistent, anonymized identifier used to recognize a physical device across reinstalls and resets.
You can [learn more about how it's generated](Docs/Unique%20Device%20ID%20Hash.md) and what makes it reliable.
```json
{
  "unique_device_id_hash": "50297CF6717C9A1089D6597E062ADDEBDCB8841BC410764FBF0A119B7C171D54",
  "organisation_name": "Acme Corp",
  "site_name": "London Office",
  "device_info": {
    "hostname": "DESKTOP-NAGRSK3",
    "management_state": "Standalone"
  },
  "os": {
    "platform": "Windows",
    "version": "10.0.22631",
    "version_display": "23H2",
    "edition": "EDUCATION",
    "sku": "Microsoft Windows 11 Education",
    "language": "English (United States)",
    "architecture": "64-bit",
    "activation": {
      "status": "Licensed",
      "type": "Volume:GVLK",
      "oem_product_key": "None found",
      "oem_product_key_description": ""
    }
  },
  "hardware": {
    "manufacturer": "Dell Inc.",
    "family": "Latitude",
    "model": "Latitude 3190",
    "type": "Desktop",
    "serial_number": "VMware-56 4d 95 9e",
    "cpu": [
      {
        "name": "Intel(R) N100",
        "manufacturer": "GenuineIntel",
        "architecture": "x64",
        "base_frequency_ghz": 0.81,
        "total_cores": 1,
        "total_threads": 1
      },
      {
        "name": "Intel(R) N100",
        "manufacturer": "GenuineIntel",
        "architecture": "x64",
        "base_frequency_ghz": 0.81,
        "total_cores": 1,
        "total_threads": 1
      }
    ],
    "ram": {
      "installed_gb": 8,
      "speed_mhz": 2400
    },
    "storage": {
      "os_disk": {
        "type": "SSD",
        "size_gb": 100
      },
      "os_volume": {
        "free_gb": 41,
        "total_gb": 99,
        "file_system": "NTFS"
      }
    },
    "battery": {
      "present": true,
      "cycle_count": 46,
      "health_percentage": 88,
      "designed_capacity_whr": 42,
      "current_capacity_whr": 37,
      "chemistry": "Unknown",
      "manufacturer": "SMP",
      "serial_number": "317"
    },
    "firmware": {
      "type": "UEFI",
      "version": "1.12.2",
      "manufacturer": "Dell Inc."
    },
    "network_adapters": [
      {
        "type": "Ethernet",
        "mac_address": "00-00-00-00-00-00",
        "description": "Intel(R) 82574L Gigabit Network Connection"
      },
      {
        "type": "Wi-Fi",
        "mac": "DC-00-00-00-00-00",
        "description": "Intel Dual Band Wireless-AC 8265"
      }
    ]
  },
  "security": {
    "security_chip": {
      "present": "Present",
      "type": "TPM",
      "version": "2.0",
      "manufacturer_id": "INTC",
      "manufacturer_version": "403.0.0.0"
    },
    "secure_boot": "Enabled",
    "os_encryption": {
      "status": "No Protection",
      "method": null
    },
    "antivirus": "Windows Defender",
    "firewall_status": "Enabled"
  },
  "platform_specific": {
    "windows": {
      "autopilot_hardware_hash": "T0GnAgEAHAAAAAoA3hJdWAAAC....",
      "windows_11_readiness": {
        "status": "Not Ready",
        "failed_checks": "CPU Clock Speed,CPU Logical Cores"
      }
    }
  }
}
```

## 🔄 Automation

## 🔒 Security & Privacy
- **No local data is stored**—data is only transmitted to the configured API.
- **Product keys are masked** before transmission.

## 🔮 Future Plans
- Enhancements based on community feedback.

## 📚 License
This project is licensed under the [MIT License](LICENSE).  
Feel free to use, modify, and share it — just include attribution.

---

🚀 **Collecto** – An efficient and comprehensive device inventory solution for IT professionals.

