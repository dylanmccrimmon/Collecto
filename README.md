# Collecto

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
```json
{
    "unique_device_id_hash": "28EB2A2502B5E9508C5DE255668FEDC9265F8084E1CA631CFAC88AC1E4479543",
    "customer_name": "Acme Corp",
    "site_name": "London Office",
    "computer_name": "DESKTOP-12345",
    "windows_activation_type": "Volume:MAK",
    "windows_original_product_key": "*****-*****-*****-*****-63CJB",
    "windows_original_product_key_description": "[4.0] ProfessionalEducation OEM:DM",
    "operating_system": "Windows",
    "operating_system_version": "10.0.19042",
    "operating_system_display_version": "20H2",
    "operating_system_language": "English (United Kingdom)",
    "operating_system_edition": "EDUCATION",
    "operating_system_sku": "Microsoft Windows 10 Education",
    "storage_total_space_gb": 57,
    "storage_free_space_gb": 15,
    "operating_system_disk_size_gb": 58,
    "operating_system_disk_type": "SSD",
    "physical_memory_total_gb": 4,
    "device_manufacturer": "Dell Inc.",
    "device_family": "Latitude",
    "device_model": "Latitude 3190",
    "device_type": "Laptop",
    "processor": "Intel(R) Celeron(R) N4120 CPU @ 1.10GHz",
    "processor_count": 1,
    "processor_logical_count": 4,
    "processor_architecture": "x64",
    "tpm_present": "Present",
    "tpm_version": "2.0",
    "tpm_manufacturer_id": "INTC",
    "tpm_manufacturer_version": "403.0.0.0",
    "secure_boot_status": "Enabled",
    "bios_manufacturer": "Dell Inc.",
    "bios_serial_number": "ABC123",
    "bios_version": "1.12.2",
    "bios_firmware_type": "UEFI",
    "wifi_mac": "DC-41-A9-2A-7A-74",
    "ethernet_mac": "",
    "encryption_status": "No Protection",
    "anti_virus_products": "Sophos Anti-Virus,Windows Defender",
    "firewall_domain_profile_status": "Enabled",
    "firewall_private_profile_status": "Enabled",
    "firewall_public_profile_status": "Enabled",
    "windows_11_readiness": "Not Ready",
    "windows_11_readiness_failed_checks": "OS Disk Size",
    "management_state": "Domain Joined",
    "hardware_hash": "T0HFAwEAHAA....."
}
```

## 🔄 Automation

## 🔒 Security & Privacy
- **No local data is stored**—data is only transmitted to the configured API.
- **Product keys are masked** before transmission.

## 🔮 Future Plans
- Enhancements based on community feedback.

## 📚 License
The license is yet to be decided. If you have suggestions, feel free to open an issue.

---

🚀 **Collecto** – An efficient and comprehensive device inventory solution for IT professionals.

