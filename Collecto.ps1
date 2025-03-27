<#PSScriptInfo

.VERSION 0.1.0

.GUID 7cb8f494-a4ac-4278-98c3-a345e13478f9

.AUTHOR Dylan McCrimmon

.COMPANYNAME Dylan McCrimmon

.COPYRIGHT 2025 Dylan McCrimmon. All rights reserved.

.TAGS

.LICENSEURI https://github.com/dylanmccrimmon/Collecto/blob/main/LICENSE

.PROJECTURI https://github.com/dylanmccrimmon/Collecto

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
Initial beta version.

.PRIVATEDATA

#>
param(
    [Parameter(Mandatory=$true)]
    [System.String]
    $CustomerName,
    [Parameter(Mandatory=$true)]
    [System.String]
    $SiteName,
    [Parameter(Mandatory=$true)]
    [System.String]
    $ReportingURL,
    [Parameter(Mandatory=$false)]
    [System.String]
    $CheckInURL = $null
)

# Check if the script is running as administrator
$RunningAsAdministrator = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
if (!$RunningAsAdministrator) {
    Write-Warning "This script requires administrator privileges to access certain data, including BitLocker, Hardware Hash, and TPM details. Please re-run this script as an Administrator to ensure all data is captured correctly."
}


#region Check-in required functions, CIM instance queries, and check-in logic
function Invoke-CheckIn {
    param (
        [Parameter(Mandatory=$true)]
        [System.String]
        $CheckInURL,
        [Parameter(Mandatory=$true)]
        [System.String]
        $UniqueDeviceIDHash
    )

    $body = [PSCustomObject]@{
        'unique_device_id_hash' = $UniqueDeviceIDHash
    }

    try {
        $response = Invoke-RestMethod -Uri $CheckInURL -Method Post -Body ($Body | ConvertTo-Json) -ContentType "application/json"

        # If the response is null, the check-in failed
        if ($null -eq $response) {

            # If the response is null, the check-in failed
            return [PSCustomObject]@{
                'CheckInSuccessful' = $false
                'CheckInErrorMessage' = "The response is null"
                'Report' = $null
            }
    
        }
    
        # If the property 'report' doesnt exists or is not a boolean, the check-in failed
        if (($null -eq $response.report) -or ($response.report.GetType().Name -ne "Boolean")) {
    
            return [PSCustomObject]@{
                'CheckInSuccessful' = $false
                'CheckInErrorMessage' = "The 'report' property is missing or not a boolean"
                'Report' = $false
    
            }
    
        } 
    
        return [PSCustomObject]@{
            'CheckInSuccessful' = $true
            'CheckInErrorMessage' = $null
            'Report' = $response.report
        }
    
    }
    catch {
        <#Do this if a terminating exception happens#>
        return [PSCustomObject]@{
            'CheckInSuccessful' = $false
            'CheckInErrorMessage' = $_.Exception.Message
            'Report' = $false
        }
    }
    
}
function Get-UniqueDeviceIDHash {
    param (
        [System.String]
        $BaseBoardSerialNumber,
        [System.String]
        $BIOSManufacturer,
        [System.String]
        $BIOSModel,
        [System.String]
        $BIOSSerialNumber
    )

    # BIOS/UEFI UUID + BIOS Manufacturer + BIOS Model + BIOS Serial Number

    $UniqueDeviceIDHash = $BaseBoardSerialNumber + $BIOSManufacturer + $BIOSModel + $BIOSSerialNumber
    $UniqueDeviceIDHashStream = [IO.MemoryStream]::new([byte[]][char[]]$UniqueDeviceIDHash)
    $UniqueDeviceIDHash = (Get-FileHash -InputStream $UniqueDeviceIDHashStream -Algorithm SHA256).Hash

    return $UniqueDeviceIDHash
}
$CIM_BIOS = Get-CimInstance Win32_BIOS
$CIM_BaseBoard = Get-CimInstance Win32_BaseBoard
$FN_UniqueDeviceIDHash = Get-UniqueDeviceIDHash -BaseBoardSerialNumber $CIM_BaseBoard.SerialNumber -BIOSManufacturer $CIM_BIOS.Manufacturer -BIOSModel $CIM_BIOS.Model -BIOSSerialNumber $CIM_BIOS.SerialNumber

if (!($null -eq $CheckInURL)) {
    $CheckInResult = Invoke-CheckIn -CheckInURL $CheckInURL -UniqueDeviceIDHash $FN_UniqueDeviceIDHash

    if ($CheckInResult.Report) {
        Write-Verbose "The check-in server requested a report."

    } else {

        if (!$CheckInResult.CheckInSuccessful) {
            Write-Error "Check-in failed. Error: $($CheckInResult.CheckInErrorMessage)"

        }

        Write-Verbose "The check-in server did not request a report."
    }
}
#endregion

#region Functions
function Get-SecureBootStatus {
    try {
        $SecureBoot = Confirm-SecureBootUEFI

        if ($SecureBoot) {
            return "Enabled"
        } else {
            return "Disabled"
        }

    }
    catch [System.PlatformNotSupportedException] {
        # PlatformNotSupportedException "Cmdlet not supported on this platform." - SecureBoot is not supported or is non-UEFI computer.
        return "Not Supported"
    }
    catch [System.UnauthorizedAccessException] {
        return "Unable to access Secure Boot data (Access Denied)"
    }
    catch {
        return "Unknown"
    }
}
function Get-WindowsEditionNameFromSKU {
    param (
        [int]$SKUID
    )

    $skus = @{
        0 = "UNDEFINED"
        1 = "ULTIMATE"
        2 = "HOME_BASIC"
        3 = "HOME_PREMIUM"
        4 = "ENTERPRISE"
        5 = "HOME_BASIC_N"
        6 = "BUSINESS"
        7 = "STANDARD_SERVER"
        8 = "DATACENTER_SERVER"
        9 = "SMALLBUSINESS_SERVER"
        10 = "ENTERPRISE_SERVER"
        11 = "STARTER"
        12 = "DATACENTER_SERVER_CORE"
        13 = "STANDARD_SERVER_CORE"
        14 = "ENTERPRISE_SERVER_CORE"
        15 = "ENTERPRISE_SERVER_IA64"
        16 = "BUSINESS_N"
        17 = "WEB_SERVER"
        18 = "CLUSTER_SERVER"
        19 = "HOME_SERVER"
        20 = "STORAGE_EXPRESS_SERVER"
        21 = "STORAGE_STANDARD_SERVER"
        22 = "STORAGE_WORKGROUP_SERVER"
        23 = "STORAGE_ENTERPRISE_SERVER"
        24 = "SERVER_FOR_SMALLBUSINESS"
        25 = "SMALLBUSINESS_SERVER_PREMIUM"
        26 = "HOME_PREMIUM_N"
        27 = "ENTERPRISE_N"
        28 = "ULTIMATE_N"
        29 = "WEB_SERVER_CORE"
        30 = "MEDIUMBUSINESS_SERVER_MANAGEMENT"
        31 = "MEDIUMBUSINESS_SERVER_SECURITY"
        32 = "MEDIUMBUSINESS_SERVER_MESSAGING"
        33 = "SERVER_FOUNDATION"
        34 = "HOME_PREMIUM_SERVER"
        35 = "SERVER_FOR_SMALLBUSINESS_V"
        36 = "STANDARD_SERVER_V"
        37 = "DATACENTER_SERVER_V"
        38 = "ENTERPRISE_SERVER_V"
        39 = "DATACENTER_SERVER_CORE_V"
        40 = "STANDARD_SERVER_CORE_V"
        41 = "ENTERPRISE_SERVER_CORE_V"
        42 = "HYPERV"
        48 = "PROFESSIONAL"
        49 = "PROFESSIONAL_N"
        121 = "EDUCATION"
        122 = "EDUCATION_N"
        125 = "ENTERPRISE_S"
        126 = "ENTERPRISE_S_N"
        161 = "PRO_WORKSTATION"
        162 = "PRO_WORKSTATION_N"
        164 = "PRO_FOR_EDUCATION"
        165 = "PRO_FOR_EDUCATION_N"
    }

    if ($skus[$SKUID]) {
        return $skus[$SKUID]
    } else {
        return "Unknown SKU Name (SKU: $SKUID)"
    }
}
function Get-WindowsActivationStatus {
    param (
        [object]
        $CIMSoftwareLicensingProduct
    )


    try {
        # Attempt to get the Windows licensing information
        $CIMSoftwareLicensingProduct = $CIMSoftwareLicensingProduct | Where-Object { $_.PartialProductKey } |  Where-Object {$_.Name -like "*Windows*"}

        if ($null -eq $CIMSoftwareLicensingProduct) {
            return [PSCustomObject]@{
                Status = 'No licensing information found'
                Method = 'No licensing information found'
            }
        }

        # Switch to handle different LicenseStatus values
        switch ($CIMSoftwareLicensingProduct.LicenseStatus) {
            0 { $Status = "Unlicensed" }
            1 { $Status = "Licensed" }
            2 { $Status = "Out-Of-Box Grace Period" }
            3 { $Status = "Out-Of-Tolerance Grace Period" }
            4 { $Status = "Non-Genuine Grace Period" }
            5 { $Status = "Notification" }
            6 { $Status = "Extended Grace" }
            default { $Status = "Unknown" }
        }

        if ($CIMSoftwareLicensingProduct.ProductKeyChannel) {
            $Method = $CIMSoftwareLicensingProduct.ProductKeyChannel
        } else {
            $Method = $null
        }

        return [PSCustomObject]@{
            Status = $Status
            Method = $Method
        }

    }
    catch {
        # Handle errors and display a message
        #Write-Error "Error: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Status = 'Unknown'
            Method = 'Unknown'
        }
    }
}
function Get-AntiVirusProducts {

    try {

        $AntiVirusProducts = (Get-CimInstance -Namespace "root/SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop).displayName | Select-Object -Unique

        if ($null -eq $AntiVirusProducts){
            return "None found"
        }

        return $AntiVirusProducts
    }
    catch [Microsoft.Management.Infrastructure.CimException] {
        if ($_.Exception.HResult -eq 0x8004100E -or $_.Exception.Message -match "Invalid namespace") {
            #Write-Output "Error: The namespace '$Namespace' is invalid or does not exist."
            return "Unknown - Query method not supported"
        } else {
            #Write-Output "CIM error occurred: $($_.Exception.Message)"
            return "Unknown"
        }
    }
    catch [System.UnauthorizedAccessException] {
        return "Unable to access Anti Virus product data (Access Denied)"
    }
    catch {
        return "Unknown"
    }

}
function Get-EncryptionStatus {
    param (
        [System.String]
        $DriveLetter
    )

    try {

        $CIM_EncryptableVolume = Get-CimInstance -Namespace "root/CIMv2/Security/MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -ErrorAction Stop | Where-Object { $_.DriveLetter -eq $DriveLetter } 

        switch ($CIM_EncryptableVolume.ProtectionStatus) {
            0 { return "No Protection" }
            1 { return "Protection On (Fully Encrypted)" }
            2 { return "Protection Off (Not Encrypted)" }
            default { return "Unknown" }
        }

    }
    catch [Microsoft.Management.Infrastructure.CimException] {

        if ($_.Exception.Message -match "Access denied") {
            return "Unknown - Unable to access encryptable volume data (Access Denied)"
        }

        if ($_.Exception.Message -match "Invalid namespace") {
            return "Unknown - Query method not supported"
        }

        return "Unknown"

    }
    catch {
        return "Unknown"
    }

}
function Get-TPMDetails {

    try {

        $CIM_TPM = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop

        if (($null -eq $CIM_TPM)) {

            return [PSCustomObject]@{
                'Presence' = "Not Present"
                'TPMVersion' = $null
                'ManufacturerId' = $null
                'ManufacturerVersion' = $null           
            }

        }

        return [PSCustomObject]@{
            'Presence' = "Present"
            'TPMVersion' = $CIM_TPM.SpecVersion.Split(",")[0]
            'ManufacturerId' = $CIM_TPM.ManufacturerIdTxt
            'ManufacturerVersion' = $CIM_TPM.ManufacturerVersion
        }

    }
    catch [Microsoft.Management.Infrastructure.CimException] {

        if ($_.Exception.Message -match "Access denied") {
            return [PSCustomObject]@{
                'Presence' = "Unknown - Unable to access TPM data (Access Denied)"
                'TPMVersion' = $null
                'ManufacturerId' = $null
                'ManufacturerVersion' = $null           
            }
        }

        return [PSCustomObject]@{
            'Presence' = "Unknown"
            'TPMVersion' = $null
            'ManufacturerId' = $null
            'ManufacturerVersion' = $null           
        }

    }
    catch {
        return [PSCustomObject]@{
            'Presence' = "Unknown"
            'TPMVersion' = $null
            'ManufacturerId' = $null
            'ManufacturerVersion' = $null           
        }
    }

}

# TODO: Clean up these functions
function Get-HardwareHash {
    try {
        $CIM_MDMDevDetailExt01 = Get-CimInstance -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" -ErrorAction Stop

        if ($CIM_MDMDevDetailExt01) {
            return $CIM_MDMDevDetailExt01.DeviceHardwareData
        } else {
            Write-Warning "No hardware hash information found."
            return $null
        }
    } catch {
        Write-Error "Failed to retrieve hardware hash: $_"
        return $null
    }
}
function Get-DeviceState {

    $DSRegCMD = dsregcmd /status

    if ($null -eq $DSRegCMD) {
        return "Unknown"
    }

    $AzureAdJoined = if ((($DSRegCMD | Select-String AzureAdJoined).ToString() -split ":")[1].trim() -eq "Yes") { $true } else {$false}
    $EnterpriseJoined = if ((($DSRegCMD | Select-String EnterpriseJoined).ToString() -split ":")[1].trim() -eq "Yes") { $true } else {$false}
    $DomainJoined = if ((($DSRegCMD | Select-String DomainJoined).ToString() -split ":")[1].trim() -eq "Yes") { $true } else {$false}
    

    # Test if device state is "Microsoft Entra joined"
    if ($AzureAdJoined -and -not $EnterpriseJoined -and -not $DomainJoined) {
        return "Microsoft Entra joined"
    }

    # Test if device state is "Domain Joined"
    if (-not $AzureAdJoined -and -not $EnterpriseJoined -and $DomainJoined) {
        return "Domain Joined"
    }

    # Test if device state is "Microsoft Entra hybrid joined"
    if ($AzureAdJoined -and -not $EnterpriseJoined -and $DomainJoined) {
        return "Microsoft Entra hybrid joined"
    }

    # Test if device state is "On-premises DRS Joined"
    if (-not $AzureAdJoined -and $EnterpriseJoined -and $DomainJoined) {
        return "On-premises DRS Joined"
    }

    # Test if device state is "standalone"
    if (-not $AzureAdJoined -and -not $EnterpriseJoined -and -not $DomainJoined) {
        return "Standalone"
    }

}
#endregion

#region CIM Instance Queries
$CIM_ComputerSystem = Get-CimInstance Win32_ComputerSystem
$CIM_OperatingSystem = Get-CimInstance Win32_OperatingSystem
$CIM_Processor = Get-CimInstance -Class Win32_Processor
$CIM_PhysicalMemory = Get-CimInstance -Class Win32_PhysicalMemory
$CIM_SoftwareLicensingProduct = Get-CimInstance -Class SoftwareLicensingProduct
$CIM_SoftwareLicensingService = Get-CimInstance -Class SoftwareLicensingService
$CIM_PhysicalDisk = Get-CimInstance -Namespace "Root/Microsoft/Windows/Storage" -ClassName MSFT_PhysicalDisk
$CIM_LogicalDisk = Get-CimInstance Win32_LogicalDisk
$CIM_DiskPartition = Get-CimInstance Win32_DiskPartition
$CIM_LogicalDiskToPartition = Get-CimInstance Win32_LogicalDiskToPartition
$CIM_Battery = Get-CimInstance Win32_Battery
if ($Null -ne $CIM_Battery) {
    $WMI_BatteryStaticData = Get-WmiObject -Namespace "ROOT\WMI" -ClassName "BatteryStaticData"
    $CIM_BatteryFullChargedCapacity = Get-CimInstance -Namespace "ROOT\WMI" -ClassName "BatteryFullChargedCapacity"
    $CIM_BatteryCycleCount = Get-CimInstance -Namespace "ROOT\WMI" -ClassName "BatteryCycleCount"
}
$CIM_NetFirewallProfile = Get-CimInstance -Namespace "root/StandardCimv2" -ClassName "MSFT_NetFirewallProfile"
#endregion

#region Function calls
$FN_NetAdapter = Get-NetAdapter
$FN_HardwareHash = Get-HardwareHash
$FN_ManagementState = Get-DeviceState
$FN_SecureBootStatus = Get-SecureBootStatus
$FN_OperatingSystemSKUName = Get-WindowsEditionNameFromSKU -SKUID $CIM_OperatingSystem.OperatingSystemSKU
$FN_WindowsActivationStatus = Get-WindowsActivationStatus -CIMSoftwareLicensingProduct $CIM_SoftwareLicensingProduct
$FN_AntiVirusProducts = Get-AntiVirusProducts
$FN_EncryptionStatus = Get-EncryptionStatus -DriveLetter $CIM_OperatingSystem.SystemDrive
$FN_TPMDetails = Get-TPMDetails
#endregion

#region Registy queries
$REG_OSDisplayVersion = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion
#endregion

#region Environment variables
$ENV_FirmwareType = [System.Environment]::GetEnvironmentVariable('firmware_type','Process')
#endregion

#region Compute values
## CPU Architecture


$CV_Processors = @()
foreach ($Processor in $CIM_Processor) {

    $ProcessorArchitecture = switch ($Processor.Architecture) {
        0 {
            "x86"
        }
        1 {
            "MIPS"
        }
        2 {
            "Alpha"
        }
        3 {
            "PowerPC"
        }
        6 {
            "ia64"
        }
        9 {
            "x64"
        }
        Default {
            "Unknown"
        }
    }


    $CV_Processors += [PSCustomObject]@{
        "name"           = $Processor.Name
        "manufacturer"   = $Processor.Manufacturer
        "architecture"   = $ProcessorArchitecture
        "base_frequency_ghz"  = [math]::Round($Processor.MaxClockSpeed / 1000, 2)
        "total_cores"    = $Processor.NumberOfCores
        "total_threads"  = $Processor.NumberOfLogicalProcessors
    }
}

## Memory
$CV_MemoryTotal = [math]::round(($CIM_PhysicalMemory.Capacity | Measure-Object -Sum).sum / 1GB, 0)

## Network Adapters
$CV_NetworkAdapters = @()
foreach ($Adapter in $FN_NetAdapter | Where-Object {$_.NdisPhysicalMedium -eq 14}) {
    $CV_NetworkAdapters += [PSCustomObject]@{
        "type"         = "Ethernet"
        "mac_address"  = $Adapter.MacAddress
        "description"  = $Adapter.InterfaceDescription
    }
} 
foreach ($Adapter in $FN_NetAdapter | Where-Object {$_.NdisPhysicalMedium -eq 9}) {
    $CV_NetworkAdapters += [PSCustomObject]@{
        "type"         = "WiFi"
        "mac_address"  = $Adapter.MacAddress
        "description"  = $Adapter.InterfaceDescription
    }
} 
foreach ($Adapter in $FN_NetAdapter | Where-Object {$_.NdisPhysicalMedium -eq 10}) {
    $CV_NetworkAdapters += [PSCustomObject]@{
        "type"         = "Bluetooth"
        "mac_address"  = $Adapter.MacAddress
        "description"  = $Adapter.InterfaceDescription
    }
} 


# OS Locale
$CV_OperatingSystemLocale = New-Object System.Globalization.CultureInfo([Convert]::ToInt32($CIM_OperatingSystem.Locale, 16))

# Device type
$CV_DeviceType = if ($CIM_ComputerSystem.PCSystemType -eq 2) { "Laptop" } elseif ($CIM_ComputerSystem.PCSystemType -eq 1) { "Desktop" } else { "Unknown" }

# Windows Original Product Key
$CV_WindowsOriginalProductKey = $CIM_SoftwareLicensingService.OA3xOriginalProductKey
$CV_WindowsOriginalProductKey = if ($CV_WindowsOriginalProductKey) {
    "*****-*****-*****-*****-" + ($CV_WindowsOriginalProductKey[-5..-1] -join "")
} else {
    "None found"
}
$CV_WindowsOriginalProductKeyDescription = $CIM_SoftwareLicensingService.OA3xOriginalProductKeyDescription

# Getting disk device type
$CV_OSLogicalDisk = $CIM_LogicalDisk | Where-Object { $_.DeviceID -eq $CIM_OperatingSystem.SystemDrive }
$CV_OSLogicalToPartition = $CIM_LogicalDiskToPartition | Where-Object { $_.Dependent -match "DeviceID = `"$($CV_OSLogicalDisk.DeviceID)`"" }
$CV_OSDiskPartition = $CIM_DiskPartition | Where-Object { $_.DeviceID -eq (($CV_OSLogicalToPartition.Antecedent -split '"')[1]) }
$CV_OSPhysicalDisk = $CIM_PhysicalDisk | Where-Object { $_.DeviceID -eq $CV_OSDiskPartition.DiskIndex  }

# Battery
$CV_HasBattery = $null -ne $CIM_Battery
if ($CV_HasBattery) {

    $CVBatteryChemistry = switch ($CIM_Battery.Chemistry) {
        1 {  "Other" }
        2 { "Unknown" }
        3 { "Lead Acid" }
        4 { "Nickel Cadmium" }
        5 { "Nickel Metal Hydride" }
        6 { "Lithium-ion" }
        7 { "Zinc air" }
        8 { "Lithium Polymer" }
        default { "Unknown" }
    }

} else {
    $CVBatteryChemistry = $null
}

# Firewall
$CV_FirewallStatus = switch (($CIM_NetFirewallProfile | Where-Object {$_.Enabled -eq $true}).count) {
    3 { "Enabled" }
    0 { "Disabled" }
    default { "Partially Enabled" }
}

# Sometimes the output will be a string or sometimes a number... account for both.
$CV_OSPhysicalDiskType = switch ($CV_OSPhysicalDisk.MediaType) {
    3 {
         "HDD"
    }
    4 {
        "SSD"
    }
    5 {
        "SCM"
    }
    0 {
        "Unspecified"
    }
    'HDD' {
        "HDD"
    }
    'SSD' {
        "SSD"
    }
    'SCM' {
        "SCM"
    }
    'Unspecified' {
        "Unspecified"
    }
    Default {
        "Unknown"
    }
}


#endregion

#region Windows 11 readiness checks
$Windows11ReadinessFailedChecks = @() # Array to store failed checks

# Set the minimum requirements for Windows 11 readiness checks
[int]$Win11ReadinessMinOSDiskSizeGB = 64
[int]$Win11ReadinessMinMemoryGB = 4
[Uint32]$Win11ReadinessMinClockSpeedMHz = 1000
[Uint32]$Win11ReadinessMinLogicalCores = 2
[Uint16]$Win11ReadinessRequiredAddressWidth = 64


# Check if the OS disk size is greater than or equal to the minimum required size
if (!([math]::round($CV_OSPhysicalDisk.Size / 1Gb, 0) -ge $Win11ReadinessMinOSDiskSizeGB)) {
    $Windows11ReadinessFailedChecks += "OS Disk Size"
}

# Check if the total memory is greater than or equal to the minimum required size
if (!($CV_MemoryTotal -ge $Win11ReadinessMinMemoryGB)) {
    $Windows11ReadinessFailedChecks += "Memory"
}

$CPU0 = $CIM_Processor[0]
# Check if the processor address width is greater than or equal to the minimum required size
if (!($CPU0.AddressWidth -ge $Win11ReadinessRequiredAddressWidth)) {
    $Windows11ReadinessFailedChecks += "CPU Address Width"
}

# Check if the processor clock speed is greater than or equal to the minimum required size
if (!($CPU0.MaxClockSpeed -ge $Win11ReadinessMinClockSpeedMHz)) {
    $Windows11ReadinessFailedChecks += "CPU Clock Speed"
}

# Check if the processor logical core count is greater than or equal to the minimum required size
if (!($CPU0.NumberOfLogicalProcessors -ge $Win11ReadinessMinLogicalCores)) {
    $Windows11ReadinessFailedChecks += "CPU Logical Cores"
}

# Check if the CPU Family is supported
$Source = @"
using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;

    public class CpuFamilyResult
    {
        public bool IsValid { get; set; }
        public string Message { get; set; }
    }

    public class CpuFamily
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort ProcessorArchitecture;
            ushort Reserved;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }

        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        public enum ProcessorFeature : uint
        {
            ARM_SUPPORTED_INSTRUCTIONS = 34
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsProcessorFeaturePresent(ProcessorFeature processorFeature);

        private const ushort PROCESSOR_ARCHITECTURE_X86 = 0;
        private const ushort PROCESSOR_ARCHITECTURE_ARM64 = 12;
        private const ushort PROCESSOR_ARCHITECTURE_X64 = 9;

        private const string INTEL_MANUFACTURER = "GenuineIntel";
        private const string AMD_MANUFACTURER = "AuthenticAMD";
        private const string QUALCOMM_MANUFACTURER = "Qualcomm Technologies Inc";

        public static CpuFamilyResult Validate(string manufacturer, ushort processorArchitecture)
        {
            CpuFamilyResult cpuFamilyResult = new CpuFamilyResult();

            if (string.IsNullOrWhiteSpace(manufacturer))
            {
                cpuFamilyResult.IsValid = false;
                cpuFamilyResult.Message = "Manufacturer is null or empty";
                return cpuFamilyResult;
            }

            string registryPath = "HKEY_LOCAL_MACHINE\\Hardware\\Description\\System\\CentralProcessor\\0";
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            GetNativeSystemInfo(ref sysInfo);

            switch (processorArchitecture)
            {
                case PROCESSOR_ARCHITECTURE_ARM64:

                    if (manufacturer.Equals(QUALCOMM_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        bool isArmv81Supported = IsProcessorFeaturePresent(ProcessorFeature.ARM_SUPPORTED_INSTRUCTIONS);

                        if (!isArmv81Supported)
                        {
                            string registryName = "CP 4030";
                            long registryValue = (long)Registry.GetValue(registryPath, registryName, -1);
                            long atomicResult = (registryValue >> 20) & 0xF;

                            if (atomicResult >= 2)
                            {
                                isArmv81Supported = true;
                            }
                        }

                        cpuFamilyResult.IsValid = isArmv81Supported;
                        cpuFamilyResult.Message = isArmv81Supported ? "" : "Processor does not implement ARM v8.1 atomic instruction";
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "The processor isn't currently supported for Windows 11";
                    }

                    break;

                case PROCESSOR_ARCHITECTURE_X64:
                case PROCESSOR_ARCHITECTURE_X86:

                    int cpuFamily = sysInfo.ProcessorLevel;
                    int cpuModel = (sysInfo.ProcessorRevision >> 8) & 0xFF;
                    int cpuStepping = sysInfo.ProcessorRevision & 0xFF;

                    if (manufacturer.Equals(INTEL_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            cpuFamilyResult.IsValid = true;
                            cpuFamilyResult.Message = "";

                            if (cpuFamily >= 6 && cpuModel <= 95 && !(cpuFamily == 6 && cpuModel == 85))
                            {
                                cpuFamilyResult.IsValid = false;
                                cpuFamilyResult.Message = "";
                            }
                            else if (cpuFamily == 6 && (cpuModel == 142 || cpuModel == 158) && cpuStepping == 9)
                            {
                                string registryName = "Platform Specific Field 1";
                                int registryValue = (int)Registry.GetValue(registryPath, registryName, -1);

                                if ((cpuModel == 142 && registryValue != 16) || (cpuModel == 158 && registryValue != 8))
                                {
                                    cpuFamilyResult.IsValid = false;
                                }
                                cpuFamilyResult.Message = "PlatformId " + registryValue;
                            }
                        }
                        catch (Exception ex)
                        {
                            cpuFamilyResult.IsValid = false;
                            cpuFamilyResult.Message = "Exception:" + ex.GetType().Name;
                        }
                    }
                    else if (manufacturer.Equals(AMD_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        cpuFamilyResult.IsValid = true;
                        cpuFamilyResult.Message = "";

                        if (cpuFamily < 23 || (cpuFamily == 23 && (cpuModel == 1 || cpuModel == 17)))
                        {
                            cpuFamilyResult.IsValid = false;
                        }
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "Unsupported Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    }

                    break;

                default:
                    cpuFamilyResult.IsValid = false;
                    cpuFamilyResult.Message = "Unsupported CPU category. Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    break;
            }
            return cpuFamilyResult;
        }
    }
"@
Add-Type -TypeDefinition $Source
$cpuFamilyResult = [CpuFamily]::Validate([String]$CPU0.Manufacturer, [uint16]$CPU0.Architecture)
if (-not $cpuFamilyResult.IsValid) {
    $Windows11ReadinessFailedChecks += "CPU Family"
}

# Check if the TPM is present and the version is greater than or equal to 2.0
if (($null -eq $FN_TPMDetails) -or ($FN_TPMDetails.Presence -eq "Not Present")) {
    $Windows11ReadinessFailedChecks += "TPM"
} elseif (($FN_TPMDetails.TPMVersion -as [int]) -lt 2) {
    $Windows11ReadinessFailedChecks += "TPM Version"
}

# Check if secure boot is enabled
if ($FN_SecureBootStatus -eq "Not Supported") {
    $Windows11ReadinessFailedChecks += "Secure Boot (Not Supported)"
} elseif ($FN_SecureBootStatus -eq "Disabled") {
    $Windows11ReadinessFailedChecks += "Secure Boot (Disabled)"
}


# Check if the device is ready for Windows 11
if ($Windows11ReadinessFailedChecks.Count -eq 0) {
    $Windows11Readiness = "Ready"
} else {
    $Windows11Readiness = "Not Ready"
}

$Windows11ReadinessFailedChecks = $Windows11ReadinessFailedChecks -join ","
#endregion

# Gather details into a object
$Data = [PSCustomObject]@{
    "unique_device_id_hash" = $FN_UniqueDeviceIDHash
    "organisation_name" = $CustomerName
    "site_name" = $SiteName

    "device_info" = [PSCustomObject]@{
        "hostname"            = $CIM_ComputerSystem.Name
        "management_state"    = $FN_ManagementState
    }

    "os" = [PSCustomObject]@{
        "platform"         = "Windows"
        "version"          = $CIM_OperatingSystem.Version
        "version_display"  = $REG_OSDisplayVersion
        "edition"          = $FN_OperatingSystemSKUName
        "sku"              = $CIM_OperatingSystem.Caption
        "language"         = $CV_OperatingSystemLocale.DisplayName
        "architecture"     = $CIM_OperatingSystem.OSArchitecture
        "activation"       = [PSCustomObject]@{
            "status"                    = $FN_WindowsActivationStatus.Status
            "type"                      = $FN_WindowsActivationStatus.Method
            "oem_product_key"           = $CV_WindowsOriginalProductKey 
            "oem_product_key_description" = $CV_WindowsOriginalProductKeyDescription
        }
    }

    "hardware" = [PSCustomObject]@{
        "manufacturer"  = $CIM_ComputerSystem.Manufacturer
        "family"        = $CIM_ComputerSystem.SystemFamily
        "model"         = $CIM_ComputerSystem.Model
        "type"          = $CV_DeviceType
        "serial_number" = $CIM_BIOS.SerialNumber
        "cpu" = $CV_Processors
        "ram" = [PSCustomObject]@{
            "installed_gb"      = $CV_MemoryTotal
            "speed_mhz"         = $CIM_PhysicalMemory.speed
        }
        "storage" = [PSCustomObject]@{
            "os_disk" = [PSCustomObject]@{
                "type"     = $CV_OSPhysicalDiskType
                "size_gb"  = [math]::round($CV_OSPhysicalDisk.Size / 1Gb, 0)
            }
            "os_volume" = [PSCustomObject]@{
                "free_gb"       = [math]::round($CV_OSLogicalDisk.FreeSpace / 1Gb, 0)
                "total_gb"      = [math]::round($CV_OSLogicalDisk.Size / 1Gb, 0)
                "file_system"   =  $CV_OSLogicalDisk.FileSystem 
            }
        }
        "battery" = [PSCustomObject]@{
            "present"               = $CV_HasBattery
            "cycle_count"           = if ($CV_HasBattery) { $CIM_BatteryCycleCount.CycleCount } else { $null }
            "health_percentage"     = if ($CV_HasBattery) { [math]::Round(($CIM_BatteryFullChargedCapacity.FullChargedCapacity / $WMI_BatteryStaticData.DesignedCapacity) * 100) } else { $null }
            "designed_capacity_whr" = if ($CV_HasBattery) { [math]::Round($WMI_BatteryStaticData.DesignedCapacity / 1000) } else { $null }
            "current_capacity_whr"  = if ($CV_HasBattery) { [math]::Round($CIM_BatteryFullChargedCapacity.FullChargedCapacity / 1000) } else { $null }
            "chemistry"             = if ($CV_HasBattery) { $CVBatteryChemistry } else { $null }
            "manufacturer"          = if ($CV_HasBattery) { $WMI_BatteryStaticData.ManufactureName } else { $null }
            "serial_number"         = if ($CV_HasBattery) { $WMI_BatteryStaticData.SerialNumber } else { $null }
        }
        "firmware" = [PSCustomObject]@{
            "type"          = $ENV_FirmwareType
            "version"       = $CIM_BIOS.SMBIOSBIOSVersion
            "manufacturer"  = $CIM_BIOS.Manufacturer
        }
        "network_adapters" = $CV_NetworkAdapters
    }

    "security" = [PSCustomObject]@{
        "security_chip" = [PSCustomObject]@{
            "present"               = $FN_TPMDetails.Presence
            "type"                  = "TPM"
            "version"               = $FN_TPMDetails.TPMVersion
            "manufacturer_id"       = $FN_TPMDetails.ManufacturerId
            "manufacturer_version"  = $FN_TPMDetails.ManufacturerVersion
        }
        "secure_boot" = $FN_SecureBootStatus
        "os_encryption" = [PSCustomObject]@{
            "status" = $FN_EncryptionStatus
            "method" = if ($FN_EncryptionStatus -in @("Protection On (Fully Encrypted)", "Protection Off (Not Encrypted)")) { "BitLocker" } else { $null }
        }
        "antivirus" = $FN_AntiVirusProducts
        "firewall_status" = $CV_FirewallStatus
    }

    "platform_specific" = [PSCustomObject]@{
        "windows" = [PSCustomObject]@{
            "autopilot_hardware_hash" = $FN_HardwareHash
            "windows_11_readiness" = [PSCustomObject]@{
                "status"         = $Windows11Readiness
                "failed_checks"  = $Windows11ReadinessFailedChecks
            }
        }
    }
}

# Convert the data to JSON
$Data = $Data | ConvertTo-Json -Depth 5

# Make the POST request
try {

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $response = Invoke-RestMethod -Uri $ReportingURL -Method Post -Body $Data -ContentType "application/json"

} catch {
    # Catch any errors during the HTTP request
    Write-Error "An error occurred during the request: $($_.Exception.Message)"
}