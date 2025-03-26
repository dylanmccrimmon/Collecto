# 🔐 The `unique_device_id_hash` – How It's Created

The `unique_device_id_hash` is a platform-agnostic, privacy-conscious identifier designed to uniquely and *consistently* identify a physical device — even if the OS is reinstalled or reset.

It’s **hashed and anonymized** using SHA-256 to ensure it cannot be reversed or traced back to personally identifiable information (PII).

It has been designed for use in scenarios where identifying a physical device across reinstalls is important (e.g., asset tracking, inventory, licensing, enrollment). **Normal hardware changes** such as replacing or upgrading RAM, disks, CPU, or performing firmware updates should **not affect** the resulting hash.

---

## 🖥 Windows

### Primary Strategy
- Query WMI:  
  `Win32_ComputerSystemProduct.UUID`

This UUID is intended to be a hardware-based identifier, typically provided by the motherboard firmware, and should persist across OS reinstalls.

### Example
Cleartext value:
```text
6f9619ff-8b86-d011-b42d-00cf4fc964ff
```
SHA-256:
```text
78b76a17b649e2cdd58cb41f4e3988939c4f6a2ea6c7e6d4b98f32ec29cb918e
```

### Known Issues
Some systems return invalid or unreliable UUIDs:
- All zeros: `00000000-0000-0000-0000-000000000000`
- All Fs: `FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF`
- Duplicate or generic UUIDs (especially in VMs)

### Fallback Strategy
When the UUID is invalid or unavailable:
- Use one or more of the following:
  - `MachineGuid` from the Windows registry:  
    `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
  - BIOS serial number (`Win32_BIOS`)
  - Motherboard serial number (`Win32_BaseBoard`)
- These values are combined (if needed) to generate a stable fallback fingerprint


---

## 🍎 macOS

- Uses the device’s hardware-based **UDID** (Unique Device Identifier)
- The UDID is persistent across factory resets and reinstalls


This value is stable across reinstalls and remains consistent unless the logic board is physically replaced.

### Example
Cleartext value:
```text
ABCDEF01-2345-6789-ABCD-EF0123456789
```
SHA-256:
```text
c9edcc7caa93d4c0e1d121cc17fc8a8c3c650cf7c23816b7991c187bf8124ff4
```

---

## 📱 iOS / iPadOS

- Uses the device’s hardware-based **UDID** (Unique Device Identifier)
- The UDID is persistent across factory resets and reinstalls

### Example
Cleartext value:
```text
00008030-000D19523410802E
```
SHA-256:
```text
e5cb40b6e7658fc5e2eb3de194bb3c703b3cc198d0ac676d1f0283c5312d24d4
```

---

## 💻 ChromeOS

Support for ChromeOS is **planned**, and methods are still being evaluated.  
The goal is to identify a stable hardware-bound identifier similar to other platforms without relying on cloud-managed data.

---

## 📌 Additional Notes

- **No salts** are used — identical hardware yields the same hash (as a consequence of using consistent source identifiers)
  - If two or more machines happen to have the same source identifier (e.g., due to manufacturer duplication or virtualization), the resulting hash would also be the same. While this would break uniqueness, it has not been encountered in practice so far.