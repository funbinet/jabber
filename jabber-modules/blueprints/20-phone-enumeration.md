# Phone Enumeration — Category Blueprint

**Category:** `PHONE_ENUMERATION` | **Slug:** `phoneenum` | **Tools Dir:** `~/jabber/jabber-tools/phoneenum/`
**Package:** `com.jabber.jabber.modules.phoneenum` | **Group:** Access & Penetration
**Exemption:** This category is EXEMPT from the Two-Mode Execution requirement. It utilizes high-fidelity, unified deep execution flows.

---

## 1. Standardized Infrastructure
Every module in this category MUST implement the following self-contained architecture:
- **`[ModuleName]Module.java`**: Controller defining the deep input schema.
- **`[ModuleName]Engine.java`**: Core orchestrator implementing the 8-step execution loop.
- **`ToolManager.java`**: Registry for `adb`, `frida`, `objection`, `drozer`, etc.
- **`InputSanitizer.java`**: Strict validation for Serial Numbers/UDIDs and package names.
- **`ProcessExecutor.java`**: Thread-safe process runner for long-running mobile audits.
- **`ReportGenerator.java`**: Aggregates mobile artifacts and telemetry into the **Artifacts System (Category 21)**.

---

## 2. Execution Doctrine (High-Fidelity)
Modules in this category do not use modes. They perform a single, exhaustive audit flow:
1.  **Validate Connection**: Verify device connectivity via `adb devices` or `idevice_id`.
2.  **Environment Audit**: Capture system properties, kernel info, and security patch levels.
3.  **Process Interrogation**: Use `frida` to map active processes and hooks.
4.  **Artifact Extraction**: Physically pull SQLite databases, XML preferences, and application binaries (`.apk`/`.ipa`).
5.  **Forensic Integrity**: Every extracted file is hashed (SHA256) and stored in `reports/artifacts/`.

---

## 3. Frontend Requirements
- **Device Selector**: UI component to refresh and select connected ADB/iOS devices.
- **Artifact Gallery**: Direct integration with Category 21 to view extracted databases and screen captures.
- **Live Console**: Real-time streaming of `adb logcat` or `frida` output.

---

## 4. Modules

### 1. AndroidEnumerationModule
**ID:** `phoneenum-android` | **Risk:** HIGH | **File:** `AndroidEnumerationModule.java`
**Tools:** `adb`, `frida`, `objection`, `drozer`, `apktool`

#### Unified Execution Flow:
1. `adb -s <serial> shell getprop` (System Properties)
2. `adb -s <serial> shell pm list packages -f -3` (App Inventory)
3. `adb -s <serial> pull /data/system/users/0/settings_secure.xml reports/artifacts/` (Security Config)
4. `frida-ps -D <serial>` (Active Process Map)
5. `objection -g <serial> explore -c "android pairing list"` (Bluetooth/Pairing Audit)
6. `adb -s <serial> shell screencap -p /sdcard/audit.png && adb pull /sdcard/audit.png reports/artifacts/` (Visual Evidence)

#### Output Generation & Artifacts:
- **`reports/artifacts/ENUM_[TS]_android_dump.zip`**: Consolidated dump of system metadata.
- **`reports/artifacts/ENUM_[TS]_secure_settings.xml`**: Extracted security configuration file.
- **`reports/artifacts/ENUM_[TS]_device_screenshot.png`**: High-resolution screen capture of the device state.
- **`reports/outputs/ENUM_[TS]_app_inventory.json`**: Structured list of all 3rd party apps and their base paths.

---

### 2. iOSEnumerationModule
**ID:** `phoneenum-ios` | **Risk:** HIGH | **File:** `iOSEnumerationModule.java`
**Tools:** `ideviceinfo`, `ideviceinstaller`, `frida`, `objection`, `iproxy`

#### Unified Execution Flow:
1. `ideviceinfo -u <udid> -s` (Core Device Metadata)
2. `ideviceinstaller -u <udid> -l` (Installed Application Audit)
3. `iproxy 2222 22 -u <udid> &` (Establish SSH Tunnel)
4. `ssh root@localhost -p 2222 "ls -R /var/mobile/Containers/Data/Application"` (Data Path Discovery)
5. `frida-ps -U` (USB Process Interrogation)
6. `objection -g <udid> explore -c "ios keychain dump"` (Keychain Artifact Extraction)

#### Output Generation & Artifacts:
- **`reports/artifacts/ENUM_[TS]_ios_keychain.json`**: Extracted keychain items (if jailbroken/accessible).
- **`reports/artifacts/ENUM_[TS]_device_info.xml`**: Complete device identity and status report.
- **`reports/outputs/ENUM_[TS]_ios_apps.json`**: Catalog of bundles, versions, and entitlements.
- **`reports/analysis/ENUM_[TS]_process_map.json`**: Technical map of active processes via Frida.

---

**© 2026 Funbinet Inc. — JABBER V 5.5.0.0**
