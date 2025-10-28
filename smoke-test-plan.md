# **Smoke Test Plan**

## **Overview**

This document outlines the tiered smoke test plan for validating new device images. Three selectable smoke-test depths are defined: **S1 Minimal**, **S2 Guided**, and **S3 Lab Deep Test**.

* Choose **S1** for fast bring-up and initial checks.  
* Choose **S2** as the recommended default gate for image promotion.  
* Choose **S3** for full release qualification.

All outputs (bootlogs, nvram dumps, validation JSON) **must be archived** alongside image artifacts for complete traceability.

## **S1 Minimal**

### **Purpose**

Fast confirmation that the image boots and the device identity is correct.

### **Prerequisites**

* Device reachable for flashing via vendor recovery or TFTP.  
* Serial console access (typical baud: 115200).

### **Steps**

1. Flash the candidate image to the device.  
2. Connect serial and start capture; power on the device.  
3. Capture until kernel completes init or for 60–120 seconds.  
4. Verify bootloader banner appears and kernel prints a **"Linux version"** line.  
5. Search captured logs for at least one **MAC address** and confirm it matches the profile's expected OUI or nvram entry.

### **Pass Criteria**

* Bootloader banner visible and kernel reaches init.  
* MAC address present and matches expected vendor pattern.

### **Artifacts to save**

* Serial capture file, timestamped.  
* Any nvram export if available.

## **S2 Guided**

### **Purpose**

Recommended step-by-step verification after a successful S1 run to confirm boot behavior, partition layout, and basic networking.

### **Prerequisites**

* Serial console connected.  
* Ethernet connection for LAN tests.  
* Original firmware backup available.

### **Steps**

1. Start serial capture and power on; capture **full boot** (3–5 minutes).  
2. Verify bootloader prints environment and flash detection messages; note **bootcmd** behavior.  
3. Confirm kernel prints "Linux version" and lists detected flash partitions (**mtd** or **parted** output).  
4. Compare observed partition names/offsets on serial with the profile's flash layout; record mismatches.  
5. Boot to operational state; bring up LAN interface (DHCP or static) and confirm link LED and carrier.  
6. From host, ping device management IP or attempt HTTP(S) UI access on expected port.  
7. Dump nvram or read U-Boot env; compare keys **board\_id**, **wl\_country**, **et0macaddr** against profile.  
8. Capture and store the post-flash nvram export and the full bootlog for re-ingestion.

### **Pass Criteria**

* Device boots to usable state and responds to basic network probes.  
* Partition table observed aligns with profile within reasonable tolerance.  
* Critical nvram/bootenv keys present and match expected patterns.

### **Artifacts to save**

* Full bootlog.  
* Parsed profile diff notes.  
* Nvram export.  
* Network probe logs.  
* Operator notes.

## **S3 Lab Deep Test**

### **Purpose**

Full device qualification for release candidates covering persistence, reset behavior, Wi‑Fi calibration, filesystem checks, and stability.

### **Prerequisites**

* Lab bench with controlled power and network.  
* RF test harness or calibrated environment for Wi‑Fi validation preferred.  
* Multiple identical devices recommended.

### **Steps**

#### **Baseline**

1. Record original firmware version and create a full backup image before flashing.

#### **Flash and Verify**

2. Flash candidate image and verify file checksums match expected values.  
3. Capture full boot (5–10 minutes) and archive logs.

#### **Factory Reset Verification**

4. Perform hardware-button factory reset and verify expected behavior.  
5. Perform software nvram erase and verify expected behavior after reboot.

#### **Persistence Verification**

6. Configure persistent settings (admin password, LAN IP, Wi‑Fi SSID), reboot, and confirm settings persist.

#### **Wireless Validation**

7. Verify runtime regulatory domain equals nvram **wl\_country**.  
8. If RF lab available, run transmit tests and verify per-chain power and allowed channel list.  
9. Validate association to a known AP and perform a short throughput check (**iperf**).

#### **Filesystem and Partition Checks**

10. Mount/extract filesystem partitions from the flashed device or image.  
11. Verify presence and checksums of critical files (/etc/config/, /etc/init.d/).  
12. Confirm overlay persistence across reboots.

#### **Stability and Stress**

13. Run a **1-hour uptime test** with continuous pings and periodic resource sampling.  
14. Monitor for kernel panics, watchdog resets, or nvram corruption.

#### **Security and Regression Checks**

15. Ensure administrative defaults meet policy (no unintended open accounts).  
16. Verify debug interfaces are not unintentionally exposed.

### **Pass Criteria**

* Successful factory reset and restore behavior.  
* Persistent configuration across reboots.  
* Wireless calibration and regulatory compliance within expected deltas.  
* Filesystem artifacts present and checksums match baselines.  
* Stability across stress window with no kernel panics or resets.

### **Artifacts to save**

* Full bootlogs.  
* Nvram exports.  
* RF calibration reports.  
* Filesystem extraction checksums.  
* Uptime/stability logs.  
* Test notes.

## **Operator Guidance**

* Use **S1** for rapid iteration and low-risk validation during early development.  
* Gate CI or manual promotion with **S2** as the standard recommended test depth.  
* Reserve **S3** for release candidates, architecture or toolchain changes, or when partition layouts change.  
* Always timestamp and tag artifacts with operator ID and git commit of mapping DB and manifest used.  
* Automate serial capture, nvram collection, and artifact upload to your traceability storage where possible.  
* Record deviations and create follow-up tickets for firmware, profile, or manifest fixes when tests fail.