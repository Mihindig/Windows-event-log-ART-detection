# **Detecting Evil with Splunk and MITRE ATT&CK**

## **Introduction**  
Cybersecurity isn’t just about running queries—it’s about understanding **how attackers think and operate**. Attackers follow patterns, and frameworks like **MITRE ATT&CK** and **Splunk** allow us to track these patterns and detect their movements.

In this write-up, I’ll walk you through how I used Splunk, MITRE ATT&CK, and **Atomic Red Team tests** to detect adversary techniques in action. I’ll include **actual event data captured in Splunk**, highlight the sections of MITRE ATT&CK that informed my detection methods, and showcase how defenders can create meaningful rules to flag **malicious activity** while avoiding noise.

Here’s what we’ll cover:  
- Mapping **BITS Job (T1197)** and **PowerShell Execution (T1059.001)** to real-world attack scenarios.  
- Using **Splunk queries** to spot attackers.  
- Applying **MITRE ATT&CK detection guidance** to differentiate **evil from false positives**.  
- Crafting **basic detection rules** that improve SOC workflows.  

---

## **Technique 1: BITS Job (T1197)**  

### **Simulating the Attack**  
The attacker leverages the legitimate tool `bitsadmin.exe` to transfer files while bypassing detection. Once the file is transferred, they set up a **scheduled task** to execute a payload later—establishing persistence.  

**Test Details:**  
```plaintext
Invoke-AtomicTest T1197 -ShowDetailsBrief  
Invoke-AtomicTest T1197  
```

---

### **Captured Events in Splunk**  
Below is the query I ran to detect `bitsadmin.exe` usage:  
```plaintext
index=project bits  
| search (CommandLine="*bitsadmin*" OR CommandLine="*CreateTask*")  
| table _time, ParentImage, ParentCommandLine, Image, CommandLine  
| sort +_time  
```

Here’s an example Splunk event captured during the test:  

| **_time**         | **ParentImage** | **ParentCommandLine**                    | **Image**     | **CommandLine**                              |  
|--------------------|-----------------|------------------------------------------|--------------|----------------------------------------------|  
| 2025-04-07 13:00  | cmd.exe         | C:\Windows\System32\cmd.exe              | bitsadmin.exe | bitsadmin.exe /create AttackBits /addfile    |  

---

### **Using MITRE ATT&CK Detection Guidance**  
To detect this, I referenced **MITRE ATT&CK’s T1197 Detection Section**. Here’s what I looked for:  
- **Unusual Parent Processes:** `bitsadmin.exe` spawned by `cmd.exe` instead of a typical system utility.  
- **Suspicious Flags in Commands:** `/addfile` pointing to external domains.  
- **Scheduled Tasks:** Commands involving `/setnotifycmdline` that trigger persistence.

---

### **Differentiating False Positives from Evil**  
Here’s the breakdown:  
- **False Positive:** `bitsadmin.exe` transferring legitimate files during Windows updates. Example: `/create update_task`.  
- **Evil:** `bitsadmin.exe` downloading a payload from `maliciousdomain.com` with a task scheduled for execution.  

Key highlight: **Not all BITS jobs are threats**. Focus on external domains, odd execution chains, or unusually timed commands.

---

## **Technique 2: PowerShell Execution (T1059.001)**  

### **Simulating the Attack**  
Attackers use PowerShell for script execution, reconnaissance, and privilege escalation. In this simulation, I ran a command to check user privileges using `whoami.exe`.  

**Test Details:**  
```plaintext
Invoke-AtomicTest T1059 -ShowDetailsBrief  
Invoke-AtomicTest T1059  
```

---

### **Captured Events in Splunk**  
Below is the query I ran to detect PowerShell activity:  
```plaintext
index=project powershell  
| search (ParentImage="*\\powershell.exe" OR Image="*\\powershell.exe")  
| table _time, ParentImage, ParentCommandLine, Image, CommandLine  
| sort +_time  
```

Here’s an example Splunk event captured during the test:  

| **_time**         | **ParentImage**       | **ParentCommandLine**                   | **Image**        | **CommandLine**                 |  
|--------------------|-----------------------|------------------------------------------|------------------|---------------------------------|  
| 2025-04-07 13:10  | powershell.exe        | C:\Windows\System32\WindowsPowerShell\  | powershell.exe   | powershell.exe whoami.exe       |  

---

### **Using MITRE ATT&CK Detection Guidance**  
To detect this, I referenced **MITRE ATT&CK’s T1059.001 Detection Section**. Here’s what I looked for:  
- **Unusual Binaries Executed:** PowerShell running `whoami.exe`, which isn’t typical admin usage.  
- **Obfuscated Commands:** Parameters like `-EncodedCommand`.  
- **Parent-Child Relationships:** PowerShell launched by non-admin applications (e.g., Office macros).

---

### **Differentiating False Positives from Evil**  
Here’s the breakdown:  
- **False Positive:** PowerShell executed by IT administrators running maintenance scripts. Example: `Get-ADUser`.  
- **Evil:** PowerShell runs obfuscated payloads (`-EncodedCommand`) or commands like `whoami.exe` for privilege enumeration.  

Key highlight: Not all PowerShell usage is malicious. **Focus on encoded commands, suspicious binaries, or odd invocation chains.**

---

## **Building Basic Detection Rules**  

### **PowerShell Detection Rule**  
Here’s a rule that flags PowerShell executing reconnaissance commands:  
```plaintext
index=project powershell  
| search (Image="*\\powershell.exe")  
| eval alert_type=if(match(CommandLine, "whoami"), "Potential Recon", "Unknown")  
| where alert_type="Potential Recon"  
| stats count by _time, alert_type, CommandLine  
```

---

## **What Else Can You Do?**  
You’ve captured key events, mapped them to MITRE ATT&CK, and built detection rules—but what’s next?  

🔹 Expand framework application:  
- Test additional MITRE ATT&CK techniques like **Registry Modifications** or **Lateral Movement**.  
- Correlate techniques to build **attack sequences** in Splunk.

🔹 Add more educational value:  
- Document **step-by-step guides** for SOC analysts to detect these techniques.  
- Highlight MITRE ATT&CK sections with relevant detection recommendations.  

---

## **Final Thoughts**  
This project demonstrates how **small attack simulations reveal big lessons**. By tying Splunk events to frameworks like MITRE ATT&CK and the Cyber Kill Chain, you can develop detection strategies that track attacker actions while filtering out benign noise.  

Cybersecurity isn’t just about finding threats—it’s about knowing **what’s worth chasing** and **how to chase smarter**.  

---

## **Screenshots**

### PowerShell Execution Policy Setup

![PowerShell Execution Policy Setup](https://github.com/caitwork/MITREATTACK/blob/main/powershell_executionpolicy_setup.png)

- First, I configured PowerShell to allow script execution by setting the execution policy to `Bypass`, This is a crucial step to ensure that Atomic Red Team tests run smoothly without restrictions.

### Atomic Red Team Installation

![Atomic Red Team Installation](https://github.com/caitwork/MITREATTACK/blob/main/Atomic_Red_Team_Installation.png)

- This screenshot shows the PowerShell commands used to install Atomic Red Team, including fetching and running the installation script. It highlights the installation prompt for the NuGet provider and confirmation of successful setup.

### Windows Security Exclusion ART

![Windows Security Exclusion ART](https://github.com/caitwork/MITREATTACK/blob/main/Windows_Security_Exclusion_ART.png)

- Here, I excluded the `C:\AtomicRedTeam` folder from Microsoft Defender’s scans to ensure adversary simulation tests run smoothly without interference from antivirus protections.

### ART Installation Complete

![ART Installation Complete](https://github.com/caitwork/MITREATTACK/blob/main/ART_Installation_Complete.png)

- This screenshot shows the execution of `Install-AtomicRedTeam` in PowerShell to install adversary simulation tests. The success message confirms that Atomic tests are ready to run, and defenders can refer to the wiki for detailed documentation.

### ART Invocation All Tests

![ART Invocation All Tests](https://github.com/caitwork/MITREATTACK/blob/main/ART_Invocation_AllTests.png)

- This screenshot displays the invocation of Atomic Red Team tests using the `-ShowDetailsBrief` flag to list available techniques. These tests simulate real-world adversary tactics like credential dumping, helping defenders validate detection capabilities.

### Inputs.conf Sysmon

![Inputs.conf Sysmon](https://github.com/caitwork/MITREATTACK/blob/main/Inputs.conf_Sysmon.png)

- This screenshot captures the configuration of Splunk inputs to ingest Sysmon logs, specifying the source type and index for event tracking. Sysmon logs are crucial for detecting adversary behaviors like process execution, aiding in detailed threat analysis.

### Splunk New Index

![Splunk New Index](https://github.com/caitwork/MITREATTACK/blob/main/Splunk_New_Index.png)

- This screenshot shows the creation of a new Splunk index named `project` . This index is dedicated to storing Sysmon logs, ensuring that the data from my detection experiments is organized and easily accessible for analysis.

### Splunk Sysmon Add On Installed

![Splunk Sysmon Add On Installed](https://github.com/caitwork/MITREATTACK/blob/main/Splunk_Sysmon_Add_On_Installed.png)

- This screenshot captures the successful installation of the Splunk Add-on for Sysmon, a key component for ingesting and analyzing Sysmon logs. This add-on enables Splunk to parse events and track attacker activity more effectively.

### ART T1197 BitsJob

![ART T1197 BitsJob](https://github.com/caitwork/MITREATTACK/blob/main/ART_T1197_BitsJob.png)

- This screenshot showcases the execution of Atomic Red Team tests for T1197 (BITS Job abuse). The results highlight various techniques attackers use, including file transfers, setting persistence, and launching executables, all while leveraging `bitsadmin.exe` .

### Splunk BitsJob Queries

![splunk_bitsadmin1](https://github.com/caitwork/MITREATTACK/blob/main/splunk_bitsadmin_1.png)

- This screenshot displays the results of a Splunk query analyzing BITS Job activity (T1197). It highlights task creation, file transfer, and execution commands using `bitsadmin.exe`, showcasing how attackers can misuse legitimate system utilities for persistence and payload delivery.


![splunk_bitsadmin2](https://github.com/caitwork/MITREATTACK/blob/main/splunk%20bitsadmin%202_.png)

- This screenshot highlights the results of a Splunk query for analyzing BITS Job activity (T1197). It focuses on command-line operations like task creation, file download, and notification setup, illustrating how attackers can misuse `bitsadmin.exe` to deliver payloads and achieve persistence.

### ART T1059 error

![ART_T1059_error](https://github.com/caitwork/MITREATTACK/blob/main/ART_T1059_error.png)

- This screenshot showcases the execution of Atomic Red Team test T1059.1 (AutoIt Script Execution) using PowerShell. The error message highlights a missing dependency (`Autolt3.exe`), providing insights into troubleshooting simulated attack techniques.

### Splunk Powershell Query

![splunk powershell query](https://github.com/caitwork/MITREATTACK/blob/main/splunk_powershell_query.png)

- This screenshot displays the results of a Splunk query for PowerShell activity (T1059.001). It highlights process relationships, timestamps, and executed commands like `whoami.exe`, offering insights into potential reconnaissance or misuse of PowerShell.

---

Yes, everything looks well-aligned and cohesive! Adding the **resources section** with links will tie it together neatly and make your project even more useful for readers. You can structure it like this:

---

## **Resources**  

- [Splunk: Operational Intelligence and Security Platform](https://www.splunk.com/)  
- [Microsoft Sysmon: Download and Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)  
- [Sysmon Modular: Advanced Configuration Repository](https://github.com/olafhartong/sysmon-modular)  
- [MITRE ATT&CK Framework: Tactics and Techniques](https://attack.mitre.org/)  
- [Cyber Kill Chain by Lockheed Martin](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)  
- [Atomic Red Team: Installation and Usage Guide](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam)  

---
Please make sure when playing around with these tools,make sure to use an isolated enviorement,such as virtual machines!




