# Windows event logs + ART detection

## Objective
This project demonstrates the setup, execution, and analysis of Windows Event Logs using Sysmon and Splunk. By leveraging the Atomic Red Team (ART) framework and aligning with the MITRE ATT&CK framework, the project focuses on simulating adversary techniques and detecting them effectively.

### Skills Learned

Windows Event Logging:

-Configured Sysmon for capturing detailed system activity logs.



Log Management & Analysis:

-Ingested, queried, and analyzed event logs using Splunk.
-Built structured Splunk queries for filtering, table creation, and process analysis.



Adversary Simulation:

-Simulated real-world adversary behaviors using the Atomic Red Team framework.
-Executed specific MITRE ATT&CK techniques (e.g., T1197 - BITS Jobs).



Threat Detection & Investigation:

-Mapped events to the MITRE ATT&CK framework for detection and analysis.
-Identified parent-child process relationships for suspicious activity detection.



Tool Proficiency:

-Hands-on experience with Sysmon, Splunk, Atomic Red Team, and VirtualBox.



Problem-Solving:

-Troubleshot antivirus interference by configuring exclusions.
-Managed large event data effectively using Splunk’s search capabilities.



Practical Threat Hunting:

-Validated false positives by cross-referencing with MITRE ATT&CK’s detection guidelines.



### Tools Used


Sysmon (System Monitor)

-For generating detailed Windows Event Logs, capturing process creation, network connections, and file modifications.



Splunk

-Used for log ingestion, analysis, and creating custom search queries to identify malicious activity.



Atomic Red Team (ART)

-A framework for simulating adversary behaviors mapped to the MITRE ATT&CK framework.



VirtualBox

-To create a controlled environment for testing, using a Windows 10 virtual machine.



MITRE ATT&CK Framework

-As a reference to map simulated adversary techniques and design detection strategies.



PowerShell

-For configuring Sysmon, managing the ART framework, and executing simulated techniques.



Windows Defender

-Configured to manage antivirus exclusions for smoother testing.



## Steps


1.Installed and Configured Sysmon

-Downloaded Sysmon and applied a custom configuration file to enable detailed logging of critical system events.


2.Installed and Set Up Splunk

-Deployed Splunk and configured the platform to ingest logs for centralized analysis.


3.Set Up a Virtual Environment

-Created a Windows 10 virtual machine using VirtualBox and an ISO image. Configured the environment for testing purposes.
 

4.Launched PowerShell as Administrator

-Ensured administrative privileges for seamless execution of scripts and frameworks.


5.Bypassed Execution Policy

-Ran the following command to bypass the execution policy temporarily, as recommended by the official documentation to avoid potential errors:

 Set-ExecutionPolicy Bypass -Scope CurrentUser


6.Installed the Atomic Red Team (ART) Execution Framework

-Installed the ART framework directly from its official repository without relying on the PowerShell Gallery:

 IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
 Install-AtomicRedTeam


7.Excluded the Atomic Folder in Antivirus Settings

-Added the Atomic Red Team folder to the antivirus exclusion list to prevent interference during testing.


8.Reinstalled the Execution Framework

-Reinstalled the framework with all techniques to ensure full functionality:

 Install-AtomicRedTeam -GetAtomics -Force


9.Verified Available ART Tests

-Used the following command to list and review all available Atomic Red Team tests:

 Invoke-AtomicTest ALL -ShowDetailsBrief


10.Selected a Technique from the MITRE ATT&CK Framework

-Navigated to the MITRE ATT&CK website and chose a technique of interest. Selected "BITS Jobs" under the Persistence category, with event ID T1197.


11.Inspected Techniques Related to T1197

-Reviewed available tests for T1197 using:

 Invoke-AtomicTest T1197 -ShowDetailsBrief


12.Executed Atomic Tests for T1197

-Ran all available tests for T1197 to simulate the technique:

 Invoke-AtomicTest T1197


13.Configured Splunk for Sysmon Log Ingestion

-Added the Sysmon log file path as a data input in Splunk to enable the monitoring of Sysmon events.


14.Verified Sysmon Events in Splunk

-Queried Sysmon events to confirm that the logging configuration was operational:

 index=main source="C:\\windows\\system32\\winevnt...etc"


15.Searched for Events Related to ART Tests

-Filtered events in Splunk to identify those associated with the Atomic Red Team tests, such as bitsadmin.exe:

 index=main source="C:\\windows\\system32\\winevnt...etc" eventcode=1 image="*bitsadmin.exe*"


16.Created a Process Analysis Table for Readability

-Built a table in Splunk for parent-child process analysis to enhance readability:

 index=main source="C:\\windows\\system32\\winevnt...etc" eventcode=1 image="*bitsadmin.exe*"
 | table _time, parentimage, parentcommandline, image, commandline
 | sort +_time


17.Reviewed MITRE ATT&CK Detection Guidelines

-Consulted the "BITS Jobs" detection section on the MITRE ATT&CK website for keywords such as "create" and "transfer" to refine searches.


18.Validated Keywords in Splunk

-Queried Splunk for related keywords (e.g., cmd.exe, create, transfer) to confirm that these were legitimate events and not false positives.



#### SCREENSHOTS


-sysmon functionality verification

![1 sysmon functionality verification](https://github.com/user-attachments/assets/1799e35b-c0d1-4d01-ae57-aa169044113f)




-preparing for the execution framework

![2 preparing for the execution framework](https://github.com/user-attachments/assets/a9ab8007-1e81-4942-a112-5b27caf4a7e5)




-installing execution framework along with the folder

![3 installing execution framework along with the atomic folder](https://github.com/user-attachments/assets/2a123441-7248-436f-acaf-24a44fd046f1)




-atomic folder

![4 atomic folder](https://github.com/user-attachments/assets/45be396d-aea9-4163-bfe4-0ad967dd7630)




-excluding the ART folder in anti virus

![5 excluding the ART folder in anti virus](https://github.com/user-attachments/assets/3e7e9026-8eb3-4e44-9e97-5eea9cc06e96)




-reinstalling execution framework

![6 reinstalling execution framework](https://github.com/user-attachments/assets/a9654154-d3ee-4def-aa63-010e96fae8cd)




-verifying available ART tests

![7 verifying available ART tests](https://github.com/user-attachments/assets/c4133d68-f483-4234-ba9a-bdfc2900b531)




-identifying the relavant MITRE ATTACK technique

![8 identifying the relavent MITRE ATTACK technique](https://github.com/user-attachments/assets/1f3d5e27-eb08-4e46-ad35-d7803f868b9e)




-insprecting T1197 techniques details

![9 inspecting T1197 techniques details](https://github.com/user-attachments/assets/66a65d3b-32fc-41bb-a649-952840163c27)




-executes the tests for T1197

![10 executes the tests for T1197](https://github.com/user-attachments/assets/85031259-7358-41e3-b460-44e4e71187d3)




-search for sysmon events related to ART tests

![11 search for sysmon events in splunk related to ART tests](https://github.com/user-attachments/assets/a4933a00-08de-4b51-bbc3-85adb4e15327)




-refer to MITRE ATTACK for detection guidance

![12 refer to MITRE ATTACK for detection guidance](https://github.com/user-attachments/assets/a108a99a-254b-4ca6-b00d-0cec89d5ace5)




-create a table for parent-child process analysis 

![13 create a table for parent-child process analysis](https://github.com/user-attachments/assets/60bf253b-2c05-40f9-90f3-f12ccebf57b0)




-analyze the tabel for suspicious keywords

![14 analyze the table for suspicious keywords](https://github.com/user-attachments/assets/b632f33b-0d8b-4d34-ae3b-b1a0121b88b4)




# Resources

### https://www.microsoft.com/en-ca/software-download/windows10
### https://www.virtualbox.org/
### https://git-scm.com/
### https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
### https://github.com/olafhartong/sysmon-modular
### https://www.splunk.com/
### https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam
### https://attack.mitre.org/
