# Windows event logs + ART detection

# Objective

This project demonstrates the use of Sysmon and Splunk for analyzing Windows Event Logs, simulating adversarial activity using Atomic Red Team (ART), and detecting potential security threats. The project integrates Sysmon for detailed event collection, Splunk for log analysis, and the MITRE ATT&CK framework for mapping attack techniques. It showcases practical threat detection, incident response capabilities, and the ability to manage large volumes of data while filtering for relevant security events.

# Skills Acquired

1. Windows Event Logging and Analysis

* Sysmon Configuration: Installed Sysmon with a custom XML configuration for monitoring detailed system activities such as process creation, network connections, and file changes.
Splunk Integration: Ingested Sysmon logs into Splunk for centralized analysis and real-time monitoring of system activities, enabling effective detection of malicious behavior.

2. Adversary Simulation Using ART

* Simulated advanced persistent threats using the ART framework, aligning with MITRE ATT&CK techniques, specifically T1197 (BITS Jobs), to emulate persistence tactics.
Executed all ART tests related to T1197 to create a comprehensive set of logs for analysis.

3. Threat Detection and Investigation

* Analyzed logs in Splunk for suspicious activities, specifically identifying process creation and parent-child process relationships related to BITS Jobs.
Applied MITRE ATT&CK’s detection guidelines to validate findings, ensuring that alerts for suspicious behavior were not false positives.

4. Process Analysis with Splunk

* Created a parent-child process relationship table in Splunk for better readability of system activity, which is vital for detecting suspicious processes and identifying chains of execution.

5. Incident Response and Troubleshooting

* Addressed and troubleshot issues, including an accidental error caused by closing a tab while running tests, which was resolved by re-importing the ART module.



# Tools Used

* Sysmon: Installed and configured Sysmon to collect event logs on process creation, file system activity, network connections, and more.

* Splunk: Utilized Splunk for centralized log collection, query building, and creating actionable insights from Sysmon logs.

* Atomic Red Team (ART): Leveraged ART to simulate adversarial activities based on the MITRE ATT&CK framework.

* MITRE ATT&CK Framework: Referenced for understanding and mapping adversary tactics, techniques, and procedures (TTPs).

* PowerShell: Used for configuring Sysmon, managing ART modules, and bypassing execution policies during testing.

* Windows Defender: Configured to exclude ART-related folders to prevent interference during testing.



## Project Workflow

1. Virtual Machine Setup and Configuration

* Set up a Windows 10 Pro VM using VirtualBox with 4GB RAM and 2 CPUs to handle event logging and testing without performance issues.

* Ensure the system has enough resources to run tests smoothly and prevent system lag or crashes.

* Optimizing resource allocation shows good system management skills, which are crucial in real-world environments, especially when dealing with large logs and system processes.


2. Sysmon Configuration and Log Collection

* Installed Sysmon with a custom sysmonconfig.xml to capture detailed logs of process creation, network connections, and file modifications.

* Verified logs in Event Viewer to ensure Sysmon was functioning correctly.

* Configuring Sysmon allows for effective monitoring of system activities, crucial for detecting suspicious actions like malware or unauthorized processes.


3. Splunk Configuration

* In Splunk, configured the data inputs to ingest Sysmon logs and validated the configuration by querying the logs.

* Successfully ingested Sysmon logs and queried them using filters for event ID 1 and the bitsadmin.exe process.

* Properly configuring Splunk for log ingestion ensures smooth data collection and analysis. In the enterprise context, this is essential for centralizing logs and quickly identifying malicious 
activity.


4. ART Setup and Test Execution

* Installed Atomic Red Team (ART) framework following official guidelines and excluded ART’s folder from Windows Defender to avoid interference during testing.

* Ran the full set of ART tests related to T1197 (BITS Jobs) to simulate persistence tactics.

* ART helps simulate real-world adversarial techniques, which is key in testing detection capabilities. Running a comprehensive set of tests ensures you cover various attack vectors.


5. Log Analysis in Splunk

* Filtered Sysmon logs in Splunk for Event ID 1 related to the execution of bitsadmin.exe, a tool used for persistence in BITS Jobs.

* Created a process analysis table to visualize parent-child process relationships.

index=main source="path\to\sysmon\logs.evtx" eventcode=1 image="bitsadmin.exe" 
| table _time, ParentImage, ParentCommandLine, Image, CommandLine 
| sort +_time

* This step enables clear visibility of the processes related to BITS Jobs, helping analysts detect malicious persistence behaviors by analyzing parent-child process relationships.


6. MITRE ATT&CK Framework Application

* Reviewed relevant MITRE ATT&CK techniques for T1197 (BITS Jobs), including keywords like cmd.exe, create, and transfer.

* Used these keywords to refine searches in Splunk and correlate findings with known attack techniques.

* The MITRE ATT&CK framework is a vital resource for mapping and understanding adversary tactics. Applying this framework to real-world scenarios enhances the ability to detect and respond to sophisticated attacks.


7. Error Resolution and Troubleshooting

* Encountered an issue when accidentally closing the ART test tab while executing tests.

* Resolved the issue by re-importing the ART module, allowing tests to run smoothly.

* Troubleshooting and resolving issues independently shows problem-solving skills and the ability to recover from technical setbacks without significant downtime.

# Project Reflection and Areas for Improvement (If This Were a Real-World Scenario):

* False Positive Handling (Not Applicable in This Demo)

In this demo project, I didn’t encounter any false positives since the tests were simulated. However, in a real-world environment, handling false positives effectively would be a critical part of the threat detection process. If false positives were flagged, I would carefully cross-reference logs with MITRE ATT&CK detection guidelines, manually verify the logs, and refine detection rules to minimize unnecessary alerts. Developing a solid process for false positive handling would be an important part of ensuring that a security system doesn’t become overwhelmed by non-malicious activity.

* Real-World Application (Demonstrated in a Simulated Environment)

While this demo focused on simulating adversary behaviors and did not involve actual attacks, in a real-world setting, the same approach would be invaluable for detecting and defending against persistent threats like BITS Jobs. I would integrate Sysmon and Splunk to continuously monitor systems, detect adversarial techniques in real-time, and quickly respond to attacks such as data exfiltration or lateral movement. Although the demo didn’t trigger real alerts, these tools and techniques are critical for protecting enterprise environments.

# Additional Information on Real-World Application and Enhancements (Beyond This Demo):

* Demo Limitations (What Was Not Tested in This Demo)

As this project was intended for demonstration purposes, no real threats were executed, and flagging wasn’t necessary. If this had been a live environment, I would have focused on actively monitoring logs for real malicious activities and would have had to address any actual threats or alerts triggered during the process. This project’s demo nature didn’t require active threat detection or remediation steps, but in a real-world scenario, managing those would be a key responsibility.

* Enhanced Detection and Analysis (Beyond Demo Scope)

The project focused mainly on simulating specific adversarial techniques and querying event logs. However, in a real-world scenario, I would expand this approach by cross-referencing network traffic, endpoint logs, and threat intelligence feeds to improve threat detection capabilities. This would allow for a more comprehensive analysis of suspicious behavior, making the detection system more robust and capable of identifying potential attacks from multiple angles.


# SCREENSHOTS


# sysmon functionality verification

![1 sysmon functionality verification](https://github.com/user-attachments/assets/1799e35b-c0d1-4d01-ae57-aa169044113f)




# preparing for the execution framework

![2 preparing for the execution framework](https://github.com/user-attachments/assets/a9ab8007-1e81-4942-a112-5b27caf4a7e5)




# installing execution framework along with the folder

![3 installing execution framework along with the atomic folder](https://github.com/user-attachments/assets/2a123441-7248-436f-acaf-24a44fd046f1)




# atomic folder

![4 atomic folder](https://github.com/user-attachments/assets/45be396d-aea9-4163-bfe4-0ad967dd7630)




# excluding the ART folder in anti virus

![5 excluding the ART folder in anti virus](https://github.com/user-attachments/assets/3e7e9026-8eb3-4e44-9e97-5eea9cc06e96)




# reinstalling execution framework

![6 reinstalling execution framework](https://github.com/user-attachments/assets/a9654154-d3ee-4def-aa63-010e96fae8cd)




# verifying available ART tests

![7 verifying available ART tests](https://github.com/user-attachments/assets/c4133d68-f483-4234-ba9a-bdfc2900b531)




# identifying the relavant MITRE ATTACK technique

![8 identifying the relavent MITRE ATTACK technique](https://github.com/user-attachments/assets/1f3d5e27-eb08-4e46-ad35-d7803f868b9e)




# insprecting T1197 techniques details

![9 inspecting T1197 techniques details](https://github.com/user-attachments/assets/66a65d3b-32fc-41bb-a649-952840163c27)




# executes the tests for T1197

![10 executes the tests for T1197](https://github.com/user-attachments/assets/85031259-7358-41e3-b460-44e4e71187d3)




# search for sysmon events related to ART tests

![11 search for sysmon events in splunk related to ART tests](https://github.com/user-attachments/assets/a4933a00-08de-4b51-bbc3-85adb4e15327)




# refer to MITRE ATTACK for detection guidance

![12 refer to MITRE ATTACK for detection guidance](https://github.com/user-attachments/assets/a108a99a-254b-4ca6-b00d-0cec89d5ace5)




# create a table for parent-child process analysis 

![13 create a table for parent-child process analysis](https://github.com/user-attachments/assets/60bf253b-2c05-40f9-90f3-f12ccebf57b0)




# analyze the tabel for suspicious keywords

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

## License:
© Mihindig 2025. All rights reserved.

This repository is for educational purposes only. Unauthorized use, redistribution, or commercial use of this code is prohibited without explicit permission from the author. Please do not copy or redistribute without providing appropriate credit.


## Contact:
<a href="https://www.linkedin.com/in/mihindi-gunawardana-44a0a432b">
    <img src="https://img.shields.io/badge/-LinkedIn-0072b1?&style=for-the-badge&logo=linkedin&logoColor=white" />
</a>


