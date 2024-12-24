# MITRE ATT&CK Persistence Detection with Splunk

## Objective
The aim of this project was to simulate and detect adversary tactics and techniques leveraging Splunk, Sysmon, the MITRE ATT&CK framework, and Atomic Red Team (ART). The focus was on generating and analyzing logs to identify malicious activity, enhancing skills in endpoint monitoring, log analysis, and SIEM querying for real-world cybersecurity defense. This hands-on project provided practical experience in detecting persistence mechanisms used by adversaries and improving defensive measures.

### Skills Learned

- SIEM Implementation & Log Analysis: Gained practical experience with Splunk for effective log ingestion, querying, and analysis within a Security Information and Event Management (SIEM) environment.
- Adversary TTP Simulation & Detection: Proficient in generating, simulating, and analyzing adversary Tactics, Techniques, and Procedures (TTPs) using Atomic Red Team (ART).
- MITRE ATT&CK Framework Expertise: In-depth understanding of MITRE ATT&CK tactics, techniques, and procedures, with the ability to map simulated attacks to real-world adversary behaviors.
- Endpoint Monitoring & Detection: Hands-on experience using Sysmon for detailed endpoint monitoring and Splunk for log analysis to identify malicious activities.
- Effective Query Crafting: Developed proficiency in crafting and refining queries to detect specific attack patterns and malicious behavior within logs.
- Attack Detection & Defense Strategies: Enhanced knowledge of attack detection methods and defensive countermeasures in a real-world cybersecurity context.

### Tools Used


- Splunk: For log ingestion, querying, and analysis in a SIEM environment.
- Sysmon: Monitored and collected detailed endpoint activity logs to track system behavior and identify potential threats.
- Atomic Red Team (ART): Simulated adversary behaviors and tactics to generate telemetry data for testing detection capabilities.
- PowerShell: Executed and managed simulation scripts to carry out attack simulations.
- MITRE ATT&CK Framework: Mapped simulated techniques to real-world attack patterns to assess detection efficacy.
- Virtual Machine (VM): Created a secure environment for attack simulation and log analysis without affecting the host system.

## Steps

### 1.Environment Setup:

- Installed Splunk and Sysmon on a virtual machine (VM) to collect and analyze system activity logs.
- Configured Sysmon with custom rules for monitoring key system activities, such as process creation, network connections, and file creation.
- Verified successful log collection from Sysmon, ensuring accurate data ingestion into Splunk.

### 2.Atomic Red Team (ART) Configuration:

- Set up Atomic Red Team by bypassing PowerShell's execution policy to run the framework scripts.
- Installed ART using PowerShell, following setup instructions from the ART wiki.
- Ensured the ART folder was excluded from Windows Defender scanning to avoid detection by security software.
- Reinstalled ART with the --force option to ensure proper installation.

### 3.Adversary Simulation (Persistence Tactic):

- Selected a relevant MITRE ATT&CK technique (e.g., Persistence - BITS Jobs [T1197]) to simulate adversary behavior.
- Utilized PowerShell to execute the BITS Jobs attack simulation (T1197), generating telemetry data and logs for Splunk ingestion.

### 4.Log Analysis in Splunk:

- Queried Splunk logs for the BITS Jobs technique (T1197) and refined the query to extract relevant data (e.g., time, parent image, command line).
- Organized the results in a clear, readable table format for effective analysis and identification of potential malicious activity.

### 5.MITRE ATT&CK Validation:

- Cross-referenced Splunk findings with the MITRE ATT&CK framework to validate detection of the simulated attack.
- Focused on key indicators (e.g., “transfer”) to identify behaviors matching known adversary tactics.
- Categorized findings as legitimate or suspicious based on ATT&CK’s detection recommendations.

### 6.System Cleanup:


### Bypass execution policy


![bypassing execution policy](https://github.com/user-attachments/assets/9724c234-1818-4552-b96d-8cc266615c40)


### Installing execution framework along with the atomic folder


![installing execution framework along with the atomic folder](https://github.com/user-attachments/assets/c0305898-5ec9-490c-95dc-496e9c1aa1c0)


### atomic folder


![atomic folder](https://github.com/user-attachments/assets/c40127f3-7737-4100-8bfb-fa5dfb1d2644)


### excluding folder under exclusions


![excluding the ART folder in exclusions](https://github.com/user-attachments/assets/1f655c58-2280-42bb-a7b6-a610136c0024)


### reinstalling folder


![reinstalling folder](https://github.com/user-attachments/assets/4b677201-b96d-493d-aeeb-0ce0446b0c8a)


### looking for everything 


![looking for everything](https://github.com/user-attachments/assets/250ee86d-9a17-41b5-9ac7-c92113d13cdf)


### using MITRE attack for event IDs


![using MITRE attack for event ID](https://github.com/user-attachments/assets/c12a08b3-379a-4b3d-9236-9fe40a6cb1d7)


### testing for techniques related to the ID


![Testing for techniques in bits jobs](https://github.com/user-attachments/assets/91672458-6117-438b-9d0b-ae645651a8f3)


### running every tests


![running everything](https://github.com/user-attachments/assets/a60f38fa-60cd-424d-806e-19335aee0518)



![Testing for techniques in bits jobs](https://github.com/user-attachments/assets/fe7aa15c-8416-42be-b833-db94e990d97a)
![running everything](https://github.com/user-attachments/assets/2dba84a0-91d5-4ff7-8064-d45dbeaf554e)
