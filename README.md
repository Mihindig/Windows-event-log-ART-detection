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

- After completing the analysis, removed all generated telemetry and logs to restore the VM environment to its original state, ensuring it was clean and secure.
