# Windows Persistence DFIR Lab
Digital Forensics & SOC Incident Response with Wazuh

End-to-end lab guide formatted in a NetLab-style walkthrough with objectives, required software, step-by-step tasks, screenshot evidence, verification, and cleanup.

I created this lab for my final project for my Intermediate Digital Forensics course. The goal was to create a lab for students to use to practice and learn SOC, Digital Forensics, and Incident Response skills. I utilized my skills and knowledge as a SOC Analyst to design and build out this intermediate-level lab. 

The lab simulates several common Windows persistence techniques in a controlled Windows 11 environment and then investigates those artifacts from both a host-based forensic and SOC/SIEM perspective.

A benign PowerShell script creates persistence artifacts on a Windows endpoint. The artifacts are then verified locally, detected through Wazuh SIEM, correlated across multiple evidence sources, organized into a forensic timeline, and removed during a final cleanup and validation phase.

Important: This project was designed exclusively for an authorized educational lab environment. The persistence mechanisms use benign payloads and do not deploy malware.

# Project Objectives

The primary goals of the lab were to:

Create multiple Windows persistence artifacts in a controlled environment
Execute and analyze a PowerShell-based persistence simulation
Identify persistence artifacts directly on a Windows 11 endpoint
Investigate Windows process and endpoint telemetry in Wazuh
Correlate host artifacts with SIEM evidence
Reconstruct a short forensic timeline
Explain the defensive significance of each persistence mechanism
Remove all created artifacts and verify that the endpoint returned to a clean state

# Lab Scenario

The scenario places the investigator in the role of a SOC analyst and digital forensics student investigating suspicious persistence behavior on a Windows 11 endpoint.

The activity is intentionally generated as part of a controlled training exercise.

The investigation follows a DFIR workflow:

Persistence Simulation  
↓  
Host Artifact Creation  
↓  
Local Verification  
↓  
Wazuh Detection  
↓  
Evidence Correlation  
↓  
Forensic Timeline  
↓  
Cleanup & Verification

The goal is not simply to identify an individual command or event, but to correlate multiple pieces of evidence to determine:

What happened
When it happened
Which artifacts were created
Which processes were involved
How the activity appeared in the SIEM
Why the activity would matter to a SOC analyst

# Lab Environment   
**Target Endpoint**  
Operating System: Windows 11  
Role: Target endpoint where persistence artifacts are created  
Required Privileges: Local administrator

**Security Monitoring**  
Wazuh Manager  
Wazuh Dashboard  
Wazuh Windows Agent

Wazuh is used to collect and analyze Windows endpoint telemetry generated during the simulation.

**Scripting**
Windows PowerShell 5.1+ or PowerShell 7+

PowerShell is used to create, execute, verify, and remove the simulated persistence artifacts.

**Optional Tool**  
Velociraptor

Velociraptor may be used for additional endpoint verification or forensic collection if available in the lab environment.

# Persistence Techniques Simulated

The PowerShell script creates four distinct Windows persistence artifacts.

| Persistence Mechanism | Lab Artifact | Purpose |
|---|---|---|
| Scheduled Task | `WindowsTelemetryUpdater` | Executes a PowerShell command at logon |
| Registry Run Key | `OneDriveSecurityUpdate` | Executes a command through the current user's Run key |
| Startup Folder | `SecurityHealthCheck.lnk` | Executes PowerShell through a Startup-folder shortcut |
| Local Administrator Account | `svc_backup` | Simulates persistence through creation of a privileged local account |

Each artifact represents a technique that could be used by an attacker to maintain continued access or execution on a compromised Windows system.

For safety, the simulated payload only writes timestamps to a local marker file.

# Phase 1 — Persistence Simulation

The main PowerShell script is:

C:\Temp\phase3-windows-persistence.ps1

Before execution, the start time is recorded so that activity on the Windows endpoint can later be correlated with events observed in Wazuh.

Example execution:

Get-Date

Set-ExecutionPolicy Bypass -Scope Process -Force

powershell.exe -ExecutionPolicy Bypass `
    -File C:\Temp\phase3-windows-persistence.ps1

Get-Date

The script records its activity in:

C:\Temp\phase3-windows-persistence.log

# Phase 2 — Scheduled Task Persistence

The first persistence mechanism creates a scheduled task named:

WindowsTelemetryUpdater

The task is configured to execute at user logon with elevated privileges.

The payload launches PowerShell and writes a timestamp to:

C:\ProgramData\phase3_persistence_marker.txt

# Verification
schtasks /Query /TN "WindowsTelemetryUpdater" /V /FO LIST

This confirms:

The scheduled task exists  
The configured trigger  
The command associated with the task  
The task's execution settings  

The task can also be manually triggered:

schtasks /Run /TN "WindowsTelemetryUpdater"

The marker file can then be inspected:

type C:\ProgramData\phase3_persistence_marker.txt

# Phase 3 — Registry Run Key Persistence

The script creates the following value in the current user's Windows Run key:

OneDriveSecurityUpdate

Registry location:

HKCU:\Software\Microsoft\Windows\CurrentVersion\Run

Run keys are important forensic artifacts because programs configured in this location can automatically execute when a user logs into Windows.

**Verification**  
Get-ItemProperty `  
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |  
Select-Object OneDriveSecurityUpdate

This confirms that the persistence value exists in the user's registry hive.

# Phase 4 — Startup Folder Persistence

The script creates a Windows shortcut named:

SecurityHealthCheck.lnk

The shortcut is placed inside the user's Startup folder:

%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup

The shortcut launches PowerShell and writes another benign timestamp entry to the persistence marker file.

**Verification**  
Get-ChildItem `  
"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

The presence of:

SecurityHealthCheck.lnk

confirms the Startup-folder persistence artifact.

# Phase 5 — Local Administrator Account Persistence

The final persistence mechanism creates a local account:

svc_backup

The account is then added to the local:

Administrators

group.

Creating a new privileged account can be a particularly significant persistence indicator because the account may provide continued administrative access even after another compromised credential has been reset.

**Verify the Account**  
Get-LocalUser svc_backup

**Verify Administrator Membership**  
Get-LocalGroupMember Administrators

The account should appear as a member of the local Administrators group.

# Host-Based Evidence

After execution, the persistence artifacts are verified directly on the Windows target.

The investigation checks for:

Scheduled task creation  
Registry modification  
Startup-folder shortcut  
Local account creation  
Administrator-group membership  
PowerShell execution log  
Marker-file creation

The PowerShell execution log provides an additional local evidence source:

type C:\Temp\phase3-windows-persistence.log

This log records the major actions performed by the simulation script and can be compared against Wazuh timestamps.

# Wazuh Detection

After the persistence artifacts are created and verified locally, the investigation moves to the Wazuh Dashboard.

Events are searched around the recorded script execution period.

Several identifiers can be used to narrow the investigation:

Agent name  
Hostname  
powershell.exe  
schtasks.exe  
WindowsTelemetryUpdater  
OneDriveSecurityUpdate  
phase3_persistence_marker.txt  
svc_backup

# Detect PowerShell Execution

Example Wazuh query:

agent.name:"WIN11-Target" AND
data.win.eventdata.processName:*powershell*

Expected evidence includes PowerShell events occurring near the recorded execution time.

# Detect Scheduled Task Activity
agent.name:"WIN11-Target" AND
(
data.win.eventdata.commandLine:*schtasks*
OR
data.win.eventdata.commandLine:*WindowsTelemetryUpdater*
)

Potential evidence includes:

schtasks.exe execution  
Scheduled-task creation activity  
WindowsTelemetryUpdater  
Task-registration information  
Scheduled-task XML content  

# Detect Registry Artifact Activity
agent.name:"WIN11-Target" AND
data.win.eventdata.commandLine:*OneDriveSecurityUpdate*

This query helps identify events associated with creation of the Run-key persistence artifact.

# Detect Marker File Activity
agent.name:"WIN11-Target" AND
data.win.eventdata.commandLine:*phase3_persistence_marker.txt*

This provides evidence that the PowerShell payload executed and interacted with the marker file.

# Detect the Local Account Artifact
agent.name:"WIN11-Target" AND
(
svc_backup OR "Backup Service Account"
)

This can help locate telemetry related to creation or use of the simulated service account.

# Detection Chain

The Wazuh investigation demonstrated the following sequence:

PowerShell script executed  
        ↓  
schtasks.exe executed  
        ↓  
WindowsTelemetryUpdater registered  
        ↓  
PowerShell payload executed  
        ↓  
Marker file written to C:\ProgramData

This is significant because no single event provides the complete picture.

The activity becomes much clearer when:  

Process execution  
Scheduled-task activity  
PowerShell telemetry  
Host artifacts  
File activity  
Script logs

are correlated together.

# Forensic Timeline

A short timeline was constructed using Wazuh telemetry and host-based evidence.

| Approx. Time | Evidence Source | Observed Activity | Forensic Meaning |
|---|---|---|---|
| 15:49:43 | Wazuh | `powershell.exe` ran `phase3-windows-persistence.ps1` | Persistence simulation script executed |
| 15:49:43 | Wazuh | `schtasks.exe` created `WindowsTelemetryUpdater` | Scheduled-task persistence was attempted or created |
| 15:46:27 | Wazuh | Scheduled-task XML content observed | Task registration information was captured |
| 15:46:47 | Wazuh | PowerShell `Add-Content` activity involving `phase3_persistence_marker.txt` | Benign persistence payload executed |
| Recorded during investigation | Host log | Persistence log documented completed actions | Local host evidence supported the SIEM findings |

The primary objective of the timeline was to demonstrate that host artifacts and SIEM telemetry describe the same underlying activity.

# Evidence Correlation

One of the central concepts demonstrated by this lab is that a single command or Windows event rarely tells the entire story.

For example, the investigation can correlate:

PowerShell execution    
+  
Scheduled task creation   
+  
Task registration  
+  
PowerShell payload execution   
+  
Marker file creation  
+  
Local persistence artifacts   

= Correlated persistence activity

This approach is important in DFIR because analysts must frequently combine multiple data sources to determine whether activity is benign, suspicious, or malicious.

# Cleanup

After completing the investigation, all simulated persistence artifacts are removed.

**Remove Scheduled Task**  
schtasks /Delete /TN "WindowsTelemetryUpdater" /F

**Remove Registry Run Key**  
Remove-ItemProperty `  
-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `  
-Name "OneDriveSecurityUpdate" `  
-ErrorAction SilentlyContinue

**Remove Startup Shortcut**  
Remove-Item `  
"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\SecurityHealthCheck.lnk" `  
-Force `  
-ErrorAction SilentlyContinue

**Remove Administrator Membership**  
Remove-LocalGroupMember `  
-Group "Administrators" `  
-Member "svc_backup" `  
-ErrorAction SilentlyContinue

**Remove Local User**  
Remove-LocalUser `  
-Name "svc_backup" `  
-ErrorAction SilentlyContinue

**Remove Marker File**  
Remove-Item `  
"C:\ProgramData\phase3_persistence_marker.txt" `  
-Force `  
-ErrorAction SilentlyContinue

**Remove Lab Files**  

Remove-Item `  
"C:\Temp\phase3-windows-persistence.ps1" `  
-Force `  
-ErrorAction SilentlyContinue

Remove-Item `  
"C:\Temp\phase3-windows-persistence.log" `  
-Force `
-ErrorAction SilentlyContinue

# Cleanup Verification

After cleanup, the endpoint is checked again to verify that the artifacts no longer exist.

schtasks /Query /TN "WindowsTelemetryUpdater"  

Get-ItemProperty `  
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |  
Select-Object OneDriveSecurityUpdate

Get-ChildItem `  
"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

Get-LocalUser svc_backup

Get-LocalGroupMember Administrators |  
findstr /i "svc_backup"

Successful cleanup should result in:

No WindowsTelemetryUpdater scheduled task  
No OneDriveSecurityUpdate Run-key value  
No SecurityHealthCheck.lnk  
No svc_backup local account  
No persistence marker file  

# Skills Demonstrated

This project demonstrates hands-on experience in several areas relevant to SOC and DFIR roles.

**Digital Forensics**

Windows artifact identification  
Persistence artifact analysis  
Registry artifact analysis  
Scheduled-task investigation  
Startup-folder analysis  
Local-account investigation  
Evidence correlation  
Timeline reconstruction  

**Security Operations**

Wazuh SIEM investigation  
Endpoint telemetry analysis  
Process-execution investigation  
Search-query development  
Event correlation  
Detection validation  
SOC-oriented incident analysis  

**Windows Security**

PowerShell  
Windows scheduled tasks  
Windows Registry  
Local users and groups  
Administrator privileges  
Windows Startup mechanisms  

**Incident Response**

Detection  
Investigation  
Evidence collection  
Timeline development  
Persistence identification  
Remediation  
Cleanup validation  

# Key Takeaways

This lab demonstrated that effective digital-forensics analysis requires more than finding one suspicious process or event.

The most useful conclusions came from correlating:

Local Windows artifacts  
PowerShell execution  
Script-generated logs  
Wazuh endpoint telemetry  
Scheduled-task activity  
File activity  
Event timestamps

By combining these sources, the investigation was able to reconstruct the simulated persistence activity and verify the relationship between what occurred on the endpoint and what was visible to the SOC.

The lab also reinforced the importance of validating remediation rather than assuming that persistence has been removed.

# Project Documentation

The complete lab report is available in:

documentation/SOC_DFIR_Lab.pdf

The report contains:

Lab objectives  
Environment requirements  
Persistence simulation script  
Host verification procedures  
Screenshot evidence  
Wazuh search methodology  
Forensic timeline  
Analysis questions  
Cleanup procedures  
Final verification  

# Security & Ethical Use

**This project was created for authorized cybersecurity education and defensive security training.**

The persistence techniques documented here should only be executed in:

Authorized classroom environments  
Isolated virtual machines  
Cybersecurity training labs  
Systems where explicit permission has been granted  

The simulated payload is intentionally benign and writes timestamp marker files instead of deploying malicious software.

Do not execute persistence techniques against production systems or systems you do not own or have explicit authorization to test.

# Author

**Brian Stauffer**

Cybersecurity | SOC Analysis | Digital Forensics | Incident Response | Threat Detection

# Project Context

Course: Intermediate Digital Forensics  
Focus: Digital Forensics & SOC Incident Response  
SIEM: Wazuh  
Target: Windows 11  
Project Type: Intermediate Digital Forensics Final Project
