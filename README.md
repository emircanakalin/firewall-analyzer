# Firewall Analyzer

A PowerShell script to analyze "Allow" rules in the Windows Defender Firewall and identify potentially suspicious applications.

## Description

This script scans all enabled "Allow" rules in the Windows Defender Firewall. For each rule associated with an application, it retrieves the application's file path, digital signature status, and publisher information. 

The primary goal is to flag applications that might pose a security risk, based on the following criteria:
- **Unsigned Applications:** Executables that lack a digital signature.
- **Unusual Locations:** Applications running from temporary or user-specific folders like `AppData` or `Temp`.
- **Non-Microsoft Publishers:** To help distinguish between operating system components and third-party software.

## Features

- **Automatic Administrator Elevation:** The script will automatically try to restart itself with administrator privileges if it's not run as an admin.
- **Clear Table-Based Output:** Results are displayed in a clean, easy-to-read table.
- **Prioritized Results:** Potentially suspicious applications (those with notes) are listed at the top for immediate attention.

## How to Use

1.  Open a PowerShell terminal.
2.  Navigate to the directory where `Firewall-Analyzer.ps1` is located.
3.  Run the script:
    ```powershell
    .\Firewall-Analyzer.ps1
    ```
4.  If not already running as an administrator, the script will prompt for elevation.
5.  Review the output table for a list of applications associated with "Allow" rules.

## Output Columns

- **ApplicationName:** The file description of the application, or its filename if the description is not available.
- **IsSigned:** `True` if the application has a valid digital signature, `False` otherwise.
- **Signer:** The name of the certificate authority that signed the application. Shows "Unsigned" if not signed.
- **Path:** The full file path to the application's executable.
- **Notes:** Highlights potential issues, such as being unsigned or located in a temporary folder.
- **RuleName:** The display name of the firewall rule that allows the application.

## Disclaimer

This script is not an antivirus or anti-malware tool. It is intended as a diagnostic helper to review your firewall configuration and identify potential anomalies that may warrant further investigation.
