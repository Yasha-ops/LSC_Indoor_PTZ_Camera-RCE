Certainly! Here’s the revised README with placeholders for where to insert the images:

---

# LSC PTZ Dualband Camera Vulnerability Exploitation

This repository demonstrates a critical security vulnerability discovered in the **LSC PTZ Dualband Camera**. The flaw, located in the `tuya_ipc_direct_connect` function of the `anyka_ipc` process, allows remote arbitrary code execution when a specially crafted QR code is presented to the camera during Wi-Fi configuration.

## Overview

The vulnerability occurs due to improper input validation in the camera's QR code scanning function. Malicious payloads can be injected into the Wi-Fi password field of the QR code, enabling an attacker to execute arbitrary system commands on the camera device.

![Example QR code process](/path/to/your/image1.png)  
*Image 1: Example of the QR code scanning process and where the vulnerability is triggered.*

## Affected Devices

- **Device**: LSC PTZ Dualband Camera
- **Firmware**: Devices using firmware with **SDK version 4.9.18** or earlier
- **Vulnerability Type**: **Command Injection** (CWE-77)
- **Severity**: High – remote arbitrary code execution

## Attack Vector

Exploitation of this vulnerability occurs when a malicious QR code is presented to the camera. The camera processes the QR code’s password field without properly sanitizing the input, allowing arbitrary system commands to be executed. An attacker can craft a payload like the following example:

```json
{
    "s": "WIFI_NAME",
    "p": "WIFI_PASSWORD; touch /tmp/POUXY",
    "t": "2387263876"
}
```

![Malicious QR Code Example](/path/to/your/image2.png)  
*Image 2: Example of a malicious QR code generated for exploitation.*

### Steps to Exploit

1. **Generate the Malicious QR Code**:  
   - Create a QR code with a custom payload, such as adding arbitrary system commands in the password field.

2. **Present the QR Code**:  
   - Hold the generated QR code in the camera's scan range during its Wi-Fi configuration process.

3. **Trigger Command Execution**:  
   - Upon scanning the malicious QR code, the camera processes the payload, and the command (e.g., `touch /tmp/POUXY`) is executed on the system.

![Example of Command Execution](/path/to/your/image3.png)  
*Image 3: Example of the outcome after command execution, such as creating a file on the system.*

## Mitigation

To mitigate the vulnerability, it’s recommended to:
- **Disable QR code Wi-Fi configuration** until an official patch is available.
- **Apply firmware updates** as they become available from the manufacturer to improve input sanitization.

## Acknowledgements

This vulnerability was discovered by Yassine Damiri. The research helps improve awareness around the security risks posed by weak input validation and serves as a basis for further security improvements.

## Disclaimer

This repository is intended for educational and ethical hacking purposes only. Unauthorized access to devices or systems is illegal. Always obtain proper authorization before conducting security testing.

