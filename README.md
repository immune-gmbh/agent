immune Guard Agent
==================

This is the agent component of the immune Guard product.
It used together with the immune Guard Platform.

How to build
------------
The service is written on Go and needs version 1.20 or later to be built.

You need to have git lfs installed for windows builds. Install with "git lfs install"
and run "git lfs pull" once and in future the next regular fetch and pull will do it.

Building the binary can be done with GNU Make:

```bash
make
```

Integration
-----------

##### Microsoft Windows

OS                                    | Version                 | Architectures   
--------------------------------------|-------------------------|-----------------
[Windows 10][Windows-client]          | Vista, 7, 8, 10, 11     | x64        
[Windows Server][Windows-Server]      | 2012+                   | x64        

[Windows-client]: https://www.microsoft.com/windows/
[Windows-Server]: https://learn.microsoft.com/windows-server/

##### Linux Distributions

OS                                    | Version               | Architectures     
--------------------------------------|-----------------------|-------------------
Generic                               | 3.x+                  | x64
[CentOS][CentOS]                      | 7+                    | x64               
[Debian][Debian]                      | 10+                   | x64 
[Fedora][Fedora]                      | 33+                   | x64               
[Red Hat Enterprise Linux][RHEL]      | 7+                    | x64       
[Ubuntu][Ubuntu]                      | 18.04+                | x64

[CentOS]: https://www.centos.org/
[Debian]: https://www.debian.org/
[Fedora]: https://getfedora.org/
[RHEL]: https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux
[Ubuntu]: https://ubuntu.com/

immune Guard Platform
=====================
Immune Guard is a comprehensive cyber security solution that aims to protect devices and systems from various threats. It uses advanced technologies such as TPM (Trusted Platform Module) and attestation to ensure the security and integrity of devices and systems.

Features
--------
Immune Guard provides a range of features to address common cyber security challenges:

* **Threat detection:** Immune Guard uses advanced algorithms and heuristics to detect and prevent malware and other threats from entering the system.

* **Vulnerability management:** Immune Guard helps identify and fix vulnerabilities in the system, improving its overall security posture.

* **Asset tracking:** Immune Guard tracks and monitors assets in the system, helping to prevent unauthorized access and tampering.

* **Incident response:** In the event of a security incident, Immune Guard provides tools and processes to respond quickly and effectively.

* **Compliance reporting:** Immune Guard helps organizations meet compliance requirements by providing reports and documentation on security measures and controls.

Technical Overview
------------------
Immune Guard is implemented using a combination of hardware and software technologies.

At the hardware level, Immune Guard uses TPM to secure devices and systems. TPM is a hardware component that provides secure storage and cryptographic capabilities, helping to ensure the integrity and confidentiality of data and processes.

At the software level, Immune Guard uses attestation to verify the integrity of devices and systems. Attestation involves comparing the current state of a device or system with a trusted reference state, helping to ensure that the system has not been compromised.

Immune Guard also uses a range of other technologies and algorithms to provide additional security features, such as threat detection and vulnerability management.

Deployment
----------
Immune Guard can be deployed on a variety of devices and systems, including servers, workstations, and mobile devices. It can be installed as a standalone solution or integrated with other security tools and systems.

Support and Maintenance
-----------------------
Immune Guard includes ongoing support and maintenance to ensure that the system stays up-to-date and effective. This includes updates to fix vulnerabilities and improve performance, as well as access to technical support for any issues that may arise.

Conclusion
----------
Immune Guard is a powerful and comprehensive cyber security solution that helps to protect devices and systems from threats. Its combination of hardware and software technologies, along with ongoing support and maintenance, make it a reliable choice for organizations looking to improve their security posture.

__Further information can be found at the [immune homepage](https://immune.gmbh/).__
