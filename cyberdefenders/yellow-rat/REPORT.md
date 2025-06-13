# [Yellow RAT](https://cyberdefenders.org/blueteam-ctf-challenges/yellow-rat/)

> [!note]
> This is a work in progress writeup

## Scenario

During a regular IT security check at GlobalTech Industries, abnormal network traffic was detected from multiple workstations. Upon initial investigation, it was discovered that certain employees' search queries were being redirected to unfamiliar websites. This discovery raised concerns and prompted a more thorough investigation. Your task is to investigate this incident and gather as much information as possible.

## Questions

1. Understanding the adversary helps defend against attacks. What is the name of the malware family that causes abnormal network traffic?
1. As part of our incident response, knowing common filenames the malware uses can help scan other workstations for potential infection. What is the common filename associated with the malware discovered on our workstations?
1. Determining the compilation timestamp of malware can reveal insights into its development and deployment timeline. What is the compilation timestamp of the malware that infected our network?
1. Understanding when the broader cybersecurity community first identified the malware could help determine how long the malware might have been in the environment before detection. When was the malware first submitted to VirusTotal?
1. To completely eradicate the threat from Industries' systems, we need to identify all components dropped by the malware. What is the name of the .dat file that the malware dropped in the AppData folder?
1. It is crucial to identify the C2 servers with which the malware communicates to block its communication and prevent further data exfiltration. What is the C2 server that the malware is communicating with?

## Analysis

Hello,

We are provided with a file at the start - `hash.txt`, the contents are:
```txt
malware hash: 30E527E45F50D2BA82865C5679A6FA998EE0A1755361AB01673950810D071C85

Use this hash on online threat intel platforms (e.g., VirusTotal, Hybrid Analysis) to complete the lab analysis.
```

We can start with a simple Google search. Search results that came up that I'm interested in:

* Malware bazaar site where we can get the file in question: https://bazaar.abuse.ch/sample/30e527e45f50d2ba82865c5679a6fa998ee0a1755361ab01673950810d071c85/
* A sandbox raport of the file: https://www.hybrid-analysis.com/sample/30e527e45f50d2ba82865c5679a6fa998ee0a1755361ab01673950810d071c85/5f87b2920788cb226f59d611
* This hash is part of a larger scale of malicious activity according to AlienVault OTX: https://otx.alienvault.com/pulse/5fcab7a1accb28c015a5717d

These links are sufficient to do a deep dive on the file, since Malware bazaar also aggregates results from popular reputation services and actually can provide a sample for you to analyze yourself, and Hybrid analysis is a great interactive sandbox that provides detailed behaviors. AlienVault OTX is also a great information source, that will give you a broader scope of the campaign the file was used in.

### Malware bazaar

The file has the name "111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll" and is a dynamic-link library. I've downloaded the sample as well, since a quick glance on other search results do not provide a lot of information.

I've tried uploading the file to Filescan.io, another tool for static analysis but that resulted in an error.

### Hybrid analysis

The report provides some insight on how this file behaves. I've selected a few that I would deem as suspicious:

* Detected a large number of ARP broadcast requests (network device lookup, such as APIPA subnets, and specific 192.168.xxx.xxx addresses) 
    > Attempt to find devices in networks: "169.254.65.32/32, 169.254.85.9/32, 169.254.92.75/32, 169.254.123.187/32, 169.254.153.124/32, 169.254.227.146/32, 169.254.234.186/32, 169.254.248.31/32, 192.168.240.1/32, 192.168.240.2/32, 192.168.240.15/32, 192.168.240.128/32, 192.168.240.141/32, 192.168.240.142/32, 192.168.240.200/32, 192.168.241.24/32, 192.168.241.57/32, 192.168.241.85/32, 192.168.241.124/32, 192.168.241.172/32, 192.168.241.230/32, 192.168.241.244/32, 192.168.242.21/32, 192.168.242.87/32, 192.168.242.88/32, 192.168.242.101/32, 192.168.242.117/32, 192.168.242.125/32, 192.168.242.166/32, 192.168.242.218/32, 192.168.242.240/32, 192.168.243.74/32, 192.168.243.94/32, 192.168.243.151/32, 192.168.243.169/32, 192.168.243.183/32, 192.168.243.199/32, 192.168.243.211/32, 192.168.243.240/32"   
* Found a reference to a WMI query string known to be used for VM detection 
    > "Win32_ComputerSystem.Name='{0}'" (Indicator: "win32_computersystem"; File: "30e527e45f50d2ba82865c5679a6fa998ee0a1755361ab01673950810d071c85.bin") 
* Sends traffic on typical HTTP outbound port, but without HTTP header 
    > TCP traffic to 52.158.209.219 on port 443 is sent without HTTP header 
* Found potential URL in binary/memory 
    > hxxps[://]gogohid[.]com"
* Installs hooks/patches the running process
    > "regsvr32.exe" wrote bytes "71117d007a3b7c00ab8b02007f950200fc8c0200729602006cc805001ecd79007d267900" to virtual address "0x776B07E4" (part of module "USER32.DLL") 
* Matched Compiler/Packer signature 
    > "30e527e45f50d2ba82865c5679a6fa998ee0a1755361ab01673950810d071c85.bin" was detected as "Microsoft visual C# v7.0 / Basic .NET" 

### AlienVault OTX

I really like AlienVault pulses, in this report we have a description, the malware's family name and references to some reports from Red Canary and Morphisec.

So we according to AlienVault we are dealing with "Yellow Cockatoo RAT" (also named as "Jupyter Infostealer ") - a .NET remote access trojan (RAT) that runs in memory and drops other payloads.

<!-- TBD -->

> [!note]
> This is a work in progress writeup

## Answers

1. Understanding the adversary helps defend against attacks. What is the name of the malware family that causes abnormal network traffic?
    > Yellow Cockatoo RAT
1. As part of our incident response, knowing common filenames the malware uses can help scan other workstations for potential infection. What is the common filename associated with the malware discovered on our workstations?
    > answer
1. Determining the compilation timestamp of malware can reveal insights into its development and deployment timeline. What is the compilation timestamp of the malware that infected our network?
    > answer
1. Understanding when the broader cybersecurity community first identified the malware could help determine how long the malware might have been in the environment before detection. When was the malware first submitted to VirusTotal?
    > answer
1. To completely eradicate the threat from Industries' systems, we need to identify all components dropped by the malware. What is the name of the .dat file that the malware dropped in the AppData folder?
    > answer
1. It is crucial to identify the C2 servers with which the malware communicates to block its communication and prevent further data exfiltration. What is the C2 server that the malware is communicating with?
    > answer

## Resources used

