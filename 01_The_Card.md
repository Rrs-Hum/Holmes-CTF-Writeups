# 01 – The Card

**TL;DR:** Suspicious script activity detected → IOC pivot → confirmed malicious card stealer → host contained.

---

## Scenario
(What the challenge description gave you.)

## Hypothesis & Approach
- Initial assumptions
- SOC triage mindset

## Detections & Queries
```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wscript.exe"
| where ProcessCommandLine has_any ("Base64","JScript")
