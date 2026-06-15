# Evidence Dataset Documentation

## Primary Dataset: Rocba Memory Image

| Field | Value |
|-------|-------|
| **Case Name** | The Fred Rocba Case |
| **Source** | SANS HACKATHON-2026 Standard Forensic Case (Egnyte) |
| **File** | Rocba-Memory.raw |
| **SHA256** | eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563 |
| **Size** | 17.74 GB (19,050,528,768 bytes) |
| **Type** | Raw memory dump (.raw) |
| **OS** | Windows 10 (build 19041, 64-bit) |
| **System** | Microsoft Surface (4 processors) |
| **Capture Time** | 2020-11-16 02:32:38 UTC |
| **User** | fredr (Fred Rocba) |

## Case Background

Fred Rocba is a new engineering hire at Stark Research Labs (SRL), a company specializing in metals, alloys, and biotech research for defense applications. Fred was shipped a Microsoft Surface for remote work. While Fred was on a pre-planned Disney vacation (Nov 10-13, 2020), someone broke into his home and specifically targeted his SRL Surface laptop.

## Key Investigation Questions

1. What key projects did Fred Rocba have access to?
2. What was stolen?
3. Where was it transferred to?
4. How was it stolen?
5. When did the activity occur?

## What the Agent Found

The agent identified 2,186 processes in the memory image. Key findings include:

- **MRC.exe** (PID 29440): Running from `D:\Tools\MRC.exe` — a remote access tool running from a non-standard location on a secondary drive. This is the most suspicious finding.
- **Three cloud sync services**: OneDrive (personal + business), Google Drive, and iCloud — all potential data exfiltration paths.
- **iCloud Photos / Apple Photo Stream**: Actively syncing Fred's Disney vacation photos — confirms the timeline.
- **Microsoft Teams**: Abnormally large number of Teams.exe processes (~1000+), most with no command line arguments.
- **Multiple browser instances**: Chrome and Microsoft Edge with multiple parent processes.

## Data Source and Access

The Rocba dataset was provided by Rob Lee (SANS) through the hackathon's Egnyte shared folder at:
`HACKATHON-2026/Standard Forensic Case/`

Additional case context was provided in `ROCBA-BACKGROUND.pptx` included in the same folder.

## Reproducibility

To reproduce this analysis:
1. Download `Rocba-Memory.zip` from the hackathon Egnyte folder
2. Extract: `unzip Rocba-Memory.zip && cd Rocba-Memory && 7z x Rocba-Memory.7z`
3. Verify hash: `sha256sum Rocba-Memory.raw` should match `eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563`
4. Run agent: `python3 src/agent.py /path/to/Rocba-Memory.raw`
