# Akira Escape Tool

Offline incident-response triage for Windows hosts hit by **Akira** ransomware.

One PowerShell script, no dependencies, no network calls. Run it on a compromised (or
suspected-compromised) host with local admin rights and it answers four questions:

| Question | What the tool does |
|---|---|
| Is anything still holding on? | Sweeps ~15 persistence mechanisms and grades each entry |
| Which Akira is this? | Fingerprints the variant from notes, extensions and host behaviour |
| What do we keep? | Collects artifacts with a SHA-256 manifest |
| Can the client go back online? | Scored return-to-service checklist with a verdict |

It produces a client-ready HTML report, a Markdown report, a machine-readable
`findings.json`, and an `AI-HANDOFF.md` you can paste straight into Claude to have the
full written report produced for you.

## Read-only by design

The tool **reads**. It never deletes files, kills processes, removes registry keys,
quarantines anything or changes configuration. That is deliberate: remediation decisions
belong to the responder, and a triage tool that changes the host destroys the evidence it
was run to collect.

If the host may become evidence in litigation, image the disk before running any live
triage — including this.

## Requirements

* Windows PowerShell 5.1 (built in on Windows 10/11 and Server 2016+)
* Run **as Administrator** — without it, registry, service, event log and collection
  checks come back incomplete and the report says so
* No internet access needed

If the script is blocked by execution policy, run it as:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\AkiraEscape.ps1
```

## Usage

Interactive (also what happens if you just run the script with no arguments):

```powershell
.\AkiraEscape.ps1
```

```
   1. Full triage            (standard scope, event logs, full report)
   2. Quick look             (fast scan, no event log export)
   3. Deep collection        (whole disk, hives, prefetch, Amcache)
   4. Persistence check only (is anything still holding on?)
   5. Encryption and variant (what hit this host, and which build?)
   6. Readiness check only   (can this host go back online?)
   7. Set case ID and operator
```

Unattended, with evidence written to removable media:

```powershell
.\AkiraEscape.ps1 -CaseId IR-2026-014 -Operator "J. Doe" -OutputRoot E:\Evidence -Scope Deep
```

Fast first look, nothing copied:

```powershell
.\AkiraEscape.ps1 -Scope Quick -SkipCollection
```

Point the scan at file shares instead of guessing:

```powershell
.\AkiraEscape.ps1 -ScanPath 'D:\Shares','E:\' -ScanTimeoutMinutes 45
```

### Parameters

| Parameter | Default | Notes |
|---|---|---|
| `-CaseId` | timestamp | Recorded in every report |
| `-Operator` | current user | Chain of custody |
| `-OutputRoot` | script folder | Point at removable media to keep evidence off the host |
| `-Scope` | `Standard` | `Quick` / `Standard` / `Deep` |
| `-ScanPath` | scope-derived | Explicit roots to scan for encrypted files and notes |
| `-ScanTimeoutMinutes` | `20` | Wall-clock budget; the scan stops cleanly and the report records that results are partial |
| `-DaysBack` | `45` | Event log review window |
| `-IncidentStart` | estimated | Known start of the incident; otherwise estimated as 14 days before the earliest encrypted file |
| `-MaxEncryptedSamples` / `-MaxNoteSamples` | `25` | Sampling caps |
| `-CollectEventLogs` / `-CollectRegistryHives` | scope-derived | Force collection on |
| `-SkipCollection` | off | Triage and report only, copy nothing |
| `-NoZip` | off | Skip compressing the case folder |
| `-Menu` | off | Force the interactive menu |

## Output

```
AkiraEscape_<HOST>_<CASE>_<UTC>Z/
  report.html                 <- client-facing report, open in any browser
  report.md                   <- same content as Markdown
  findings.json               <- everything, machine-readable
  AI-HANDOFF.md               <- paste into Claude to get the written report
  summary.txt                 <- one-screen summary
  collection-manifest.csv     <- every collected file with its SHA-256
  logs/akira-escape.log
  artifacts/
    notes/        ransom notes, verbatim
    samples/      header/footer hex and entropy of sampled encrypted files
    eventlogs/    exported .evtx
    registry/     hive exports (Deep), Amcache, NTUSER.DAT copies
    tasks/        scheduled task XML created in the incident window
    prefetch/     .pf files (Deep)
    system/       command output: netstat, firewall rules, auditpol, vssadmin, ...
```

The whole folder is zipped with a printed SHA-256 unless `-NoZip` is used.

### Handing it to Claude

`AI-HANDOFF.md` contains a prompt plus a condensed JSON of the run. Paste the whole file
into Claude and it will write the client report — executive summary, timeline, remaining
risk, return-to-service assessment, recommendations. The prompt tells it not to invent
findings and to keep the confidence levels and caveats intact.

For a full-detail write-up, attach `findings.json` as well.

## What it checks

**Encryption survey** — budgeted file system walk that counts encrypted files by
extension, locates ransom notes, derives the encryption window from file timestamps,
tallies the worst-hit folders and original file types, samples header/footer bytes and
entropy (to show partial "spot" encryption), and flags *unrecognised* appended extensions
so a new variant or a second actor is not silently missed.

**Variant assessment** — ranks candidates with a confidence score and the evidence behind
it:

| Variant | Extension | Note |
|---|---|---|
| Akira (C++ / Windows), original line | `.akira` | `akira_readme.txt` |
| Megazord (Rust / Windows) | `.powerranges` | `powerranges.txt` |
| Akira_v2 / Rust line | `.akira` | `akira_readme.txt` |
| Akira ESXi / Linux encryptor | `.akira` | `akira_readme.txt` |

Extension and note names separate the Megazord branch reliably. They **cannot** separate
the C++ and Rust Akira lines — both use `.akira` and `akira_readme.txt`, and only analysis
of the recovered encryptor binary settles it. The tool says so in every report rather than
overclaiming; confidence is capped at 95%.

**Persistence sweep** — registry Run/RunOnce (machine and every loaded user hive), startup
folders, Winlogon Shell/Userinit, IFEO debuggers and SilentProcessExit, accessibility
binary replacement (sethc/utilman), LSA security/authentication packages, netsh helper
DLLs, print monitor DLLs, network provider DLLs, Active Setup StubPath, shell command
hijacks, scheduled tasks (with task XML captured when created in the incident window),
services, drivers (including a bring-your-own-vulnerable-driver list), WMI event
subscriptions, BITS jobs and local GPO scripts. Each entry is graded on path, command
line, signature state and whether the binary appeared inside the incident window.

**Intrusion tooling hunt** — processes, services, installed programs, prefetch, staging
directories and transfer-tool configuration files, matched against the utilities that
recur in Akira intrusions: AnyDesk, RustDesk, ScreenConnect, ngrok, Cloudflared, Chisel,
rclone, WinSCP, FileZilla, MEGA, Advanced IP Scanner, SoftPerfect NetScan, AdFind,
Mimikatz, LaZagne, ProcDump, PsExec, PCHunter, Process Hacker and friends. An `rclone.conf`
or `WinSCP.ini` is collected and flagged — that is the exfiltration/notification question,
not just an IOC.

**Security posture** — Defender state and exclusions (broad exclusions are called out),
tamper protection, third-party EDR service health, firewall profiles, RDP and NLA, WDigest
credential caching, `LocalAccountTokenFilterPolicy`, UAC, SMBv1, BitLocker, PowerShell
logging, patch age, pending reboot.

**Accounts** — local users and administrators, hidden `$`-suffixed names, passwordless
accounts, password changes inside the incident window, RDP group membership, user
profiles, and (where the AD module is available) Domain Admins and the krbtgt reset date.

**Backup and recovery** — shadow copies, `vssadmin` state, `bcdedit` recovery disablement,
backup product services and their state.

**Event log triage** — log clearing (1102/104), account creation and group changes,
service installs, scheduled task creation, RDP logon sources, failed-logon volume,
suspicious PowerShell script blocks (4104), Defender detections and protection-off events,
plus a log-coverage check that reports when a log does not reach back to the start of the
incident window.

**Return-to-service readiness** — 17 checks scored Pass / Warn / Fail / Manual, producing a
`NOT READY` / `READY WITH CONDITIONS` / `READY` verdict. Environment-level items the tool
cannot see from one host (initial access vector closed, whole-environment sweep, krbtgt
reset, exfiltration/notification assessment, monitoring for re-entry) are included as
explicit manual sign-offs rather than quietly omitted.

## Limits — read these before signing anything

* **Single host.** The verdict is a host-level opinion. Akira intrusions usually touch
  domain controllers, backup servers and hypervisors first. Run the tool everywhere and
  reconcile.
* **A clean persistence result is not proof of a clean host.** It means nothing was found
  in the locations checked. Only rebuild from known-good media gives certainty.
* **Variant identification is heuristic** and based on host-side artifacts, not binary
  analysis.
* **The file scan is bounded** by scope and time budget. Where a scan was truncated, the
  counts in the report are a floor, not a total.
* **Offline user hives are not loaded.** Per-user autostart keys are read for loaded hives
  only; `NTUSER.DAT` files are collected for offline parsing in Deep mode.
* **ESXi/Linux encryptors are out of reach.** If VM disks were encrypted from the
  hypervisor, the Windows guest shows the damage but not the cause — check the host.

## Maintaining the fingerprints

All matching data lives in one block near the top of the script under
`REFERENCE DATA`: note file names, note-content markers, known extensions, variant
records, the intrusion tooling list, the vulnerable driver list and the event IDs pulled
during triage. Edit those tables between engagements as new variants appear — no other
part of the script needs to change.
