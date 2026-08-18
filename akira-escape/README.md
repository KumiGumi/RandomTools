# Akira Escape Tool

Offline triage for Windows hosts caught in an Akira ransomware incident.

One PowerShell script. Drop it on a contained host, run it elevated, and it
reports what persistence is present, assesses which Akira variant hit the
machine, collects the evidence, and produces a return-to-service readiness
report you can hand to the client.

**It is read-only.** Nothing is cleaned, quarantined, deleted, killed or
decrypted. The only files it writes are inside its own case folder.

---

## Running it

```powershell
# Full run, non-interactive - this is the normal one
.\AkiraEscape.ps1 -RunAll -CaseName "ACME-IR-2026-014"

# Menu mode (no -RunAll) - pick individual modules
.\AkiraEscape.ps1

# Wider net: 90-day log window, specific volumes, plus a recovered encryptor
.\AkiraEscape.ps1 -RunAll -DaysBack 90 -ScanPath C:\,D:\,E:\ -SamplePath C:\evidence\w.exe

# Fast pass on a big file server - skip the volume walk and hive export
.\AkiraEscape.ps1 -RunAll -SkipFileScan -SkipHives
```

If PowerShell blocks the script:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\AkiraEscape.ps1 -RunAll
```

### Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-OutputPath` | `<SystemDrive>\AkiraEscape` | Where the case folder is created |
| `-CaseName` | *(none)* | Case reference printed on the report |
| `-ScanPath` | all fixed drives | Volumes/folders to search for notes and encrypted files |
| `-DaysBack` | `45` | Event log and "recent change" review window |
| `-MaxScanDepth` | `5` | Directory recursion depth for the file walk |
| `-SamplePath` | *(none)* | A recovered encryptor binary to fingerprint statically |
| `-RunAll` | off | Run every module and write the report without prompting |
| `-SkipEventLogs` | off | Skip event log queries and `.evtx` export |
| `-SkipHives` | off | Skip registry hive / Amcache / SRUM export |
| `-SkipFileScan` | off | Skip the volume walk entirely |

Runtime on a typical server is 5–20 minutes. The file walk dominates; on a
large file server use `-MaxScanDepth 3` or point `-ScanPath` at the shares
that matter.

---

## What it checks

**Persistence** — Run/RunOnce keys across HKLM and every loaded user hive,
startup folders, non-Microsoft scheduled tasks, services (unquoted paths,
binaries outside Windows/Program Files, unsigned), WMI event subscriptions,
Winlogon `Shell`/`Userinit` hijacks, IFEO debuggers, `AppInit_DLLs`, LSA
packages, print monitors, netsh helpers, BITS jobs, sticky-key/accessibility
binary swaps, and root certificates added inside the incident window.

**Variant** — weighted assessment from encrypted-file extensions, ransom note
filenames, note contents, and (if you supply a sample) the encryptor's build
language. Separates the 2023 C++ lineage, the Rust rewrite, and Megazord
(`.powerranges`). The report always shows the individual signals behind the
verdict and states plainly what the evidence cannot settle.

**Remote access** — AnyDesk, RustDesk, ScreenConnect, Atera, Splashtop,
TeamViewer, Radmin, Level, Action1, Ngrok, Cloudflared, Tailscale, Netbird,
Datto, Syncro. AnyDesk trace files are parsed for incoming connection IDs and
source addresses. RDP posture (enabled, port, NLA, allowed users).

**Defences and anti-forensics** — Defender status, exclusions, tamper
protection and policy kill switches; third-party AV registration; firewall
profiles; shadow copy presence and VSS state; `bcdedit` recovery tampering;
BYOVD drivers (`rwdrv.sys`, `hlpdrv.sys`, `zam64.sys`, `truesight.sys` and
friends) plus any running driver loaded from a user-writable path.

**Accounts** — local users and admins, accounts and profiles created or reset
inside the window, credential-dump artefacts (`lsass.dmp`, stray `ntds.dit`,
procdump), and a domain-controller flag.

**Network** — listeners, established sessions (anything reaching a public
address on a supposedly isolated host is flagged), shares, hosts file, DNS,
proxy, SMBv1.

**Events** — log clearing (1102/104), service installs (7045), account and
group changes, RDP logons (21/25/1149), failed-logon volume, Defender
detections and RTP-disable events (5001), suspicious PowerShell script blocks
(4104), and VSS events.

**Adversary tooling on disk** — netscan, Advanced IP Scanner, Rclone, WinSCP,
MEGAsync, Mimikatz, LaZagne, PsExec/PSEXESVC, PCHunter, Process Hacker, and
the encryptor filenames Akira has used.

## What it collects

Into `Artifacts\`, each SHA256-hashed into `Manifest.csv`:

- Event logs exported with `wevtutil` (Security, System, Application,
  PowerShell, TerminalServices ×3, TaskScheduler, Defender, Sysmon, WMI, BITS)
- Registry hives via `reg save` (SYSTEM, SOFTWARE, SAM, SECURITY), plus
  Amcache, SRUM and the SOFTWARE/SYSTEM transaction logs
- Prefetch (whole directory — last-execution times also feed the timeline)
- Ransom notes (up to 25), scheduled task XML, suspicious startup items
- AnyDesk traces, PSReadLine history per user, RDP bitmap cache
- Command captures: `ipconfig /all`, `netstat -ano`, `arp -a`, `route print`,
  `net share`, `net session`, `tasklist /v`, `tasklist /svc`, `whoami /all`,
  `systeminfo`, `qwinsta`

Locked files (hives, SRUM, Amcache) fall back to `esentutl /y /vss`.

---

## Output

```
AkiraEscape_<HOST>_<yyyyMMdd-HHmmss>\
├── Report.html        the client-facing report - open this one
├── Summary.txt        console-style summary
├── findings.json      everything, structured - give this to Claude
├── ClaudePrompt.md    ready-made prompt for writing the client report
├── Timeline.csv       merged timeline (filesystem + events + prefetch)
├── Findings.csv       findings in spreadsheet form
├── Manifest.csv       SHA256 of every collected artefact
├── Log.txt            what the tool did, timestamped
└── Artifacts\         the evidence itself
```

`Report.html` is self-contained, prints cleanly, and follows the reader's
light/dark theme.

### Getting a written report out of it

Open a Claude conversation, attach `findings.json` and `ClaudePrompt.md`, and
send. The prompt already carries the host facts, the variant assessment, the
readiness verdict and the required caveats, so the write-up cannot drift from
the evidence.

---

## The readiness verdict

The tool answers what it can from collected evidence and marks the rest
`MANUAL`, because no host-local tool can honestly answer them:

| Verdict | Meaning |
|---|---|
| `NOT READY` | An automated check failed, or a critical finding is open |
| `READY WITH CONDITIONS` | Nothing failed, but warnings/high findings need a decision |
| `READY (pending manual checks)` | Every automated host check passed |

Even the best case says *pending manual checks*. Initial access vector,
domain-wide credential reset, backup validation, MFA coverage and monitoring
are environment-level questions. The tool states them as outstanding actions
rather than pretending to have cleared them.

**This is triage evidence, not an eradication certificate.** The
return-to-service decision belongs to the lead responder and the client.

---

## Notes for the field

- Run it **before** anything is cleaned. The value is in the artefacts.
- Copy the whole case folder off the host before it gets rebuilt.
- Run it on more than one host — a DC, a file server, and the earliest
  suspected patient zero give you a much better picture than any single box.
- The tool never contacts the internet, so it is safe on an isolated segment.
  If it finds an active connection to a public address, that is a finding.
- Akira intrusions usually start at an internet-facing appliance (VPN/SSL-VPN,
  firewall, backup server), not at the host you are scanning. A clean report
  here does not mean the entry vector is closed.
- There is no free decryptor for current Akira builds. Plan on restore from
  known-good offline backup.
- Indicator lists (tooling, drivers, note signatures, extensions) are plain
  arrays at the top of the script — extend them as your intel changes.
