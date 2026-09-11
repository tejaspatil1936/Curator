# APT29 dataset — schema notes

Recorded from the files themselves. Every count comes from streaming all 783,367 records
of both event files; nothing is taken from documentation alone. The few statements that
are interpretation rather than measurement say so.

Generated tables were produced by profiling scripts from the data; the prose was checked
against the same output.

## 1. Where it is

OTRF Security-Datasets (the successor to Mordor), directory `datasets/compound/apt29/`,
pinned to commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` (tip of `master`, committed
2023-09-20). The files are ordinary Git blobs, not Git LFS pointers, fetched from
`https://raw.githubusercontent.com/OTRF/Security-Datasets/<commit>/datasets/compound/apt29/<path>`.

| Local path (under `datasets/`) | Bytes | SHA-256 |
|---|---:|---|
| `apt29/day1/apt29_evals_day1_manual.zip` | 13,944,973 | `98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5` |
| `apt29/day2/apt29_evals_day2_manual.zip` | 43,033,041 | `377f8cba5db95a453a3ee8bd19f493efafc23724541482a4da99da28ee4665f9` |
| `apt29/emulationplans/apt29.xlsx` | 25,051 | `053e70c6ba95eac481b370f8b1545ec3f1f00306c828634741a8c7399719c228` |
| `apt29/day1/zeek/combined_zeek.log` | 1,243,861 | not ingested, see §8 |
| `apt29/day2/zeek/combined_zeek.log` | 1,542,562 | not ingested, see §8 |
| `apt29/README.md`, `apt29/day1/README.md` | 6,391 and 3,952 | upstream documentation |

In the repository but not downloaded: packet captures (`day1/pcaps/`, `day2/pcaps/`,
about 70 MB) and per-host Zeek logs. There is no `_metadata` YAML for APT29 (the
`datasets/compound/_metadata/` directory covers other datasets only).

## 2. Format

- Each event zip holds exactly one member, a JSON Lines file:

  | Member | Bytes | Records |
  |---|---:|---:|
  | `apt29_evals_day1_manual_2020-05-01225525.json` | 385,334,029 | 196,081 |
  | `apt29_evals_day2_manual_2020-05-02035409.json` | 1,714,987,031 | 587,286 |
  | **Total** | 2,100,321,060 | **783,367** |

- One JSON object per line, terminated by `\n` (never `\r\n`). UTF-8, no byte-order
  mark, no blank lines. Every line parses; no object repeats a key; no line contains a
  `\u0000` escape. Longest line: 22,325 bytes.
- Lines are not in time order (day 2 line 1 has `UtcTime` 07:51:24.628, line 2 has
  07:50:47.031).
- No two lines are byte-identical, and no two records share (`Hostname`, `Channel`,
  `RecordNumber`). Records can be identical apart from `RecordNumber`: day 1 lines 1 and
  2 are the same Sysmon 10 process access, with RecordNumber 138294 and 138295.
- Curator reads the members straight out of the zips. `events.raw` is a line's text
  without its `\n`; `ocsf.metadata.uid` is `apt29/<member>:<line number>`.

## 3. Record structure

Each record is one Windows event as rendered by NXLog's `im_msvistalog` module (the
value of `SourceModuleType`), collected through a Windows Event Collector and passed
through Logstash. The event's own data fields sit at the top level beside NXLog's
envelope and Logstash's additions (`@timestamp`, `@version`, `host`, `port`, `tags`).

Envelope fields present in all 783,367 records, with their JSON type:

`@timestamp` (str), `@version` (str), `Channel` (str), `EventID` (int), `EventReceivedTime` (str), `EventTime` (str), `EventType` (str), `ExecutionProcessID` (int), `Hostname` (str), `Keywords` (int), `Message` (str), `RecordNumber` (int), `Severity` (str), `SeverityValue` (int), `SourceModuleName` (str), `SourceModuleType` (str), `SourceName` (str), `Task` (int), `ThreadID` (int), `host` (str), `port` (int), `tags` (list)

Every other field is a JSON string, including numeric data (`"ProcessId": "900"`,
`"DestinationPort": "1234"`), except NXLog's `OpcodeValue` and `Version`, which are
numbers where present.

What the envelope actually contains:

- **`Hostname` is the endpoint that produced the event**, as an FQDN:

  | `Hostname` | Records |
  |---|---:|
  | `UTICA.dmevals.local` | 492,268 |
  | `SCRANTON.dmevals.local` | 197,538 |
  | `NEWYORK.dmevals.local` | 53,142 |
  | `NASHUA.dmevals.local` | 40,419 |

- **`host` is not the endpoint.** It is `wec.internal.cloudapp.net`, the collector, in
  every record.
- `tags` is `["mordorDataset"]` and `@version` is `"1"` in every record.
- **`EventType` is NXLog's field**, with values `INFO`, `AUDIT_SUCCESS`,
  `AUDIT_FAILURE`, `WARNING`, `VERBOSE`, `ERROR`. Sysmon's own `EventType` data field
  (`CreateKey`, `SetValue`, and so on) uses the same key and was overwritten: every
  Sysmon record carries NXLog's value (`INFO` for EventIDs 1–23, `ERROR` for 255), and
  Sysmon's value survives only inside `Message` (for example `EventType: SetValue`).
- `Message` is NXLog's rendering of the whole event as text. It is 31% of day 1's bytes
  and 42% of day 2's.
- `AccountName`, `Domain`, `UserID` and `AccountType` (617,883 records) are the event's
  logging security context, not necessarily the actor:
  - Sysmon: always `SYSTEM` / `NT AUTHORITY` / `S-1-5-18`, the Sysmon service.
  - `Microsoft-Windows-PowerShell/Operational`: the account running PowerShell
    (`pbeesly`, `dschrute`, `mscott`, `wardog`, `SYSTEM`).
  - `Security`, `security` and `Windows PowerShell`: absent.

## 4. Sources

| Channel (exact string) | Day 1 | Day 2 | Total | Curator `source` |
|---|---:|---:|---:|---|
| `Microsoft-Windows-Sysmon/Operational` | 143,884 | 407,265 | 551,149 | `sysmon` |
| `Windows PowerShell` | 5,285 | 69,084 | 74,369 | `powershell` |
| `Microsoft-Windows-PowerShell/Operational` | 5,694 | 60,372 | 66,066 | `powershell` |
| `Security` | 28,627 | 27,207 | 55,834 | `winsec` |
| `security` | 12,375 | 22,854 | 35,229 | `winsec` |
| `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | 10 | 292 | 302 | `winevt` |
| `System` | 91 | 105 | 196 | `winevt` |
| `Microsoft-Windows-WMI-Activity/Operational` | 90 | 81 | 171 | `winevt` |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | 15 | 14 | 29 | `winevt` |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | 9 | 10 | 19 | `winevt` |
| `Microsoft-Windows-Bits-Client/Operational` | 1 | 2 | 3 | `winevt` |
| **Total** | **196,081** | **587,286** | **783,367** | |

- `Security` and `security` are two spellings from two collection paths, not copies of
  each other. Both come from provider `Microsoft-Windows-Security-Auditing`. Lower-case
  `security` comes only from SCRANTON (12,375 records) and UTICA (22,854), and only from
  23:18:35 on day 1 and 04:11:47 on day 2 (local `EventTime`). No (`Hostname`,
  `RecordNumber`) pair occurs under both spellings, and their EventIDs differ in part
  (§5).
- `SourceName` by channel: Sysmon is `Microsoft-Windows-Sysmon`; both Security spellings
  are `Microsoft-Windows-Security-Auditing` (plus two `Microsoft-Windows-Eventlog`
  records in `Security`); `Windows PowerShell` is `PowerShell`;
  `Microsoft-Windows-PowerShell/Operational` is `Microsoft-Windows-PowerShell`; `System`
  has 21 providers.
- The `source` column shows how Curator's parser (`api/curator/ingest/sysmon.py`)
  labels each channel.

## 5. Field names by source

`[n/m]`: present in n of the m records with that EventID. Types other than string are
given in parentheses. Envelope fields (§3) are omitted.

### Sysmon — `Microsoft-Windows-Sysmon/Operational`

| EventID | Records | Fields |
|---:|---:|---|
| 1 | 1,028 | `AccountName`, `AccountType`, `CommandLine` [1,027/1,028], `Company` [1,027/1,028], `CurrentDirectory` [1,027/1,028], `Description` [1,027/1,028], `Domain`, `FileVersion` [1,027/1,028], `Hashes` [1,027/1,028], `Image` [1,027/1,028], `IntegrityLevel` [1,027/1,028], `LogonGuid` [1,027/1,028], `LogonId` [1,027/1,028], `OpcodeValue` (int), `OriginalFileName` [1,027/1,028], `ParentCommandLine` [1,027/1,028], `ParentImage` [1,027/1,028], `ParentProcessGuid` [1,027/1,028], `ParentProcessId` [1,027/1,028], `ProcessGuid` [1,027/1,028], `ProcessId`, `Product` [1,027/1,028], `ProviderGuid`, `RuleName` [1,027/1,028], `TerminalSessionId` [1,027/1,028], `User` [1,027/1,028], `UserID`, `UtcTime` [1,027/1,028], `Version` (int) |
| 2 | 569 | `AccountName`, `AccountType`, `CreationUtcTime`, `Domain`, `Image`, `OpcodeValue` (int), `PreviousCreationUtcTime`, `ProcessGuid`, `ProcessId`, `ProviderGuid`, `RuleName`, `TargetFilename`, `UserID`, `UtcTime`, `Version` (int) |
| 3 | 3,415 | `AccountName`, `AccountType`, `DestinationHostname`, `DestinationIp`, `DestinationIsIpv6`, `DestinationPort`, `DestinationPortName`, `Domain`, `Image`, `Initiated`, `OpcodeValue` (int), `ProcessGuid`, `ProcessId`, `Protocol`, `ProviderGuid`, `RuleName`, `SourceHostname`, `SourceIp`, `SourceIsIpv6`, `SourcePort`, `SourcePortName`, `User`, `UserID`, `UtcTime`, `Version` (int) |
| 4 | 2 | `AccountName`, `AccountType`, `Domain`, `OpcodeValue` (int), `ProviderGuid`, `SchemaVersion`, `State`, `UserID`, `UtcTime`, `Version` (int) |
| 5 | 1,008 | `AccountName`, `AccountType`, `Domain`, `Image`, `OpcodeValue` (int), `ProcessGuid`, `ProcessId`, `ProviderGuid`, `RuleName`, `UserID`, `UtcTime`, `Version` (int) |
| 7 | 52,271 | `AccountName`, `AccountType`, `Company`, `Description` [52,217/52,271], `Domain`, `FileVersion`, `Hashes`, `Image`, `ImageLoaded`, `OpcodeValue` (int), `OriginalFileName`, `ProcessGuid`, `ProcessId`, `Product`, `ProviderGuid`, `RuleName`, `Signature`, `SignatureStatus`, `Signed`, `UserID`, `UtcTime`, `Version` (int) |
| 8 | 198 | `AccountName`, `AccountType`, `Domain`, `NewThreadId`, `OpcodeValue` (int), `ProcessId`, `ProviderGuid`, `RuleName`, `SourceImage`, `SourceProcessGuid`, `SourceProcessId`, `StartAddress`, `StartFunction`, `StartModule`, `TargetImage`, `TargetProcessGuid`, `TargetProcessId`, `UserID`, `UtcTime`, `Version` (int) |
| 9 | 1,625 | `AccountName`, `AccountType`, `Device`, `Domain`, `Image`, `OpcodeValue` (int), `ProcessGuid`, `ProcessId`, `ProviderGuid`, `RuleName`, `UserID`, `UtcTime`, `Version` (int) |
| 10 | 138,501 | `AccountName`, `AccountType`, `CallTrace`, `Domain`, `GrantedAccess`, `OpcodeValue` (int), `ProcessId`, `ProviderGuid`, `RuleName`, `SourceImage`, `SourceProcessGUID`, `SourceProcessId`, `SourceThreadId`, `TargetImage`, `TargetProcessGUID`, `TargetProcessId`, `UserID`, `UtcTime`, `Version` (int) |
| 11 | 7,128 | `AccountName`, `AccountType`, `CreationUtcTime`, `Domain`, `Image`, `OpcodeValue` (int), `ProcessGuid`, `ProcessId`, `ProviderGuid`, `RuleName`, `TargetFilename`, `UserID`, `UtcTime`, `Version` (int) |
| 12 | 224,045 | `AccountName`, `AccountType`, `Domain`, `Image`, `OpcodeValue` (int), `ProcessGuid`, `ProcessId`, `ProviderGuid`, `RuleName`, `TargetObject`, `UserID`, `UtcTime`, `Version` (int) |
| 13 | 118,771 | `AccountName`, `AccountType`, `Details` [118,769/118,771], `Domain`, `Image` [118,769/118,771], `OpcodeValue` (int), `ProcessGuid` [118,769/118,771], `ProcessId`, `ProviderGuid`, `RuleName` [118,769/118,771], `TargetObject` [118,769/118,771], `UserID`, `UtcTime` [118,769/118,771], `Version` (int) |
| 15 | 36 | `AccountName`, `AccountType`, `CreationUtcTime`, `Domain`, `Hash`, `Image`, `OpcodeValue` (int), `ProcessGuid`, `ProcessId`, `ProviderGuid`, `RuleName`, `TargetFilename`, `UserID`, `UtcTime`, `Version` (int) |
| 17 | 150 | `AccountName`, `AccountType`, `Domain`, `Image`, `OpcodeValue` (int), `PipeName`, `ProcessGuid`, `ProcessId`, `ProviderGuid`, `RuleName`, `UserID`, `UtcTime`, `Version` (int) |
| 18 | 722 | `AccountName`, `AccountType`, `Domain`, `Image`, `OpcodeValue` (int), `PipeName`, `ProcessGuid`, `ProcessId`, `ProviderGuid`, `RuleName`, `UserID`, `UtcTime`, `Version` (int) |
| 19 | 1 | `AccountName`, `AccountType`, `Domain`, `EventNamespace`, `Name`, `OpcodeValue` (int), `Operation`, `ProviderGuid`, `Query`, `RuleName`, `User`, `UserID`, `UtcTime`, `Version` (int) |
| 20 | 1 | `AccountName`, `AccountType`, `Destination`, `Domain`, `Name`, `OpcodeValue` (int), `Operation`, `ProviderGuid`, `RuleName`, `Type`, `User`, `UserID`, `UtcTime`, `Version` (int) |
| 21 | 1 | `AccountName`, `AccountType`, `Consumer`, `Domain`, `Filter`, `OpcodeValue` (int), `Operation`, `ProviderGuid`, `RuleName`, `User`, `UserID`, `UtcTime`, `Version` (int) |
| 22 | 226 | `AccountName`, `AccountType`, `Domain`, `Image`, `OpcodeValue` (int), `ProcessGuid`, `ProcessId`, `ProviderGuid`, `QueryName`, `QueryResults`, `QueryStatus`, `RuleName`, `UserID`, `UtcTime`, `Version` (int) |
| 23 | 1,449 | `AccountName`, `AccountType`, `Archived`, `Domain`, `Hashes`, `Image`, `IsExecutable`, `OpcodeValue` (int), `ProcessGuid`, `ProcessId`, `ProviderGuid`, `RuleName`, `TargetFilename`, `User`, `UserID`, `UtcTime`, `Version` (int) |
| 255 | 2 | `AccountName`, `AccountType`, `Description`, `Domain`, `ID`, `OpcodeValue` (int), `ProviderGuid`, `UserID`, `UtcTime`, `Version` (int) |

- Sysmon 10 spells its GUID fields `SourceProcessGUID` and `TargetProcessGUID`; Sysmon 8
  spells them `SourceProcessGuid` and `TargetProcessGuid`.
- Sysmon 8 and 10 records also carry `ProcessId`, equal to `SourceProcessId` in every
  one of them (138,501 and 198 records checked).
- Three Sysmon records have no event-data fields except `ProcessId`; their data exists
  only in `Message`. They are day 1 line 186,178 (EventID 1, SCRANTON, RecordNumber
  439712) and day 2 lines 342,200 and 584,181 (EventID 13, UTICA, RecordNumbers 932120
  and 1053683). They account for the `[1,027/1,028]` and `[118,769/118,771]` gaps above.
- `SourceHostname` and `DestinationHostname` (Sysmon 3) are `-` in all 3,415 records.

### Windows Security — `Security` and `security`

`*`: present in only some of that EventID's records.

| EventID | `Security` | `security` | Fields |
|---:|---:|---:|---|
| 1100 | 2 | 0 | `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `Version` (int) |
| 4608 | 0 | 2 | `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `Version` (int) |
| 4610 | 0 | 2 | `ActivityID`, `AuthenticationPackageName`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `Version` (int) |
| 4611 | 6 | 20 | `ActivityID`, `Category`, `LogonProcessName`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4614 | 0 | 4 | `ActivityID`, `Category`, `NotificationPackageName`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `Version` (int) |
| 4616 | 2 | 0 | `Category`, `NewTime`, `Opcode`, `OpcodeValue` (int), `PreviousTime`, `ProcessId`, `ProcessName`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4622 | 0 | 20 | `ActivityID`\*, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `SecurityPackageName`, `Version` (int) |
| 4624 | 461 | 137 | `ActivityID`\*, `AuthenticationPackageName`, `Category`, `ElevatedToken`, `ImpersonationLevel`, `IpAddress`, `IpPort`, `KeyLength`, `LmPackageName`, `LogonGuid`, `LogonProcessName`, `LogonType`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProcessName`\*, `ProviderGuid`, `RestrictedAdminMode`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetLinkedLogonId`, `TargetLogonId`, `TargetOutboundDomainName`, `TargetOutboundUserName`, `TargetUserName`, `TargetUserSid`, `TransmittedServices`, `Version` (int), `VirtualAccount`, `WorkstationName` |
| 4627 | 461 | 137 | `ActivityID`\*, `Category`, `EventCountTotal`, `EventIdx`, `GroupMembership`, `LogonType`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetLogonId`, `TargetUserName`, `TargetUserSid`, `Version` (int) |
| 4634 | 441 | 10 | `Category`, `LogonType`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `TargetDomainName`, `TargetLogonId`, `TargetUserName`, `TargetUserSid`, `Version` (int) |
| 4647 | 3 | 0 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `TargetDomainName`, `TargetLogonId`, `TargetUserName`, `TargetUserSid`, `Version` (int) |
| 4648 | 20 | 18 | `ActivityID`, `Category`, `IpAddress`, `IpPort`, `LogonGuid`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProcessName`\*, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetInfo`, `TargetLogonGuid`, `TargetServerName`, `TargetUserName`, `Version` (int) |
| 4656 | 7,811 | 3,326 | `AccessList`, `AccessMask`, `AccessReason`, `Category`, `HandleId`, `ObjectName`, `ObjectServer`, `ObjectType`, `Opcode`, `OpcodeValue` (int), `PrivilegeList`, `ProcessId`, `ProcessName`, `ProviderGuid`, `ResourceAttributes`, `RestrictedSidCount`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TransactionId`, `Version` (int) |
| 4657 | 7 | 68 | `Category`, `HandleId`, `NewValue`, `NewValueType`, `ObjectName`, `ObjectValueName`, `OldValue`, `OldValueType`, `Opcode`, `OpcodeValue` (int), `OperationType`, `ProcessId`, `ProcessName`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4658 | 15,618 | 6,519 | `Category`, `HandleId`, `ObjectServer`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProcessName`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4660 | 0 | 30 | `Category`, `HandleId`, `ObjectServer`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProcessName`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TransactionId`, `Version` (int) |
| 4661 | 62 | 0 | `AccessList`, `AccessMask`, `AccessReason`, `Category`, `HandleId`, `ObjectName`, `ObjectServer`, `ObjectType`, `Opcode`, `OpcodeValue` (int), `PrivilegeList`, `ProcessId`, `ProcessName`, `Properties`, `ProviderGuid`, `RestrictedSidCount`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TransactionId`, `Version` (int) |
| 4662 | 11 | 16 | `AccessList`, `AccessMask`, `ActivityID` ()\*, `AdditionalInfo`, `AdditionalInfo2`\*, `Category`, `HandleId`, `ObjectName`, `ObjectServer`, `ObjectType`, `Opcode`, `OpcodeValue` (int), `OperationType`, `Properties`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4663 | 7,503 | 3,093 | `AccessList`, `AccessMask`, `Category`, `HandleId`, `ObjectName`, `ObjectServer`, `ObjectType`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProcessName`, `ProviderGuid`, `ResourceAttributes`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4664 | 23 | 8 | `Category`, `FileName`, `LinkName`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TransactionId`, `Version` (int) |
| 4670 | 118 | 208 | `Category`, `HandleId`, `NewSd`, `ObjectName`, `ObjectServer`, `ObjectType`, `OldSd`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProcessName`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4672 | 320 | 127 | `ActivityID`\*, `Category`, `Opcode`, `OpcodeValue` (int), `PrivilegeList`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4673 | 1,769 | 893 | `Category`, `ObjectServer`, `Opcode`, `OpcodeValue` (int), `PrivilegeList`, `ProcessId`, `ProcessName`, `ProviderGuid`, `Service`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4674 | 118 | 8 | `AccessMask`, `Category`, `HandleId`, `ObjectName`, `ObjectServer`, `ObjectType`, `Opcode`, `OpcodeValue` (int), `PrivilegeList`, `ProcessId`, `ProcessName`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4688 | 396 | 620 | `Category`, `CommandLine`\*, `MandatoryLabel`, `NewProcessId`, `NewProcessName`, `Opcode`, `OpcodeValue` (int), `ParentProcessName`\*, `ProcessId`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetLogonId`, `TargetUserName`, `TargetUserSid`, `TokenElevationType`, `Version` (int) |
| 4689 | 586 | 378 | `Category`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProcessName`, `ProviderGuid`, `Status`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4690 | 7,781 | 3,248 | `Category`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProviderGuid`, `SourceHandleId`, `SourceProcessId`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetHandleId`, `TargetProcessId`, `Version` (int) |
| 4696 | 0 | 2 | `Category`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetLogonId`, `TargetProcessId`, `TargetProcessName`, `TargetUserName`, `TargetUserSid`, `Version` (int) |
| 4697 | 5 | 36 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `ServiceAccount`, `ServiceFileName`, `ServiceName`, `ServiceStartType`, `ServiceType`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 4698 | 1 | 0 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TaskContent`, `TaskName`, `Version` (int) |
| 4702 | 14 | 13 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TaskContentNew`, `TaskName`, `Version` (int) |
| 4703 | 2,951 | 2,211 | `Category`, `DisabledPrivilegeList`, `EnabledPrivilegeList`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProcessName`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetLogonId`, `TargetUserName`, `TargetUserSid`, `Version` (int) |
| 4720 | 1 | 0 | `AccountExpires`, `ActivityID`, `AllowedToDelegateTo`, `Category`, `DisplayName`, `HomeDirectory`, `HomePath`, `LogonHours`, `NewUacValue`, `OldUacValue`, `Opcode`, `OpcodeValue` (int), `PasswordLastSet`, `PrimaryGroupId`, `PrivilegeList`, `ProfilePath`, `ProviderGuid`, `SamAccountName`, `ScriptPath`, `SidHistory`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetSid`, `TargetUserName`, `UserAccountControl`, `UserParameters`, `UserPrincipalName`, `UserWorkstations`, `Version` (int) |
| 4722 | 1 | 0 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetSid`, `TargetUserName`, `Version` (int) |
| 4724 | 1 | 0 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetSid`, `TargetUserName`, `Version` (int) |
| 4728 | 1 | 0 | `ActivityID`, `Category`, `MemberName`, `MemberSid`, `Opcode`, `OpcodeValue` (int), `PrivilegeList`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetSid`, `TargetUserName`, `Version` (int) |
| 4732 | 1 | 0 | `ActivityID`, `Category`, `MemberName`, `MemberSid`, `Opcode`, `OpcodeValue` (int), `PrivilegeList`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetSid`, `TargetUserName`, `Version` (int) |
| 4738 | 1 | 0 | `AccountExpires`, `ActivityID`, `AllowedToDelegateTo`, `Category`, `DisplayName`, `Dummy`, `HomeDirectory`, `HomePath`, `LogonHours`, `NewUacValue`, `OldUacValue`, `Opcode`, `OpcodeValue` (int), `PasswordLastSet`, `PrimaryGroupId`, `PrivilegeList`, `ProfilePath`, `ProviderGuid`, `SamAccountName`, `ScriptPath`, `SidHistory`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetSid`, `TargetUserName`, `UserAccountControl`, `UserParameters`, `UserPrincipalName`, `UserWorkstations`, `Version` (int) |
| 4768 | 21 | 0 | `Category`, `IpAddress`, `IpPort`, `Opcode`, `OpcodeValue` (int), `PreAuthType`, `ProviderGuid`, `ServiceName`, `ServiceSid`, `Status`, `TargetDomainName`, `TargetSid`, `TargetUserName`, `TicketEncryptionType`, `TicketOptions`, `Version` (int) |
| 4769 | 59 | 0 | `Category`, `IpAddress`, `IpPort`, `LogonGuid`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `ServiceName`, `ServiceSid`, `Status`, `TargetDomainName`, `TargetUserName`, `TicketEncryptionType`, `TicketOptions`, `TransmittedServices`, `Version` (int) |
| 4776 | 2 | 0 | `Category`, `Opcode`, `OpcodeValue` (int), `PackageName`, `ProviderGuid`, `Status`, `TargetUserName`, `Version` (int), `Workstation` |
| 4798 | 47 | 14 | `ActivityID`, `CallerProcessId`, `CallerProcessName`, `Category`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetSid`, `TargetUserName`, `Version` (int) |
| 4799 | 14 | 38 | `ActivityID`\*, `CallerProcessId`, `CallerProcessName`, `Category`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetDomainName`, `TargetSid`, `TargetUserName`, `Version` (int) |
| 4826 | 0 | 2 | `AdvancedOptions`, `Category`, `ConfigAccessPolicy`, `DisableIntegrityChecks`, `FlightSigning`, `HypervisorDebug`, `HypervisorLaunchType`, `HypervisorLoadOptions`, `KernelDebug`, `LoadOptions`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `RemoteEventLogging`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TestSigning`, `Version` (int), `VsmLaunchType` |
| 4902 | 0 | 2 | `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `PuaCount`, `PuaPolicyId`, `Version` (int) |
| 4944 | 0 | 2 | `ActivityID`, `Category`, `GroupPolicyApplied`, `LogDroppedPacketsEnabled`, `LogSuccessfulConnectionsEnabled`, `MulticastFlowsEnabled`, `Opcode`, `OpcodeValue` (int), `OperationMode`, `Profile`, `ProviderGuid`, `RemoteAdminEnabled`, `Version` (int) |
| 4945 | 0 | 412 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProfileUsed`, `ProviderGuid`, `RuleId`, `RuleName`, `Version` (int) |
| 4946 | 282 | 8 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProfileChanged`, `ProviderGuid`, `RuleId`, `RuleName`, `Version` (int) |
| 4948 | 0 | 8 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProfileChanged`, `ProviderGuid`, `RuleId`, `RuleName`, `Version` (int) |
| 4953 | 0 | 6 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `Profile`, `ProviderGuid`, `ReasonForRejection`, `RuleId`, `RuleName`, `Version` (int) |
| 4956 | 0 | 2 | `ActiveProfile`, `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `Version` (int) |
| 4957 | 0 | 54 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `RuleAttr`, `RuleId`, `RuleName`, `Version` (int) |
| 5024 | 0 | 2 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `Version` (int) |
| 5033 | 0 | 2 | `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `Version` (int) |
| 5058 | 16 | 4 | `AlgorithmName`, `Category`, `ClientCreationTime`, `ClientProcessId`, `KeyFilePath`, `KeyName`, `KeyType`, `Opcode`, `OpcodeValue` (int), `Operation`, `ProcessId`, `ProviderGuid`, `ProviderName`, `ReturnCode`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 5059 | 1 | 4 | `AlgorithmName`, `Category`, `ClientCreationTime`, `ClientProcessId`, `KeyName`, `KeyType`, `Opcode`, `OpcodeValue` (int), `Operation`, `ProcessId`, `ProviderGuid`, `ProviderName`, `ReturnCode`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 5061 | 16 | 4 | `AlgorithmName`, `Category`, `KeyName`, `KeyType`, `Opcode`, `OpcodeValue` (int), `Operation`, `ProviderGuid`, `ProviderName`, `ReturnCode`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 5140 | 78 | 0 | `AccessList`, `AccessMask`, `Category`, `IpAddress`, `IpPort`, `ObjectType`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `ShareLocalPath`\*, `ShareName`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 5142 | 0 | 8 | `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `ShareLocalPath`\*, `ShareName`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 5145 | 178 | 0 | `AccessList`, `AccessMask`, `AccessReason`, `Category`, `IpAddress`, `IpPort`, `ObjectType`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `RelativeTargetName`, `ShareLocalPath`\*, `ShareName`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `Version` (int) |
| 5154 | 208 | 2,632 | `Application`, `Category`, `FilterRTID`, `LayerName`, `LayerRTID`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `Protocol`, `ProviderGuid`, `SourceAddress`, `SourcePort`, `Version` (int) |
| 5156 | 5,010 | 1,924 | `Application`, `Category`, `DestAddress`, `DestPort`, `Direction`, `FilterRTID`, `LayerName`, `LayerRTID`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `Protocol`, `ProviderGuid`, `RemoteMachineID`, `RemoteUserID`, `SourceAddress`, `SourcePort`, `Version` (int) |
| 5157 | 40 | 1 | `Application`, `Category`, `DestAddress`, `DestPort`, `Direction`, `FilterRTID`, `LayerName`, `LayerRTID`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `Protocol`, `ProviderGuid`, `RemoteMachineID`, `RemoteUserID`, `SourceAddress`, `SourcePort`, `Version` (int) |
| 5158 | 3,208 | 3,192 | `Application`, `Category`, `FilterRTID`, `LayerName`, `LayerRTID`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `Protocol`, `ProviderGuid`, `SourceAddress`, `SourcePort`, `Version` (int) |
| 5379 | 70 | 13 | `ActivityID`, `Category`, `ClientProcessId`, `CountOfCredentialsReturned`, `Opcode`, `OpcodeValue` (int), `ProcessCreationTime`, `ProviderGuid`, `ReadOperation`, `ReturnCode`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `TargetName`, `Type`, `Version` (int) |
| 5441 | 0 | 114 | `Action`, `ActivityID`, `CalloutKey`, `CalloutName`, `Category`, `Conditions`, `FilterId`, `FilterKey`, `FilterName`, `FilterType`, `LayerId`, `LayerKey`, `LayerName`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `ProviderKey`, `ProviderName`, `Version` (int), `Weight` |
| 5442 | 0 | 8 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `ProviderKey`, `ProviderName`, `ProviderType`, `Version` (int) |
| 5444 | 0 | 14 | `ActivityID`, `Category`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `ProviderKey`, `ProviderName`, `SubLayerKey`, `SubLayerName`, `SubLayerType`, `Version` (int), `Weight` |
| 5446 | 0 | 76 | `ActivityID`, `CalloutId`, `CalloutKey`, `CalloutName`, `CalloutType`, `Category`, `ChangeType`, `LayerId`, `LayerKey`, `LayerName`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProviderGuid`, `ProviderKey`, `ProviderName`, `UserName`, `UserSid`, `Version` (int) |
| 5447 | 88 | 5,490 | `Action`, `ActivityID`, `CalloutKey`, `CalloutName`, `Category`, `ChangeType`, `Conditions`, `FilterId`, `FilterKey`, `FilterName`, `FilterType`, `LayerId`, `LayerKey`, `LayerName`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProviderGuid`, `ProviderKey`, `ProviderName`, `UserName`, `UserSid`, `Version` (int), `Weight` |
| 5448 | 0 | 6 | `ActivityID`, `Category`, `ChangeType`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProviderGuid`, `ProviderKey`, `ProviderName`, `ProviderType`, `UserName`, `UserSid`, `Version` (int) |
| 5449 | 0 | 6 | `ActivityID`, `Category`, `ChangeType`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProviderContextKey`, `ProviderContextName`, `ProviderContextType`, `ProviderGuid`, `ProviderKey`, `ProviderName`, `UserName`, `UserSid`, `Version` (int) |
| 5450 | 0 | 16 | `ActivityID`, `Category`, `ChangeType`, `Opcode`, `OpcodeValue` (int), `ProcessId`, `ProviderGuid`, `ProviderKey`, `ProviderName`, `SubLayerKey`, `SubLayerName`, `SubLayerType`, `UserName`, `UserSid`, `Version` (int), `Weight` |
| 6416 | 0 | 11 | `Category`, `ClassId`, `ClassName`, `CompatibleIds`, `DeviceDescription`, `DeviceId`, `LocationInformation`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserName`, `SubjectUserSid`, `VendorIds`, `Version` (int) |

### `Microsoft-Windows-PowerShell/Operational`

| EventID | Records | Fields |
|---:|---:|---|
| 4100 | 49 | `AccountName`, `AccountType`, `ActivityID`, `Category`, `ContextInfo`, `Domain`, `Opcode`, `OpcodeValue` (int), `Payload`, `ProviderGuid`, `UserID`, `Version` (int) |
| 4101 | 2 | `AccountName`, `AccountType`, `ActivityID`, `ContextInfo`, `Domain`, `Opcode`, `OpcodeValue` (int), `Payload`, `ProviderGuid`, `UserData`, `UserID`, `Version` (int) |
| 4103 | 64,627 | `AccountName`, `AccountType`, `ActivityID`, `Category`, `ContextInfo` [64,573/64,627], `Domain`, `Opcode`, `OpcodeValue` (int), `Payload` [64,573/64,627], `ProviderGuid`, `UserID`, `Version` (int) |
| 4104 | 1,130 | `AccountName`, `AccountType`, `ActivityID`, `Category`, `Domain`, `MessageNumber` [585/1,130], `MessageTotal` [585/1,130], `Opcode`, `OpcodeValue` (int), `Path` [49/1,130], `ProviderGuid`, `ScriptBlockId` [585/1,130], `ScriptBlockText` [585/1,130], `UserID`, `Version` (int) |
| 8193 | 6 | `AccountName`, `AccountType`, `ActivityID`, `Category`, `Domain`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `UserID`, `Version` (int), `param1` |
| 8194 | 6 | `AccountName`, `AccountType`, `ActivityID`, `Category`, `Domain`, `InstanceId`, `MaxRunspaces`, `MinRunspaces`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `UserID`, `Version` (int) |
| 8195 | 6 | `AccountName`, `AccountType`, `ActivityID`, `Category`, `Domain`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `UserID`, `Version` (int) |
| 8196 | 77 | `AccountName`, `AccountType`, `ActivityID`, `Domain`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `UserID`, `Version` (int) |
| 8197 | 22 | `AccountName`, `AccountType`, `ActivityID`, `Category`, `Domain`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `UserID`, `Version` (int), `param1` |
| 12039 | 77 | `AccountName`, `AccountType`, `ActivityID`, `Domain`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `UserID`, `Version` (int) |
| 40961 | 19 | `AccountName`, `AccountType`, `ActivityID`, `Category`, `Domain`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `UserID`, `Version` (int) |
| 40962 | 17 | `AccountName`, `AccountType`, `ActivityID`, `Category`, `Domain`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `UserID`, `Version` (int) |
| 53504 | 28 | `AccountName`, `AccountType`, `ActivityID` [24/28], `Category`, `Domain`, `Opcode`, `OpcodeValue` (int), `ProviderGuid`, `UserID`, `Version` (int), `param1`, `param2` |

### `Windows PowerShell`

| EventID | Records | Fields |
|---:|---:|---|
| 400 | 33 | `Category`, `Opcode` |
| 403 | 16 | `Category`, `Opcode` |
| 600 | 217 | `Category`, `Opcode` |
| 800 | 74,103 | `Category`, `Opcode` |

`Windows PowerShell` records carry no event-data fields; their content is only in
`Message`.

### Other channels (all `winevt`)

| Channel | EventIDs (records) |
|---|---|
| `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | 2002 (2), 2004 (290), 2006 (8), 2010 (2) |
| `System` | 1 (6), 3 (2), 6 (22), 10 (4), 11 (6), 12 (2), 13 (2), 14 (2), 16 (15), 18 (2), 20 (4), 25 (2), 27 (2), 32 (2), 35 (2), 37 (3), 46 (2), 55 (4), 98 (6), 109 (2), 153 (2), 172 (2), 1074 (2), 1500 (2), 6005 (2), 6006 (2), 6009 (2), 6013 (2), 6038 (2), 7001 (2), 7002 (3), 7026 (2), 7036 (30), 7040 (8), 7045 (5), 8013 (2), 10010 (1), 10016 (9), 10148 (2), 10149 (2), 16962 (2), 50036 (2), 50037 (2), 50103 (2), 50104 (2), 50105 (2), 50106 (2), 51046 (2), 51047 (2), 51057 (2) |
| `Microsoft-Windows-WMI-Activity/Operational` | 5857 (97), 5858 (61), 5859 (2), 5860 (7), 5861 (4) |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | 258 (4), 261 (2), 263 (15), 1136 (2), 1149 (2), 20523 (4) |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | 21 (2), 22 (2), 23 (3), 24 (2), 32 (2), 40 (2), 41 (2), 42 (2), 54 (2) |
| `Microsoft-Windows-Bits-Client/Operational` | 306 (3) |

## 6. Timestamps

| Field | Where | Format | Clock |
|---|---|---|---|
| `UtcTime` | Sysmon, 551,146 of 551,149 records | `YYYY-MM-DD HH:MM:SS.fff` | UTC |
| `EventTime` | every record | `YYYY-MM-DD HH:MM:SS` | local, UTC−4 (derived below) |
| `EventReceivedTime` | every record | `YYYY-MM-DD HH:MM:SS` | local, UTC−4 |
| `@timestamp` | every record | `YYYY-MM-DDTHH:MM:SS.fffZ` | UTC; Logstash processing time |

Other time-named fields describe attributes, not the event: `CreationUtcTime` and
`PreviousCreationUtcTime` (Sysmon 2, 11, 15; `YYYY-MM-DD HH:MM:SS.fff`), and
`ClientCreationTime`, `ProcessCreationTime`, `NewTime`, `PreviousTime` (Security) and
`DeviceTime`, `StartTime`, `StopTime`, `NewTime`, `OldTime` (System), all
`YYYY-MM-DDTHH:MM:SS.fffffffffZ`.

**No record states `EventTime`'s offset.** It was derived:

- Sysmon records carry both clocks. `floor(UtcTime) − EventTime` is exactly 14,400 s
  (4 h) in 523,179 records, between 14,363 and 14,399 s in 27,966, and 14,401 s in 1.
  The shortfall is `EventTime` trailing Sysmon's own timestamp by 0–37 s (the moment the
  record was written to the log). The pattern is the same on all four hosts.
- `@timestamp − EventReceivedTime` is 4.00 h in 761,129 records and 4.01 h in 22,238.
- UTC−4 is the US Eastern daylight offset for these dates. That is context, not a
  measurement.

`@timestamp` is not event time. For Sysmon it trails `UtcTime` by under 10 s in 89,092
records, by 10–60 s in 46,186, and by 1–10 minutes in 415,696, and it is earlier than
`UtcTime` in 172. On day 2, `EventReceivedTime − EventTime` ranges from 0 to 8 minutes.

Curator's rule, applied at parse time: Sysmon records use `UtcTime` as UTC, with
millisecond precision. All other records, and the three Sysmon records without `UtcTime`,
use `EventTime` + 4 h, with second precision. `ocsf.x_curator.time_field` records which.

Resulting time range (UTC):

| | First event | Last event |
|---|---|---|
| Day 1 | 2020-05-02 02:55:23.551 | 2020-05-02 03:28:17.683 |
| Day 2 | 2020-05-02 07:50:47.031 | 2020-05-02 08:29:22.020 |

## 7. Value formats

- **Process IDs.** Sysmon uses decimal strings. Security uses `0x…` hex strings for
  `ProcessId` in most EventIDs and for `NewProcessId`, `SourceProcessId`,
  `TargetProcessId` and `CallerProcessId`, but decimal strings for `ProcessId` in the
  filtering-platform events 5154–5158, in 5058/5059 and 5446–5450, and for
  `ClientProcessId`. The single key `ProcessId` holds both forms (day 1 `Security`:
  23,535 hex, 4,203 decimal).
- **Image paths.** `C:\…` in Sysmon and most Security fields, with inconsistent case
  (`C:\windows\system32\svchost.exe` and `C:\Windows\System32\svchost.exe` both occur).
  Security filtering-platform `Application` values are lower-case kernel paths
  (`\device\harddiskvolume2\windows\system32\svchost.exe`) or `System`. `ObjectName` for
  process objects in 4656/4663 is also a kernel path
  (`\Device\HarddiskVolume2\Windows\System32\lsass.exe`).
- **IP addresses.** IPv4; IPv6 including `0:0:0:0:0:0:0:1`, `::` and `fe80::…`; `-` for
  none (Security 4624, 4648); IPv4-mapped IPv6 such as `::ffff:10.0.1.4`, only in
  Security 4768 and 4769. Ports are decimal strings, with `-` or `0` in some Security
  4624/4648 records.
- **Users.** Sysmon `User` is `DOMAIN\user` (`DMEVALS\pbeesly`,
  `NT AUTHORITY\LOCAL SERVICE`); the single Sysmon 21 record holds a SID-like string
  there. Security splits `SubjectUserName` / `SubjectDomainName` / `SubjectUserSid` from
  the matching `Target…` fields; values include `-`, machine accounts (`UTICA$`) and, in
  4769, UPNs (`dschrute@DMEVALS.LOCAL`). One domain is written `DMEVALS`,
  `DMEVALS.LOCAL`, `dmevals.local` and `dmevals`.
- **Hashes.** Sysmon `Hashes` (EventIDs 1, 7, 23) is
  `SHA1=<40 hex>,MD5=<32>,SHA256=<64>,IMPHASH=<32>` in every record. Sysmon 15 uses
  `Hash`: that layout in 28 records, the literal `Unknown` in 8.
- **Registry paths.** Sysmon `TargetObject` is `HKLM\…` or `HKU\…`; Security
  `ObjectName` is `\REGISTRY\MACHINE\…` or `\REGISTRY\USER\…`.
- **Security `ObjectType`** (complete): 4656 — Key 10,909, File 91, Process 37,
  SAM_DOMAIN 28, Unknown 28, SAM_SERVER 26, SERVICE OBJECT 12, SAM_ALIAS 3, Enumerate 3;
  4663 — Key 10,573, Process 23; 4661 — SAM_DOMAIN, SAM_GROUP, SAM_ALIAS, SAM_USER; 4662
  — SecretObject, WMI Namespace, `%{19195a5b-6da0-11d0-afd3-00c04fd930c9}`; 4670 — Token;
  4674 — `-`, Key, Semaphore, SERVICE OBJECT, SC_MANAGER OBJECT, Mutant, File; 5140 and
  5145 — File.
- **`LogonType`** (complete): 3 (1,304), 5 (276), 2 (55), 10 (8), 0 (4).
  `AuthenticationPackageName` (4624): Kerberos, Negotiate, NTLM, `-`, and a DLL path.
- **Filtering platform.** `Protocol`: 6, 17, 58, 2. `Direction`: `%%14593` (5,719) and
  `%%14592` (1,256), which are message-table codes, not words.
- **Integrity.** Sysmon 1 `IntegrityLevel`: System, Medium, AppContainer, High. Security
  4688 `MandatoryLabel`: `S-1-16-16384`, `S-1-16-8192`, `S-1-16-4096`, `S-1-16-12288`.
- **DNS.** Sysmon 22 `QueryStatus`: 0 (210), 9003 (11), 9501, 123, 9852.
- `MemberName` (Security 4728, 4732) is `-` in both records.
- **HTML entities inside values**: `&lt;Anonymous Pipe&gt;` (Sysmon 17/18 `PipeName`),
  `-&gt;` (System `TimeSource`).
- **A mis-encoded character in the attacker's file name.** Values read
  `C:\ProgramData\victim\â€®cod.3aka3.scr`. `â€®` is what the UTF-8 bytes of U+202E
  (RIGHT-TO-LEFT OVERRIDE) look like when decoded as Windows-1252, consistent with a
  right-to-left-override file name that was double-encoded upstream; the emulation plan
  (step 4.B) calls the process `rcs.3aka3.doc`. That reading is interpretation; the
  stored bytes are exactly as found.

Nothing is normalised at ingest except event time (to UTC, §6), and in the `src_ip` and
`dst_ip` columns only, IPv4-mapped IPv6 written as plain IPv4. `ocsf` and `raw` keep the
original values.

## 8. Not ingested: Zeek and packet captures

| File | Lines | `ts` range (UTC), over lines that have `ts` |
|---|---:|---|
| `apt29/day1/zeek/combined_zeek.log` | 2,140 | 2020-04-30 00:06:38 to 00:45:00 |
| `apt29/day2/zeek/combined_zeek.log` | 5,664 | 2020-05-01 07:02:02 to 2020-05-02 02:16:53 |

Neither range overlaps the host events (2020-05-02 02:55 to 08:29 UTC), and the day 1
README dates its packet captures 2020-04-30. The network data comes from different runs
of the scenarios, so it cannot be correlated with these host events and is not loaded.

Zeek streams present: day 1 — conn 613, files 448, ssl 378, x509 378, dce_rpc 123, http
62, dns 53, kerberos 35, dpd 12, smb_files 12, weird 12, smb_mapping 11, notice 2, pe 1.
Day 2 — loaded_scripts 2,880, conn 1,172, ssl 686, dce_rpc 388, dns 250, kerberos 86,
reporter 65, files 33, weird 26, smb_mapping 23, stats 17, x509 12, smb_files 9,
capture_loss 8, packet_filter 6, http 1, notice 1, pe 1.

There is no Linux data, so nothing for the `auditd` parser.

## 9. Ground truth

Ground truth ships with the dataset: `apt29/emulationplans/apt29.xlsx`, which the
dataset README lists as the emulation plan for both scenarios.

- Two sheets. `day1` has 32 rows with header `Stage, Technique, Step, Description,
  hands-on, User, Source, Target`. `day2` has 35 rows with header `Stage, Techniques,
  Step, Description, Hands-on, User, Source Endpoint, Target Endpoint`.
- Technique **IDs** appear only inside the Description prose, in parentheses ("a
  legitimate user clicks (T1204)"). The Technique(s) column holds names. Setup rows have
  Step `0` and cite no IDs. Step values sometimes carry trailing spaces (`1.B `).
- 49 step rows cite IDs (25 on day 1, 24 on day 2), giving 127 (step, ID) pairs and 59
  distinct IDs.
- The plan has no timestamps, so `ground_truth.ts` is NULL.
- The IDs predate ATT&CK sub-techniques (the evaluation ran in 2020). Against ATT&CK
  Enterprise 19.2: 35 are current, 23 are revoked with a named replacement (MITRE's
  `revoked-by` relationship in the bundle), and 1 is deprecated.
- Anomalies, loaded exactly as shipped:
  - Day 2 step 16.D says the attacker "dumps the hash of the KRBTGT account (T1103)".
    T1103 is AppInit DLLs. The behaviour described is credential dumping, which the
    Technique column also lists ("Remote File Copy, Credential Dumping").
  - Day 1 steps 5.A and 5.B have identical Descriptions (both cite T1050 and T1060).
  - Day 1 step 10.B's Technique column says "Registry Run Keys / Startup Folder", while
    its Description cites T1106 and T1134.
- The `hands-on` column contains lab credentials in plain text. Curator does not load it.

| Shipped ID | Cited in steps | ATT&CK Enterprise 19.2 |
|---|---|---|
| T1204 | day1 1.A, day2 11.A | current: User Execution |
| T1036 | day1 1.A, day1 6.A | current: Masquerading |
| T1065 | day1 1.A | revoked → T1571 Non-Standard Port |
| T1059 | day1 1.B | current: Command and Scripting Interpreter |
| T1086 | day1 1.B, day1 4.A, day1 9.B, day2 11.A, day2 20.A | revoked → T1059.001 PowerShell |
| T1083 | day1 2.A, day1 4.C, day1 9.B, day2 11.A, day2 12.A | current: File and Directory Discovery |
| T1119 | day1 2.A, day1 9.B | current: Automated Collection |
| T1005 | day1 2.A, day1 7.B, day1 9.B, day2 17.B | current: Data from Local System |
| T1002 | day1 2.A, day1 7.B, day1 9.B, day2 17.C | revoked → T1560 Archive Collected Data |
| T1074 | day1 2.A, day1 9.B, day2 17.B | current: Data Staged |
| T1041 | day1 2.B, day1 9.B | current: Exfiltration Over C2 Channel |
| T1105 | day1 3.A, day1 9.A, day2 14.B, day2 16.D | current: Ingress Tool Transfer |
| T1027 | day1 3.A, day2 14.B, day2 17.C | current: Obfuscated Files or Information |
| T1122 | day1 3.B, day2 14.A | revoked → T1546.015 Component Object Model Hijacking |
| T1088 | day1 3.B, day2 14.A | revoked → T1548.002 Bypass User Account Control |
| T1043 | day1 3.B, day2 11.A | deprecated (Commonly Used Port) |
| T1071 | day1 3.B, day2 11.A | current: Application Layer Protocol |
| T1032 | day1 3.B, day2 11.A | revoked → T1573 Encrypted Channel |
| T1112 | day1 3.C | current: Modify Registry |
| T1140 | day1 4.A, day2 11.A, day2 14.B | current: Deobfuscate/Decode Files or Information |
| T1057 | day1 4.B, day1 4.C, day1 8.A, day2 11.A, day2 13.D, day2 14.B | current: Process Discovery |
| T1107 | day1 4.B, day1 9.C, day2 19.A, day2 19.B, day2 19.C | revoked → T1070.004 File Deletion |
| T1033 | day1 4.C, day2 11.A, day2 13.C, day2 15.A, day2 16.B | current: System Owner/User Discovery |
| T1082 | day1 4.C, day2 11.A, day2 13.A | current: System Information Discovery |
| T1016 | day1 4.C, day2 11.A | current: System Network Configuration Discovery |
| T1063 | day1 4.C, day2 12.B, day2 13.B | revoked → T1518.001 Security Software Discovery |
| T1069 | day1 4.C | current: Permission Groups Discovery |
| T1106 | day1 4.C, day1 10.B, day2 16.B | current: Native API |
| T1050 | day1 5.A, day1 5.B | revoked → T1543.003 Windows Service |
| T1060 | day1 5.A, day1 5.B, day1 10.A, day2 11.A | revoked → T1547.001 Registry Run Keys / Startup Folder |
| T1081 | day1 6.A | revoked → T1552.001 Credentials In Files |
| T1003 | day1 6.A, day1 6.C, day2 14.B | current: OS Credential Dumping |
| T1145 | day1 6.B | revoked → T1552.004 Private Keys |
| T1113 | day1 7.A | current: Screen Capture |
| T1115 | day1 7.A | current: Clipboard Data |
| T1056 | day1 7.A | current: Input Capture |
| T1022 | day1 7.B, day1 9.B | revoked → T1560 Archive Collected Data |
| T1048 | day1 7.B, day2 18.A | current: Exfiltration Over Alternative Protocol |
| T1018 | day1 8.A, day2 16.A | current: Remote System Discovery |
| T1028 | day1 8.A, day2 16.C, day2 20.B | revoked → T1021.006 Windows Remote Management |
| T1045 | day1 8.B | revoked → T1027.002 Software Packing |
| T1077 | day1 8.C | revoked → T1021.002 SMB/Windows Admin Shares |
| T1035 | day1 8.C, day1 10.A | revoked → T1569.002 Service Execution |
| T1078 | day1 8.C, day2 16.C | current: Valid Accounts |
| T1134 | day1 10.B | current: Access Token Manipulation |
| T1096 | day2 11.A | revoked → T1564.004 NTFS File Attributes |
| T1497 | day2 11.A | current: Virtualization/Sandbox Evasion |
| T1120 | day2 11.A | current: Peripheral Device Discovery |
| T1099 | day2 12.A | revoked → T1070.006 Timestomp |
| T1012 | day2 12.C | current: Query Registry |
| T1047 | day2 14.B | current: Windows Management Instrumentation |
| T1084 | day2 15.A, day2 20.A | revoked → T1546.003 Windows Management Instrumentation Event Subscription |
| T1103 | day2 16.D | revoked → T1546.010 AppInit DLLs |
| T1114 | day2 17.A | current: Email Collection |
| T1102 | day2 18.A | current: Web Service |
| T1055 | day2 19.A, day2 19.B, day2 19.C | current: Process Injection |
| T1085 | day2 20.A | revoked → T1218.011 Rundll32 |
| T1097 | day2 20.B | revoked → T1550.003 Pass the Ticket |
| T1136 | day2 20.B | current: Create Account |
