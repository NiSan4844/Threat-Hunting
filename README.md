# Threat-Hunting for Stuxbot with Elastic

## Threat Intelligence Report Sumamry 

The Stuxbot group is an organized cybercrime collective known for its opportunistic phishing campaigns targeting Microsoft Windows users. The group's primary motivation is espionage, not financial gain. Their methods involve phishing emails containing malicious OneNote files, which trigger the deployment of a Remote Access Trojan (RAT) with modular capabilities. Persistence is achieved through EXE files, and lateral movement is performed using tools like PsExec and WinRM.


### Key Details

- Target Platform: Microsoft Windows
- Threat Level: Critical
- Primary Motivation: Espionage
- Initial Access: Phishing emails
- Indicator of Compromise (IOCs):
    - OneNote Files:
        - `https://transfer.sh/get/kNxU7/invoice.one`
        - `https://mega.io/dl9o1Dz/invoice.one`
    - PowerShell Scripts:
        - `https://pastebin.com/raw/AvHtdKb2`
        - `https://pastebin.com/raw/gj58DKz`
    - Command and Control Nodes:
        - 91.90.213.14:443
        - 103.248.70.64:443
        - 141.98.6.59:443
    - Cryptographic Hashes of Involved Files (SHA256)

## Hunting Procedures

### Identifying Phishing Attempts

- Search for OneNote File Downloads: `event.code:15 AND file.name:*invoice.one`
  
  ![S1](https://github.com/user-attachments/assets/e6898228-9f37-468d-826b-71cedab02c5b)

- Verify Download Details: `event.code:11 AND file.name:invoice.one*`

  ![S2 ](https://github.com/user-attachments/assets/600b5396-1120-4f57-a3b5-ac3c310b344e)

### Trace the Source Machine

- Identify Host Details from the above query.
- Check Zeek Logs:
    - Filter DNS queries from the source IP 192.168.28.130:
    
      `source.ip:192.168.28.130 AND dns.question.name:*`
        
    - Identify major sources of noise and apply filter.

      ![S3](https://github.com/user-attachments/assets/3fcd8bcb-d9d5-442d-8ef8-bab5286a9c84)
  
### Analyze DNS queries

- Display only the `dns.question.name` field in the result table with time period specified from March 26th 2023 @ 22:05:00 to March 26th 2023 @ 22:05:48.

 ![S4](https://github.com/user-attachments/assets/4e4a2ed7-a072-4a78-8f8c-ad3c802fedcd)

- From this data, we infer that the user accessed Google Mail, followed by interaction with "file.io", a known hosting provider. Subsequently, Microsoft Defender SmartScreen initiated a file scan, typically triggered when a file is downloaded via Microsoft Edge. Expanding the log entry for file.io reveals the returned IP addresses (`dns.answers.data` or `dns.resolved_ip` or `zeek.dns.answers` fields) as: `34.197.10.85`, `3.213.216.16`

  ![S5 1](https://github.com/user-attachments/assets/e7ff0f54-3fdd-4260-92ee-1335cb55bb98)

  ![S5 2](https://github.com/user-attachments/assets/9d7ef6ad-e4b6-40d0-b9d3-4c15b5ba6e3f)

- Run a search for any connections to these IP addresses during the same timeframe as the DNS query.

  ![S6](https://github.com/user-attachments/assets/06d64245-52c1-452e-bc64-2b3a42f6d94b)

### Further analysis

- At this juncture, we have two choices: we can either cross-reference the data with the Threat Intel report to identify overlapping information within our environment, or we can conduct an Incident Response (IR)-like investigation to trace the sequence of events post the OneNote file download.

- Hypothetically, if "invoice.one" was accessed, it would be opened with the OneNote application. So, the following query will flag the event, if it transpired.

  `event.code:1 AND process.command_line:*invoice.one*`

  ![S7](https://github.com/user-attachments/assets/6b729bf8-9644-4bc8-9d36-3a69798048ba)

- Indeed, we find that the OneNote file was accessed shortly after its download, with a delay of roughly 6 seconds. Now, with OneNote.exe in operation and the file open, we can speculate that it either contains a malicious link or a malevolent file attachment. In either case, OneNote.exe will initiate either a browser or a malicious file. Therefore, we should scrutinize any new processes where OneNote.exe is the parent process.

  `event.code:1 AND process.parent.name:"ONENOTE.EXE"`

  ![S8](https://github.com/user-attachments/assets/f67ebc2b-8364-426c-aaf4-11acc2166075)


- The results of this query present three hits. However, one of these (the bottom one) falls outside the relevant time frame and can be dismissed. Evaluating the other two results:

    - The middle entry documents (when expanded) a new process OneNoteM.exe, which is a component of OneNote and assists in launching files.
    - The top entry reveals "cmd.exe" in operation, executing a file named "invoice.bat". Here is the view upon expanding the log.
    
      ![S9 1](https://github.com/user-attachments/assets/a4da1f29-d86e-4baf-8624-b3641ac28db0)

      ![S9 2](https://github.com/user-attachments/assets/0c8ef4d3-5f8b-4e68-9f04-02bce030a76c)


- Now we can establish a connection between "OneNote.exe", the suspicious "invoice.one", and the execution of "cmd.exe" that initiates "invoice.bat" from a temporary location (highly likely due to its attachment inside the OneNote file). The question now is, has this batch script instigated anything else? Let's search if a parent process with a command line argument pointing to the batch file has spawned any child processes with the following query.

  `event.code:1 AND process.parent.command_line:*invoice.bat*`

  ![S10](https://github.com/user-attachments/assets/63de9aa0-49c8-4f57-90d6-2efea0bcc46c)


- This query returns a single result: the initiation of PowerShell, and the arguments passed to it appear conspicuously suspicious (note that we have added `process.name`, `process.args`, and `process.pid` as columns)! A command to download and execute content from Pastebin, an open text hosting provider! We can try to access and see if the content, which the script attempted to download, is still available.

  ![S11](https://github.com/user-attachments/assets/49b4861d-45ff-4579-a821-eac62e41554e)

- This is referred to in the Threat Intelligence report, stating that a PowerShell Script from Pastebin was downloaded.

- To figure out what PowerShell did, we can filter based on the process ID and name to get an overview of activities. Note that we have added the `event.code` field as a column.

  `process.pid:"9944" and process.name:"powershell.exe"`

- Immediately, we can observe intriguing output indicating file creation, attempted network connections, and some DNS resolutions leverarging Sysmon Event ID 22 (DNSEvent). By adding some additional informative fields (`file.path`, `dns.question.name`, and `destination.ip`) as columns to that view, we can expand it.

  ![S12 1](https://github.com/user-attachments/assets/416b1271-fee7-43ea-a394-d138a0e1687b)

  ![S12 2](https://github.com/user-attachments/assets/f185eda5-062e-4ba5-8b33-86114a011338)

- Now, this presents us with rich data on the activities. Ngrok was likely employed as C2 (to mask malicious traffic to a known domain). If we examine the connections above the DNS resolution for Ngrok, it points to the destination IP Address 443, implying that the traffic was encrypted.

- Let's review Zeek data for information on the destination IP address `18.158.249.75` that we just discovered. Note that the `source.ip`, `destination.ip`, and `destination.port` fields were added as columns.

  ![S13](https://github.com/user-attachments/assets/cc71871c-30b5-46dd-b733-2946b4c5da5b)

- Intriguingly, the activity seems to have extended into the subsequent day. The reason for the termination of the activity is unclear... Was there a change in C2 IP? Or did the attack simply halt? Upon inspecting DNS queries for "ngrok.io", we find that the returned IP (`dns.answers.data`) has indeed altered. Note that the `dns.answers.data` field was added as a column.

  ![S14](https://github.com/user-attachments/assets/9e9ec735-6cc4-4edb-aeea-cf6ad8393d2b)

- The newly discovered IP also indicates that connections continued consistently over the following days.

- Thus, it's apparent that there is sustained network activity, and we can deduce that the C2 has been accessed continually. Now, as for the earlier uploaded executable file "default.exe" – did that ever execute? By probing the Sysmon logs for a process with that name, we can ascertain this. Note that the `process.name`, `process.args`, `event.code`, `file.path`, `destination.ip`, and `dns.question.name` fields were added as columns.
  
  `process.name:"default.exe"`

  ![image](https://github.com/user-attachments/assets/17a2288b-e48a-4721-a157-24dc61d83695)


- Indeed, it has been executed – we can instantly discern that the executable initiated DNS queries for Ngrok and established connections with the C2 IP addresses. It also uploaded two files "svchost.exe" and "SharpHound.exe". SharpHound is a recognized tool for diagramming Active Directory and identifying attack paths for escalation. As for svchost.exe, we're unsure – is it another malicious agent? The name implies it attempts to mimic the legitimate svchost file, which is part of the Windows Operating System.

- If we scroll up there's further activity from this executable, including the uploading of "payload.exe", a VBS file, and repeated uploads of "svchost.exe".

- At this juncture, we're left with one question: did SharpHound execute? Did the attacker acquire information about Active Directory? We can investigate this with the following query (since it was an on-disk executable file).

  `process.name:"SharpHound.exe"`

  ![S16](https://github.com/user-attachments/assets/4da894ff-fb8f-4f19-a903-377498d7de3a)

- Indeed, the tool appears to have been executed twice, roughly 2 minutes apart from each other.

- It's vital to note that Sysmon has flagged "default.exe" with a file hash (`process.hash.sha256` field) that aligns with one found in the Threat Intel report. This leads us to question whether this executable has been detected on other devices within the environment. Let's conduct a broad search. Note that the `host.hostname` field was added as a column.  

  `process.hash.sha256:018d37cbd3878258c29db3bc3f2988b6ae688843801b9abc28e6151141ab66d4`

  ![S17](https://github.com/user-attachments/assets/47dae32d-ebe5-45de-8813-170b32acf47b)

- Files with this hash value have been found on WS001 and PKI, indicating that the attacker has also breached the PKI server at a minimum. It also appears that a backdoor file has been placed under the profile of user "svc-sql1", suggesting that this user's account is likely compromised.

- Expanding the first instance of "default.exe" execution on PKI, we notice that the parent process was "PSEXESVC", a component of PSExec from SysInternals – a tool often used for executing commands remotely, frequently utilized for lateral movement in Active Directory breaches.

  ![S18 1](https://github.com/user-attachments/assets/0268c159-2f9d-488e-9275-f7ce477a097b)

  ![S18 2](https://github.com/user-attachments/assets/898438d5-dfa0-486e-b770-e136d77b976e)


- Further down the same log, we notice "svc-sql1" in the user.name field, thereby confirming the compromise of this user.

- How was the password of "svc-sql1" compromised? The only plausible explanation from the available data so far is potentially the earlier uploaded PowerShell script, seemingly designed for Password Bruteforcing. We know that this was uploaded on WS001, so we can check for any successful or failed password attempts from that machine, excluding those for Bob, the user of that machine (and the machine itself).

  `(event.code:4624 OR event.code:4625) AND winlog.event_data.LogonType:3 AND source.ip:192.168.28.130`

  ![S19](https://github.com/user-attachments/assets/53773f67-366b-4994-8529-c517aa97e579)

- The results are quite intriguing – two failed attempts for the administrator account, roughly around the time when the initial suspicious activity was detected. Subsequently, there were numerous successful logon attempts for "svc-sql1". It appears they attempted to crack the administrator's password but failed. However, two days later on the 28th, we observe successful attempts with svc-sql1.

## Conclusion

- At this stage, we have gathered substantial evidence indicating a significant security breach within our organization, centered around the malicious Stuxbot attack. The data reveals that attackers initially attempted to compromise an administrator account through brute-force methods but subsequently succeeded in breaching the "svc-sql1" account.

- The findings demonstrate a sophisticated attack involving phishing, file execution, and lateral movement within the network. The attackers leveraged a series of tactics, including credential theft and PowerShell-based attacks, to establish persistence and maintain control over compromised systems.

- To address this breach, we must implement immediate containment measures, including isolating the affected accounts and conducting a thorough forensic investigation to assess the full impact. Additionally, strengthening our security posture through enhanced monitoring, updated threat intelligence, and improved incident response procedures will be crucial in mitigating future risks.

- The incident response should be conducted in alignment with company policies, ensuring that all actions are documented and communicated effectively to stakeholders. This will facilitate a comprehensive understanding of the breach and support the development of strategies to prevent similar incidents in the future.
