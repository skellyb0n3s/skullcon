Note: Still being updating

# Offensive

## Tools
- **Sh3lldon** "A tool which bypasses AMSI (AntiMalware Scan Interface) and PowerShell CLM (Constrained Language Mode) and gives you a FullLanguage PowerShell reverse shell." `https://github.com/Sh3lldon/FullBypass`
- **smbclient-ng** "golang implementation of smbclient" `https://github.com/p0dalirius/smbclient-ng`
- **Chrome Katz** "Dump cookies directly from Chrome process memory" `https://github.com/Meckazin/ChromeKatz`
- **Frag Tunnel** "Fragtunnel is a PoC TCP tunneling tool" `https://github.com/efeali/fragtunnel?s=09`
- **Shellzor** "XOR shellcode framework - Windows, Linux" `https://github.com/vatsalgupta67/Shellzor`
- **Wapiti** "Web Vulnerability Scanner" `https://github.com/wapiti-scanner/wapiti?s=09`
## Tools (from the crypt)
## Infrastructure
## Tradecraft
* **Bring your own JAR** `https://red.0xbad53c.com/red-team-operations/initial-access/webshells/java-jsp-bring-your-own-jar`
* **BEEP APi for anti malware** `https://securityliterate.com/beeeeeeeeep-how-malware-uses-the-beep-winapi-function-for-anti-analysis/`
* **Im your domain admin** `https://decoder.cloud/2024/04/24/hello-im-your-domain-admin-and-i-want-to-authenticate-against-you/`
* **RtlCLone** `https://github.com/rbmm/RtlClone`
* **TheShelf** "Trusted Sec retired tools and pocs" `https://trustedsec.com/blog/introducing-the-shelf`
* **Byass ACL** "Bypass ACL for C:\Program Files\WindowsApp" `https://www.tiraniddo.dev/2024/06/working-your-way-around-acl.html`
  - what was interesting was this snippet "They use the same technique I describe in this blog post except they need a specific WIN://SYSAPPID, for example "MicrosoftWindows.Client.AIX_cw5n1h2txyewy". You can get a token for this attribute by opening the instance of AIXHost.exe, getting its token and using that to access the database files. Or, as the files are owned by the user you can just rewrite the DACLs for the files and gain access that way, no admin required"
  - windows app folder contains packaged applications; if you know the exact name you can view it
  - "his guess seems likely because if you know the name of the packaged application there's nothing stopping you listing it's contents, it's only the top level WindowsApps folder which is blocked"
  - turns out that although BUILTIN\Users group should get read and execute access, it only works if the WIN://SYSAPPID security attribute exists in the user's access token.
  - "There are various ways around this but the simplest is to start the process suspended, then use NtSetInformationProcess to swap the token to the one with the attribute. Setting the token after creation does not strip the attributes."

## Windows
* **AD CS** "ADCS " `https://hadess.io/pwning-the-domain-ad-cs/`
* **Perfect DLL Hijacking** "Description" `https://elliotonsecurity.com/perfect-dll-hijacking/`
* **SCCM CRED2 Misconfiguration** `https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-2/cred-2_description.md`
* **Guest vs Null Session** `https://sensepost.com/blog/2024/guest-vs-null-session-on-windows/`
  - Guest - relies on guest account; exists as local and domain account
  - Null - built-in group; Anonymous Logon group -> Pre-Windows 2000 Compatible Access would contain it
* **Windows Hardening** `https://github.com/HotCakeX/Harden-Windows-Security?s=09`

# Threat Intelligence 
* **QakBOT v5 Deep Malware Analysis** "Come Back To" `https://zw01f.github.io/malware%20analysis/qakbot/`
* **Understand hashing Algorithms** `https://fareedfauzi.github.io/2024/06/01/Hashing-Algo.html`
* **Menance Unleashed Excel Cobalt Dropper** "malicious Excel document themed around the Ukrainian military to deliver a multi-stage Cobalt Strike loader in 2023" `https://www.fortinet.com/blog/threat-research/menace-unleashed-excel-file-deploys-cobalt-strike-at-ukraine`
* **REMCOS CAT Campaign** `https://x.com/1ZRR4H/status/1798735303286685905`
* 
# CVEs
* **TELERIK #CVE-2024-4358 / #CVE-2024-1800** "Always test the :83 default port on servers, maybe there is Telerik Report Server, you can take advantage of the newly revealed vulnerability." `https://github.com/sinsinology/CVE-2024-4358`
* ** NETFILTER CVE-2024-1086** `https://arstechnica.com/security/2024/05/federal-agency-warns-critical-linux-vulnerability-being-actively-exploited/`

# Web Applications
* "XSS Payloads" `https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md`
* "Quick LFI Checker" `https://x.com/ott3rly/status/1798411966018408470`
```bash
cat targets.txt | (gau || hakrawler || katana || gospider) |  gf lfi |  httpx -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST  -tech-detect -status-code -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
```

# Windows
* **Building a DLL Verifier** "Description" `https://scorpiosoftware.net/2024/06/01/building-a-verifier-dll/`
  - The verifier infrastructure (part of verifier.dll) provides convenient facilities to hook functions.
  - As mentioned before, we can use the verifier engine’s support for hooking functions in arbitrary DLLs
* **APT Hunter** "APT-Hunter is Threat Hunting tool for windows event logs which made by purple team mindset to provide detect APT movements hidden in the sea of windows event logs to decrease the time to uncover suspicious activity" `https://github.com/ahmedkhlief/APT-Hunter`
* **Windows Recall** "Description" `https://doublepulsar.com/recall-stealing-everything-youve-ever-typed-or-viewed-on-your-own-windows-pc-is-now-possible-da3e12e9465e`
* **SEH AND VEH in perspective** "Description" `https://amunrha.github.io/posts/seh_veh_security_perspective/`
* **LDAPS Certificate Deepsive** `https://awakecoding.com/posts/active-directory-ldaps-certificate-selection-deep-dive/`
* **MS Recall sqlitedb** "Located at C:\Users\Username\appdata\local\microsoft\edge\user data\default\load_statistics.db"
* **Secure entra id alert and monitoring** `https://securediam.com/f/entra-id-monitoring-and-alerting---are-you-doing-the-basics`

# Linux 
* **Invsibility Cloak** `https://dfir.ch/posts/slash-proc/`
* **EDR Internals for MAC and LINUX** `https://www.outflank.nl/blog/2024/06/03/edr-internals-macos-linux/`

# EDRs
* Nothing reported
  
# Misc
* **Python for dark web osint monitoring** `https://medium.com/@ervin.zubic/python-for-dark-web-osint-automate-threat-monitoring-5994b63c4d4a`
* **Lesser Known quirks features of c** `https://jorenar.com/blog/less-known-c`
* **Rise of the agents** `https://blog.openthreatresearch.com/rise-of-the-planet-of-the-agents/`
* **Reflections on certificates part 2** `https://theinternetprotocolblog.wordpress.com/2023/02/12/reflections-on-certificates-part-2/`
* **Pentest Notes** `https://tzero86.gitbook.io/tzero86/scanning/running-scans-with-nmap?s=09`
* **Guide AWS Pentesting** `https://tzero86.gitbook.io/tzero86/scanning/running-scans-with-nmap?s=09`
