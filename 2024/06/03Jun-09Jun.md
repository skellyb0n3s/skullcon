Note: Published June 7th
                                                                                                                 
```                                                                                            :                    
        .,                             ,;                                    ,;      .,    t#,     L.            
       ,Wt           .               f#i j.               j.               f#i      ,Wt   ;##W.    EW:        ,ft
      i#D.f.     ;WE.Ef.           .E#t  EW,              EW,            .E#t      i#D.  :#L:WE    E##;       t#E
     f#f  E#,   i#G  E#Wi         i#W,   E##j             E##j          i#W,      f#f   .KG  ,#D   E###t      t#E
   .D#i   E#t  f#f   E#K#D:      L#D.    E###D.           E###D.       L#D.     .D#i    EE    ;#f  E#fE#f     t#E
  :KW,    E#t G#i    E#t,E#f.  :K#Wfff;  E#jG#W;          E#jG#W;    :K#Wfff;  :KW,    f#.     t#i E#t D#G    t#E
  t#f     E#jEW,     E#WEE##Wt i##WLLLLt E#t t##f         E#t t##f   i##WLLLLt t#f     :#G     GK  E#t  f#E.  t#E
   ;#G    E##E.      E##Ei;;;;. .E#L     E#t  :K#E:       E#t  :K#E:  .E#L      ;#G     ;#L   LW.  E#t   t#K: t#E
    :KE.  E#G        E#DWWt       f#E:   E#KDDDD###i      E#KDDDD###i   f#E:     :KE.    t#f f#:   E#t    ;#W,t#E
     .DW: E#t        E#t f#K;      ,WW;  E#f,t#Wi,,,      E#f,t#Wi,,,    ,WW;     .DW:    f#D#;    E#t     :K#D#E
       L#,E#t        E#Dfff##E,     .D#; E#t  ;#W:        E#t  ;#W:       .D#;      L#,    G#t     E#t      .E##E
        jtEE.        jLLLLLLLLL;      tt DWi   ,KK:       DWi   ,KK:        tt       jt     t      ..         G#E
          t                                                                                                    fE
                                                                                                                ,
```
# Offensive

## Tools
- **Sh3lldon** "A tool which bypasses AMSI (AntiMalware Scan Interface) and PowerShell CLM (Constrained Language Mode) and gives you a FullLanguage PowerShell reverse shell." `https://github.com/Sh3lldon/FullBypass`
- **smbclient-ng** "golang implementation of smbclient" `https://github.com/p0dalirius/smbclient-ng`
- **Chrome Katz** "Dump cookies directly from Chrome process memory" `https://github.com/Meckazin/ChromeKatz`
- **Frag Tunnel** "Fragtunnel is a PoC TCP tunneling tool" `https://github.com/efeali/fragtunnel?s=09`
- **Shellzor** "XOR shellcode framework - Windows, Linux" `https://github.com/vatsalgupta67/Shellzor`
- **Wapiti** "Web Vulnerability Scanner" `https://github.com/wapiti-scanner/wapiti?s=09`
- **Proxy DLL Load** "Using undocumented syscalls?" `https://github.com/kleiton0x00/Proxy-DLL-Loads/tree/cfg-bypass`
- **MDE Enum** `https://github.com/0xsp-SRD/MDE_Enum`
- **Aleph** "allows you to index large documents" `https://github.com/alephdata/aleph`
- **Phone tracker** "track phone?" `https://github.com/HunxByts/GhostTrack?s=09`
- **OSINT Framework** `https://github.com/AnonCatalyst/Coeus-Framework`
  
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
* **SYSTEM Parent Impersonation** "impersonate via parent; requires sedebug" `https://decoder.cloud/2018/02/02/getting-system/`
* **Read ASR Rules** `https://x.com/I_Am_Jakoby/status/1797670291025637645`
* **Understanding Malware Patching** `https://medium.com/phrozen/understanding-malware-patching-resources-81650bb6190d`
* **Phishing like a pro** `https://fortbridge.co.uk/research/add-spf-dmarc-dkim-mx-records-evilginx/?s=09`
* **Swapalla** "Sleep Technique" `https://oldboy21.github.io/posts/2024/06/sleaping-issues-swappala-and-reflective-dll-friends-forever/?s=09`
* **Opsec tradecraft** `https://github.com/WesleyWong420/OPSEC-Tradecraft`
* **The CP Command** `https://x.com/xmodulo/status/1798686601460986088`

### Windows
* **AD CS** "ADCS " `https://hadess.io/pwning-the-domain-ad-cs/`
* **Perfect DLL Hijacking** "Description" `https://elliotonsecurity.com/perfect-dll-hijacking/`
* **SCCM CRED2 Misconfiguration** `https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-2/cred-2_description.md`
* **Guest vs Null Session** `https://sensepost.com/blog/2024/guest-vs-null-session-on-windows/`
  - Guest - relies on guest account; exists as local and domain account
  - Null - built-in group; Anonymous Logon group -> Pre-Windows 2000 Compatible Access would contain it
* **Windows Hardening** `https://github.com/HotCakeX/Harden-Windows-Security?s=09`
* **Schedule Task Tampering** "Hafnium ttp" `https://ipurple.team/2024/01/03/scheduled-task-tampering/?s=09`
* **SMB Cheatsheet** `https://0xdf.gitlab.io/2024/03/21/smb-cheat-sheet.html?s=09`
* **Get Password Policies** `https://www.login-securite.com/2024/06/03/spray-passwords-avoid-lockouts`
* **Bypass defender ppl lsass dump protection** `https://tastypepperoni.medium.com/bypassing-defenders-lsass-dump-detection-and-ppl-protection-in-go-7dd85d9a32e6`
* **ESC14** `https://x.com/BlWasp_/status/1798254119075090908`
* **Shadow Credentials** `https://www.fortalicesolutions.com/posts/shadow-credentials-workstation-takeover-edition`
* **Breaking through defender's gates** `https://www.alteredsecurity.com/post/disabling-tamper-protection-and-other-defender-mde-components`

# Threat Intelligence 
* **QakBOT v5 Deep Malware Analysis** "Come Back To" `https://zw01f.github.io/malware%20analysis/qakbot/`
* **Understand hashing Algorithms** `https://fareedfauzi.github.io/2024/06/01/Hashing-Algo.html`
* **Menance Unleashed Excel Cobalt Dropper** "malicious Excel document themed around the Ukrainian military to deliver a multi-stage Cobalt Strike loader in 2023" `https://www.fortinet.com/blog/threat-research/menace-unleashed-excel-file-deploys-cobalt-strike-at-ukraine`
* **REMCOS CAT Campaign** `https://x.com/1ZRR4H/status/1798735303286685905`
* **Scanning Phish Sites** `https://checkphish.bolster.ai/?s=09`
* **Agent Tesla Analysis** `https://0xmrmagnezi.github.io/malware%20analysis/AgentTesla/`
* **Analysis Kimsuky** `https://www.genians.co.kr/blog/threat_intelligence/interview`
* **Forest Blizzard** `https://github.com/blackorbird/APT_REPORT/blob/master/APT28/logpoint-etpr-forest-blizzard.pdf?s=09`
* **Crimson Palace** `https://news.sophos.com/en-us/2024/06/05/operation-crimson-palace-a-technical-deep-dive/`

# CVEs
* **TELERIK #CVE-2024-4358 / #CVE-2024-1800** "Always test the :83 default port on servers, maybe there is Telerik Report Server, you can take advantage of the newly revealed vulnerability." `https://github.com/sinsinology/CVE-2024-4358`
* ** NETFILTER CVE-2024-1086** `https://arstechnica.com/security/2024/05/federal-agency-warns-critical-linux-vulnerability-being-actively-exploited/`
* **CVE 2024-4577 php cgi** `https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/?s=09`

# Web Applications
* "XSS Payloads" `https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md`
* "Quick LFI Checker" `https://x.com/ott3rly/status/1798411966018408470`
```bash
cat targets.txt | (gau || hakrawler || katana || gospider) |  gf lfi |  httpx -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST  -tech-detect -status-code -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
```
* **SSRF Bypass** `https://x.com/RootMoksha/status/1797821225819148786`
* **SVG file upload** `https://x.com/RootMoksha/status/1798709502956785973`
* **Advanced javascript injections** `https://brutelogic.com.br/blog/advanced-javascript-injections/?s=09`

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
* **Windows Rootkit Guide** "Summarizes information on rootkit techniques" `https://artemonsecurity.blogspot.com/2024/06/windows-rootkits-guide.html?m=1&s=09`
* **Windows Memory Internals** "Concepts relevant to both blue/red teams" `https://azr43lkn1ght.github.io/Malware%20Development,%20Analysis%20and%20DFIR%20Series%20-%20Part%20III/?s=09`
* **Active Directory Canaries** "Setting up canaries for AD" `https://github.com/AirbusProtect/AD-Canaries?s=09`
* **Windows Recall 2** `https://x.com/tiraniddo/status/1798461595565347164?s=09`
* **Disable Recall** `https://x.com/0x6d69636b/status/1798390805180379206?s=09`
* **NTLM Deprecated in Server 2025** `https://x.com/NerdPyle/status/1797689291642147032`

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
* **Rust Malware Stuff** `https://github.com/BlackSnufkin/Rusty-Playground/tree/main`
