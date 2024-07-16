Note: published Jul 16 

Searchbot v1 results


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
* **BlueSpy** " PoC to record audio" `https://github.com/TarlogicSecurity/BlueSpy`
* **IAT Tracer** " A new version of the cool #TinyTracer helper is out! IAT-Tracer makes tracing functions arguments much easier . It can autogener" `https://x.com/hasherezade/status/1810007445001155015`
* **Dictofuscation** "Obfuscate the bytes of your payload with an association dictionary" `https://github.com/ProcessusT/Dictofuscation`
* **Parth** "Hueristic parameter scanner"`https://github.com/s0md3v/Parth`
* **RDPStrike** "Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP." `https://github.com/0xEr3bus/RdpStrike`
* **ecapture** "Capturing SSL/TLS plaintext without a CA certificate using eBPF. Supported on Linux/Android kernels for amd64/arm64" `https://github.com/gojue/ecapture`
* **hayabusa** " Hayabusa is a sigma-based threat hunting and fast" `https://github.com/Yamato-Security/hayabusa`
* **Bypass UAC** " Sliver extension to bypass UAC" `https://github.com/0xb11a1/sliver_extension_uac_bypass_cmstp`
* **DLL Dragon** " DllDragon is a utility for dynamically loading functions from Windows DLLs (Dynamic Link Libraries) at runtime. It allows you to load a DLL module and retrieve the address of a specific function within that module, without having to link the DLL statically or load it manually." `https://github.com/a7t0fwa7/DllDragon`
* **RunPE** " RunPE adapted for x64 and written in C, does not use RWX. Based on the original RunPE at https://github.com/Zer0Mem0ry/RunPE. Mostly because too many RunPE implementations use RWX, is terrible for evasion." `https://github.com/fern89/runpe-x64`
* **10 years of potatos** https://github.com/decoder-it/Troopers24/
---

## Tools (from the crypt)
* **Compilation of tools** " All-in-One Hacking Tools" `https://github.com/mishakorzik/AllHackingTools`
* **ETW Listicle** " List the ETW provider(s)" `https://github.com/whokilleddb/ETWListicle`
* **?? Disable driver??** `https://gist.github.com/OlivierLaflamme/2e0670718a904f21b03cb753df02cf67#file-driver_to_disable_be_process_thread_object_callbacks-L38`                             

---
## Infrastructure
* **AWS Firewall** " AWS Network Firewall Rule Group paired with Lambda function to perform steps ." `https://github.com/aws-samples/aws-network-firewall-automation-examples`
* **SSRF in havoc** " Unauthenticated attackers could create a TCP socket on the teamserver with an arbitrary IP/port . By exploiting this vulnerability, attackers could leak the origin IP of a teamserver behind public redirectors and abuse vulnerable teamservers as a" `https://blog.chebuya.com/posts/server-side-request-forgery-on-havoc-c2/`


---
## Tradecraft
* **Alt method hooking dllmain** " Want to hook application entry point from DllMain with just a pointer swap?  You can replace the RtlUserThreadStart" `https://x.com/mrexodia/status/1809936086400938187`
* **Alt method obtaining bootkey** " Remote LSA secrets dumping works and retrieves a Windows computer's BOOTKEY using less common methods . Decorrelate attack tool behaviour" `https://sensepost.com/blog/2024/dumping-lsa-secrets-a-story-about-task-decorrelation/`
* **CHM Stealer** " An Info Stealer CHM File Evaded All the AV Solutions . The initial malicious script was obfuscated by obfuscating CMD command in CHM file . The report was created by CamScanner 10-07-2024 10" `https://x.com/doc_guard/status/1812141457655976164`
* **Overview Shellcode Injection** " Shellcode injection in a process refers to injecting portable executable (PE) code into the virtual address space of the running process and then executing it via a new thread . The flowchart below describes the process that should be followed during the injection" `https://nirajkharel.com.np/posts/process-injection-shellcode/`

### Windows
* **SeRelabel Privilege** " In a recent assessment, it was found that a specific Group Poilcy granted via “User Right Assignments” the SeRelabelPrivilege to the built-in Users group and was applied on several computer accounts ." `https://decoder.cloud/2024/05/30/abusing-the-serelabelprivilege/`
* **Have something in program files** " Anyone who has any software or databases installed on anything other than the c:\program files, go  run privesccheck.ps1 by itm4" `https://x.com/EricaZelic/status/1810821014550454471`
* **Hiding evil code in folders** " "Hiding in Plain Sight" is a "fileless" storage solution . It's no surprise that AV software examines files, but what about folders? The TL;DR at the end of this post explains how it all ends ." `https://t.co/eJkBQ4SQX8`
* **Silent way installing Chrome Extension** " A way to silently install a Chrome extension avoiding the “common” IOC’s attackers use today . The extension can be installed while in use but it wont re-load until chrome restarts ." `https://syntax-err0r.github.io/Silently_Install_Chrome_Extension.html`
* **Kernel exploitation primitives** " In this blog, our focus is on understanding and utilizing multiple kernel heap exploitation primitives to build an effective exploit. By spending additional effort into finding a read primitive after finding a write primitive, we have opened up additional avenues for exploitation." `https://northwave-cybersecurity.com/exploiting-enterprise-backup-software-for-privilege-escalation-part-two`

---
# Threat Intelligence 
* **Sharepoint phishing** " In just the last 24 hours, our service has seen over 500 public sandbox sessions with SharePoint phishing! This campaign is very dangerous because it looks trustworthy at every step . It uses the legitimate SharePoint service for hosting phishing PDF" `https://x.com/anyrun_app/status/1811405911820218803`
* **Osint China Course** " Module 4 - Fusion Intelligence - Explore unconventional information gathering methods, tools, strategies that are not typically practiced by the average intelligence or OSINT professionals for OSINT in China ." `https://epcyber.com/osint-china-advanced`
* **Supply Chain from North Korean APT** " Phylum has been exposing North Korean threat actors attacking software developers in the open-source supply chain . This blog post highlights evolving tactics from a North Korean campaign that began September 2023 ." `https://blog.phylum.io/new-tactics-from-a-familiar-threat/`
* **DateGate** " DarkGate malware-as-a-service (MaaS) operation shifts away from AutoIt scripts to an AutoHotkey mechanism to deliver the last stages . The updates have been observed in version 6 of DarkGate released in March" `https://thehackernews.com/2024/06/darkgate-malware-replaces-autoit-with.html`
* **callstack spoofing** `https://www.zscaler.com/blogs/security-research/dodgebox-deep-dive-updated-arsenal-apt41-part-1`
* **NoodleRat** " Since 2018, multiple reports have been published about attacks involving Noodle RAT . The ELF backdoor was inadvertently identified as different malware families . We uncovered in VirusTotal a couple of command-and-control (C&C) panels" `https://www.trendmicro.com/en_us/research/24/f/noodle-rat-reviewing-the-new-backdoor-used-by-chinese-speaking-g.html`
* **URLDNA** " URLDNA is a website analysis tool that offers detailed insight into URLs by collecting screenshots, SSL certificates, technologies, and more" `https://x.com/DailyOsint/status/1811007470074057127`

---
# CVEs
* **CVE-2024-6387** " The Wild West of Proof of Concept Exploit Code (PoC) The 1990s and early 2000s were a tumultuous time in the world of cybersecurity . Numerous hacking groups emerged, discovering vulnerabilities and releasing exploit code ." `https://santandersecurityresearch.github.io/blog/sshing_the_masses`

---
# Web Applications
* **Account Takeover** " How I Got Easy Account Take Over? How I got easy account take over? I got a lot of urls that have a parameter leaks the email and password of the users . #BugBounty #bugbountytips ." `https://x.com/Sayed_v2/status/1810385795703861557`
* **Bypass rate limiting** `https://x.com/Mane0090/status/1809999665288688040`
* **SqlMap Customization** " There are many ways people usually customize SQLmap like using extra headers, random user agents, tampering scripts, or delays between requests . Fine-tuning those options could sometimes help to fuzz specific endpoints or avoid Web Application Firewall rules" `https://ott3rly.com/advanced-sqlmap-customization/`
                        
---
# Windows
* **Sysmon - viable alt to edr** " This is a recurring topic in workshops with clients from completely different industries/verticals . I'm not talking about forensics or any post-incident use case, I'm talking about leveraging Sysmon's log telemetry for building" `https://detect.fyi/sysmon-a-viable-alternative-to-edr-44d4fbe5735a`
* **Anti debugging measures** " This week I took a break from SYSTEM chasing to review some anti-debugging techniques . With quite a few Bug Bounty programs available relying on client-side applications, I thought I’d share one of the techniques used by numerous" `https://blog.xpnsec.com/anti-debug-openprocess/`
* **Enable AD Recycle bin** " When you install Active Directory (AD DS role) and promote the server to a Domain Controller, the Active Directory Recycle Bin is not enabled by default . This should be a must, unfortunately, it is not baked into the deployment ." `https://www.alitajran.com/enable-active-directory-recycle-bin/`
* **Common Mistakes Defender Endpoint** " Microsoft Defender for Endpoint (MDE) is part of Microsoft Defender XDR and can be deployed via multiple configurations . MDE is the logical grouping of the following items:TVM (Threat Vulnerability Management) (EDR" `https://jeffreyappel.nl/common-mistakes-during-microsoft-defender-for-endpoint-deployments/`
* **ASR Blocking Teams** " ASR blocks for ms-teams.exe - users trying to join meetings from outlook and being blocked by Block Office communication applications from creating child processes ." `https://x.com/pjrouse/status/1810621731456917992`

---
# Linux 
* **Methods priv esc** "Methods for Privilege Escalation (Linux/Windows/macOS) have been created ." `https://x.com/Hadess_security/status/1811432018414334126`
* **Process NAme Stomping** " This post explores the defence evasion technique of dynamically modifying process names in UNIX-like systems . First observed as far back as the late '80s, the technique is certainly alive and well today ." `https://doubleagent.net/process-name-stomping/`


---
# MAC

---
# EDRs
* **Borrow Legitimate Driver** " Ziyi Shen shares a technique that can be used to evade EDR products . The principle behind the technique is neither groundbreaking nor complex . Instead, it exploits oversights in detection mechanisms ." `https://www.3nailsinfosec.com/post/edrprison-borrow-a-legitimate-driver-to-mute-edr-agent`
  
---
# Misc
* **Memprocfs** `https://github.com/ufrisk/MemProcFS`
* **Automatedlab** " AutomatedLab (AL) enables you to set up lab and test environments on Hyper-v or Azure with multiple products . The system needs to meet the following requirements: Intel VT-x or AMD/V capable CPU A generous amount" `http://automatedlab.org`
* **NTLM to PW** `http://ntlm.pw`
* **Heap Exploitation Series** `https://x.com/0xor0ne/status/1811053045699985833`
* **Top 50 search engines** " StationX résume très bien les principaux domaines de la cybersécurité qu’on retrouve en entreprise . Voici un aperçu des objectifs de cha" `https://www.linkedin.com/posts/khalilb_cybersaezcuritaez-activity-7217807517207138305-ODfY`
* **Introduction Virtualization** "In this article we’re going to introduce virtualization, the various forms of virtualization, terminology, and a high level view of the abstraction that is virtualization. We’ll also be building out a test function for support of virtual machine instructions, followed by defining structures to represent various architectural registers and components." `https://revers.engineering/day-1-introduction-to-virtualization/`
* **Reverse engineering protobuf binaries** " A few years ago I released protodump, a CLI for extracting full source protobuf definitions from compiled binaries . This can come in handy if you’re trying to reverse engineer an API used by a closed source binary ." `https://arkadiyt.com/2024/03/03/reverse-engineering-protobuf-definitiions-from-compiled-binaries/`
