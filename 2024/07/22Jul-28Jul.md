Note: published Jul 30 

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
* **Specula** " TrustedSec is releasing Specula (our previously internal framework) for leveraging this simple Registry change into an initial access platform . This technique has been reported on before and despite that continues to be a weak point in many otherwise very well" `https://trustedsec.com/blog/specula-turning-outlook-into-a-c2-with-one-registry-change`
* **AirStrike** "This project is a Stage0 C2 that is highly customizable and can be used to create a template for your own C2 or to use it as a base for your own C2 agents." `https://github.com/smokeme/airstrike/`
* **Xenorat** " Xeno-RAT is an open-source remote access tool (RAT) developed in C# . Has features such as HVNC, live" `https://github.com/moom825/xeno-rat`
* **Variety of Cobalt tools** " Cobalt Strike is Cobalt" `https://github.com/REDMED-X/OperatorsKit`
* * **JS Tap** " Application penetration testers often create custom weaponized JavaScript payloads to demonstrate potential impact to clients . Documents are stolen, privileges escalated, or account transfers initiated . Red teams have opportunities to introduce malicious JavaScript beyond XSS vulnerabilities ." `https://trustedsec.com/blog/js-tap-weaponizing-javascript-for-red-teams`
* **Greatfon** " Greatfon lets you anonymously view profiles, stories, followers, and tags . Need to investigate an account on" `https://x.com/DailyOsint/status/1816093671017558227`


---

## Tools (from the crypt)


---
## Infrastructure

---
## Tradecraft
* **x64 shellcoding** " NASM source code is well documented and easy to read . Shellcode must work everywhere without any dependencies! Shellcode does not have access to functions we normally execute in C with a single line of code ." `https://print3m.github.io/blog/x64-winapi-shellcoding`
* **Injecting java in memory** " Back in March, we described tips that could be used when exploiting arbitrary deserialization on Java applications . This article will try to present a few other tricks that were used to inject an in-memory Java payload ." `https://www.synacktiv.com/publications/injecting-java-in-memory-payloads-for-post-exploitation`
* **Must have services and tools** " Some of my absolute must-have services/tools that I use daily: Tailscale: WireGuard-based private VPN (exit-nodes <3) Parsec: Ultra-fast, low-latency remote" `https://x.com/Flangvik/status/1816789795860877615`
* **Exploiting secrets in docker** " The secrets stored in docker images might be exploited in case that an attacker gets access to a private docker registry . Getting a docker image of a target may be the same as getting access to the target’s git or source code ." `https://medium.com/@red.whisperer/blind-spot-from-docker-registry-to-rce-b0d46e043798`
* **KDmapper** " kdmapper is a project that maps kernel mode drivers into the kernel . Instead of using some vulnerable driver, it uses PE images to bypass DSE ." `https://tulach.cc/detecting-manually-mapped-drivers/`
* **Recon Methodology** " In Depth Recon Methodology Bug Bounty Part 01 Om Arora . I write these posts to share what I’ve learned in a way that would have helped me when I was starting out . My goal is to make cybersecurity easier to" `https://omarora1603.medium.com/recon-is-important-in-depth-recon-methodology-bug-bounty-part-01-2b69c3b168fe`
* **40 methods priv esc** " for Linux,Mac,Windows" `https://www.linkedin.com/posts/richardjoneshacker_priv-ugcPost-7219710610228264963-vU59`
* **Oblivion Research** `https://oblivions-research.gitbook.io/`
* **Javascript in pdf** " The PDF standard allows for the execution of JavaScript code within the document . This feature offers various attack vectors that can be used for Red Team tests and cybersecurity research . In this article, we will examine how to inject JavaScript into a PDF file" `https://cti.monster/blog/2024/07/25/pdfdropper.html`


### Windows
* **Process Injection** " Process injection technique is not directly utilising VirtualProtect, VirtualAlloc, NtAllocateVirtualMemory and NtProtectVirtualMemory APIs inside the code . Exploit is using direct syscalls to bypass user-mode hooking" `https://www.linkedin.com/posts/usman-sikander13_%3F%3F%3F-%3F%3F%3F%3F%3F%3F-%3F%3F%3F%3F%3F-%3F%3F%3F-%3F%3F%3F%3F%3F%3F%3F%3F-ugcPost-7223665220416622592-s6wQ`
* **Abusing PIM** " The original idea was to write a single post documenting all PIM-related application permissions that could be abused to escalate to Global Admin . I quickly realized the final post would be too large to digest, so I decided to make a final" `https://www.emiliensocchi.io/abusing-pim-related-application-permissions-in-microsoft-graph-part-1/`
* **Callstack analysis** "  When stack gets corrupted, our target function of interest is invoked . This leads to context capture and stack unwinding followed by process termination ." `https://www.linkedin.com/posts/anandeshwar-unnikrishnan_daniel-feichter-hey-man-i-really-like-your-activity-7223772201857011712-_lPV`
* **MUIs** " Hash value of an executed application can save you a lot of time and effort in future cases . With the hash value, you can efficiently perform scoping within your environment or the incident area . It also allows you to identify the malware family" `https://www.linkedin.com/posts/muhammadtalaat_%D8%A7%D9%86%D8%AA-%D9%83%D8%A7-analyst-%D9%85%D9%85%D9%83%D9%86-%D8%AA%D8%AC%D8%B1%D8%A8-%D8%A7%D9%84%D9%85%D8%B9%D9%84%D9%88%D9%85%D8%A9-%D8%AF%D9%87-activity-7222903560542277632-JPkr`
* **In Memory Execution** " Malware often leverages this to inject malicious code into legitimate processes . We're particularly interested in the "[in] lpBuffer parameter", which is described as: A pointer to the buffer that contains data to be written in the address" `https://www.linkedin.com/posts/aleborges_reverseengineering-malwareanalysis-malware-activity-7221927545854652418-Fqzn`
* **QueueUserApc** " Process Injection (ShellCode) - QueueUserAPC (Asynchronous Procedure Call) on Windows involves threads having APC queues for functions that execute only under specific thread conditions . This method is stealthier than using CreateRemoteThread" `https://nirajkharel.com.np/posts/process-injection-shellcode-queuUserApc/`
* **Blog of an attack** " This blog explains how attackers after gaining credentials of a user can enumerate services the user is registered for, reading sensitive emails and moving laterally to dump data from customer database . For this demonstration I will be covering PwnedLabs" `https://chrollo-dll.gitbook.io/chrollo/security-blogs/cloud-pentesting/azure/pwned-labs-loot-exchange-teams-and-sharepoint-with-graphrunner`
* **How Process Hollowing works** " How process hollow" `https://x.com/ACEResponder/status/1815889487685186001`
* **Session takeover via pass the challenge** " Session Takeover via Pass the Challenge powered by  @m" `https://x.com/0x64616e/status/1816109595380560023`
* **Active Directory cheat sheet** " This cheat sheet contains common enumeration and attack methods for Windows Active Directory ." `https://github.com/drak3hft7/Cheat-Sheet---Active-Directory`
* **APCs** " Asynchronous Procedure Calls (APCs) in Windows are objects that can be attached to threads . Every thread has its own APC queue, where an APC stores a function and arguments to call . This is because the process this thread" `https://scorpiosoftware.net/2024/07/24/what-can-you-do-with-apcs/`
* **Handling the Handler** " "Red Team Tip - Handling the Handler for Process Injection" If you are developing a malware/loader that will be executed in-memory, you will need a host process to inject into . Process injection is heavily monitored by EDR" `https://www.linkedin.com/posts/0xhossam_redteam-malwares-evasion-activity-7222231570256973828-cIiq`
* **Pebwalk** " A legacy antivirus software was dependent on signature based detection . They calculate the hash of binary and see if this specific signature match with known malware signature in the database than mark the binary malicious or benign accordingly . To bypass hash based detection procedure" `https://medium.com/@merasor07/peb-walk-avoid-api-calls-inspection-in-iat-by-analyst-and-bypass-static-detection-of-1a2ef9bd4c94`


---
# Threat Intelligence 
* **Malware Analysis series** " Malware often leverages this to inject malicious code into legitimate processes . We're particularly interested in the "[in] lpBuffer parameter", which is described as: A pointer to the buffer that contains data to be written in the address" `https://www.linkedin.com/posts/aleborges_reverseengineering-malwareanalysis-malware-activity-7221927545854652418-Fqzn`
* **Brute Ratel Analysis** " Brute Ratel C4 (BRC4) is a customized, commercial command and control (C2) framework that was first introduced in December 2020 . Its primary use is for conducting adversarial attack simulation, red-team engagements" `https://any.run/cybersecurity-blog/brute-ratel-c4-analysis/`
* **Crowdstrike breach** " BreachForums member posted about a significant data breach involving CrowdStrike . The compromised data includes aliases, last active dates, status, origin, target industries, target countries, actor types, and motivations . CrowdStrike's entire IOC list," `https://x.com/FalconFeedsio/status/1816230348369387822`
* **Thread Name Calling** " Check Point Research (CPR) explains how the API for thread descriptions can be abused to bypass endpoint protection products . Process Injection is one of the important techniques in the attackers’ toolkit ." `https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/`
* **How i met your beacon** " How I Met Your Beacon (Part 3) : https://md.co.uk/2022/" `https://x.com/binitamshah/status/1816038365558628473`
* **Ghidra** " Ghidra offers the ability to automatically download symbols on your behalf . It takes some configuration, but it is really useful once you get going . The list of symbol servers is available as a config file in the build.pdburl" `https://medium.com/@clearbluejar/everyday-ghidra-symbols-automatic-symbol-acquisition-with-ghidra-part-2-bf9033a35b39`


---
# CVEs
* **RCE GIT** " A new RCE in Git caught my attention on a recent security feed, labeled CVE-2024-32002 . The idea of an RCE being triggered through a simple git clone command fascinated me . I wanted to see it wre" `https://amalmurali.me/posts/git-rce/`


---
# Web Applications
* **hacking s3 buckets** " A simple way to detect an S3 bucket is by examining the URLs associated with its files . When you encounter a file URL likehttps://<bucket-name>.s3-us-west-1.amazonaws.com" `https://medium.com/@qaafqasim/the-ultimate-guide-to-hack-s3-buckets-data-leaks-and-discovery-techniques-40a29641d18b`
* **XXE** " XXE (XML External Entity) is a security vulnerability stemming from improper handling of external entities within XML documents by an XML parser . This flaw arises when an attacker manipulates XML messages sent to an application, such as a web service" `https://www.optistream.io/blogs/tech/redteam-stories-1-soapy-xxe`

---
# Windows
* **Credential Guard** " Windows Defender Credential Guard is intended to safeguard both NTLM hashes and Kerberos tickets . For the purposes of this post, we will focus solely on NTLm hashes ." `https://research.ifcr.dk/pass-the-challenge-defeating-windows-defender-credential-guard-31a892eee22`
* **What are named pipes** " Named pipes are a mechanism for inter-process communication (IPC) in Windows operating systems . In Linux, we have two types of pipes: pipes (also known as anonymous or unnamed pipes) and FIFO’s (" `https://mthcht.medium.com/threat-hunting-suspicious-named-pipes-a4206e8a4bc8`
* **Print Nightmare** " “PrintNightmare” was the name given to a vulnerability in the Print Spooler service which could be exploited to achieve Remote Code Execution (RCE) or Local Privilege Escalation (LPE) on a" `https://itm4n.github.io/printnightmare-exploitation/`
* **SharpLDAP and SCCM** " If you're looking to replicate these attacks, we'd highly recommend looking at SharpSCCM and SharpLdapRelayScan" `https://x.com/domchell/status/1636014621071949827`


---
# Linux 
* **Linux ShellCoding** " Linux Shellcoding is a great way to learn more about assembly language and how a program interacts with the operating system . Shellcode is machine code that, when executed, opens a shell ." `https://sid4hack.medium.com/linux-shellcoding-9ce073353011`
* **Injection without ptrace** " The project has a simple premise: injecting code into a process without using ptrace . It uses /proc/mem to write code directly into memory, allowing running threads to pick up the code and execute it ." `https://erfur.dev/blog/dev/code-injection-without-ptrace`

---
# MAC

---
# EDRs
* **Blocking EDRS** "You can block EDR telemetry reaching its cloud servers by performing a Person-in-the-Middle (PitM) attack and filtering telemetry packets, effectively hiding alerts from the SOC team. This can be achieved by conducting ARP poisoning against target host(s) and configuring iptables. Instead of blocking a wide range of IP subnets, we can use Server Name Indication (SNI) in the TLS Client Hello packets to identify specific IP addresses to block. While unsent alerts get cached on the host, they are cleared upon reboot." `https://tierzerosecurity.co.nz/2024/07/23/edr-telemetry-blocker.html`
* **What is an edr** " EDR (Endpoint Detection and Response) is a kind of security products that aims at detecting abnormal activities being executed on a computer or server . This article aims at demystigying how EDR’s work building a" `https://blog.whiteflag.io/blog/from-windows-drivers-to-a-almost-fully-working-edr/`


---
# Misc
* **Writing a C Compilier** " Writing a C Compiler will take you step by step through the process of building your own . No prior experience with compiler construction or assembly code needed . The algorithms in the book are all in pseudocode, so you can implement your" `https://nostarch.com/writing-c-compiler`
* **Leaking user's drive files** " Google Classroom allows you to gain access to someone else's Google Drive files without being granted access to it . The issue is now fixed and Google VRP gave a nice bounty for it ." `https://secreltyhiddenwriteups.blogspot.com/2024/07/leaking-all-users-google-drive-files.html`
* **Compilier hardening options** " Compiler Options Hardening Guide for C and C++ . Compiler options hardening guide by Open Source Security Foundation Best Practices Working Group ." `https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html`
* **LVM** " We revived llvmcpy, our Python wrappers for LLVM! We exploit the native LLVM libraries . Support for Python from 3.7 to 3.13 to" `https://x.com/_revng/status/1816473487634280935`
* **OLAMA** " Running Llama 3.1 locally as a code assistant in VSCode with Ollama (http://ollama.com) Running" `https://x.com/dani_avila7/status/1816142424801992947`
* **Data Science for red team** " The ADCS is highly leveraged to speed up the domain compromise through the set of ESCXX vulnerabilities . The CICD infrastructures are exploited to easily rebound on the internal network . The typology of applications in each category" `https://www.riskinsight-wavestone.com/en/2024/07/datascience-for-redteam-extend-your-attack-surface/`


