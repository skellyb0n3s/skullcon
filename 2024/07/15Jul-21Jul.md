Note: published Jul 22 

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
* **Mythic 3.3** " Mythic 3.3 is going into a public Beta phase for a few weeks first . To use this Mythic and any updated agents/profiles, be sure to use the Mythic3.3 branches . The following projects are" `https://ghst.ly/462EUYz`
* **NoConsolidation** " With NoConsolation you can now custom load all the dependencies from the PE you are going to execute" `https://x.com/s4ntiago_p/status/1813338676547723542`
* **Polyhook 2.0** " C++" `https://github.com/stevemk14ebr/PolyHook_2_0`
* **Ad Explorer Snapshot** " There have been a ton of performance improvements, edges added, and usability improvements since the quoted tweet . I'm really excited for people to start using and breaking it ." `https://x.com/0xdab0/status/1814784712289730906`


---

## Tools (from the crypt)


---
## Infrastructure

---
## Tradecraft
* **Sharphound detection** " BloodHound is an attack path management solution which can discover hidden relationships in Active Directory by performing data analysis to identify paths in the domain that will lead to lateral movement and domain escalation . SharpHound has been developed in C# and" `https://ipurple.team/2024/07/15/sharphound-detection/`
* **Different process injection technique** " Process injection technique is not directly utilising VirtualProtect, VirtualAlloc, NtAllocateVirtualMemory and NtProtectVirtualMemory APIs inside the code . Exploit is using direct syscalls to bypass user-mode hooking" `https://www.linkedin.com/posts/usman-sikander13_github-offensive-pandawpm-majic-entry-point-injection-activity-7219623276493385729-zUvk`



### Windows
* **Process Injection Died** " Process Injection is Dead. Long Live IHxHelpPaneServer CICADA8 . Cross-Session Activation allows attackers to execute code in the context of another user ." `https://cicada-8.medium.com/process-injection-is-dead-long-live-ihxhelppaneserver-af8f20431b5d`
* **PEB Walk** " The PEB contains the information about loaded modules (malware’s interests: kernel32.dll and ntdll.dll ) that have been mapped into process space . Shellcode often uses this PEB walk to reconstruct the" `https://fareedfauzi.github.io/2024/07/13/PEB-Walk.html`
* **Session Enumeration** " qwinsta leverages Windows API functions in order to retrieve session information from a host . It is also possible to remotely enumerate user sessions via the /server:{hostname} parameter ." `https://0xv1n.github.io/posts/sessionenumeration/`
* **What is VEH** " Vectored Exception Handling is a built-in Windows mechanism that allows an application to catch and handle exceptions with a custom handler function before SEH is called . VEH s are global to an application, unlike SEH that is coupled" `https://mannyfreddy.gitbook.io/ya-boy-manny`
* **kerberos ticket event ids** " Kerberos Request/Response ticket hashes are being included in EIDs 4768/" `https://x.com/4ndr3w6S/status/1813296329852088351`
* **Compilation of different lsass dumping techniques** " Windows LSASS process is crucial for managing security policies and storing security credentials . The "LSASS dump" technique involves the use of direct system calls, or "direct syscalls" These instructions take us to the famous low level or" `https://www.linkedin.com/posts/joas-antonio-dos-santos_redteam-redteamexercises-informationsecurity-activity-7220958774251913216-aOYp`
* **Process protections** " process protections" `https://x.com/jamieantisocial/status/1812979610428318010`
* **Process Hollowing Technique** " Hollow Process Injection is a stealthy technique used by malware to execute malicious code within the address space of a legitimate process . It involves creating a benign process in a suspended state, removing its executable code, injecting malicious code, altering the" `https://www.darkrelay.com/post/demystifying-hollow-process-injection`
* **Direct vs indirect syscalls** " Red Team Exercises #14 - Direct and Indirect Syscall . Direct syscall implements system call instructions directly in the malware code . Indirect sycall partially uses ntdll.dll, jumping to legitimate sysc" `https://www.linkedin.com/posts/joas-antonio-dos-santos_redteam-cybersecurity-syscall-ugcPost-7218437409443618816-aN9b`
* **Exploring winsxs** "This post explores Windows Side-by-Side (WinSxS) and DLL hijacking, deep-diving some tooling I've written and some of the fun along the way." `https://blog.zsec.uk/hellojackhunter-exploring-winsxs/`



---
# Threat Intelligence 
* **Rada Malware Analysis** " The first stage contained a relatively short PowerShell script that was somewhat obfuscated . After cleaning up the code and deobfuscating it, we were left with clear code . The first URL downloads a PDF and opens it, while the second" `https://0xmrmagnezi.github.io/malware%20analysis/Rhadamanthys/`
* **More Kimsuky Anslysis** " Kimsuky APT is a North Korea-based cyber espionage group operating since at least 2012 . Initially, The group targeted South Korean government entities, think tanks, and individuals identified as experts in various fields . They have developed unique malware" `https://darkatlas.io/blog/kimsuky-apt-the-trollagent-stealer-analysis`
* **Dogebox** " Read our two-part blog series about the latest updates to the arsenal of #APT41 . DodgeBox - A heavily updated variant of StealthVector - A slightly modified version of Stealth Vector (2024) MoonWalk backdoor loaded by" `https://x.com/SinghSoodeep/status/1812205686169727124`
* **Tracking Lazarus Group** " How to use Validin's DNS history and host responses to track the Lazarus Group . North Korean state-sponsored cyber threat group (APT38) responsible for Sony Pictures Entertainment cyber-attack ." `https://www.validin.com/blog/hunting-lazarus-dns-history-host-responses/`
* **Void Banshee** " APT Group Void Banshee + Microsoft 0" `https://x.com/blackorbird/status/1813506977919848720`
* **Malicious MSC files** " Malicious MSC files are starting to trend as a initial access method . It has huge phishing potential and here are some reasons why . It can be complex to build MSC payloads as the XML format is not public ." `https://www.linkedin.com/posts/emeric-nasi-84950528_after-a-few-attacks-targeting-east-asia-countries-activity-7219732971027628034-Gv9A`
* **Spammers evasion via html smuggling** " Attackers are starting to use spear phishing tactics in bulk phishing campaigns . Spammers are using spear-phishing tactics" `https://x.com/blackorbird/status/1812749858832629938`


---
# CVEs

---
# Web Applications
* **Injecting javascript** " Attackers may leverage the ISO-2022-JP character encoding to inject arbitrary JavaScript code into a website . XSS on any website with missing charset" `https://x.com/Sonar_Research/status/1812864424807444825`


---
# Windows
* **ADCS** " Active Directory Certificate Services (AD CS) is a Microsoft Windows server role that provides a public key infrastructure (PKI) It allows you to create, manage, and distribute digital certificates ." `https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-certificate-services/`
* **Defender Signature by Category** " For those collecting Defender logs, I extracted all of the existing Defender signatures by category . Can be useful for including or excluding specific categories in your detections ." `https://x.com/mthcht/status/1813690813202792757`
* **Windbg extensions** " WinDbg extension and PoCs" `https://github.com/daem0nc0re/PrivFu`
* **ADCS Lab Exploitation Notes** " No about section found" `https://github.com/myexploit/LAB/blob/master/Active_Directory_Certificate_Service_ADCS.md`
* **Reverse engineering series** " Software Reverse Engineering: Diffusing Phase 4 on Windows platform using Windbg . We see sscanf() call exactly the same way as in phase_3() . We’ll be following an initial approach similar to previous phase ." `https://compilepeace.medium.com/software-reverse-engineering-diffusing-phase-4-4112619ac2b4`


---
# Linux 
* **Crafting a peaceful parasite** " Two Part series "`https://x.com/binitamshah/status/1812778748674183498`
* **Syzkaller** " This article covers my experience with fuzzing the Linux kernel externally over the network . I’ll explain how I extended a kernel fuzzer called syzkaller for this purpose and show off the found bugs . The article also" `https://xairy.io/articles/syzkaller-external-network`

---
# MAC

---
# EDRs


---
# Misc
* **ProxMark3** " Proxmark3 is a powerful general purpose RFID tool, the size of a deck of cards, designed to snoop, listen and emulate everything from Low Frequency (125kHz) to High Frequency (13.56MHz)" `https://x.com/binitamshah/status/1812495036564824251`
* **HTB Corporate Walkthrough** " Corporate is an epic box, with a lot of really neat technologies along the way . I’ll start with a very complicated XSS attack that must utilize two HTML injections and an injection into dynamic JavaScript to bypass a content security policy" `https://0xdf.gitlab.io/2024/07/13/htb-corporate.html`
* **Phantom Vulnhub Walkthrough** " Phantom is a medium-difficulty AD machine from " `https://x.com/seriotonctf/status/1812447969926394006`
* **Internals of virtualization** " Series on virtualization and internals of various solutions (QEMU, Xen and VMWare) Series on" `https://x.com/0xor0ne/status/1813106342153847025`
* **Random insight** " The strangest thing from all this is people being worried attackers might know what EDR product a company runs . Outside of Endgame I’m not sure any EDR products tried to hide their existence ." `https://x.com/HackingLZ/status/1814649457058648236`
* **15 leet code patterns** " LeetCode was HARD until I Learned these 15 Patterns: "Prefix Sum," "Two Pointers," "Top 'K' Elements," "Sliding Window," "LinkedList In-place Reversal," "" `https://x.com/ashishps_1/status/1814884401249198569`
* **International directory of search engines** " A 26 years old International Directory of Search Engines, you can check specific country's search engines and web directories" `https://x.com/0xtechrock/status/1815045176366370971`
* **Beginner introduction pwnkit** " Beginners introduction to pwntools for exploit development and CTFs . Pwnt" `https://x.com/ptracesecurity/status/1812321156512330220`

