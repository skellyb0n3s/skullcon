Note: published October 25

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
* **EDR Telemetry website** " No about section found" `https://github.com/tsale/edr-telemetry-website`
* **recover deleted files** " Interactively find and recover deleted or overwritten files" `https://github.com/PabloLec/RecoverPy`
* **LSASS Reflective loading** " This tool leverages the Process Forking technique using the RtlCreateProcessReflection API to clone the lsass.exe process . Once the clone is" `https://github.com/Offensive-Panda/LsassReflectDumping`
---

## Tools (from the crypt)

---
## Infrastructure

---
## Tradecraft
* **Early Cascade Injection** " New Early Cascade Injection technique targets user-mode part of process creation . This new technique avoids queuing cross-process Asynchronous Procedure Calls (APCs), while having minimal remote process interaction . Unlike Early Bird APC Injection," `https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/`
* **Maldev Topics** "This repository was created to archive and document all of my attempts to learn and develop malware. I'm brand new to all of this. We'll start from the absolute beginning and see how far we can get." `https://github.com/cr-0w/maldev`
* **Legitimate Domains** " Attackers are using popular legitimate domains when conducting phishing, C&C, exfiltration and downloading tools to evade detection . The list of websites below allow attackers to use their domain" `https://lots-project.com/`
* **DLL Sideloading** " Dynamic Link Library (DLL) is a file containing code and data that multiple programs can use simultaneously . DLLs are a crucial component in the Windows operating system because Windows heavily relies on them for pretty much anything . Unlike static libraries" `https://www.r-tec.net/r-tec-blog-dll-sideloading.html`
* **Bypass YARA for Cobalt Strike** "Learn how to bypass the YARA rule Windows_Trojan_CobaltStrike_f0b627fc targeting Cobalt Strike’s signature shellcode by replacing key bytes with alternative shellcode and using a Python script to randomize the shellcode with NOPs, for EDRs evasion." `https://wafflesexploits.github.io/posts/Bypass-YARA-Rule-Windows_Trojan_CobaltStrike_f0b627fc-to-Evade-EDRs/`
* **?Administrator  Protection bypass using "Kerberos trick" by @tiraniddo** `https://x.com/decoder_it/status/1848037756670263630`

### Windows
* **Different ways enumerating AD domain** " This is possible by levaraging native Windows functionality . Leveraging native functionality helps attackers evade detection . The available information can be valuable to anyone that perfoms reconnaissance in an AD domain ." `https://stmxcsr.com/micro/search-ad.html`
* **Old .net techniques** " This blog post provides insights into three exploitation techniques that can still be used in cases of a hardened .NET Remoting server with TypeFilterLevel.Low and Code Access Security (CAS) restrictions in place . Two of these tricks are" `https://code-white.com/blog/teaching-the-old-net-remoting-new-exploitation-tricks/`

* **Deserialization for deploying specula?** " Using Deserializer, we can use deserialization to backdoor a workstation with Specula . We will use a simple 'dummy' app for our proof-of-concept code . Sorry, there will be no free" `https://trustedsec.com/blog/spec-tac-ula-deserialization-deploying-specula-with-net`

---
# Threat Intelligence 
* **Schedule Task Tampering** " The HAFNIUM threat actor is using an unconventional method to tamper scheduled tasks in order to establish persistence via modification of registry keys in their malware called Tarrask . The technique has been identified by the Microsoft Detection and Response Team" `https://ipurple.team/2024/01/03/scheduled-task-tampering/`
* **Detecting/Classification persistence techniques** " Dynamic Detection and Classification of Persistence Techniques in Windows Malware - master thesis by Jor" `https://essay.utwente.nl/94945/1/van%20Nielen_MA_EEMCS.pdf`
* **Muddled Libra** " The group Muddled Libra used bedevil to target vCenter servers in 2024, according to Palo Alto’s Unit42 Blog . The rootkit comes with a feature called Dynamic Linker Patching ." `https://x.com/malmoeb/status/1847614668929458425`

---
# CVEs

---
# Web Applications
* **CSPT Traversal** " Client Side Path Traversal (or CSPT for short) is a vulnerability which occurs when attacker-controlled input is not properly encoded . When this happens, an attacker can inject path traversal sequences (`../`) to" `https://matanber.com/blog/cspt-levels`

---
# Windows
* **Anti NTLM Relay** " An SMB client could not connect to an SMB server, even though the credentials were correct . The client was connecting to an IP which was not the real server’s IP . This can happen in some VPN network setups ." `https://medium.com/tenable-techblog/smb-access-is-denied-caused-by-anti-ntlm-relay-protection-659c60089895`


---
# Linux 
* **Execp** "Use fork() to create a child process, execvp() to execute our command, and wait() to reap the child process, all in C." `https://x.com/7etsuo/status/1846799502696763845`
---
# MAC

---
# EDRs

---
# Misc
* **USB and lnk files** " A USB (Universal Serial Bus) device is a standardized interface used for communication between computers and peripherals such as storage devices, input devices, and more . USB devices are built on the USB standard, which has evolved (USB 1." `https://securitymaven.medium.com/when-usbs-attack-exploring-the-underbelly-of-malicious-lnk-files-f536d5dbc753`
* **License plate lookup** " Nearly 1 in 4 used cars have some form of negative history lurking beneath the surface . FAXVIN’s free license plate lookup you can check a car's history in just minutes, without the need to visit your local DMV" `https://www.faxvin.com/license-plate-lookup`
* **Enforcing SMB Signing** " This week's series of articles will focus on the importance of SMB hardening . The two most important issues are ensuring the integrity of the system . We need to know how to deal with these issues ." `https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/active-directory-hardening-series-part-6-enforcing-smb-signing/ba-p/4272168`