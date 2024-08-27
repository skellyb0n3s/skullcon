Note: published Aug 27

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
* **VeilTransfer** " VeilTransfer is a data exfiltration utility designed to test and enhance the detection capabilities . This tool simulates real-world data ex-filtration techniques used" `https://github.com/infosecn1nja/VeilTransfer`
* **SCCM Secrets** " SCCMSecrets.py is a python utility that builds upon existing SCCM research . It aims to provide a comprehensive approach regarding SCCm policies exploitation . The tool can be executed from various levels of privileges, and will" `https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial`
* **USP** " Establishes persistence on a Linux system by creating a udev rule that triggers the execution of" `https://github.com/grahamhelton/USP`
* **AMSI VEH** " A Powershell AMSI Bypass technique via Vectored Exception Handler (VEH) This technique does not perform" `https://github.com/vxCrypt0r/AMSI_VEH`


---

## Tools (from the crypt)


---
## Infrastructure
* **Cobalt strike dns listener** " We have disabled all incoming ports when creating the VM . We also open the port for DNS (UDP) However, unlike SSH, we do not restrict this to specific IP addresses . This is important because in a red teaming scenario" `https://redops.at/en/blog/cobalt-strike-dns-listener`


---
## Tradecraft
* **CDN Crowdstrike** " Content Delivery Networks (CDNs) play a crucial role in our context . They allow us to use Microsoft Azure domains (e.g. ajax.microsoft.com) with a reputation to effectively disguise our command and control traffic" `https://redops.at/en/blog/cobalt-strike-cdn-reverse-proxy-setup`
* **Unwind metadata** " From this code, we can infer that rcx points to a struct that has a QWORD -sized field at offset +0x70 . However, from this code alone, we don't know much more about the struct ." `https://www.msreverseengineering.com/blog/2024/8/20/c-unwind-metadata-1`
* **DLLs the hidden potential** " Dynamic Link Libraries (DLLs) are essential components that contribute significantly to the functionality and modularity of applications . However, their very nature makes them a prime target for exploitation ." `https://www.alternativesec.xyz/DLLs-the-hidden-potential`
* **Understanding the PEB** " Process Environment Block (PEB) is a crucial memory structure in any Windows process . It is responsible for managing process-specific data such as the program base address, heap, environment variables and command line information . The PEB is unique" `https://redops.at/en/blog/edr-analysis-leveraging-fake-dlls-guard-pages-and-veh-for-enhanced-detection`
* **Power of cobalt profiles** " The Malleable C2 profile lends versatility to Cobalt Strike . The existing profiles are good enough to bypass most of the Antivi . The article assumes that you are familiar with the fundamentals of flexible C2 ." `https://kleiton0x00.github.io/posts/Harnessing-the-Power-of-Cobalt-Strike-Profiles-for-EDR-Evasion/#solution-1-make-the-payload-crt-library-independent`


### Windows

---
# Threat Intelligence 
* **NK Infrastructure** " Cisco Talos is exposing infrastructure we assess with high confidence is being used by a state-sponsored North Korean nexus of threat actors . This campaign consists of distributing a variant of the open-source XenoRAT malware we're calling �" `https://blog.talosintelligence.com/moonpeak-malware-infrastructure-north-korea/`
* **PDF Files** " PDF files are a popular tool for cybercriminals to use in phishing attacks . They allow direct execution of scripts that can reload additional malware . Dynamic analysis using a sandbox can provide additional information about the document ." `https://www.oneconsult.com/en/blogs/dfir-analysts-diary/dfir-simple-analysis-of-pdf-files/`
* **Sidewinder** " We just released a technical analysis on #Sidewinder #APT's" `https://x.com/DarkAtlasSquad/status/1824806525665165706`


---
# CVEs

---
# Web Applications

---
# Windows
* **Overview rdp settings** " Determines whether desktop composition (needed for Aero) is permitted when you log on to the remote computer . Do not use the administrative session of the remote . administrative session i 0 Connect to the administrative . session ." `https://www.donkz.nl/overview-rdp-file-settings/`
* **Deprecating NTLM** " Microsoft has been hinting at the deprecation and removal of NTLM from Windows for a while now . We're finally talking about how we're doing it ." `https://syfuhs.net/deprecating-ntlm-is-easy-and-other-lies-we-tell-ourselves`
* **Windows api cheat sheet** " Windows API function calls include functions for file operations, process management, memory management, thread management, DLL management, synchronization, interprocess communication, Unicode string manipulation," `https://github.com/7etsuo/windows-api-function-cheatsheets`
* **New Teams persistence** " The Teams application is no longer an Electron app . Previously, we achieved persistence through apps like Slack, Discord, Zoom, and Teams ." `https://merterpreter.medium.com/new-teams-new-persistence-408d9df00595`


---
# Linux 


---
# MAC
* **MACOS Redteaming** " macOS red teaming involves simulating cyber-attacks on macOS environments to identify vulnerabilities, assess security posture, and improve defensive measures . This process encompasses a wide array of techniques, tools, and methodologies aimed at mimicking the tactics," `https://redteamrecipe.com/macos-red-teaming#heading-gathering-system-information-using-ioplatformexpertdevice`


---
# EDRs

---
# Misc
* **Offsec Reporting** " Offensive Security OSCP, OSWP, OSEP, OSWA," `https://github.com/Syslifters/OffSec-Reporting
* **Retrieve deleted tweets** " This tool can retrieve deleted tweets and replies . It can also retrieve old bios and bios of the account" `https://github.com/0xcyberpj/tweet-machine`
* **Pentest Notes** " My Notes" `https://github.com/0xDigimon/PenetrationTesting_Notes-`
* **Review of engagement** " A sudden check-in from a new agent on ALICE-PC gives red teamers a mini heart attack . In this post, I will review how an engagement went awfully wrong for me by expanding on this concept ." `https://hubs.la/Q02KcC9V0`
