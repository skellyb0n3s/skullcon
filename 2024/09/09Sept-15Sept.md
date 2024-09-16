Note: published Sept 16

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
* **Smb takeover** "BOF and Python3 implementation of technique to unbind 445/tcp on Windows via SCM interactions" `https://github.com/zyn3rgy/smbtakeover/`
* **Ldap Shell** " ldap-shell is included only in ntlmrelayx, so we set up a trivial relay for using it" `https://x.com/an0n_r0/status/1834744407402131947`
* **Gofuzz** "gofuzz.py is a powerful tool that recursively processes JavaScript files to extract URLs and secrets using both the JSluice command-line utility and Nuclei. It starts with an initial URL, processes all JavaScript files it encounters, and outputs a comprehensive list of unique URLs and any secrets found, sorted by severity." `https://github.com/nullenc0de/gofuzz`
* **IOT Implant** " This tiny hardware implant could be a cute little backdoor into your corporate network . “Zovek” , My Offensive IoT Redteam Implant v1.0 alt3kx ." `https://medium.com/@alt3kx/zovek-my-offensive-iot-redteam-implant-v1-0-f9787217fec0`
* **Jar Plant** " Java implant" `https://github.com/w1th4d/JarPlant`
* **Automate red team infra** " RedInfraCraft automates the deployment of powerful red team infrastructures . It streamlines the setup" `https://github.com/RedTeamOperations/Red-Infra-Craft`
* **SGN** " Shikata ga nai (�" `https://github.com/EgeBalci/sgn`
* **Decrypt Global vpn config** " Decrypt Global" `https://github.com/rotarydrone/GlobalUnProtect`
* **POC demonstrating both exe and dll payload** " PoC demonstrating executable "exe" file that can be used like exe" `https://github.com/Dump-GUY/EXE-or-DLL-or-ShellCode`


---

## Tools (from the crypt)
* **Subdomain Tool** "Subdomain Takeover Tool" `https://github.com/haccer/subjack`

---
## Infrastructure


---
## Tradecraft
* **Replay vpn cookies** " VPN authentication tokens are equally as vulnerable to session hijacking as browser session cookies . Device requirements for VPN access may be defeated by reconstructing profiles from a working device and replaying them with a third-party VPN client ." `https://rotarydrone.medium.com/decrypting-and-replaying-vpn-cookies-4a1d8fc7773e`
* **Mutation Gate** " EDR products like placing inline hooks at NTAPIs that are usually leveraged in malware . An NTAPI is a bridge between user space and kernel space . By placing an unconditional jump instruction at the NTAPI, no matter whether the" `https://winslow1984.com/books/malware/page/mutationgate`
* **Tactical Pretexting** " This article is part two of a three-part series on the art of crafting effective pretexts in social engineering . The strategies and techniques we'll be covering are for research and professional purposes only ." `https://hackerhermanos.com/influenceops-tactical-pretexting-part-2/`
* **Harnessing power of cobalt profiles** " The Malleable C2 profile lends versatility to Cobalt Strike . The existing profiles are good enough to bypass most of the Antivi . The article assumes that you are familiar with the fundamentals of flexible C2 ." `https://kleiton0x00.github.io/posts/Harnessing-the-Power-of-Cobalt-Strike-Profiles-for-EDR-Evasion/`
* **Classic injection techniques** " In this lab, we cover classic code injection in local process technique . This technique uses Windows API calls to allocate memory in local Process, write the shellcode to the allocated memory, and then execute it . This is one of the most" `https://offensive-panda.github.io/ProcessInjectionTechniques/`
* **Phantom dll** " Many native OS PE files still rely on delayed imports . When APIs imported this way are called for the first time, a so-called delay load helper function is executed first – it loads the actual delayed library, resolves the address of its" `https://www.hexacorn.com/blog/2024/09/14/the-delayed-import-table-phantomdll-opportunities/`



### Windows
* **Hijack SQL Sessions** " In this blog I’ll introduce the use of credential objects to execute code as either a login, local Windows user, or Domain user . I'll also cover how to enable logging that can be used to detect the associated behavior ." `https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/`
* **Using VEH Defense Evasion** " Vectored Exception Handlers (VEH) has been used in malware for well over a decade now . VEH provides developers with an easy way to catch exceptions and modify register contexts . Back in 2015, an UnKnoW" `https://securityintelligence.com/x-force/using-veh-for-defense-evasion-process-injection/`
* **Display bitlocker key** " A very friendly reminder, especially for non-corporate PCs protected with BitLocker: If you're not sure if you have your Recovery Password handy, you can display it any moment with "manage-" `https://x.com/0gtweet/status/1833964934348345740`
* **Graphic on how COM objects work** " Microsoft releases a new version of the" `https://x.com/ACEResponder/status/1834965916188078258`


---
# Threat Intelligence 
* **Remco Malware Report** " This feature requires an online-connection to the VMRay backend . An offline version with limited functionality is also provided ." `https://www.vmray.com/analyses/_vt/d534ed1c1ca0/report/overview.html`
* **Stack Thread Telemetry** " The stack spoofing that comes straight out of the box creates a problematic stack . We are going to discuss about a commercial C2 framework which is heavily abused by threat actors . This tool often gets cracked and sold on underground forums ." `https://sabotagesec.com/gotta-catch-em-all-catching-your-favorite-c2-in-memory-using-stack-thread-telemetry/`
* **Kernel ETW the best etw**  " Most Windows components generate logs using Event Tracing for Windows (ETW) These events expose some of Windows's inner workings . For security purposes, not all ETW providers are created equal . The first consideration is typically the reliability of the" `https://www.elastic.co/security-labs/kernel-etw-best-etw`
* **Threat actors leveraging http refresh attribute** " Unit 42 researchers observed many large-scale phishing campaigns in 2024 that used a refresh entry in the HTTP response header . From May-July we detected around 2,000 malicious URLs daily that were associated with campaigns of this type of ph" `https://unit42.paloaltonetworks.com/rare-phishing-page-delivery-header-refresh/`
* **Script Block Smuggling** " PowerShell’s Script Block Logging is a security feature that records and logs the contents of all scripts and commands executed within PowerShell . This includes both legitimate administrative scripts and potentially malicious commands ." `https://dfir.ch/posts/scriptblock_smuggling/`
* **Osint search engines** " Search engines for osint are based on search engines . The search engine is based in the U.S. based in California ." `https://x.com/akaclandestine/status/1835039085175750696`
* **Report on attacker lsass dump methodology** " In a recent incident response case, the attacker tried to dump lsass with the well-known comsvcs.dll technique: "tokens=1,2 delims= " ^%A in ('"tasklist /" `https://x.com/malmoeb/status/1825888362265182578`
* **Forensic investigations windows** " Forensic Investigation Operations — Windows Base II Baris Dincer . Follow 7 min read · Jul 19, 2024 -- Listen Share your analysis of a hacked windows machine ." `https://medium.com/@brsdncr/forensic-investigation-operations-windows-base-ii-6262a33ccfb2`



---
# CVEs
* **CVE 2020-27786** " This blog post describes how to exploit a use-after-free vulnerability due to a race condition in Linux Kernel 5.6.13 . The vulnerability is identified as CVE-2020-27786 . The MIDI driver can be opened through" `https://ii4gsp.github.io/cve-2020-27786/`
---
# Web Applications

---
# Windows
* **diving into kernel rootkit development** " The series would be coming in parts, as I find the time to learn and document everything that I encounter . I thought of diving into the kernel, and sharing everything I learn in the process ." `https://rootkits.xyz/blog/2017/06/kernel-setting-up/`
* **Comprehensive Guide NTLM Relaying** " For years, Internal Penetration Testing teams have been successful in obtaining a foothold or even compromising entire domains through a technique called NTLM relaying . This blog post aims to be a comprehensive resource that will walk through the attack primitives" `https://trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022`
* **UserAccountRestriction Abuse** " good to know: if having write access on the userAccountRestrictions property set of a computer, it does not matter if it is disabled . The property set includes userAccountControl also, so by modifying it" `https://x.com/an0n_r0/status/1834744402205364330`
* **Abuse Forgotten Permissions** " A while back, I read an interesting blog by Oddvar Moe about Pre-created computer accounts in Active Directory . In the blog, Oddvar also describes the option to configure who can join the computer to the domain after the object is" `https://dirkjanm.io/abusing-forgotten-permissions-on-precreated-computer-objects-in-active-directory/`

---
# Linux 
* **Real crypto examples in linux** " Dive into cryptography basics with real Linux examples! Dive into cryptosystems for embedded Linux developers . Series by Ser" `https://x.com/0xor0ne/status/1826273375368491167`
* **Series on linux internals** " Linux internals 0x1: You will learn concepts that are important for vulnerability research, reverse engineering, and low level dev. programming . On Linux systems," `https://x.com/husseinmuhaisen/status/1826131935543828480`


---
# MAC

---
# EDRs
* **Linux vs Windows telemetry** " Telemetry on Linux vs. Windows: A Comparative Analysis . What works for Windows cannot be translated into Linux and vice versa . Linux and Windows platforms have their own mechanisms for telemetry ." `https://kostas-ts.medium.com/telemetry-on-linux-vs-windows-a-comparative-analysis-849f6b43ef8e`


---
# Misc
* **Learn Reverse Engineering** `https://www.youtube.com/watch?v=sGPmh_5kwkw`
* **Setup lock rotation for docker containers** " This article is about setting up log rotation for Docker containers . We can configure different logging drivers for containers . By default, the log file is written in a JSON file located in /var/lib/docker/containers/[container" `https://www.freecodecamp.org/news/how-to-setup-log-rotation-for-a-docker-container-a508093912b2/`
* **Hackthebox intuition writeup** " Intuition starts off with a set of websites around a page that handles compressing documents . I’ll abuse a cross-site scripting attack in the bug report to get access first as a web developer, and then again as" `https://0xdf.gitlab.io/2024/09/14/htb-intuition.html`
* **Container networking from scratch** " Containers are just isolated and restricted Linux processes . Images aren't really needed to run containers, and that, on the contrary, to build an image we may need containers . How to reach containers running on a Linux host? How to" `https://labs.iximiuz.com/tutorials/container-networking-from-scratch`
* **x86 reverse engineering** " idk_lol.exe is called idk-lol.com . It contains a list of files called "idklol.org" and "Idk-loo" It contains the code for the most recent version of" `https://x86re.com/1.html`
* **Remove exif metadata from image** " This article is based off the following thread on Dread and was created by /u/EmpBomb . The article follows a thread created by EmpBomb ." `https://darkwebinformer.com/step-by-step-guide-how-to-remove-exif-metadata-from-your-pictures/`
* **Docker deployment for ai development** " Docker Compose template will bootstrap a fully-featured low-code development environment to build AI applications . There are 4 things included here: Ollama, Qdrant, Postgres and Postgres ." `https://x.com/svpino/status/1826590311948452035`
