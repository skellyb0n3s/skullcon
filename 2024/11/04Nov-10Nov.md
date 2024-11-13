Note: published November 13

Searchbot v1 results
* Update: Restructured key topics


```                                                                                            :                    
                         __________
                      .~#########%%;~.
                     /############%%;`\
                    /######/~\/~\%%;,;,\
                   |#######\    /;;;;.,.|
                   |#########\/%;;;;;.,.|
          XX       |##/~~\####%;;;/~~\;,|       XX
        XX..X      |#|  o  \##%;/  o  |.|      X..XX
      XX.....X     |##\____/##%;\____/.,|     X.....XX
 XXXXX.....XX      \#########/\;;;;;;,, /      XX.....XXXXX
X |......XX%,.@      \######/%;\;;;;, /      @#%,XX......| X
X |.....X  @#%,.@     |######%%;;;;,.|     @#%,.@  X.....| X
X  \...X     @#%,.@   |# # # % ; ; ;,|   @#%,.@     X.../  X
 X# \.X        @#%,.@                  @#%,.@        X./  #
  ##  X          @#%,.@              @#%,.@          X   #
, "# #X            @#%,.@          @#%,.@            X ##
   `###X             @#%,.@      @#%,.@             ####'
  . ' ###              @#%.,@  @#%,.@              ###`"
    . ";"                @#%.@#%,.@                ;"` ' .
      '                    @#%,.@                   ,.
      ` ,                @#%,.@  @@                `
                          @@@  @@@  

```
# Offensive

## Tools
* **Shadow Dumper** " Shadow Dumper is a powerful tool used to dump LSASS memory, often needed in penetration testing and red teaming . It uses multiple advanced techniques to dump memory" `https://github.com/Offensive-Panda/ShadowDumper`
* **Rocabella** "Rocabella is an open-source tool that generates sniffing files." `https://github.com/nickvourd/Rocabella`
* **Teleco Finder** " No about section found" `Telco F1ND3R is a comprehensive toolkit designed to discover, analyze, and visualize telecom infrastructure targets. `
* **Get SharePoint Version PS Script** " No about section found" `https://gist.github.com/LuemmelSec/208b8ba52b645ec189031d2b5200f76e`
* **Early Cascade Technique** " The code is boring but the blog post was very interesting to read . Reimplemented the Early Cascade Injection technique ." `https://x.com/C5pider/status/1854648777023332666`
* **ECC Attacks** " Elliptic" `https://github.com/elikaski/ECC_Attacks`
* **POC Loader** " A proof-of-concept shellcode loader leverages AI/ML face recognition models to" `https://github.com/0xTriboulet/T-70`
* **ADCheck** " Assess the security of your Active Directory with" `https://github.com/CobblePot59/ADcheck`
* **Teams C2** " C2 infrastructure allows Red Teamers to execute system commands on compromised" `https://github.com/cxnturi0n/convoC2`
* **PHP JPEG Injecting** " Injects" `https://github.com/dlegs/php-jpeg-injector`
* **loxs** "best tool for finding SQLi,CRLF,XSS,LFi,OpenRedirect" `https://github.com/coffinxp/loxs`
* **Nuke amsi** " NukeAMSI is a powerful tool designed to neutralize the" `https://github.com/anonymous300502/Nuke-AMSI`
* **CoffeeLdr** `https://github.com/joaoviictorti/coffeeldr`

---
## Infrastructure
* **Free RDS/VPS** " List of Websites that give free RDP/VPS gives list of Webs" `https://x.com/HackingTeam777/status/1853691851296940126`
---
▬▬|═══════ﺤ
# Tradecraft
## General
* **Section Hashing** " Section Hashing explains how software breakpoints work internally and how they work in the software . We open x32dbg.exe and debug a 32 bit PE and set a breakpoint near the entry point . We can examine how this" `https://malwareandstuff.com/catching-debuggers-with-section-hashing/`
* **Structured Storage** " Structured Storage is a Windows technology that abstracts the notions of files and directories behind COM interfaces – mainly IStorage and IStream . Its primary intent is to provide a file system hierarchy within a single physical file ." `https://scorpiosoftware.net/2024/11/09/structured-storage-and-compound-files/`
* **Sleep Obfuscation Foliage** " In this post, we will cover topics such as memory detection evasion . We will discuss how memory scanners work and APC-based sleeping obfuscation ." `https://oblivion-malware.xyz/posts/sleep-obf-foliage/`
* **Malware development techniques** " Malware Development  : Guidelines: Reverse Shell Via Dll Hijacking . Guidelines: DLL injection into the process, advanced code injection and reverse shell hacking ." `https://x.com/akaclandestine/status/1854289373811900554`
* **x64 and shellcoding** `https://g3tsyst3m.github.io/`
* **Interesting way identifying U2U/UnPac** " There are some interesting detections for U2U/UnPAC the hash in certipy/rubues/mimiktaz/impacket based on TGS ticket options (https://lnkd" `https://www.linkedin.com/posts/alex-reid-2b5360222_redteam-cybersecurity-infosec-activity-7260678727880044544-_7Yz`
* **Accessing SAM** "On related note, did you know, that 7z (running as admin), can browse to "PhysicalDrive0" (so \\.\PhysicalDrive0\3.Basic data partition.ntfs\Windows\System32\config\) and copy file from there? SAM is not locked, AV/EDR don't seem to give a damn :)" `https://x.com/rnmx123/status/1853908167559627001`. Something similar " 7z can browse .VHD and .VMDK files and even directly browse ntfs filesystems . Copy SAM/SECURITY/SYSTEM hives directly from the images ." `https://x.com/nyxgeek/status/1853749702971314288`


## Windows
* **Identifying Callbacks** " Certain Windows APIs support passing a function pointer as one of its parameters . This is then called when a particular event is triggered, or a scenario takes place . Some of the popularly known callbacks are EnumChildWindows , RegisterClass" `https://whiteknightlabs.com/2024/11/03/huntingcallbacks-enumerating-the-entire-system32/`
* **Userland to kernelland** " Master C&C from Userland to Kernel Mode onWindows (Part 1: DNS Tunneling) Abdel Ahmed will walk you through building a C2 from scratch, exploring everything from userland to kernel mode ." `https://osintteam.blog/master-c-c-from-userland-to-kernel-mode-onwindows-part-1-dns-tunneling-85c7a7f469bb`
* **Return address spoofing** " Anti-Virus or EDR solutions determine if an activity is malicious based on behavioural thresholds . Trusted processes, like system services, have a higher threshold . Typically, one such activity is the execution of suspicious APIs from unbacked memory" `https://hulkops.gitbook.io/blog/red-team/x64-return-address-spoofing`
* **Managed Service Accounts** " Managed Service Accounts allow you to run programs as an account that doesn't require a password while still having the security of a strong password . They're special in that they're managed, but under the covers they're computer accounts ." `https://syfuhs.net/how-managed-service-accounts-in-active-directory-work`
* **Monitor windows tokens regular intervals** " In a recent engagement my teammates and I compromised a Windows server where some high privileged users were connected . We decided to abuse Windows tokens to move laterally in the network . The idea to be able to monitor Windows tokens at regular intervals came" `https://sokarepo.github.io/redteam/2024/04/18/monitor-cobaltstrike-windows-token-kerberos-persistence.html`
* **LDAP queries offensive/defensive** " BloodHound integrates a strong visual perspective, security descriptors, inbound and outbound object controls, exploit information, OPSEC considerations, and so much more ." `https://ericazelic.medium.com/ldap-queries-for-offensive-and-defensive-operations-4b035b816814`
* **Steal RDP Sessions** " A short demo to explain how easy it is/was to steal a disconnected RDP session once local administrator privileges have been obtained ." `https://secureyourit.co.uk/wp/2024/11/07/local-admin-disconnected-rdp-sessions/`
* **Analyzing procman stack trace** " Analyzing Procmon stack trace is always a great source of knowledge . In current versions of Windows win32u.dll performs syscalls in a legitimate way . Idk if its needed, but I guess it can be" `https://x.com/_Kudaes_/status/1854885388743033146`
* **SMB Relay technique** " This page deals with gaining code execution relaying NTLMv1/2 hashes in a very effective manner . Attackers have two options: Crack it to retrieve cleartext passwords and relay it to gain code execution on a target" `https://aas-s3curity.gitbook.io/cheatsheet/internalpentest/active-directory/exploitation/exploit-without-account/smb-relay`
* **.Net Hooking** " Decompiling .NET code with dnSpy is possible due to the way .NET executables and libraries are structured . When you compile a .NET application, the code is not native machine code ." `https://watson0x90.com/net-hooking-with-frida-and-fermion-c14d4f19c823`
* **Way to use psexec** "net use * https://live.sysinternals.com/tools" `https://x.com/chriselgee/status/1854512515863998655`
* **LOLad** " The LOLAD and Exploitation project provides a collection of Active Directory techniques, commands, and functions . These techniques leverage AD’s built-in tools to conduct reconnaissance, privilege escalation, and lateral movement . Understanding these methods helps" `https://lolad-project.github.io/`
* **X Forwarding to logging** `https://support.kemptechnologies.com/hc/en-us/articles/202744899-X-Forwarding-For-and-IIS-logging-for-non-transparent-services`
* **Windows Priv Escalation** " Great talk by my friend @decoder_it on Windows Privilege Escalation . Worth a watch!" `https://x.com/splinter_code/status/1833608259674034341`
* **Credential Guard enabled on servers** " Credential Guard is now enabled by default on servers . Delegated Managed Service Account (DMSA) is now introduced ." `https://x.com/sekurlsa_pw/status/1853559728967995805`
* **Executing code via long pointer** `https://www.hexacorn.com/blog/2024/11/07/beating-the-dead-horse-only-to-inject-it-some-more/`

## Linux 
* **Linux Persistence Techniques** " Persistence techniques refer to methods employed by threat actors to maintain a connection to the target system after infiltration . As a single breach may not be enough to achieve all their goals, threat actors look for ways to re-access the system ." `https://asec.ahnlab.com/en/83779/`
* **Hide processes with bind fs** " Hiding Linux processes with bind-mounts is" `https://x.com/0xor0ne/status/1854433627775394125`
* **Understanding file descriptor table** " The File Descriptor Table is a per-process data structure that serves as the user-facing interface for file operations . Each open file is represented by an integer, known as a file descriptor, which acts as an index into this" `https://mohitmishra786.github.io/chessman/2024/09/25/Understanding-File-System-Management-In-Unix-Like-Operating-Systems.html`
* **Detection cheatsheet** `https://edu.defensive-security.com/`
* **Understanding ASLR** " Address Space Layout Randomization (ASLR) is a crucial security feature implemented in modern operating systems to protect against various types of memory corruption attacks . ASLR works by randomly arranging the address space positions of key data areas of a process," `https://mohitmishra786.github.io/chessman/2024/09/29/Address-Space-Layout-Randomization.html`

---
## MAC
* **Apple UUID Finder** " Universally Unique Identifiers (UUIDs) are unique 128-bit values embedded within each macOS executable file . They provide a unique ID for each app . By the end of this article, you will learn how to identify all" `https://karol-mazurek.medium.com/apple-uuid-finder-a5173bdd1a8a`

---

## Web Applications
* **X Forward Host Injection** " "X-Forwarded-Host" helped me find my first bug . "Host header injection" is a request header that specifies the domain that a client (browser) wants to access ." `https://medium.com/@spettyial/x-forwarded-host-helped-me-find-my-first-bug-c2c16347af18`
* **Sensitive data via 403 bypass** " The story happens when I was using Google dorks to find some domains to check for bugs . It was then this particular domain of a well reputed company caught my eye (Lets call it redacted.com)" `https://sagarsajeev.medium.com/sensitive-data-exposure-via-403-forbidden-bypass-df9b4dcd0fd`
* **Useful fileupload technique** " Kerstan shares useful file upload tip in Bug bounty Tuesday . File upload to RCE — Bug Bounty Tuesday kerstan . If you can upload a.zip file on target then: create a.php file(rce.php)" `https://medium.com/@kerstan/file-upload-to-rce-bug-bounty-tuesday-f8dda0ed4077`
* **Bypass WAF** " You can bypass path-based WAF restrictions by appending raw/unencoded non" `https://x.com/d4d89704243/status/1854562239547674971`
* **Web API Vuln lists** " C2 infrastructure allows Red Teamers to execute system commands on compromised" `https://github.com/cxnturi0n/convoC2`

## Cloud


# EDRs

▬▬|═══════ﺤ


---
# Threat Intelligence
* **Evasive Zip** " The ZIP format is widely used for compressing and bundling multiple files into a single one . Its structural flexibility makes it an attractive vector for evasive malware delivery ." `https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/`
* **Europe Onion Search Engine** " Europe - Onion" `https://x.com/akaclandestine/status/1855264701770240299`
* **Zip Concatenation Techniques** " Hackers are targeting Windows machines using ZIP file concatenation technique to deliver malicious payloads in compressed archives without security solutions detecting them . The technique exploits the different methods ZIP parsers and archive managers handle concatenated ZIP files ." `https://www.bleepingcomputer.com/news/security/hackers-now-use-zip-file-concatenation-to-evade-detection/`
* **Dynamic Linking Patching** " The group Muddled Libra used bedevil to target VMware vCenter servers, according to Palo Alto’s Unit42 Blog, 2024 . The rootkit comes with a nifty feature called Dynamic Linker Patching : Upon installation," `https://dfir.ch/posts/bedevil_dynamic_linker_patching/`
* **Windows subsystem for linux** " Windows Subsystem for Linux allows you to run lightweight linux on top of Windows OS . WSL is a great feature for sysadmins, cyber security experts and the likes whom enjoy using linux but may be stuck with using Windows ." `https://threathunt.blog/wsl/`
* **Microsoft teams forensics** " Microsoft Teams is probably the most popular messaging app used in companies from various industries . In case of internal fraud it can be interesting sources of evidences . Because I didn't have access to enterprise of Microsoft Office environment, my approach to investigate" `https://hexseven.pl/articles/microsoft-teams-forensics/`
* **Abusing VSCode** " Unit 42 researchers recently found that Stately Taurus abused the popular Visual Studio Code software in espionage operations targeting government entities in Southeast Asia . The group is a Chinese advanced persistent threat (APT) group that carries out cyberespionage" `https://unit42.paloaltonetworks.com/stately-taurus-abuses-vscode-southeast-asian-espionage/`
* **Detecting and preventing lsass dumping** " Credentialed OS credentials from a targeted device is among the primary goals when launching attacks . These credentials serve as a gateway to various objectives they can achieve in their target environment . Detecting and stopping OS credential theft is important because it" `https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/`
* **Veildrive** " VEILDrive leverages Microsoft services for command and control (C2) A cybersecurity team at Hunters, AXON, recently uncovered an ongoing threat campaign . The attackers embedded C2 functionality within custom malware, allowing them to discreetly" `https://securityonline.info/veildrive-a-novel-attack-exploits-microsoft-services-for-command-control/`
* **KQL for devices talking to internet** " KQL query for PowerShell talking to the Internet: "DeviceNetworkEvents" where RemoteIPType == "Public" and RemoteIP" `https://x.com/NathanMcNulty/status/1854435646322164222`
* **OceanLotus** "During recent daily operations, the Qi'anxin Threat Intelligence Center discovered that the New OceanLotus organization, which we have been tracking since mid-2022, has become active again and used a new method of abusing MSI files. " `https://mp.weixin.qq.com/s/alaZxCd61gJNI9D01eQzgg`
* **Keylogger attributed to NK** " IT security blog focusing on malware forensics, dynamic and static analysis, as" `https://hybrid-analysis.blogspot.com/2024/11/recent-keylogger-attributed-to-north.html`
* **New NK group** " ThreatLabz has observed new Contagious Interview campaign attacks where a threat actor posted a job opening for a full-stack developer on part-time hiring platforms, like Freelancer. As part of the interview process, applicants were" `https://www.zscaler.com/blogs/security-research/pyongyang-your-payroll-rise-north-korean-remote-workers-west`


▬▬|═══════ﺤ
# CVEs



---
▬▬|═══════ﺤ
# Misc
* **Dman Vuln WIindows App** " The code and techniques provided in this blog are intended for educational purposes only . Under no circumstances should the information or code be used for unauthorized access, illegal hacking, or any activities that violate the law ." `https://medium.com/@securitymaven/damn-vulnerable-win-app-in-a-nutshell-eee650b6f25e`
* **Constructing defenses** " Constructing Defense is 3 courses combined into a single Path . Course #1 features an introduction to the massive, web-based lab and dives into Windows Servers and Clients including Active Directory. Course #2 showcases Linux and Kuber" `https://www.justhacking.com/course/constructing-defense/`
* **Final draft osint techniques** " The final draft of OSINT Techniques, 11th Edition is finished: 47 chapters | 276,000 words | 590 pages @ 8.5 x 11 . Digital version should be released very soon but print version will take some extra time" `https://inteltechniques.com/blog/2024/11/08/osint-11-almost-ready/`
* **Evasive red team tool?** " This blog post reviews the evolution of one of Fox-IT’s evasive tools . The tool is designed to aid in payload delivery during Red Teaming engagements ." `https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/`
* **Deobfuscation .net strings** " Automating Deobfuscation of XorStringsNet is a de-obfsucator for a .NET obfuscator . The CIL is basically the equivalent to assembly for .NET managed code . There are deobfusc" `https://eversinc33.com/posts/unxorstringsnet.html`
* **Interesting response** " Before g_pfnSE_DllLoaded is invoked it will be decoded using SharedUserData->Cookie value ." `https://x.com/C5pider/status/1854661803596562882`
* **Reverse Engineering network protocols** " Attacking Network Protocols is a deep dive into network protocol security from James Forshaw . This comprehensive guide looks at networking from an attacker’s perspective to help you discover, exploit, and ultimately protect vulnerabilities ." `https://jhalon.github.io/reverse-engineering-protocols/`
* **Other tools** " The competition is aimed at smaller tools and not big tool sets, but I welcome this new competition . Happy to see more offsec dev entrepreneurs entering the field!" `https://x.com/MarcOverIP/status/1854272717647978927`
* **Cable** " Cable is a .NET post-exploitation tool aimed at Active Directory recon and exploitation . Some of the newly added functionality as part of this release includes: - Reformatting of enumeration output for all previous modules into a tree" `https://www.linkedin.com/posts/logan-goins_i-just-published-the-cable-v10-release-activity-7259388658099593216-k6wG`
* **Another maldev topics** " Malware Development is a guide to how to use a reverse shell via Dll Hijacking . Part 8: DLL injection into the process . Part 7: Advanced code injection . Part 9: Reverse Shell via DLL Hij" `https://x.com/binitamshah/status/1853361591359504694`