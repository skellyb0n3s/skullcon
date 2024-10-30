Note: published October 30

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
* **AuthStager** "AuthStager is a proof-of-concept tool that generates a custom stager shellcode that authenticates to the stager server using an authentication token. The server validates client requests before sending the second stage, enhancing security in the staging process. The detailed information regarding this project is explained in this blog post: Stage, But Verify" `https://github.com/HulkOperator/AuthStager`
* **LUMA Config Extractor** " C2 extractor for Lumma Stealer" `https://github.com/YungBinary/Lumma-Config-Extractor`
* **Chrome Extension** " Chrome-extension implant turns victim Chrome browsers into fully-functional HTTP proxies ." `https://github.com/mandatoryprogrammer/CursedChrome`
* **Lolbins and beyond** " A curated list of awesome LOLBins, GTFO projects," `https://github.com/sheimo/awesome-lolbins-and-beyond`
* **Execute PE from lnk** " Extract and execute a PE embedded within a PNG file using" `https://github.com/Maldev-Academy/ExecutePeFromPngViaLNK`
* **Evil Cascade Injection** " In this blog post we introduce a novel process injection technique named Early Cascade Injection, explore Windows process creation, and identify how several Endpoint Detection and Response systems (EDRs) initialize their in-process detection capabilities. This new Early Cascade Injection technique targets the user-mode part of process creation and combines elements of the well-known Early Bird APC Injection technique with the recently published EDR-Preloading technique by Marcus Hutchins [1]. Unlike Early Bird APC Injection, this new technique avoids queuing cross-process Asynchronous Procedure Calls (APCs), while having minimal remote process interaction. This makes Early Cascade Injection a stealthy process injection technique that is effective against top tier EDRs while avoiding detection." `https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/`



---
## Infrastructure

---
▬▬|═══════ﺤ
# Tradecraft
## General
* **Polymorphic Engine** " Poly Polymorphic Engine is a programming library, created for encryption of data & code . It differs from other encryption libraries by its unique functionality: the construction of a different encryption algorithm during every encryption process, built from randomly selected encryption operations" `https://www.pelock.com/products/poly-polymorphic-engine`
* **Way you order a struct matters** `https://x.com/chompie1337/status/1849260389944717672`
* **API Show Cursor** " The well known API ShowCursor can show/hide mouse cursor, but only for current (caller) thread . It is exported by ordinal only from user32.dll ." `https://www.linkedin.com/posts/alex-s-ba3743121_well-known-api-showcursor-can-showhide-mouse-activity-7256003098324713472-Nuqt`
* **Script to escape container with /proc/sys** " Script to escape a container with /proc/sys/" `https://x.com/akaclandestine/status/1850253432663470482`

## Windows
* **Userworkstation attribute** " TIL, the attribute userWorkstations is still in play in modern windows . If you set the attribute on a user to something random the user cannot login to the computers anymore ." `https://x.com/Oddvarmoe/status/1848869990327542129`
* **Reading bitlocker numerical passwords** "The technique is not crossing any security boundaries. Manage-bde.exe is a well-known tool and if you can use it at any moment. There are some WMI interfaces as well." `https://x.com/0gtweet/status/1848821825813315901`
* **DLL Hijacking** " Dynamic Link Library (DLL) hijacking is a common occurrence that impacts Windows-based applications . Microsoft acknowledged it in an advisory back in 2010 . By manipulating the search order for DLL files, attackers can deceive an application into loading" `https://labs.jumpsec.com/breaking-into-libraries-dll-hijacking/`
* **Exception Junction** " The first part contains the ‘what’, ‘how’ and ‘why’ I reached here, and the second part focuses on the solution . This blog is in relation to some of the hurdles I�" `https://bruteratel.com/research/2024/10/20/Exception-Junction/`
* **New Com Persistence Technique** " Attackers use various methods to get a persistence on a computer: AutoRun folder, Scheduled Tasks, registry keys . These methods are well known to defenders, which makes them easy to detect . There are also more exotic methods of" `https://medium.com/@cicada-8/hijack-the-typelib-new-com-persistence-technique-32ae1d284661`
* **UNveiling windows services** " Unveiling Windows Services: The Hidden Engines of Your OS . Windows Services were like the unseen guardians of the realm, working in the background ." `https://securitymaven.medium.com/unveiling-windows-services-the-hidden-engines-of-your-os-09beb5597b4b`
* **COM Pitfalls** " I spend hours and hours googling and reading very old COM headers just to solve a problem . I hope this short post helps this week’s work ." `https://sabotagesec.com/i-hate-you-com-pitfalls-of-com-object-activation/`
* **Hookchain** " HookChain is a novel technique aimed at bypassing Endpoint Detection and Response (EDR) solutions by leveraging low-level Windows APIs and manipulating how system calls interact with user-mode hooks . To better understand how HookChain operates," `https://0xmaz.me/posts/HookChain-A-Deep-Dive-into-Advanced-EDR-Bypass-Techniques/`



## Linux 
* **Hide process in linux** " This is a nice simple way to hide a process name on Linux . You can see it happening due to /proc/PID/exe, /proc/.PID/.exe," `https://x.com/CraigHRowland/status/1850253934147092713`
* **Understanding mseal syscall** " Linux kernel 6.10 introduces the mseal syscall for memory protection . Discover its unique features, how it differs from prior schemes" `https://x.com/trailofbits/status/1849805615276634176`
* **Silly trick hide bash** " Silly trick to hide bash in ps awwwfux output: "replace your bash with" `https://x.com/MagisterQuis/status/1850185020473852400`


---
## MAC

---

## Web Applications
* **Finding More Subdomains** " A recon tip to find more subdomains (Shodan) by Shodan search engine . Big companies often use their own CDN (Content Delivery Network) and some of them are used to serve internal static files ." `https://x.com/bountywriteups/status/1849348727913300040`
* **Web Security Testing Tools** `https://x.com/bountywriteups/status/1850266862560641356`

## Cloud
* **Azure permissions** " If you have an AzureApp with http://File.Read and http://Site.Read privileges, you can dump the whole Sharepoint and OneDrive . I've created" `https://x.com/OtterHacker/status/1849076522046378134`



# EDRs
* **EDR Bypass techniques and how to detect it** " We document every EDR bypass technique used in the wild along with how to detect it using new memory forensics techniques and plugins . Feedback appreciated!" `https://x.com/attrc/status/1849108364145401915`
* **EDRnometry** " EDRmetry - Effective Linux EDR/SIEM Evaluation Testing Playbook . The FAQ section has been added recently ." `https://x.com/cr0nym/status/1849014022643097618`
* **Trendmicro excluding by name** " A lot of EDR are excluding specific processes by name . In TrendMicro, renaming explorer.exe or Chrome." `https://x.com/OtterHacker/status/1850198712699527313`
>> related " Using IDA, I identified an exclusion rule that prevents an entire detection chain from being triggered . By assigning the "correct" name to a process, certain DLLs associated with the EDR are not loaded, effectively bypassing the" `https://www.linkedin.com/posts/daniel-feichter-5277a0140_redteam-itsecurity-infosec-activity-7255831411490762753-eZPk`


▬▬|═══════ﺤ
# Threat Intelligence & Blue Team Related Topics
* **GhostPulse Malware** " According to Elastic Security Labs the Ghostpulse malware (aka hijackloader) has started hiding payloads in pixels and extracting them using RBG values" `https://x.com/Malcoreio/status/1848481271661342981`
* **Anti VM Techniques used by Lumma** " Anti-VM techniques being used by threat actors in the wild . This is a PowerShell script protecting a #Lumma Stealer build and being spread on YouTube videos ." `https://x.com/g0njxa/status/1848706395954180493`
* **Hunting Malicious Traffic** " Project Name: Hunting Strategies and Techniques of Malicious Processes Creating Network Traffic . Hunting malicious processes generating network traffic using Wireshark involves tracking abnormal traffic patterns initiated by suspicious processes like PowerShell or cmd.exe ." `https://hackforlab.com/hunting-strategies-and-techniques-of-malicious-processes-creating-network-traffic/`
* **Dead Drop Resolver?** " The Dead Drop Resolver (DDR) is a guidebook written by Steam and C2 (Command and Control) The guidebook is based on a book written by MetaStealer . The book is published by Steam ." `https://rt-solar.ru/solar-4rays/blog/4795/`
* **Turla Backdoor Defenses** " Turla Backdoor Bypasses ETW, EventLog and AMSI But It’s Buggy. This blog focuses on the defense evasion capabilities of a 32-bit fileless backdoor variant attributed to Turla . The 32" `https://nikhilh-20.github.io/blog/turla_backdoor_defenses_bypass/`

* **Registry key HeapLeakDetection**" Registry key HeapLeakDetection is useful in identifying the execution of a malicious executable . Each subkey has its own LastDetectionTime which tells us the last time a memory leak occurred and which executable was affected ." `https://x.com/samaritan_o/status/1848743680384889031`


---
▬▬|═══════ﺤ
# CVEs



---
▬▬|═══════ﺤ
# Misc
* **Hackthebox Pikacptcha** " The attack turns out to be a malicious captcha that manipulates the user into running a PowerShell command via the Windows run dialoag . The attack became common in September 2024 ." `https://0xdf.gitlab.io/2024/10/22/htb-sherlock-pikaptcha.html`
* **All in one latin wordlist** " All_in_one.latin.txt for NTLM contains 26.5 billion pairs of hash:password inside!" `https://x.com/w34kp455/status/1848327623417442573`
* **Rust for malware development** " This repository contains my complete resources and coding practices for malware development" `https://github.com/Whitecat18/Rust-for-Malware-Development`
* **RT Workshop 2024** `https://github.com/soheilsec/RT-workshop-2024`
