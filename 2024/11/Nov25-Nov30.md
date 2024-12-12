November Week 4
Note: published Dec 12


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
* **REDEDR** " Windows tele" `https://github.com/dobin/RedEdr`
* **Get System LCI** " GetSystem-LCI is a PowerShell script to escalate privileges from" `https://github.com/Helixo32/GetSystem-LCI`
* **ShadowHound** " ShadowHound aims to map Active Directory environments for BloodHound without introducing known-malicious / foreign binaries like SharpHound or SoapHound . Two methods (protocols) can be used for data collection: Using" `https://blog.fndsec.net/2024/11/25/shadowhound`
* **IIS Builder** `https://github.com/MHaggis/notes/tree/master/utilities/IISBuilder`
* **A simple Sleepmask BOF example** " A simple" `https://github.com/Cobalt-Strike/sleepmask-vs`
* **SDDLs** " No about section found" `https://github.com/rbmm/sddl`
* **SilentLoad** "Loads a drivers through NtLoadDriver by setting up the service registry key directly. To be used in engagement for BYOVD, where service creation creates an alert." `https://github.com/ioncodes/SilentLoad`
* **Nice Day Phishing** " No about section found" `https://github.com/dmcxblue/NiceDayPhishing`
* **Script sentry** "Non-existent shares that are attempted to be mapped via logon scripts ARE exploitable in default configurations of Active Directory. This is one of the issues I discovered when I did research on logon script abuse last year. I created a tool, called ScriptSentry, to look for this and 8 other unique logon script misconfigurations." `https://github.com/techspence/ScriptSentry`
* **Eclipes** "Eclipse is a PoC that performs Activation Context hijack to load and run an arbitrary DLL in any desired process. Initially, this technique was created as a more flexible alternative to DLL Sideloading + DLL proxying that can be leveraged to inject arbitrary code in a trusted process, altought it has proven to have other applications." `https://github.com/Kudaes/Eclipse`
* **Bruteforce rpc** `https://gist.github.com/ThePirateWhoSmellsOfSunflowers/3673746454aef7d55a5efed4dc4e1a61`
---
## Infrastructure

---
▬▬|═══════ﺤ
# Tradecraft
## General
* **Bypassing memory scanners** " The technique presented here is rather primitive and if anything, very silly . New ways to find those concealed implants have been discussed at BLACKHAT ASIA 2023 by John Uhlmann (aka jdu260)" `https://sillywa.re/posts/flower-da-flowin-shc/`
* **Create Own C2** " If it wasn’t for Metasploit, I likely would have never became interested in Cybersecurity at all . It was the pivotal moment in my life when everything started to click, at least in terms of my aspirations as" `https://g3tsyst3m.github.io/c2/python/Create-your-own-C2-using-Python-Part-1/`
* **Malware techniques used in wild** " Public malware techniques used in the wild: Virtual Machine" `https://github.com/ayoubfaouzi/al-khaser`
* **Shellcode runner** " Red Team Exercises #33 - Shellcode Runner with Kill Switch / Panic Switch . Shellcode runner can use a shellcode runner to execute a payload and establish communication with a Command and Control (C2) server . The focus" `https://www.linkedin.com/posts/joas-antonio-dos-santos_redteamexercises-redteam-cybersecurity-activity-7268790211692670977-kFeT`
* **URDL SLeepmask/beacongate** " Beacon is designed after Stephen Fewer's Reflective DLL Injection technique . Beacon is a Windows DLL that needs to be loaded into a process to run . The DLL is responsible for loading itself by implementing its own PE loader" `https://rastamouse.me/udrl-sleepmask-and-beacongate`
* **Build portable hack platform** " How to build portable hacking lab and control it with" `https://x.com/androidmalware2/status/1862469744739209340`
* **OSINT tips** " How to find the email of the Linkedin profile owner without a Linkedin account? Use various third-party databases (Amazing Hiring, Prospeo, SalesQL etc). Use" `https://x.com/cyb_detective/status/1862267251518308453`
* **Bypass crowdstrike/mde** " Endpoint Detection and Response (EDR) solutions are critical for protecting organizations from malicious activities . The goal is not to go in depth and provide the exact code I used to bypass different security solutions . Instead, I want to share my" `https://ericesquivel.github.io/posts/bypass`

## Windows
* **Introduction Kernel Exploitation** " This post will be the first of many in which I present you with a guide into the world of Windows Kernel Exploitation . We will be focusing on Windows 7 (x86) and Windows 10 (x64) for this post" `https://wetw0rk.github.io/posts/0x00-introduction-to-windows-kernel-exploitation/`
* **thread on interesting windows struct** " Theoretically, the WHEA_ERROR_PACKET_V2 should have the Length field at offset 8, but it appears to be 2 bytes off . The UEFI" `https://x.com/0gtweet/status/1862967305677758502`
* **NTLM Relay AttacK** " An NTLM relay attack is an MITM attack usually involving some form of authentication coercion . This type of attack can be absolutely devastating to an Active Directory environment, especially if the attacker is able to coerce authentication from an unauthent" `https://logan-goins.com/2024-07-23-ldap-relay/`
* **Secure windows rdp** " Powershell Skript created by @corner" `https://x.com/endi24/status/1862143914611761205`
* **Azure service principals** " Azure Service Principals serve as non-human identities that allow applications to authenticate and interact with Azure resources . If a Service Principal is misconfigured or compromised, it can lead to privilege escalation . This article provides an in-" `https://laythchebbi.com/index.php/2024/09/01/privilege-escalation-using-azure-service-principal/`
* **ADCS Exploitation** " Abuse the Client Supplies Subject flag on the CT ADCS Template 2021-06-17 [Will S. & Lee C.] @ SpecterOps LDAP on DC (1) Basic Prerequisites: Any Purpose EKU CE" `https://docs.google.com/spreadsheets/u/0/d/1E5SDC5cwXWz36rPP_TXhhAvTvqz2RGnMYXieu4ZHx64/htmlview`
* **Disable privacy?** " Organisation admins can turn it off with gpo: Policies\Administrative" `https://x.com/2345Jonte/status/1860614232829517891`


## Linux 
* **Linux Priv escalation bootcamp** `https://tbhaxor.com/linux-privilege-escalation/`
* **Analyzing bootkit** " The bootkit described in this report seems to be part of a project created by cybersecurity students participating in Korea's Best of the Best (BoB) training program . It is a functional bootkit with limited support and represents the first UE" `https://www.welivesecurity.com/en/eset-research/bootkitty-analyzing-first-uefi-bootkit-linux/`
* **ROPChain exploit with example** " ROP Chain Exploit x64 with example Akshit Singhal explains how to exploit a 64 bit architecture . ROP chain attack is a way to exploit security features enabled in a binary ." `https://akshit-singhal.medium.com/rop-chain-exploit-with-example-7e444939a2ec`
* **Debug, profiling, tracing** " Debugging, profiling and tracing Linux by  @bootlincom." `https://x.com/0xor0ne/status/1862043823234269350`
* **Linux log volumes** " Linux Log" `https://x.com/sysxplore/status/1862205069824782374`
* **Peekfd to spy on processes** " You can use the Linux peekfd command to spy on shells/processes . May be useful if investigating suspicious activity, but carries risk attacker may be alerted ." `https://x.com/CraigHRowland/status/1862274243654033453`

---
## MAC
* **MACOS something :)** `https://github.com/Evi1Grey5/MacOS-S`
---

## Web Applications
* **Interactive application?** " JavaScript Required: This is a heavily interactive web application, and JavaScript is required . Simple HTML interfaces are possible, but that's not what this is ." `https://bsky.app/profile/theaveragejoe.org/post/3lbzxy2q4mk2x`

## Cloud


# EDRs

▬▬|═══════ﺤ


---
# Threat Intelligence
* **Guardians become predators** `https://www.trellix.com/blogs/research/when-guardians-become-predators-how-malware-corrupts-the-protectors/`
* **Introduction to the North Korea-backed Scarcruft ROKRAT Malware Cluster** `https://www.s2w.inc/en/resource/detail/678`
* **Quick assist detection patterns** " Quickassist detection patterns: High volumes of external emails sent to a single recipient . Teams interactions with a foreign tenant ." `https://x.com/mthcht/status/1862419057011572975`
* **Async rat** " Async Rat is being used as a tool to schedule tasks for AsyncRat . #AsyncRat #Malware.103.195.103" `https://x.com/RacWatchin8872/status/1862119006041264199`
* **Poison vine** " APT-C-01/#Poisonvine specializes in creating phishing pages to trick targets into downloading a malicious loader written in C# . The loader" `https://x.com/blackorbird/status/1862442853445902387`
* **Piracy wat??** " This is the largest breakthrough in Windows / Office piracy ever . The solution will be available in the coming" `https://x.com/massgravel/status/1862492822261399731`
* **Forensic/browser extensions** `https://medium.com/@securitymaven/unmasking-browser-extensions-from-forensics-to-security-9800429b4455`
* **Asyncrat analysis** `https://medium.com/@coormac/malware-analysis-async-rat-06b9ceaaa2b1`
▬▬|═══════ﺤ
# CVEs
* **SMBGhost pre-auth RCE abusing Direct Memory Access structs** " Ricerca Security" `https://ricercasecurity.blogspot.com/2020/04/ill-ask-your-body-smbghost-pre-auth-rce.html`


---
▬▬|═══════ﺤ
# Misc
* **Full LInux environment in browser?** " WebVM is a full Linux environment running in the browser, client-side . It is a complete virtual machine, with support for persistent data storage, networking and, as of today’s release, Xorg and complete desktop environments" `https://labs.leaningtech.com/blog/webvm-20.html`
* **PKCS in c** " No about section found" `https://github.com/rbmm/PfxViewer/blob/main/Pem/Pkcs.cpp#L353`
* **PICO CTF Challenges** " Day 50 of the 100 Days of PicoCTF Challenge: Cracking the Code and Uncovering the Flag . I tackled a binary exploitation problem that required a deep understanding of input handling in C ." `https://www.linkedin.com/posts/meowmycks_maldev-malwaredevelopment-windows-activity-7264700111459344387-Bgeb`
* **List of C/C++ Resources** " List of C/C++ Project Ideas in Networking Programming is a collection of practical projects with references to help you get started ." `https://x.com/_trish_07/status/1862789569352978589`
* **Hackthebox Lantern writeup** " Lantern starts out with two websites . The first is a Flask website served over Skipper proxy, and the other is a Blazor site on .NET on Linux . I’ll abuse an SSRF in Skipper to get access" `https://0xdf.gitlab.io/2024/11/30/htb-lantern.html`
* **Docker visualized** " Docker is a containerization platform that uses OS-level virtualization to package and isolate applications with all their dependencies, ensuring consistent behavior across different environments . Docker is" `https://x.com/xmodulo/status/1862483095330377944`
* **Understanding kube cluster** " Kubernetes clusters are like LEGO - they are assembled from the building blocks . The best way to demystify K8s is to bootstrap your own ." `https://x.com/iximiuz/status/1862221113721315407`
* **Build os from scratch** " 1/2 Build a Linux From Scratch: Make Your Own Operating System . Resources" `https://x.com/chessMan786/status/1862350266697240645`
* **Leetcode patterns** " LeetCode was HARD. But these 15 patterns made it easier for me to learn them better . I wrote detailed articles on these patterns and provide links to Leet code problems you can practice to learn better ." `https://x.com/ashishps_1/status/1861983609558581515`
* **No idea** `https://github.com/rbmm/cmd/tree/master/X64`
* **Identify aws account from bucket** `https://medium.com/@august.vansickle/identify-the-aws-account-id-from-a-public-s3-bucket-f928d86e6fd1`
* **Reverse engineering course** " A FREE comprehensive reverse engineering tutorial covering x86, x64" `https://github.com/mytechnotalent/Reverse-Engineering`
* **Setting up av/edr lab** `https://an0nud4y.notion.site/AV-EDR-Lab-Env-Setup-130bc870022d8071935cc682d3eb34b9`
* **Socket programming** " 1/2 Socket Programming in C: Set up a server using socket() and bind() . Accept client connections with accept()- Send and receive data over TCP . Video 2: Client-Side Programming will" `https://x.com/_trish_07/status/1860998670298042690`