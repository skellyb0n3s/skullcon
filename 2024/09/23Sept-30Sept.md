Note: published Sept 27

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
* **Recursive Loader** `https://github.com/Evi1Grey5/Recursive-Loader`
* **MFA Sweep** " A tool for checking if MFA is enabled" `https://github.com/dafthack/MFASweep`
* **Nameless C2** " Nameless C2 - A C2 with" `https://github.com/trickster0/NamelessC2`
* **DNA** " LLVM based" `https://github.com/Colton1skees/Dna`
* **Gshark** " Scan for sensitive information" `https://github.com/madneal/gshark`
* **Facedancer** " FaceDancer is an exploitation tool aimed at creating hijackable proxy-based D" `https://github.com/Tylous/FaceDancer`
* **Illusive Fog** " Windows" `https://github.com/ChaitanyaHaritash/IllusiveFog`
* **Generate AES key** " Generate AES128 and AES256 Kerberos" `https://github.com/seriotonctf/kerberos_aes_key`
---

## Tools (from the crypt)

---
## Infrastructure
* **SSH via haproxy** " Security rules are put in place to prevent employees from going out on ports other than http⋅s (ports 80 and 443) Haproxy bypasses this kind of protection and can be complex ." `https://medium.com/@talhakhalid101/ssh-over-openssl-over-haproxy-bypassing-blocks-f4b4c276d8dd`

---
## Tradecraft
* **Evasion through virtualization** " This blog post reviews the evolution of one of Fox-IT’s evasive tools . The tool is designed to aid in payload delivery during Red Teaming engagements ." `http://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/amp/`
* **Unhooking** " Unhooking patch is the process of removing or reverting modifications made to system functions or APIs that have been intercepted by antivirus or EDRs . When a function is hooked, the original code is altered to redirect its execution to" `https://www.linkedin.com/posts/joas-antonio-dos-santos_redteam-redteamexercises-cybersecurity-ugcPost-7245123541250002944-X6dz`
* **Stealthy backdoor?** `https://www.linkedin.com/posts/malwaretech_stealthy-user-mode-backdoors-via-the-httpsys-ugcPost-7244984635598741504-EVSJ`


### Windows
* **Powershell cmd insight** " #PowerShell to show what Firewall rules there are on specific remote ports . #Get-NetFirewallPortFilter|where remoteport -ine 'Any'" `https://x.com/guyrleech/status/1838214158048780374`
* **Examining superfetch** " In the previous blogpost we dig into the tool Meminfo.exe from Windows Internals Book highlighting “FileInfo requests” I suggest you take a look at some details about another type of request named ‘SuperFetch" `https://v1k1ngfr.github.io/superfetchquery-superpower/`
* **Exe Activity** " Exe entry point takes 1 argument - a pointer to PEB . Native applications developers will use NtProcessStartup[W] as the entry point of the program ." `https://www.linkedin.com/posts/alex-s-ba3743121_oddly-enough-many-do-not-know-that-the-exe-activity-7244090509604864001-3leB`
* **Deep dive windows access token** " Pre-Windows 2000 Compatible Access Security group that definitely deserves your attention . This group does exactly what the description says it does: "A backward compatibility group which allows read access on all users and groups in the domain"" `https://www.linkedin.com/posts/hosein-tahaee_deep-dive-to-access-token-on-windows-activity-7241929779145306112-zf46`
* **How Kerberos Works** " Traditional password-based systems were not sufficient because they transmitted passwords in plain text, making them vulnerable to eavesdropping . So, the Massachusetts Institute of Technology (MIT) developed a protocol called Kerberos . The protocol’s name" `https://medium.com/@makhentosch/how-does-kerberos-work-75378390c7cd`
* **Make ntlm great again** " Some of the old tricks used before ADCS and SCCM were used to gain quick wins . These techniques should be part of your on-premise AD toolkit, so let’s use them ." `https://labs.jumpsec.com/ntlm-relaying-making-the-old-new-again/`
* **Onedrive sync** " The case of the OneDrive Sync Client in an estate that enforces C: drive restrictions is an interesting demonstration of this conundrum . This article runs through that, as well as discussing a number of ways you can improve the security of" `https://james-rankin.com/videos/using-onedrive-sync-client-with-c-drive-restrictions-and-a-bunch-of-handy-security-tips-too/`
* **MSI** " An MSI file is a Microsoft Installer file, used for installing software on Windows operating systems . MSI files were introduced by Microsoft with the release of Windows 2000 and Windows Installer 1.0 ." `https://securitymaven.medium.com/exploring-msi-files-the-good-the-bad-and-the-ugly-d0f004d0f0b6`
* **RDP Event logs** " Remote Desktop Protocol (RDP) abuse for lateral movement . This isn’t an exploit or some zero-day. It’s literally just using a tool that you, your admins or possibly general users use every day ." `https://www.thedfirspot.com/post/lateral-movement-remote-desktop-protocol-rdp-event-logs`
* **Havoc past defender** " Getting a Havoc agent past Windows Defender (2024) lainkusanagi explains how to get your Havoc Demons past the latest version of Defender as of September 2024 ." `https://medium.com/@luisgerardomoret_69654/getting-a-havoc-agent-past-windows-defender-2024-dad51f7e5c79`
* **Bypassing new amsi?** " Some unit tests began failing on code that had not been recently changed . The code that was breaking is my code that patches this function . Microsoft released new behavioral signatures designed to prevent patching of the amsi.dll::Amsi" `https://practicalsecurityanalytics.com/obfuscating-api-patches-to-bypass-new-windows-defender-behavior-signatures/`
* **Bypassing windows group policy??** " Bypassing Windows 10 User Group Policy is not the end of the world, but it’s also not something that should be allowed . This technique has been tested against Windows 7 and Windows 10 Enterprise x64 ." `https://medium.com/tenable-techblog/bypass-windows-10-user-group-policy-and-more-with-this-one-weird-trick-552d4bc5cc1b`



---
# Threat Intelligence 
* **Practical IR** " Incident Response is a structured process organizations use to detect and respond to cyber threats, security breaches, and other unexpected events . The lab's theme is centered around a hypothetical tech company named XOPS ." `https://nxb1t.is-a.dev/incident-response/practical_ir_ad/`
* **Analyzing newest turla** " IT security blog focusing on malware forensics, dynamic and static analysis, as" `https://hybrid-analysis.blogspot.com/2024/09/analyzing-newest-turla-backdoor-through.html`



---
# CVEs


---
# Web Applications
* **Blogs about hidden parameters** " 10 Blogs about Hidden parameters have been published about how to use these tools . Hidden parameters can be used in bug bounties ." `https://x.com/h4x0r_fr34k/status/1838181016088756694`
* **Bug Bounty WriteUp** " Django, Django, or Node.js Web Application Header Values are Django, . Django, Rails, or . Node.JS Web application Header Values ." `https://x.com/bountywriteups/status/1839943560550068491`


---
# Windows

---
# Linux 
* **Exploiting buffer overflows** `https://x.com/7etsuo/status/1839638889344155897`

---
# MAC

---
# EDRs
* **EDR BYpass** " EDR & Antiv" `https://github.com/murat-exp/EDR-Antivirus-Bypass-to-Gain-Shell-Access`


---
# Misc
* **Online tools geo locating from photos** " Online tools for determining geolocation by photo: http://agent.earthkit.app (Ge" `https://x.com/cyb_detective/status/1838010437100507244`
* **GCP Privilege Escalation** " An attacker with these permissions can create a run service running arbitrary code (arbitrary Docker container), attach a Service Account to it, and make the code exfiltrate the Service Account token from the metadata . An exploit script for" `https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-run-privesc`
* **Leak pro project?** " The LeakPro project at AI Sweden (partially funded by Vinnova) is building a tool to stress test an object that has been exposed to sensitive data in order to find out if it exhibits unintended leakage ." `https://www.linkedin.com/posts/stefanjaeschke_this-is-probably-the-best-paper-on-active-activity-7245734290888572928-ZsPy`
* **10 algorithms master** " 10 Algorithms to Master Graphs for Coding Interviews:. The algorithms include Depth First Search (DS) and Breadth First Search . They provide links to LeetCode problems you can practice to learn them better ." `https://x.com/ashishps_1/status/1840250585607745560`