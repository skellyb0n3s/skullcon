Note: Still being updated
                                                                                                                 
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
* **subBruter** "Sub directory brute force tool" `https://github.com/aashishsec/subBruter`
* **Cadiclus** "Privilege Escalation Tool for Linux Systems that use PowerShell" `https://github.com/tjnull/pentest-arsenal/tree/main/Cadiclus`
* **avred** "Analyse your malware to surgically obfuscate it" `https://github.com/dobin/avred`
* **BadDns** "It’s primarily a subdomain takeover detection tool but covers other DNS related issues like zone transfers and NSEC walking as wel" `https://blog.blacklanternsecurity.com/p/introducing-baddns`
* **Reconic** "Reconic is a network scanning and discovery tool designed to empower cybersecurity professionals and bug hunters in mapping, analyzing and securing digital infrastructures." `https://github.com/fkkarakurt/reconic`
* **W.A.L.K** "A new tool, W.A.L.K. (Web Assembly Lure Krafter), is released alongside this blogpost to automate the generation of payloads using Rust, bringing back HTML smuggling attacks and enhancing red teamers tradecraft." `https://labs.jumpsec.com/wasm-smuggling-for-initial-access-and-w-a-l-k-tool-release/`
* **SIGMA Potato** "SeImpersonate privilege escalation tool for Windows 8 - 11 and Windows Server 2012 - 2022 with extensive PowerShell and .NET reflection support." `https://github.com/tylerdotrar/SigmaPotato`
* **EDR Internals** "Tool to analyze EDR Agents" `https://github.com/outflanknl/edr-internals`
* **Living off the Orchard** "Lolbins but for macs" `https://www.loobins.io/`
* 

## Tools (from the crypt)
* **DLLirant** "DLLirant is a tool to automatize the DLL Hijacking researches on a specified binary" `https://github.com/redteamsocietegenerale/DLLirant`
* **ChiselStrike** "A .NET XOR encrypted cobalt strike aggressor implementation for chisel to utilize faster proxy and advanced socks5 capabilities" `https://github.com/m3rcer/Chisel-Strike`


## Infrastructure
* **Evilginx setup** "Setup of evilginx for phishing" `https://github.com/An0nUD4Y/Evilginx-Phishing-Infra-Setup`

## Tradecraft
* **Comphrensive mimikatz guide** `https://hadess.io/mimikatz-comprehensive-guide`
* **Ethical Hacking Notes** `https://tzero86.gitbook.io/tzero86`

### Windows

# Threat Intelligence 
* **ValeyRat** `https://www.zscaler.com/blogs/security-research/technical-analysis-latest-variant-valleyrat`
* **Threat Actors Used Github as email** " deliver #phishing emails through the legitimate account "notifications@github[.]com". In addition, the sender's name can be manipulated by renaming the attacker's GitHub account." `https://x.com/1ZRR4H/status/1799137435432939892`
* **ExGoBalt** `https://www.ptsecurity.com/ru-ru/research/pt-esc-threat-intelligence/ex-cobalt-go-red-tehnika-skrytogo-tunnelya/`
  
# CVEs
* **Nuclei Template for CVE-2024-4577**  "php cgi" `https://github.com/11whoami99/CVE-2024-4577`
# Web Applications
* **Wwayback and Https** `https://x.com/RootMoksha/status/1799716815280668822`
```bash
waybackurls url | grep '\.js$' | awk -F '?' '{print $1}' | sort -u | xargs -I{} python lazyegg[.]py "{}" --js_urls --domains --ips > urls && cat urls | grep '\.' | sort -u  | xargs -I{} httpx -silent -u {} -sc -title -td
```
* **JWT Cheat Sheet** "nice diagram of how JWTs are structed" `https://x.com/bountywriteups/status/1799284296731279373`
* **SSRF Bypass** `https://x.com/bountywriteups/status/1798668531996995705`

# Windows
* **WinNative API Programming** `https://leanpub.com/windowsnativeapiprogramming`

# Linux 


# EDRs
* Nothing reported
  
# Misc
* **Nameit** " NAMINT has you covered. It allows you to search for potential usernames across various platforms using their first & last names" `https://seintpl.github.io/NAMINT/`
* **AWS Hacking IAM** `https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation`
* **VulnLab Klendathu** "Auth Coercion, Mixed Kerberos Stacks & Domain Backup Keys" `https://www.youtube.com/watch?v=yU4N7CyoKf0`
* **Modern Attacks Red Vs Blue** `https://x.com/PyroTek3/status/1799130126053155114`
