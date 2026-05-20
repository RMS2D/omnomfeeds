// Package curated ships editorial lists with the binary so the UI can offer
// one-click subscribe to Bluesky researchers without typing every handle.
package curated

type BlueskyHandle struct {
	Handle      string `json:"handle"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
}

var Bluesky = []BlueskyHandle{
	// --- Vulnerability research ---
	{Handle: "taviso.bsky.social", Name: "Tavis Ormandy", Category: "Vulnerability Research", Description: "Project Zero veteran, prolific bug finder"},
	{Handle: "wdormann.bsky.social", Name: "Will Dormann", Category: "Vulnerability Research", Description: "CERT/CC, vuln triage and PoC analysis"},
	{Handle: "gentilkiwi.bsky.social", Name: "Benjamin Delpy", Category: "Vulnerability Research", Description: "Author of mimikatz, Windows auth internals"},
	{Handle: "tiraniddo.bsky.social", Name: "James Forshaw", Category: "Vulnerability Research", Description: "Project Zero, Windows attack-surface research"},
	{Handle: "jonasl.bsky.social", Name: "Jonas L", Category: "Vulnerability Research", Description: "Windows kernel bug hunter"},
	{Handle: "matrosov.bsky.social", Name: "Alex Matrosov", Category: "Vulnerability Research", Description: "Firmware and bootkit research, Binarly"},
	{Handle: "daeken.bsky.social", Name: "Cody Brocious", Category: "Vulnerability Research"},
	{Handle: "daveaitel.bsky.social", Name: "Dave Aitel", Category: "Vulnerability Research", Description: "Immunity, offensive R and D"},
	{Handle: "hdm.bsky.social", Name: "HD Moore", Category: "Vulnerability Research", Description: "Metasploit, runZero"},
	{Handle: "evilsocket.bsky.social", Name: "Simone Margaritelli", Category: "Vulnerability Research", Description: "bettercap, offensive tooling"},
	{Handle: "ohpe.bsky.social", Name: "Antonio Cocomazzi", Category: "Vulnerability Research", Description: "Windows privesc research"},
	{Handle: "binitamshah.bsky.social", Name: "Binni Shah", Category: "Vulnerability Research"},
	{Handle: "rcvalle.bsky.social", Name: "Ramon Valle", Category: "Vulnerability Research", Description: "Rust security, exploit mitigations"},
	{Handle: "iangcarroll.bsky.social", Name: "Ian Carroll", Category: "Vulnerability Research"},
	{Handle: "amitse.bsky.social", Name: "Amit Serper", Category: "Vulnerability Research"},
	{Handle: "svch0st.bsky.social", Name: "svch0st", Category: "Vulnerability Research", Description: "Windows internals deep dives"},
	{Handle: "retr0.id", Name: "David Buchanan", Category: "Vulnerability Research", Description: "Hardware, crypto, and weird bugs"},
	{Handle: "amlweems.bsky.social", Name: "amlweems", Category: "Vulnerability Research"},
	{Handle: "n0x08.bsky.social", Name: "n0x08", Category: "Vulnerability Research"},
	{Handle: "wugeej.bsky.social", Name: "wugeej", Category: "Vulnerability Research"},
	{Handle: "lennaert.bsky.social", Name: "Lennaert", Category: "Vulnerability Research"},
	{Handle: "ericrzhang.bsky.social", Name: "Eric Zhang", Category: "Vulnerability Research"},
	{Handle: "sfsam.bsky.social", Name: "Samuel Erb", Category: "Vulnerability Research"},

	// --- Red team and offensive ---
	{Handle: "harmj0y.bsky.social", Name: "Will Schroeder", Category: "Red Team & Offensive", Description: "SpecterOps, AD attack research"},
	{Handle: "mattifestation.bsky.social", Name: "Matt Graeber", Category: "Red Team & Offensive", Description: "PowerShell, AMSI, code signing"},
	{Handle: "enigma0x3.bsky.social", Name: "Matt Nelson", Category: "Red Team & Offensive"},
	{Handle: "tifkin.bsky.social", Name: "Lee Christensen", Category: "Red Team & Offensive", Description: "SpecterOps, AD tradecraft"},
	{Handle: "fuzzysec.bsky.social", Name: "Ruben Boonen", Category: "Red Team & Offensive", Description: "Windows internals, FuzzySec"},
	{Handle: "flangvik.bsky.social", Name: "Flangvik", Category: "Red Team & Offensive", Description: "TrustedSec, offensive C# and tradecraft"},
	{Handle: "mubix.bsky.social", Name: "Rob Fuller", Category: "Red Team & Offensive", Description: "Veteran red teamer, mubix"},
	{Handle: "john-hammond.bsky.social", Name: "John Hammond", Category: "Red Team & Offensive", Description: "Huntress, malware and CTF educator"},
	{Handle: "jaysonstreet.bsky.social", Name: "Jayson E. Street", Category: "Red Team & Offensive", Description: "Social engineering, physical pentesting"},
	{Handle: "deviantollam.bsky.social", Name: "Deviant Ollam", Category: "Red Team & Offensive", Description: "Physical security, lock research"},
	{Handle: "ippsec.bsky.social", Name: "IppSec", Category: "Red Team & Offensive", Description: "CTF / HTB walkthroughs"},
	{Handle: "thegrugq.bsky.social", Name: "the grugq", Category: "Red Team & Offensive", Description: "OPSEC, threat actor analysis"},
	{Handle: "redteamnews.bsky.social", Name: "Red Team News", Category: "Red Team & Offensive"},
	{Handle: "ghostexodus.bsky.social", Name: "GhostExodus", Category: "Red Team & Offensive"},

	// --- Malware analysis ---
	{Handle: "vxunderground.bsky.social", Name: "vx-underground", Category: "Malware Analysis", Description: "Large malware archive and intel"},
	{Handle: "malwaretech.com", Name: "Marcus Hutchins", Category: "Malware Analysis", Description: "MalwareTech"},
	{Handle: "didierstevens.bsky.social", Name: "Didier Stevens", Category: "Malware Analysis", Description: "Document/maldoc analysis tooling"},
	{Handle: "hexacorn.bsky.social", Name: "Adam @ Hexacorn", Category: "Malware Analysis", Description: "Persistence, LOLBins, Windows artifact deep dives"},
	{Handle: "marcusbotacin.bsky.social", Name: "Marcus Botacin", Category: "Malware Analysis", Description: "Academic malware research"},

	// --- Threat intel and DFIR ---
	{Handle: "cyb3rops.bsky.social", Name: "Florian Roth", Category: "Threat Intel & DFIR", Description: "YARA / Sigma, threat hunting"},
	{Handle: "cyb3rward0g.bsky.social", Name: "Roberto Rodriguez", Category: "Threat Intel & DFIR", Description: "Detection engineering, ATT&CK"},
	{Handle: "cglyer.bsky.social", Name: "Christopher Glyer", Category: "Threat Intel & DFIR"},
	{Handle: "abuse-ch.bsky.social", Name: "abuse.ch", Category: "Threat Intel & DFIR", Description: "Malware tracker / IoC feeds"},
	{Handle: "stevenadair.bsky.social", Name: "Steven Adair", Category: "Threat Intel & DFIR", Description: "Volexity, APT tracking"},
	{Handle: "pwnallthethings.bsky.social", Name: "Matt Tait", Category: "Threat Intel & DFIR"},
	{Handle: "nixonnixoff.bsky.social", Name: "Allison Nixon", Category: "Threat Intel & DFIR", Description: "Unit 221B, cybercrime research"},
	{Handle: "chrissanders88.bsky.social", Name: "Chris Sanders", Category: "Threat Intel & DFIR", Description: "Network forensics educator"},
	{Handle: "craigwilliams.bsky.social", Name: "Craig Williams", Category: "Threat Intel & DFIR", Description: "Cisco Talos"},
	{Handle: "hacks4pancakes.com", Name: "Lesley Carhart", Category: "Threat Intel & DFIR", Description: "ICS / DFIR, Dragos"},
	{Handle: "taggart-tech.com", Name: "Allan Liska", Category: "Threat Intel & DFIR", Description: "Ransomware analyst, Recorded Future"},

	// --- Vendor research teams ---
	{Handle: "unit42.bsky.social", Name: "Unit 42", Category: "Vendor Research", Description: "Palo Alto Networks threat research"},
	{Handle: "paloaltonetworks.bsky.social", Name: "Palo Alto Networks", Category: "Vendor Research"},
	{Handle: "fireeye.bsky.social", Name: "FireEye (Mandiant)", Category: "Vendor Research"},
	{Handle: "kaspersky.bsky.social", Name: "Kaspersky", Category: "Vendor Research"},
	{Handle: "rapid7.bsky.social", Name: "Rapid7", Category: "Vendor Research"},
	{Handle: "redcanary.bsky.social", Name: "Red Canary", Category: "Vendor Research", Description: "Detection-centric threat research"},
	{Handle: "sophos.bsky.social", Name: "Sophos", Category: "Vendor Research"},
	{Handle: "symantec.bsky.social", Name: "Symantec", Category: "Vendor Research"},
	{Handle: "tenablesecurity.bsky.social", Name: "Tenable", Category: "Vendor Research"},
	{Handle: "trendmicro.bsky.social", Name: "Trend Micro", Category: "Vendor Research"},
	{Handle: "dragosinc.bsky.social", Name: "Dragos", Category: "Vendor Research", Description: "ICS / OT threat intel"},
	{Handle: "duosec.bsky.social", Name: "Duo Security", Category: "Vendor Research"},
	{Handle: "portswigger.bsky.social", Name: "PortSwigger", Category: "Vendor Research", Description: "Burp Suite + web research"},
	{Handle: "threatintel.microsoft.com", Name: "Microsoft Threat Intelligence", Category: "Vendor Research"},

	// --- Cloud and container security ---
	{Handle: "raesene.bsky.social", Name: "Rory McCune", Category: "Cloud & Container", Description: "Container / Kubernetes security"},
	{Handle: "lizrice.bsky.social", Name: "Liz Rice", Category: "Cloud & Container", Description: "eBPF, container internals"},
	{Handle: "mauilion.bsky.social", Name: "Duffie Cooley", Category: "Cloud & Container"},
	{Handle: "0xdade.bsky.social", Name: "Adam Baldwin", Category: "Cloud & Container"},

	// --- Web and AppSec ---
	{Handle: "albinowax.bsky.social", Name: "James Kettle", Category: "Web & AppSec", Description: "PortSwigger research lead"},
	{Handle: "soroush.bsky.social", Name: "Soroush Dalili", Category: "Web & AppSec"},
	{Handle: "filedescriptor.bsky.social", Name: "filedescriptor", Category: "Web & AppSec"},
	{Handle: "jhaddix.bsky.social", Name: "Jason Haddix", Category: "Web & AppSec", Description: "Bug bounty hunter / educator"},
	{Handle: "zseano.bsky.social", Name: "zseano", Category: "Web & AppSec"},
	{Handle: "stokfredrik.bsky.social", Name: "STÖK", Category: "Web & AppSec"},
	{Handle: "nahamsec.bsky.social", Name: "NahamSec", Category: "Web & AppSec"},
	{Handle: "snyff.bsky.social", Name: "Frans Rosén", Category: "Web & AppSec"},
	{Handle: "lupin.bsky.social", Name: "Lupin", Category: "Web & AppSec"},
	{Handle: "intigriti.bsky.social", Name: "Intigriti", Category: "Web & AppSec", Description: "Bug bounty platform"},
	{Handle: "hackerone.bsky.social", Name: "HackerOne", Category: "Web & AppSec"},
	{Handle: "bugcrowd.bsky.social", Name: "Bugcrowd", Category: "Web & AppSec"},

	// --- Journalism and news ---
	{Handle: "zackwhittaker.com", Name: "Zack Whittaker", Category: "Journalism & News", Description: "TechCrunch security reporter"},
	{Handle: "kimzetter.bsky.social", Name: "Kim Zetter", Category: "Journalism & News", Description: "Author, Countdown to Zero Day"},
	{Handle: "josephcox.bsky.social", Name: "Joseph Cox", Category: "Journalism & News", Description: "404 Media co-founder"},
	{Handle: "lawrenceabrams.bsky.social", Name: "Lawrence Abrams", Category: "Journalism & News", Description: "BleepingComputer founder"},
	{Handle: "joemenn.bsky.social", Name: "Joseph Menn", Category: "Journalism & News"},
	{Handle: "carlypage.bsky.social", Name: "Carly Page", Category: "Journalism & News"},
	{Handle: "doublepulsar.com", Name: "Kevin Beaumont", Category: "Journalism & News", Description: "DoublePulsar analysis"},
	{Handle: "theregister.com", Name: "The Register", Category: "Journalism & News"},
	{Handle: "bellingcat.com", Name: "Bellingcat", Category: "Journalism & News", Description: "OSINT investigations"},
	{Handle: "liveuamap.com", Name: "LiveUAMap", Category: "Journalism & News"},
	{Handle: "molly.wiki", Name: "Molly White", Category: "Journalism & News", Description: "Web3 critic, citation needed"},
	{Handle: "cyberhub.blog", Name: "Cyber Hub Blog", Category: "Journalism & News"},
	{Handle: "swiftonsecurity.com", Name: "SwiftOnSecurity", Category: "Journalism & News"},
	{Handle: "brianhonan.bsky.social", Name: "Brian Honan", Category: "Journalism & News"},

	// --- Privacy, policy, and crypto ---
	{Handle: "eff.org", Name: "EFF", Category: "Privacy, Policy & Crypto", Description: "Electronic Frontier Foundation"},
	{Handle: "snowden.bsky.social", Name: "Edward Snowden", Category: "Privacy, Policy & Crypto"},
	{Handle: "evacide.bsky.social", Name: "Eva Galperin", Category: "Privacy, Policy & Crypto", Description: "EFF, stalkerware research"},
	{Handle: "runasand.bsky.social", Name: "Runa Sandvik", Category: "Privacy, Policy & Crypto"},
	{Handle: "shelbygrossman.bsky.social", Name: "Shelby Grossman", Category: "Privacy, Policy & Crypto"},
	{Handle: "stamos.org", Name: "Alex Stamos", Category: "Privacy, Policy & Crypto"},
	{Handle: "k8em0.bsky.social", Name: "Katie Moussouris", Category: "Privacy, Policy & Crypto", Description: "Vuln disclosure policy"},
	{Handle: "matthewdgreen.bsky.social", Name: "Matthew Green", Category: "Privacy, Policy & Crypto", Description: "Applied cryptography, JHU"},
	{Handle: "filippo.abyssdomain.expert", Name: "Filippo Valsorda", Category: "Privacy, Policy & Crypto", Description: "Cryptography engineering"},
	{Handle: "kennethreitz.bsky.social", Name: "Kenneth Reitz", Category: "Privacy, Policy & Crypto", Description: "Python ecosystem"},
}
