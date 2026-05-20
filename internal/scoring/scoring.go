package scoring

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"strings"
	"sync"
)

type category struct {
	weight    int
	mitreTags []string
	keywords  []string
}

type Scorer struct {
	categories []category
	kevMap     map[string]bool
	mu         sync.RWMutex
}

func New() *Scorer {
	return &Scorer{
		kevMap: make(map[string]bool),
		categories: []category{
			// Execution control + AV/EDR/AMSI/ETW bypass
			{
				weight:    18,
				mitreTags: []string{"T1562.001", "T1218"},
				keywords: []string{
					"application whitelisting bypass",
					"applocker bypass", "wdac bypass",
					"constrained language mode bypass",
					"application control bypass",
					"allowlisting bypass",
					"code integrity bypass",
					"edr bypass", "edr evasion",
					"av bypass", "av evasion",
					"amsi bypass", "etw bypass", "etw patching",
					"unhooking", "defense evasion",
					"antivirus evasion",
				},
			},
			// TIER 1: BYOVD / Driver Abuse
			{
				weight:    18,
				mitreTags: []string{"T1068", "T1562.001"},
				keywords: []string{
					"byovd", "bring your own vulnerable driver",
					"vulnerable driver", "loldriver",
					"kernel driver exploit", "signed driver bypass",
					"terminator edr", "zemana bypass", "procexp bypass",
				},
			},
			// TIER 1: Active exploitation -- something IS running right now
			{
				weight:    16,
				mitreTags: []string{"T1190", "T1203"},
				keywords: []string{
					"zero-day", "zero day", "0day", "0-day",
					"in the wild", "actively exploited",
					"exploitation in the wild",
					"pre-auth", "unauthenticated rce",
				},
			},
			// TIER 2: Unauthorized execution -- all forms
			{
				weight:    14,
				mitreTags: []string{"T1059", "T1486"},
				keywords: []string{
					"malware", "trojan", "backdoor", "implant",
					"virus", "worm",
					"ransomware", "wiper", "cryptominer",
					"rat ", "remote access trojan",
					"infostealer", "stealer", "keylogger",
					"spyware", "adware",
					"loader", "dropper", "stager",
					"downloader",
					"botnet", "bot ",
				},
			},
			// Execution techniques
			{
				weight:    14,
				mitreTags: []string{"T1574.002", "T1055"},
				keywords: []string{
					"dll sideload", "dll hijack", "dll injection",
					"dll proxying", "dll search order",
					"process injection", "process hollowing",
					"thread injection", "apc injection",
					"reflective loading", "reflective dll",
					"shellcode", "code injection",
					"ntdll", "syscall",
					"direct syscall", "indirect syscall",
					"lolbin", "lolbas", "living off the land",
					"trojanized", "trojanised",
				},
			},
			// Code execution exploits
			{
				weight:    14,
				mitreTags: []string{"T1190"},
				keywords: []string{
					"remote code execution", "rce",
					"arbitrary code execution",
					"code execution",
					"command injection",
					"deserialization",
					"buffer overflow", "heap overflow",
					"stack overflow", "use after free",
					"type confusion",
					"sandbox escape",
					"container escape",
				},
			},
			// C2 / post-exploitation frameworks
			{
				weight:    13,
				mitreTags: []string{"T1071"},
				keywords: []string{
					"cobalt strike", "brute ratel", "sliver",
					"meterpreter", "havoc", "mythic",
					"nighthawk", "poshc2",
					"covenant", "merlin",
					"c2 framework", "c2 server",
					"command and control",
					"beacon",
				},
			},
			// Script/macro execution
			{
				weight:    13,
				mitreTags: []string{"T1059"},
				keywords: []string{
					"powershell", "wscript", "cscript",
					"mshta", "regsvr32", "rundll32",
					"msiexec", "certutil", "bitsadmin",
					"macro", "vba", "hta",
					"javascript malware", "jscript",
					"vbscript",
				},
			},
			// Supply chain / trojanized delivery
			{
				weight:    13,
				mitreTags: []string{"T1195"},
				keywords: []string{
					"supply chain attack", "supply-chain",
					"supply chain compromise",
					"dependency confusion",
					"typosquatting",
					"seo poisoning", "malvertising",
					"watering hole",
					"fake update", "fake installer",
					"signed malware", "code signing",
					"hijacked package",
				},
			},
			// Boot/firmware level execution
			{
				weight:    13,
				mitreTags: []string{"T1542"},
				keywords: []string{
					"bootkit", "rootkit",
					"uefi", "firmware",
					"bootloader", "bootsector",
					"mbr ", "bios ",
				},
			},
			// Delivery vectors that lead to execution
			{
				weight:    12,
				mitreTags: []string{"T1566.001"},
				keywords: []string{
					"iso ", "img mount", "vhd ",
					"lnk file", "shortcut",
					"msi ", "msix ",
					"oneNote malware",
					"zip bomb", "archive",
					"html smuggling",
					"qr code phishing",
				},
			},
			// TIER 3: Threat context
			{
				weight:    8,
				mitreTags: []string{},
				keywords: []string{
					"apt", "threat actor", "threat group",
					"nation state", "nation-state",
					"lazarus", "cozy bear", "fancy bear",
					"sandworm", "turla", "kimsuky",
					"mustang panda", "volt typhoon",
					"scattered spider", "alphv", "lockbit",
					"black basta", "cl0p", "clop",
					"akira", "play ransomware", "rhysida",
					"ransomhub", "medusa", "bianlian",
					"royal ransomware", "blacksuit",
					"initial access broker",
				},
			},
			// Detection & defense
			{
				weight:    6,
				mitreTags: []string{},
				keywords: []string{
					"yara", "sigma rule",
					"detection engineering",
					"threat hunting",
					"ioc", "indicator of compromise",
					"incident response", "dfir",
					"forensic",
				},
			},
			// Vulnerability management
			{
				weight:    5,
				mitreTags: []string{},
				keywords: []string{
					"vulnerability", "exploit",
					"privilege escalation", "privesc",
					"kernel exploit",
					"local privilege",
				},
			},
			// General access / movement
			{
				weight:    4,
				mitreTags: []string{"T1566"},
				keywords: []string{
					"phishing", "spearphishing",
					"initial access",
					"credential", "brute force",
					"lateral movement", "persistence",
					"exfiltration",
					"kerberoasting", "mimikatz",
					"lsass", "golden ticket",
					"active directory",
				},
			},
			// Cloud security - misconfigurations, IAM, container escape
			{
				weight:    13,
				mitreTags: []string{"T1078.004", "T1552"},
				keywords: []string{
					"aws", "azure", "gcp", "google cloud",
					"s3 bucket", "s3 misconfig", "exposed bucket",
					"iam misconfiguration", "iam privilege",
					"assume role", "instance metadata",
					"kubernetes", "k8s", "kubelet",
					"container escape", "docker escape",
					"eks", "aks", "gke",
					"terraform", "cloudformation",
					"serverless", "lambda exploit",
					"oauth misconfiguration", "saml misconfiguration",
					"entra id", "azure ad", "azuread",
				},
			},
			// Web application security
			{
				weight:    13,
				mitreTags: []string{"T1190", "T1059.007"},
				keywords: []string{
					"sql injection", "sqli",
					"cross-site scripting", "xss",
					"server-side request forgery", "ssrf",
					"server side request forgery",
					"xxe", "xml external entity",
					"prototype pollution",
					"path traversal", "directory traversal",
					"open redirect", "csrf",
					"insecure deserialization",
					"graphql injection",
					"jwt vulnerability", "jwt bypass",
					"oauth bypass", "saml bypass",
					"web cache poisoning", "request smuggling",
					"http smuggling",
				},
			},
			// Identity & authentication
			{
				weight:    11,
				mitreTags: []string{"T1078", "T1556"},
				keywords: []string{
					"mfa bypass", "2fa bypass",
					"passkey", "fido2",
					"oauth abuse", "oauth phishing",
					"oidc", "openid connect",
					"saml relay", "saml golden",
					"sso compromise",
					"session hijack", "session fixation",
					"cookie theft",
					"refresh token theft",
					"oktajacking",
				},
			},
			// Mobile security
			{
				weight:    10,
				mitreTags: []string{},
				keywords: []string{
					"android malware", "android trojan",
					"ios malware", "iphone exploit",
					"jailbreak", "rooted device",
					"banking trojan", "banking malware",
					"smishing",
					"play store malware", "app store malware",
					"sideload malware",
					"pegasus", "predator spyware",
					"nso", "intellexa",
				},
			},
			// Cryptographic / protocol vulnerabilities
			{
				weight:    9,
				mitreTags: []string{},
				keywords: []string{
					"tls vulnerability", "ssl vulnerability",
					"ssh vulnerability",
					"signature forgery",
					"key recovery",
					"side channel", "side-channel",
					"timing attack",
					"padding oracle",
					"weak entropy", "weak randomness",
					"downgrade attack",
					"quantum threat", "post-quantum",
				},
			},
			// Hardware / firmware / IoT
			{
				weight:    9,
				mitreTags: []string{"T1542"},
				keywords: []string{
					"fault injection", "voltage glitch",
					"hardware backdoor",
					"router exploit", "iot exploit",
					"firmware extraction",
					"baseboard management",
					"bmc compromise", "ipmi",
					"intel me", "amd psp",
					"spectre", "meltdown",
					"rowhammer",
				},
			},
			// Privacy / breach / data leak (newsworthy not technical)
			{
				weight:    7,
				mitreTags: []string{"T1530"},
				keywords: []string{
					"data breach", "data leak",
					"records exposed", "leak site",
					"breach disclosure", "leaked database",
					"customer data exposed",
					"pii exposed", "credentials exposed",
					"ransomware leak",
					"gdpr violation",
				},
			},
			// Detection & response tooling (broader than just IR)
			{
				weight:    7,
				mitreTags: []string{},
				keywords: []string{
					"sigma rule", "yara rule",
					"detection engineering",
					"threat hunting",
					"siem rule", "splunk query",
					"sentinel query", "kql",
					"velociraptor", "osquery",
					"sysmon",
					"purple team",
				},
			},
			// Platform-specific context
			{
				weight:    3,
				mitreTags: []string{},
				keywords: []string{
					"windows", "linux", "macos",
					"endpoint", "edr", "xdr",
					"patch tuesday", "security update",
					"advisory", "hotfix",
					"cisa kev",
				},
			},
		},
	}
}

// UpdateKEV downloads the official CISA KEV catalog and stores it in memory
func (s *Scorer) UpdateKEV() {
	resp, err := http.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if err != nil {
		log.Printf("[KEV] fetch error: %v", err)
		return
	}
	defer resp.Body.Close()

	var data struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Printf("[KEV] decode error: %v", err)
		return
	}

	newMap := make(map[string]bool)
	for _, v := range data.Vulnerabilities {
		newMap[strings.ToUpper(v.CveID)] = true
	}

	s.mu.Lock()
	s.kevMap = newMap
	s.mu.Unlock()
	log.Printf("[KEV] Loaded %d known exploited vulnerabilities from CISA", len(s.kevMap))
}

// CategoryInfo is the JSON shape exposed to the UI so users can see what we
// score against. Keep parallel to the slice inside New().
type CategoryInfo struct {
	Name      string   `json:"name"`
	Weight    int      `json:"weight"`
	MITRETags []string `json:"mitre_tags"`
	Keywords  []string `json:"keywords"`
}

// categoryNames is positional - same order as the categories slice in New().
// Update this when reordering / adding / removing categories.
var categoryNames = []string{
	"Execution control / AV / EDR / AMSI / ETW bypass",
	"BYOVD / vulnerable-driver abuse",
	"Active exploitation in the wild",
	"Malware family / unauthorized execution",
	"Process injection / DLL hijacking / LOLBins",
	"Code execution exploits (RCE, container escape)",
	"C2 / post-exploitation frameworks",
	"Script + macro execution (PowerShell, MSHTA, etc.)",
	"Supply chain / trojanized delivery",
	"Bootkit / rootkit / firmware-level execution",
	"Delivery vectors (ISO, LNK, MSI, smuggling)",
	"Threat actor + APT context",
	"Detection engineering + threat hunting",
	"Vulnerability management + privesc",
	"General access + lateral movement",
	"Cloud security (AWS, Azure, GCP, K8s)",
	"Web app security (SQLi, XSS, SSRF, etc.)",
	"Identity + authentication",
	"Mobile security",
	"Cryptographic + protocol vulns",
	"Hardware + firmware + IoT",
	"Privacy / breach / data leak",
	"Detection + response tooling",
	"Platform-specific context",
}

// Categories returns the scoring rules in a JSON-friendly shape. The UI
// renders this to show what "security-related" actually means here.
func (s *Scorer) Categories() []CategoryInfo {
	out := make([]CategoryInfo, 0, len(s.categories))
	for i, c := range s.categories {
		name := ""
		if i < len(categoryNames) {
			name = categoryNames[i]
		}
		out = append(out, CategoryInfo{
			Name:      name,
			Weight:    c.weight,
			MITRETags: append([]string(nil), c.mitreTags...),
			Keywords:  append([]string(nil), c.keywords...),
		})
	}
	return out
}

func (s *Scorer) Score(article *models.Article) (int, []string) {
	text := strings.ToLower(article.Title + " " + article.Summary)
	score := 0
	tagSet := make(map[string]bool)
	hasKEVMatch := false

	// 1. Keyword Scoring & MITRE Mapping
	for _, cat := range s.categories {
		hit := false
		for _, kw := range cat.keywords {
			if strings.Contains(text, kw) {
				score += cat.weight
				tag := normalizeTag(kw)
				tagSet[tag] = true
				hit = true
			}
		}
		if hit {
			for _, mTag := range cat.mitreTags {
				tagSet[mTag] = true
			}
		}
	}

	// 2. Automated IOC Extraction (Hashes)
	sha256Re := regexp.MustCompile(`\b[a-f0-9]{64}\b`)
	for _, hash := range sha256Re.FindAllString(text, -1) {
		tagSet["sha256:"+hash] = true
	}

	md5Re := regexp.MustCompile(`\b[a-f0-9]{32}\b`)
	for _, hash := range md5Re.FindAllString(text, -1) {
		tagSet["md5:"+hash] = true
	}

	// 3. Application Control Artifact Extraction (What Ran?)
	artifactRe := regexp.MustCompile(`(?i)\b([a-z0-9_-]+\.(exe|dll|sys|ps1|vbs|bat|cmd|hta|js|iso|msi|lnk))\b`)
	for _, match := range artifactRe.FindAllStringSubmatch(text, -1) {
		if len(match) > 1 {
			tagSet["artifact:"+strings.ToLower(match[1])] = true
		}
	}

	// 4. CVE Extraction & CISA KEV Cross-Reference
	cveRe := regexp.MustCompile(`(?i)cve-\d{4}-\d{4,7}`)

	s.mu.RLock()
	for _, cve := range cveRe.FindAllString(text, -1) {
		cveUpper := strings.ToUpper(cve)

		// Is this CVE in the official CISA KEV list?
		if s.kevMap[cveUpper] {
			tagSet["kev:"+cveUpper] = true
			hasKEVMatch = true
		} else {
			tagSet[cveUpper] = true
		}
	}
	s.mu.RUnlock()

	// If the article mentions a KEV, instantly escalate its score to maximum
	if hasKEVMatch {
		score = 100
	} else if score > 100 {
		score = 100
	}

	var tags []string
	for t := range tagSet {
		tags = append(tags, t)
	}
	return score, tags
}

func normalizeTag(kw string) string {
	replacer := strings.NewReplacer(
		"zero-day", "zero-day",
		"zero day", "zero-day",
		"0day", "zero-day",
		"0-day", "zero-day",
		"remote code execution", "rce",
		"arbitrary code execution", "rce",
		"code execution", "rce",
		"privilege escalation", "privesc",
		"local privilege", "privesc",
		"dll sideload", "dll-attack",
		"dll hijack", "dll-attack",
		"dll injection", "dll-attack",
		"dll proxying", "dll-attack",
		"dll search order", "dll-attack",
		"process injection", "injection",
		"process hollowing", "injection",
		"thread injection", "injection",
		"apc injection", "injection",
		"code injection", "injection",
		"living off the land", "lolbin",
		"command and control", "c2",
		"supply chain attack", "supply-chain",
		"supply chain compromise", "supply-chain",
		"supply-chain", "supply-chain",
		"active directory", "ad",
		"remote access trojan", "rat",
		"application whitelisting bypass", "awl-bypass",
		"application control bypass", "awl-bypass",
		"allowlisting bypass", "awl-bypass",
		"applocker bypass", "awl-bypass",
		"wdac bypass", "awl-bypass",
		"constrained language mode bypass", "clm-bypass",
		"code integrity bypass", "ci-bypass",
		"indicator of compromise", "ioc",
		"incident response", "dfir",
		"seo poisoning", "seo-poisoning",
		"dependency confusion", "supply-chain",
		"typosquatting", "supply-chain",
		"html smuggling", "smuggling",
		"sandbox escape", "escape",
		"container escape", "escape",
		"edr bypass", "edr-bypass",
		"edr evasion", "edr-bypass",
		"av bypass", "av-bypass",
		"av evasion", "av-bypass",
		"antivirus evasion", "av-bypass",
		"amsi bypass", "amsi-bypass",
		"etw bypass", "etw-bypass",
		"etw patching", "etw-bypass",
		"defense evasion", "evasion",
		"reflective loading", "reflective-load",
		"reflective dll", "reflective-load",
		"direct syscall", "syscall",
		"indirect syscall", "syscall",
		"bring your own vulnerable driver", "byovd",
		"vulnerable driver", "byovd",
		"loldriver", "byovd",
	)
	tag := replacer.Replace(kw)
	tag = strings.TrimSpace(tag)
	return tag
}
