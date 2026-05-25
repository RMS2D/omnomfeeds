// Package actors matches well-known threat actor groups and malware
// families in article text, emitting "actor:<slug>" / "malware:<slug>" tags.
// Lists are hand-curated for lower noise vs MITRE auto-import.
package actors

import (
	"regexp"
	"strings"
)

// Actor is one named threat group. Display is the canonical form the
// frontend shows on the chip. Aliases are case-insensitive substrings
// used for detection (word-boundary matched at runtime).
type Actor struct {
	Slug    string
	Display string
	Aliases []string
	Origin  string // ISO-ish country code or "??" if attribution unclear
}

// Actors is the curated list. Aliases should be LOWERCASE - the
// matcher lowercases the haystack before checking.
var Actors = []Actor{
	{"apt41", "APT41", []string{"apt41", "apt-41", "double dragon", "winnti group", "barium"}, "CN"},
	{"apt28", "APT28 / Fancy Bear", []string{"apt28", "apt-28", "fancy bear", "sofacy", "strontium", "forest blizzard"}, "RU"},
	{"apt29", "APT29 / Cozy Bear", []string{"apt29", "apt-29", "cozy bear", "midnight blizzard", "nobelium", "the dukes"}, "RU"},
	{"apt38", "Lazarus / APT38", []string{"lazarus group", "lazarus", "apt38", "apt-38", "hidden cobra"}, "KP"},
	{"sandworm", "Sandworm", []string{"sandworm", "unit 74455", "voodoo bear", "iron viking"}, "RU"},
	{"turla", "Turla", []string{"turla", "snake group", "venomous bear", "waterbug"}, "RU"},
	{"fin7", "FIN7", []string{"fin7", "fin-7", "carbanak", "carbon spider"}, "??"},
	{"scatteredspider", "Scattered Spider", []string{"scattered spider", "muddled libra", "octo tempest", "0ktapus"}, "??"},
	{"volttyphoon", "Volt Typhoon", []string{"volt typhoon", "voltzite"}, "CN"},
	{"saltphoon", "Salt Typhoon", []string{"salt typhoon"}, "CN"},
	{"flaxtyphoon", "Flax Typhoon", []string{"flax typhoon"}, "CN"},
	{"kimsuky", "Kimsuky", []string{"kimsuky", "thallium", "velvet chollima"}, "KP"},
	{"andariel", "Andariel", []string{"andariel"}, "KP"},
	{"muddywater", "MuddyWater", []string{"muddywater", "muddy water", "static kitten"}, "IR"},
	{"oilrig", "OilRig / APT34", []string{"oilrig", "apt34", "apt-34", "helix kitten"}, "IR"},
	{"agriusgroup", "Agrius", []string{"agrius group", "agrius apt"}, "IR"},
	// Ransomware operators
	{"lockbit", "LockBit", []string{"lockbit", "lockbit 3.0", "lockbit 4.0", "lockbit ransomware"}, "??"},
	{"alphv", "ALPHV / BlackCat", []string{"alphv", "blackcat ransomware", "alphv/blackcat", "noberus"}, "??"},
	{"clop", "Clop", []string{"clop ransomware", "cl0p", "ta505"}, "??"},
	{"akira", "Akira", []string{"akira ransomware", "akira group"}, "??"},
	{"play", "Play", []string{"play ransomware", "playcrypt"}, "??"},
	{"royal", "Royal", []string{"royal ransomware", "blacksuit"}, "??"},
	{"qilin", "Qilin", []string{"qilin ransomware", "agenda ransomware"}, "??"},
	{"medusa", "Medusa", []string{"medusa ransomware", "medusa locker"}, "??"},
	{"rhysida", "Rhysida / Vice Society", []string{"rhysida", "vice society"}, "??"},
	{"ransomhub", "RansomHub", []string{"ransomhub"}, "??"},
	{"dragonforce", "DragonForce", []string{"dragonforce", "dragonforce ransomware"}, "??"},
	{"interlock", "Interlock", []string{"interlock ransomware"}, "??"},
}

// Malware is a tracked malware family.
type Malware struct {
	Slug    string
	Display string
	Aliases []string
	Kind    string // c2 | loader | stealer | rat | ransomware | worm | credential | webshell
}

// Malwares is the curated list. Aliases should be LOWERCASE.
var Malwares = []Malware{
	// Offensive C2 frameworks
	{"cobaltstrike", "Cobalt Strike", []string{"cobalt strike", "cobaltstrike", "cs beacon"}, "c2"},
	{"sliver", "Sliver", []string{"sliver framework", "sliver c2", "sliver implant"}, "c2"},
	{"bruteratel", "Brute Ratel", []string{"brute ratel", "bruteratel", "br c4"}, "c2"},
	{"havoc", "Havoc", []string{"havoc framework", "havoc c2"}, "c2"},
	{"mythic", "Mythic", []string{"mythic c2", "mythic framework"}, "c2"},
	{"meterpreter", "Meterpreter", []string{"meterpreter"}, "c2"},
	{"empire", "Empire", []string{"powershell empire", "empire framework"}, "c2"},
	// Credential / dumping
	{"mimikatz", "Mimikatz", []string{"mimikatz", "kekeo"}, "credential"},
	// Loaders
	{"emotet", "Emotet", []string{"emotet"}, "loader"},
	{"trickbot", "TrickBot", []string{"trickbot", "trickloader"}, "loader"},
	{"qakbot", "QakBot", []string{"qakbot", "qbot", "pinkslipbot"}, "loader"},
	{"icedid", "IcedID", []string{"icedid", "bokbot"}, "loader"},
	{"darkgate", "DarkGate", []string{"darkgate"}, "loader"},
	{"latrodectus", "Latrodectus", []string{"latrodectus", "icenova"}, "loader"},
	{"smokeloader", "SmokeLoader", []string{"smokeloader", "smoke loader"}, "loader"},
	{"gootloader", "GootLoader", []string{"gootloader", "gootkit"}, "loader"},
	{"bumblebee", "BumbleBee", []string{"bumblebee loader"}, "loader"},
	// Info-stealers
	{"redline", "RedLine", []string{"redline stealer", "redline malware"}, "stealer"},
	{"raccoon", "Raccoon Stealer", []string{"raccoon stealer", "raccoon v2"}, "stealer"},
	{"vidar", "Vidar", []string{"vidar stealer", "vidar malware"}, "stealer"},
	{"lumma", "Lumma", []string{"lumma stealer", "lummac2", "lumma c2"}, "stealer"},
	{"stealc", "StealC", []string{"stealc malware", "stealc stealer"}, "stealer"},
	{"agenttesla", "Agent Tesla", []string{"agent tesla", "agenttesla"}, "stealer"},
	{"formbook", "FormBook", []string{"formbook", "form book"}, "stealer"},
	// RATs
	{"asyncrat", "AsyncRAT", []string{"asyncrat", "async rat"}, "rat"},
	{"njrat", "njRAT", []string{"njrat", "bladabindi"}, "rat"},
	{"warzone", "Warzone RAT", []string{"warzone rat", "ave maria"}, "rat"},
	{"remcos", "Remcos", []string{"remcos rat", "remcos malware"}, "rat"},
	{"netwire", "NetWire", []string{"netwire rat"}, "rat"},
	// Worms
	{"shaihulud", "Shai-Hulud", []string{"shai-hulud", "shaihulud worm"}, "worm"},
	{"raspberryrobin", "Raspberry Robin", []string{"raspberry robin"}, "worm"},
	// Web shells
	{"chinachopper", "China Chopper", []string{"china chopper"}, "webshell"},
	{"behinder", "Behinder", []string{"behinder", "ice scorpion"}, "webshell"},
}

// Extract scans the article's title + summary + existing tags for any
// known actor or malware-family name. Returns matched tags in the form
//
//	actor:<slug>|<display>
//	malware:<slug>|<display>
//
// The `|<display>` suffix lets the frontend render the proper name
// (e.g. "Scattered Spider") on the chip without a separate lookup
// round-trip, while the slug stays available for click-to-filter and
// the click-to-modal endpoint.
//
// Case-insensitive word-boundary match. Empty result is the common
// case (most articles don't reference named actors).
func Extract(title, summary string, tags []string) []string {
	haystack := strings.ToLower(title + "  " + summary + "  " + strings.Join(tags, " "))
	var out []string
	seen := map[string]bool{}
	for _, a := range Actors {
		for _, alias := range a.Aliases {
			if matchWord(haystack, alias) {
				tag := "actor:" + a.Slug + "|" + a.Display
				if !seen[tag] {
					seen[tag] = true
					out = append(out, tag)
				}
				break
			}
		}
	}
	for _, m := range Malwares {
		for _, alias := range m.Aliases {
			if matchWord(haystack, alias) {
				tag := "malware:" + m.Slug + "|" + m.Display
				if !seen[tag] {
					seen[tag] = true
					out = append(out, tag)
				}
				break
			}
		}
	}
	return out
}

// matchWord checks haystack for needle with regex word-boundary.
// Compiles a fresh regex per call - the list is small enough that the
// compile cost is dwarfed by the article-text scan. Pre-screen with
// strings.Contains to skip regex on most misses.
func matchWord(haystack, needle string) bool {
	if !strings.Contains(haystack, needle) {
		return false
	}
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(needle) + `\b`)
	return re.MatchString(haystack)
}

// FindActor returns the Actor record for a given slug, or nil if not
// found. Powers the "what does this chip mean?" tooltip / insight card.
func FindActor(slug string) *Actor {
	for i := range Actors {
		if Actors[i].Slug == slug {
			return &Actors[i]
		}
	}
	return nil
}

// FindMalware is the malware-family equivalent of FindActor.
func FindMalware(slug string) *Malware {
	for i := range Malwares {
		if Malwares[i].Slug == slug {
			return &Malwares[i]
		}
	}
	return nil
}
