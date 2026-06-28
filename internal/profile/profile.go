package profile

import "fmt"

// Settings holds boolean flags that profiles can enable.
type Settings struct {
	DoAxfr         bool
	DoDork         bool
	DoZoneWalk     bool
	DoProbe        bool
	DoTakeover     bool
	DoPerm         bool
	DoPortScan     bool
	DoRecursive    int
	DoHeaders      bool
	DoCORS         bool
	DoSSL          bool
	DoWAF          bool
	DoFavicon      bool
	DoASN          bool
	DoJS           bool
	DoAdmin        bool
	DoExposed      bool
	DoBuckets      bool
	DoOpenRedirect bool
	DoDefaultCreds bool
	DoCDNBypass    bool
	DoBanner       bool
	DoAPIDiscover  bool
	DoWhois        bool
	DoCertCorr     bool
	DoNeighbors    bool
	DoSummary      bool
}

const (
	ProfileBugBounty = "bug-bounty"
	ProfileOSINT     = "osint"
	ProfileStealth   = "stealth"
	ProfileFull      = "full"
	ProfileQuick     = "quick"
)

var Descriptions = map[string]string{
	ProfileBugBounty: "Full active + security audit (bug bounty recon)",
	ProfileOSINT:     "Passive only + enrichment (OSINT, no active probing)",
	ProfileStealth:   "Passive sources only, low noise",
	ProfileFull:      "Everything enabled",
	ProfileQuick:     "Fast passive enumeration only",
}

// Apply returns settings pre-configured for the given profile name.
func Apply(name string) (*Settings, error) {
	s := &Settings{}
	switch name {
	case ProfileBugBounty:
		s.DoAxfr = true
		s.DoProbe = true
		s.DoTakeover = true
		s.DoPerm = true
		s.DoPortScan = true
		s.DoHeaders = true
		s.DoCORS = true
		s.DoSSL = true
		s.DoWAF = true
		s.DoJS = true
		s.DoAdmin = true
		s.DoExposed = true
		s.DoBuckets = true
		s.DoOpenRedirect = true
		s.DoDefaultCreds = true
		s.DoCDNBypass = true
		s.DoAPIDiscover = true
		s.DoSummary = true

	case ProfileOSINT:
		s.DoWhois = true
		s.DoASN = true
		s.DoCertCorr = true
		s.DoDork = true
		s.DoProbe = true
		s.DoFavicon = true
		s.DoSummary = true

	case ProfileStealth:
		// Passive sources only — no active probing
		s.DoSummary = true

	case ProfileFull:
		s.DoAxfr = true
		s.DoDork = true
		s.DoZoneWalk = true
		s.DoProbe = true
		s.DoTakeover = true
		s.DoPerm = true
		s.DoPortScan = true
		s.DoHeaders = true
		s.DoCORS = true
		s.DoSSL = true
		s.DoWAF = true
		s.DoFavicon = true
		s.DoASN = true
		s.DoJS = true
		s.DoAdmin = true
		s.DoExposed = true
		s.DoBuckets = true
		s.DoOpenRedirect = true
		s.DoDefaultCreds = true
		s.DoCDNBypass = true
		s.DoBanner = true
		s.DoAPIDiscover = true
		s.DoWhois = true
		s.DoCertCorr = true
		s.DoNeighbors = true
		s.DoSummary = true

	case ProfileQuick:
		s.DoSummary = true

	default:
		return nil, fmt.Errorf("unknown profile %q — valid: bug-bounty, osint, stealth, full, quick", name)
	}
	return s, nil
}

// List prints all available profiles with descriptions.
func List() {
	fmt.Println("Available profiles:")
	for _, name := range []string{ProfileQuick, ProfileStealth, ProfileOSINT, ProfileBugBounty, ProfileFull} {
		fmt.Printf("  %-15s %s\n", name, Descriptions[name])
	}
}
