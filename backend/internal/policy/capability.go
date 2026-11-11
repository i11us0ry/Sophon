package policy

import "strings"

type Capability string

const (
	CapabilityPassive     Capability = "passive"
	CapabilityRead        Capability = "read"
	CapabilityIntrusive   Capability = "intrusive"
	CapabilityDestructive Capability = "destructive"
)

var capabilityRank = map[Capability]int{
	CapabilityPassive:     0,
	CapabilityRead:        1,
	CapabilityIntrusive:   2,
	CapabilityDestructive: 3,
}

func NormalizeCapability(value string) (Capability, bool) {
	capability := Capability(strings.ToLower(strings.TrimSpace(value)))
	_, ok := capabilityRank[capability]
	return capability, ok
}

func (c Capability) Rank() int {
	return capabilityRank[c]
}

// DefaultCapability 对未知工具采取失败关闭策略。
func DefaultCapability(toolName string) Capability {
	capability, _ := defaultCapability(toolName)
	return capability
}

func IsKnownCapabilityTool(toolName string) bool {
	_, known := defaultCapability(toolName)
	return known
}

func defaultCapability(toolName string) (Capability, bool) {
	name := strings.ToLower(strings.TrimSpace(toolName))
	switch {
	case name == "exec",
		name == "execute-python-script",
		name == "install-python-package",
		name == "job":
		return CapabilityDestructive, true
	case name == "read_artifact", name == "read_skill", name == "project_situation",
		strings.HasPrefix(name, "project_"),
		strings.HasPrefix(name, "list_"),
		strings.HasPrefix(name, "get_"),
		strings.HasPrefix(name, "read_"):
		return CapabilityRead, true
	case isKnownIntrusiveTool(name):
		return CapabilityIntrusive, true
	default:
		return CapabilityDestructive, false
	}
}

func isKnownIntrusiveTool(name string) bool {
	switch name {
	case "nmap", "masscan", "nikto", "wpscan", "ffuf", "dirsearch",
		"nuclei", "sqlmap", "hydra", "john", "hashcat", "metasploit",
		"msfconsole", "xsser", "dotdotpwn", "commix", "dalfox",
		"subfinder", "amass", "gobuster", "feroxbuster", "whatweb",
		"wafw00f", "impacket", "responder":
		return true
	default:
		return false
	}
}
