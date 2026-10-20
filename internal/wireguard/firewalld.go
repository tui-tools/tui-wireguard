package wireguard

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// This file is the forwarding side of a firewalld host (issue #30).
//
// firewalld keeps its rules in its own nftables table, and a packet has to be
// accepted by every base chain on its hook, so a FORWARD accept inserted with
// iptables forwards nothing when firewalld's forward chain rejects the same
// packet. On such a host the forwarding server's rules are firewalld's own: a
// policy object per interface, and the FORWARD column is read back from
// firewalld's runtime state rather than from `iptables -S`.
//
// The model is two listings, `firewall-cmd --list-all-zones` and
// `firewall-cmd --list-all-policies`, both runtime reads. A read that failed
// (firewalld not running, no firewall-cmd) leaves Running false, and the
// iptables model answers as it always did.

// Firewalld is firewalld's runtime zones and policies.
type Firewalld struct {
	// Running reports that firewalld answered: it is the firewall in charge
	// of forwarding.
	Running bool
	// Error carries why it could not be read, when firewall-cmd exists.
	Error    string
	Zones    []FirewalldZone
	Policies []FirewalldPolicy
}

// FirewalldZone is one zone of `firewall-cmd --list-all-zones`.
type FirewalldZone struct {
	Name       string
	Default    bool
	Active     bool
	Target     string
	Interfaces []string
	Sources    []string
	Forward    bool
	Masquerade bool
	RichRules  []string
}

// FirewalldPolicy is one policy of `firewall-cmd --list-all-policies`.
type FirewalldPolicy struct {
	Name       string
	Active     bool
	Priority   int
	Target     string
	Ingress    []string
	Egress     []string
	Masquerade bool
	RichRules  []string
	// Disabled is firewalld 2.x's "disable: yes", listed as "(disabled)"
	// in the header: the policy is kept but not applied. Fedora 44 ships
	// five gateway-* policies that way.
	Disabled bool
}

// firewalldBlock is one object of a firewall-cmd listing: the header line
// ("public (default, active)"), its "key: value" lines, and its rich rules.
type firewalldBlock struct {
	name   string
	flags  map[string]bool
	fields map[string]string
	rich   []string
}

// parseFirewalldBlocks splits a `--list-all-zones` or `--list-all-policies`
// listing into its objects. An object starts at an unindented line; its
// settings are indented "key: value" lines; the rich rules follow the
// "rich rules:" line, one per line, indented with a tab.
func parseFirewalldBlocks(out string) []firewalldBlock {
	var blocks []firewalldBlock
	var cur *firewalldBlock
	inRich := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, " \r")
		if strings.TrimSpace(line) == "" {
			inRich = false
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			name, flags := line, map[string]bool{}
			if open := strings.IndexByte(line, '('); open > 0 && strings.HasSuffix(line, ")") {
				name = strings.TrimSpace(line[:open])
				for _, f := range strings.Split(line[open+1:len(line)-1], ",") {
					flags[strings.TrimSpace(f)] = true
				}
			}
			if strings.ContainsAny(name, " :") {
				// Not an object header: a message such as "FirewallD is
				// not running".
				cur, inRich = nil, false
				continue
			}
			blocks = append(blocks, firewalldBlock{name: name, flags: flags, fields: map[string]string{}})
			cur, inRich = &blocks[len(blocks)-1], false
			continue
		}
		if cur == nil {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if inRich && (line[0] == '\t' || strings.HasPrefix(trimmed, "rule ")) {
			cur.rich = append(cur.rich, trimmed)
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		cur.fields[key] = strings.TrimSpace(value)
		inRich = key == "rich rules"
	}
	return blocks
}

// ParseFirewalldZones reads `firewall-cmd --list-all-zones`.
func ParseFirewalldZones(out string) []FirewalldZone {
	var zones []FirewalldZone
	for _, b := range parseFirewalldBlocks(out) {
		zones = append(zones, FirewalldZone{
			Name:       b.name,
			Default:    b.flags["default"],
			Active:     b.flags["active"],
			Target:     b.fields["target"],
			Interfaces: strings.Fields(b.fields["interfaces"]),
			Sources:    strings.Fields(b.fields["sources"]),
			Forward:    b.fields["forward"] == "yes",
			Masquerade: b.fields["masquerade"] == "yes",
			RichRules:  b.rich,
		})
	}
	return zones
}

// ParseFirewalldPolicies reads `firewall-cmd --list-all-policies`.
func ParseFirewalldPolicies(out string) []FirewalldPolicy {
	var policies []FirewalldPolicy
	for _, b := range parseFirewalldBlocks(out) {
		priority, _ := strconv.Atoi(b.fields["priority"])
		policies = append(policies, FirewalldPolicy{
			Name:       b.name,
			Active:     b.flags["active"],
			Priority:   priority,
			Target:     b.fields["target"],
			Ingress:    strings.Fields(b.fields["ingress-zones"]),
			Egress:     strings.Fields(b.fields["egress-zones"]),
			Masquerade: b.fields["masquerade"] == "yes",
			RichRules:  b.rich,
			Disabled:   b.fields["disable"] == "yes" || b.flags["disabled"],
		})
	}
	return policies
}

// ZoneOf is the zone firewalld puts an interface in: the zone it is bound
// to, else the default zone, which takes every interface no zone claims.
func (f Firewalld) ZoneOf(iface string) string {
	if zone := f.BoundZone(iface); zone != "" {
		return zone
	}
	return f.DefaultZone()
}

// BoundZone is the zone an interface is explicitly bound to, empty when it
// only falls into the default zone.
func (f Firewalld) BoundZone(iface string) string {
	for _, z := range f.Zones {
		if contains(z.Interfaces, iface) {
			return z.Name
		}
	}
	return ""
}

// DefaultZone is the zone that takes every interface no zone claims.
func (f Firewalld) DefaultZone() string {
	for _, z := range f.Zones {
		if z.Default {
			return z.Name
		}
	}
	return ""
}

// Forwards reports whether firewalld forwards traffic that comes in on
// iface to somewhere other than this host: an active policy whose ingress is
// ANY or iface's zone, whose egress is not only HOST, and which accepts:
// by its target, or by an accept rich rule. A rich rule scoped to a source
// address counts only in the interface's own policy (<iface>-fwd): with
// ingress ANY, the source is what ties such a rule to one interface's peers,
// and the source is not something this read can map back to an interface.
// A zone's intra-zone forwarding
// ("forward: yes") is not counted: it only joins interfaces of one zone, and
// on its own it neither masquerades nor reaches another zone.
func (f Firewalld) Forwards(iface string) bool {
	if !f.Running {
		return false
	}
	zone := f.ZoneOf(iface)
	for _, p := range f.Policies {
		fromIface := contains(p.Ingress, "ANY") || (zone != "" && contains(p.Ingress, zone))
		if !p.Active || p.Disabled || !fromIface {
			continue
		}
		outward := false
		for _, e := range p.Egress {
			if e != "HOST" {
				outward = true
			}
		}
		if !outward {
			continue
		}
		if p.Target == "ACCEPT" {
			return true
		}
		own, _ := FirewalldPolicyName(iface)
		for _, r := range p.RichRules {
			// A rule scoped to a source cannot be told apart from another
			// interface's peers unless the policy is this interface's own.
			if richAction(r) == "accept" && (p.Name == own || !strings.Contains(r, "source ")) {
				return true
			}
		}
	}
	return false
}

// richAction is a rich rule's action: the last of its words that is one
// (accept, reject, drop, mark, masquerade), so a log or audit clause before
// it does not hide it.
func richAction(rule string) string {
	fields := strings.Fields(rule)
	for i := len(fields) - 1; i >= 0; i-- {
		switch fields[i] {
		case "accept", "reject", "drop", "mark", "masquerade":
			return fields[i]
		}
	}
	return ""
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// maxFirewalldName is the longest policy name firewalld accepts: its longest
// iptables chain for a policy leaves 17 characters for the name.
const maxFirewalldName = 17

// FirewalldPolicyName is the policy a forwarding server owns on a firewalld
// host: the interface name and "-fwd", so it is recognisably this
// interface's and PostDown can delete it whole.
func FirewalldPolicyName(iface string) (string, error) {
	name := iface + "-fwd"
	if len(name) > maxFirewalldName {
		return "", fmt.Errorf("interface name %q is too long for a firewalld policy name "+
			"(%s, at most %d characters)", iface, name, maxFirewalldName)
	}
	return name, nil
}

// firewalldForwardingRules is ForwardingRules on a firewalld host. It builds
// one policy owned by the interface:
//
//   - ingress ANY, egress the zone of the egress NIC. What makes the policy
//     the interface's own is its rich rules, which match the peers' network
//     as the source, so the peers' access to the host itself does not change.
//   - one accept and one masquerade rich rule per destination network (or
//     one of each for any destination), scoped to the peers' source network,
//     so nothing else that crosses into that zone is accepted or rewritten.
//   - the return path needs nothing: firewalld accepts established and
//     related traffic before any policy.
//   - when neither the WireGuard interface nor the egress NIC is bound to a
//     zone (bindZone is then the zone they fall into, the default zone),
//     the WireGuard interface is bound to that same zone. That changes
//     nothing for its traffic but gives firewalld an interface to dispatch
//     the policy on: between two interfaces in the default zone's
//     catch-all firewalld generates no forward dispatch for the policy at
//     all, and the packet meets the zone's reject. That is the case of an
//     egress NIC NetworkManager does not manage (a second NIC, a veth).
//     When the egress NIC is bound, as NetworkManager binds the NICs it
//     manages, the lab showed the policy dispatched without it.
//
// No line may contain "&": `wg-quick save` (the `w` key, and the save the
// add-peer flow offers) writes the hooks back through a bash substitution in
// which "&" stands for the matched text, so `2>&1` came back as
// `2>[Interface]` in the lab and the saved conf no longer parsed.
//
// Policies are permanent-only objects in firewalld, so every line is
// --permanent and the last one is a --reload. PostUp first deletes a
// leftover policy of the same name (a crash while the interface was up
// leaves it in the permanent configuration), so up never fails on it;
// PostDown deletes the policy, which takes its rules with it, unbinds the
// interface when PostUp bound it, and reloads.
func firewalldForwardingRules(iface, peers, egressZone, bindZone string, dests []string) (up, down []string, err error) {
	policy, err := FirewalldPolicyName(iface)
	if err != nil {
		return nil, nil, err
	}
	if egressZone == "" || !ValidInterface(egressZone) {
		return nil, nil, fmt.Errorf("not a valid firewalld zone for the egress interface: %q", egressZone)
	}
	if bindZone != "" && !ValidInterface(bindZone) {
		return nil, nil, fmt.Errorf("not a valid firewalld zone for %s: %q", iface, bindZone)
	}
	fc := "firewall-cmd --permanent"
	up = []string{fc + " --delete-policy=" + policy + " -q 2>/dev/null || true"}
	if bindZone != "" {
		up = append(up, fc+" --zone="+bindZone+" --add-interface="+iface)
	}
	up = append(up,
		fc+" --new-policy="+policy,
		fc+" --policy="+policy+" --add-ingress-zone=ANY",
		fc+" --policy="+policy+" --add-egress-zone="+egressZone,
	)
	for _, action := range []string{"accept", "masquerade"} {
		for _, dst := range dests {
			rule := `rule family="ipv4" source address="` + peers + `"`
			if dst != "" {
				rule += ` destination address="` + dst + `"`
			}
			up = append(up, fc+" --policy="+policy+" --add-rich-rule='"+rule+" "+action+"'")
		}
	}
	up = append(up, "firewall-cmd --reload")
	down = []string{fc + " --delete-policy=" + policy}
	if bindZone != "" {
		down = append(down, fc+" --zone="+bindZone+" --remove-interface="+iface)
	}
	down = append(down, "firewall-cmd --reload")
	return up, down, nil
}

// peersNetwork is the peers' network of an interface address in CIDR form.
func peersNetwork(address string) (string, error) {
	own, err := netip.ParsePrefix(address)
	if err != nil || !own.Addr().Is4() {
		return "", fmt.Errorf("forwarding needs an IPv4 interface address, got %q", address)
	}
	return own.Masked().String(), nil
}

// policyNameOr is FirewalldPolicyName for a comment: the name, or the
// interface's own when it is too long (ForwardingRules refuses that case).
func policyNameOr(iface string) string {
	if name, err := FirewalldPolicyName(iface); err == nil {
		return name
	}
	return iface
}
