package wireguard

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// This file is the other half of a WireGuard server: an interface that
// peers use to reach networks behind this host needs the kernel to forward
// their packets, the host firewall to let them through in both directions,
// and NAT so the networks behind can answer. `N` used to write a conf whose
// PostUp only loaded the key, and all of that had to be done by hand.
//
// It is written as PostUp/PostDown lines in the interface's own conf, so it
// comes and goes with the interface, and the confirm dialog shows every line
// before the file is written.

// Route is one entry of `ip -j route`: enough of it to propose the networks a
// forwarding server forwards to, and the NIC it forwards through.
type Route struct {
	Dst     string   `json:"dst"`
	Gateway string   `json:"gateway,omitempty"`
	Dev     string   `json:"dev"`
	Scope   string   `json:"scope,omitempty"`
	Flags   []string `json:"flags,omitempty"`
}

// ParseRoutes reads `ip -j route`.
func ParseRoutes(data []byte) ([]Route, error) {
	var routes []Route
	if err := json.Unmarshal(data, &routes); err != nil {
		return nil, fmt.Errorf("ip -j route: %w", err)
	}
	return routes, nil
}

// DefaultRouteDevice is the NIC the default route leaves through: the
// proposed egress of a forwarding server.
func DefaultRouteDevice(routes []Route) string {
	for _, r := range routes {
		if r.Dst == "default" && ValidInterface(r.Dev) {
			return r.Dev
		}
	}
	return ""
}

// ForwardCandidates are the networks this host can reach directly, which a
// forwarding server most often forwards to: every IPv4 network route that is
// not the default, not a single host, not link-local, not on a link that is
// down, and not on one of the skip devices (the WireGuard interfaces
// themselves).
func ForwardCandidates(routes []Route, skip map[string]bool) []string {
	linkLocal := netip.MustParsePrefix("169.254.0.0/16")
	seen := map[string]bool{}
	var out []string
	for _, r := range routes {
		prefix, err := netip.ParsePrefix(r.Dst)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() >= 32 || prefix.Bits() == 0 ||
			linkLocal.Overlaps(prefix) || skip[r.Dev] || hasFlag(r.Flags, "linkdown") {
			continue
		}
		p := prefix.Masked().String()
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// ForwardSpec is what makes a new interface a forwarding server: the
// networks its peers reach through it (empty: any destination), and the NIC
// the traffic leaves by.
type ForwardSpec struct {
	Networks []string
	Egress   string
	// Manager is ManagerFirewalld when firewalld was running when the
	// interface was created: its rules are then a firewalld policy instead
	// of iptables rules (issue #30). EgressZone is the zone firewalld puts
	// the egress NIC in, which the policy forwards to.
	Manager    string
	EgressZone string
	// BindZone is set when the WireGuard interface is not bound to a
	// firewalld zone: the zone it falls into, which PostUp binds it to so
	// firewalld has an interface to dispatch the policy on.
	BindZone string
}

// SplitList reads a human-typed list, separated by commas or spaces, into
// its entries.
func SplitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ParseNetworks reads the typed "forwards traffic for" list: IPv4 networks in
// CIDR form, normalised to their network address. IPv6 is refused rather than
// half-done: the rules are iptables, not ip6tables.
func ParseNetworks(s string) ([]string, error) {
	var out []string
	for _, entry := range SplitList(s) {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("not a network in CIDR form (such as 10.0.0.0/16): %q", entry)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%s is IPv6: the forwarding rules are IPv4 (iptables) only", entry)
		}
		out = append(out, prefix.Masked().String())
	}
	return out, nil
}

// Validate checks the spec.
func (f ForwardSpec) Validate() error {
	if !ValidInterface(f.Egress) {
		return fmt.Errorf("not a valid egress interface: %q", f.Egress)
	}
	if _, err := ParseNetworks(strings.Join(f.Networks, " ")); err != nil {
		return err
	}
	return nil
}

// ForwardingRules renders the PostUp and PostDown lines of a forwarding
// server whose own address is address (the interface's Address=, in CIDR
// form: the peers' network is its masked prefix).
//
//   - net.ipv4.ip_forward is not here: a hook that sets it is denied by
//     Ubuntu 26.04's AppArmor profile for wg-quick, so the tool sets it in
//     its own previewed step (BuildEnableForwarding, issue #33).
//   - FORWARD rules are inserted (-I), never appended: a ruleset whose
//     FORWARD chain ends in REJECT would never reach an appended rule. The
//     return path is accepted by connection tracking only, so nothing behind
//     the host can open a connection towards the peers.
//   - MASQUERADE makes the traffic leave with the host's own address, so the
//     networks behind need no route back to the peers.
//
// On a firewalld host (spec.Manager) the same intent is a firewalld policy
// instead: see firewalldForwardingRules. iface names that policy.
func ForwardingRules(iface, address string, spec ForwardSpec) (up, down []string, err error) {
	if err := spec.Validate(); err != nil {
		return nil, nil, err
	}
	peers, err := peersNetwork(address)
	if err != nil {
		return nil, nil, err
	}
	egress := spec.Egress

	dests := spec.Networks
	if len(dests) == 0 {
		dests = []string{""}
	}
	if spec.Manager == ManagerFirewalld {
		return firewalldForwardingRules(iface, peers, spec.EgressZone, spec.BindZone, dests)
	}

	var rules []string
	for _, dst := range dests {
		d := ""
		if dst != "" {
			d = " -d " + dst
		}
		rules = append(rules, "FORWARD -i %i -o "+egress+d+" -j ACCEPT")
	}
	rules = append(rules, "FORWARD -i "+egress+" -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	var nat []string
	for _, dst := range dests {
		d := ""
		if dst != "" {
			d = " -d " + dst
		}
		nat = append(nat, "POSTROUTING -s "+peers+" -o "+egress+d+" -j MASQUERADE")
	}

	for _, r := range rules {
		up = append(up, "iptables -I "+r)
		down = append(down, "iptables -D "+r)
	}
	for _, r := range nat {
		up = append(up, "iptables -t nat -I "+r)
		down = append(down, "iptables -t nat -D "+r)
	}
	return up, down, nil
}

// BuildOpenListenPort assembles the runtime rule that lets handshakes reach a
// listen port: inserted at the top of INPUT, so a trailing REJECT (the
// provider image case) cannot shadow it. It is not persisted: it is gone at
// the next reboot or firewall reload, which the dialog says.
func BuildOpenListenPort(port int) (runner.Command, error) {
	if port < 1 || port > 65535 {
		return runner.Command{}, fmt.Errorf("not a valid listen port: %d", port)
	}
	p := strconv.Itoa(port)
	return runner.Command{
		Argv:        []string{"iptables", "-I", "INPUT", "-p", "udp", "--dport", p, "-j", "ACCEPT"},
		Description: "Open udp/" + p + " in the host firewall (until reboot)",
	}, nil
}

// BuildOpenListenPortFor is BuildOpenListenPort for the firewall manager the
// input read recognised. firewalld rejects in its own nftables table whatever
// its zones do not allow, before or after iptables' INPUT chain, so a port
// there is opened with `firewall-cmd --add-port`, in the running
// configuration only, like the iptables rule. Any other host gets the
// iptables rule.
func BuildOpenListenPortFor(manager string, port int) (runner.Command, error) {
	if manager != ManagerFirewalld {
		return BuildOpenListenPort(port)
	}
	if port < 1 || port > 65535 {
		return runner.Command{}, fmt.Errorf("not a valid listen port: %d", port)
	}
	p := strconv.Itoa(port)
	return runner.Command{
		Argv:        []string{"firewall-cmd", "--add-port=" + p + "/udp"},
		Description: "Open udp/" + p + " in firewalld (until reload)",
	}, nil
}

// BuildOpenListenPortPermanent opens a listen port in firewalld's permanent
// configuration only. It is the port step of a forwarding server on a
// firewalld host: that interface's PostUp ends in `firewall-cmd --reload`,
// which drops runtime-only changes, and applies this one.
func BuildOpenListenPortPermanent(port int) (runner.Command, error) {
	if port < 1 || port > 65535 {
		return runner.Command{}, fmt.Errorf("not a valid listen port: %d", port)
	}
	p := strconv.Itoa(port)
	return runner.Command{
		Argv:        []string{"firewall-cmd", "--permanent", "--add-port=" + p + "/udp"},
		Description: "Open udp/" + p + " in firewalld's permanent configuration (active at the next reload)",
	}, nil
}

// TUIFirewallSearchPaths are where tui-firewall is installed by its packages
// and by `make install`.
var TUIFirewallSearchPaths = []string{"/usr/bin/tui-firewall", "/usr/local/bin/tui-firewall"}
