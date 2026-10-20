package wireguard

import (
	"reflect"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/runner"
)

// TestCloudImageFirewall is the real case: the provider image's INPUT chain
// ends in REJECT, so the WireGuard port was closed with the cloud's own
// security list open, and FORWARD ends in REJECT too.
func TestCloudImageFirewall(t *testing.T) {
	fw := ParseIptablesRules(readFixture(t, "iptables-cloud-image.txt"))
	input := iptablesInput(t, readFixture(t, "iptables-cloud-image.txt"))
	for port, want := range map[int]Verdict{
		51820: VerdictReject, // the interface's port: the finding
		41641: VerdictAccept, // opened by a udp rule above the REJECT
		22:    VerdictReject, // tcp only
		443:   VerdictReject, // tcp only
	} {
		if got := input.UDPVerdict(port); got != want {
			t.Errorf("udp/%d = %s, want %s", port, got, want)
		}
	}
	if fw.Forwards("wg0") {
		t.Error("the image forwards nothing for wg0")
	}
	// The quoted --comment is one argument: the rule keeps its target.
	rules := fw.Rules["InstanceServices"]
	if len(rules) == 0 || rules[0][len(rules[0])-1] != "ACCEPT" {
		t.Errorf("a quoted comment split the rule: %q", rules[0])
	}

	// The runtime rule the wizard previews, inserted at the top, opens it.
	f := &Fake{firewall: strings.Split(strings.TrimSpace(readFixture(t, "iptables-cloud-image.txt")), "\n")}
	cmd, _ := BuildOpenListenPort(51820)
	if err := f.iptables(cmd.Argv[1:]); err != nil {
		t.Fatal(err)
	}
	if got := iptablesInput(t, strings.Join(f.firewall, "\n")).UDPVerdict(51820); got != VerdictAccept {
		t.Errorf("after the insert udp/51820 = %s", got)
	}
}

// TestUFWFirewall follows jumps into user chains, and does not count a rule
// that only some senders match.
func TestUFWFirewall(t *testing.T) {
	fw := iptablesInput(t, readFixture(t, "iptables-ufw.txt"))
	if fw.Manager != ManagerUFW {
		t.Errorf("manager = %q, want ufw from its chains", fw.Manager)
	}
	for port, want := range map[int]Verdict{
		51820: VerdictAccept,
		60500: VerdictAccept, // a multiport range
		41641: VerdictAccept, // a multiport list entry
		5353:  VerdictDrop,   // accepted for one source only
		68:    VerdictDrop,   // needs a source port
		1234:  VerdictDrop,   // the policy
		137:   VerdictDrop,   // RETURN, then the policy
	} {
		if got := fw.UDPVerdict(port); got != want {
			t.Errorf("udp/%d = %s, want %s", port, got, want)
		}
	}
	if got := (InputFirewall{}).UDPVerdict(51820); got != VerdictUnknown {
		t.Errorf("an unread firewall = %s, want unknown", got)
	}
}

func TestRoutes(t *testing.T) {
	routes, err := ParseRoutes([]byte(readFixture(t, "ip-route.json")))
	if err != nil {
		t.Fatal(err)
	}
	if got := DefaultRouteDevice(routes); got != "ens3" {
		t.Errorf("default device = %q", got)
	}
	got := ForwardCandidates(routes, map[string]bool{"wg0": true})
	if !reflect.DeepEqual(got, []string{"198.51.100.0/24"}) {
		t.Errorf("candidates = %q: want the NIC's network only (no default, host, "+
			"link-local, linkdown or WireGuard route)", got)
	}
}

func TestParseNetworks(t *testing.T) {
	got, err := ParseNetworks("198.51.100.7/24, 192.0.2.0/25")
	if err != nil || !reflect.DeepEqual(got, []string{"198.51.100.0/24", "192.0.2.0/25"}) {
		t.Errorf("ParseNetworks = %q, %v", got, err)
	}
	for _, bad := range []string{"2001:db8::/32", "198.51.100.0", "not-a-net"} {
		if _, err := ParseNetworks(bad); err == nil {
			t.Errorf("ParseNetworks(%q) accepted it", bad)
		}
	}
	if got, err := ParseNetworks(""); err != nil || len(got) != 0 {
		t.Errorf("empty = %q, %v", got, err)
	}
}

func TestForwardingRules(t *testing.T) {
	up, down, err := ForwardingRules("wg0", "192.0.2.1/24",
		ForwardSpec{Networks: []string{"198.51.100.0/24"}, Egress: "ens3"})
	if err != nil {
		t.Fatal(err)
	}
	// No sysctl hook: Ubuntu 26.04's AppArmor profile for wg-quick denies
	// it, and the tool sets the switch in its own step (issue #33).
	wantUp := []string{
		"iptables -I FORWARD -i %i -o ens3 -d 198.51.100.0/24 -j ACCEPT",
		"iptables -I FORWARD -i ens3 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"iptables -t nat -I POSTROUTING -s 192.0.2.0/24 -o ens3 -d 198.51.100.0/24 -j MASQUERADE",
	}
	wantDown := []string{
		"iptables -D FORWARD -i %i -o ens3 -d 198.51.100.0/24 -j ACCEPT",
		"iptables -D FORWARD -i ens3 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"iptables -t nat -D POSTROUTING -s 192.0.2.0/24 -o ens3 -d 198.51.100.0/24 -j MASQUERADE",
	}
	if !reflect.DeepEqual(up, wantUp) || !reflect.DeepEqual(down, wantDown) {
		t.Errorf("up:\n%s\ndown:\n%s", strings.Join(up, "\n"), strings.Join(down, "\n"))
	}
	// Any destination: no -d at all.
	up, _, _ = ForwardingRules("wg0", "192.0.2.1/24", ForwardSpec{Egress: "ens3"})
	if strings.Contains(strings.Join(up, "\n"), " -d ") {
		t.Errorf("a full tunnel still restricts the destination:\n%s", strings.Join(up, "\n"))
	}
	if _, _, err := ForwardingRules("wg0", "2001:db8::1/64", ForwardSpec{Egress: "ens3"}); err == nil {
		t.Error("an IPv6 interface address was accepted")
	}
	if _, _, err := ForwardingRules("wg0", "192.0.2.1/24", ForwardSpec{Egress: "-o"}); err == nil {
		t.Error("a flag as egress was accepted")
	}

	conf, err := InterfaceConfWith("wg1", "192.0.2.1/24", 51821,
		&ForwardSpec{Networks: []string{"198.51.100.0/24"}, Egress: "ens3"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range append([]string{"PostUp = wg set %i private-key"}, wantUp...) {
		if !strings.Contains(conf, want) {
			t.Errorf("the conf is missing %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "iptables -A FORWARD") || strings.Contains(conf, "PrivateKey") {
		t.Errorf("the conf appends to FORWARD or inlines a key:\n%s", conf)
	}
	if _, err := BuildWriteInterfaceConf("wg1", conf); err != nil {
		t.Errorf("the forwarding conf is refused by the writer: %v", err)
	}
}

func TestBuildOpenListenPort(t *testing.T) {
	cmd, err := BuildOpenListenPort(51820)
	if err != nil || strings.Join(cmd.Argv, " ") != "iptables -I INPUT -p udp --dport 51820 -j ACCEPT" {
		t.Errorf("BuildOpenListenPort = %q, %v", cmd.Argv, err)
	}
	if _, err := BuildOpenListenPort(0); err == nil {
		t.Error("port 0 was accepted")
	}
}

// TestFakeForwardingInterface: the demo applies a new interface's PostUp
// rules at up and its PostDown rules at down, like wg-quick.
func TestFakeForwardingInterface(t *testing.T) {
	f := NewFake()
	state, _ := f.Load(t.Context())
	if dev, _ := state.Device("wg0"); !dev.Forwarding || dev.PortVerdict != VerdictAccept {
		t.Errorf("the demo wg0 should forward and have its port open: %+v", dev)
	}
	conf, _ := InterfaceConfWith("wg1", "192.0.2.129/25", 51821,
		&ForwardSpec{Networks: []string{"198.51.100.0/24"}, Egress: "eth0"})
	write, _ := BuildWriteInterfaceConf("wg1", conf)
	up, _ := BuildInterfaceUp("wg1")
	down, _ := BuildInterfaceDown("wg1")
	for _, cmd := range []runner.Command{write, up} {
		if _, err := f.Run(t.Context(), cmd); err != nil {
			t.Fatal(err)
		}
	}
	state, _ = f.Load(t.Context())
	dev, _ := state.Device("wg1")
	if !dev.Forwarding || dev.PortVerdict != VerdictReject {
		t.Errorf("wg1 after up: forwarding %v, port %s (want forwarding, port still closed)",
			dev.Forwarding, dev.PortVerdict)
	}
	if _, err := f.Run(t.Context(), down); err != nil {
		t.Fatal(err)
	}
	state, _ = f.Load(t.Context())
	if dev, _ := state.Device("wg1"); dev.Forwarding {
		t.Error("PostDown did not remove the FORWARD rule")
	}
}
