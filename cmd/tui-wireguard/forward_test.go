package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-wireguard/internal/wireguard"
)

// enter submits the open dialog without typing anything, which is how a
// prefilled input is accepted and how a picker takes its highlighted option.
func enter(t *testing.T, a *app) *app {
	t.Helper()
	model, _ := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	return model.(*app)
}

// clearAndType replaces the open input's whole value. The wizard prefills
// some steps (the port, the proposed networks), so a test that wants a
// different answer has to take the old one out first.
func clearAndType(t *testing.T, a *app, text string) *app {
	t.Helper()
	if a.mode != modeInput {
		t.Fatalf("no input is open (mode %d)", a.mode)
	}
	a.input.Model.SetValue("")
	model, _ := a.Update(key(text))
	a = model.(*app)
	return enter(t, a)
}

// pick selects a picker option by its text and submits it.
func pick(t *testing.T, a *app, option string) *app {
	t.Helper()
	if a.mode != modePicker {
		t.Fatalf("no picker is open (mode %d, status %q)", a.mode, a.status)
	}
	for i, o := range a.picker.Options {
		if o == option {
			a.picker.Cursor = i
			return enter(t, a)
		}
	}
	t.Fatalf("the picker has no option %q: %q", option, a.picker.Options)
	return a
}

// startForwardingServer drives N up to the role picker for wg9 on port.
func startForwardingServer(t *testing.T, a *app, port string) *app {
	t.Helper()
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("N"))
	a = model.(*app)
	a = typeAndEnter(t, a, "wg9")
	a = typeAndEnter(t, a, "192.0.2.129/25")
	a = clearAndType(t, a, port)
	return pick(t, a, roleForwarder)
}

// TestCreateForwardingServer is the real case end to end: a server whose
// peers reach the network behind it, on a host whose INPUT and FORWARD chains
// end in REJECT. The wizard proposes the networks and the egress from the
// routing table, writes the forwarding rules into the conf (previewed whole),
// offers the listen port, and the interface comes up forwarding.
func TestCreateForwardingServer(t *testing.T) {
	a := newTestApp(t)
	a = startForwardingServer(t, a, "51821")
	if a.inputPurpose != inputNewIfaceNetworks || a.input.Model.Value() != "198.51.100.0/24" {
		t.Fatalf("networks step: purpose %d, proposed %q (want the host's own network, "+
			"not wg0's or a link that is down)", a.inputPurpose, a.input.Model.Value())
	}
	a = enter(t, a)
	if a.inputPurpose != inputNewIfaceEgress || a.input.Model.Value() != "eth0" {
		t.Fatalf("egress step: purpose %d, proposed %q", a.inputPurpose, a.input.Model.Value())
	}
	a = enter(t, a)

	if !strings.Contains(a.confirm.Body, "Step 1 of 5") {
		t.Errorf("the forwarding and port steps are not counted:\n%s", a.confirm.Body)
	}
	a = confirmAndRun(t, a) // keygen
	body := a.confirm.Body
	if strings.Contains(body, "sysctl") && strings.Contains(body, "PostUp = sysctl") {
		t.Errorf("the conf still turns forwarding on in a hook (issue #33):\n%s", body)
	}
	for _, want := range []string{
		"# net.ipv4.ip_forward is set by /etc/sysctl.d/90-tui-wireguard-wg9-forward.conf",
		"PostUp = iptables -I FORWARD -i %i -o eth0 -d 198.51.100.0/24 -j ACCEPT",
		"PostUp = iptables -I FORWARD -i eth0 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"PostUp = iptables -t nat -I POSTROUTING -s 192.0.2.128/25 -o eth0 -d 198.51.100.0/24 -j MASQUERADE",
		"PostDown = iptables -D FORWARD -i %i -o eth0 -d 198.51.100.0/24 -j ACCEPT",
		"inserts FORWARD rules with -I",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the conf step is missing %q:\n%s", want, body)
		}
	}
	a = confirmAndRun(t, a) // conf

	// The kernel switch, outside wg-quick (issue #33).
	if a.confirm.Command != "sh -c 'install -D -m 644 /dev/stdin "+
		"/etc/sysctl.d/90-tui-wireguard-wg9-forward.conf && sysctl -w net.ipv4.ip_forward=1'" {
		t.Fatalf("forwarding step preview = %q", a.confirm.Command)
	}
	for _, want := range []string{"Step 3 of 5", "AppArmor", "net.ipv4.ip_forward = 1",
		"# Written by tui-wireguard for the forwarding server wg9", "Now: on"} {
		if !strings.Contains(a.confirm.Body, want) {
			t.Errorf("the forwarding step is missing %q:\n%s", want, a.confirm.Body)
		}
	}
	a = confirmAndRun(t, a) // forwarding

	if a.confirm.Command != "iptables -I INPUT -p udp --dport 51821 -j ACCEPT" {
		t.Fatalf("port step preview = %q", a.confirm.Command)
	}
	for _, want := range []string{"Step 4 of 5", "NOT persisted", "REJECT", "Oracle Cloud",
		"netfilter-persistent"} {
		if !strings.Contains(a.confirm.Body, want) {
			t.Errorf("the port step is missing %q:\n%s", want, a.confirm.Body)
		}
	}
	a = confirmAndRun(t, a) // port
	if !strings.Contains(a.confirm.Command, "wg-quick up wg9") ||
		!strings.Contains(a.confirm.Body, "Step 5 of 5") {
		t.Fatalf("up step: %q\n%s", a.confirm.Command, a.confirm.Body)
	}
	a = confirmAndRun(t, a)

	state, _ := a.backend.Load(t.Context())
	dev, ok := state.Device("wg9")
	if !ok || !dev.Forwarding || dev.PortVerdict != wireguard.VerdictAccept {
		t.Errorf("wg9 after the wizard: %+v", dev)
	}
	if !state.Kernel.HasDropIn("wg9") {
		t.Errorf("wg9 has no drop-in after the wizard: %+v", state.Kernel)
	}
	a.state = state
	if view := a.View(); !strings.Contains(view, "FORWARD") || !strings.Contains(view, "UDP IN") {
		t.Errorf("the interfaces table does not show the firewall columns:\n%s", view)
	}
}

// TestPortStepNamesTUIFirewall: with tui-firewall installed, the port step
// says to make the rule permanent there, since it cannot be driven.
func TestPortStepNamesTUIFirewall(t *testing.T) {
	a := newTestApp(t)
	a.state.TUIFirewall = true
	a = startForwardingServer(t, a, "51821")
	a = enter(t, a)
	a = enter(t, a)
	a = confirmAndRun(t, a) // keygen
	a = confirmAndRun(t, a) // conf
	a = confirmAndRun(t, a) // forwarding
	if !strings.Contains(a.confirm.Body, "tui-firewall is installed") {
		t.Errorf("the port step does not name tui-firewall:\n%s", a.confirm.Body)
	}
}

// TestOpenPortIsSkipped: a port the firewall already accepts is not offered,
// and the count says three steps.
func TestOpenPortIsSkipped(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("N"))
	a = model.(*app)
	a = typeAndEnter(t, a, "wg9")
	a = typeAndEnter(t, a, "192.0.2.129/25")
	a = enter(t, a) // 51820, which the demo firewall accepts
	a = pick(t, a, roleEndpoint)
	if !strings.Contains(a.confirm.Body, "Step 1 of 3") {
		t.Errorf("an open port was still counted:\n%s", a.confirm.Body)
	}
}

// TestNetworksStepRefusesIPv6: the rules are iptables, so an IPv6 network is
// refused at its step, which reopens with the reason.
func TestNetworksStepRefusesIPv6(t *testing.T) {
	a := newTestApp(t)
	a = startForwardingServer(t, a, "51821")
	a = clearAndType(t, a, "2001:db8::/32")
	if a.inputPurpose != inputNewIfaceNetworks || !strings.Contains(a.input.Help, "IPv6") {
		t.Errorf("IPv6 was not refused: purpose %d\n%s", a.inputPurpose, a.input.Help)
	}
	// Empty is an answer: any destination.
	a.input.Model.SetValue("")
	model, _ := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = model.(*app)
	if a.inputPurpose != inputNewIfaceEgress {
		t.Errorf("an empty network list did not move on (purpose %d)", a.inputPurpose)
	}
}

// TestCheckReportsTheListenPortAndForwarding: --check says, per interface,
// what INPUT does with a handshake and whether the host forwards for it.
func TestCheckReportsTheListenPortAndForwarding(t *testing.T) {
	var out strings.Builder
	if err := runCheck(context.Background(), wireguard.NewFake(), nil, &out); err != nil {
		t.Fatal(err)
	}
	var report checkReport
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatal(err)
	}
	wg := report.WireGuard
	if !wg.FirewallChecked || len(wg.Interfaces) != 1 ||
		wg.Interfaces[0].ListenPortInput != wireguard.VerdictAccept || !wg.Interfaces[0].Forwarding {
		t.Errorf("wireguard summary = %+v", wg)
	}
	if strings.Contains(out.String(), "198.51.100.") {
		t.Error("--check printed a network of the host")
	}
	if wg.FirewallSource != wireguard.SourceIptables {
		t.Errorf("firewallSource = %q, want the demo's iptables", wg.FirewallSource)
	}
}

// firewalldInput reads a firewalld rule set captured on Fedora 44 (issue #28).
func firewalldInput(t *testing.T, fixture string) wireguard.InputFirewall {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "wireguard", "testdata", fixture)) //nolint:gosec // testdata is in the repository
	if err != nil {
		t.Fatal(err)
	}
	fw, ok := wireguard.ParseNftRuleset(string(data))
	if !ok {
		t.Fatalf("%s did not read", fixture)
	}
	return fw
}

// TestPortStepOnFirewalld: on a firewalld host whose zone does not allow the
// port, the UDP IN column says closed and the wizard opens the port with
// firewall-cmd, since an iptables rule would sit in a table firewalld's
// reject never consults.
func TestPortStepOnFirewalld(t *testing.T) {
	a := newTestApp(t)
	a.state.Input = firewalldInput(t, "nft-firewalld-closed.json")
	a = startForwardingServer(t, a, "51821")
	a = enter(t, a)
	a = enter(t, a)
	if !strings.Contains(a.confirm.Body, "Step 1 of 5") {
		t.Fatalf("the port step was not counted:\n%s", a.confirm.Body)
	}
	a.state.Input = firewalldInput(t, "nft-firewalld-closed.json")
	a = confirmAndRun(t, a) // keygen
	a.state.Input = firewalldInput(t, "nft-firewalld-closed.json")
	a = confirmAndRun(t, a) // conf
	a.state.Input = firewalldInput(t, "nft-firewalld-closed.json")
	a = confirmAndRun(t, a) // forwarding
	if !strings.Contains(a.confirm.Command, "firewall-cmd --add-port=51821/udp") {
		t.Errorf("port step preview = %q, want firewall-cmd", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Body, "firewalld does not allow udp/51821") ||
		!strings.Contains(a.confirm.Body, "--permanent") {
		t.Errorf("the port step does not explain firewalld:\n%s", a.confirm.Body)
	}
}

// TestUDPInColumnReadsFirewalld: the column follows the input read, closed
// before `firewall-cmd --add-port` and open after it.
func TestUDPInColumnReadsFirewalld(t *testing.T) {
	for fixture, want := range map[string]string{
		"nft-firewalld-closed.json": "closed",
		"nft-firewalld-open.json":   "open",
	} {
		dev := wireguard.Device{Name: "wg0", ListenPort: 51820,
			PortVerdict: firewalldInput(t, fixture).UDPVerdict(51820)}
		if got := firewallText(dev); got != want {
			t.Errorf("%s: UDP IN = %q, want %q", fixture, got, want)
		}
	}
}

// runningFirewalld is a firewalld host read from the zone and policy
// fixtures: default zone public holding eth0, and no forwarding policy.
func runningFirewalld(t *testing.T) wireguard.Firewalld {
	t.Helper()
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join("..", "..", "internal", "wireguard", "testdata", name)) //nolint:gosec // testdata is in the repository
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(data), "interfaces: ens3", "interfaces: eth0")
	}
	return wireguard.Firewalld{Running: true,
		Zones:    wireguard.ParseFirewalldZones(read("firewalld-zones.txt")),
		Policies: wireguard.ParseFirewalldPolicies(read("firewalld-policies-default.txt"))}
}

// TestForwardingServerOnFirewalld is issue #30: with firewalld running, the
// forwarding server's conf builds a firewalld policy forwarding to the egress
// NIC's zone instead of iptables rules, and the port step goes into
// firewalld's permanent configuration, since PostUp's reload would drop a
// runtime-only port.
func TestForwardingServerOnFirewalld(t *testing.T) {
	a := newTestApp(t)
	a.state.Firewalld = unboundEgress(runningFirewalld(t))
	a.state.Input = firewalldInput(t, "nft-firewalld-closed.json")
	a = startForwardingServer(t, a, "51821")
	a = enter(t, a) // the proposed networks
	a = enter(t, a) // the proposed egress, eth0
	if a.draft.forward == nil || a.draft.forward.Manager != wireguard.ManagerFirewalld ||
		a.draft.forward.EgressZone != "public" || a.draft.forward.BindZone != "public" {
		t.Fatalf("draft = %+v, want firewalld forwarding to public", a.draft.forward)
	}
	a = confirmAndRun(t, a) // the keygen
	body := a.confirm.Body
	for _, want := range []string{
		"PostUp = firewall-cmd --permanent --zone=public --add-interface=wg9",
		"PostDown = firewall-cmd --permanent --zone=public --remove-interface=wg9",
		"PostUp = firewall-cmd --permanent --new-policy=wg9-fwd",
		"PostUp = firewall-cmd --permanent --policy=wg9-fwd --add-egress-zone=public",
		`source address="192.0.2.128/25" destination address="198.51.100.0/24" masquerade'`,
		"PostUp = firewall-cmd --reload",
		"PostDown = firewall-cmd --permanent --delete-policy=wg9-fwd",
		"firewalld is in charge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("conf preview lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "iptables -I") {
		t.Errorf("conf preview inserts iptables rules on a firewalld host:\n%s", body)
	}
	a.state.Firewalld = unboundEgress(runningFirewalld(t))
	a.state.Input = firewalldInput(t, "nft-firewalld-closed.json")
	a = confirmAndRun(t, a) // write the conf
	if !strings.Contains(a.confirm.Command, "sysctl -w net.ipv4.ip_forward=1") {
		t.Fatalf("the forwarding step is not next on firewalld: %q", a.confirm.Command)
	}
	a.state.Firewalld = unboundEgress(runningFirewalld(t))
	a.state.Input = firewalldInput(t, "nft-firewalld-closed.json")
	a = confirmAndRun(t, a) // the kernel switch
	if !strings.Contains(a.confirm.Command, "firewall-cmd --permanent --add-port=51821/udp") {
		t.Errorf("port step preview = %q, want the permanent firewall-cmd", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Body, "permanent configuration") {
		t.Errorf("the port step does not say why it is permanent:\n%s", a.confirm.Body)
	}
}

// TestForwardingServerWithoutFirewalld keeps today's rules on a host where
// firewalld is not running (ufw, plain iptables or nftables).
func TestForwardingServerWithoutFirewalld(t *testing.T) {
	a := newTestApp(t)
	a = startForwardingServer(t, a, "51821")
	a = enter(t, a)
	a = enter(t, a)
	if a.draft.forward.Manager != "" {
		t.Fatalf("manager = %q without firewalld", a.draft.forward.Manager)
	}
	a = confirmAndRun(t, a)
	if !strings.Contains(a.confirm.Body, "PostUp = iptables -I FORWARD -i %i -o eth0") ||
		strings.Contains(a.confirm.Body, "firewall-cmd") {
		t.Errorf("conf preview without firewalld:\n%s", a.confirm.Body)
	}
}

// TestCheckReportsForwardingSource: --check says what answered for the
// FORWARD column.
func TestCheckReportsForwardingSource(t *testing.T) {
	var out strings.Builder
	if err := runCheck(context.Background(), wireguard.NewFake(), nil, &out); err != nil {
		t.Fatal(err)
	}
	var report checkReport
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatal(err)
	}
	wg := report.WireGuard
	if !wg.ForwardingChecked || wg.ForwardingSource != wireguard.ForwardSourceIptables || wg.ForwardingManager != "" {
		t.Errorf("forwarding = %v %q %q, want the demo's iptables", wg.ForwardingChecked,
			wg.ForwardingSource, wg.ForwardingManager)
	}
}

// TestForwardingServerOnFirewalldBoundEgress: when the egress NIC is bound to
// a zone (NetworkManager binds the NICs it manages), firewalld dispatches the
// policy on it and the WireGuard interface is left alone.
func TestForwardingServerOnFirewalldBoundEgress(t *testing.T) {
	a := newTestApp(t)
	a.state.Firewalld = unboundEgress(runningFirewalld(t))
	a = startForwardingServer(t, a, "51821")
	a = enter(t, a)
	a = enter(t, a)
	if a.draft.forward.BindZone != "public" {
		t.Fatalf("unbound egress: bind zone = %q, want public", a.draft.forward.BindZone)
	}

	b := newTestApp(t)
	b.state.Firewalld = runningFirewalld(t) // eth0 bound to public
	b = startForwardingServer(t, b, "51821")
	b = enter(t, b)
	b = enter(t, b)
	if b.draft.forward.BindZone != "" {
		t.Fatalf("bound egress: bind zone = %q, want none", b.draft.forward.BindZone)
	}
	b = confirmAndRun(t, b)
	if strings.Contains(b.confirm.Body, "--add-interface") {
		t.Errorf("the conf binds the WireGuard interface although eth0 is bound:\n%s", b.confirm.Body)
	}
}

// unboundEgress leaves eth0 in the default zone's catch-all only, the shape
// of a NIC NetworkManager does not manage.
func unboundEgress(fw wireguard.Firewalld) wireguard.Firewalld {
	for i := range fw.Zones {
		if fw.Zones[i].Name == "public" {
			fw.Zones[i].Interfaces = nil
		}
	}
	return fw
}
