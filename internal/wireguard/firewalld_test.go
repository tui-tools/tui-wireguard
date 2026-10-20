package wireguard

import (
	"reflect"
	"strings"
	"testing"
)

// firewalldFixture is a running firewalld read from the zone listing and one
// of the policy listings.
func firewalldFixture(t *testing.T, policies string) Firewalld {
	t.Helper()
	return Firewalld{
		Running:  true,
		Zones:    ParseFirewalldZones(readFixture(t, "firewalld-zones.txt")),
		Policies: ParseFirewalldPolicies(readFixture(t, policies)),
	}
}

func TestParseFirewalldZones(t *testing.T) {
	zones := ParseFirewalldZones(readFixture(t, "firewalld-zones.txt"))
	if len(zones) != 6 {
		t.Fatalf("zones = %d, want 6", len(zones))
	}
	var public FirewalldZone
	for _, z := range zones {
		if z.Name == "public" {
			public = z
		}
	}
	if !public.Default || !public.Active || public.Target != "default" || !public.Forward {
		t.Errorf("public = %+v", public)
	}
	if !reflect.DeepEqual(public.Interfaces, []string{"ens3"}) {
		t.Errorf("public interfaces = %q", public.Interfaces)
	}
	if zones[1].Name != "block" || zones[1].Target != "%%REJECT%%" || zones[1].Default {
		t.Errorf("block = %+v", zones[1])
	}
}

func TestParseFirewalldPolicies(t *testing.T) {
	policies := ParseFirewalldPolicies(readFixture(t, "firewalld-policies-forwarding.txt"))
	if len(policies) != 2 {
		t.Fatalf("policies = %d, want 2", len(policies))
	}
	host := policies[0]
	if host.Name != "allow-host-ipv6" || !host.Active || host.Priority != -15000 ||
		!reflect.DeepEqual(host.Egress, []string{"HOST"}) || len(host.RichRules) != 8 {
		t.Errorf("allow-host-ipv6 = %+v", host)
	}
	fwd := policies[1]
	if fwd.Name != "wg0-fwd" || !fwd.Active || fwd.Priority != -1 || fwd.Target != "CONTINUE" ||
		!reflect.DeepEqual(fwd.Ingress, []string{"ANY"}) || !reflect.DeepEqual(fwd.Egress, []string{"public"}) {
		t.Errorf("wg0-fwd = %+v", fwd)
	}
	if len(fwd.RichRules) != 2 || richAction(fwd.RichRules[0]) != "accept" ||
		richAction(fwd.RichRules[1]) != "masquerade" {
		t.Errorf("wg0-fwd rich rules = %q", fwd.RichRules)
	}
}

// TestFirewalldForwards is the read side of issue #30: the FORWARD column on
// a firewalld host comes from its policies, not from iptables.
func TestFirewalldForwards(t *testing.T) {
	stock := firewalldFixture(t, "firewalld-policies-default.txt")
	if stock.Forwards("wg0") {
		t.Error("stock firewalld: allow-host-ipv6 only reaches HOST, nothing is forwarded")
	}
	if got := stock.ZoneOf("wg0"); got != "public" {
		t.Errorf("an unbound interface falls into the default zone, got %q", got)
	}
	if got := stock.ZoneOf("ens3"); got != "public" {
		t.Errorf("ZoneOf(ens3) = %q", got)
	}
	if stock.BoundZone("wg0") != "" || stock.BoundZone("ens3") != "public" || stock.DefaultZone() != "public" {
		t.Errorf("bound wg0 %q, ens3 %q, default %q", stock.BoundZone("wg0"), stock.BoundZone("ens3"),
			stock.DefaultZone())
	}

	fwd := firewalldFixture(t, "firewalld-policies-forwarding.txt")
	if !fwd.Forwards("wg0") {
		t.Error("the wg0-fwd policy accepts from ANY to public: wg0 is forwarded")
	}
	if (Firewalld{Policies: fwd.Policies, Zones: fwd.Zones}).Forwards("wg0") {
		t.Error("a firewalld that is not running forwards nothing")
	}

	// A policy with target ACCEPT and an ingress zone, the shape docker and
	// libvirt install; inactive policies do not count.
	accept := Firewalld{Running: true, Zones: fwd.Zones, Policies: []FirewalldPolicy{
		{Name: "trusted-out", Active: true, Target: "ACCEPT", Ingress: []string{"trusted"}, Egress: []string{"ANY"}},
		{Name: "idle", Active: false, Target: "ACCEPT", Ingress: []string{"ANY"}, Egress: []string{"public"}},
	}}
	if accept.Forwards("wg0") {
		t.Error("wg0 is in public: trusted-out does not match, idle is inactive")
	}
	accept.Zones = append(accept.Zones, FirewalldZone{Name: "trusted", Interfaces: []string{"wg0"}})
	if !accept.Forwards("wg0") {
		t.Error("wg0 bound to trusted matches trusted-out")
	}
}

// TestFirewalldDisabledPolicy: firewalld 2.x lists "disable: yes" for a
// policy that is kept but not applied; it forwards nothing.
func TestFirewalldDisabledPolicy(t *testing.T) {
	listing := strings.Replace(readFixture(t, "firewalld-policies-forwarding.txt"),
		"wg0-fwd (active)\n", "wg0-fwd (active)\n  disable: yes\n", 1)
	fw := Firewalld{Running: true, Zones: ParseFirewalldZones(readFixture(t, "firewalld-zones.txt")),
		Policies: ParseFirewalldPolicies(listing)}
	if !fw.Policies[1].Disabled || fw.Forwards("wg0") {
		t.Errorf("a disabled policy forwards: %+v", fw.Policies[1])
	}
}

func TestFirewalldNotRunning(t *testing.T) {
	if got := ParseFirewalldPolicies("FirewallD is not running\n"); len(got) != 0 {
		t.Errorf("a not-running message parsed as %+v", got)
	}
}

// TestFirewalldForwardingRules is the write side: the policy PostUp builds
// and PostDown deletes.
func TestFirewalldForwardingRules(t *testing.T) {
	spec := ForwardSpec{Networks: []string{"203.0.113.0/24"}, Egress: "ens3",
		Manager: ManagerFirewalld, EgressZone: "public"}
	up, down, err := ForwardingRules("wg0", "198.51.100.1/24", spec)
	if err != nil {
		t.Fatal(err)
	}
	// No sysctl hook: Ubuntu 26.04's AppArmor profile for wg-quick denies
	// it, and the tool sets the switch in its own step (issue #33).
	wantUp := []string{
		"firewall-cmd --permanent --delete-policy=wg0-fwd -q 2>/dev/null || true",
		"firewall-cmd --permanent --new-policy=wg0-fwd",
		"firewall-cmd --permanent --policy=wg0-fwd --add-ingress-zone=ANY",
		"firewall-cmd --permanent --policy=wg0-fwd --add-egress-zone=public",
		`firewall-cmd --permanent --policy=wg0-fwd --add-rich-rule='rule family="ipv4" source address="198.51.100.0/24" destination address="203.0.113.0/24" accept'`,
		`firewall-cmd --permanent --policy=wg0-fwd --add-rich-rule='rule family="ipv4" source address="198.51.100.0/24" destination address="203.0.113.0/24" masquerade'`,
		"firewall-cmd --reload",
	}
	if !reflect.DeepEqual(up, wantUp) {
		t.Errorf("up =\n%s", strings.Join(up, "\n"))
	}
	wantDown := []string{"firewall-cmd --permanent --delete-policy=wg0-fwd", "firewall-cmd --reload"}
	if !reflect.DeepEqual(down, wantDown) {
		t.Errorf("down = %q", down)
	}

	// An interface no zone claims is bound to the zone it falls into, so
	// firewalld has an interface to dispatch the policy on, and unbound at
	// down.
	bound := spec
	bound.BindZone = "public"
	up2, down2, err := ForwardingRules("wg0", "198.51.100.1/24", bound)
	if err != nil {
		t.Fatal(err)
	}
	if len(up2) != len(up)+1 || up2[1] != "firewall-cmd --permanent --zone=public --add-interface=wg0" {
		t.Errorf("bound up =\n%s", strings.Join(up2, "\n"))
	}
	if !reflect.DeepEqual(down2, []string{"firewall-cmd --permanent --delete-policy=wg0-fwd",
		"firewall-cmd --permanent --zone=public --remove-interface=wg0", "firewall-cmd --reload"}) {
		t.Errorf("bound down = %q", down2)
	}
	bound.BindZone = "public --panic-on"
	if _, _, err := ForwardingRules("wg0", "198.51.100.1/24", bound); err == nil {
		t.Error("a bind zone that is not a plain name was accepted")
	}
	for _, line := range up {
		if strings.Contains(line, "iptables") {
			t.Errorf("an iptables line on a firewalld host: %s", line)
		}
	}

	// Any destination: one accept and one masquerade, by source only.
	spec.Networks = nil
	up, _, _ = ForwardingRules("wg0", "198.51.100.1/24", spec)
	if got := strings.Join(up, "\n"); strings.Contains(got, "destination") ||
		strings.Count(got, "--add-rich-rule") != 2 {
		t.Errorf("any destination =\n%s", got)
	}

	// The rich rules the PostUp writes are what the reader counts as
	// forwarding, once firewalld lists them back.
	listed := FirewalldPolicy{Name: "wg0-fwd", Active: true, Target: "CONTINUE",
		Ingress: []string{"ANY"}, Egress: []string{"public"}}
	for _, line := range up {
		if _, rule, ok := strings.Cut(line, "--add-rich-rule='"); ok {
			listed.RichRules = append(listed.RichRules, strings.TrimSuffix(rule, "'"))
		}
	}
	if !(Firewalld{Running: true, Policies: []FirewalldPolicy{listed}}).Forwards("wg0") {
		t.Error("the policy PostUp builds does not read back as forwarding")
	}

	if _, _, err := ForwardingRules("wg-a-very-long", "198.51.100.1/24", spec); err == nil {
		t.Error("a policy name over 17 characters was accepted")
	}
	spec.EgressZone = ""
	if _, _, err := ForwardingRules("wg0", "198.51.100.1/24", spec); err == nil {
		t.Error("an empty egress zone was accepted")
	}
	spec.EgressZone = "public; reboot"
	if _, _, err := ForwardingRules("wg0", "198.51.100.1/24", spec); err == nil {
		t.Error("a zone that is not a plain name was accepted")
	}
}

// TestHooksSurviveWgQuickSave: wg-quick save writes PostUp/PostDown back
// through a bash substitution where "&" is the matched text, which turned
// `2>&1` into `2>[Interface]` on Fedora 44. No hook this tool writes may
// carry one, on any firewall.
func TestHooksSurviveWgQuickSave(t *testing.T) {
	for _, spec := range []ForwardSpec{
		{Egress: "ens3"},
		{Egress: "ens3", Networks: []string{"203.0.113.0/24"}},
		{Egress: "ens3", Manager: ManagerFirewalld, EgressZone: "public"},
		{Egress: "ens3", Manager: ManagerFirewalld, EgressZone: "public", BindZone: "public",
			Networks: []string{"203.0.113.0/24"}},
	} {
		conf, err := InterfaceConfWith("wg0", "198.51.100.1/24", 51820, &spec)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(conf, "&") {
			t.Errorf("a hook carries \"&\", which wg-quick save mangles:\n%s", conf)
		}
	}
}

// TestInterfaceConfFirewalld is the conf a firewalld forwarding server
// writes: firewall-cmd hooks, no iptables.
func TestInterfaceConfFirewalld(t *testing.T) {
	conf, err := InterfaceConfWith("wg0", "198.51.100.1/24", 51820, &ForwardSpec{
		Egress: "ens3", Manager: ManagerFirewalld, EgressZone: "public"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PostUp = firewall-cmd --permanent --new-policy=wg0-fwd\n",
		"PostUp = firewall-cmd --reload\n",
		"PostDown = firewall-cmd --permanent --delete-policy=wg0-fwd\n",
		"# firewalld is in charge: the rules are the firewalld policy wg0-fwd",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("conf lacks %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "iptables") {
		t.Errorf("conf carries iptables:\n%s", conf)
	}
}

// TestForwardSourceAndManager is what --check reports as in charge of
// forwarding.
func TestForwardSourceAndManager(t *testing.T) {
	var s State
	if s.ForwardSource() != "" || s.ForwardManager() != "" {
		t.Error("nothing read: no source, no manager")
	}
	s.Firewall = Firewall{Checked: true}
	s.Input.Manager = ManagerUFW
	if s.ForwardSource() != ForwardSourceIptables || s.ForwardManager() != ManagerUFW {
		t.Errorf("ufw: %q %q", s.ForwardSource(), s.ForwardManager())
	}
	s.Firewalld = firewalldFixture(t, "firewalld-policies-forwarding.txt")
	s.Devices = []Device{{Name: "wg0"}}
	// iptables alone has no FORWARD rule for wg0; firewalld's policy is what
	// counts.
	s.annotateFirewall()
	if s.ForwardSource() != ForwardSourceFirewalld || s.ForwardManager() != ManagerFirewalld ||
		!s.Devices[0].Forwarding {
		t.Errorf("firewalld: %q %q %v", s.ForwardSource(), s.ForwardManager(), s.Devices[0].Forwarding)
	}
	// And the reverse: iptables accepts, firewalld does not.
	s.Firewall = ParseIptablesRules("-A FORWARD -i wg0 -o ens3 -j ACCEPT")
	s.Firewalld = firewalldFixture(t, "firewalld-policies-default.txt")
	s.annotateFirewall()
	if s.Devices[0].Forwarding {
		t.Error("an iptables FORWARD accept is overruled by firewalld: not forwarding")
	}
}

// TestFirewalldCapturedFedora44 reads firewalld 2.4.4's own listings, captured
// on Fedora 44 before and while a forwarding server built by this tool was
// up (issue #30). Fedora ships five gateway-* policies disabled, some with
// target ACCEPT: none of them may count as forwarding.
func TestFirewalldCapturedFedora44(t *testing.T) {
	stock := ParseFirewalldPolicies(readFixture(t, "firewalld-f44-policies-stock.txt"))
	if len(stock) != 6 {
		t.Fatalf("stock policies = %d, want 6", len(stock))
	}
	disabled := 0
	for _, p := range stock {
		if p.Disabled {
			disabled++
		}
	}
	if disabled != 5 {
		t.Errorf("disabled stock policies = %d, want 5", disabled)
	}
	zones := ParseFirewalldZones(readFixture(t, "firewalld-f44-zones-forwarding.txt"))
	fw := Firewalld{Running: true, Zones: zones, Policies: stock}
	if fw.Forwards("wg0") {
		t.Error("stock Fedora 44 policies forward wg0")
	}
	// Even bound to trusted, which the disabled gateway-lan-to-world
	// accepts from, nothing forwards while that policy is disabled.
	trusted := Firewalld{Running: true, Policies: stock, Zones: []FirewalldZone{
		{Name: "trusted", Interfaces: []string{"wg0"}}, {Name: "public", Default: true}}}
	if trusted.Forwards("wg0") {
		t.Error("a disabled gateway policy counted as forwarding")
	}

	up := Firewalld{Running: true, Zones: zones,
		Policies: ParseFirewalldPolicies(readFixture(t, "firewalld-f44-policies-forwarding.txt"))}
	if up.BoundZone("wg0") != "public" || up.DefaultZone() != "public" {
		t.Errorf("wg0 bound to %q, default %q", up.BoundZone("wg0"), up.DefaultZone())
	}
	if !up.Forwards("wg0") {
		t.Error("the captured wg0-fwd policy does not read as forwarding")
	}
	// Another WireGuard interface on the same host is not forwarded by
	// wg0's policy: its rules match wg0's peers only.
	if up.Forwards("wg1") {
		t.Error("wg0-fwd's source-scoped rules counted for wg1")
	}
}
