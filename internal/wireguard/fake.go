package wireguard

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// Fake is the in-memory backend behind --demo and the tests. It previews
// exactly the commands the real backend would, then applies them to its own
// state instead of to the machine, so the UI cannot tell it from the real
// thing and a test can assert that the command that ran is the command the
// preview showed.
//
// Every key in here is an obviously invented placeholder and every address is
// from a documentation range, enforced by the tests: the demo has to run with
// nothing installed and leak nothing about the host it runs on.
type Fake struct {
	mu    sync.Mutex
	state State
	// firewall is the demo's `iptables -S`, as lines: the ruleset of a cloud
	// image whose INPUT and FORWARD chains end in REJECT, with the demo
	// interface's port opened and its forwarding rules in place. The
	// previewed iptables commands edit it, and every Load parses it.
	firewall []string
	// confs are the configuration files the demo wrote for new interfaces,
	// so bringing one up applies its PostUp rules the way wg-quick would.
	confs map[string]string
	run   *runner.Fake
}

// Demonstration keys. They are valid WireGuard key syntax (43 base64 characters
// and a '=') but plainly not real: a run of one letter could not be a key any
// tool generated.
const (
	demoIfacePub = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	demoPeer1Pub = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	demoPeer2Pub = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	// demoNewIfacePub is the public key the demo "generates" for an interface
	// created from zero. Only ever a public key: the demo, like the real
	// backend, has no private key to show.
	demoNewIfacePub = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
)

// DemoIfacePub, DemoPeer1Pub and DemoPeer2Pub expose the placeholder public
// keys the demo uses, so tests can assert they never leak into a report.
func DemoIfacePub() string { return demoIfacePub }
func DemoPeer1Pub() string { return demoPeer1Pub }
func DemoPeer2Pub() string { return demoPeer2Pub }

// NewFake returns a Fake preloaded with a plausible network: one forwarding
// interface with two peers, one mid-handshake and one that has never
// connected, on a host whose firewall ends INPUT and FORWARD in REJECT.
func NewFake() *Fake {
	f := &Fake{state: demoState(),
		firewall: append([]string(nil), demoFirewall...), confs: map[string]string{}}
	f.run = &runner.Fake{Hook: f.apply}
	return f
}

// Name identifies the backend.
func (f *Fake) Name() string { return "demo" }

// Describe is the one-line summary shown in the header.
func (f *Fake) Describe() string {
	return "wireguard  ·  demo (no changes are applied)"
}

// Preview renders the command the way the real backend would.
func (f *Fake) Preview(cmd runner.Command) string { return f.run.Preview(cmd) }

// Run applies a confirmed command to the in-memory state.
func (f *Fake) Run(ctx context.Context, cmd runner.Command) (string, error) {
	return f.run.Run(ctx, cmd)
}

// Commands returns every command the fake was asked to run, for the tests.
func (f *Fake) Commands() []runner.Command { return f.run.Ran }

// Load returns a copy of the sample state, with the firewall parsed the way
// the real backend parses `iptables -S`.
func (f *Fake) Load(_ context.Context) (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state := f.state
	state.Devices = append([]Device(nil), f.state.Devices...)
	state.Kernel.DropIns = append([]string(nil), f.state.Kernel.DropIns...)
	state.Kernel.Files = append([]SysctlFile(nil), f.state.Kernel.Files...)
	state.Firewall = ParseIptablesRules(strings.Join(f.firewall, "\n"))
	state.Input, _ = ParseIptablesInput(strings.Join(f.firewall, "\n")) // the demo always reads
	state.annotateFirewall()
	return state, nil
}

// apply mutates the sample state the way the real command would. It is the
// runner.Fake hook, so it runs only for a command that was previewed and
// confirmed — the same path the real backend takes.
func (f *Fake) apply(cmd runner.Command) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	argv := cmd.Argv
	switch {
	case len(argv) == 3 && argv[0] == "wg-quick" && argv[1] == "up":
		return f.setUp(argv[2], true)
	case len(argv) == 3 && argv[0] == "wg-quick" && argv[1] == "down":
		return f.setUp(argv[2], false)
	case len(argv) == 5 && argv[3] == saveScriptName:
		iface, ok := SavedInterface(cmd)
		if !ok {
			return "", fmt.Errorf("demo backend: not a save shell: %q", cmd.String())
		}
		return f.saveConfig(iface)
	case len(argv) >= 6 && argv[0] == "wg" && argv[1] == "set" && argv[3] == "peer" && argv[5] == "remove":
		return f.removePeer(argv[2], argv[4])
	case len(argv) >= 7 && argv[0] == "wg" && argv[1] == "set" && argv[3] == "peer" && argv[5] == "allowed-ips":
		return f.addPeer(argv[2], Peer{
			PublicKey:       argv[4],
			AllowedIPs:      strings.Split(argv[6], ","),
			HasPresharedKey: hasToken(argv, "preshared-key"),
			Endpoint:        tokenValue(argv, "endpoint"),
			Keepalive:       atoiOr0(tokenValue(argv, "persistent-keepalive")),
		})
	case len(argv) == 3 && argv[0] == "sh" && argv[1] == "-c" && isForwardingStep(cmd):
		iface, enable, _ := ForwardingStep(cmd)
		return f.setForwarding(iface, enable)
	case len(argv) == 3 && argv[0] == "sh" && argv[1] == "-c" && strings.Contains(argv[2], "wg genkey"):
		// The keygen shell: the demo "writes" the private key nowhere and
		// answers with the invented public key, exactly the value the real
		// command would print.
		return demoNewIfacePub, nil
	case len(argv) == 3 && argv[0] == "sh" && argv[1] == "-c" && strings.Contains(argv[2], "wg genpsk"):
		// The PSK shell: nothing to return — the value stays in its file.
		return "", nil
	case len(argv) == 5 && argv[0] == "install" && strings.HasPrefix(argv[4], "/etc/wireguard/") && strings.HasSuffix(argv[4], ".conf"):
		return f.writeConf(argv[4], cmd.Stdin)
	case len(argv) >= 3 && argv[0] == "iptables":
		return "", f.iptables(argv[1:])
	default:
		return "", fmt.Errorf("demo backend does not know how to apply %q", cmd.String())
	}
}

// hasToken reports whether argv carries a literal token.
func hasToken(argv []string, token string) bool {
	for _, a := range argv {
		if a == token {
			return true
		}
	}
	return false
}

// tokenValue is the argument that follows a literal token in argv, empty when
// the token is absent or last.
func tokenValue(argv []string, token string) string {
	for i, a := range argv[:max(len(argv)-1, 0)] {
		if a == token {
			return argv[i+1]
		}
	}
	return ""
}

// atoiOr0 is strconv.Atoi for a value a builder already validated.
func atoiOr0(s string) int {
	n, _ := strconv.Atoi(s) // 0 on an absent value is the right default
	return n
}

// demoFirewall is the demo host's `iptables -S`: the shape of a cloud
// provider's Ubuntu image, whose INPUT and FORWARD chains end in REJECT, with
// wg0's listen port opened and its forwarding rules inserted above the
// REJECT. Every address is from a documentation range.
var demoFirewall = []string{
	"-P INPUT ACCEPT",
	"-P FORWARD DROP",
	"-P OUTPUT ACCEPT",
	"-A INPUT -p udp -m udp --dport 51820 -j ACCEPT",
	"-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
	"-A INPUT -p icmp -j ACCEPT",
	"-A INPUT -i lo -j ACCEPT",
	"-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT",
	"-A INPUT -j REJECT --reject-with icmp-host-prohibited",
	"-A FORWARD -d 198.51.100.0/24 -i wg0 -o eth0 -j ACCEPT",
	"-A FORWARD -i eth0 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
	"-A FORWARD -j REJECT --reject-with icmp-host-prohibited",
}

// iptables applies an insert or a delete to the demo's filter table. The nat
// table is accepted and not modelled: nothing on screen reads it.
func (f *Fake) iptables(args []string) error {
	if len(args) >= 2 && args[0] == "-t" {
		if args[1] != "filter" {
			return nil
		}
		args = args[2:]
	}
	if len(args) < 3 {
		return fmt.Errorf("iptables: not enough arguments")
	}
	op, chain, rule := args[0], args[1], "-A "+args[1]+" "+strings.Join(args[2:], " ")
	switch op {
	case "-I":
		// Insert at the top of the chain: right after its policy lines.
		at := 0
		for i, line := range f.firewall {
			if strings.HasPrefix(line, "-P ") || strings.HasPrefix(line, "-N ") {
				at = i + 1
			}
		}
		for i, line := range f.firewall {
			if strings.HasPrefix(line, "-A "+chain+" ") {
				at = i
				break
			}
		}
		f.firewall = append(f.firewall[:at], append([]string{rule}, f.firewall[at:]...)...)
	case "-D":
		for i, line := range f.firewall {
			if line == rule {
				f.firewall = append(f.firewall[:i], f.firewall[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("iptables: Bad rule (does a matching rule exist in that chain?)")
	default:
		return fmt.Errorf("iptables: the demo does not model %s", op)
	}
	return nil
}

// applyConfHooks runs the iptables lines of a conf's PostUp (up) or PostDown
// (down), the way wg-quick would, with %i replaced by the interface.
func (f *Fake) applyConfHooks(iface string, up bool) {
	hook := "PostDown = "
	if up {
		hook = "PostUp = "
	}
	for _, line := range strings.Split(f.confs[iface], "\n") {
		cmd, ok := strings.CutPrefix(strings.TrimSpace(line), hook)
		if !ok || !strings.HasPrefix(cmd, "iptables ") {
			continue
		}
		_ = f.iptables(strings.Fields(strings.ReplaceAll(cmd, "%i", iface))[1:]) // best effort, like wg-quick's own hooks
	}
}

func (f *Fake) setUp(iface string, up bool) (string, error) {
	for i := range f.state.Devices {
		if f.state.Devices[i].Name == iface {
			if f.state.Devices[i].Up != up {
				f.applyConfHooks(iface, up)
			}
			f.state.Devices[i].Up = up
			// Like the real listing: a down interface is known from its
			// configuration file alone.
			f.state.Devices[i].ConfigOnly = !up
			if up {
				return "[#] interface " + iface + " up", nil
			}
			return "[#] interface " + iface + " down", nil
		}
	}
	return "", fmt.Errorf("no such interface: %s", iface)
}

func (f *Fake) removePeer(iface, key string) (string, error) {
	for i := range f.state.Devices {
		if f.state.Devices[i].Name != iface {
			continue
		}
		peers := f.state.Devices[i].Peers
		for j := range peers {
			if peers[j].PublicKey == key {
				f.state.Devices[i].Peers = append(peers[:j], peers[j+1:]...)
				return "", nil
			}
		}
	}
	return "", fmt.Errorf("no such peer on %s", iface)
}

// addPeer applies `wg set … peer`. Like wg, it replaces the peer when the key
// is already there rather than adding it twice.
func (f *Fake) addPeer(iface string, peer Peer) (string, error) {
	for i := range f.state.Devices {
		if f.state.Devices[i].Name == iface {
			peers := f.state.Devices[i].Peers
			for j := range peers {
				if peers[j].PublicKey == peer.PublicKey {
					peers[j] = peer
					return "", nil
				}
			}
			f.state.Devices[i].Peers = append(peers, peer)
			return "", nil
		}
	}
	return "", fmt.Errorf("no such interface: %s", iface)
}

// saveConfig persists nothing (the demo has no disk) but answers the way the
// save shell would, so the UI flow is exercised end to end: the demo's confs
// are the tool's own, so the key and every pre-shared key are in files.
func (f *Fake) saveConfig(iface string) (string, error) {
	for _, d := range f.state.Devices {
		if d.Name != iface {
			continue
		}
		// wg-quick save's own trace comes first, as on a real host.
		msg := "[#] wg showconf " + iface + "\n" +
			ConfPath(iface) + " saved: the private key is loaded from " + KeyPath(iface)
		psks := 0
		for _, p := range d.Peers {
			if p.HasPresharedKey {
				psks++
			}
		}
		if psks > 0 {
			msg += fmt.Sprintf(", %d pre-shared key(s) loaded from their files", psks)
		}
		return msg, nil
	}
	return "", fmt.Errorf("no such interface: %s", iface)
}

func isForwardingStep(cmd runner.Command) bool {
	_, _, ok := ForwardingStep(cmd)
	return ok
}

// setForwarding applies the forwarding step: the drop-in appears (and the
// kernel forwards) or the drop-in goes (and the kernel, as on a real host,
// keeps forwarding until the next boot).
func (f *Fake) setForwarding(iface string, enable bool) (string, error) {
	k := &f.state.Kernel
	path := ForwardDropInPath(iface)
	var files []SysctlFile
	for _, file := range k.Files {
		if file.Path != path {
			files = append(files, file)
		}
	}
	var dropIns []string
	for _, name := range k.DropIns {
		if name != iface {
			dropIns = append(dropIns, name)
		}
	}
	out := ""
	if enable {
		files = append(files, SysctlFile{Path: path, Content: ForwardDropIn(iface)})
		dropIns = append(dropIns, iface)
		k.Forward = "1"
		out = ForwardSysctl + " = 1"
	} else if !k.HasDropIn(iface) {
		return "", fmt.Errorf("sh: 1: cannot open %s: No such file", path)
	}
	k.Files, k.DropIns = files, dropIns
	k.ForwardAtBoot, k.ForwardAtBootFrom = BootSysctl(k.Files, ForwardSysctl)
	return out, nil
}

// writeConf applies the install that creates a new interface's conf: the demo
// grows a device, down and peerless, keyed with the invented public key the
// keygen step answered.
func (f *Fake) writeConf(path, conf string) (string, error) {
	name := strings.TrimSuffix(strings.TrimPrefix(path, "/etc/wireguard/"), ".conf")
	if name == "" || !ValidInterface(name) {
		return "", fmt.Errorf("not a wireguard conf path: %s", path)
	}
	for _, d := range f.state.Devices {
		if d.Name == name {
			return "", fmt.Errorf("interface %s already exists", name)
		}
	}
	port := 0
	for _, line := range strings.Split(conf, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ListenPort ="); ok {
			_, _ = fmt.Sscanf(strings.TrimSpace(v), "%d", &port) // best-effort: 0 on mismatch is fine for the fake
		}
	}
	f.confs[name] = conf
	f.state.Devices = append(f.state.Devices, Device{
		Name:          name,
		PublicKey:     demoNewIfacePub,
		HasPrivateKey: true,
		ListenPort:    port,
		FwMark:        "off",
		Up:            false,
		ConfigOnly:    true,
	})
	return "", nil
}

// demoState is the sample network. Times are relative to now, so the view reads
// sensibly however long after this was written it runs.
func demoState() State {
	now := time.Now()
	return State{
		// The demo host: a VM on 198.51.100.0/24 behind eth0, with wg0's
		// peers on 192.0.2.0/24 and a container bridge that is down.
		Routes: []Route{
			{Dst: "default", Gateway: "198.51.100.1", Dev: "eth0"},
			{Dst: "198.51.100.0/24", Dev: "eth0", Scope: "link"},
			{Dst: "192.0.2.0/24", Dev: "wg0", Scope: "link"},
			{Dst: "203.0.113.0/24", Dev: "docker0", Scope: "link", Flags: []string{"linkdown"}},
		},
		// The demo kernel forwards, from wg0's own drop-in.
		Kernel: Kernel{Forward: "1", ForwardAtBoot: "1", ForwardAtBootFrom: ForwardDropInPath("wg0"),
			DropIns: []string{"wg0"},
			Files:   []SysctlFile{{Path: ForwardDropInPath("wg0"), Content: ForwardDropIn("wg0")}}},
		WGAvailable: true,
		Devices: []Device{{
			Name:          "wg0",
			PublicKey:     demoIfacePub,
			HasPrivateKey: true,
			ListenPort:    51820,
			FwMark:        "off",
			Up:            true,
			Peers: []Peer{
				{
					// Mid-handshake: connected seconds ago, moving bytes.
					PublicKey:       demoPeer1Pub,
					HasPresharedKey: true,
					Endpoint:        "198.51.100.10:51820",
					AllowedIPs:      []string{"192.0.2.2/32"},
					LastHandshake:   now.Add(-42 * time.Second),
					RxBytes:         8_452_112,
					TxBytes:         3_221_004,
					Keepalive:       25,
				},
				{
					// Configured but never connected.
					PublicKey:     demoPeer2Pub,
					Endpoint:      "",
					AllowedIPs:    []string{"192.0.2.3/32", "2001:db8::3/128"},
					LastHandshake: time.Time{},
				},
			},
		}},
	}
}
