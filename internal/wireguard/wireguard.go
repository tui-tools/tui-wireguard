// Package wireguard is the part of tui-wireguard that is about its own
// subject: WireGuard interfaces, their peers, and the host around them (the
// routing table a forwarding server proposes its networks from, and the
// firewall that decides whether a handshake reaches the listen port).
// Everything generic (palette, widgets, configuration, running commands) comes
// from tui-kit and is not repeated here.
//
// This package is also the tool's single exec site: the only place a process
// is started (through the kit runner) is internal/wireguard, so the command
// the confirm dialog showed is provably the command that ran. It drives a
// handful of programs — `wg`, `wg-quick`, read-only `ip`, `sh`/`install` for
// the bootstrap flow, and `iptables` for the host firewall — but every one of
// them goes through the same runner boundary.
//
// PRIVACY: a private key never leaves this package on an argv or in any
// rendered value. A new interface's key pair is generated inside one root
// shell that writes the private key straight into a root-only file and prints
// only the public key; the interface conf references that file through PostUp
// instead of inlining the key. Adding a peer needs only its public key; a
// pre-shared key is generated the same way and passed to `wg set` as a file
// path, never as a value on the command line (a command line is visible in
// `ps` to every user on the machine). The model records whether an interface
// has a private key, never the key itself.
package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// Screen is one of the views the tool is made of. They are tabs because they
// answer two separate questions: what is my WireGuard doing, and who are the
// peers of the interface I selected.
type Screen int

const (
	// ScreenStatus lists the WireGuard interfaces on this host.
	ScreenStatus Screen = iota
	// ScreenPeers lists the peers of the selected interface.
	ScreenPeers
	// ScreenCount is the number of screens: it drives the tab bar and the
	// per-screen cursor arrays.
	ScreenCount
)

// Title is the tab label.
func (s Screen) Title() string {
	if s == ScreenPeers {
		return "peers"
	}
	return "interfaces"
}

// Device is one WireGuard interface. It never carries the private key: the most
// a running tool needs to know is that one is configured.
type Device struct {
	Name string `json:"name"`
	// PublicKey is the interface's own public key. It is safe to show.
	PublicKey string `json:"publicKey"`
	// HasPrivateKey reports that a private key is configured, without being it.
	HasPrivateKey bool `json:"hasPrivateKey"`
	// ListenPort is the UDP port the interface listens on, 0 when unset.
	ListenPort int `json:"listenPort"`
	// FwMark is the firewall mark, "off" when unset.
	FwMark string `json:"fwMark,omitempty"`
	// Up reports whether the link is up, as `ip link` sees it.
	Up bool `json:"up"`
	// ConfigOnly reports an interface that has a configuration file in
	// /etc/wireguard but no link: created and never brought up, or taken
	// down. `wg show` does not list it, and without this it would vanish
	// from the screen the moment `d` took it down, leaving nothing to press
	// `u` on.
	ConfigOnly bool   `json:"configOnly,omitempty"`
	Peers      []Peer `json:"peers"`
	// Forwarding reports that the host forwards traffic coming in on this
	// interface: it is a forwarding server (see ForwardingRules). Read from
	// the live ruleset: firewalld's policies when firewalld is running, else
	// the iptables FORWARD chain.
	Forwarding bool `json:"forwarding"`
	// PortVerdict is what the host firewall does with a handshake to
	// ListenPort; unknown when it could not be read or judged.
	PortVerdict Verdict `json:"portVerdict,omitempty"`
}

// Peer is one entry under an interface.
type Peer struct {
	// PublicKey identifies the peer. It is safe to show.
	PublicKey string `json:"publicKey"`
	// HasPresharedKey reports that a pre-shared key is set, without being it.
	HasPresharedKey bool `json:"hasPresharedKey"`
	// Endpoint is the peer's ip:port, empty when it has never connected.
	Endpoint string `json:"endpoint,omitempty"`
	// AllowedIPs is the set of prefixes routed to this peer.
	AllowedIPs []string `json:"allowedIPs"`
	// LastHandshake is when the peer last completed a handshake; zero = never.
	LastHandshake time.Time `json:"lastHandshake,omitempty"`
	// RxBytes and TxBytes are the counters since the interface came up.
	RxBytes int64 `json:"rxBytes"`
	TxBytes int64 `json:"txBytes"`
	// Keepalive is the persistent-keepalive interval in seconds, 0 = off.
	Keepalive int `json:"keepalive"`
}

// State is everything one read produces: the interfaces and the host facts
// around them, each able to be empty without the others failing.
type State struct {
	// WGAvailable reports that the wg binary was found.
	WGAvailable bool `json:"wgAvailable"`
	// WGError carries why an available wg could not be read (usually: no
	// privilege). It is not fatal: the host facts may still have answers.
	WGError string   `json:"wgError,omitempty"`
	Devices []Device `json:"devices"`

	// Routes is `ip -j route`, the source of the networks and the egress a
	// new forwarding server proposes. Firewall is `iptables -S`, where the
	// forwarding rules are. Input is the host firewall's input side, read
	// from tui-firewall, nftables or iptables (input.go). None is
	// serialised: they are addresses of this host.
	Routes   []Route       `json:"-"`
	Firewall Firewall      `json:"-"`
	Input    InputFirewall `json:"-"`
	// TUIFirewall reports that tui-firewall is installed: the tool that
	// opens a port for good, which the listen-port step names.
	TUIFirewall bool `json:"-"`
	// Firewalld is firewalld's runtime zones and policies. When it is
	// running, it is in charge of forwarding and the FORWARD column is read
	// from it instead of from `iptables -S` (issue #30).
	Firewalld Firewalld `json:"-"`
}

// Forwarding sources: what the FORWARD column was read from.
const (
	ForwardSourceFirewalld = "firewalld"
	ForwardSourceIptables  = "iptables"
)

// ForwardSource says what answered for forwarding: firewalld when it is
// running, iptables when its filter table was read, empty when neither was.
func (s State) ForwardSource() string {
	switch {
	case s.Firewalld.Running:
		return ForwardSourceFirewalld
	case s.Firewall.Checked:
		return ForwardSourceIptables
	}
	return ""
}

// ForwardManager is the firewall manager in charge of forwarding: firewalld
// when it is running, else the manager the input read recognised (ufw's
// forwarding is still iptables' FORWARD chain), empty for a bare ruleset.
func (s State) ForwardManager() string {
	if s.Firewalld.Running {
		return ManagerFirewalld
	}
	if s.Input.Manager == ManagerUFW {
		return ManagerUFW
	}
	return ""
}

// annotateFirewall fills each device's forwarding flag and listen-port
// verdict from the firewall that was read.
func (s *State) annotateFirewall() {
	for i := range s.Devices {
		d := &s.Devices[i]
		if s.Firewalld.Running {
			d.Forwarding = s.Firewalld.Forwards(d.Name)
		} else {
			d.Forwarding = s.Firewall.Forwards(d.Name)
		}
		d.PortVerdict = VerdictUnknown
		if d.ListenPort > 0 {
			d.PortVerdict = s.Input.UDPVerdict(d.ListenPort)
		}
	}
}

// Device returns the interface by name.
func (s State) Device(name string) (Device, bool) {
	for _, d := range s.Devices {
		if d.Name == name {
			return d, true
		}
	}
	return Device{}, false
}

// Action is something the user can do. Each maps to one previewed command.
type Action string

const (
	// ActionInterfaceUp brings an interface up with wg-quick.
	ActionInterfaceUp Action = "interface-up"
	// ActionInterfaceDown takes an interface down with wg-quick.
	ActionInterfaceDown Action = "interface-down"
	// ActionRemovePeer removes a peer from an interface.
	ActionRemovePeer Action = "remove-peer"
	// ActionCreateInterface bootstraps a new WireGuard interface from zero:
	// keygen, config file, optional up.
	ActionCreateInterface Action = "create-interface"
	// ActionSaveConfig persists an interface's runtime state with wg-quick save.
	ActionSaveConfig Action = "save-config"
)

// keyPattern is a WireGuard key on the wire: 43 base64 characters and a '='.
// Both public and private keys share this shape, which is exactly why the shape
// alone cannot be trusted: the safeguard is that this package only ever accepts
// a parameter named "public key" and never builds a `private-key` argument.
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// ValidPublicKey reports whether s is a syntactically valid WireGuard key.
func ValidPublicKey(s string) bool { return keyPattern.MatchString(s) }

// ifacePattern is a plausible network interface name: letters, digits and a
// few separators, nothing that could turn into a second argument or a flag.
var ifacePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

// ValidInterface reports whether s is a plausible interface name.
func ValidInterface(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && ifacePattern.MatchString(s)
}

// BuildInterfaceUp assembles `wg-quick up <iface>`.
func BuildInterfaceUp(iface string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	return runner.Command{
		Argv:        []string{"wg-quick", "up", iface},
		Description: "Bring up " + iface,
	}, nil
}

// BuildInterfaceDown assembles `wg-quick down <iface>`.
func BuildInterfaceDown(iface string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	return runner.Command{
		Argv:        []string{"wg-quick", "down", iface},
		Description: "Bring down " + iface,
		Destructive: true,
	}, nil
}

// BuildRemovePeer assembles `wg set <iface> peer <public-key> remove`.
func BuildRemovePeer(iface, publicKey string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	if !ValidPublicKey(publicKey) {
		return runner.Command{}, fmt.Errorf("not a valid public key")
	}
	return runner.Command{
		Argv:        []string{"wg", "set", iface, "peer", publicKey, "remove"},
		Description: "Remove peer from " + iface,
		Destructive: true,
	}, nil
}

// PeerSpec is everything the add-peer form collects about one peer. None of
// it is secret: the peer is named by its PUBLIC key and a pre-shared key only
// ever travels as the path of the root-only file that holds it.
type PeerSpec struct {
	// PublicKey identifies the peer.
	PublicKey string
	// AllowedIPs are the prefixes routed to the peer; at least one.
	AllowedIPs []string
	// PresharedKeyFile is the file wg reads a pre-shared key from, empty for
	// none.
	PresharedKeyFile string
	// Endpoint is where to reach the peer, host:port or [v6]:port; empty
	// leaves it unset, so the peer has to dial in first.
	Endpoint string
	// Keepalive is the persistent-keepalive interval in seconds; 0 leaves it
	// off. A peer behind NAT usually wants 25.
	Keepalive int
}

// MaxKeepalive is the largest persistent-keepalive interval wg accepts.
const MaxKeepalive = 65535

// SuggestedKeepalive is the interval the WireGuard docs suggest for a peer
// behind NAT: short enough to keep a typical NAT mapping open.
const SuggestedKeepalive = 25

// BuildAddPeer assembles `wg set <iface> peer <public-key> allowed-ips <ips>`,
// followed by the optional `endpoint <host:port>`, `persistent-keepalive <s>`
// and `preshared-key <file>`.
//
// The peer is identified by its PUBLIC key. A pre-shared key, when given, is a
// path to a file `wg` opens itself: it is never a value on the argv, so it can
// never appear in the confirm dialog or in `ps`. A private key has no place in
// this call at all, and the guard below refuses one if it is ever wired in by
// mistake.
func BuildAddPeer(iface string, spec PeerSpec) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	if !ValidPublicKey(spec.PublicKey) {
		return runner.Command{}, fmt.Errorf("not a valid public key")
	}
	ips := make([]string, 0, len(spec.AllowedIPs))
	for _, ip := range spec.AllowedIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if !ValidAllowedIP(ip) {
			return runner.Command{}, fmt.Errorf("not a valid allowed-ip: %q", ip)
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return runner.Command{}, fmt.Errorf("a peer needs at least one allowed-ip")
	}
	argv := []string{"wg", "set", iface, "peer", spec.PublicKey, "allowed-ips", strings.Join(ips, ",")}
	if spec.Endpoint != "" {
		if err := CheckEndpoint(spec.Endpoint); err != nil {
			return runner.Command{}, err
		}
		argv = append(argv, "endpoint", spec.Endpoint)
	}
	if spec.Keepalive < 0 || spec.Keepalive > MaxKeepalive {
		return runner.Command{}, fmt.Errorf("persistent keepalive must be 0-%d seconds, not %d",
			MaxKeepalive, spec.Keepalive)
	}
	if spec.Keepalive > 0 {
		argv = append(argv, "persistent-keepalive", strconv.Itoa(spec.Keepalive))
	}
	if spec.PresharedKeyFile != "" {
		if strings.ContainsAny(spec.PresharedKeyFile, " \t\n") {
			return runner.Command{}, fmt.Errorf("not a valid file path for the pre-shared key")
		}
		argv = append(argv, "preshared-key", spec.PresharedKeyFile)
	}
	return runner.Command{
		Argv:        argv,
		Description: "Add peer to " + iface,
	}, nil
}

// hostnamePattern is one DNS label: letters, digits and inner hyphens.
var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// CheckEndpoint validates a peer endpoint the way wg reads one: host:port,
// where the host is an IPv4 address or a DNS name, or [v6]:port with the IPv6
// address in brackets. The port is 1-65535. Nothing that could become a
// second argument or a flag gets through.
func CheckEndpoint(s string) error {
	bad := func(why string) error {
		return fmt.Errorf("not a valid endpoint %q: %s (host:port or [v6]:port)", s, why)
	}
	if s == "" || strings.HasPrefix(s, "-") || strings.ContainsAny(s, " \t\n") {
		return bad("empty or not one word")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return bad("no port, or an IPv6 address without brackets")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return bad("the port must be 1-65535")
	}
	if strings.HasPrefix(s, "[") {
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return bad("brackets hold an IPv6 address")
		}
		return nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !addr.Is4() {
			return bad("an IPv6 address goes in brackets")
		}
		return nil
	}
	if len(host) > 253 {
		return bad("the host name is too long")
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if !hostnamePattern.MatchString(label) {
			return bad("the host is neither an address nor a DNS name")
		}
	}
	return nil
}

// ValidEndpoint reports whether s is a peer endpoint CheckEndpoint accepts.
func ValidEndpoint(s string) bool { return CheckEndpoint(s) == nil }

// ParseKeepalive reads the keepalive field of the add-peer form: empty or
// "off" is 0 (off), otherwise a whole number of seconds in 0-65535.
func ParseKeepalive(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "off") {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > MaxKeepalive {
		return 0, fmt.Errorf("persistent keepalive must be 0-%d seconds (%d behind NAT), not %q",
			MaxKeepalive, SuggestedKeepalive, s)
	}
	return n, nil
}

// ConfDir is where wg-quick looks for interface configurations.
const ConfDir = "/etc/wireguard"

// ConfPath is where wg-quick expects an interface's configuration file.
func ConfPath(iface string) string { return ConfDir + "/" + iface + ".conf" }

// ParseConfNames reads a listing of ConfDir into the interface names that
// have a configuration: every `<name>.conf` whose name is a valid interface
// name. Keys, pre-shared keys and anything else in the directory are skipped.
func ParseConfNames(listing string) []string {
	var names []string
	for _, line := range strings.Split(listing, "\n") {
		name, ok := strings.CutSuffix(strings.TrimSpace(line), ".conf")
		if ok && ValidInterface(name) {
			names = append(names, name)
		}
	}
	return names
}

// MergeConfigured appends a down, config-only device for each configured name
// that is not already a live device, keeping the live ones first and in the
// order `wg show` gave them.
func MergeConfigured(devices []Device, names []string) []Device {
	live := make(map[string]bool, len(devices))
	for _, d := range devices {
		live[d.Name] = true
	}
	for _, name := range names {
		if !live[name] {
			devices = append(devices, Device{Name: name, ConfigOnly: true})
			live[name] = true
		}
	}
	return devices
}

// KeyPath is where the tool keeps an interface's private key: a root-only file
// next to the configuration, which `wg set … private-key` reads itself.
func KeyPath(iface string) string { return "/etc/wireguard/" + iface + ".key" }

// BuildGenerateInterfaceKey assembles the one command that creates a new
// interface's key pair. The whole flow happens inside a single root shell at
// the exec site: generate the private key, write it to a root-only file
// (umask 077 makes it 600 before a byte lands), and print only the PUBLIC key.
// The private key exists on disk for one purpose — `wg set` reads it from the
// file — and never crosses back into the UI, an argv, or the screen.
func BuildGenerateInterfaceKey(iface string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	script := "umask 077 && wg genkey | tee " + KeyPath(iface) + " | wg pubkey"
	return runner.Command{
		Argv:        []string{"sh", "-c", script},
		Description: "Generate key pair for " + iface,
	}, nil
}

// InterfaceConf renders the configuration file for a freshly created
// interface. The design decision worth a comment: the file contains NO private
// key at all. Instead of writing `PrivateKey = …` (which would put a secret in
// the preview, in this process's memory and in the dialog), the conf carries a
// PostUp line — `wg set %i private-key /etc/wireguard/<if>.key` — so wg-quick
// loads the key from its root-only file at up time. WireGuard supports this
// natively, the whole conf is then safe to show in the confirm dialog, and the
// key never exists anywhere but the file the root shell wrote it to.
//
// A later save (`w`) rewrites this file from runtime state with `wg-quick
// save`, which inlines the private key; the same previewed step takes it back
// out again, because this PostUp line is there to load it (see save.go).
func InterfaceConf(iface, address string, listenPort int) (string, error) {
	return InterfaceConfWith(iface, address, listenPort, nil)
}

// InterfaceConfWith is InterfaceConf for an interface that may be a
// forwarding server: with a spec, the PostUp and PostDown lines of
// ForwardingRules follow the key line.
func InterfaceConfWith(iface, address string, listenPort int, fwd *ForwardSpec) (string, error) {
	if !ValidInterface(iface) {
		return "", fmt.Errorf("not a valid interface name: %q", iface)
	}
	if !ValidCIDR(address) {
		return "", fmt.Errorf("not a valid CIDR address: %q", address)
	}
	if listenPort < 1 || listenPort > 65535 {
		return "", fmt.Errorf("not a valid listen port: %d", listenPort)
	}
	conf := fmt.Sprintf(`[Interface]
# The private key lives in %s (root, mode 600) and is loaded
# at up time; this file deliberately contains no secret.
Address = %s
ListenPort = %d
PostUp = wg set %%i private-key %s
`, KeyPath(iface), address, listenPort, KeyPath(iface))
	if fwd == nil {
		return conf, nil
	}
	up, down, err := ForwardingRules(iface, address, *fwd)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(conf)
	b.WriteString("# Forwarding server: peers reach the networks behind this host through " +
		fwd.Egress + ".\n# ip_forward is left on at down; something else may rely on it.\n")
	if fwd.Manager == ManagerFirewalld {
		b.WriteString("# firewalld is in charge: the rules are the firewalld policy " + policyNameOr(iface) +
			",\n# created at up and deleted at down. Each --reload drops runtime-only firewalld changes.\n")
	}
	for _, line := range up {
		b.WriteString("PostUp = " + line + "\n")
	}
	for _, line := range down {
		b.WriteString("PostDown = " + line + "\n")
	}
	return b.String(), nil
}

// BuildWriteInterfaceConf assembles the install that writes the configuration
// file. The content travels on stdin, never on the argv — not because it is
// secret (with the PostUp design it is not), but because content on an argv is
// one quoting bug away from being commands. `install -m 600` creates the file
// with the right mode atomically instead of touch-then-chmod.
func BuildWriteInterfaceConf(iface, conf string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	if strings.TrimSpace(conf) == "" {
		return runner.Command{}, fmt.Errorf("refusing to write an empty configuration")
	}
	if strings.Contains(conf, "PrivateKey") {
		// The guard for the design above: no code path may ever compose a conf
		// that inlines a private key.
		return runner.Command{}, fmt.Errorf("refusing to write a configuration that inlines a private key")
	}
	return runner.Command{
		Argv:        []string{"install", "-m", "600", "/dev/stdin", ConfPath(iface)},
		Description: "Write " + ConfPath(iface),
		Stdin:       conf,
	}, nil
}

// PSKPath is the root-only file a generated pre-shared key is written to,
// named after the interface and a filename-safe slice of the peer's public
// key so two peers never collide.
func PSKPath(iface, peerPublicKey string) string {
	var b strings.Builder
	for _, r := range peerPublicKey {
		if b.Len() == 8 {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return pskPrefix(iface) + b.String() + ".psk"
}

// BuildGeneratePSK assembles the root shell that generates a pre-shared key
// into a root-only file. Like the interface key, the value never leaves the
// exec site: only the file PATH does, and BuildAddPeer hands that path to
// `wg set … preshared-key`, which opens the file itself.
func BuildGeneratePSK(iface, peerPublicKey string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	if !ValidPublicKey(peerPublicKey) {
		return runner.Command{}, fmt.Errorf("not a valid public key")
	}
	path := PSKPath(iface, peerPublicKey)
	script := "umask 077 && wg genpsk > " + path
	return runner.Command{
		Argv:        []string{"sh", "-c", script},
		Description: "Generate pre-shared key file " + path,
	}, nil
}

// cidrPattern is an address with a mandatory /prefix: the Address= line of an
// interface needs the prefix length, and the shape rules out anything that
// could become a second argument or an ini injection.
var cidrPattern = regexp.MustCompile(`^[0-9A-Fa-f:.]+/[0-9]{1,3}$`)

// ValidCIDR reports whether s is a plausible address-with-prefix.
func ValidCIDR(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && cidrPattern.MatchString(s)
}

// allowedIPPattern is a CIDR or a bare address: digits, hex, dots, colons and a
// single optional /prefix, nothing that could become a second argument.
var allowedIPPattern = regexp.MustCompile(`^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$`)

// ValidAllowedIP reports whether s is a plausible allowed-ip entry.
func ValidAllowedIP(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && allowedIPPattern.MatchString(s)
}

// Backend is the boundary between the UI and the machine. Load reads the model;
// Preview renders the exact command a confirmed action would run; Run executes
// it. Nothing else may start a process.
type Backend interface {
	// Name identifies the backend ("wireguard", "demo").
	Name() string
	// Describe is the one-line summary shown in the header.
	Describe() string
	// Load reads the current state. It never fails as a whole: a missing wg or
	// an unreadable firewall is a fact in the State, not an error.
	Load(ctx context.Context) (State, error)
	// Preview renders the exact command line Run will execute, routing to the
	// right binary so the privilege prefix shown is the one that will apply.
	Preview(cmd runner.Command) string
	// Run executes a previously previewed command.
	Run(ctx context.Context, cmd runner.Command) (string, error)
}
