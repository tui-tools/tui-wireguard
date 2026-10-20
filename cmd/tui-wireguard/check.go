package main

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-wireguard/internal/wireguard"
)

// checkTimeout bounds the whole read.
const checkTimeout = 30 * time.Second

// checkReport is what --check prints: one read of the interfaces and the host
// firewall around them, reduced to counts and ages.
//
// PRIVACY: this block is meant to be pasted into scripts and issues, so it
// carries no public key, no endpoint and no address of this host — only how
// many of each thing there are and how long ago each peer last shook hands.
type checkReport struct {
	Tool     string `json:"tool"`
	Version  string `json:"version"`
	Backend  string `json:"backend"`
	Describe string `json:"describe"`

	WireGuard wgSummary `json:"wireguard"`

	// Compat is what the version probe found, one entry per backend declared.
	Compat []compat.Result `json:"compat"`
}

// wgSummary is the WireGuard side, reduced.
type wgSummary struct {
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
	// FirewallChecked reports that the host firewall's input side was read;
	// without root it is not, and every listenPortInput is "unknown".
	// FirewallSource says what answered: tui-firewall (its --check),
	// nftables (`nft -j list ruleset`) or iptables (`iptables -S`).
	// FirewallManager is firewalld or ufw when one was recognised.
	FirewallChecked bool   `json:"firewallChecked"`
	FirewallSource  string `json:"firewallSource,omitempty"`
	FirewallManager string `json:"firewallManager,omitempty"`
	// ForwardingChecked reports that the forwarding side was read, and
	// ForwardingSource what answered: firewalld (`firewall-cmd
	// --list-all-policies` and `--list-all-zones`) when it is running, else
	// iptables (`iptables -S`, the FORWARD chain). ForwardingManager is
	// firewalld, or ufw when the input read recognised it (issue #30).
	ForwardingChecked bool   `json:"forwardingChecked"`
	ForwardingSource  string `json:"forwardingSource,omitempty"`
	ForwardingManager string `json:"forwardingManager,omitempty"`
	// KernelForwarding is net.ipv4.ip_forward now (on, off, or unknown when
	// /proc could not be read), and KernelForwardingAtBoot what the sysctl.d
	// files set it to at boot (off when none sets it). Rules on a kernel
	// that does not forward pass nothing (issue #33).
	KernelForwarding       string         `json:"kernelForwarding"`
	KernelForwardingAtBoot string         `json:"kernelForwardingAtBoot"`
	Interfaces             []ifaceSummary `json:"interfaces"`
}

// ifaceSummary is one interface without anything that identifies it on the wire.
type ifaceSummary struct {
	Name          string `json:"name"`
	Up            bool   `json:"up"`
	ListenPort    int    `json:"listenPort"`
	HasPrivateKey bool   `json:"hasPrivateKey"`
	// ConfigOnly is an interface known from its file in /etc/wireguard
	// alone: it is down, so wg has nothing to say about its peers.
	ConfigOnly bool          `json:"configOnly,omitempty"`
	PeerCount  int           `json:"peerCount"`
	Peers      []peerSummary `json:"peers"`
	// ListenPortInput is what the host firewall does with a handshake to
	// the listen port: accept, reject, drop, or unknown when the firewall
	// could not be read or its rules could not be judged.
	ListenPortInput wireguard.Verdict `json:"listenPortInput"`
	// Forwarding is whether the host forwards traffic in on this interface
	// (a forwarding server), as forwardingSource answered: its rules.
	Forwarding bool `json:"forwarding"`
	// ForwardingDropIn reports the tool's /etc/sysctl.d drop-in for it.
	ForwardingDropIn bool `json:"forwardingDropIn,omitempty"`
	// Problems are failures the other fields only imply, such as forwarding
	// rules on a kernel that does not forward.
	Problems []string `json:"problems,omitempty"`
}

// peerSummary is one peer's health, with no key and no endpoint.
type peerSummary struct {
	// LastHandshakeAgeSeconds is how long ago the peer last shook hands, or -1
	// when it never has.
	LastHandshakeAgeSeconds int  `json:"lastHandshakeAgeSeconds"`
	AllowedIPCount          int  `json:"allowedIpCount"`
	HasPresharedKey         bool `json:"hasPresharedKey"`
	KeepaliveSeconds        int  `json:"keepaliveSeconds"`
}

// runCheck reads the state once and prints the reduced summary as JSON.
func runCheck(ctx context.Context, backend wireguard.Backend,
	backends []compat.Result, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	state, err := backend.Load(ctx)
	if err != nil {
		return err
	}

	report := checkReport{
		Tool:      toolName,
		Version:   version,
		Backend:   backend.Name(),
		Describe:  backend.Describe(),
		WireGuard: summariseWG(state),
		Compat:    backends,
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// summariseWG reduces the WireGuard side to counts and ages.
func summariseWG(state wireguard.State) wgSummary {
	now := time.Now()
	summary := wgSummary{Available: state.WGAvailable, Error: state.WGError,
		FirewallChecked: state.Input.Source != "", FirewallSource: state.Input.Source,
		FirewallManager:   state.Input.Manager,
		ForwardingChecked: state.ForwardSource() != "", ForwardingSource: state.ForwardSource(),
		ForwardingManager: state.ForwardManager(),
		KernelForwarding:  state.Kernel.ForwardWord(), KernelForwardingAtBoot: state.Kernel.ForwardAtBootWord()}
	for _, dev := range state.Devices {
		verdict := dev.PortVerdict
		if verdict == "" {
			verdict = wireguard.VerdictUnknown
		}
		iface := ifaceSummary{
			Name:             dev.Name,
			Up:               dev.Up,
			ListenPort:       dev.ListenPort,
			HasPrivateKey:    dev.HasPrivateKey,
			ConfigOnly:       dev.ConfigOnly,
			PeerCount:        len(dev.Peers),
			ListenPortInput:  verdict,
			Forwarding:       dev.Forwarding,
			ForwardingDropIn: state.Kernel.HasDropIn(dev.Name),
			Problems:         state.Problems(dev),
		}
		for _, peer := range dev.Peers {
			iface.Peers = append(iface.Peers, peerSummary{
				LastHandshakeAgeSeconds: handshakeAge(now, peer.LastHandshake),
				AllowedIPCount:          len(peer.AllowedIPs),
				HasPresharedKey:         peer.HasPresharedKey,
				KeepaliveSeconds:        peer.Keepalive,
			})
		}
		summary.Interfaces = append(summary.Interfaces, iface)
	}
	return summary
}

// handshakeAge is seconds since a handshake, or -1 when there has never been
// one.
func handshakeAge(now, t time.Time) int {
	if t.IsZero() {
		return -1
	}
	return int(now.Sub(t).Seconds())
}
