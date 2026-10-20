package wireguard

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// --- create interface from zero ---------------------------------------------

func TestBuildGenerateInterfaceKey(t *testing.T) {
	cmd, err := BuildGenerateInterfaceKey("wg9")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cmd.Argv[0] != "sh" || cmd.Argv[1] != "-c" || len(cmd.Argv) != 3 {
		t.Fatalf("argv = %q, want a single sh -c script", cmd.Argv)
	}
	script := cmd.Argv[2]
	for _, must := range []string{"umask 077", "wg genkey", "tee /etc/wireguard/wg9.key", "wg pubkey"} {
		if !strings.Contains(script, must) {
			t.Errorf("script %q is missing %q", script, must)
		}
	}
	for _, bad := range []string{"", "-wg0", "wg 0", "wg0;reboot", "../etc", "a/b"} {
		if _, err := BuildGenerateInterfaceKey(bad); err == nil {
			t.Errorf("accepted a bad interface name: %q", bad)
		}
	}
}

// TestInterfaceConfContainsNoPrivateKey is the design's own guard: the conf a
// created interface gets references the root-only key file through PostUp and
// never inlines a key, which is why the confirm dialog may show it whole.
func TestInterfaceConfContainsNoPrivateKey(t *testing.T) {
	conf, err := InterfaceConf("wg9", "192.0.2.1/24", 51820)
	if err != nil {
		t.Fatalf("conf: %v", err)
	}
	if strings.Contains(conf, "PrivateKey") {
		t.Fatalf("the conf inlines a private key:\n%s", conf)
	}
	for _, must := range []string{
		"[Interface]",
		"Address = 192.0.2.1/24",
		"ListenPort = 51820",
		"PostUp = wg set %i private-key /etc/wireguard/wg9.key",
	} {
		if !strings.Contains(conf, must) {
			t.Errorf("conf is missing %q:\n%s", must, conf)
		}
	}
}

func TestInterfaceConfRejectsBadInput(t *testing.T) {
	if _, err := InterfaceConf("wg9", "not-an-address", 51820); err == nil {
		t.Error("accepted a non-CIDR address")
	}
	if _, err := InterfaceConf("wg9", "192.0.2.1", 51820); err == nil {
		t.Error("accepted an address without a prefix length")
	}
	if _, err := InterfaceConf("wg9", "192.0.2.1/24\n[Peer]", 51820); err == nil {
		t.Error("accepted an address carrying an ini injection")
	}
	if _, err := InterfaceConf("wg9", "192.0.2.1/24", 0); err == nil {
		t.Error("accepted port 0")
	}
	if _, err := InterfaceConf("wg9", "192.0.2.1/24", 70000); err == nil {
		t.Error("accepted a port above 65535")
	}
}

func TestBuildWriteInterfaceConf(t *testing.T) {
	conf, err := InterfaceConf("wg9", "192.0.2.1/24", 51820)
	if err != nil {
		t.Fatalf("conf: %v", err)
	}
	cmd, err := BuildWriteInterfaceConf("wg9", conf)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := []string{"install", "-m", "600", "/dev/stdin", "/etc/wireguard/wg9.conf"}
	if !reflect.DeepEqual(cmd.Argv, want) {
		t.Errorf("argv = %q, want %q", cmd.Argv, want)
	}
	// The content rides stdin, never the argv: nothing from the conf may be a
	// command-line token.
	if cmd.Stdin != conf {
		t.Error("the conf content is not the stdin payload")
	}
	for _, tok := range cmd.Argv {
		if strings.Contains(tok, "Address") || strings.Contains(tok, "PostUp") {
			t.Errorf("conf content leaked onto the argv: %q", tok)
		}
	}
	// The guard: a conf that inlines a private key must be refused, whatever
	// composed it.
	if _, err := BuildWriteInterfaceConf("wg9", "[Interface]\nPrivateKey = x\n"); err == nil {
		t.Error("accepted a conf that inlines a private key")
	}
	if _, err := BuildWriteInterfaceConf("wg9", "   \n"); err == nil {
		t.Error("accepted an empty conf")
	}
}

// --- persistence -------------------------------------------------------------

// TestBuildSaveConfig and the save's rewrite are in save_test.go.

// --- pre-shared key ----------------------------------------------------------

func TestBuildGeneratePSK(t *testing.T) {
	cmd, err := BuildGeneratePSK("wg0", testPub)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cmd.Argv[0] != "sh" || cmd.Argv[1] != "-c" {
		t.Fatalf("argv = %q, want sh -c", cmd.Argv)
	}
	if !strings.Contains(cmd.Argv[2], "umask 077") || !strings.Contains(cmd.Argv[2], "wg genpsk") {
		t.Errorf("script = %q", cmd.Argv[2])
	}
	if !strings.Contains(cmd.Argv[2], PSKPath("wg0", testPub)) {
		t.Errorf("script does not write the PSK path: %q", cmd.Argv[2])
	}
	if _, err := BuildGeneratePSK("wg0", "not-a-key"); err == nil {
		t.Error("accepted an invalid public key")
	}
}

// TestPSKPathIsFilenameSafe: a public key is base64 and may carry '/' and '+';
// neither may reach a path the shell script embeds.
func TestPSKPathIsFilenameSafe(t *testing.T) {
	key := "ab/+" + strings.Repeat("Z", 39) + "="
	path := PSKPath("wg0", key)
	name := strings.TrimPrefix(path, "/etc/wireguard/")
	if strings.ContainsAny(name, "/+= ") {
		t.Errorf("PSK path is not filename-safe: %q", path)
	}
	if !strings.HasPrefix(path, "/etc/wireguard/wg0-") || !strings.HasSuffix(path, ".psk") {
		t.Errorf("PSK path shape = %q", path)
	}
}

// TestNoNewBuilderEmitsAPrivateKey extends the package's core promise to the
// manage builders: no argv token names a private key or carries one. The keygen
// script mentions the key FILE it writes, but never a `private-key` flag and
// never a key value.
func TestNoNewBuilderEmitsAPrivateKey(t *testing.T) {
	conf, _ := InterfaceConf("wg9", "192.0.2.1/24", 51820)
	cmds := []struct {
		name string
		make func() (runnerArgv []string, err error)
	}{
		{"keygen", func() ([]string, error) { c, e := BuildGenerateInterfaceKey("wg9"); return c.Argv, e }},
		{"write-conf", func() ([]string, error) { c, e := BuildWriteInterfaceConf("wg9", conf); return c.Argv, e }},
		// The save's last argument is the awk program, which names the key
		// line it recognises; save_test.go checks the shell itself.
		{"save", func() ([]string, error) { c, e := BuildSaveConfig("wg0"); return c.Argv[:4], e }},
		{"genpsk", func() ([]string, error) { c, e := BuildGeneratePSK("wg0", testPub); return c.Argv, e }},
	}
	for _, tc := range cmds {
		argv, err := tc.make()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, tok := range argv {
			if strings.Contains(tok, "private-key") || strings.Contains(tok, "privatekey") {
				t.Errorf("%s command carries a private-key token: %q", tc.name, argv)
			}
			if ValidPublicKey(tok) && tc.name != "genpsk" {
				t.Errorf("%s command carries a key-shaped value: %q", tc.name, argv)
			}
		}
	}
}

func TestManageValidators(t *testing.T) {
	if !ValidCIDR("192.0.2.1/24") || !ValidCIDR("2001:db8::1/64") {
		t.Error("a real CIDR should validate")
	}
	if ValidCIDR("192.0.2.1") || ValidCIDR("-192.0.2.1/24") || ValidCIDR("a b/24") {
		t.Error("a non-CIDR should not validate")
	}
}

// --- fake parity -------------------------------------------------------------

// TestFakeCreateInterfaceFlow drives the whole bootstrap against the demo
// backend: keygen answers a (fake) public key, the conf write grows a new
// device, and wg-quick up brings it up — so --demo exercises the exact flow.
func TestFakeCreateInterfaceFlow(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	keygen, err := BuildGenerateInterfaceKey("wg9")
	if err != nil {
		t.Fatalf("keygen build: %v", err)
	}
	pub, err := f.Run(ctx, keygen)
	if err != nil {
		t.Fatalf("keygen run: %v", err)
	}
	if !ValidPublicKey(strings.TrimSpace(pub)) {
		t.Fatalf("keygen answered %q, want a public-key-shaped value", pub)
	}

	conf, err := InterfaceConf("wg9", "192.0.2.9/24", 51999)
	if err != nil {
		t.Fatalf("conf: %v", err)
	}
	write, err := BuildWriteInterfaceConf("wg9", conf)
	if err != nil {
		t.Fatalf("write build: %v", err)
	}
	if _, err := f.Run(ctx, write); err != nil {
		t.Fatalf("write run: %v", err)
	}

	state, _ := f.Load(ctx)
	dev, ok := state.Device("wg9")
	if !ok {
		t.Fatal("the new interface is missing after the conf write")
	}
	if dev.Up {
		t.Error("a freshly created interface should be down")
	}
	if dev.ListenPort != 51999 {
		t.Errorf("listen port = %d, want 51999", dev.ListenPort)
	}
	if !dev.HasPrivateKey {
		t.Error("the created interface should report a configured private key")
	}

	up, _ := BuildInterfaceUp("wg9")
	if _, err := f.Run(ctx, up); err != nil {
		t.Fatalf("up run: %v", err)
	}
	state, _ = f.Load(ctx)
	if dev, _ := state.Device("wg9"); !dev.Up {
		t.Error("wg9 should be up after wg-quick up")
	}
}

func TestFakeRejectsDuplicateInterface(t *testing.T) {
	f := NewFake()
	conf, _ := InterfaceConf("wg0", "192.0.2.9/24", 51999)
	write, _ := BuildWriteInterfaceConf("wg0", conf)
	if _, err := f.Run(context.Background(), write); err == nil {
		t.Error("writing a conf over an existing interface should fail in the demo")
	}
}

func TestFakeAppliesSaveConfig(t *testing.T) {
	f := NewFake()
	cmd, _ := BuildSaveConfig("wg0")
	out, err := f.Run(context.Background(), cmd)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "/etc/wireguard/wg0.conf") {
		t.Errorf("save answered %q, want the conf path", out)
	}
	bad, _ := BuildSaveConfig("nope0")
	if _, err := f.Run(context.Background(), bad); err == nil {
		t.Error("saving a missing interface should fail")
	}
}

func TestFakeAddPeerWithPSKMarksIt(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	psk, _ := BuildGeneratePSK("wg0", testPub)
	if _, err := f.Run(ctx, psk); err != nil {
		t.Fatalf("genpsk: %v", err)
	}
	add, err := BuildAddPeer("wg0", PeerSpec{PublicKey: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=",
		AllowedIPs: []string{"192.0.2.7/32"}, PresharedKeyFile: PSKPath("wg0", testPub)})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := f.Run(ctx, add); err != nil {
		t.Fatalf("run: %v", err)
	}
	state, _ := f.Load(ctx)
	dev, _ := state.Device("wg0")
	last := dev.Peers[len(dev.Peers)-1]
	if !last.HasPresharedKey {
		t.Error("a peer added with a preshared-key file should report one")
	}
}

// TestFakeAddPeerRecordsEndpointAndKeepalive: the demo applies the optional
// fields the way wg would, so the peers screen shows them after an add.
func TestFakeAddPeerRecordsEndpointAndKeepalive(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	pub := "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE="
	add, err := BuildAddPeer("wg0", PeerSpec{PublicKey: pub, AllowedIPs: []string{"192.0.2.7/32"},
		Endpoint: "198.51.100.7:51820", Keepalive: 25})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := f.Run(ctx, add); err != nil {
		t.Fatalf("run: %v", err)
	}
	state, _ := f.Load(ctx)
	dev, _ := state.Device("wg0")
	last := dev.Peers[len(dev.Peers)-1]
	if last.PublicKey != pub || last.Endpoint != "198.51.100.7:51820" || last.Keepalive != 25 {
		t.Errorf("peer = %+v, want the endpoint and keepalive applied", last)
	}
}
